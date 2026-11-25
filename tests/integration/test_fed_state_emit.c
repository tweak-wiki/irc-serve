/* test_fed_state_emit.c -- inbound S-verbs render client lines to local members.
 *
 * Issue #559: every inbound state verb applied to the cache but none rendered
 * a client-shaped line. A client of node A sharing #T with a client of node B
 * never saw the remote client's PART/JOIN/TOPIC -- its member list showed the
 * remote member forever, until a manual NAMES.
 *
 * The case below is the acceptance criterion: bob (on B, the origin) PARTs and
 * re-JOINs, and alice (on A) must see `:bob!... PART #T` and `:bob!... JOIN #T`.
 * A TOPIC round is included because it exercises the stored-value echo. The
 * fixture, the spawn order and the waits are test_fed_roster.c's, shortened:
 * the ordering argument is stated there and not repeated here.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/peer_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET     "irc-serve-federation-secret-a"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define CHAN       "#T"
#define NICK_A     "alice"
#define NICK_B     "bob"

static int g_peer_port;
static int g_trace;
static const char *g_peer_name = NAME_A;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child");
    s->trace = g_trace;
    s->on_tick = child_tick;
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);

    if (g_peer_port <= 0) {
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, g_peer_name, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d",
                 g_peer_name, g_peer_port);
}

static void register_client(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    TF_CHECK_MSG(tc_send(c, "PING :registered") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG", T_IO_MS) == 0,
                 "%s got no PONG after registration", nick);
}

/* Drain BEFORE acting, then wait for the line. The drain is what makes the wait
 * prove anything: without it the needle would match a line the client's own
 * earlier command produced and the case would pass on a node that emits
 * nothing. The drain lives with the caller rather than in here because a drain
 * after the action would eat a line that already arrived and wait out the
 * deadline against nothing. */
static void expect_fresh_line(test_client_t *who, const char *who_name,
                              const char *needle, const char *attribution)
{
    TF_CHECK_MSG(tc_expect(who, needle, T_IO_MS) == 0,
                 "%s never saw \"%s\" after the remote client's action, so the "
                 "inbound S-verb applied to the cache but rendered no client "
                 "line. What %s did see: %s",
                 who_name, needle, who_name, tc_buffer(who));
    if (attribution != NULL) {
        TF_CHECK_MSG(strstr(tc_buffer(who), attribution) != NULL,
                     "%s saw \"%s\" but not from \"%s\" -- the line arrived "
                     "without its actor: %s",
                     who_name, needle, attribution, tc_buffer(who));
    }
}

static void case_remote_part_join_topic(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(&alice, a.port, NICK_A);
    register_client(&bob, b.port, NICK_B);

    /* bob joins FIRST, on B, which therefore owns #T. alice joins on A, which
     * does not own it -- so everything alice does below is the JOIN/PART
     * exception: applied locally on A and forwarded to the owner. The
     * owner-side direction (acting on B) is deliberately not used here: a
     * PART on the owning node has no SPART forward arm in chan_verbs.c, which
     * is a separate gap outside this change. */
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the owning node");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied bob's SJOIN: %s", a.out);

    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never applied alice's SJOIN: %s", b.out);

    /* Remote PART renders a client PART line to the members who stay. */
    (void)tc_drain(&bob, 0, NULL);
    TF_CHECK_MSG(tc_send(&alice, "PART " CHAN " :leaving") == 0,
                 "alice's PART send failed");
    TF_CHECK_MSG(nf_expect(&b, "fed_spart: channel=" CHAN " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never applied alice's SPART: %s", b.out);
    expect_fresh_line(&bob, NICK_B, "PART " CHAN, NICK_A "!");

    /* And the re-JOIN renders again -- the roster alone is not convergence. */
    (void)tc_drain(&bob, 0, NULL);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's re-JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's re-JOIN never completed");
    expect_fresh_line(&bob, NICK_B, "JOIN " CHAN, NICK_A "!");

    /* A TOPIC alice sets on the non-owner is forwarded to the origin and
     * applied there, so the origin's members see it. (Whether the origin's
     * relay reaches back to A is the forward path's business -- G6 drops an
     * emission stamped with A's own origin -- and is asserted nowhere here.) */
    (void)tc_drain(&bob, 0, NULL);
    TF_CHECK_MSG(tc_send(&alice, "TOPIC " CHAN " :hello over there") == 0,
                 "alice's TOPIC send failed");
    expect_fresh_line(&bob, NICK_B, "TOPIC " CHAN, NICK_A "!");
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");

    tc_close(&alice);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * Gap 1 + 2: server-prefixed lines, and the held JOIN a resync completes.
 * ---------------------------------------------------------------------------
 * No node built from this code emits an SJOIN with a server prefix, so a
 * two-node fixture can only prove the prefix path is not reached. A raw peer
 * socket speaks the fed handshake for real and then puts anything on the
 * line -- a server prefix, an unknown mask -- and the assertions below pin
 * what renders: the burst record's hostmask, else the bare nick, and never a
 * `:server VERB` or an `!*@*` guess. ONE MESH PER CASE: cases 2 and 3 both
 * assert an ABSENCE, and an absence is only attributable to one case if the
 * buffer belongs to one case. */
static int g_raw_peer_port;

static void raw_child_setup(server_t *s)
{
    struct sockaddr_in sa;

    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0, "fed_open() failed in the child");
    s->on_tick = child_tick;
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_raw_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, NAME_B, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s", NAME_B);
}

/* Open the link and answer the handshake. Returns the live peer socket. */
static int raw_peer_open(nf_node_t *node)
{
    const char *needles[2];
    char line[512];
    int listen_fd;
    int fd;

    listen_fd = pf_listen_loopback(&g_raw_peer_port);
    TF_CHECK_MSG(listen_fd >= 0, "no listening socket for the raw peer");
    TF_CHECK_MSG(nf_spawn_inline_named(node, NAME_A, raw_child_setup) == 0,
                 "could not spawn node A");
    fd = pf_accept_deadline(listen_fd, T_IO_MS);
    (void)close(listen_fd);
    TF_CHECK_MSG(fd >= 0, "node A never dialled the raw peer: %s", node->out);
    needles[0] = ":" NAME_A " FEDERATE " NAME_A " ";
    needles[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
    TF_CHECK_MSG(pf_read_until(fd, needles, 2, T_IO_MS) == 0,
                 "node A never sent FEDERATE: %s", node->out);
    (void)snprintf(line, sizeof line, ":" NAME_B " FEDERATE " NAME_B
                   " 1700000000 " SECRET " " IRC_SERVE_VERSION);
    TF_CHECK_MSG(pf_send_line(fd, line) == 0, "FEDERATE answer failed");
    TF_CHECK_MSG(nf_expect(node, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "link never established: %s", node->out);
    return fd;
}

/* The 2.4 stamp, rendered by the test rather than read from the node. `id`
 * differs per line so two lines are two messages to the dedup store rather
 * than the second being dropped as a duplicate. */
static void raw_stamp(char *out, size_t cap, unsigned long id)
{
    (void)snprintf(out, cap,
                    "@irc-serve-origin=%s;irc-serve-epoch=1700000000;"
                    "irc-serve-id=%lu;irc-serve-hops=1 ", NAME_B, id);
}

static void case_server_prefixed_verbs(void)
{
    nf_node_t a;
    test_client_t alice;
    char line[1024];
    char stamp[256];
    unsigned long id = 1;
    int peer_fd;

    peer_fd = raw_peer_open(&a);
    TF_CHECK_MSG(a.port > 0, "node A reported no port");
    register_client(&alice, a.port, NICK_A);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");

    /* A server-prefixed SJOIN applies to the roster. No JOIN line is asserted
     * here: with no burst record the emission is held, and case 2 proves the
     * silence by showing what is absent after the resync delivers it. */
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SJOIN " CHAN " "
                   NICK_B " - * - -", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SJOIN send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied the SJOIN: %s", a.out);

    /* A server-prefixed SPART renders the bare nick: no `:server VERB`, and
     * no guessed `!*@*` mask. The positive wait first, so the absences below
     * are facts about a line that arrived rather than a wait that expired. */
    (void)tc_drain(&alice, 0, NULL);
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SPART " NICK_B " " CHAN,
                   stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SPART send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_spart: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied the SPART: %s", a.out);
    expect_fresh_line(&alice, NICK_A, "PART " CHAN, ":" NICK_B " ");
    TF_CHECK_MSG(strstr(tc_buffer(&alice), ":" NAME_B " PART") == NULL,
                 "a server prefix rendered as the PART actor: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "!*@*") == NULL,
                 "a guessed hostmask rendered on PART: %s", tc_buffer(&alice));

    /* An unknown-mask STOPIC renders the bare setter the same way. */
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SJOIN " CHAN " dave"
                   " - * - -", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SJOIN dave failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=dave",
                           T_IO_MS) == 0,
                 "node A never applied dave's SJOIN: %s", a.out);
    (void)tc_drain(&alice, 0, NULL);
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:weird STOPIC dave " CHAN
                   " :hello there", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "STOPIC send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_topic: channel=" CHAN " member=dave",
                           T_IO_MS) == 0,
                 "node A never applied the STOPIC: %s", a.out);
    expect_fresh_line(&alice, NICK_A, "TOPIC " CHAN, ":dave ");
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "weird") == NULL,
                 "an unknown mask rendered as the TOPIC actor: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "!*@*") == NULL,
                 "a guessed hostmask rendered on TOPIC: %s", tc_buffer(&alice));

    /* A server-prefixed SKICK renders the bare kicker; the removal took the
     * target, so the kicker's record is still there to render from. */
    (void)tc_drain(&alice, 0, NULL);
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SKICK dave " CHAN
                   " " NICK_A " :gone", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SKICK send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_skick: channel=" CHAN, T_IO_MS) == 0,
                 "node A never applied the SKICK: %s", a.out);
    expect_fresh_line(&alice, NICK_A, "KICK " CHAN, ":dave ");
    TF_CHECK_MSG(strstr(tc_buffer(&alice), ":" NAME_B " KICK") == NULL,
                 "a server prefix rendered as the KICK actor: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "!*@*") == NULL,
                 "a guessed hostmask rendered on KICK: %s", tc_buffer(&alice));
    /* The SKICK above removed alice herself (#606: a SKICK whose victim is
     * local drops the local membership after the emit), so the MODE below
     * would have no audience. Re-JOIN her first; the channel still holds
     * remote dave, so it was never disposed. */
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice re-JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice re-JOIN never completed: %s", tc_buffer(&alice));

    (void)tc_drain(&alice, 0, NULL);
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:evil!x SMODES " NAME_B " " CHAN
                   " +b *!*@example.com", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SMODES send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_modes: channel=" CHAN, T_IO_MS) == 0,
                 "node A never applied the SMODES: %s", a.out);
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN, T_IO_MS) == 0,
                 "alice never saw the MODE line: %s", tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "evil") == NULL,
                 "a garbage prefix rendered as the MODE actor: %s",
                 tc_buffer(&alice));

    (void)close(peer_fd);
    tc_close(&alice);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    nf_free(&a);
}

/* Gap 2: the held JOIN a resync completes. A server-prefixed SJOIN applies
 * to the roster but renders nothing (no record yet); the burst that
 * completes the record renders the held JOIN with the burst hostmask. The
 * absence that proves the hold is a string absence AFTER the burst delivered
 * it: had the SJOIN rendered, the bare form would be in the buffer next to
 * the masked one. */
static void case_resync_then_join(void)
{
    nf_node_t a;
    test_client_t alice;
    char line[1024];
    char stamp[256];
    unsigned long id = 1;
    int peer_fd;

    peer_fd = raw_peer_open(&a);
    TF_CHECK_MSG(a.port > 0, "node A reported no port");
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SJOIN " CHAN " carol"
                   " - * - -", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SJOIN send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "node A never applied the SJOIN: %s", a.out);

    register_client(&alice, a.port, NICK_A);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    (void)tc_drain(&alice, 0, NULL);

    /* The resync: one nick record with a hostmask, one channel, one member.
     * Epoch matches the handshake so no peer restart is adopted. */
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SBURST 1700000000 1",
                   stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SBURST send failed");
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SBURSTN carol cuser"
                   " chost - 1700000000 -", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SBURSTN send failed");
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SBURSTC " CHAN " " NAME_B
                   " - 0 - welcome", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SBURSTC send failed");
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SBURSTM " CHAN " " NAME_B
                   " carol - *", stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SBURSTM send failed");
    raw_stamp(stamp, sizeof stamp, id++);
    (void)snprintf(line, sizeof line, "%s:" NAME_B " SBURSTE 1700000000 1 1 1",
                   stamp);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "SBURSTE send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never applied the burst: %s", a.out);

    /* The held JOIN, rendered once, with the burst hostmask -- and no bare
     * twin from the SJOIN, which proves the hold rather than asserting a
     * silence nobody can time. */
    TF_CHECK_MSG(tc_expect(&alice, "JOIN " CHAN, T_IO_MS) == 0,
                 "alice never saw carol's held JOIN: %s", tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), ":carol!") != NULL,
                 "the held JOIN did not render carol's burst hostmask: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "carol JOIN") == NULL,
                 "the SJOIN rendered a bare JOIN before the burst: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), ":" NAME_B " JOIN") == NULL,
                 "a server prefix rendered as the JOIN actor: %s",
                 tc_buffer(&alice));

    (void)close(peer_fd);
    tc_close(&alice);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    nf_free(&a);
}

/* Gap 3: a graceful two-node departure renders QUIT on the survivor. bob is
 * on B before A links, so B's establishment burst carries his hostmask; when
 * B leaves cleanly, A relays nothing onward (no third node) but must still
 * tell its own members -- the exact line #559 was filed for. */
static void case_graceful_stop_quit(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");
    register_client(&bob, b.port, NICK_B);
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed");

    g_peer_port = b.port;
    g_peer_name = NAME_B;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    g_peer_name = NAME_A;
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never applied B's burst: %s", a.out);

    register_client(&alice, a.port, NICK_A);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");

    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_expect(&a, "fed_shutdown: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never received B's SHUTDOWN: %s", a.out);
    TF_CHECK_MSG(tc_expect(&alice, " QUIT", T_IO_MS) == 0,
                 "alice never saw bob's QUIT: %s", tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), ":" NICK_B "!") != NULL,
                 "the QUIT did not render bob's burst hostmask: %s",
                 tc_buffer(&alice));

    tc_close(&alice);
    tc_close(&bob);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_remote_part_join_topic();
    case_server_prefixed_verbs();
    case_resync_then_join();
    case_graceful_stop_quit();
    tf_done("fed_state_emit");
    return 0;
}
