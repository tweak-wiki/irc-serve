/* test_fed_kick_mode_remote.c -- #606: KICK/MODE against a remote member.
 *
 * handle_kick() and the MODE +o/+v arm resolved the target with
 * chan_find_nick() only (local members), so an op kicking or voicing a member
 * on the other node got 401 though the target was on the channel. The fix
 * resolves the union of the local roster and ch->remotes[]; fed_in_smodes()
 * applies inbound +o/+v to the roster instead of caching the letter in
 * modes[]; fed_in_skick() drops a locally-held victim after the emit.
 *
 * Two nodes, both directions: #K owned by A (alice first), #L owned by B (bob
 * first). The join ordering follows test_fed_roster.c: the owner's SJOIN is
 * waited for on the other node before the second JOIN, or the second node
 * would create the channel and own it too.
 */
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
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET     "irc-serve-federation-secret-a"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define CHAN_K     "#K"
#define CHAN_L     "#L"
#define NICK_A     "alice"
#define NICK_B     "bob"
#define NICK_C     "carol"

static int g_peer_port;
static int g_trace;
static const char *g_dial_name = NAME_A;

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

    TF_CHECK_MSG(fed_open(s, SECRET) == 0, "fed_open() failed in the child");
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
    TF_CHECK_MSG(fed_link_configure(s, g_dial_name,
                                    (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d",
                 g_dial_name, g_peer_port);
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

/* A real flush: tc_drain() with a zero timeout only drops the buffer and never
 * touches the socket, so bytes already sent but not yet read -- a JOIN bundle
 * still in flight, an unread echo -- surface at the next expect. A 366 waited
 * for after such a drain then matches the PREVIOUS channel's 366 still sitting
 * in the buffer, and an absence asserted after it passes against history
 * rather than against the fresh reply. Pull the socket dry first
 * (non-blocking), then drop the buffer. Anything arriving between the two is
 * genuinely new, which is what the caller wants to see. */
static void flush_client(test_client_t *c)
{
    int eof = 0;

    (void)tc_read_available(c, &eof);
    (void)tc_drain(c, 0, NULL);
}

static void link_up(nf_node_t *a, nf_node_t *b)
{
    g_peer_port = 0;
    g_trace = 0;
    g_dial_name = NAME_A;
    TF_CHECK_MSG(nf_spawn_inline_named(a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a->port > 0, "node A reported no port");
    g_peer_port = a->port;
    TF_CHECK_MSG(nf_spawn_inline_named(b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(nf_expect(b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");
}

/* Owner joins first, then the peer's SJOIN is waited for on the other node
 * before the second JOIN, for the reason test_fed_roster.c gives. Flushed
 * first: the 366s below must be the fresh JOIN replies, not a previous
 * channel's 366 still in the buffer. */
static void join_shared(nf_node_t *owner, nf_node_t *other,
                        test_client_t *oc, test_client_t *tc, const char *chan,
                        const char *owner_nick, const char *other_nick)
{
    char line[256];
    char want[128];

    flush_client(oc);
    flush_client(tc);
    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(oc, line) == 0, "%s JOIN failed",
                 owner_nick);
    TF_CHECK_MSG(tc_expect(oc, " 366 ", T_IO_MS) == 0,
                 "%s JOIN never completed", owner_nick);
    /* Scoped to this channel AND member: a bare "fed_sjoin:" also matches an
     * earlier channel's line still sitting in the node's buffer. */
    (void)snprintf(want, sizeof want, "fed_sjoin: channel=%s member=%s", chan,
                   owner_nick);
    TF_CHECK_MSG(nf_expect(other, want, T_IO_MS) == 0,
                 "peer never applied %s's SJOIN for %s: %s", owner_nick, chan,
                 other->out);
    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(tc, line) == 0, "%s JOIN failed",
                 other_nick);
    TF_CHECK_MSG(tc_expect(tc, " 366 ", T_IO_MS) == 0,
                 "%s JOIN never completed", other_nick);
    (void)snprintf(want, sizeof want, "fed_sjoin: channel=%s member=%s", chan,
                   other_nick);
    TF_CHECK_MSG(nf_expect(owner, want, T_IO_MS) == 0,
                 "owner never applied %s's SJOIN for %s: %s", other_nick, chan,
                 owner->out);
}

static void expect_names_line(test_client_t *c, const char *who,
                              const char *chan, const char *names)
{
    char want[256];

    /* Flushed first: without this the needle below matches the JOIN-time 353
     * and a changed roster passes unasserted. */
    flush_client(c);
    (void)snprintf(want, sizeof want, "NAMES %s", chan);
    TF_CHECK_MSG(tc_send(c, want) == 0, "%s NAMES failed", who);
    (void)snprintf(want, sizeof want, " 353 %s = %s %s\r\n", who, chan, names);
    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                 "%s never saw 353 \"%s\" for %s: %s", who, names, chan,
                 tc_buffer(c));
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0, "%s got no 366", who);
}

int main(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    test_client_t carol;

    link_up(&a, &b);
    register_client(&alice, a.port, NICK_A);
    register_client(&bob, b.port, NICK_B);
    register_client(&carol, a.port, NICK_C);

    /* #K owned by A: alice first, bob second. */
    join_shared(&a, &b, &alice, &bob, CHAN_K, NICK_A, NICK_B);

    /* MODE +v against a remote member: no 401, MODE renders on both nodes,
     * 353 carries the sigil on both. */
    flush_client(&alice);
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_K " +v " NICK_B) == 0,
                 "alice MODE +v failed");
    TF_CHECK_MSG(tc_expect(&bob, "MODE " CHAN_K " +v " NICK_B, T_IO_MS) == 0,
                 "bob never saw alice's +v: %s", tc_buffer(&bob));
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN_K " +v " NICK_B, T_IO_MS) == 0,
                 "alice never saw her own +v echo: %s", tc_buffer(&alice));
    expect_names_line(&alice, NICK_A, CHAN_K, "@" NICK_A);
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "+" NICK_B) != NULL,
                 "A's 353 lost bob's +v: %s", tc_buffer(&alice));
    expect_names_line(&bob, NICK_B, CHAN_K, "@" NICK_A);
    TF_CHECK_MSG(strstr(tc_buffer(&bob), "+" NICK_B) != NULL,
                 "B's 353 lost bob's +v: %s", tc_buffer(&bob));

    /* And back off again, on the same remote path. */
    flush_client(&alice);
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_K " -v " NICK_B) == 0,
                 "alice MODE -v failed");
    TF_CHECK_MSG(tc_expect(&bob, "MODE " CHAN_K " -v " NICK_B, T_IO_MS) == 0,
                 "bob never saw alice's -v: %s", tc_buffer(&bob));

    /* 401/441 are still distinct: unknown nick 401s, a registered nick that
     * is not on the channel 441s, on both verbs. */
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "KICK " CHAN_K " zzzznobody :out") == 0,
                 "KICK unknown send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 401 ", T_IO_MS) == 0,
                 "KICK of an unknown nick did not 401: %s", tc_buffer(&alice));
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_K " +v zzzznobody") == 0,
                 "MODE unknown send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 401 ", T_IO_MS) == 0,
                 "MODE +v of an unknown nick did not 401: %s",
                 tc_buffer(&alice));
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "KICK " CHAN_K " " NICK_C " :out") == 0,
                 "KICK carol send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 441 ", T_IO_MS) == 0,
                 "KICK of a nick not on the channel did not 441: %s",
                 tc_buffer(&alice));
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_K " +v " NICK_C) == 0,
                 "MODE carol send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 441 ", T_IO_MS) == 0,
                 "MODE +v of a nick not on the channel did not 441: %s",
                 tc_buffer(&alice));

    /* KICK against a remote member: no 401, the victim sees the KICK, and
     * both rosters drop them. */
    flush_client(&alice);
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&alice, "KICK " CHAN_K " " NICK_B " :getout") == 0,
                 "alice KICK failed");
    TF_CHECK_MSG(tc_expect(&bob, "KICK " CHAN_K " " NICK_B " getout",
                           T_IO_MS) == 0,
                 "bob never saw his own KICK: %s", tc_buffer(&bob));
    TF_CHECK_MSG(tc_expect(&alice, "KICK " CHAN_K " " NICK_B, T_IO_MS) == 0,
                 "alice never saw the KICK echo: %s", tc_buffer(&alice));
    /* Flushed, so the absence below is asserted against the fresh NAMES reply
     * and not against the KICK echo still in flight. */
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "NAMES " CHAN_K) == 0, "alice NAMES failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice got no 366 after the KICK");
    TF_CHECK_MSG(strstr(tc_buffer(&alice), NICK_B) == NULL,
                 "A's roster still names the kicked member: %s",
                 tc_buffer(&alice));
    /* NAMES is public: a kicked client gets the roster, not 442. The roster
     * is what must have dropped them, in every rendering. */
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&bob, "NAMES " CHAN_K) == 0, "bob NAMES failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob got no 366 after being kicked");
    TF_CHECK_MSG(strstr(tc_buffer(&bob), "@" NICK_B) == NULL &&
                 strstr(tc_buffer(&bob), "+" NICK_B) == NULL &&
                 strstr(tc_buffer(&bob), " " NICK_B "\r\n") == NULL,
                 "B's roster still names the kicked member: %s",
                 tc_buffer(&bob));

    /* Reverse direction on a B-owned channel: bob voices then kicks alice. */
    join_shared(&b, &a, &bob, &alice, CHAN_L, NICK_B, NICK_A);
    flush_client(&alice);
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&bob, "MODE " CHAN_L " +o " NICK_A) == 0,
                 "bob MODE +o failed");
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN_L " +o " NICK_A, T_IO_MS) == 0,
                 "alice never saw bob's +o: %s", tc_buffer(&alice));
    /* Both are ops now, so one 353 line with both names (local first). */
    flush_client(&alice);
    TF_CHECK_MSG(tc_send(&alice, "NAMES " CHAN_L) == 0, "alice NAMES failed");
    TF_CHECK_MSG(tc_expect(&alice, " 353 " NICK_A " = " CHAN_L " :@" NICK_A
                           " @" NICK_B, T_IO_MS) == 0,
                 "A's 353 lost alice's +o: %s", tc_buffer(&alice));
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice got no 366");
    flush_client(&alice);
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&bob, "KICK " CHAN_L " " NICK_A " :out") == 0,
                 "bob KICK failed");
    TF_CHECK_MSG(tc_expect(&alice, "KICK " CHAN_L " " NICK_A, T_IO_MS) == 0,
                 "alice never saw her own KICK: %s", tc_buffer(&alice));
    /* The kicker's own echo, asserted before the flush: it causally orders
     * every line the KICK produced ahead of the fresh NAMES reply below. */
    TF_CHECK_MSG(tc_expect(&bob, "KICK " CHAN_L " " NICK_A, T_IO_MS) == 0,
                 "bob never saw the KICK echo: %s", tc_buffer(&bob));
    flush_client(&bob);
    TF_CHECK_MSG(tc_send(&bob, "NAMES " CHAN_L) == 0, "bob NAMES failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob got no 366 after the KICK");
    TF_CHECK_MSG(strstr(tc_buffer(&bob), NICK_A) == NULL,
                 "B's roster still names the kicked member: %s",
                 tc_buffer(&bob));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");

    tc_close(&alice);
    tc_close(&bob);
    tc_close(&carol);
    nf_free(&a);
    nf_free(&b);

    tf_done("fed_kick_mode_remote");
    return 0;
}
