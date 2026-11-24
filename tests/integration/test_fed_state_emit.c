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
    TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", NAME_A,
                 g_peer_port);
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

int main(void)
{
    case_remote_part_join_topic();
    tf_done("fed_state_emit");
    return 0;
}
