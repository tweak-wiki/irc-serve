/* test_fed_queries_remote.c -- issue #607: WHOIS/WHO/ISON see remote members.
 *
 * Two linked nodes, alice on irc.a and bob on irc.b, both on #T. Before the
 * fix every query verb answered from the local table only: WHOIS bob was
 * 401, WHO #T listed only the local member, ISON dropped the remote nick.
 * After it, alice sees bob in all three, qualified WHOIS works, and an
 * unknown nick is still 401 + 318.
 */
#include <netinet/in.h>
#include <stdio.h>
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

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define NAME_B "irc.b"

static int g_peer_port;

/* The federation dial, handshake and resync all run off the tick; an inline
 * child with no tick hook never dials. */
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
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);
    s->on_tick = child_tick;
    if (g_peer_port <= 0) {
        return; /* the accepting side; the inbound claim configures its link */
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer " NAME_A);
}

/* Register a client and wait for the welcome, with a PING as the drain token. */
static void register_client(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
    TF_CHECK_MSG(tc_send(c, "PING :registered") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG", T_IO_MS) == 0,
                 "%s got no PONG after registration", nick);
}

int main(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);

    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never applied a burst from node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied a burst from node A: %s", b.out);

    register_client(&alice, a.port, "alice");
    register_client(&bob, b.port, "bob");

    TF_CHECK_MSG(tc_send(&alice, "JOIN #T") == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=#T member=alice", T_IO_MS)
                     == 0,
                 "node B never learned about alice: %s", b.out);
    TF_CHECK_MSG(tc_send(&bob, "JOIN #T") == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=#T member=bob", T_IO_MS)
                     == 0,
                 "node A never learned about bob: %s", a.out);

    /* WHOIS of the remote nick: 311 with the cached user/host, 312 naming
     * the holder, 319 naming the shared channel, 318 closing. */
    TF_CHECK_MSG(tc_send(&alice, "WHOIS bob") == 0, "WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 311 alice bob bob 127.0.0.1 * bob",
                           T_IO_MS) == 0,
                 "alice got no 311 for remote bob: %s", alice.buf);
    TF_CHECK_MSG(tc_expect(&alice, " 312 alice bob " NAME_B " ", T_IO_MS) == 0,
                 "alice got no 312 naming " NAME_B " for bob: %s", alice.buf);
    TF_CHECK_MSG(tc_expect(&alice, " 319 alice bob #T", T_IO_MS) == 0,
                 "alice got no 319 naming #T for bob: %s", alice.buf);
    TF_CHECK_MSG(tc_expect(&alice, " 318 alice bob ", T_IO_MS) == 0,
                 "alice got no 318 for bob: %s", alice.buf);

    /* Qualified WHOIS resolves from the holder's cache. */
    TF_CHECK_MSG(tc_send(&alice, "WHOIS bob@" NAME_B) == 0,
                 "qualified WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 311 alice bob bob ", T_IO_MS) == 0,
                 "alice got no 311 for qualified bob@" NAME_B ": %s",
                 alice.buf);

    /* WHO #T lists the remote member with its cached hostmask. */
    TF_CHECK_MSG(tc_send(&alice, "WHO #T") == 0, "WHO send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 352 alice #T bob 127.0.0.1 " NAME_B " bob H ",
                           T_IO_MS) == 0,
                 "alice got no 352 for remote bob: %s", alice.buf);
    TF_CHECK_MSG(tc_expect(&alice, " 315 alice #T ", T_IO_MS) == 0,
                 "alice got no 315 for #T: %s", alice.buf);

    /* ISON names the remote nick. */
    TF_CHECK_MSG(tc_send(&alice, "ISON alice bob") == 0, "ISON send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 303 alice :alice bob", T_IO_MS) == 0,
                 "alice got no 303 naming remote bob: %s", alice.buf);

    /* A nick known nowhere is still 401 + 318. */
    TF_CHECK_MSG(tc_send(&alice, "WHOIS ghost") == 0, "WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 401 alice ghost ", T_IO_MS) == 0,
                 "alice got no 401 for unknown ghost: %s", alice.buf);
    TF_CHECK_MSG(tc_expect(&alice, " 318 alice ghost ", T_IO_MS) == 0,
                 "alice got no 318 for unknown ghost: %s", alice.buf);

    /* The other direction: bob sees alice. */
    TF_CHECK_MSG(tc_send(&bob, "WHOIS alice") == 0, "WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 311 bob alice alice 127.0.0.1 * alice",
                           T_IO_MS) == 0,
                 "bob got no 311 for remote alice: %s", bob.buf);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
    tf_done("fed_queries_remote");
    return 0;
}
