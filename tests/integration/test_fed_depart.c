/* test_fed_depart.c -- #608/#663: a local client departure must reach the mesh.
 *
 * QUIT, a bare EOF and a flood close all end in chan_conn_gone(), which used
 * to emit PART to local members only (#608: the peer kept the chan_remote_t
 * entry and the nickreg record, so the ghost stayed in NAMES until the next
 * burst). Since #663 the departure crosses the wire as a quit-flagged SPART,
 * so the far side renders one QUIT -- with the reason on a graceful QUIT,
 * bare on a hangup -- instead of one PART per channel. Each case below drops
 * bob (on B) one way and asserts the far side converges: A applies the
 * SPART, alice sees `:bob!... QUIT`, NAMES #T drops bob, and `bob@irc.b`
 * stops resolving (401) instead of answering from the registry. An explicit
 * PART still renders PART (test_fed_state_emit.c pins that half).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

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
#define CHAN   "#T"
#define CHAN2  "#U"
#define NICK_A "alice"
#define NICK_B "bob"

static int g_peer_port;

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
                 "the child could not configure its peer");
}

static void register_client(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
    TF_CHECK_MSG(tc_send(c, "PING :registered") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG", T_IO_MS) == 0,
                 "%s got no PONG after registration", nick);
}

/* Two nodes linked, bob first on B (so B owns #T), alice on A. Bob's SJOIN is
 * what teaches A the nickreg entry the departure must clear. */
static void mesh_up(nf_node_t *a, nf_node_t *b, test_client_t *alice,
                    test_client_t *bob)
{
    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a->port > 0, "node A reported no port");

    g_peer_port = a->port;
    TF_CHECK_MSG(nf_spawn_inline_named(b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(nf_expect(b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(alice, a->port, NICK_A);
    register_client(bob, b->port, NICK_B);

    TF_CHECK_MSG(tc_send(bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed");
    TF_CHECK_MSG(nf_expect(a, "fed_sjoin: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied bob's SJOIN: %s", a->out);

    TF_CHECK_MSG(tc_send(alice, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    TF_CHECK_MSG(nf_expect(b, "fed_sjoin: channel=" CHAN " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never applied alice's SJOIN: %s", b->out);

    /* nick@server resolves while bob is present: the 401 after the drop is
     * then a fact about the departure, not about broken routing. */
    (void)tc_drain(bob, 0, NULL);
    (void)tc_drain(alice, 0, NULL);
    TF_CHECK_MSG(tc_send(alice, "PRIVMSG " NICK_B "@" NAME_B " :knock") == 0,
                 "pre-drop scoped PRIVMSG send failed");
    TF_CHECK_MSG(tc_expect(bob, "PRIVMSG", T_IO_MS) == 0,
                 "scoped PRIVMSG never reached bob before the drop: %s",
                 tc_buffer(bob));
}
/* Occurrences of needle in haystack, for asserting one departure rendered
 * exactly one QUIT. */
static size_t count_hits(const char *haystack, const char *needle)
{
    size_t n = 0;
    const char *p = haystack;
    size_t len = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}


/* The far side converged: SPART applied, one QUIT rendered, roster and
 * registry clean. The SPART wait comes first so the NAMES below cannot pass
 * on a node that answers from a stale cache. want_reason is NULL for a bare
 * QUIT (hangup) or the reason text for a graceful QUIT. union_check waits
 * for the second channel's SPART too and asserts the whole departure rendered
 * exactly one QUIT -- never one per channel, never a PART. It must run before
 * the drains below compact alice's history. */
static void expect_remote_gone(nf_node_t *a, test_client_t *alice,
                               const char *want_reason, int union_check)
{
    TF_CHECK_MSG(nf_expect(a, "fed_spart: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied the departure SPART: %s", a->out);
    if (union_check != 0) {
        TF_CHECK_MSG(nf_expect(a, "fed_spart: channel=" CHAN2
                               " member=" NICK_B, T_IO_MS) == 0,
                     "node A never applied the departure SPART " CHAN2 ": %s",
                     a->out);
    }
    TF_CHECK_MSG(tc_expect(alice, " QUIT", T_IO_MS) == 0,
                 "alice never saw bob's departure QUIT: %s",
                 tc_buffer(alice));
    TF_CHECK_MSG(strstr(tc_buffer(alice), ":" NICK_B "!") != NULL,
                 "the departure QUIT carried no hostmask actor: %s",
                 tc_buffer(alice));
    if (want_reason != NULL) {
        /* The colon is framing, not content: a one-word reason needs none
        * on the wire, so `QUIT bye` and `QUIT :bye` are the same reason. */
        char want[256];
        char want_bare[256];

        (void)snprintf(want, sizeof want, "QUIT :%s", want_reason);
        (void)snprintf(want_bare, sizeof want_bare, "QUIT %s", want_reason);
        TF_CHECK_MSG(strstr(tc_buffer(alice), want) != NULL ||
                     strstr(tc_buffer(alice), want_bare) != NULL,
                     "the departure QUIT carried no reason: %s",
                     tc_buffer(alice));
    } else {
        TF_CHECK_MSG(strstr(tc_buffer(alice), "QUIT :") == NULL,
                     "a hangup must render a bare QUIT: %s",
                     tc_buffer(alice));
    }
    TF_CHECK_MSG(strstr(tc_buffer(alice), "PART " CHAN) == NULL,
                 "a remote quit rendered as PART: %s", tc_buffer(alice));
    if (union_check != 0) {
        TF_CHECK_MSG(count_hits(tc_buffer(alice), " QUIT") == 1u,
                     "one departure rendered more than one QUIT: %s",
                     tc_buffer(alice));
    }

    (void)tc_drain(alice, 0, NULL);
    TF_CHECK_MSG(tc_send(alice, "NAMES " CHAN) == 0, "NAMES send failed");
    TF_CHECK_MSG(tc_expect(alice, " 366 ", T_IO_MS) == 0,
                 "NAMES never completed after the departure");
    TF_CHECK_MSG(strstr(tc_buffer(alice), NICK_B) == NULL,
                 "NAMES still lists the departed nick: %s", tc_buffer(alice));

    (void)tc_drain(alice, 0, NULL);
    TF_CHECK_MSG(tc_send(alice, "PRIVMSG " NICK_B "@" NAME_B " :knock") == 0,
                 "post-drop scoped PRIVMSG send failed");
    TF_CHECK_MSG(tc_expect(alice, " 401 ", T_IO_MS) == 0,
                 "bob@irc.b still resolves after the departure: the nickreg "
                 "record survived: %s",
                 tc_buffer(alice));
}

static void mesh_down(nf_node_t *a, nf_node_t *b, test_client_t *alice,
                      test_client_t *bob)
{
    tc_close(alice);
    tc_close(bob);
    TF_CHECK_MSG(nf_stop(a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(b) == 0, "node B did not exit cleanly");
    nf_free(a);
    nf_free(b);
}

static void case_eof_depart(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    mesh_up(&a, &b, &alice, &bob);
    /* Gone with no QUIT: the socket close is the whole signal, and the far
    * node still renders QUIT -- bare, with no reason. */
    tc_close(&bob);
    (void)tc_drain(&alice, 0, NULL);
    expect_remote_gone(&a, &alice, NULL, 0);
    mesh_down(&a, &b, &alice, &bob);
}

static void case_quit_depart(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    mesh_up(&a, &b, &alice, &bob);
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN2) == 0, "bob's JOIN " CHAN2
                 " send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN " CHAN2 " never completed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN2 " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied bob's SJOIN " CHAN2 ": %s", a.out);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN2) == 0, "alice's JOIN " CHAN2
                 " send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN " CHAN2 " never completed");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN2 " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never applied alice's SJOIN " CHAN2 ": %s", b.out);
    (void)tc_drain(&bob, 0, NULL);
    (void)tc_drain(&alice, 0, NULL);
    TF_CHECK_MSG(tc_send(&bob, "QUIT :bye for now") == 0,
                 "bob's QUIT send failed");
    tc_close(&bob);
    (void)tc_drain(&alice, 0, NULL);
    expect_remote_gone(&a, &alice, "bye for now", 1);
    mesh_down(&a, &b, &alice, &bob);
}

static void case_flood_depart(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    int i;
    int rc;

    mesh_up(&a, &b, &alice, &bob);
    /* Spend past the 256 burst: one 417, then the reaper closes. A send past
     * the close fails, which proves the 417 below is already on its way. */
    for (i = 0; i < 300; i++) {
        if (tc_send(&bob, "PING :flood") != 0) {
            break;
        }
    }
    TF_CHECK_MSG(tc_expect(&bob, " 417 ", T_IO_MS) == 0,
                 "the flood was never refused with 417");
    rc = tc_expect_eof(&bob, T_IO_MS);
    TF_CHECK_MSG(rc == 0 || rc == -3,
                 "the flooding connection was not closed after the 417 "
                 "(rc=%d)",
                 rc);
    (void)tc_drain(&alice, 0, NULL);
    expect_remote_gone(&a, &alice, NULL, 0);
    mesh_down(&a, &b, &alice, &bob);
}

int main(void)
{
    case_eof_depart();
    case_quit_depart();
    case_flood_depart();
    tf_done("fed_depart");
    return 0;
}
