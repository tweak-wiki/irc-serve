/* test_fed_notify.c -- the 4.3 extension (#563) crosses a peer link.
 *
 * A three-node star: irc.a dials irc.b and irc.c, which both accept. alice is
 * on A and owns #T (she joins first); bob is on B; carol is on C.
 *
 *   1. A live SJOIN carries user+host, so a 353 with userhost-in-names on a
 *      third node renders a remote member as nick!user@host rather than a
 *      bare nick. Before the extension the SJOIN had four parameters and the
 *      bare nick was the normal state.
 *   2. SETNAME on B reaches carol on C as a SETNAME line, and C's log shows
 *      the SSETNAME it applied.
 *   3. AWAY set and cleared on B reaches carol on C as both AWAY shapes, and
 *      C's log shows the SAWAY it applied.
 *   4. INVITE by the owner on A reaches carol on C as an INVITE line, and B --
 *      which holds a member but no invitee -- logs the SINVITE it relayed.
 *   5. INVITE to `carol@irc.c` reaches carol on C herself (#664): the 341 goes
 *      to the inviter, the SINVITE crosses, C delivers, and no 401 is sent.
 *   6. A FEDERATE naming irc-serve-0.1.0 is refused with BAD_VERSION and
 *      establishes nothing: the version bump is what keeps a 0.1.x node from
 *      misparsing the six-parameter SJOIN.
 *
 * ONE DIRECTION PER PAIR: B and C configure no peer and accept; A configures
 * both. A node that configured both ends of a pair would both dial and neither
 * accept, and the pair would end up with no link at all.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/cap.h"
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
#define NAME_C "irc.c"
#define CHAN   "#T"
#define OLD_VERSION "irc-serve-0.1.0"

typedef struct {
    const char *name;
    int         port;
} peer_cfg_t;

static peer_cfg_t g_peers[2];
static size_t     g_npeers;
static int        g_trace;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0, "fed_open() failed in the child");
    s->trace = g_trace;
    s->on_tick = child_tick;
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);

    for (size_t i = 0; i < g_npeers; i++) {
        struct sockaddr_in addr;

        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_peers[i].name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_peers[i].name, g_peers[i].port);
    }
}

static void set_peers(const peer_cfg_t *peers, size_t n)
{
    memset(g_peers, 0, sizeof g_peers);
    g_npeers = n;
    for (size_t i = 0; i < n && i < sizeof g_peers / sizeof g_peers[0]; i++) {
        g_peers[i] = peers[i];
    }
}

/* Register `c` as `nick`, negotiating `caps` first (NULL for no exchange). */
static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    tc_init(c);
    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\"", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
}

static void join_chan(test_client_t *c, const char *chan)
{
    char line[128];

    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(c, line) == 0, "JOIN %s send failed", chan);
    /* 366 and not the echo: a JOIN on a channel this node does not own is
     * applied locally but its echo takes the forward-only row, so a client on
     * a non-owning node gets the numerics without ever seeing its own JOIN.
     * test_fed_loop.c joins the same way for the same reason. */
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "JOIN %s never completed", chan);
}
static void drain(test_client_t *c)
{
    TF_CHECK_MSG(tc_send(c, "PING :drain") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG", T_IO_MS) == 0, "no drain PONG");
}

/* The mesh every case stands on. Spawns the star, links it, registers one
 * client per node and joins all three to #T with alice first so A owns it. */
static void setup_star(nf_node_t *a, nf_node_t *b, nf_node_t *c,
                       test_client_t *alice, test_client_t *bob,
                       test_client_t *carol)
{
    peer_cfg_t a_peers[2];

    set_peers(NULL, 0);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b->port > 0, "node B reported no port");
    TF_CHECK_MSG(nf_spawn_inline_named(c, NAME_C, child_setup) == 0,
                 "could not spawn node C");
    TF_CHECK_MSG(c->port > 0, "node C reported no port");

    a_peers[0].name = NAME_B;
    a_peers[0].port = b->port;
    a_peers[1].name = NAME_C;
    a_peers[1].port = c->port;
    set_peers(a_peers, 2);
    TF_CHECK_MSG(nf_spawn_inline_named(a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    TF_CHECK_MSG(nf_expect(a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "A never linked B: %s", a->out);
    TF_CHECK_MSG(nf_expect(b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "B never linked A: %s", b->out);
    TF_CHECK_MSG(nf_expect(a, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "A never linked C: %s", a->out);
    TF_CHECK_MSG(nf_expect(c, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "C never linked A: %s", c->out);

    register_caps(alice, a->port, "alice", NULL);
    register_caps(bob, b->port, "bob", CAP_SETNAME " " CAP_INVITE_NOTIFY);
    register_caps(carol, c->port, "carol",
                  CAP_SETNAME " " CAP_AWAY_NOTIFY " " CAP_USERHOST_IN_NAMES " "
                      CAP_INVITE_NOTIFY);

    join_chan(alice, CHAN);
    join_chan(bob, CHAN);
    join_chan(carol, CHAN);

    /* Every node has seen every member's SJOIN before any case measures
     * anything, so a missing notification below is the verb's fault and not
     * the fixture's. */
    TF_CHECK_MSG(nf_expect(b, "fed_sjoin: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "B never learned carol's SJOIN: %s", b->out);
    TF_CHECK_MSG(nf_expect(c, "fed_sjoin: channel=" CHAN " member=bob",
                           T_IO_MS) == 0,
                 "C never learned bob's SJOIN: %s", c->out);
    drain(alice);
    drain(bob);
    drain(carol);
}

static void teardown_star(nf_node_t *a, nf_node_t *b, nf_node_t *c,
                          test_client_t *alice, test_client_t *bob,
                          test_client_t *carol)
{
    tc_close(alice);
    tc_close(bob);
    tc_close(carol);
    TF_CHECK_MSG(nf_stop(a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(c) == 0, "node C did not exit cleanly");
    nf_free(a);
    nf_free(b);
    nf_free(c);
}

/* 1. The 353 on the third node draws the live-joined member whole. */
static void case_sjoin_carries_hostmask(void)
{
    nf_node_t a, b, c;
    test_client_t alice, bob, carol;

    setup_star(&a, &b, &c, &alice, &bob, &carol);

    TF_CHECK_MSG(tc_send(&carol, "NAMES " CHAN) == 0, "NAMES send failed");
    TF_CHECK_MSG(tc_expect(&carol, "bob!bob@127.0.0.1", T_IO_MS) == 0,
                 "carol's 353 has no hostmask for the member C learned from a "
                 "live SJOIN, so the SJOIN did not carry user+host.\n"
                 "  carol saw: %s",
                 tc_buffer(&carol));

    teardown_star(&a, &b, &c, &alice, &bob, &carol);
}

/* 2. A realname change on B arrives on C. */
static void case_setname_federates(void)
{
    nf_node_t a, b, c;
    test_client_t alice, bob, carol;

    setup_star(&a, &b, &c, &alice, &bob, &carol);

    TF_CHECK_MSG(tc_send(&bob, "SETNAME :Bobby Tables") == 0,
                 "bob's SETNAME send failed");
    TF_CHECK_MSG(tc_expect(&carol, ":bob!bob@127.0.0.1 SETNAME :Bobby Tables",
                           T_IO_MS) == 0,
                 "carol never saw bob's SETNAME, so SSETNAME did not cross the "
                 "mesh.\n  carol saw: %s",
                 tc_buffer(&carol));
    TF_CHECK_MSG(nf_expect(&c, "fed_ssetname: server=" NAME_A " nick=bob",
                           T_IO_MS) == 0,
                 "node C never applied the SSETNAME: %s", c.out);

    teardown_star(&a, &b, &c, &alice, &bob, &carol);
}

/* 3. Both away edges on B arrive on C. */
static void case_away_federates(void)
{
    nf_node_t a, b, c;
    test_client_t alice, bob, carol;

    setup_star(&a, &b, &c, &alice, &bob, &carol);

    TF_CHECK_MSG(tc_send(&bob, "AWAY :going to lunch") == 0,
                 "bob's AWAY send failed");
    TF_CHECK_MSG(tc_expect(&carol, ":bob!bob@127.0.0.1 AWAY " CHAN
                                  " :going to lunch",
                           T_IO_MS) == 0,
                 "carol never saw bob go away, so the SAWAY did not cross the "
                 "mesh.\n  carol saw: %s",
                 tc_buffer(&carol));
    TF_CHECK_MSG(nf_expect(&c, "fed_saway: server=" NAME_A " nick=bob",
                           T_IO_MS) == 0,
                 "node C never applied the SAWAY: %s", c.out);

    TF_CHECK_MSG(tc_send(&bob, "AWAY") == 0, "bob's AWAY clear send failed");
    TF_CHECK_MSG(tc_expect(&carol, ":bob!bob@127.0.0.1 AWAY " CHAN "\r\n",
                           T_IO_MS) == 0,
                 "carol never saw bob come back, so the cleared SAWAY did not "
                 "cross the mesh.\n  carol saw: %s",
                 tc_buffer(&carol));

    teardown_star(&a, &b, &c, &alice, &bob, &carol);
}

/* 4. The owner's invite on A reaches the members on B and C through SINVITE. */
static void case_invite_federates(void)
{
    nf_node_t a, b, c;
    test_client_t alice, bob, carol, dave;

    setup_star(&a, &b, &c, &alice, &bob, &carol);

    /* INVITE names a LOCAL user here: a bare nick resolves only on its own
     * node. (A `nick@server` names a remote user and is covered by the next
     * case.) The invitee is dave, who is registered on A and is on no
     * channel. What federates is the notify to the channel's members on the
     * other nodes. */
    register_caps(&dave, a.port, "dave", NULL);
    drain(&dave);

    /* alice created #T on A, so she holds +o there and may invite. */
    TF_CHECK_MSG(tc_send(&alice, "INVITE dave " CHAN) == 0,
                 "alice's INVITE send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 341 ", T_IO_MS) == 0,
                 "alice got no 341, so the INVITE never left A: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(tc_expect(&dave, ":alice!alice@127.0.0.1 INVITE dave " CHAN,
                           T_IO_MS) == 0,
                 "dave never saw alice's INVITE on the originating node: %s",
                 tc_buffer(&dave));
    /* One copy each, through the SINVITE: carol and bob are members on the
     * other nodes and both negotiated invite-notify. */
    TF_CHECK_MSG(tc_expect(&carol, ":alice!alice@127.0.0.1 INVITE dave " CHAN,
                           T_IO_MS) == 0,
                 "carol never saw alice's INVITE, so the SINVITE did not cross "
                 "the mesh.\n  carol saw: %s",
                 tc_buffer(&carol));
    TF_CHECK_MSG(tc_expect(&bob, ":alice!alice@127.0.0.1 INVITE dave " CHAN,
                           T_IO_MS) == 0,
                 "bob never saw alice's INVITE, so B did not notify from the "
                 "SINVITE.\n  bob saw: %s",
                 tc_buffer(&bob));
    TF_CHECK_MSG(nf_expect(&b, "fed_sinvite: server=" NAME_A
                               " channel=" CHAN " target=dave",
                           T_IO_MS) == 0,
                 "node B never relayed the SINVITE: %s", b.out);

    tc_close(&dave);
    teardown_star(&a, &b, &c, &alice, &bob, &carol);
}

/* 5. INVITE to a `nick@server` reaches the invitee on their own node (#664). */
static void case_invite_remote_user(void)
{
    nf_node_t a, b, c;
    test_client_t alice, bob, carol;

    setup_star(&a, &b, &c, &alice, &bob, &carol);

    /* alice owns #T on A; carol is registered on C and the mesh roster holds
     * her at irc.c, so A resolves `carol@irc.c` to a route instead of 401. */
    TF_CHECK_MSG(tc_send(&alice, "INVITE carol@irc.c " CHAN) == 0,
                 "alice's INVITE send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 341 ", T_IO_MS) == 0,
                 "alice got no 341, so the remote INVITE was refused: %s",
                 tc_buffer(&alice));
    /* The invitee's own copy, delivered on C from the SINVITE -- the same
     * `:inviter INVITE <target> <channel>` shape a local invite carries. */
    TF_CHECK_MSG(tc_expect(&carol, ":alice!alice@127.0.0.1 INVITE carol " CHAN,
                           T_IO_MS) == 0,
                 "carol never saw alice's INVITE, so the SINVITE did not "
                 "deliver it on C.\n  carol saw: %s",
                 tc_buffer(&carol));
    TF_CHECK_MSG(nf_expect(&c, "fed_sinvite: server=" NAME_A
                               " channel=" CHAN " target=carol",
                           T_IO_MS) == 0,
                 "node C never applied the SINVITE: %s", c.out);
    drain(&alice);
    TF_CHECK_MSG(strstr(tc_buffer(&alice), " 401 ") == NULL,
                 "alice was answered 401 for a held remote nick: %s",
                 tc_buffer(&alice));

    teardown_star(&a, &b, &c, &alice, &bob, &carol);
}

/* 6. A 0.1.0 FEDERATE is refused before it can misparse the new shapes. */
static void case_old_version_refused(void)
{
    nf_node_t a;
    test_client_t old;
    char line[512];

    set_peers(NULL, 0);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    tc_init(&old);
    TF_CHECK_MSG(tc_connect(&old, a.port) == 0,
                 "the test could not open a connection to node A");
    /* The version word is a literal on purpose: it names the build this node
     * must refuse, and spelling it as the header's macro would make the case
     * pass by sending the current version. */
    (void)snprintf(line, sizeof line, ":irc.old FEDERATE irc.old 1700000000 %s %s",
                   SECRET, OLD_VERSION);
    TF_CHECK_MSG(tc_send(&old, line) == 0, "the test could not send FEDERATE");

    TF_CHECK_MSG(nf_expect(&a, "link_rejected: peer=irc.old reason=BAD_VERSION",
                           T_IO_MS) == 0,
                 "a 0.1.0 FEDERATE was not refused with BAD_VERSION: %s", a.out);
    TF_CHECK_MSG(strstr(a.out, "link_established: peer=irc.old") == NULL,
                 "the old-version link was established anyway: %s", a.out);

    tc_close(&old);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    nf_free(&a);
}

int main(void)
{
    case_sjoin_carries_hostmask();
    case_setname_federates();
    case_away_federates();
    case_invite_federates();
    case_invite_remote_user();
    case_old_version_refused();
    tf_done("fed_notify");
    return 0;
}
