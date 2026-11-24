/* test_fed_incr_resync.c -- #541: a flap must not replay a burst the peer holds.
 *
 * docs/SERVER_DESIGN.md 4.3 ("A resync REPLACES state for that origin") and the
 * #541 finding: every link-up replays all nicks/channels/memberships, so a
 * flapping link re-sends thousands of lines each time onto the receiving loop
 * thread. The fix is an acknowledged resync: the sender fingerprints what a
 * burst would render, the receiver acks the BEGIN id it committed, and a later
 * resync whose fingerprint still matches under the same epochs sends nothing.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE PROVES
 * ---------------------------------------------------------------------------
 *   1. A resync after a state change sends in full, and the peer applies it.
 *      (The skip must not fire when the fingerprint moved.)
 *   2. A resync with no intervening change sends nothing: the sender prints
 *      fed_burst_skipped, counts n_burst_skipped, and the peer applies nothing
 *      new. (The thousands of lines stay unsent.)
 *   3. The mesh still converges after a skip: a later change resyncs in full
 *      again, and the peer applies it. (A skip is not a wedge.)
 * The acks both directions take are asserted by presence (fed_burstack_sent /
 * fed_burstack_applied): a skip without an ack would be optimism, and the
 * test would be asserting the shape of the log rather than the mechanism.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURE
 * ---------------------------------------------------------------------------
 * Two nodes, like the establishment half of test_fed_burst.c: A accepts, B
 * dials A. Only A ever holds clients. The resyncs are driven from A's own
 * tick hook through the product function, gated on state the parent creates:
 *
 *   resync #1   alice is a local member of #T on A (the parent's JOIN)
 *   resync #2   A's link has acked resync #1 (the peer's SBURSTACK, in-child)
 *   resync #3   A holds two nicks (the parent registers eve, who never joins)
 *
 * The gates are all in-child state rather than ticks or sleeps, for the reason
 * test_fed_burst.c gives: a forked child cannot see anything the parent writes
 * after the fork, so a gate has to be something the parent does ON THE WIRE.
 * #2's gate is the exception that proves the rule -- it is A's own link
 * record, which is the thing under test, and it is race-free because the tick
 * that checks it is the tick that fires the resync.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/channel.h"
#include "core/commands.h"
#include "core/server.h"
#include "federation/burst.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define CHAN_T "#T"
#define NICK_A "alice"
#define NICK_E "eve"

/* PRE-FORK STATE. The parent writes g_peer_port from A's reported port between
 * the two spawns; 0 means "configure no peer", which is how node A is set up. */
static int g_peer_port;
static int g_is_b;

/* The resyncs node A has already driven. */
static int g_stage;

static void child_tick(server_t *s, uint64_t now_ms);
static void offer_resync(server_t *s);

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
    offer_resync(s);
}

/* The driver: three resyncs, each gated on the state that makes it meaningful.
 * Node B drives none -- B holds no clients, so B has nothing whose resync
 * would differ from its establishment burst. */
static void offer_resync(server_t *s)
{
    server_link_t *link;
    chan_t *ch;

    if (g_is_b != 0) {
        return;
    }
    link = server_find_link(s, NAME_B);
    if (link == NULL) {
        return;
    }
    if (g_stage == 0) {
        ch = server_chan_get(s, CHAN_T);
        if (ch == NULL || ch->nmembers == 0u) {
            return; /* alice has not JOINed yet */
        }
        g_stage = 1;
        if (federation_resync(s, link) == 0) {
            printf("[fixture] resync_offered: stage=1\n");
        } else {
            printf("[fixture] resync_refused: stage=1\n");
        }
        fflush(stdout);
        return;
    }
    if (g_stage == 1) {
        /* THE ACK GATE: the peer has confirmed the burst above, so what it
         * holds is what the fingerprint below will describe. Firing before
         * the ack would be a correct full send rather than a skip, and the
         * case would be waiting on a line that never comes. */
        if (link->burst_valid == 0 ||
            link->burst_ack_id != link->burst_begin_id) {
            return;
        }
        g_stage = 2;
        if (federation_resync(s, link) == 0) {
            printf("[fixture] resync_offered: stage=2 skipped=%llu\n",
                   (unsigned long long)s->n_burst_skipped);
        } else {
            printf("[fixture] resync_refused: stage=2\n");
        }
        fflush(stdout);
        return;
    }
    if (g_stage == 2) {
        if (server_nick_count(s) < 2u) {
            return; /* eve has not registered yet */
        }
        g_stage = 3;
        if (federation_resync(s, link) == 0) {
            printf("[fixture] resync_offered: stage=3\n");
        } else {
            printf("[fixture] resync_refused: stage=3\n");
        }
        fflush(stdout);
        return;
    }
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child");
    s->on_tick = child_tick;
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);

    if (g_peer_port <= 0) {
        return; /* the accepting side; the inbound claim configures its link */
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
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
}

static void case_skip_acked_resync(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t eve;

    g_peer_port = 0;
    g_is_b = 0;
    g_stage = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_sent: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never burst on establishment: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_sent: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never burst on establishment: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never applied a burst from node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied a burst from node A: %s", b.out);

    register_client(&alice, a.port, NICK_A);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN_T " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never learned about alice: %s", b.out);

    /* Resync #1: the fingerprint moved (alice + #T), so this is a FULL burst
     * carrying one nick, one channel and one member -- not the establishment
     * burst's zeros, which is what tells the two apart. */
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=1", T_IO_MS) == 0,
                 "node A never drove the post-JOIN resync: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "nicks=1 chans=1 members=1", T_IO_MS) == 0,
                 "node B never applied the post-JOIN burst: %s", b.out);

    /* Resync #2: nothing changed, so NOTHING goes out. The ack is the proof
     * the mechanism ran rather than the shape of one log line: B sent one
     * when it committed, and A recorded it. */
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=2 skipped=1", T_IO_MS)
                 == 0,
                 "node A never skipped the unchanged resync: %s", a.out);
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_skipped: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never reported the skip: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burstack_sent: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never acked a burst: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "fed_burstack_applied: peer=" NAME_B, T_IO_MS)
                 == 0,
                 "node A never recorded a burst ack: %s", a.out);
    /* AND THE PEER APPLIED EXACTLY TWO bursts from A -- establishment plus
     * resync #1 -- so the skip put no third transaction on the wire. */
    TF_CHECK_MSG(nf_expect_nth(&b, "fed_burst_applied: peer=" NAME_A, 2u,
                               T_IO_MS) == 0,
                 "node B did not apply exactly two bursts from node A: %s",
                 b.out);

    /* Resync #3: a new nick moves the fingerprint, so the burst goes out in
     * full again -- the skip wedged nothing. */
    register_client(&eve, a.port, NICK_E);
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=3", T_IO_MS) == 0,
                 "node A never drove the post-eve resync: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "nicks=2 chans=1 members=1", T_IO_MS) == 0,
                 "node B never applied the post-eve burst: %s", b.out);
    TF_CHECK_MSG(nf_expect_nth(&b, "fed_burst_applied: peer=" NAME_A, 3u,
                               T_IO_MS) == 0,
                 "node B did not apply a third burst after the change: %s",
                 b.out);

    tc_close(&alice);
    tc_close(&eve);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_skip_acked_resync();
    tf_done("fed_incr_resync");
    return 0;
}
