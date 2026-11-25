/* test_splitbrain_refuse.c -- issue #676: partitioned JOIN-creates are refused.
 *
 * docs/SERVER_DESIGN.md 2.2 (fail-closed creation): while a peer link that was
 * up is down again, a JOIN that would create a channel is refused with 437,
 * because the far side may have created the same name while unreachable and
 * the resync has no verdict for that collision (origin is immutable). Creating
 * anyway would fork the name into two channels that never converge.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE
 * ---------------------------------------------------------------------------
 *   1. A link that was ESTABLISHED and then died refuses a later JOIN-create
 *      with 437 -- the orphan rule extended to creation. The death is real
 *      (a frozen peer and the node's own T4), not a flag set by the test.
 *   2. The refusal leaves nothing behind: no JOIN echo, and NAMES afterwards
 *      terminates an empty list (366) with no roster (353).
 *   3. The node's own account names the reason: `chan_create_refused ...
 *      reason=PARTITIONED`, and no `chan_create:` line for the name.
 *   4. An own-origin channel that empties while partitioned is HELD, so a
 *      re-JOIN revives it instead of drawing 437 -- without this, the
 *      refusal would drain every channel that flapped into nothing.
 *   5. The vacated shell nobody revived is collected by the establishment
 *      sweep once the mesh is whole (and the revived one is kept).
 *   6. The exemption: a node whose peer was only ever configured (never
 *      ESTABLISHED) still creates on JOIN. Fail-closed covers a real
 *      partition, not a peer that was never reached.
 *
 * ---------------------------------------------------------------------------
 * WHY A FROZEN PEER, NOT A KILLED ONE
 * ---------------------------------------------------------------------------
 * For the reason test_sync_state.c gives: a killed peer sends a FIN and the
 * survivor observes a closed connection rather than silence. T4 exists to
 * notice silence, and the partition this test needs is silence, so the peer
 * is frozen with SIGSTOP and resumed before the stop.
 *
 * NO fixed sleep anywhere (6.3): every wait is a deadline over a socket or
 * over a child's output.
 */
#include <netinet/in.h>
#include <signal.h>
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

#define T_IO_MS 20000

#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define NAME_GHOST "irc.ghost"

#define CHAN "#SPLITBRAIN"
#define CHAN_KEEP "#REVIVE"
#define CHAN_SWEEP "#SWEEP"

/* The liveness pair, the shipped three-to-one relationship written out so the
 * test's numbers and IRC_FED_DEAD_MS cannot drift apart silently. Shortened
 * like test_sync_state.c, because the shipped 90 s dead threshold would make a
 * partition test take minutes rather than seconds. */
#define KEEPALIVE_MS 200
#define DEAD_MS (3 * KEEPALIVE_MS)

/* The retry scale, shortened like test_sync_state.c: only one reconnect-free
 * interval matters here (the link must stay down while the JOIN is refused). */
#define RETRY_BASE_MS 300
#define RETRY_MAX_MS 1200
#define RETRY_BUDGET 8

/* A port nothing listens on: connect() is refused, so the link never leaves
 * INIT. Even if something did listen, the handshake would fail on the secret
 * and the link would still never be ESTABLISHED. */
#define GHOST_PORT 1

typedef struct {
    const char *peer_name; /* NULL: no peer configured */
    int         peer_port;
} child_cfg_t;

static child_cfg_t g_cfg;

static void child_setup(server_t *s)
{
    struct sockaddr_in addr;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, "splitbrain-secret") == 0,
                 "fed_open() failed in the child");
    s->on_tick = fed_tick;
    fed_set_timeouts(s, 2000, 2000, KEEPALIVE_MS, DEAD_MS);
    fed_set_retry(s, RETRY_BASE_MS, RETRY_MAX_MS, RETRY_BUDGET);

    if (g_cfg.peer_name != NULL) {
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_cfg.peer_port);
        TF_CHECK_MSG(fed_link_configure(s, g_cfg.peer_name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_cfg.peer_name, g_cfg.peer_port);
    }
}

static void register_client(test_client_t *c, int port, const char *nick,
                            const char *token)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's drain PING send failed", nick);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s got no PONG carrying its drain token", nick);
}

/* A PING round-trip behind everything queued on the connection, so an absence
 * asserted afterwards is about processed commands rather than about the
 * parent's read schedule. */
static void drain(test_client_t *c, const char *token)
{
    char line[128];

    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the drain PING for %s failed to send",
                 token);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG carrying the drain token %s", token);
}

static void case_partitioned_create_refused(void)
{
    nf_node_t a;
    nf_node_t b;
    nf_node_t p;
    test_client_t keeper;
    test_client_t sweeper;
    test_client_t survivor;
    test_client_t ghost;
    size_t mark;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    memset(&p, 0, sizeof p);

    /* --- the pair: B dials A, so B is the initiator and the one that will
     * declare the link dead when A goes silent. --- */
    memset(&g_cfg, 0, sizeof g_cfg);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");
    g_cfg.peer_name = NAME_A;
    g_cfg.peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never accepted the link from node B: %s", a.out);
    /* --- own channels, created while the mesh is whole: #REVIVE stays
     * occupied through the partition, #SWEEP is vacated during it. --- */
    register_client(&keeper, b.port, "keeper", "reg-keeper");
    TF_CHECK_MSG(tc_send(&keeper, "JOIN " CHAN_KEEP) == 0,
                 "the keeper's JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&keeper, " 366 ", T_IO_MS) == 0,
                 "the keeper never completed its JOIN while the link was up, "
                 "so the revive claim below would be about nothing: %s",
                 tc_buffer(&keeper));
    register_client(&sweeper, b.port, "sweeper", "reg-sweeper");
    TF_CHECK_MSG(tc_send(&sweeper, "JOIN " CHAN_SWEEP) == 0,
                 "the sweeper's JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&sweeper, " 366 ", T_IO_MS) == 0,
                 "the sweeper never completed its JOIN while the link was up: "
                 "%s",
                 tc_buffer(&sweeper));

    /* --- the partition: A goes silent, and B says so itself. --- */
    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");
    TF_CHECK_MSG(nf_expect(&b, "link_dead: peer=" NAME_A " silent_ms=",
                           T_IO_MS) == 0,
                 "node B did not notice that node A had gone silent, so the "
                 "JOIN below would run against a link that is still up: %s",
                 b.out);

    /* --- claim 1: the same JOIN that would have created now draws 437. --- */
    register_client(&survivor, b.port, "kept", "reg-kept");
    TF_CHECK_MSG(tc_send(&survivor, "JOIN " CHAN) == 0,
                 "the survivor's JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&survivor, " 437 ", T_IO_MS) == 0,
                 "the partitioned node created " CHAN " instead of refusing "
                 "it with 437 -- the split-brain fork of issue #676: %s",
                 tc_buffer(&survivor));

    /* --- claim 2: the refusal left nothing behind. --- */
    drain(&survivor, "drain-after-437");
    TF_CHECK_MSG(strstr(tc_buffer(&survivor), "JOIN " CHAN) == NULL,
                 "the refused JOIN still produced a JOIN echo, so the client "
                 "is on a channel the node refused to manage: %s",
                 tc_buffer(&survivor));
    mark = tc_received(&survivor);
    TF_CHECK_MSG(tc_send(&survivor, "NAMES " CHAN) == 0,
                 "the NAMES probe could not be sent");
    TF_CHECK_MSG(tc_expect(&survivor, " 366 ", T_IO_MS) == 0,
                 "NAMES of the refused channel never terminated: %s",
                 tc_buffer(&survivor));
    TF_CHECK_MSG(strstr(tc_buffer(&survivor) + mark, " 353 ") == NULL,
                 "the refused creation left a channel behind: NAMES of " CHAN
                 " lists members: %s",
                 tc_buffer(&survivor));

    /* --- claim 3: the node's own account of the refusal. --- */
    TF_CHECK_MSG(nf_expect(&b, "chan_create_refused: channel=" CHAN,
                           T_IO_MS) == 0,
                 "node B never logged the refused creation: %s", b.out);
    TF_CHECK_MSG(strstr(b.out, "reason=PARTITIONED") != NULL,
                 "the refused creation was logged under the wrong reason: %s",
                 b.out);
    TF_CHECK_MSG(strstr(b.out, "chan_create: channel=" CHAN) == NULL,
                 "node B created " CHAN " after refusing it: %s", b.out);
    /* --- claim 4: an own channel that empties while partitioned is held, so
     * a re-JOIN revives it instead of drawing 437. --- */
    TF_CHECK_MSG(tc_send(&keeper, "PART " CHAN_KEEP) == 0,
                 "the keeper's PART could not be sent");
    drain(&keeper, "drain-after-part");
    mark = tc_received(&keeper);
    TF_CHECK_MSG(tc_send(&keeper, "JOIN " CHAN_KEEP) == 0,
                 "the keeper's re-JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&keeper, " JOIN " CHAN_KEEP "\r\n", T_IO_MS) == 0,
                 "the keeper's re-JOIN of its own channel was not revived "
                 "while partitioned -- the disposal delay is broken: %s",
                 tc_buffer(&keeper));
    TF_CHECK_MSG(tc_expect(&keeper, " 366 ", T_IO_MS) == 0,
                 "the revived JOIN never completed: %s", tc_buffer(&keeper));
    TF_CHECK_MSG(strstr(tc_buffer(&keeper) + mark, " 437 ") == NULL,
                 "the re-JOIN of a held own channel drew 437: %s",
                 tc_buffer(&keeper));

    /* --- claim 5: the vacated shell nobody revived is collected once the
     * mesh is whole again. --- */
    TF_CHECK_MSG(tc_send(&sweeper, "PART " CHAN_SWEEP) == 0,
                 "the sweeper's PART could not be sent");
    drain(&sweeper, "drain-after-sweep-part");
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");
    TF_CHECK_MSG(nf_expect_nth(&b, "link_established: peer=" NAME_A, 2u,
                               T_IO_MS) == 0,
                 "node B's link to node A never came back, so the sweep below "
                 "would be about a mesh that is still partitioned: %s", b.out);
    TF_CHECK_MSG(nf_expect(&b, "chan_destroy: channel=" CHAN_SWEEP,
                           T_IO_MS) == 0,
                 "the establishment sweep never collected the vacated shell: "
                 "%s",
                 b.out);
    TF_CHECK_MSG(strstr(b.out, "chan_destroy: channel=" CHAN_KEEP) == NULL,
                 "the sweep destroyed the revived channel it must keep: %s",
                 b.out);

    /* --- claim 6, the exemption: a peer that was never reached is not a
     * partition, so creation there still works. --- */
    g_cfg.peer_name = NAME_GHOST;
    g_cfg.peer_port = GHOST_PORT;
    TF_CHECK_MSG(nf_spawn_inline_named(&p, "irc.part", child_setup) == 0,
                 "could not spawn the never-linked node");
    register_client(&ghost, p.port, "fresh", "reg-fresh");
    TF_CHECK_MSG(tc_send(&ghost, "JOIN " CHAN) == 0,
                 "the never-linked client's JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&ghost, " 366 ", T_IO_MS) == 0,
                 "the never-linked node refused a JOIN-create with no "
                 "partition behind it, so the exemption is broken: %s",
                 tc_buffer(&ghost));
    TF_CHECK_MSG(strstr(p.out, "reason=PARTITIONED") == NULL,
                 "the never-linked node logged a partition refusal it should "
                 "never have drawn: %s",
                 p.out);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&p) == 0, "the never-linked node did not exit cleanly");
    tc_close(&keeper);
    tc_close(&sweeper);
    tc_close(&survivor);
    tc_close(&ghost);
    nf_free(&a);
    nf_free(&b);
    nf_free(&p);
}

int main(void)
{
    case_partitioned_create_refused();
    tf_done("splitbrain_refuse");
    return 0;
}
