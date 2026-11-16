/* test_shutdown_drain.c -- MT 3.1 (#290): the shutdown drain holds wq_lock.
 *
 * fed_send_shutdown() drains each ESTABLISHED peer's receive queue through
 * transport_recv(). On a TLS link that is SSL_read on the conn's SSL*, and
 * OpenSSL forbids concurrent use of one SSL* -- so at N > 0 a writer's
 * SSL_write on the same conn would race the drain and corrupt the SSL state
 * or crash inside libssl. The fix is one lock: the drain holds c->wq_lock,
 * the same contract conn_fill() and conn_pump() already keep.
 *
 * The regression shape: two linked inline nodes, A with writer_threads = 4,
 * B streaming channel traffic at A while A shuts down. Under TSan at N=4 a
 * missing lock is a data race on the transport state; a crash is the louder
 * form. The build under test is plaintext (ci_tsan is WITH_TLS=OFF), so this
 * exercises the same locked code path rather than a real SSL* -- the lock
 * is transport-agnostic and the race it closes is structural, not
 * TLS-gated: without the lock the drain's transport_recv runs concurrent
 * with writers' conn_pump on the same conn with no serialization at all.
 *
 * NO FIXED sleep() (6.3): streams and stops are deadline-driven, and the
 * link precondition is nf_expect() on link_established.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define SECRET "irc-serve-shutdown-drain-secret"
#define NAME_A "irc.a"
#define NAME_B "irc.b"

static int g_peer_port;
static int g_writers;

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
    if (g_writers > 0) {
        server_set_writer_threads(s, g_writers);
    }
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
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
}

int main(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t on_a;
    test_client_t on_b;
    char line[256];
    int i;
    int rc_a;

    /* Node A first: accepting side, writers ON. The IRC_WRITERS=N=4 suite
     * pass overrides this anyway; the explicit 4 is what makes THIS test
     * exercise the race even at N=0 defaults. */
    g_peer_port = 0;
    g_writers = 4;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    /* Node B dials A; no writers, single-threaded. */
    g_peer_port = a.port;
    g_writers = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);

    /* Flood A's link receive queue: clients on opposite ends of one channel,
     * so B's client streaming PRIVMSG puts unread bytes on A's link socket
     * while A's writers may be pumping it. */
    register_client(&on_a, a.port, "watcher");
    register_client(&on_b, b.port, "streamer");
    TF_CHECK_MSG(tc_send(&on_a, "JOIN #drain") == 0, "watcher's JOIN failed");
    TF_CHECK_MSG(tc_expect(&on_a, " 366 ", T_IO_MS) == 0,
                 "the watcher's JOIN never completed");
    TF_CHECK_MSG(tc_send(&on_b, "JOIN #drain") == 0, "streamer's JOIN failed");
    TF_CHECK_MSG(tc_expect(&on_b, " 366 ", T_IO_MS) == 0,
                 "the streamer's JOIN never completed");

    for (i = 0; i < 200; i++) {
        (void)snprintf(line, sizeof line, "PRIVMSG #drain :stream-%d", i);
        if (tc_send(&on_b, line) != 0) {
            break;
        }
    }
    /* STRUCTURAL HALF, and it is needed because the runtime half above cannot
     * observe the race on this build: ci_tsan is WITH_TLS=OFF, so no SSL*
     * exists to corrupt, and an unlocked drain passes the runtime sequence
     * (verified by stashing the fix). The property is a property of the
     * code's shape -- the drain's transport_recv runs under c->wq_lock -- so
     * looking is the check, the same move test_close_sites.c makes. find the
     * drain in fed_send_shutdown() and require a wq_lock lock between the
     * function and the drain loop and an unlock after the block. */
    {
        char code[TF_SRC_MAX];
        size_t len = 0;
        long got = tf_read_code_into(code, sizeof code,
                                     "src/federation/link.c", &len);
        const char *fn;
        const char *drain;
        const char *lock;
        const char *unlock;

        TF_CHECK_MSG(got >= 0,
                     "could not read src/federation/link.c (is "
                     "IRCSERVE_SRC_DIR set?)");
        fn = strstr(code, "fed_send_shutdown(server_t");
        TF_CHECK_MSG(fn != NULL,
                     "could not find fed_send_shutdown() in link.c");
        drain = strstr(fn, "transport_recv(c, sink, sizeof sink)");
        TF_CHECK_MSG(drain != NULL,
                     "could not find the shutdown drain's transport_recv in "
                     "link.c");
        lock = strstr(fn, "pthread_mutex_lock(&c->wq_lock)");
        TF_CHECK_MSG(lock != NULL && lock < drain,
                     "the shutdown drain does not run under c->wq_lock: "
                     "transport_recv on a TLS link is SSL_read, and at N > 0 "
                     "a writer's SSL_write on the same SSL* without the "
                     "caller-holds lock is corruption or a crash (#290)");
        unlock = strstr(drain, "pthread_mutex_unlock(&c->wq_lock)");
        TF_CHECK_MSG(unlock != NULL,
                     "the shutdown drain takes c->wq_lock and never releases "
                     "it: the next line on that conn would deadlock");
    }

    /* Shutdown while the peer is streaming: A's fed_send_shutdown() drains
     * the link under wq_lock while its 4 writers may be pumping the same
     * conn. A race here is a TSan failure or a crash, not a wrong counter. */
    rc_a = nf_stop(&a);
    TF_CHECK_MSG(rc_a == 0, "node A did not exit cleanly under writer load");
    TF_CHECK_MSG(nf_expect(&a, "fed_shutdown_sent:", T_IO_MS) == 0,
                 "node A sent no SHUTDOWN goodbye on the way out: %s", a.out);

    tc_close(&on_a);
    tc_close(&on_b);
    (void)nf_stop(&b);
    nf_free(&a);
    nf_free(&b);
    tf_done("shutdown_drain");
    return 0;
}
