/* test_writers_tls_417.c -- N=4 coverage for the two writer interactions that
 * only run single-threaded in tests today (issue #282). Tests only: no
 * product code is touched, and the two cases below exercise the shipped paths
 * rather than reimplementing them.
 *
 * Case 1, TLS pending-drain with writers: two implicit-TLS clients on one
 * node started with `--writers 4`, each sending a 64KiB multi-record burst.
 * The burst arrives as several TLS records, so the fill path must loop on
 * SSL_pending() while writer threads pump the replies through SSL_write on
 * the same SSL* objects -- the serialization the one-SSL-one-thread contract
 * names. The oracle is byte-exact: every PONG arrives exactly once on each
 * client, which a corrupted OpenSSL state cannot produce. A race itself is
 * TSan's to report under the ci_tsan job; this file's job is to make the
 * racy interleaving happen. Runs only when TLS is compiled in, and says so
 * rather than skipping: the plaintext build still runs case 2.
 *
 * Case 2, 417-flush-deferred-to-writers: a flooder at N=4 whose 4KiB receive
 * buffer cannot absorb the ~100KiB of queued PONGs, so a writer pump
 * necessarily comes up short (partial_writes) while the CLOSING mark waits
 * on the drain -- the 417 arrives before the EOF. No fixed sleeps anywhere:
 * every wait is a deadline wait.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/connection.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

#define T_IO_MS 30000
/* Deferred-close waits (cases 2a/2b): the reaper defers a CLOSING conn with
 * queued bytes until the writers drain it or the 2 s deadline lands, so on
 * a loaded runner these waits outlast the drain round-trips (4 KiB server
 * sndbuf against ~105 KiB of queued PONGs) and the reaper's own ticks.
 * Observed stalls to ~35 s on macOS Release -j2; 120 s absorbs them the way
 * FLOOD_IO_MS does for the 8k-record refusal (#330). ctest's 60 s cap bounds
 * the actual wait, so a stall past that still goes red as a Timeout. */
#define T_CLOSE_MS 120000
#define T_BURST_PINGS 160
#define T_FLOOD_LINES 300
#define T_TOKEN_LEN 400
#define T_RCVBUF 4096

#define TF_DIR_MAX 512
#define TF_PATH (TF_DIR_MAX + 128)

/* ---------------------------------------------------------------------------
 * Shared helpers
 * ---------------------------------------------------------------------------
 * A per-test directory under the build tree, so parallel ctest runs never
 * share certificate material. */
static void cert_dir(char *out, size_t cap)
{
    const char *base = getenv("IRCSERVE_BUILD_DIR");

    if (base == NULL) {
        base = "/tmp";
    }
    snprintf(out, cap, "%s/tls-writers-417-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* How many times `needle` occurs in `hay`. The PONG oracle: one occurrence
 * per reply line, so the count is the reply count. */
static int count_occurrences(const char *hay, const char *needle)
{
    size_t nlen = strlen(needle);
    int n = 0;
    const char *p = hay;

    if (nlen == 0) {
        return 0;
    }
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += nlen;
    }
    return n;
}

/* The LAST partial_writes total in the node's accumulated output. The inline
 * fixture republishes stats on counter change, and unconditionally once at
 * shutdown, so the final line is the run's total however the drain
 * interleaved. */
static int last_partial_writes(const char *out, unsigned long long *v)
{
    const char *p = out;
    const char *last = NULL;

    while ((p = strstr(p, "partial_writes=")) != NULL) {
        last = p;
        p++;
    }
    if (last == NULL) {
        return -1;
    }
    return (sscanf(last + 15, "%llu", v) == 1) ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * Case 1: TLS pending-drain with writers (issue #282, first half)
 * ---------------------------------------------------------------------------
 * Two clients, N=4, a 64KiB multi-record burst each, every PONG back exactly
 * once. Returns 0 on success. */
static int case_tls_pending_with_writers(void)
{
    char dir[TF_DIR_MAX];
    char crt[TF_PATH];
    char key[TF_PATH];
    char port0[] = "0";
    char workers[] = "4";
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.test";
    char *argv[14];
    char line[512];
    char tok_a[T_TOKEN_LEN + 1];
    char tok_b[T_TOKEN_LEN + 1];
    nf_node_t n;
    tf_tls_t a;
    tf_tls_t b;
    const char *why = NULL;
    const char *p = NULL;
    int tls_port = -1;
    int i;

    cert_dir(dir, sizeof dir);
    if (tf_tls_make_cert(dir, "srv", "irc.tls",
                         "DNS:irc.tls,IP:127.0.0.1,DNS:localhost", 0, 86400,
                         0600) != 0) {
        printf("note: no certificate generated, so no TLS handshake to race\n");
        TF_CHECK_MSG(tf_tls_available() == 0,
                     "certificate generation works exactly when TLS is "
                     "compiled in");
        return 0;
    }
    TF_CHECK_MSG(tf_tls_available() != 0,
                 "a generated certificate means TLS is compiled in");
    snprintf(crt, sizeof crt, "%s/srv.crt", dir);
    snprintf(key, sizeof key, "%s/srv.key", dir);

    argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
    argv[4] = "--tls-cert"; argv[5] = crt;
    argv[6] = "--tls-key"; argv[7] = key;
    argv[8] = "--tls-port"; argv[9] = port0;
    argv[10] = "--writers"; argv[11] = workers;
    argv[12] = NULL; argv[13] = NULL;
    TF_CHECK_MSG(nf_spawn_binary_argv(&n, argv) == 0,
                 "node with --tls-port 0 --writers 4 did not start");
    p = strstr(n.out, "tls_port=");
    if (p != NULL) {
        tls_port = atoi(p + 9);
    }
    TF_CHECK_MSG(tls_port > 0, "the implicit-TLS listener reports a port:\n%s",
                 n.out);

    tf_tls_init(&a);
    tf_tls_init(&b);
    TF_CHECK_MSG(tf_tls_connect(&a, tls_port, crt, "irc.tls", &why) == 0,
                 "first TLS handshake failed: %s", why);
    TF_CHECK_MSG(tf_tls_connect(&b, tls_port, crt, "irc.tls", &why) == 0,
                 "second TLS handshake failed: %s", why);

    TF_CHECK_MSG(tf_tls_send(&a, "NICK tls-a") == 0, "NICK failed");
    TF_CHECK_MSG(tf_tls_send(&a, "USER tls-a 0 * :A") == 0, "USER failed");
    TF_CHECK_MSG(tf_tls_expect(&a, " 001 ", T_IO_MS) == 0,
                 "first client never registered");
    TF_CHECK_MSG(tf_tls_send(&b, "NICK tls-b") == 0, "NICK failed");
    TF_CHECK_MSG(tf_tls_send(&b, "USER tls-b 0 * :B") == 0, "USER failed");
    TF_CHECK_MSG(tf_tls_expect(&b, " 001 ", T_IO_MS) == 0,
                 "second client never registered");

    /* The bursts overlap on the wire: alternating sends keep both
     * connections' records in flight while 4 writers drain both. */
    memset(tok_a, 'Q', T_TOKEN_LEN);
    tok_a[T_TOKEN_LEN] = '\0';
    memset(tok_b, 'Z', T_TOKEN_LEN);
    tok_b[T_TOKEN_LEN] = '\0';
    for (i = 0; i < T_BURST_PINGS; i++) {
        snprintf(line, sizeof line, "PING :%s", tok_a);
        TF_CHECK_MSG(tf_tls_send(&a, line) == 0, "burst send %d failed", i);
        snprintf(line, sizeof line, "PING :%s", tok_b);
        TF_CHECK_MSG(tf_tls_send(&b, line) == 0, "burst send %d failed", i);
    }
    /* Tail markers prove the full burst arrived: IRC preserves line order
     * per connection, so nothing after the marker can be missing either. */
    TF_CHECK_MSG(tf_tls_send(&a, "PING :tail-a") == 0, "tail send failed");
    TF_CHECK_MSG(tf_tls_send(&b, "PING :tail-b") == 0, "tail send failed");
    TF_CHECK_MSG(tf_tls_expect(&a, "tail-a", T_IO_MS) == 0,
                 "first client's burst never fully arrived:\n%s",
                 tf_tls_buffer(&a));
    TF_CHECK_MSG(tf_tls_expect(&b, "tail-b", T_IO_MS) == 0,
                 "second client's burst never fully arrived:\n%s",
                 tf_tls_buffer(&b));
    /* +1 each: the tail marker is itself a PING and earns its own PONG. */
    TF_CHECK_MSG(count_occurrences(tf_tls_buffer(&a), "PONG ") ==
                     T_BURST_PINGS + 1,
                 "first client got %d PONGs for %d PINGs -- a record was "
                 "dropped or duplicated",
                 count_occurrences(tf_tls_buffer(&a), "PONG "),
                 T_BURST_PINGS);
    TF_CHECK_MSG(count_occurrences(tf_tls_buffer(&b), "PONG ") ==
                     T_BURST_PINGS + 1,
                 "second client got %d PONGs for %d PINGs -- a record was "
                 "dropped or duplicated",
                 count_occurrences(tf_tls_buffer(&b), "PONG "),
                 T_BURST_PINGS);

    tf_tls_close(&a);
    tf_tls_close(&b);
    TF_CHECK_MSG(nf_stop(&n) == 0, "node did not exit cleanly");
    nf_free(&n);
    tf_tls_rmtree(dir);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Cases 2a/2b: 417-flush-deferred-to-writers at N=4 (issue #282, second half)
 * ---------------------------------------------------------------------------
 * Inline nodes with the REAL dispatch and 4 writer threads. The two halves
 * are split because they need opposite client behaviour: the short-pump
 * proof needs a client that never drains (so the backlog cannot fit the
 * socket), while the delivery proof needs one that drains everything (so
 * the 417 must arrive before the EOF). */
static int g_sndbuf_shrunk = 0;

/* Shrink the flooder's server-side send buffer, the way short-write proofs
 * do: the burst then cannot fit the kernel, so a writer pump necessarily
 * comes up short. Done on tick because the connection does not exist when
 * setup runs; the nick lookup is exact and the flag makes it once-only per
 * node. */
static void writers_tick(server_t *s, uint64_t now_ms)
{
    (void)now_ms;
    if (g_sndbuf_shrunk == 0 && s != NULL) {
        conn_t *c = server_nick_lookup(s, "flooder");

        if (c != NULL && c->fd >= 0) {
            int small = T_RCVBUF;

            (void)setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &small,
                             sizeof small);
            g_sndbuf_shrunk = 1;
        }
    }
}

static void writers_setup(server_t *s)
{
    s->dispatch = commands_dispatch;
    server_set_writer_threads(s, 4);
    s->on_tick = writers_tick;
    g_sndbuf_shrunk = 0;
}
/* The short pump, proved without reading a byte. The flooder's server send
 * buffer is shrunk on tick, so the ~100KiB of queued PONGs stay queued, the
 * client never drains them, the reaper must defer the close -- and every
 * writer visit in that window leaves a remainder. The wait is node-side (the
 * reaped line, then the shutdown totals), never on a socket the test refuses
 * to drain. */
static int case_writers_short_pump(void)
{
    nf_node_t node;
    test_client_t flood;
    char tok[T_TOKEN_LEN + 1];
    char line[512];
    unsigned long long pw = 0;
    int i;

    TF_CHECK_MSG(nf_spawn_inline(&node, writers_setup) == 0,
                 "inline node with 4 writers did not start");

    memset(tok, 'y', T_TOKEN_LEN);
    tok[T_TOKEN_LEN] = '\0';

    tc_init(&flood);
    TF_CHECK_MSG(tc_connect_rcvbuf(&flood, node.port, T_RCVBUF) == 0,
                 "flood connect failed");
    TF_CHECK_MSG(tc_send(&flood, "NICK flooder") == 0, "flood NICK failed");
    TF_CHECK_MSG(tc_send(&flood, "USER flooder 0 * :Flooder") == 0,
                 "flood USER failed");
    TF_CHECK_MSG(tc_expect(&flood, " 001 ", T_IO_MS) == 0,
                 "the flooding client never registered");
    for (i = 0; i < T_FLOOD_LINES; i++) {
        snprintf(line, sizeof line, "PING :%s", tok);
        TF_CHECK_MSG(tc_send(&flood, line) == 0,
                     "flood PING %d of %d could not be sent", i,
                     T_FLOOD_LINES);
    }

    /* The reaper cannot close while the backlog drains, so this line is the
     * proof the deferral path ran; the close itself lands on the 2s deadline
     * with the socket still full. The 417 is NOT asserted here -- an
     * unread backlog ends in RST, which may drop it. Delivery is the next
     * case's claim, on a connection the test drains. */
    TF_CHECK_MSG(nf_expect(&node, "conn_reaped:", T_CLOSE_MS) == 0,
                 "the flooder was never reaped:\n%s", node.out);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(last_partial_writes(node.out, &pw) == 0 && pw >= 1,
                 "final stats show partial_writes=%llu, want >= 1:\n%s", pw,
                 node.out);

    nf_free(&node);
    tc_close(&flood);
    return 0;
}

/* The deferred close, proved the other way round: this time the test drains
 * everything, so the 417 queued behind the PONGs must arrive before the EOF
 * that only follows a full drain. */
static int case_417_deferred_close(void)
{
    nf_node_t node;
    test_client_t honest;
    test_client_t flood;
    char tok[T_TOKEN_LEN + 1];
    char line[512];
    int i;
    int rc;

    TF_CHECK_MSG(nf_spawn_inline(&node, writers_setup) == 0,
                 "inline node with 4 writers did not start");

    memset(tok, 'y', T_TOKEN_LEN);
    tok[T_TOKEN_LEN] = '\0';

    /* The honest client first, on its own bucket. */
    tc_init(&honest);
    TF_CHECK_MSG(tc_connect(&honest, node.port) == 0, "honest connect failed");
    TF_CHECK_MSG(tc_send(&honest, "NICK honest") == 0, "honest NICK failed");
    TF_CHECK_MSG(tc_send(&honest, "USER honest 0 * :Honest") == 0,
                 "honest USER failed");
    TF_CHECK_MSG(tc_expect(&honest, " 001 ", T_IO_MS) == 0,
                 "the honest client never registered");

    tc_init(&flood);
    TF_CHECK_MSG(tc_connect(&flood, node.port) == 0, "flood connect failed");
    TF_CHECK_MSG(tc_send(&flood, "NICK flooder") == 0, "flood NICK failed");
    TF_CHECK_MSG(tc_send(&flood, "USER flooder 0 * :Flooder") == 0,
                 "flood USER failed");
    TF_CHECK_MSG(tc_expect(&flood, " 001 ", T_IO_MS) == 0,
                 "the flooding client never registered");
    for (i = 0; i < T_FLOOD_LINES; i++) {
        snprintf(line, sizeof line, "PING :%s", tok);
        TF_CHECK_MSG(tc_send(&flood, line) == 0,
                     "flood PING %d of %d could not be sent", i,
                     T_FLOOD_LINES);
    }

    /* Drain: the 417 queued behind the PONGs, then the close that only
     * follows a full drain at N > 0. */
    TF_CHECK_MSG(tc_expect(&flood, " 417 ", T_IO_MS) == 0,
                 "the flood was never refused with 417 at N=4:\n%s",
                 tc_buffer(&flood));
    TF_CHECK_MSG(strstr(tc_buffer(&flood), "Input rate limit exceeded") != NULL,
                 "the 417 did not carry the rate-limit reason:\n%s",
                 tc_buffer(&flood));
    TF_CHECK_MSG(nf_expect(&node, "rate_limited:", T_IO_MS) == 0,
                 "the node never reported the rate limit:\n%s", node.out);
    rc = tc_expect_eof(&flood, T_CLOSE_MS);
    TF_CHECK_MSG(rc == 0 || rc == -3,
                 "the flooding connection was not closed after the 417 "
                 "(rc=%d)", rc);

    /* The limiter is per-connection: the honest client still gets its PONG. */
    TF_CHECK_MSG(tc_send(&honest, "PING :honest-after") == 0,
                 "honest PING failed");
    TF_CHECK_MSG(tc_expect(&honest, "PONG irc.fixture honest-after", T_IO_MS) == 0,
                 "the honest client stopped getting PONGs after another "
                 "client was rate-limited:\n%s", tc_buffer(&honest));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    tc_close(&honest);
    nf_free(&node);
    tc_close(&flood);
    return 0;
}

int main(void)
{
    if (tf_tls_available() != 0) {
        TF_CHECK_MSG(case_tls_pending_with_writers() == 0,
                     "TLS pending-drain with writers failed");
    } else {
        printf("note: plaintext build, asserting only the 417 halves\n");
        TF_CHECK_MSG(tf_tls_available() == 0,
                     "TLS is unavailable exactly when the fixture says so");
    }
    TF_CHECK_MSG(case_writers_short_pump() == 0,
                 "writer short-pump proof failed");
    TF_CHECK_MSG(case_417_deferred_close() == 0,
                 "417-flush-deferred-to-writers failed");

    tf_done("writers_tls_417");
    return 0;
}
