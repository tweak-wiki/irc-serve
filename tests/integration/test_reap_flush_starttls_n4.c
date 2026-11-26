/* test_reap_flush_starttls_n4.c -- issue #500: N=0/N=4 wire coverage for the
 * two N>0-critical paths that run single-threaded in every other test.
 *
 * Leg A (417-flush with writers started): a flooder bursts past the 256-line
 * bucket and the client must see `417` before the close, at N=0 and at N=4.
 * At N=4 the burst is ~120 KiB, so the reaper observes pending bytes with
 * the writer pool running and defers to the pump -- the path
 * test_close_handoff never runs, because it starts no writers. A reap that
 * drops the reason goes red here.
 *
 * Leg B (STARTTLS order at N=4): a plaintext client sends STARTTLS before
 * registering and must see the cleartext `670` first. The 670 is queued and
 * the handshake starts only once it has fully drained (conn_pump_locked);
 * a handler that began the handshake at once would put OpenSSL's ServerHello
 * ahead of the 670, and binary TLS bytes where a line is expected fail the
 * expect below. The leg then upgrades and registers, proving the handshake
 * still works after the ordered 670.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

#define T_IO_MS 15000
#define FLOOD_BIG_TOKEN 400
/* The N=4 EOF wait: the deferred close waits out the writer drain plus the
 * reaper's own ticks, so it gets the same 120 s bound test_writers_tls_417
 * uses for its deferred-close case instead of the 15 s I/O bound. A shared
 * runner can stall either side past 15 s without anything being wrong. */
#define T_CLOSE_MS 120000
/* Send-until-refused batches: the limiter refills 50 tokens/s against a 256
 * burst, so the mid-flood wait must be short -- a 2 s wait per batch used to
 * grant the refill time to catch up, and on a slow runner the bucket never
 * drained and the 417 never came (#743). 20 batches of 150 with 100 ms
 * waits grant at most ~100 refill tokens against 3000 sent, so the refusal
 * still lands mid-backlog on any runner; the waits are load-bearing the
 * other way too, draining the reply side so the server's final pump never
 * meets a full socket. The per-batch overshoot past the refusal (~61 KiB)
 * still fits in kernel buffers. */
#define FLOOD_BATCH 150
#define FLOOD_BATCHES 20
#define FLOOD_BATCH_MS 100
/* The lagging refusal: after the last batch goes out the server may still be
 * working the backlog -- at N=4 a ~120 KiB writer-pool drain on a loaded
 * (sanitizer) runner, and a shared runner can stall either side past 15 s
 * without anything being wrong. Same 30 s bound test_writers_tls_417 uses
 * for its 417 wait (#745); the per-batch polls above already spent the cheap
 * waiting, so this only binds when the runner is truly stalled. */
#define T_REFUSAL_MS 30000

#define T_DIR_MAX 512
#define T_PATH (T_DIR_MAX + 128)

static void cert_dir(char *out, size_t cap)
{
    const char *base = getenv("IRCSERVE_BUILD_DIR");

    if (base == NULL) {
        base = "/tmp";
    }
    (void)snprintf(out, cap, "%s/tls-500-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* Leg B: plaintext STARTTLS at N=4. With a certificate the node must answer
 * the cleartext 670 before any handshake bytes; without one it must refuse
 * with 691 (the NOT CONFIGURED arm, which is a property of the node rather
 * than of the build). */
static void starttls_leg(int port, const char *cert, int have_cert)
{
    /* With TLS compiled in this opens a plain TCP connection that is later
     * upgraded in place; the 670 expect below runs on the cleartext. */
    tf_tls_t up;

    if (!have_cert) {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, port) == 0, "STARTTLS connect failed");
        TF_CHECK_MSG(tc_send(&c, "STARTTLS") == 0, "STARTTLS send failed");
        TF_CHECK_MSG(tc_expect(&c, " 691 ", T_IO_MS) == 0,
                     "STARTTLS without a certificate was not refused with "
                     "691.\n  saw: %s", tc_buffer(&c));
        tc_close(&c);
        return;
    }
    TF_CHECK_MSG(tf_tls_available() != 0,
                 "a generated certificate means TLS is compiled in");
    TF_CHECK_MSG(tf_tls_connect_plain(&up, port) == 0,
                 "plaintext connect for STARTTLS failed");
    TF_CHECK_MSG(tf_tls_send(&up, "STARTTLS") == 0, "STARTTLS send failed");
    TF_CHECK_MSG(tf_tls_expect(&up, " 670 ", T_IO_MS) == 0,
                 "STARTTLS did not reach 670 at N=4 -- handshake bytes came "
                 "first:\n%s", tf_tls_buffer(&up));
    {
        const char *why = NULL;

        TF_CHECK_MSG(tf_tls_upgrade(&up, up.fd, cert, "irc.tls", &why) == 0,
                     "STARTTLS upgrade handshake failed: %s",
                     (why != NULL) ? why : "no reason");
    }
    TF_CHECK_MSG(tf_tls_send(&up, "NICK stls500") == 0, "NICK failed");
    TF_CHECK_MSG(tf_tls_send(&up, "USER stls500 0 * :S") == 0, "USER failed");
    TF_CHECK_MSG(tf_tls_expect(&up, " 001 ", T_IO_MS) == 0,
                 "no 001 after STARTTLS upgrade:\n%s", tf_tls_buffer(&up));
    TF_CHECK_MSG(tf_tls_send(&up, "PING :stls500-tok") == 0, "PING failed");
    TF_CHECK_MSG(tf_tls_expect(&up, "stls500-tok", T_IO_MS) == 0,
                 "no PONG after STARTTLS upgrade:\n%s", tf_tls_buffer(&up));
    tf_tls_close(&up);
}

/* Leg A: the 417 must arrive before the close. The burst is short lines at
 * N=0, so the mark-time flush takes the whole queue -- including the
 * trailing 417 -- into the kernel before the loop-thread reaper closes; a
 * reap that dropped the reason would hand the client an EOF without it. At
 * N=4 the burst is 400-byte lines (~120 KiB queued): more than a mark-time
 * flush emits, so the reaper observes pending bytes under the writer pool
 * and defers to the pump rather than closing under it, and the deferred
 * drain carries the 417 out ahead of the EOF. A fat queue at N=0 would NOT
 * make that leg stronger: the loop-thread reaper closes without waiting, so
 * bytes still queued at close are lost on a RST and the assertion becomes a
 * race over socket buffers rather than a property of the reap.
 */
static void flood_leg(int port, int big)
{
    test_client_t flood;
    char line[FLOOD_BIG_TOKEN + 32];
    char tok[FLOOD_BIG_TOKEN + 1];
    int i;

    if (big) {
        memset(tok, 'F', FLOOD_BIG_TOKEN);
        tok[FLOOD_BIG_TOKEN] = '\0';
    }

    tc_init(&flood);
    TF_CHECK_MSG(tc_connect(&flood, port) == 0, "flood connect failed");
    TF_CHECK_MSG(tc_send(&flood, "NICK flooder500") == 0, "flood NICK failed");
    TF_CHECK_MSG(tc_send(&flood, "USER flooder500 0 * :Flooder") == 0,
                 "flood USER failed");
    TF_CHECK_MSG(tc_expect(&flood, " 001 ", T_IO_MS) == 0,
                 "the flooding client never registered");
    /* Send in batches until the 417 shows up (see FLOOD_BATCH): a send error
     * just means the server already closed us, and tc_expect scans what is
     * already buffered, so the poll is free once the refusal has landed. The
     * per-batch wait doubles as the reply-side drain that keeps the
     * server-to-client pipe empty for the reaper's final pump. */
     {
         int batch, got = 0;
         for (batch = 0; batch < FLOOD_BATCHES && !got; batch++) {
             for (i = 0; i < FLOOD_BATCH; i++) {
                 if (big) {
                     (void)snprintf(line, sizeof line, "PING :%s", tok);
                 } else {
                     (void)snprintf(line, sizeof line, "PING :flood500");
                 }
                 if (tc_send(&flood, line) != 0) {
                     break;
                 }
             }
            got = (tc_expect(&flood, " 417 ", FLOOD_BATCH_MS) == 0);
         }
        /* A slow server may still be working the backlog when the last batch
         * goes out; one final generous wait covers the lagging refusal. */
        if (!got) {
            got = (tc_expect(&flood, " 417 ", T_REFUSAL_MS) == 0);
        }
        {
            const char *saw = tc_buffer(&flood);
            size_t n = strlen(saw);
            TF_CHECK_MSG(got, "the flood never saw 417 before the close: the reap left "
                         "the reason behind.\n  saw: %s",
                         (n > 512u) ? saw + (n - 512u) : saw);
        }
    }
    {
        /* The close follows the drain, and at N=4 the drain is a writer
         * round-trip plus reaper ticks -- the long bound, not the I/O one
         * (big == writers started; at N=0 the close is immediate). */
        int rc = tc_expect_eof(&flood, big ? T_CLOSE_MS : T_IO_MS);

        TF_CHECK_MSG(rc == 0 || rc == -3,
                     "the flooding connection was not closed after the 417 "
                     "(rc=%d)", rc);
    }
    tc_close(&flood);
}

static void run_node(const char *writers, char *crt, char *key,
                     int have_cert)
{
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.test";
    char a4[] = "--tls-cert";
    char a6[] = "--tls-key";
    char a8[] = "--writers";
    char a9[8];
    char *argv[11];
    nf_node_t n;
    int argc = 0;

    (void)snprintf(a9, sizeof a9, "%s", writers);
    argv[argc++] = a0;
    argv[argc++] = a1;
    argv[argc++] = a2;
    argv[argc++] = a3;
    if (have_cert) {
        argv[argc++] = a4;
        argv[argc++] = crt;
        argv[argc++] = a6;
        argv[argc++] = key;
    }
    argv[argc++] = a8;
    argv[argc++] = a9;
    argv[argc++] = NULL;
    TF_CHECK_MSG(nf_spawn_binary_argv(&n, argv) == 0,
                 "node with --writers %s did not start", writers);

    starttls_leg(n.port, crt, have_cert);
    flood_leg(n.port, writers[0] != '0');

    TF_CHECK_MSG(nf_stop(&n) == 0, "node did not exit cleanly");
    nf_free(&n);
}

int main(void)
{
    char dir[T_DIR_MAX];
    char crt[T_PATH];
    char key[T_PATH];
    int have_cert = 0;

    cert_dir(dir, sizeof dir);
    if (tf_tls_make_cert(dir, "srv", "irc.tls",
                         "DNS:irc.tls,IP:127.0.0.1,DNS:localhost", 0, 86400,
                         0600) == 0) {
        (void)snprintf(crt, sizeof crt, "%s/srv.crt", dir);
        (void)snprintf(key, sizeof key, "%s/srv.key", dir);
        have_cert = 1;
    }
    /* Both legs at N=0 (the loop reaps and pumps) and at N=4 (the writers
     * own the pump and the reaper defers): the 417-before-close and
     * 670-before-ServerHello orderings hold on both. */
    run_node("0", crt, key, have_cert);
    run_node("4", crt, key, have_cert);

    if (have_cert) {
        tf_tls_rmtree(dir);
    }
    tf_done("reap_flush_starttls_n4");
    return 0;
}
