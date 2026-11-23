/* test_reap_flush_starttls_n4.c -- issue #500: N=4 wire coverage for the two
 * N>0-critical paths that run single-threaded in every other test.
 *
 * Leg A (417-flush-past-deadline): at --writers 4 a flooder with a 4 KiB
 * receive buffer bursts past the 256-line bucket, then the test withholds
 * reads for 3 s so the reaper's 2 s wq_close_at bound expires with the 417
 * still queued (server_reap's synchronous conn_pump, the #292 arm). The
 * client must then see `417` before the close: a reap that drops the reason
 * behind the deadline goes red here.
 *
 * Leg B (STARTTLS order at N=4): a plaintext client sends STARTTLS before
 * registering and must see the cleartext `670` first. The 670 is queued and
 * the handshake starts only once it has fully drained (conn_pump_locked);
 * a handler that began the handshake at once would put OpenSSL's ServerHello
 * ahead of the 670, and binary TLS bytes where a line is expected fail the
 * expect below. The leg then upgrades and registers, proving the handshake
 * still works after the ordered 670.
 *
 * shortcut: on kernels with roomy socket buffers the writers may drain the
 * burst before the 2 s bound expires, so leg A exercises the normal deferred
 * close rather than the past-deadline pump. The wire assertion is identical
 * either way (417 before close), which is what a regression would break.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

#define T_IO_MS 15000
#define T_DRAIN_MS 30000
#define FLOOD_LINES 300
#define FLOOD_TOKEN_LEN 400
#define T_RCVBUF 4096

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

/* Leg A: the 417 must arrive before the close at N=4, even when the drain
 * stalls past the reaper's deadline. The 4 KiB receive buffer plus a 3 s
 * no-read stall (the stall IS the test input: it lets the 2 s bound expire)
 * holds the burst queued; the client then drains and must find the reason
 * ahead of the EOF. */
static void flood_leg(int port)
{
    test_client_t flood;
    char line[FLOOD_TOKEN_LEN + 32];
    char tok[FLOOD_TOKEN_LEN + 1];
    struct timespec stall = { 3, 0 };
    int i;

    tc_init(&flood);
    TF_CHECK_MSG(tc_connect_rcvbuf(&flood, port, T_RCVBUF) == 0,
                 "flood connect failed");
    TF_CHECK_MSG(tc_send(&flood, "NICK flooder500") == 0, "flood NICK failed");
    TF_CHECK_MSG(tc_send(&flood, "USER flooder500 0 * :Flooder") == 0,
                 "flood USER failed");
    TF_CHECK_MSG(tc_expect(&flood, " 001 ", T_IO_MS) == 0,
                 "the flooding client never registered");
    memset(tok, 'F', FLOOD_TOKEN_LEN);
    tok[FLOOD_TOKEN_LEN] = '\0';
    for (i = 0; i < FLOOD_LINES; i++) {
        (void)snprintf(line, sizeof line, "PING :%s", tok);
        if (tc_send(&flood, line) != 0) {
            break;
        }
    }
    /* Let the deadline expire while the burst is queued: no reads here, so
     * the writers stall against the 4 KiB receive buffer and the reaper's
     * synchronous pump is what gets the 417 out. A plain wait-for-event
     * would read and drain; this delay is the input, not the sync. */
    (void)nanosleep(&stall, NULL);
    TF_CHECK_MSG(tc_expect(&flood, " 417 ", T_DRAIN_MS) == 0,
                 "the N=4 flood never saw 417 before the close: the reap "
                 "left the reason behind.\n  saw: %s", tc_buffer(&flood));
    {
        int rc = tc_expect_eof(&flood, T_DRAIN_MS);

        TF_CHECK_MSG(rc == 0 || rc == -3,
                     "the flooding connection was not closed after the 417 "
                     "(rc=%d)", rc);
    }
    tc_close(&flood);
}

int main(void)
{
    char dir[T_DIR_MAX];
    char crt[T_PATH];
    char key[T_PATH];
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.test";
    char a4[] = "--tls-cert";
    char a6[] = "--tls-key";
    char a8[] = "--writers";
    char a9[] = "4";
    char *argv[11];
    nf_node_t n;
    int have_cert = 0;
    int argc = 0;

    cert_dir(dir, sizeof dir);
    if (tf_tls_make_cert(dir, "srv", "irc.tls",
                         "DNS:irc.tls,IP:127.0.0.1,DNS:localhost", 0, 86400,
                         0600) == 0) {
        (void)snprintf(crt, sizeof crt, "%s/srv.crt", dir);
        (void)snprintf(key, sizeof key, "%s/srv.key", dir);
        have_cert = 1;
    }
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
                 "node with --writers 4 did not start");

    starttls_leg(n.port, have_cert ? crt : NULL, have_cert);
    flood_leg(n.port);

    TF_CHECK_MSG(nf_stop(&n) == 0, "node did not exit cleanly");
    nf_free(&n);
    if (have_cert) {
        tf_tls_rmtree(dir);
    }
    tf_done("reap_flush_starttls_n4");
    return 0;
}
