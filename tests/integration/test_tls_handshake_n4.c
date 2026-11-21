/* test_tls_handshake_n4.c -- Issue #294, gap 1: TLS handshakes at N=4 writers.
 *
 * One node with `--writers 4`, a certificate and an implicit-TLS port. Two
 * clients handshake at the SAME time -- one implicit-TLS, one STARTTLS-upgraded
 * in a forked child -- and each registers and exchanges PING/PONG. The
 * STARTTLS leg asserts the 670 reply arrives before the upgrade.
 *
 * WHY TWO AT ONCE, rather than the sequential cases test_tls.c already owns:
 * at N > 0 the loop never pumps, so both handshakes progress through the
 * writer-owned conn_pump() empty pass (the pass that exists so a handshake
 * can start with no application data queued) while the loop keeps reading.
 * That is the SSL_do_handshake-against-SSL_read race the audit named, and a
 * sequential test never has two handshakes in flight for it to bite. The race
 * itself is timing-dependent and cannot be fired on demand; running both
 * handshakes concurrently is what makes it possible rather than certain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

#define T_IO_MS 15000

static int fails = 0;

#define CHECK(cond, msg, detail)                                              \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("FAIL: %s [%s]\n", (msg), ((detail) != NULL) ? (detail) : "-"); \
            fails++;                                                          \
        }                                                                     \
    } while (0)

/* Where the generated certificate goes: under the build tree, per-process, so
 * parallel ctest workers never share a directory of private keys. */
static void cert_dir(char *out, size_t cap)
{
    const char *base = getenv("IRCSERVE_BUILD_DIR");

    if (base == NULL) {
        base = "/tmp";
    }
    (void)snprintf(out, cap, "%s/tls-n4-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* Register over an established TLS connection and prove the channel is live
 * with a PING/PONG round trip. `tag` distinguishes the two clients' lines. */
static void tls_register_and_ping(tf_tls_t *t, const char *nick,
                                  const char *ident, const char *token)
{
    char line[256];

    (void)snprintf(line, sizeof line, "NICK %s", nick);
    CHECK(tf_tls_send(t, line) == 0, "NICK send failed", line);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", ident, ident);
    CHECK(tf_tls_send(t, line) == 0, "USER send failed", line);
    CHECK(tf_tls_expect(t, " 001 ", T_IO_MS) == 0, "no 001 after TLS register",
          tf_tls_buffer(t));
    (void)snprintf(line, sizeof line, "PING :%s", token);
    CHECK(tf_tls_send(t, line) == 0, "PING send failed", line);
    CHECK(tf_tls_expect(t, token, T_IO_MS) == 0, "no PONG after TLS register",
          tf_tls_buffer(t));
}

/* The implicit-TLS leg, run in the parent. */
static void implicit_leg(int tls_port, const char *cert)
{
    tf_tls_t t;
    const char *why = NULL;

    if (tf_tls_connect(&t, tls_port, cert, "irc.tls", &why) != 0) {
        CHECK(0, "implicit-TLS handshake failed",
              (why != NULL) ? why : "no reason");
        return;
    }
    tls_register_and_ping(&t, "n4imp", "n4impident", "n4imp-tok");
    tf_tls_close(&t);
}

/* The STARTTLS leg, run in the forked child: 670 on the plaintext port, then
 * an in-place upgrade, then the same register + PING/PONG. */
static void starttls_leg(int port, const char *cert)
{
    tf_tls_t up;
    const char *why = NULL;

    if (tf_tls_connect_plain(&up, port) != 0) {
        CHECK(0, "plaintext connect for STARTTLS failed", NULL);
        return;
    }
    if (tf_tls_send(&up, "STARTTLS") != 0 ||
        tf_tls_expect(&up, " 670 ", T_IO_MS) != 0) {
        CHECK(0, "STARTTLS did not reach 670 at N=4", tf_tls_buffer(&up));
        tf_tls_close(&up);
        return;
    }
    if (tf_tls_upgrade(&up, up.fd, cert, "irc.tls", &why) != 0) {
        CHECK(0, "STARTTLS upgrade handshake failed",
              (why != NULL) ? why : "no reason");
        tf_tls_close(&up);
        return;
    }
    tls_register_and_ping(&up, "n4tls", "n4tlsident", "n4tls-tok");
    tf_tls_close(&up);
}

int main(void)
{
    char dir[1024];
    char cert[1024];
    char key[1024];
    nf_node_t n;
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.tls";
    char a4[] = "--tls-cert";
    char a6[] = "--tls-key";
    char a8[] = "--tls-port";
    char a9[] = "0";
    char a10[] = "--writers";
    char a11[] = "4";
    char *argv[13];
    const char *p;
    int tls_port;
    pid_t kid;
    int status;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_tls_handshake_n4 ==\n");
    if (tf_tls_available() == 0) {
        printf("note: TLS is not compiled in; the handshake legs need OpenSSL, "
               "so there is nothing to race\n");
        tf_done("tls_handshake_n4");
        return 0;
    }
    cert_dir(dir, sizeof dir);
    if (tf_tls_make_cert(dir, "srv", "irc.tls",
                         "DNS:irc.tls,IP:127.0.0.1,DNS:localhost", 0, 86400,
                         0600) != 0) {
        printf("note: certificate generation failed; cannot build the TLS node\n");
        tf_done("tls_handshake_n4");
        return 0;
    }
    (void)snprintf(cert, sizeof cert, "%s/srv.crt", dir);
    (void)snprintf(key, sizeof key, "%s/srv.key", dir);

    argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
    argv[4] = a4; argv[5] = cert; argv[6] = a6; argv[7] = key;
    argv[8] = a8; argv[9] = a9; argv[10] = a10; argv[11] = a11;
    argv[12] = NULL;
    if (nf_spawn_binary_argv(&n, argv) != 0) {
        CHECK(0, "spawn of the --writers 4 TLS node failed", NULL);
        tf_tls_rmtree(dir);
        tf_done("tls_handshake_n4");
        return (fails != 0) ? 1 : 0;
    }
    p = strstr(n.out, "tls_port=");
    tls_port = (p != NULL) ? atoi(p + 9) : -1;
    CHECK(tls_port > 0, "the N=4 node bound its own implicit-TLS port", n.out);

    /* BOTH HANDSHAKES IN FLIGHT AT ONCE. The child speaks plaintext STARTTLS
     * while the parent starts the implicit handshake, so the node's writer
     * pumps and loop reads interleave the two SSL_do_handshake flights. */
    kid = fork();
    if (kid < 0) {
        CHECK(0, "fork for the concurrent STARTTLS leg failed", NULL);
    } else if (kid == 0) {
        starttls_leg(n.port, cert);
        _exit((fails != 0) ? 1 : 0);
    } else {
        implicit_leg(tls_port, cert);
        if (waitpid(kid, &status, 0) < 0) {
            CHECK(0, "waitpid for the STARTTLS leg failed", NULL);
        } else {
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "the concurrent STARTTLS leg failed its register+PING/PONG",
                  NULL);
        }
    }

    (void)nf_stop(&n);
    nf_free(&n);
    tf_tls_rmtree(dir);
    if (fails == 0) {
        printf("ok: implicit-TLS and STARTTLS register and PING/PONG "
               "concurrently at N=4\n");
    }
    tf_done("tls_handshake_n4");
    return (fails != 0) ? 1 : 0;
}
