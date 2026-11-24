/* test_sasl_stack_wipe.c -- issue #358: no credential outlives the stack frame.
 *
 * handle_authenticate() decodes the PLAIN payload into four stack locals
 * (payload, authzid, authcid, passwd). The framework wipes ITS copies, but the
 * handler's own stack copies survived in the dead frame until reuse. Every
 * return below the decode must therefore run auth_wipe_credential() first.
 *
 * A black-box test cannot see a dead stack frame -- the bytes are not emitted
 * anywhere either way -- so this pins the property two ways:
 *
 *   1. THE EXCHANGE STILL WORKS. A real node, a real credential store, a real
 *      AUTHENTICATE PLAIN exchange (both the one-shot and the two-step forms),
 *      and the node reports outcome=COMPLETED. This is the half that proves the
 *      wipe did not break the path it scrubs: a wipe placed before the verify,
 *      or over the wrong length, fails here rather than in every SASL test.
 *
 *   2. THE WIPE IS PRESENT. src/core/commands.c contains auth_wipe_credential()
 *      calling auth_wipe() over all four locals, the wipe runs through a
 *      volatile pointer (so the compiler cannot delete it as a dead store),
 *      and all eleven exits of handle_authenticate() call it. Removing any call
 *      -- or emptying the helper -- fails this half. The source read uses
 *      tf_read_code(), the same instrument test_account.c uses to pin
 *      server_shutdown()'s account_store_free() for the same reason: some
 *      properties have no runtime-observable form.
 *
 * And the password never appears in the node's own output, on either exchange
 * -- the scrub is about memory, but a wipe that logged first would be no wipe.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* base64 of "authzid\0authcid\0passwd", for a PLAIN payload. Written out here
 * rather than shared with sasl_framework.c because this is the CLIENT side of
 * the wire: an encoder shared with the decoder cannot catch the two agreeing
 * on something the specification says they should not. */
static void b64_encode(const char *in, size_t len, char *out, size_t cap)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t n = 0;

    while (i < len && n + 5u < cap) {
        unsigned long acc = 0;
        int have = 0;
        char chunk[4];

        for (int k = 0; k < 3; k++) {
            acc <<= 8;
            if (i < len) {
                acc |= (unsigned long)(unsigned char)in[i++];
                have++;
            }
        }
        chunk[0] = alpha[(acc >> 18) & 0x3Fu];
        chunk[1] = alpha[(acc >> 12) & 0x3Fu];
        chunk[2] = (have > 1) ? alpha[(acc >> 6) & 0x3Fu] : '=';
        chunk[3] = (have > 2) ? alpha[acc & 0x3Fu] : '=';
        for (int k = 0; k < 4; k++) {
            out[n++] = chunk[k];
        }
    }
    out[n] = '\0';
}

/* RFC 4616's PLAIN payload. Returns its LENGTH, and the length is the point:
 * the payload is not a C string -- it BEGINS with a NUL whenever authzid is
 * empty -- so anything that reaches for strlen() on it encodes one byte. */
static size_t plain_payload(char *buf, size_t cap, const char *authzid,
                            const char *authcid, const char *passwd)
{
    const size_t za = strlen(authzid);
    const size_t zc = strlen(authcid);
    const size_t zp = strlen(passwd);
    size_t n = 0;

    if (za + 1u + zc + 1u + zp + 1u > cap) {
        buf[0] = '\0';
        return 0;
    }
    memcpy(buf + n, authzid, za);
    n += za;
    buf[n++] = '\0';
    memcpy(buf + n, authcid, zc);
    n += zc;
    buf[n++] = '\0';
    memcpy(buf + n, passwd, zp);
    n += zp;
    buf[n] = '\0';
    return n;
}

static void run_one_shot(nf_node_t *node)
{
    test_client_t c;
    char payload[640];
    char encoded[1024];
    char line[1200];
    size_t plen;

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node->port) == 0, "tc_connect failed");
    plen = plain_payload(payload, sizeof payload, "", "alice",
                         "correct horse battery staple");
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(line, sizeof line, "AUTHENTICATE PLAIN %s", encoded);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "AUTHENTICATE send failed");
    TF_CHECK_MSG(nf_expect(node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "a correct one-shot PLAIN credential was not accepted");
    TF_CHECK_MSG(tc_send(&c, "QUIT") == 0, "QUIT send failed");
    tc_close(&c);
}

static void run_two_step(nf_node_t *node)
{
    test_client_t c;
    char payload[640];
    char encoded[1024];
    size_t plen;

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node->port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, "AUTHENTICATE * +", T_IO_MS) == 0,
                 "no initial-response request");
    plen = plain_payload(payload, sizeof payload, "", "alice",
                         "correct horse battery staple");
    b64_encode(payload, plen, encoded, sizeof encoded);
    TF_CHECK_MSG(tc_send(&c, encoded) == 0, "response send failed");
    TF_CHECK_MSG(nf_expect(node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "a correct two-step PLAIN credential was not accepted");
    TF_CHECK_MSG(tc_send(&c, "QUIT") == 0, "QUIT send failed");
    tc_close(&c);
}

/* The wipe is pinned in the source because a dead stack frame has no
 * wire-observable form: the bytes are not emitted whether they are scrubbed
 * or not. Removing a call -- or emptying the helper -- fails here. */
static void expect_wipe_in_source(void)
{
    char *code = tf_read_code("src/core/commands.c", NULL);
    size_t calls = 0;
    const char *at;

    TF_CHECK_MSG(code != NULL, "could not read src/core/commands.c");
    if (code == NULL) {
        return;
    }
    /* The helper exists and scrubs through a volatile pointer, so the compiler
     * cannot delete it as a dead store -- the same shape as secret_util.c's
     * secret_wipe(). */
    TF_CHECK_MSG(strstr(code, "static void auth_wipe(void *p, size_t n)") != NULL,
                 "auth_wipe() is missing from src/core/commands.c");
    TF_CHECK_MSG(strstr(code, "volatile unsigned char *v") != NULL,
                 "auth_wipe() must write through a volatile pointer");
    TF_CHECK_MSG(strstr(code, "auth_wipe(passwd, SASL_MAX_PASSWORD + 1u)") != NULL,
                 "the credential wipe must cover passwd");
    TF_CHECK_MSG(strstr(code, "auth_wipe(payload, SASL_MAX_PAYLOAD)") != NULL,
                 "the credential wipe must cover payload");
    /* All eleven exits of handle_authenticate() scrub all four locals (#539
     * adds the RATE_LIMITED refusal, which wipes like every other exit). */
    at = code;
    while ((at = strstr(at, "auth_wipe_credential(payload, authzid, authcid, "
                            "passwd)")) != NULL) {
        calls++;
        at++;
    }
    TF_CHECK_MSG(calls == 11,
                 "expected auth_wipe_credential() at all 11 exits of "
                 "handle_authenticate(), found %zu",
                 calls);
    free(code);
}

int main(void)
{
    char store[] = "/tmp/irc_serve_sasl_wipe.XXXXXX";
    char *argv[6];
    char portbuf[16];
    nf_node_t node;
    int fd;

    fd = mkstemp(store);
    TF_CHECK_MSG(fd >= 0, "could not create the credential store");
    if (fd < 0) {
        return 1;
    }
    TF_CHECK_MSG(write(fd, "alice\tcorrect horse battery staple\n",
                       (size_t)35) == 35,
                 "could not write the credential store");
    (void)close(fd);
    TF_CHECK_MSG(chmod(store, S_IRUSR | S_IWUSR) == 0,
                 "could not chmod the credential store");

    (void)snprintf(portbuf, sizeof portbuf, "0");
    argv[0] = (char *)"irc-serve";
    argv[1] = portbuf;
    argv[2] = (char *)"--sasl-store";
    argv[3] = store;
    argv[4] = NULL;
    argv[5] = NULL;
    TF_CHECK_MSG(nf_spawn_binary_argv(&node, argv) == 0,
                 "could not spawn a node");

    run_one_shot(&node);
    run_two_step(&node);

    /* The password crossed the wire twice and was verified twice; it must not
     * appear in the node's own output on either exchange. */
    TF_CHECK_MSG(strstr(node.out, "correct horse battery staple") == NULL,
                 "the ACCOUNT PASSWORD appears in the node's own output");

    expect_wipe_in_source();

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    nf_free(&node);
    (void)unlink(store);
    printf("ok: sasl_stack_wipe\n");
    return 0;
}
