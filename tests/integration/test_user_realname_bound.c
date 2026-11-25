/* test_user_realname_bound.c -- #669: USER refuses an over-long realname.
 *
 * Observed: `USER ... :<400 x R>` registered fine and WHOIS 311 showed the
 * realname truncated to 255, while `SETNAME :<400 x X>` on the same input is
 * refused with 417. Same field, same bound, opposite handling: registration
 * silently stored a shortened value the peer never sent, which then federates
 * via extended-join as if the client wrote it.
 *
 * The fix mirrors SETNAME: an over-long USER realname is 417 and registration
 * is held (no 001) until a valid USER arrives. 255 registers; 256 is refused.
 *
 * NO FIXED sleep() ANYWHERE: every wait is tc_expect()'s deadline loop, and
 * absence of 001 is proven by a PING whose PONG drains the window first.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* Spelled out as literals so raising CONN_MAX_REALNAME in src/ breaks this
 * file -- the same argument test_registration.c makes about the 005 tokens:
 * a test that follows the constant cannot notice the constant moved. */
#define AT_LIMIT 255
#define OVER_LIMIT 256

static unsigned g_drain_seq;

/* Send a PING with a unique token and wait for its PONG, so everything the
 * node already wrote for earlier commands is in the buffer. Numbered per
 * call, because tc_expect() searches the ACCUMULATED buffer and a reused
 * token would match an earlier PONG without any new read. */
static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "urb%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained "
                 "and an absence claim below would be about the read schedule",
                 token);
}

/* Fill `out` (size AT_LIMIT+2) with `n` copies of `ch`. */
static void repeat(char *out, size_t n, char ch)
{
    memset(out, ch, n);
    out[n] = '\0';
}

int main(void)
{
    nf_node_t node;
    char realname[OVER_LIMIT + 2];
    char line[2048];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ---- ONE OVER THE BOUNDARY: 417, NO 001, AND THE CLIENT RECOVERS ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "over could not connect");
        TF_CHECK_MSG(tc_send(&c, "NICK over") == 0, "over NICK send failed");
        repeat(realname, OVER_LIMIT, 'R');
        (void)snprintf(line, sizeof line, "USER over 0 *spoofed :%s", realname);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "over USER send failed");
        TF_CHECK_MSG(tc_expect(&c, " 417 ", T_IO_MS) == 0,
                     "a USER realname of 256 bytes was not refused with 417. "
                     "It must be REFUSED and not truncated: a shortened "
                     "realname is one the user did not write, and this node "
                     "reports it to every member of every channel they are on "
                     "as though it were theirs.\n  client saw: %s",
                     tc_buffer(&c));
        drain(&c);
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 001 ") == 0,
                     "001 arrived for a connection whose USER realname was "
                     "refused. Registration must be HELD until a valid USER "
                     "arrives.\n  client saw: %s", tc_buffer(&c));
        /* The refusal strands nothing: a valid USER on the same connection
         * still registers. */
        TF_CHECK_MSG(tc_send(&c, "USER over 0 *spoofed :Real Over") == 0,
                     "over retry USER send failed");
        TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                     "a connection refused for an over-long USER realname "
                     "could not then register with a valid USER");
        tc_close(&c);
    }

    /* ---- AT THE BOUNDARY: 255 bytes registers ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "edge could not connect");
        TF_CHECK_MSG(tc_send(&c, "NICK edge") == 0, "edge NICK send failed");
        repeat(realname, AT_LIMIT, 'a');
        (void)snprintf(line, sizeof line, "USER edge 0 *spoofed :%s", realname);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "edge USER send failed");
        TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                     "a USER realname of exactly 255 bytes was refused. A "
                     "bound that rejects everything is not a bound, and 005's "
                     "NAMELEN=255 says this node accepts it.\n  client saw: %s",
                     tc_buffer(&c));
        tc_close(&c);
    }

    /* ---- THE ISSUE'S OWN SHAPE: 400 bytes is 417, not a quiet 001 ---- */
    {
        test_client_t c;
        char big[401];

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "long2 could not connect");
        TF_CHECK_MSG(tc_send(&c, "NICK long2") == 0, "long2 NICK send failed");
        repeat(big, sizeof big - 1u, 'R');
        (void)snprintf(line, sizeof line, "USER long2 0 * :%s", big);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "long2 USER send failed");
        TF_CHECK_MSG(tc_expect(&c, " 417 ", T_IO_MS) == 0,
                     "a USER realname of 400 bytes was not refused with 417 "
                     "(#669).\n  client saw: %s", tc_buffer(&c));
        drain(&c);
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 001 ") == 0,
                     "001 arrived for a 400-byte USER realname (#669).\n"
                     "  client saw: %s", tc_buffer(&c));
        tc_close(&c);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("user_realname_bound");
    return 0;
}
