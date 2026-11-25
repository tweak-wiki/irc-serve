/* test_user_realname_417.c -- issue #669: USER refuses an over-long realname.
 *
 * SETNAME 417s a realname past CONN_MAX_REALNAME, but USER silently TRUNCATED
 * the same input and registered the client under a name it never wrote -- a
 * value this node then reports as the user's on every channel. The fix is one
 * refusal: an over-long USER realname is answered 417 with nothing stored and
 * registration held, so the client can retry.
 *
 * The bound is spelled out as a literal rather than CONN_MAX_REALNAME, the same
 * argument test_setname.c makes about its 255: a test that follows the constant
 * cannot notice the constant moved. 400 is over whatever the bound is without
 * depending on its exact value.
 *
 * NO FIXED sleep() ANYWHERE: every wait is tc_expect()'s deadline loop, and the
 * absence window is closed by a PING whose PONG is the drain token.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* Well past the bound, comfortably inside one IRC line. */
#define TOO_LONG 400

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "ur%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "the absence claim below would be about the read schedule", token);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    char realname[TOO_LONG + 1];
    char line[1024];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "NICK longuser") == 0, "NICK send failed");

    memset(realname, 'r', sizeof realname - 1u);
    realname[sizeof realname - 1u] = '\0';
    (void)snprintf(line, sizeof line, "USER longuser 0 *spoofed :%s", realname);
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "over-long USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 417 ", T_IO_MS) == 0,
                 "an over-long USER realname was not refused with 417. It must be "
                 "REFUSED and not truncated: a shortened realname is one the user "
                 "did not write, and this node reports it to every member of every "
                 "channel they are on as though it were theirs.\n  client saw: %s",
                 tc_buffer(&c) + mark);

    /* AND REGISTRATION DID NOT COMPLETE: the drain PONG closes the window, so a
     * 001 that the node sent anyway is in the buffer and fails this. */
    drain(&c);
    TF_CHECK_MSG(strstr(tc_buffer(&c) + mark, " 001 ") == NULL,
                 "the client was registered under a refused realname. 417 is the "
                 "refusal and 001 is the success, and a window holding both means "
                 "the refusal stored nothing but registered anyway.\n  client saw: %s",
                 tc_buffer(&c) + mark);

    /* AND THE CONNECTION IS STILL USABLE: a retry with an acceptable realname
     * registers. A refusal that stranded the client would force a reconnect for
     * a value the client can simply shorten. */
    TF_CHECK_MSG(tc_send(&c, "USER longuser 0 *spoofed :Real Longuser") == 0,
                 "retry USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "a connection refused for an over-long realname could not then "
                 "register with an acceptable one.\n  client saw: %s",
                 tc_buffer(&c));

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&c);
    return 0;
}
