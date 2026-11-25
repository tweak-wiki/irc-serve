/* test_quit_nick_echo.c -- issue #609: a local QUIT renders as QUIT (not
 * PART) to channel members, and a renamer gets its own NICK echo.
 *
 * Two behaviors, one file, because the defect is one sentence: the teardown
 * path emitted only PART, and the rename path emitted nothing to the renamer.
 * Both are asserted on the wire, from the receiving client's buffer:
 *
 *   1. qa1 and qa2 share #qchan. qa2 sends `QUIT :see you`. qa1 must see
 *      `:qa2!qa2@127.0.0.1 QUIT :see you` -- with the reason -- and must see
 *      no PART line at all.
 *   2. soloB joins #qchan, then sends `NICK soloB2`. soloB must see its own
 *      `:soloB!soloB@127.0.0.1 NICK soloB2` echo (RFC 2812 mandates the
 *      client receive it), and qa1 must see the same line once.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

static void register_as(test_client_t *c, int port, const char *nick)
{
    char user[128];
    char nickcmd[128];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "tc_connect failed for %s", nick);
    (void)snprintf(nickcmd, sizeof nickcmd, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, nickcmd) == 0, "NICK send failed for %s",
                 nick);
    (void)snprintf(user, sizeof user, "USER %s 0 * :%s Example", nick, nick);
    TF_CHECK_MSG(tc_send(c, user) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "registration did not complete for %s", nick);
}

int main(void)
{
    nf_node_t node;
    test_client_t qa1;
    test_client_t qa2;
    test_client_t solo;

    tc_init(&qa1);
    tc_init(&qa2);
    tc_init(&solo);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    register_as(&qa1, node.port, "qa1");
    register_as(&qa2, node.port, "qa2");

    TF_CHECK_MSG(tc_send(&qa1, "JOIN #qchan") == 0, "qa1 JOIN failed");
    TF_CHECK_MSG(tc_expect(&qa1, " 366 ", T_IO_MS) == 0,
                 "qa1 JOIN never completed");
    TF_CHECK_MSG(tc_send(&qa2, "JOIN #qchan") == 0, "qa2 JOIN failed");
    TF_CHECK_MSG(tc_expect(&qa2, " 366 ", T_IO_MS) == 0,
                 "qa2 JOIN never completed");

    /* --- 1. QUIT renders as QUIT, with the reason, and never as PART --- */
    TF_CHECK_MSG(tc_send(&qa2, "QUIT :see you") == 0, "qa2 QUIT send failed");
    TF_CHECK_MSG(tc_expect(&qa1, " QUIT", T_IO_MS) == 0,
                 "qa1 never saw qa2's QUIT: %s", tc_buffer(&qa1));
    TF_CHECK_MSG(strstr(tc_buffer(&qa1),
                        ":qa2!qa2@127.0.0.1 QUIT :see you") != NULL,
                 "qa1 did not see qa2's QUIT with reason and hostmask: %s",
                 tc_buffer(&qa1));
    TF_CHECK_MSG(tf_count(tc_buffer(&qa1), " PART ") == 0,
                 "qa1 saw a PART for qa2's QUIT: %s", tc_buffer(&qa1));
    TF_CHECK_MSG(tc_expect_eof(&qa2, T_IO_MS) == 0,
                 "qa2 did not see a clean EOF after QUIT");
    tc_close(&qa2);

    /* --- 2. the renamer gets its own NICK echo; members see it once --- */
    register_as(&solo, node.port, "soloB");
    TF_CHECK_MSG(tc_send(&solo, "JOIN #qchan") == 0, "solo JOIN failed");
    TF_CHECK_MSG(tc_expect(&solo, " 366 ", T_IO_MS) == 0,
                 "solo JOIN never completed");
    TF_CHECK_MSG(tc_send(&solo, "NICK soloB2") == 0, "solo NICK send failed");
    TF_CHECK_MSG(tc_expect(&solo, " NICK soloB2", T_IO_MS) == 0,
                 "renamer never saw its own NICK echo: %s", tc_buffer(&solo));
    TF_CHECK_MSG(strstr(tc_buffer(&solo),
                        ":soloB!soloB@127.0.0.1 NICK soloB2") != NULL,
                 "renamer's echo lacks the old hostmask prefix: %s",
                 tc_buffer(&solo));
    TF_CHECK_MSG(tc_expect(&qa1, " NICK soloB2", T_IO_MS) == 0,
                 "channel member never saw the rename: %s", tc_buffer(&qa1));
    TF_CHECK_MSG(tf_count(tc_buffer(&qa1),
                          ":soloB!soloB@127.0.0.1 NICK soloB2") == 1,
                 "channel member did not see the rename exactly once: %s",
                 tc_buffer(&qa1));
    tc_close(&solo);
    tc_close(&qa1);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 3, T_IO_MS) == 0,
                 "accepted should be 3");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 3, T_IO_MS) == 0,
                 "closed should be 3");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");

    nf_free(&node);
    tf_done("quit_nick_echo");
    return 0;
}
