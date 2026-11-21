/* test_final_drain.c -- issue #229: pipelined lines lost on EOF close.
 *
 * conn_readable() frames at most 128 lines per call, and the EOF/error arms of
 * conn_on_readable() drained once and then marked CLOSING, which stops the
 * loop's conn_has_line() revisit. A client that pipelined more than 128 lines
 * and closed lost everything past line 128. This pipelines 200 PINGs and
 * half-closes: all 200 must be framed (the node's lines= counter says so)
 * before the close is honoured.
 *
 * 200 is past the 128 budget and inside the 256-token rate burst, so no 417
 * can fire and the count below is purely about the drain. PING is pre_reg, so
 * no registration is needed and no reply traffic is asserted.
 */
#include <stdio.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* Past the 128-line per-call budget, inside the 256-token rate burst. */
#define N_PIPELINED 200

int main(void)
{
    nf_node_t node;
    test_client_t c;
    int i;

    tc_init(&c);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(nf_expect(&node, "client_connect:", T_IO_MS) == 0,
                 "node never reported the accept");
    /* One write() so the burst arrives as one chunk: the server's EOF fill
     * then holds all 200 lines at once, which is the shape that stranded
     * everything past line 128. */
    {
        static char bulk[N_PIPELINED * 24];
        size_t off = 0;

        for (i = 0; i < N_PIPELINED; i++) {
            off += (size_t)snprintf(bulk + off, sizeof bulk - off,
                                    "PING :drain%04d\r\n", i);
        }
        TF_CHECK_MSG(tc_send_raw(&c, bulk, off) == 0, "bulk send failed");
    }
    TF_CHECK_MSG(tc_half_close(&c) == 0, "tc_half_close failed");
    TF_CHECK_MSG(nf_expect(&node, "reason=eof", T_IO_MS) == 0,
                 "node never reported closing the connection");
    TF_CHECK_MSG(tc_expect_eof(&c, T_IO_MS) == 0, "no clean EOF from node");
    tc_close(&c);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* loop_stats prints once at shutdown: all 200 lines must have been
     * framed before the close was honoured (128 with the #229 bug). */
    TF_CHECK_MSG(nf_expect_u64(&node, "lines=", (uint64_t)N_PIPELINED,
                               T_IO_MS) == 0,
                 "node closed with fewer than %d lines framed", N_PIPELINED);
    nf_free(&node);
    tf_done("final_drain");
    return 0;
}
