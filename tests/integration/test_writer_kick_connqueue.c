/* test_writer_kick_connqueue.c -- Issue #294, gap 2: the dispatch that queues
 * directly.
 *
 * server_queue() is conn_queue() plus a kick to the owning writer. A dispatch
 * that calls conn_queue() itself skips the kick, and at N > 0 the loop never
 * pumps -- writers own the drain -- so the bytes move only if something kicks.
 * That something is the loop's post-dispatch POLLOUT arm (poll_loop.c's
 * conn_on_writable), which kicks because queued bytes mean POLLOUT demand the
 * loop would otherwise serve itself.
 *
 * The test queues one NOTICE via bare conn_queue() on a TRIGGER command and
 * asserts it arrives within one second with no second line: a lost kick parks
 * it past the bound, and a double-delivery (loop and writer both draining)
 * fails the exactly-once count.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 10000
#define T_ARRIVE_MS 1000
#define T_QUIET_MS 400

static const char k_notice[] = ":irc.fixture NOTICE you :kicked\r\n";

static void kick_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const char *cmd = (m->command != NULL) ? m->command : "";

    (void)s;
    if (strcmp(cmd, "TRIGGER") != 0) {
        return;
    }
    /* DIRECTLY, with no server_queue() and therefore no kick: the POLLOUT arm
     * is the only thing that may move these bytes. */
    TF_CHECK_MSG(conn_queue(c, k_notice, strlen(k_notice)) == 0,
                 "direct conn_queue() refused the NOTICE");
}

static void setup(server_t *s)
{
    s->dispatch = kick_dispatch;
    server_set_writer_threads(s, 4);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    const char *buf;
    int count = 0;
    int eof = 0;
    const char *at;

    TF_CHECK_MSG(nf_spawn_inline(&node, setup) == 0, "inline N=4 spawn failed");
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");
    TF_CHECK_MSG(tc_send(&c, "TRIGGER") == 0, "TRIGGER send failed");
    TF_CHECK_MSG(tc_expect(&c, "kicked", T_ARRIVE_MS) == 0,
                 "the directly-queued NOTICE did not arrive within 1s, so the "
                 "kick path the POLLOUT arm owns lost it: %s",
                 tc_buffer(&c));
    /* EXACTLY ONCE. A second delivery would mean two drainers both owned the
     * queue -- the shape a loop-that-pumps beside writers would take. */
    buf = tc_buffer(&c);
    for (at = buf; (at = strstr(at, "kicked")) != NULL; at++, count++) {
    }
    TF_CHECK_MSG(count == 1, "NOTICE delivered %d times, want exactly once",
                 count);
    /* tc_drain() DISCARDS the buffer and reports whether it held anything, so
     * a single drain cannot tell the NOTICE from a second line. Clear first
     * (a zero timeout only drops what is already buffered), then the timed
     * drain must find nothing new. */
    (void)tc_drain(&c, 0, &eof);
    eof = 0;
    TF_CHECK_MSG(tc_drain(&c, T_QUIET_MS, &eof) == 0 && eof == 0,
                 "a second line arrived after the NOTICE: %s", tc_buffer(&c));
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("writer_kick_connqueue");
    return 0;
}
