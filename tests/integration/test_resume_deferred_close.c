/* test_resume_deferred_close.c -- Issue #294, gap 3: resume across the
 * reap-deferral at N=4.
 *
 * At N > 0 a CLOSING conn with unsent bytes stays registered while writers
 * drain it, and only then does server_close_conn() run resume_note() -- up to
 * the 2 s wq_close_at deadline if the bytes never move. A client that drops
 * with a MODE reply still queued and reconnects immediately must still resume
 * (hit=1, auto re-admitted to its channel) rather than fall back to a fresh
 * registration, and the window must be noted on the drain path rather than at
 * the deadline.
 *
 * The test registers, JOINs, sends MODE (a reply is queued behind the drop),
 * closes the socket unread, and then: waits for the node's own
 * session_resume_note (proving the deferred close completed), measures the
 * drop-to-note delay against the 2000 ms deadline (proving the drain path,
 * not the deadline, recorded the window), reconnects the same nick+ident with
 * NO fresh JOIN, and asserts session_resume with joined=1 plus
 * resume_applied=1. A refused NICK (433) or a silent fresh registration fails
 * it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/commands.h"
#include "core/resume.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 10000
#define RESUME_WINDOW_MS 4000
/* The reap-deferral deadline server.c arms per fd (wq_close_at = now + 2000).
 * A note at or past it means the window was recorded by the deadline rather
 * than by the drain, which is the behaviour this test pins against. */
#define DEFER_DEADLINE_MS 2000

#define NICK "n4bob"
#define IDENT "n4bobident"
#define CHAN "#N4CHAN"

static void child_setup(server_t *s)
{
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    resume_set_window(s, RESUME_WINDOW_MS);
    server_set_writer_threads(s, 4);
}

static long long now_ms(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

/* Register and drain with a unique token, so every later wait is against bytes
 * read since. */
static void register_client(test_client_t *c, int port, const char *token)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "reconnect could not connect");
    (void)snprintf(line, sizeof line, "NICK %s", NICK);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", IDENT,
                   IDENT);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "no 001 on reconnect -- the nick may still be held by the "
                 "deferred close: %s",
                 tc_buffer(c));
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for the drain token: %s", tc_buffer(c));
}

int main(void)
{
    nf_node_t n;
    test_client_t c;
    long long dropped_at;
    long long noted_at;

    TF_CHECK_MSG(nf_spawn_inline(&n, child_setup) == 0,
                 "inline N=4 spawn failed");
    tc_init(&c);
    register_client(&c, n.port, "reg-first");
    TF_CHECK_MSG(tc_send(&c, "JOIN " CHAN) == 0, "JOIN failed");
    TF_CHECK_MSG(tc_expect(&c, " 366 ", T_IO_MS) == 0, "JOIN never completed");
    /* A reply is queued behind the drop: the MODE answer is still in wlen
     * when the FIN arrives, which is what arms the reap-deferral. Whether it
     * is armed or the writers already drained it, the oracle below is the
     * same -- the window must be noted promptly either way. */
    TF_CHECK_MSG(tc_send(&c, "MODE " CHAN) == 0, "MODE send failed");
    tc_close(&c);
    dropped_at = now_ms();
    TF_CHECK_MSG(nf_expect(&n,
                           "[observable] session_resume_note: nick=" NICK,
                           T_IO_MS) == 0,
                 "the node recorded no window for the dropped client: %s",
                 n.out);
    noted_at = now_ms();
    TF_CHECK_MSG(noted_at - dropped_at < DEFER_DEADLINE_MS,
                 "the window was noted %lld ms after the drop, at or past the "
                 "2 s deferral deadline -- the drain path did not record it: %s",
                 noted_at - dropped_at, n.out);

    /* Back within the window, and with NO fresh JOIN: the resume must carry
     * the client back onto the channel it never re-asked for. */
    tc_init(&c);
    register_client(&c, n.port, "reg-second");
    TF_CHECK_MSG(nf_expect(&n,
                           "[observable] session_resume: nick=" NICK
                           " ident=" IDENT " chans=1 joined=1",
                           T_IO_MS) == 0,
                 "no session_resume hit for the returning client, so the "
                 "deferred close lost the session and the reconnect fell back "
                 "to a fresh registration: %s",
                 n.out);
    TF_CHECK_MSG(nf_expect_u64(&n, "resume_applied=", 1u, T_IO_MS) == 0,
                 "resume_applied is not 1 after the hit: %s", n.out);
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&n) == 0, "node did not exit cleanly");
    nf_free(&n);
    tf_done("resume_deferred_close");
    return 0;
}
