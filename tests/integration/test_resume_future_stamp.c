/* test_resume_future_stamp.c -- #323: a future-stamped window is NOT expired.
 *
 * resume_apply() has two expiry arms over the same subtraction
 * `now_ms - dropped_ms`, which is UNSIGNED: when now_ms < dropped_ms the
 * subtraction wraps to ~2^64, which is larger than every window bound, so the
 * arm reads "expired" for a window stamped in the FUTURE (clock stepped back
 * between resume_note() and the reclaim). The first arm carries the
 * `now_ms >= dropped_ms` guard; the second did not, so without the guard a
 * future-stamped window falls through the first arm live and is then retired
 * by the second.
 *
 * In-process: record a window at t=5000 via the real path (join, then
 * resume_note), then apply at t=4000 -- before the stamp. Without the guard
 * the second arm expires it (returns 0); with the guard the window restores
 * (returns 1). The apply time is EARLIER than the note time, which is exactly
 * what a backwards clock step looks like to this subtraction. */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/connection.h"
#include "core/resume.h"
#include "core/server.h"
#include "harness/test_util.h"

#define NODE "irc.test"
#define CHAN "#t"

int main(void)
{
    server_t s;
    chan_t *ch;
    conn_t *drop;
    conn_t *back;
    int droppair[2];
    int backpair[2];

    TF_CHECK_MSG(server_init(&s, NODE) == 0, "server_init failed");

    ch = chan_new(CHAN, NODE, s.epoch);
    TF_CHECK_MSG(ch != NULL, "chan_new failed");
    TF_CHECK_MSG(server_chan_attach(&s, ch) == 0, "chan attach failed");

    /* The dropped session: registered conn, nick claimed, joined, member. */
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, droppair) == 0,
                 "socketpair failed for the dropped session");
    drop = conn_new(droppair[0], CONN_CLIENT);
    TF_CHECK_MSG(drop != NULL, "conn_new failed for the dropped session");
    TF_CHECK_MSG(server_add_conn(&s, drop) == 0, "drop conn not registered");
    memcpy(drop->nick, "bob", sizeof "bob");
    memcpy(drop->user, "bob", sizeof "bob");
    memcpy(drop->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(&s, "bob", drop) == 0, "nick claim failed");
    TF_CHECK_MSG(chan_admit(&s, drop, ch, CHAN_MEMBER_OP) == 0,
                 "join failed for the dropped session");

    /* The loss, at t=5000: record the window, then release the nick and leave
     * the channel as the reaper would (state, not QUIT -- a QUIT records no
     * window, which is the case this test is not). */
    resume_note(&s, drop, 5000u);
    TF_CHECK_MSG(resume_count(&s) == 1u, "no window recorded: resume_count=%zu",
                 resume_count(&s));
    server_nick_unclaim(&s, drop);
    chan_member_leave(&s, ch, drop, 0, "");

    /* The return, at t=4000 -- BEFORE the stamp. A backwards clock step, and
     * the window must survive it. */
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, backpair) == 0,
                 "socketpair failed for the returning session");
    back = conn_new(backpair[0], CONN_CLIENT);
    TF_CHECK_MSG(back != NULL, "conn_new failed for the returning session");
    TF_CHECK_MSG(server_add_conn(&s, back) == 0, "back conn not registered");
    memcpy(back->nick, "bob", sizeof "bob");
    memcpy(back->user, "bob", sizeof "bob");
    memcpy(back->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(&s, "bob", back) == 0,
                 "nick reclaim failed for the returning session");

    TF_CHECK_MSG(resume_apply(&s, back, 4000u) == 1,
                 "a window stamped at t=5000 was treated as expired at t=4000: "
                 "the unsigned age wrapped and the second arm has no "
                 "now >= dropped guard");
    TF_CHECK_MSG(resume_count(&s) == 0u,
                 "the window was not consumed by the restore");

    close(droppair[1]);
    close(backpair[1]);
    /* Both conns registered: freed through the node's own exit path. */
    server_shutdown(&s);
    tf_done("resume_future_stamp");
    return 0;
}
