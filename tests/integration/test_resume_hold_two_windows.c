/* test_resume_hold_two_windows.c -- #318: the first sweep past only window 0's
 * hold must not dispose a channel a second window still holds.
 *
 * Two overlapping resume windows can name the same channel: A joins, drops,
 * returns, drops again <50ms later. A sweep past window 0's hold releases
 * window 0's channels via resume_reclaim(), and chan_dispose_if_empty() must
 * ask resume_holds() about the REMAINING windows before disposing -- window 1
 * still holds the channel, so it survives. Only the sweep past window 1's
 * hold disposes it.
 *
 * In-process: two drops at t0 and t0+40, sweep at t0+hold (channel alive,
 * both windows still recorded), sweep at t1+hold (channel gone). Without the
 * resume_holds() gate the first sweep would dispose the channel out from
 * under the live second window. */
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

/* A registered, nick-claimed, joined session, ready for resume_note(). */
static conn_t *new_session(server_t *s, int *peer_fd, chan_t *ch)
{
    int pair[2];
    conn_t *c;

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                 "socketpair failed");
    c = conn_new(pair[0], CONN_CLIENT);
    TF_CHECK_MSG(c != NULL, "conn_new failed");
    TF_CHECK_MSG(server_add_conn(s, c) == 0, "conn not registered");
    memcpy(c->nick, "bob", sizeof "bob");
    memcpy(c->user, "bob", sizeof "bob");
    memcpy(c->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(s, "bob", c) == 0, "nick claim failed");
    TF_CHECK_MSG(chan_admit(s, c, ch, CHAN_MEMBER_OP) == 0, "join failed");
    *peer_fd = pair[1];
    return c;
}

/* The reaper's half of a drop: record the window, then part the channel as a
 * lost session would (state, not QUIT). The detach mirrors the PART verb path:
 * chan_member_leave drops the channel side only, and a conn that still lists
 * a disposed channel corrupts the shutdown walk. */
static void drop_session(server_t *s, conn_t *c, chan_t *ch, uint64_t now_ms)
{
    resume_note(s, c, now_ms);
    server_nick_unclaim(s, c);
    chan_member_leave(s, ch, c, 0, "");
    TF_CHECK_MSG(chan_detach_conn(c, ch) == 0, "detach failed");
}

int main(void)
{
    server_t s;
    chan_t *ch;
    conn_t *first;
    conn_t *second;
    int peer1;
    int peer2;
    uint64_t t0;
    uint64_t t1;
    uint64_t hold;

    TF_CHECK_MSG(server_init(&s, NODE) == 0, "server_init failed");
    hold = resume_hold_ms(&s);
    TF_CHECK_MSG(hold > 50u, "hold must exceed the 40ms drop gap: hold=%llu",
                 (unsigned long long)hold);

    ch = chan_new(CHAN, NODE, s.epoch);
    TF_CHECK_MSG(ch != NULL, "chan_new failed");
    TF_CHECK_MSG(server_chan_attach(&s, ch) == 0, "chan attach failed");

    t0 = 100000u;
    t1 = t0 + 40u;

    /* The first drop records window 0; the channel is empty but held. */
    first = new_session(&s, &peer1, ch);
    drop_session(&s, first, ch, t0);
    TF_CHECK_MSG(resume_count(&s) == 1u, "window 0 not recorded");
    TF_CHECK_MSG(server_chan_get(&s, CHAN) != NULL,
                 "channel disposed on leave while window 0 holds it");

    /* The return and the second drop record window 1 on the same channel. */
    ch = server_chan_get(&s, CHAN);
    TF_CHECK_MSG(ch != NULL, "channel gone before the return");
    second = new_session(&s, &peer2, ch);
    drop_session(&s, second, ch, t1);
    TF_CHECK_MSG(resume_count(&s) == 2u, "window 1 not recorded");

    /* Past window 0's hold only: window 0 releases, window 1 still holds,
     * so the channel survives and both windows stay recorded. */
    TF_CHECK_MSG(resume_sweep(&s, t0 + hold) == 0u,
                 "no window should be freed by a hold release");
    TF_CHECK_MSG(server_chan_get(&s, CHAN) != NULL,
                 "first sweep disposed a channel window 1 still holds: "
                 "the reclaim ignored the remaining window");
    TF_CHECK_MSG(resume_count(&s) == 2u, "a window went missing");

    /* Past window 1's hold: nothing holds the channel, so it goes. */
    TF_CHECK_MSG(resume_sweep(&s, t1 + hold) == 0u,
                 "no window should be freed by a hold release");
    TF_CHECK_MSG(server_chan_get(&s, CHAN) == NULL,
                 "second sweep left a channel no window holds");
    TF_CHECK_MSG(resume_count(&s) == 2u,
                 "windows must outlive their holds until retire");

    close(peer1);
    close(peer2);
    /* Both conns registered: freed through the node's own exit path. */
    server_shutdown(&s);
    tf_done("resume_hold_two_windows");
    return 0;
}
