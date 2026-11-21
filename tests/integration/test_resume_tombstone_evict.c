/* test_resume_tombstone_evict.c -- #333: a full table evicts a tombstone first.
 *
 * resume_note() at a full table used to drop index 0 unconditionally. A retired
 * window (tombstone) can sit BEHIND a live one when the clock stepped back
 * between notes -- the older note carries the later stamp, so the sweep retires
 * the younger-looking entries first -- and then the eviction dropped the live
 * window while dead weight stayed. A retired window can never resume again
 * (its owner was already told), so that trade loses a live session for
 * nothing.
 *
 * In-process with explicit timestamps, no sleeps: X is noted with a
 * future stamp (live at every later `now` below), 63 others with past stamps
 * (retired by the sweep but inside their grace, so still held), the table is
 * filled to IRC_RESUME_MAX, and one more note forces the eviction. X must
 * still resume afterwards (resume_apply returns 1); with the old victim the
 * eviction took X itself and the apply returns 0. */
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
#define WINDOW_MS 10000u
#define SWEEP_NOW 11001u

/* One drop: claim, join, note at `when`, then leave as the reaper would. The
 * nick stays unclaimed afterwards, so a later connection can hold it again. */
static conn_t *drop_one(server_t *s, chan_t *ch, int *peer_fd, const char *nick,
                        uint64_t when)
{
    int pair[2];
    conn_t *c;

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                 "socketpair failed for %s", nick);
    c = conn_new(pair[0], CONN_CLIENT);
    TF_CHECK_MSG(c != NULL, "conn_new failed for %s", nick);
    TF_CHECK_MSG(server_add_conn(s, c) == 0, "%s conn not registered", nick);
    TF_CHECK_MSG(strlen(nick) < IRC_MAX_NICK, "nick too long: %s", nick);
    memcpy(c->nick, nick, strlen(nick) + 1u);
    memcpy(c->user, nick, strlen(nick) + 1u);
    memcpy(c->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(s, nick, c) == 0,
                 "nick claim failed for %s", nick);
    TF_CHECK_MSG(chan_admit(s, c, ch, 0u) == 0, "join failed for %s", nick);
    resume_note(s, c, when);
    server_nick_unclaim(s, c);
    chan_member_leave(s, ch, c, 0, "");
    *peer_fd = pair[1];
    return c;
}

int main(void)
{
    server_t s;
    chan_t *ch;
    conn_t *back;
    int backpair[2];
    int peers[IRC_RESUME_MAX + 1u];
    size_t i;
    char nick[32];

    TF_CHECK_MSG(server_init(&s, NODE) == 0, "server_init failed");
    resume_set_window(&s, WINDOW_MS);

    ch = chan_new(CHAN, NODE, s.epoch);
    TF_CHECK_MSG(ch != NULL, "chan_new failed");
    TF_CHECK_MSG(server_chan_attach(&s, ch) == 0, "chan attach failed");

    /* X, noted with a stamp in the future: no sweep below retires it. */
    (void)drop_one(&s, ch, &peers[0], "rx", 50000u);
    /* 63 more, noted in the past: old enough to retire at SWEEP_NOW. */
    for (i = 0; i < IRC_RESUME_MAX - 1u; i++) {
        (void)snprintf(nick, sizeof nick, "ry%02zu", i);
        (void)drop_one(&s, ch, &peers[i + 1u], nick, 1000u + (uint64_t)i);
    }
    TF_CHECK_MSG(resume_count(&s) == IRC_RESUME_MAX,
                 "table is not full: resume_count=%zu", resume_count(&s));

    /* Retire the past-stamped windows. X's stamp is still in the future, so
     * it stays live at index 0 with 63 tombstones behind it -- the state the
     * old eviction got wrong. Nothing is freed: all retired inside grace. */
    (void)resume_sweep(&s, SWEEP_NOW);
    TF_CHECK_MSG(resume_count(&s) == IRC_RESUME_MAX,
                 "sweep freed windows inside grace: resume_count=%zu",
                 resume_count(&s));

    /* One more note at a full table: the eviction fires. */
    (void)drop_one(&s, ch, &peers[IRC_RESUME_MAX], "rz", SWEEP_NOW);
    TF_CHECK_MSG(s.n_resume_evicted == 1u, "no eviction fired: evicted=%llu",
                 (unsigned long long)s.n_resume_evicted);
    TF_CHECK_MSG(resume_count(&s) == IRC_RESUME_MAX,
                 "table did not stay full: resume_count=%zu", resume_count(&s));

    /* X must still resume: the victim was the oldest tombstone, not X. With
     * the old index-0 victim this apply finds no window and returns 0. */
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, backpair) == 0,
                 "socketpair failed for the returning session");
    back = conn_new(backpair[0], CONN_CLIENT);
    TF_CHECK_MSG(back != NULL, "conn_new failed for the returning session");
    TF_CHECK_MSG(server_add_conn(&s, back) == 0, "back conn not registered");
    memcpy(back->nick, "rx", sizeof "rx");
    memcpy(back->user, "rx", sizeof "rx");
    memcpy(back->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(&s, "rx", back) == 0,
                 "nick reclaim failed for the returning session");
    TF_CHECK_MSG(resume_apply(&s, back, SWEEP_NOW) == 1,
                 "X's live window was evicted while tombstones sat behind it "
                 "(#333): the full-table victim must be a retired window "
                 "first");

    for (i = 0; i < IRC_RESUME_MAX + 1u; i++) {
        close(peers[i]);
    }
    close(backpair[1]);
    /* Every conn registered: freed through the node's own exit path. */
    server_shutdown(&s);
    tf_done("resume_tombstone_evict");
    return 0;
}
