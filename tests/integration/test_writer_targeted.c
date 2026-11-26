/* test_writer_targeted.c -- Issue #367: targeted writer wakeup, never broadcast.
 *
 * One server_t with writer_threads = 4 and socketpair-backed conns.
 * Queueing bytes on one conn must wake exactly its owning writer (fd % N):
 * the owner's wq_wakes counter rises by one per drain turn and every other
 * writer's counter stays flat. Delivery of the queued bytes still proves
 * the drain happened.
 */
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/server.h"
#include "harness/test_util.h"

#define NW 4
#define DEADLINE_MS 10000
#define PAYLOAD "PING :targeted\r\n"

static long long now_us(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

static unsigned long wakes(server_t *s, int slot)
{
    return (unsigned long)atomic_load_explicit(&s->wq_wakes[slot],
                                               memory_order_relaxed);
}

int main(void)
{
    server_t s;
    conn_t *conns[NW];
    int peers[NW];
    int slots[NW];
    int i;
    int other = -1;
    int owner;
    long long deadline;
    unsigned long before[NW];
    size_t j;

    memset(&s, 0, sizeof s);
    memset(conns, 0, sizeof conns);
    for (i = 0; i < NW; i++) {
        peers[i] = -1;
    }
    TF_CHECK_MSG(server_init(&s, "target.test") == 0, "server_init failed");
    for (i = 0; i < NW; i++) {
        int pair[2];
        int flags;

        TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                     "socketpair failed");
        flags = fcntl(pair[0], F_GETFL, 0);
        (void)fcntl(pair[0], F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(pair[1], F_GETFL, 0);
        (void)fcntl(pair[1], F_SETFL, flags | O_NONBLOCK);
        conns[i] = conn_new(pair[0], CONN_CLIENT);
        TF_CHECK_MSG(conns[i] != NULL, "conn %d: conn_new failed", i);
        TF_CHECK_MSG(server_add_conn(&s, conns[i]) == 0,
                     "conn %d: server_add_conn failed", i);
        peers[i] = pair[1];
        slots[i] = pair[0] % NW;
    }
    /* Need two conns on different owner slots: consecutive socketpair fds
     * always cover at least two slots, but pin it rather than assume it. */
    for (i = 1; i < NW; i++) {
        if (slots[i] != slots[0]) {
            other = i;
            break;
        }
    }
    TF_CHECK_MSG(other >= 0, "no second owner slot (fds %d..%d all slot %d)",
                 conns[0]->fd, conns[NW - 1]->fd, slots[0]);
    server_set_writer_threads(&s, NW);
    TF_CHECK_MSG(server_writers_start(&s) == 0, "pool did not start");

    /* Let writers park, then baseline the wake counters. */
    (void)usleep(100000);
    for (i = 0; i < NW; i++) {
        before[i] = wakes(&s, i);
    }

    /* Queue on conn 0 only; the owner slot must take exactly one wake and
     * the rest must stay parked. */
    owner = slots[0];
    TF_CHECK_MSG(server_queue(&s, conns[0], PAYLOAD, strlen(PAYLOAD)) == 0,
                 "queue refused");
    /* #681: wait for the bytes on the wire (poll, no wq_lock held) instead
     * of polling conn_write_pending_locked() every millisecond. That poll
     * grabbed the conn's wq_lock, which the owner's drain takes as a
     * trylock: one collision parked the writer past its single consumed
     * wakeup with no re-kick coming, stalling to the deadline. The locked
     * read below runs only after bytes arrive, so it cannot collide with
     * the drain; the deadline still fails loudly on a genuine stall. */
    int delivered = 0;

    deadline = now_us() + (long long)DEADLINE_MS * 1000LL;
    for (;;) {
        char sink[1024];
        struct pollfd pfd;
        long long remain_us;
        int timeout_ms;

        while (read(peers[0], sink, sizeof sink) > 0) {
            delivered = 1;
        }
        if (delivered && conn_write_pending_locked(conns[0]) == 0u) {
            break;
        }
        TF_CHECK_MSG(now_us() < deadline, "stall: owner never drained");
        remain_us = deadline - now_us();
        timeout_ms = (remain_us > 0) ? (int)(remain_us / 1000LL) : 0;
        if (timeout_ms > 1000) {
            timeout_ms = 1000;
        }
        memset(&pfd, 0, sizeof pfd);
        pfd.fd = peers[0];
        pfd.events = POLLIN;
        (void)poll(&pfd, 1u, timeout_ms);
    }
    TF_CHECK_MSG(wakes(&s, owner) == before[owner] + 1u,
                 "owner slot %d woke %lu times, want exactly one more than %lu",
                 owner, wakes(&s, owner), before[owner]);
    for (j = 0; j < (size_t)NW; j++) {
        if ((int)j == owner) {
            continue;
        }
        TF_CHECK_MSG(wakes(&s, (int)j) == before[j],
                     "writer %zu woke on another conn's queue: %lu != %lu", j,
                     wakes(&s, (int)j), before[j]);
    }

    /* A targeted conn kick wakes its owner; NULL server/conn kicks are
     * no-ops -- never a broadcast. */
    for (i = 0; i < NW; i++) {
        before[i] = wakes(&s, i);
    }
    server_writers_kick_conn(&s, conns[other]);
    server_writers_kick_conn(NULL, NULL); /* no-op, must not crash */
    server_writers_kick_conn(&s, NULL);   /* no-op, must not crash */
    deadline = now_us() + (long long)DEADLINE_MS * 1000LL;
    while (now_us() < deadline) {
        unsigned long want_other = before[slots[other]] + 1u;

        if (wakes(&s, slots[other]) == want_other) {
            break;
        }
        (void)usleep(1000);
    }
    TF_CHECK_MSG(wakes(&s, slots[other]) == before[slots[other]] + 1u,
                 "kick_conn target slot %d: %lu != %lu", slots[other],
                 wakes(&s, slots[other]), before[slots[other]] + 1u);
    /* The two NULL kicks above must not have woken anyone: only the
     * targeted slot moved. */
    for (j = 0; j < (size_t)NW; j++) {
        if ((int)j == slots[other]) {
            continue;
        }
        TF_CHECK_MSG(wakes(&s, (int)j) == before[j],
                     "writer %zu woke on a kick for another slot: %lu != %lu",
                     j, wakes(&s, (int)j), before[j]);
    }

    server_shutdown(&s);
    for (i = 0; i < NW; i++) {
        (void)close(peers[i]);
    }
    printf("PASS test_writer_targeted\n");
    return 0;
}
