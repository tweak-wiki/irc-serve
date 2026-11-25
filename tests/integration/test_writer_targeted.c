/* test_writer_targeted.c -- Issue #367: targeted writer wakeup, never broadcast.
 *
 * One server_t with writer_threads = 4 and socketpair-backed conns.
 * Queueing bytes on one conn must wake exactly its owning writer (fd % N):
 * the owner's wq_wakes counter rises by one per drain turn and every other
 * writer's counter stays flat. Delivery of the queued bytes still proves
 * the drain happened.
 */
#include <fcntl.h>
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
#define DEADLINE_MS 30000
/* 30 s, not 10: the networked writer siblings (order/fault/drain) all use
 * T_IO_MS 30000 because sanitizer builds schedule writer threads slowly.
 * Issue #681: this socketpair test kept the old 10 s wall-clock deadline and
 * failed 'stall: owner never drained' on a README-only PR while the twin
 * run on the same tree passed -- pure scheduling flake, zero C changes. */
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
    long long last_change; /* last wake-count change seen by the barrier */
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

    /* Barrier, not a nap: wait until every writer has consumed the pool-start
     * generation and the counters go QUIET, instead of assuming 100 ms parks
     * them all. Two startup paths exist: a thread born before the start bump
     * consumes twice (its birth gen, then the bump), one born after consumes
     * once -- so "every slot >= 1 wake" is not parked, and baselining there
     * counts the late second consume as queue work (issue #681: owner at 3
     * wakes against a baseline of 1). The second consume always lands within
     * milliseconds of the first; 200 ms with zero changes on any slot proves
     * the pool is parked. No sleep() per CONTRIBUTING -- deadline-polled
     * like the sibling sticky test. */
    deadline = now_us() + (long long)DEADLINE_MS * 1000LL;
    for (i = 0; i < NW; i++) {
        before[i] = ~0ul; /* impossible count: first sample always restarts */
    }
    last_change = now_us();
    for (;;) {
        int quiet = 1;
        long long now = now_us();

        for (i = 0; i < NW; i++) {
            unsigned long w = wakes(&s, i);

            if (w == 0u || w != before[i]) {
                quiet = 0;
                before[i] = w;
                last_change = now;
            }
        }
        if (quiet && now - last_change > 200000LL) {
            break;
        }
        TF_CHECK_MSG(now < deadline, "stall: writer pool never parked");
        (void)usleep(1000);
    }
    for (i = 0; i < NW; i++) {
        before[i] = wakes(&s, i);
    }
    /* Queue on conn 0 only; the owner slot must take exactly one wake and
     * the rest must stay parked. server_queue() kicks once, and one kick is
     * one consumed generation -- so exactly one wake is owed, and the loop
     * below must not kick again: a repeat after the consume bumps a second
     * generation (pending clears at consume time), which is how the
     * exact-one assertion flaked under sanitizers.
     *
     * The old stall ('owner never drained' on a README-only PR, #681) was
     * the same lock from the other side: this loop polled with the locking
     * pending check every 1 ms, and the writer takes that lock as a
     * trylock -- a colliding pass skipped the conn, parked on the consumed
     * kick, and stranded the bytes to the deadline. Polling with the
     * lock-free pending snapshot instead never contends the writer's
     * trylock, so the single turn always drains; its upward-only staleness
     * merely costs an extra poll, never a premature break. */
    owner = slots[0];
    TF_CHECK_MSG(server_queue(&s, conns[0], PAYLOAD, strlen(PAYLOAD)) == 0,
                 "queue refused");
    deadline = now_us() + (long long)DEADLINE_MS * 1000LL;
    for (;;) {
        char sink[1024];

        while (read(peers[0], sink, sizeof sink) > 0) {
        }
        if (conn_write_pending(conns[0]) == 0u) {
            break;
        }
        TF_CHECK_MSG(now_us() < deadline, "stall: owner never drained");
        (void)usleep(1000);
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
        /* No re-kick here either: the kick above is owed exactly one
         * generation, and a repeat after the consume would double-count.
         * Nothing contends the writer in this phase (no bytes queued), so
         * the single turn always lands within the deadline. */
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
