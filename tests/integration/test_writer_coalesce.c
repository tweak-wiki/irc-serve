/* test_writer_coalesce.c -- Issue #279: one kick per emission, not per member.
 *
 * Two conns sharing one owner slot are queued quietly and kicked once as a
 * set: the owner wakes exactly once (not once per member) and both conns
 * drain. Untouched slots stay parked.
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
#define NCONN 8
#define DEADLINE_MS 10000
#define PAYLOAD "PING :coalesced\r\n"

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
    conn_t *conns[NCONN];
    int peers[NCONN];
    int i;
    int a = -1;
    int b = -1;
    int slot = -1;
    long long deadline;
    unsigned long before[NW];

    memset(&s, 0, sizeof s);
    memset(conns, 0, sizeof conns);
    for (i = 0; i < NCONN; i++) {
        peers[i] = -1;
    }
    TF_CHECK_MSG(server_init(&s, "coalesce.test") == 0, "server_init failed");
    for (i = 0; i < NCONN; i++) {
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
    }
    /* Two conns on the same owner slot: consecutive socketpair fds cycle
     * through slots, so a repeat within 8 conns at N=4 is guaranteed. */
    for (i = 0; i < NCONN && a < 0; i++) {
        int k;

        for (k = i + 1; k < NCONN; k++) {
            if (conns[i]->fd % NW == conns[k]->fd % NW) {
                a = i;
                b = k;
                slot = conns[i]->fd % NW;
                break;
            }
        }
    }
    TF_CHECK_MSG(a >= 0, "no shared owner slot");
    server_set_writer_threads(&s, NW);
    TF_CHECK_MSG(server_writers_start(&s) == 0, "pool did not start");

    (void)usleep(100000);
    for (i = 0; i < NW; i++) {
        before[i] = wakes(&s, i);
    }

    /* Quiet queue on both, then ONE kick carrying the slot twice: dedupe
     * must collapse it to a single wake. */
    TF_CHECK_MSG(server_queue_quiet(&s, conns[a], PAYLOAD, strlen(PAYLOAD)) == 0,
                 "quiet queue refused");
    TF_CHECK_MSG(server_queue_quiet(&s, conns[b], PAYLOAD, strlen(PAYLOAD)) == 0,
                 "quiet queue refused");
    {
        int slots[2];

        slots[0] = slot;
        slots[1] = slot;
        server_writers_kick_slots(&s, slots, 2u);
    }
    server_writers_kick_slots(NULL, NULL, 0u); /* no-op, must not crash */
    server_writers_kick_slots(&s, NULL, 0u);

    deadline = now_us() + (long long)DEADLINE_MS * 1000LL;
    for (;;) {
        char sink[1024];

        while (read(peers[a], sink, sizeof sink) > 0) {
        }
        while (read(peers[b], sink, sizeof sink) > 0) {
        }
        if (conn_write_pending_locked(conns[a]) == 0u &&
            conn_write_pending_locked(conns[b]) == 0u) {
            break;
        }
        TF_CHECK_MSG(now_us() < deadline, "stall: coalesced kick never drained");
        (void)usleep(1000);
    }
    TF_CHECK_MSG(wakes(&s, slot) == before[slot] + 1u,
                 "owner slot %d woke %lu times, want exactly one more than %lu",
                 slot, wakes(&s, slot), before[slot]);
    for (i = 0; i < NW; i++) {
        if (i == slot) {
            continue;
        }
        TF_CHECK_MSG(wakes(&s, i) == before[i],
                     "writer %d woke on another slot's coalesced kick: %lu != %lu",
                     i, wakes(&s, i), before[i]);
    }

    server_shutdown(&s);
    for (i = 0; i < NCONN; i++) {
        (void)close(peers[i]);
    }
    printf("PASS test_writer_coalesce\n");
    return 0;
}
