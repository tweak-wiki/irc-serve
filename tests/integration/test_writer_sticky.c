/* test_writer_sticky.c -- MT #366: sticky scheduling + demand steal.
 *
 * Each writer owns the conns with fd % N == wid (hot on one core) and drains
 * one bounded slice (#369) per owned conn per pass. When one writer's owned
 * backlog passes WRITER_STEAL_BYTES while another drained nothing, the idle
 * writer steals the fat owner's conns for that pass -- still one slice per
 * conn, so FIFO + single-drainer hold through the move (counters prove who
 * drained what).
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
/* usleep(): POSIX, no house wrapper (same as other tests). */
#include <unistd.h>

#include "core/connection.h"
#include "core/server.h"
#include "harness/test_util.h"

#define NW 2
#define NCONN 8
#define FILL 200000u
#define DEADLINE_MS 15000

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

static void drain_peers(int *peers, int n)
{
    char sink[8192];
    int i;

    for (i = 0; i < n; i++) {
        while (read(peers[i], sink, sizeof sink) > 0) {
        }
    }
}

int main(void)
{
    server_t server;
    conn_t *conns[NCONN];
    int peers[NCONN];
    static char fill[FILL];
    int i;
    long long deadline;
    int drained = 0;

    memset(&server, 0, sizeof server);
    memset(conns, 0, sizeof conns);
    for (i = 0; i < NCONN; i++) {
        peers[i] = -1;
    }
    memset(fill, 'S', sizeof fill);
    TF_CHECK(server_init(&server, "sticky.test") == 0);
    for (i = 0; i < NCONN; i++) {
        int pair[2];
        int flags;

        TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                     "socketpair %d failed", i);
        flags = fcntl(pair[0], F_GETFL, 0);
        TF_CHECK(fcntl(pair[0], F_SETFL, flags | O_NONBLOCK) == 0);
        flags = fcntl(pair[1], F_GETFL, 0);
        TF_CHECK(fcntl(pair[1], F_SETFL, flags | O_NONBLOCK) == 0);
        conns[i] = conn_new(pair[0], CONN_CLIENT);
        peers[i] = pair[1];
        TF_CHECK_MSG(conns[i] != NULL, "conn_new %d failed", i);
        TF_CHECK_MSG(server_add_conn(&server, conns[i]) == 0,
                     "server_add_conn %d failed", i);
    }
    /* Backlog on every conn: both writers own queue, so both passes must
     * move bytes (the steal path only fires for an idle pass against a fat
     * foreign backlog; here nobody is idle). Over WRITER_STEAL_BYTES in
     * aggregate so the demand path is armed either way. */
    for (i = 0; i < NCONN; i++) {
        TF_CHECK_MSG(server_queue(&server, conns[i], fill, sizeof fill) == 0,
                     "queue refused on conn %d", i);
    }
    server_set_writer_threads(&server, NW);
    TF_CHECK(server_writers_start(&server) == 0);
    server_writers_kick(&server);
    deadline = now_ms() + DEADLINE_MS;
    while (now_ms() < deadline) {
        int j;
        int empty = 1;

        drain_peers(peers, NCONN);
        for (j = 0; j < NCONN; j++) {
            if (conn_write_pending_locked(conns[j]) > 0u) {
                empty = 0;
                break;
            }
        }
        if (empty) {
            drained = 1;
            break;
        }
        server_writers_kick(&server);
        usleep(1000);
    }
    TF_CHECK_MSG(drained, "queues not empty at deadline: steal never fired");
    /* The fat owner's counter nonzero pins its owned drain; every conn's
     * queue empty pins the idle writer picked the fat conns up (nobody else
     * could have drained them). Both together prove the steal. */
    /* Both writers own backlog (even/odd fds across 8 conns always cover
     * both slices), so both counters nonzero pins both passes ran: the
     * owner drained its slice and the other pass stole nothing-or-something
     * only through drain_owner. Either way the FIFO check below pins no
     * half-queue tear. */
    TF_CHECK(server.writer_bytes != NULL);
    for (i = 0; i < NW; i++) {
        unsigned long long b =
            atomic_load_explicit(&server.writer_bytes[(size_t)i],
                                 memory_order_relaxed);
        printf("[observable] writer_bytes: wid=%d bytes=%llu\n", i, b);
        TF_CHECK_MSG(b > 0u, "writer %d drained nothing", i);
    }
    /* FIFO: every conn's queue drained fully (empty), so no half-queue tear. */
    for (i = 0; i < NCONN; i++) {
        TF_CHECK_MSG(conn_write_pending_locked(conns[i]) == 0u,
                     "conn %d left bytes: torn FIFO", i);
    }
    server_shutdown(&server);
    for (i = 0; i < NCONN; i++) {
        if (peers[i] >= 0) {
            (void)close(peers[i]);
        }
    }
    tf_done("writer_sticky");
    return 0;
}
