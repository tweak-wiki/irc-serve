/* test_writer_slice.c -- MT 3.x (#369): writers drain a bounded slice per conn.
 *
 * A writer with an unbounded backlog on one conn must drain at most
 * CONN_WQ_SLICE bytes, then move on to the next owned conn with queued
 * bytes -- round-robin, not priority -- so a thin conn's reply goes out
 * within one slice of being queued while the fat conn still progresses.
 *
 * In-process against server_t with ONE writer thread, because that is the
 * sharpest form of the claim: the order is deterministic (the scan visits
 * the fat conn first, the thin conn second) and no kick from the test
 * disturbs it (writers start only after both conns are queued, so exactly
 * one drain pass runs before the test looks). A wire-level test cannot pin
 * this: on loopback the socket absorbs a whole backlog in milliseconds, so
 * "thin waited behind fat" is a race rather than an assertion. What is
 * asserted here holds on any kernel:
 *
 *   1. once the thin conn's queue is empty, the fat conn still holds at
 *      least a full cap minus two slices -- at most two slices moved before
 *      the thin conn was served (one racing pass may revisit fat first),
 *      whatever the socket buffers hold;
 *   2. with the peers reading and a kick per pass, the fat conn then drains
 *      to empty, byte-exact -- the slice bounds one visit, it does not
 *      starve the fat conn.
 *
 * Against the pre-fix writer (one unbounded conn_pump per visit) the first
 * assertion fails wherever the socket absorbs more than a slice, which is
 * why the peer buffers are REQUESTED large (256 KB each end; requested, not
 * measured -- see test_partial_write.c for why a read-back comparison would
 * be macOS-only). Post-fix it passes with any buffer size, because moving at
 * most one slice is what the code does, not what the kernel allows.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/server.h"
#include "harness/test_util.h"

#define T_DRAIN_MS 15000
#define CHUNK_BYTES (16u * 1024u)
#define THIN_LINE ":irc.fixture NOTICE you :THIN-OK\r\n"

/* Fill pattern: position-dependent, so a duplication or reorder fails the
 * final comparison. */
static void pattern_at(size_t offset, char *dst, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (char)('!' + (int)((offset + i) % 251u));
    }
}

static long long now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

/* Read whatever the peer holds without blocking. Returns bytes read. */
static size_t drain_peer(int fd, char *dst, size_t n)
{
    size_t off = 0;

    for (;;) {
        ssize_t got = recv(fd, dst + off, n - off, 0);

        if (got > 0) {
            off += (size_t)got;
            if (off == n) {
                break;
            }
            continue;
        }
        break;
    }
    return off;
}

int main(void)
{
    server_t server;
    conn_t *fat = NULL;
    conn_t *thin = NULL;
    int fat_pair[2] = { -1, -1 };
    int thin_pair[2] = { -1, -1 };
    char chunk[CHUNK_BYTES];
    size_t queued = 0;
    size_t fat_pending = 0;
    size_t thin_pending = 0;
    long long deadline;
    char *got = NULL;
    size_t got_off = 0;
    int bigbuf = 256 * 1024;
    int flags;

    memset(&server, 0, sizeof server);
    TF_CHECK_MSG(server_init(&server, "slice.test") == 0, "server_init failed");

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, fat_pair) == 0,
                 "fat socketpair failed");
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, thin_pair) == 0,
                 "thin socketpair failed");
    /* Large buffers so one unbounded pump COULD take the whole backlog (and
     * the pre-fix writer demonstrably does); requested, never read back. */
    (void)setsockopt(fat_pair[0], SOL_SOCKET, SO_SNDBUF, &bigbuf, sizeof bigbuf);
    (void)setsockopt(fat_pair[0], SOL_SOCKET, SO_RCVBUF, &bigbuf, sizeof bigbuf);
    (void)setsockopt(fat_pair[1], SOL_SOCKET, SO_SNDBUF, &bigbuf, sizeof bigbuf);
    (void)setsockopt(fat_pair[1], SOL_SOCKET, SO_RCVBUF, &bigbuf, sizeof bigbuf);
    /* Peer ends nonblocking: the progress half of this test reads whatever
     * is there without ever waiting in recv(). */
    flags = fcntl(fat_pair[1], F_GETFL, 0);
    (void)fcntl(fat_pair[1], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(thin_pair[1], F_GETFL, 0);
    (void)fcntl(thin_pair[1], F_SETFL, flags | O_NONBLOCK);

    fat = conn_new(fat_pair[0], CONN_CLIENT);
    thin = conn_new(thin_pair[0], CONN_CLIENT);
    TF_CHECK_MSG(fat != NULL && thin != NULL, "conn_new failed");
    TF_CHECK_MSG(server_add_conn(&server, fat) == 0, "fat add failed");
    TF_CHECK_MSG(server_add_conn(&server, thin) == 0, "thin add failed");

    /* Queue the whole backlog BEFORE writers exist, so no pass runs until
     * both conns hold what the test says they hold. */
    for (queued = 0; queued < CONN_WQ_MAX; queued += CHUNK_BYTES) {
        pattern_at(queued, chunk, CHUNK_BYTES);
        TF_CHECK_MSG(server_queue(&server, fat, chunk, CHUNK_BYTES) == 0,
                     "fat queue refused at %zu", queued);
    }
    TF_CHECK_MSG(conn_write_pending_locked(fat) == CONN_WQ_MAX,
                 "fat holds %zu, expected a full cap",
                 conn_write_pending_locked(fat));
    TF_CHECK_MSG(server_queue(&server, thin, THIN_LINE, strlen(THIN_LINE)) == 0,
                 "thin queue refused");

    /* One writer: the scan visits fat first, thin second, every pass. */
    server_set_writer_threads(&server, 1);
    TF_CHECK_MSG(server_writers_start(&server) == 0, "writers_start failed");

    /* Writers start with a nonzero generation, so exactly one pass is already
     * due; the test process and the writer race after that, so a second pass
     * may visit fat before this thread observes the thin drain. Either way
     * the bound holds: fat moved at most three slices, not the whole
     * backlog. (A full socket buffer stops every slice early, so fewer is
     * common; and a trylock-skip under contention defers one slice to the
     * next pass.) */
    deadline = now_us() + (long long)T_DRAIN_MS * 1000LL;
    for (;;) {
        thin_pending = conn_write_pending_locked(thin);
        if (thin_pending == 0) {
            break;
        }
        TF_CHECK_MSG(now_us() < deadline,
                     "thin conn never drained: writers stalled with %zu pending",
                     thin_pending);
        (void)usleep(1000);
    }
    fat_pending = conn_write_pending_locked(fat);
    TF_CHECK_MSG(fat_pending >= CONN_WQ_MAX - 3u * CONN_WQ_SLICE,
                 "thin was served only after fat moved %zu bytes (more than "
                 "two %zu-byte slices): the writer drained the whole backlog "
                 "before moving on",
                 CONN_WQ_MAX - fat_pending, CONN_WQ_SLICE);

    /* Round-robin, not priority: the fat conn still drains, byte-exact. */
    got = (char *)malloc(CONN_WQ_MAX);
    TF_CHECK(got != NULL);
    deadline = now_us() + (long long)T_DRAIN_MS * 1000LL;
    for (;;) {
        got_off += drain_peer(fat_pair[1], got + got_off, CONN_WQ_MAX - got_off);
        if (conn_write_pending_locked(fat) == 0) {
            got_off += drain_peer(fat_pair[1], got + got_off,
                                  CONN_WQ_MAX - got_off);
            break;
        }
        TF_CHECK_MSG(now_us() < deadline,
                     "fat conn stalled with %zu queued: the slice starved it",
                     conn_write_pending_locked(fat));
        server_writers_kick(&server);
        (void)usleep(1000);
    }
    TF_CHECK_MSG(got_off == CONN_WQ_MAX,
                 "fat drained %zu of %zu bytes", got_off, CONN_WQ_MAX);
    for (queued = 0; queued < CONN_WQ_MAX; queued++) {
        char want;

        pattern_at(queued, &want, 1);
        if (got[queued] != want) {
            TF_CHECK_MSG(0, "fat byte %zu is 0x%02x, expected 0x%02x",
                         queued, (unsigned char)got[queued],
                         (unsigned char)want);
        }
    }
    free(got);

    server_shutdown(&server);
    (void)close(fat_pair[1]);
    (void)close(thin_pair[1]);
    tf_done("writer_slice");
    return 0;
}
