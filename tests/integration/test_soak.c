/* test_soak.c -- soak: a busy node for a bounded T, asserting no growth (#534).
 *
 * No long-run test existed: unit tests catch leaks they can see in one shot,
 * not state that accumulates a little per message. This spins a linked pair,
 * chats N clients through joins/parts/messages for T seconds, flaps the peer
 * link once mid-run, then asserts the surviving node's fd count and RSS are
 * back near the pre-load baseline (tolerant margins, not equality: allocators
 * and the kernel do not return every page on cue).
 *
 * BOUNDED FOR CI: IRC_SOAK_SECONDS sets T (default 30). The CTest TIMEOUT is
 * 150, six times the ~25 s a default run measures, per the per-test timeout
 * rule in tests/integration/CMakeLists.txt.
 *
 * PORTABILITY: fd/RSS sampling reads /proc/<pid> and exists only on Linux
 * (__linux__). Elsewhere both samplers return -1 and the growth asserts are
 * skipped; the functional tail (a fresh client still registers and chats
 * after the load) runs everywhere, so the test still earns its place. Under
 * ASan/TSan the RSS half is additionally skipped (their runtimes retain
 * freed memory by design; LSan, which runs in the same jobs, is the leak
 * oracle there) while the fd half still runs.
 *
 * NO FIXED sleep(): the load loop paces itself off CLOCK_MONOTONIC and the
 * link re-establishment after the flap is an nf_expect() deadline wait.
 */
#include <dirent.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define SECRET "irc-serve-soak-secret"
#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define NCLI 8
#define DEFAULT_SOAK_SECONDS 30L

static int g_peer_port;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

/* Client command surface BEFORE fed_open(): the fixture header explains why
 * the order matters (fed_open wraps whatever dispatch is already there). */
static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0, "fed_open() failed in the child");
    s->on_tick = child_tick;
    /* Short liveness pair (200/600 ms, the shipped three-to-one) and a short
     * retry ladder, copied from test_failover_reconnect.c: the mid-soak flap
     * freezes B with SIGSTOP, and A must notice (dead) and recover (retry)
     * in seconds, not in shipped 30/90 s. The numbers are the scale, not the
     * behaviour: the same code computes the same decisions. */
    fed_set_timeouts(s, 2000, 1500, 200, 600);
    fed_set_retry(s, 300, 1200, 4);
    if (g_peer_port <= 0) {
        return; /* the accepting side */
    }
    (void)memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", NAME_A,
                 g_peer_port);
}

static void register_client(test_client_t *c, int port, const char *nick)
{
    char line[256];

    tc_init(c);
    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered",
                 nick);
}

/* Monotonic seconds, for pacing the load loop without sleep(). */
static long now_seconds(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

static long soak_seconds(void)
{
    const char *env = getenv("IRC_SOAK_SECONDS");
    long v = DEFAULT_SOAK_SECONDS;

    if (env != NULL && env[0] != '\0') {
        char *end = NULL;
        long parsed = strtol(env, &end, 10);

        if (end != env && parsed > 0 && parsed <= 600) {
            v = parsed;
        }
    }
    return v;
}

#ifdef __linux__
/* RSS of another process in KiB, via /proc/<pid>/statm (resident field).
 * Returns -1 when the kernel will not say. */
static long sample_rss_kb(pid_t pid)
{
    char path[64];
    char buf[256];
    FILE *f = NULL;
    unsigned long size = 0UL;
    unsigned long resident = 0UL;
    long page_kb;

    (void)snprintf(path, sizeof path, "/proc/%d/statm", (int)pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1L;
    }
    if (fgets(buf, (int)sizeof buf, f) == NULL) {
        (void)fclose(f);
        return -1L;
    }
    (void)fclose(f);
    if (sscanf(buf, "%lu %lu", &size, &resident) != 2) {
        return -1L;
    }
    (void)size;
    page_kb = (long)(sysconf(_SC_PAGESIZE) / 1024L);
    if (page_kb <= 0) {
        return -1L;
    }
    return (long)resident * page_kb;
}

/* Open fd count of another process, by counting /proc/<pid>/fd entries.
 * Returns -1 when the kernel will not say. */
static long sample_fd_count(pid_t pid)
{
    char path[64];
    DIR *d = NULL;
    struct dirent *e = NULL;
    long n = 0L;

    (void)snprintf(path, sizeof path, "/proc/%d/fd", (int)pid);
    d = opendir(path);
    if (d == NULL) {
        return -1L;
    }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;
        }
        n++;
    }
    (void)closedir(d);
    return n > 0 ? n : -1L;
}
#else
static long sample_rss_kb(pid_t pid)
{
    (void)pid;
    return -1L;
}

static long sample_fd_count(pid_t pid)
{
    (void)pid;
    return -1L;
}
#endif

int main(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t clients[NCLI];
    char nick[32];
    char line[256];
    long budget;
    long deadline;
    long flap_at;
    int flapped = 0;
    int i;
    int round = 0;
    long base_fds;
    long base_rss;
    long end_fds;
    long end_rss;
    test_client_t fresh;
    int eof = 0;

    for (i = 0; i < NCLI; i++) {
        tc_init(&clients[i]);
    }
    tc_init(&fresh);

    /* Node A first (accepting side), then B dials it. */
    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");
    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);

    for (i = 0; i < NCLI; i++) {
        (void)snprintf(nick, sizeof nick, "soak%d", i);
        register_client(&clients[i], a.port, nick);
        (void)snprintf(line, sizeof line, "JOIN #soak");
        TF_CHECK_MSG(tc_send(&clients[i], line) == 0,
                     "client %d could not JOIN", i);
    }
    for (i = 0; i < NCLI; i++) {
        TF_CHECK_MSG(tc_expect(&clients[i], " 366 ", T_IO_MS) == 0,
                     "client %d never saw end-of-NAMES", i);
    }

    base_fds = sample_fd_count(a.pid);
    base_rss = sample_rss_kb(a.pid);

    /* The busy window: joins/parts/messages, paced UNDER the node's flood
     * token bucket (poll_loop.c: burst 256, refill 50 lines/sec per client).
     * An unpaced loop is not a soak, it is a flood test: the node 417s the
     * flooder, marks it CLOSING, never reads it again, and a further
     * blocking send wedges (or, once the reaper closes it, fails). So each
     * round sends ~1 line per client and naps 100 ms: 10 lines/sec/client,
     * 5x under the refill. The nap is pacing, not readiness (6.3).
     *
     * Every round also drains every client: nobody here asserts on the
     * chatter, but unread sockets would back the node's write queues up and
     * turn a leak test into a flow-control test. */
    budget = soak_seconds();
    deadline = now_seconds() + budget;
    flap_at = now_seconds() + budget / 2;
    while (now_seconds() < deadline) {
        struct timespec nap;
        int deof = 0;

        for (i = 0; i < NCLI; i++) {
            if (round % 4 == 3) {
                (void)snprintf(line, sizeof line, "PART #soak :flap-%d", round);
                TF_CHECK_MSG(tc_send(&clients[i], line) == 0,
                             "client %d PART failed in round %d", i, round);
                (void)snprintf(line, sizeof line, "JOIN #soak");
                TF_CHECK_MSG(tc_send(&clients[i], line) == 0,
                             "client %d re-JOIN failed in round %d", i, round);
            } else {
                (void)snprintf(line, sizeof line,
                               "PRIVMSG #soak :soak round %d from %d", round, i);
                TF_CHECK_MSG(tc_send(&clients[i], line) == 0,
                             "client %d PRIVMSG failed in round %d", i, round);
            }
            TF_CHECK_MSG(!tc_closed(&clients[i]),
                         "client %d was closed mid-soak (rate limiter?)", i);
            (void)tc_drain(&clients[i], 0, &deof);
        }
        round++;
        /* Flap the peer link once, halfway through: freeze B with SIGSTOP (the
         * failover test's pattern -- the socket stays open but unanswered),
         * require A to declare it dead, revive B, and require the SECOND
         * link_established before resuming the load. nf_expect_nth() with
         * want=2 because nf_expect() searches the accumulated buffer and
         * would match the pre-flap line. */
        if (!flapped && now_seconds() >= flap_at) {
            flapped = 1;
            TF_CHECK_MSG(kill(b.pid, SIGSTOP) == 0, "could not freeze node B");
            TF_CHECK_MSG(nf_expect(&a, "link_dead: peer=" NAME_B, T_IO_MS) == 0,
                         "node A never declared the frozen link dead: %s",
                         a.out);
            TF_CHECK_MSG(kill(b.pid, SIGCONT) == 0, "could not resume node B");
            TF_CHECK_MSG(nf_expect_nth(&a, "link_established: peer=" NAME_B,
                                       2u, T_IO_MS) == 0,
                         "node A never re-established its link: %s", a.out);
        }
        (void)memset(&nap, 0, sizeof nap);
        nap.tv_nsec = 100L * 1000L * 1000L; /* 100 ms pacing, see above */
        (void)nanosleep(&nap, NULL);
    }

    /* Drain the room: every load client parts and disconnects, so the growth
     * asserts below measure retained state, not open connections. */
    for (i = 0; i < NCLI; i++) {
        (void)tc_send(&clients[i], "PART #soak :done");
        tc_close(&clients[i]);
    }

    /* Let the reaper run: the node only notices closed clients when it
     * serves something, so a fresh client registering + chatting both
     * quiesces the node and proves it still works after the load. */
    register_client(&fresh, a.port, "soakfresh");
    TF_CHECK_MSG(tc_send(&fresh, "JOIN #soak") == 0, "fresh JOIN failed");
    TF_CHECK_MSG(tc_expect(&fresh, " 366 ", T_IO_MS) == 0,
                 "fresh client never saw end-of-NAMES");
    TF_CHECK_MSG(tc_send(&fresh, "PRIVMSG #soak :still alive") == 0,
                 "fresh PRIVMSG failed");
    (void)tc_drain(&fresh, 2000, &eof);
    (void)eof;

    end_fds = sample_fd_count(a.pid);
    end_rss = sample_rss_kb(a.pid);

    /* Tolerant margins: +2 fds (a transient accept/reap race), and RSS +2 MiB
     * or +10%, whichever is larger (allocator high-water, not a leak). */
    if (base_fds >= 0 && end_fds >= 0) {
        TF_CHECK_MSG(end_fds <= base_fds + 2,
                     "fd growth: baseline %ld, after soak %ld", base_fds,
                     end_fds);
    }
    /* No RSS assert under a sanitizer runtime: ASan's quarantine and TSan's
     * shadow deliberately retain freed memory, so resident size grows with
     * churn there even when nothing leaks (measured +4.4 MiB on a clean
     * run). The leak oracle in those jobs is LSan, which fails the run at
     * child exit before this line is reached. The fd assert above -- the
     * sharper signal, since fds are never quarantined -- runs everywhere. */
    /* Apple Clang predefines neither __SANITIZE_*__ macro, so both spellings
     * are asked: __has_feature where it exists, the GCC macros elsewhere. */
#ifdef __has_feature
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define SOAK_SANITIZER_RSS_SKIP 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SOAK_SANITIZER_RSS_SKIP 1
#endif
#ifdef SOAK_SANITIZER_RSS_SKIP
    (void)base_rss;
    (void)end_rss;
#else
    if (base_rss > 0 && end_rss > 0) {
        long slack = base_rss / 10;

        if (slack < 2048L) {
            slack = 2048L;
        }
        TF_CHECK_MSG(end_rss <= base_rss + slack,
                     "RSS growth: baseline %ld KiB, after soak %ld KiB",
                     base_rss, end_rss);
    }
#endif

    tc_close(&fresh);
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B exited nonzero: %s", b.out);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A exited nonzero: %s", a.out);
    return 0;
}
