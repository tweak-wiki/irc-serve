/* server_lifecycle.c -- see core/server.h. The server_t lifecycle
 * (server_init plus the msgid seed helpers), the clock (server_now_ms), the
 * tick (server_tick) and the msg-id counter (server_next_msg_id), verbatim
 * out of server.c (issue #543); this is the final family, so server.c is now
 * a split-map pointer file only. All four functions were already declared in
 * core/server.h and the two seed helpers stay static here, so there is no
 * new header (server_shutdown.c precedent).
 */
#include "core/server.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

#include "core/message.h"
#include "core/resume.h"
#include "federation/burst.h"
#include "federation/link.h"
/* The nick/channel string -> pointer map (open-addressed strtab). */
#include "core/strtab.h"

/* ---------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------------
 */

/* ---------------------------------------------------------------------------
 * The first msg_id of a boot is RANDOM, not 1 (issue #180).
 * ---------------------------------------------------------------------------
 * (origin, epoch, id) is the dedup key, and epoch is only boot-time
 * milliseconds: two boots in the same millisecond share an epoch, so a counter
 * that restarts at 1 reissues (origin, epoch, 1..N) and a peer drops the replay
 * as a duplicate. A random 64-bit start makes a collision need the same epoch
 * AND the same draw, which is not a thing that happens twice.
 *
 * One draw per boot, here rather than per message: getrandom()/arc4random_buf()
 * once is free, per message it would be a syscall per relay. 0 is never drawn:
 * it means "unset", and server_next_msg_id() already skips it on wrap, so the
 * counter keeps its shape (monotonic, wrap-skip-0) whatever the start. Epoch is
 * untouched: still the boot time in milliseconds.
 *
 * No new dependency: arc4random_buf() on Apple/BSD, getrandom() on Linux, and a
 * server_now_ms/pid mix when neither is available or the call fails. The
 * fallback only has to be better than a constant, and differing boots differ
 * in time or pid; adjacent milliseconds are spread by a Knuth constant so
 * adjacent boots do not get adjacent starts. */
static uint64_t server_msgid_fallback(void)
{
    uint64_t v;

    v = server_now_ms() * 6364136223846793005ULL +
        (uint64_t)getpid() * 1442695040888963407ULL;
    return (v != 0) ? v : 1;
}

static uint64_t server_msgid_seed(void)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
    uint64_t v = 0;

    arc4random_buf(&v, sizeof v);
    return (v != 0) ? v : server_msgid_fallback();
#elif defined(__linux__)
    uint64_t v = 0;
    ssize_t n = getrandom(&v, sizeof v, 0);

    if (n == (ssize_t)sizeof v && v != 0) {
        return v;
    }
    return server_msgid_fallback();
#else
    return server_msgid_fallback();
#endif
}

int server_init(server_t *s, const char *name)
{
    if (s == NULL || name == NULL) {
        return -1;
    }
    memset(s, 0, sizeof *s);
    s->listen_fd = -1;
    /* Phase 12: there is NO second listener until an operator asks for one with
     * --tls-port. -1 rather than 0, because 0 is a legal descriptor and the
     * loop's step 3 tests this field against >= 0. */
    s->tls_listen_fd = -1;
    s->tls_listen_port = -1;

    /* A name this node cannot stamp on its own irc-serve-origin tag would
     * break the never-forward-own-origin rule at the first relay, so it is
     * refused here rather than discovered in Phase 6. */
    if (!irc_serve_server_name_valid(name)) {
        return -1;
    }
    if (strlen(name) > IRC_MAX_SERVER_NAME) {
        return -1;
    }
    memcpy(s->name, name, strlen(name) + 1u);

    s->by_fd = (conn_t **)calloc(SERVER_FD_TABLE, sizeof *s->by_fd);
    /* Folded and exact, for the reasons spelled out at the strtab: 2.1 makes
     * nicknames case-insensitive while the case the user chose is what gets
     * displayed, and 2.2 makes a channel name uppercase-normalised, which is
     * also how it is displayed. Issue #331: both tables share one per-boot
     * random seed (same source as the #180 msg_id start), so the home bucket
     * of every key differs per boot and pre-computed collisions do not hold. */
    s->hash_seed = server_msgid_seed();
    s->nicks = strtab_new(1, s->hash_seed);
    s->chans = strtab_new(0, s->hash_seed);
    if (s->by_fd == NULL || s->nicks == NULL || s->chans == NULL) {
        server_shutdown(s);
        return -1;
    }

    /* 2.4: epoch is per-boot and both counters start at 1, because id 0 is
     * reserved as "unset" so an absent tag is never read as a real id. The
     * epoch is the boot time in milliseconds, which is monotonic enough for a
     * value that only has to differ from the previous boot's. */
    s->epoch = server_now_ms();
    if (s->epoch == 0) {
        s->epoch = 1;
    }
    /* Issue #180: the start is random per boot (server_msgid_seed), never 0.
     * Same-epoch reboots would otherwise reissue the same low ids. */
    s->msg_id = server_msgid_seed();

    /* Issue #173: seed the per-node federation and resume configuration with
     * the shipped defaults, so a node that never calls a setter and a node
     * whose setter passes 0 ("keep the built-in") both run the documented
     * values. The setters only ever OVERWRITE these fields, which is what
     * keeps two server_t in one process from sharing them. */
    s->fed_dial_ms = (uint64_t)IRC_FED_DIAL_TIMEOUT_MS;
    s->fed_hs_ms = (uint64_t)IRC_FED_HS_TIMEOUT_MS;
    s->fed_advertise_ms = (uint64_t)IRC_FED_ADVERTISE_MS;
    s->fed_keepalive_ms = (uint64_t)IRC_FED_KEEPALIVE_MS;
    s->fed_dead_ms = (uint64_t)IRC_FED_DEAD_MS;
    s->fed_retry_base_ms = (uint64_t)IRC_FED_RETRY_BASE_MS;
    s->fed_retry_max_ms = (uint64_t)IRC_FED_RETRY_MAX_MS;
    s->fed_retry_budget = (unsigned)IRC_FED_RETRY_BUDGET;
    s->burst_max_bytes = (size_t)IRC_BURST_MAX_BYTES;
    s->resume_window_ms = (uint64_t)IRC_RESUME_WINDOW_MS;
    /* MT 2.2 (#241): the seam default; the pool starts in server_writers_start()
     * once the count is set (node_main / tests call the seam before serving). */
    s->writer_threads = 0;
    s->writers = NULL;
    s->slots = NULL;
    s->writer_bytes = NULL;
    s->wq_stop = 0;
    s->writers_started = 0;
    /* MT 2.2: reg_mu guards the registry against writer scans. Initialized
     * here (not in writers_start) so the loop's add/close paths can take it
     * unconditionally, even at N == 0 where it is uncontended. */
    if (pthread_mutex_init(&s->reg_mu, NULL) != 0) {
        server_shutdown(s);
        return -1;
    }
    s->reg_started = 1;
    /* The resync shadow itself is NOT allocated here: burst.c allocates it on
     * the first SBURST BEGIN and fed_burst_close() releases it, so a node
     * with no peers pays nothing for a second node in the process not
     * sharing its transactions. */
    return 0;
}

uint64_t server_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

void server_tick(server_t *s, uint64_t now_ms)
{
    if (s == NULL) {
        return;
    }
    s->n_ticks++;
    /* THE SESSION WINDOW'S SWEEP IS HERE AND NOT IN on_tick, and the reason is
     * ownership: the window is a CORE structure and this is the core tick, while
     * on_tick belongs to whichever module the embedding application installed
     * (federation's fed_tick in this build). A core store swept from a
     * federation callback would never expire on a node that federates with
     * nobody -- which is exactly the quiet node whose windows are all stale.
     *
     * IT IS THROTTLED HERE AND NOT IN resume_sweep(), so the walk happens about
     * once per window/16 rather than on every 50 ms tick: expiry is O(windows)
     * and nothing about it needs millisecond resolution. The same split
     * fed_dedup_sweep()'s throttle makes, and for the same reason -- the TIME
     * half of "is a sweep due" belongs to the store's owner, and the OCCUPANCY
     * half to the tick. */
    if (s->resume_windows != NULL) {
        /* The divisor is CLAMPED AT 1 and the guard is the same `now >=` test
         * the sweep itself uses: a window shorter than the divisor has to be
         * swept every tick, and a stamp in the future (which a clock that went
         * backwards would produce) must not be read as "due long ago". */
        uint64_t due = resume_window_ms(s) / RESUME_TICK_DIVISOR;

        if (due == 0u) {
            due = 1u;
        }
        if (s->resume_swept_ms == 0u || now_ms < s->resume_swept_ms ||
            (now_ms - s->resume_swept_ms) >= due) {
            (void)resume_sweep(s, now_ms);
            s->resume_swept_ms = now_ms;
        }
    }
    if (s->on_tick != NULL) {
        s->on_tick(s, now_ms);
    }
}

uint64_t server_next_msg_id(server_t *s)
{
    uint64_t id;

    if (s == NULL) {
        return 0;
    }
    id = s->msg_id++;
    if (s->msg_id == 0) {
        s->msg_id = 1; /* never hand out 0: it means "unset" */
    }
    return id;
}
