/* server_writers.c -- see server_writers.h. The writer-pool family, verbatim
 * out of server.c (issue #543); the lifecycle, registries and shutdown stay
 * there.
 */
#include "core/server_writers.h"

#include <stdio.h>
#include <stdlib.h>

void server_set_writer_threads(server_t *s, int n)
{
    if (s == NULL) {
        return;
    }
    s->writer_threads = (n < 0) ? 0 : n;
}
/* MT #366: sticky scheduling + demand steal. Pass `wid`'s slice is the conns
 * with fd % N == wid, so each queue stays hot on one core. A pass that
 * drained nothing (idle) checks the other owners' aggregate unsent bytes and,
 * when the fattest sits above WRITER_STEAL_BYTES, drains that owner's conns
 * for this pass only. Each pump takes that conn's wq_lock and drains one
 * bounded slice (#369), so a conn is still drained by exactly one writer at
 * a time and FIFO holds through the move. Ownership stays a pure function
 * of (fd, N): no migration state, no reg_mu -> wq_lock order change. */
static size_t writer_drain_slot(server_t *s, int wid);

static void *writer_main(void *arg);

/* Drain one bounded slice of a conn's queued FIFO (#369: CONN_WQ_SLICE bytes
 * via conn_pump_slice_locked(), so a fat conn cannot hold a writer past one
 * slice while a thin conn's reply waits). The caller already holds the
 * conn's wq_lock (taken as a trylock under reg_mu, see writer_drain_owner),
 * so FIFO + single-drainer hold across steal moves. The pending reads use
 * the plain accessor: wq_lock is already held, and the _locked form takes
 * the lock itself (self-deadlock inside a pump critical section, by its own
 * contract). Adds the bytes drained to `*drained`. */
static void writer_pump_conn(server_t *s, conn_t *c, size_t *drained)
{
    size_t before;
    size_t left;
    int rc;

    before = conn_write_pending(c);
    rc = conn_pump_slice_locked(c);
    if (rc < 0) {
        atomic_fetch_add_explicit(&s->n_write_error, 1u, memory_order_relaxed);
        printf("[observable] conn_close: fd=%d reason=write_error\n", c->fd);
        conn_mark_closing(c);
        return;
    }
    left = conn_write_pending(c);
    if (left < before) {
        *drained += before - left;
    }
    if (before > 0 && left > 0) {
        atomic_fetch_add_explicit(&s->n_partial_writes, 1u, memory_order_relaxed);
    }
}

/* True when the conn has anything to drain: CLOSING conns with queued bytes
 * included (the 417-flush path leaves them for us). Only the reaper closes. */
static int writer_conn_live(conn_t *c)
{
    if (c == NULL) {
        return 0;
    }
    if (atomic_load_explicit(&c->state, memory_order_acquire) != CONN_CLOSING &&
        !atomic_load_explicit(&c->want_write, memory_order_acquire)) {
        return 0;
    }
    return 1;
}

static int writer_owner(int fd, int n)
{
    return ((fd % n) + n) % n;
}

static conn_t *writer_resolve(server_t *s, int fd)
{
    if (s->by_fd == NULL || fd < 0 || fd >= SERVER_FD_TABLE) {
        return NULL;
    }
    return s->by_fd[fd];
}

/* #497: single-scan steal target. One walk over active_fds attributes each
 * live conn's backlog to its owner and notes CLOSING-with-bytes, so an idle
 * tick costs one pass (one trylock per conn) instead of one pass per writer
 * plus a second pass for the closing check. The caller holds reg_mu
 * (active_fds/by_fd stability); each pending read takes wq_lock as a trylock,
 * so the scan never blocks under reg_mu (#279). Lock order reg_mu -> wq_lock
 * holds: nothing takes them in reverse. Returns the fattest other owner when
 * it trips the stickiness floor (WRITER_STEAL_BYTES, 2x the per-conn cap, so
 * a single full conn never migrates) or holds a CLOSING conn with queued
 * bytes (the 417-flush shape), else -1. */
static int writer_steal_target(server_t *s, int self, int n)
{
    size_t i;
    int w;
    int fat = -1;
    unsigned long long best = 0ull;
    unsigned long long *totals;
    unsigned char *closing;

    if (n <= 0 || self < 0 || self >= n) {
        return -1;
    }
    /* Per-owner totals without repeated walks: n is the live writer count,
     * and the caller only steals when n > 1. Heap scratch, freed before
     * return; NULL (OOM) skips the steal this tick. */
    totals = (unsigned long long *)calloc((size_t)n, sizeof *totals);
    closing = (unsigned char *)calloc((size_t)n, sizeof *closing);
    if (totals == NULL || closing == NULL) {
        free(totals);
        free(closing);
        return -1;
    }
    for (i = 0; i < s->nactive; i++) {
        int fd;
        int owner;
        conn_t *c;
        size_t pending;

        if (i >= s->nactive) {
            break;
        }
        fd = s->active_fds[i];
        owner = writer_owner(fd, n);
        if (owner == self) {
            continue;
        }
        c = writer_resolve(s, fd);
        if (!writer_conn_live(c)) {
            continue;
        }
        if (pthread_mutex_trylock(&c->wq_lock) != 0) {
            continue;
        }
        pending = conn_write_pending(c);
        if (pending > 0 &&
            atomic_load_explicit(&c->state,
                                 memory_order_acquire) == CONN_CLOSING) {
            closing[owner] = 1;
        }
        totals[owner] += (unsigned long long)pending;
        pthread_mutex_unlock(&c->wq_lock);
    }
    for (w = 0; w < n; w++) {
        if (w == self) {
            continue;
        }
        if (totals[w] > best) {
            best = totals[w];
            fat = w;
        }
    }
    if (fat < 0 ||
        (best < (unsigned long long)WRITER_STEAL_BYTES && !closing[fat])) {
        fat = -1;
    }
    free(totals);
    free(closing);
    return fat;
}

/* Drain one bounded slice of every live conn owned by `owner`. The caller
 * holds reg_mu; each conn's wq_lock is taken as a trylock while still
 * holding reg_mu (order reg_mu -> wq_lock, never the reverse, never
 * blocking), then reg_mu is released across the pump and retaken after.
 * Holding reg_mu over every conn_pump_slice_locked serialized all writers
 * on one mutex (N=4 ~= N=1) and stalled the loop's add/detach behind write
 * syscalls (#279). The held wq_lock is what keeps the reaper from
 * detaching/freeing mid-pump -- its trylock fails and it defers the close
 * (#242) -- so resolve-to-pump has no gap. A detach between pumps only
 * moves active_fds, which is re-read every iteration, so a conn is at worst
 * visited twice or next pass. */
static void writer_drain_owner(server_t *s, int owner, int n, size_t *drained)
{
    size_t i;

    for (i = 0; i < s->nactive; i++) {
        int fd;
        conn_t *c;

        if (i >= s->nactive) {
            break;
        }
        fd = s->active_fds[i];
        if (writer_owner(fd, n) != owner) {
            continue;
        }
        c = writer_resolve(s, fd);
        /* No CLOSING skip: writers drain CLOSING conns with queued bytes too
         * (the 417-flush path leaves them for us). Only the reaper closes; a
         * failed pump still only marks. */
        if (!writer_conn_live(c)) {
            continue;
        }
        if (pthread_mutex_trylock(&c->wq_lock) != 0) {
            /* Another writer is pumping this conn, or the reaper is reading
             * its pending: either way it is being handled, and the next pass
             * picks up what is left. */
            continue;
        }
        if (s->reg_started) {
            pthread_mutex_unlock(&s->reg_mu);
        }
        writer_pump_conn(s, c, drained);
        pthread_mutex_unlock(&c->wq_lock);
        if (s->reg_started) {
            pthread_mutex_lock(&s->reg_mu);
        }
    }
}

static size_t writer_drain_slot(server_t *s, int wid)
{
    int n;
    size_t drained = 0u;

    /* The pass holds reg_mu across the registry scans but never across a
     * pump: each pump drops it per-conn (see writer_drain_owner), so writers
     * never serialize on one mutex and the loop's add/detach never waits on
     * a write syscall. Lock order reg_mu -> wq_lock is fixed throughout:
     * wq_lock is only ever taken (as a trylock) while reg_mu is held, and
     * reg_mu is retaken only after wq_lock is released. */
    if (s->reg_started) {
        pthread_mutex_lock(&s->reg_mu);
    }
    n = s->writer_threads;
    if (n > 0 && wid >= 0 && wid < n) {
        /* Owned slice first: one bounded slice per owned conn (#369), so a
         * fat conn cannot hold this writer past one slice while a thin
         * conn's reply waits. */
        writer_drain_owner(s, wid, n, &drained);
        if (drained == 0u && n > 1) {
            /* Idle this pass: steal by demand against live backlog, not the
             * last-pass accounting (stale the moment bytes drain). One walk
             * picks the fattest other owner (#497); a single full conn can
             * never trip it (bound is 2x the per-conn cap), so owned queues
             * stay sticky until imbalance. Draining below is for this pass
             * only. */
            int fat = writer_steal_target(s, wid, n);

            if (fat >= 0) {
                writer_drain_owner(s, fat, n, &drained);
            }
        }
        if (s->writer_bytes != NULL && drained > 0u) {
            atomic_fetch_add_explicit(&s->writer_bytes[(size_t)wid],
                                      (unsigned long long)drained,
                                      memory_order_relaxed);
        }
    }
    if (s->reg_started) {
        pthread_mutex_unlock(&s->reg_mu);
    }
    return drained;
}

/* MT #366: per-writer thread argument. Carries both ends the thread
 * needs; owned by the pool (slots[]), so stop has nothing to release. */
static void *writer_main(void *arg)
{
    writer_slot_t *slot = (writer_slot_t *)arg;
    server_t *s = slot->s;
    int wid = slot->wid;
    /* MT 2.4 (#243): wakeup-generation predicate. Each writer remembers the
     * last generation it consumed on its OWN slot; a targeted kick between
     * drain-finish and the lock bumps that slot's gen, so the waiter below
     * sees gen != seen and drains instead of sleeping past it (idle conn,
     * no POLLOUT-driven pump at N > 0). wq_stop is part of the same
     * predicate, so the shutdown wakeup is never mistaken for a spurious
     * wakeup. Consuming a generation counts one wake (wq_wakes). #316: the
     * consume also clears wq_kick_pending, so kicks that arrived mid-drain
     * collapse into this wakeup instead of queueing another. */
    unsigned long seen = 0ul;

    for (;;) {
        /* Drain first: queued work is handled without waiting for a wakeup.
         * One bounded slice per conn per pass (#369); a kick that landed
         * mid-drain is consumed by the next pass's generation check. */
        (void)writer_drain_slot(s, wid);
        pthread_mutex_lock(&s->wq_mu);
        for (;;) {
            if (s->wq_stop) {
                pthread_mutex_unlock(&s->wq_mu);
                return NULL;
            }
            if (s->wq_slot_gen[wid] != seen) {
                seen = s->wq_slot_gen[wid];
                s->wq_kick_pending[wid] = 0;
                (void)atomic_fetch_add_explicit(&s->wq_wakes[wid], 1u,
                                                  memory_order_relaxed);
                break;
            }
            pthread_cond_wait(&s->wq_slot_avail[wid], &s->wq_mu);
        }
        pthread_mutex_unlock(&s->wq_mu);
    }
}


/* Pool allocation without threads: handles, slot condvars/gens, wake
 * counters, sticky slots + drained-byte totals, wq_mu + per-slot condvars --
 * but no spawn and no started flag. server_writers_start() calls this then
 * spawns. */
static int server_writers_init_pool(server_t *s)
{
    int i;

    s->writers = (pthread_t *)calloc((size_t)s->writer_threads, sizeof *s->writers);
    s->wq_slot_avail =
        (pthread_cond_t *)calloc((size_t)s->writer_threads, sizeof *s->wq_slot_avail);
    s->wq_slot_gen =
        (unsigned long *)calloc((size_t)s->writer_threads, sizeof *s->wq_slot_gen);
    s->wq_kick_pending =
        (unsigned char *)calloc((size_t)s->writer_threads, sizeof *s->wq_kick_pending);
    s->wq_wakes =
        (atomic_ullong *)calloc((size_t)s->writer_threads, sizeof *s->wq_wakes);
    if (s->writers == NULL || s->wq_slot_avail == NULL || s->wq_slot_gen == NULL ||
        s->wq_kick_pending == NULL || s->wq_wakes == NULL) {
        free(s->writers);
        free(s->wq_slot_avail);
        free(s->wq_slot_gen);
        free(s->wq_kick_pending);
        free(s->wq_wakes);
        s->writers = NULL;
        s->wq_slot_avail = NULL;
        s->wq_slot_gen = NULL;
        s->wq_kick_pending = NULL;
        s->wq_wakes = NULL;
        return -1;
    }
    /* MT #366: sticky slots + per-writer drained-byte totals. Zeroed, so the
     * first demand check sees an idle pool and owns its slice. */
    s->slots = (writer_slot_t *)calloc((size_t)s->writer_threads, sizeof *s->slots);
    s->writer_bytes = (atomic_ullong *)calloc(
        (size_t)s->writer_threads, sizeof *s->writer_bytes);
    if (s->slots == NULL || s->writer_bytes == NULL) {
        free(s->writer_bytes);
        s->writer_bytes = NULL;
        free(s->slots);
        s->slots = NULL;
        free(s->writers);
        s->writers = NULL;
        return -1;
    }
    for (i = 0; i < s->writer_threads; i++) {
        s->slots[i].s = s;
        s->slots[i].wid = i;
    }
    if (pthread_mutex_init(&s->wq_mu, NULL) != 0) {
        free(s->writer_bytes);
        s->writer_bytes = NULL;
        free(s->slots);
        s->slots = NULL;
        free(s->writers);
        free(s->wq_slot_avail);
        free(s->wq_slot_gen);
        free(s->wq_kick_pending);
        free(s->wq_wakes);
        s->writers = NULL;
        s->wq_slot_avail = NULL;
        s->wq_slot_gen = NULL;
        s->wq_kick_pending = NULL;
        s->wq_wakes = NULL;
        return -1;
    }
    for (i = 0; i < s->writer_threads; i++) {
        if (pthread_cond_init(&s->wq_slot_avail[i], NULL) != 0) {
            int k;

            for (k = 0; k < i; k++) {
                (void)pthread_cond_destroy(&s->wq_slot_avail[k]);
            }
            pthread_mutex_destroy(&s->wq_mu);
            free(s->writer_bytes);
            s->writer_bytes = NULL;
            free(s->slots);
            s->slots = NULL;
            free(s->writers);
            free(s->wq_slot_avail);
            free(s->wq_slot_gen);
            free(s->wq_kick_pending);
            free(s->wq_wakes);
            s->writers = NULL;
            s->wq_slot_avail = NULL;
            s->wq_slot_gen = NULL;
            s->wq_kick_pending = NULL;
            s->wq_wakes = NULL;
            return -1;
        }
    }
    return 0;
}

int server_writers_start(server_t *s)
{
    int i;

    if (s == NULL || s->writer_threads <= 0 || s->writers_started) {
        return 0;
    }
    if (server_writers_init_pool(s) != 0) {
        return -1;
    }
    s->wq_stop = 0;
    for (i = 0; i < s->writer_threads; i++) {
        /* nonzero: writers start with seen = 0, so the first predicate
         * check drains rather than sleeps. */
        s->wq_slot_gen[i] = 1ul;
    }
    s->writers_started = 1;
    for (i = 0; i < s->writer_threads; i++) {
        if (pthread_create(&s->writers[i], NULL, writer_main, &s->slots[i]) == 0) {
            continue;
        }
        break;
    }
    if (i < s->writer_threads) {
        int j;

        pthread_mutex_lock(&s->wq_mu);
        s->wq_stop = 1;
        for (j = 0; j < s->writer_threads; j++) {
            pthread_cond_signal(&s->wq_slot_avail[j]);
        }
        pthread_mutex_unlock(&s->wq_mu);
        for (j = 0; j < i; j++) {
            (void)pthread_join(s->writers[j], NULL);
        }
        for (j = 0; j < s->writer_threads; j++) {
            (void)pthread_cond_destroy(&s->wq_slot_avail[j]);
        }
        pthread_mutex_destroy(&s->wq_mu);
        free(s->writers);
        free(s->wq_slot_avail);
        free(s->wq_slot_gen);
        free(s->wq_kick_pending);
        free(s->wq_wakes);
        s->writers = NULL;
        s->wq_slot_avail = NULL;
        s->wq_slot_gen = NULL;
        s->wq_kick_pending = NULL;
        s->wq_wakes = NULL;
        s->writers_started = 0;
        s->writer_threads = 0;
        return -1;
    }
    /* MT 2.4 (#243): bumping each slot gen turns the start into a countable
     * event; a writer that finished draining just before takes this lock,
     * sees gen != seen, and drains again instead of losing the wakeup. */
    pthread_mutex_lock(&s->wq_mu);
    for (i = 0; i < s->writer_threads; i++) {
        s->wq_slot_gen[i]++;
        s->wq_kick_pending[i] = 1;
        pthread_cond_signal(&s->wq_slot_avail[i]);
    }
    pthread_mutex_unlock(&s->wq_mu);
    return 0;
}

/* Owner slot for a conn. fd % N spreads conns across writers; a stale or
 * missing fd still lands on slot 0, never nowhere. Shared with the sticky
 * drain path so kick target and drain owner always agree. */
static int writer_owner_slot(const server_t *s, int fd)
{
    if (s == NULL || s->writer_threads <= 0) {
        return 0;
    }
    return writer_owner(fd, s->writer_threads);
}

void server_writers_kick(server_t *s)
{
    int i;

    if (s == NULL || !s->writers_started) {
        return;
    }
    /* #316: one kick per slot per drain turn. A slot with an unconsumed kick
     * is skipped: its pending bump already guarantees its writer will drain
     * everything queued so far (writers drain the whole scan, not one
     * conn), so a fanout burst costs one wakeup per slot, not one per
     * member. Skipping is lossless -- pending == 1 means a bump happened
     * after the writer's last consume, and the writer always drains after
     * consuming, covering every byte queued before the skip. */
    pthread_mutex_lock(&s->wq_mu);
    for (i = 0; i < s->writer_threads; i++) {
        if (s->wq_kick_pending[i] != 0) {
            continue;
        }
        s->wq_kick_pending[i] = 1;
        s->wq_slot_gen[i]++;
        pthread_cond_signal(&s->wq_slot_avail[i]);
    }
    pthread_mutex_unlock(&s->wq_mu);
}

/* The 417-flush path queues the reply then marks CLOSING and kicks; its
 * owner may be mid-backlog draining another conn on its slice. Waking every
 * slot (not just the owner) lets the first free writer steal the closing
 * backlog via the closing-bypass instead of pacing the reply behind the
 * owner's whole queue. Wake accounting stays exact: one kick, one consumed
 * gen per writer. Targeting is preserved for the open-conn case, which keeps
 * the single-owner wake the #367 test pins. */
void server_writers_kick_conn(server_t *s, const conn_t *c)
{
    int slot;
    int closing;
    int i;

    if (s == NULL || !s->writers_started || c == NULL) {
        return;
    }
    closing =
        (atomic_load_explicit(&c->state, memory_order_acquire) == CONN_CLOSING);
    pthread_mutex_lock(&s->wq_mu);
    if (closing && s->writer_threads > 1) {
        for (i = 0; i < s->writer_threads; i++) {
            if (s->wq_kick_pending[i] != 0) {
                continue;
            }
            s->wq_kick_pending[i] = 1;
            s->wq_slot_gen[i]++;
            pthread_cond_signal(&s->wq_slot_avail[i]);
        }
    } else {
        slot = writer_owner_slot(s, c->fd);
        if (s->wq_kick_pending[slot] == 0) {
            s->wq_kick_pending[slot] = 1;
            s->wq_slot_gen[slot]++;
            pthread_cond_signal(&s->wq_slot_avail[slot]);
        }
    }
    pthread_mutex_unlock(&s->wq_mu);
}

int server_writer_slot(const server_t *s, int fd)
{
    if (s == NULL) {
        return 0;
    }
    return writer_owner_slot(s, fd);
}

void server_writers_kick_slots(server_t *s, const int *slots, size_t nslots)
{
    size_t i;
    size_t k;

    if (s == NULL || !s->writers_started || slots == NULL || nslots == 0) {
        return;
    }
    /* #279: one wq_mu hold for the whole emission, not one per member.
     * Duplicate slots are signalled once: a second bump before the owner
     * drains is a second wake for bytes the first wake already covers. */
    pthread_mutex_lock(&s->wq_mu);
    for (i = 0; i < nslots; i++) {
        int slot = slots[i];

        if (slot < 0 || slot >= s->writer_threads) {
            continue;
        }
        for (k = 0; k < i; k++) {
            if (slots[k] == slot) {
                break;
            }
        }
        if (k != i) {
            continue;
        }
        /* #316: collapse into an unconsumed kick for the same slot. */
        if (s->wq_kick_pending[slot] != 0) {
            continue;
        }
        s->wq_kick_pending[slot] = 1;
        s->wq_slot_gen[slot]++;
        pthread_cond_signal(&s->wq_slot_avail[slot]);
    }
    pthread_mutex_unlock(&s->wq_mu);
}

void server_writers_stop(server_t *s)
{
    int i;

    if (s == NULL || !s->writers_started) {
        return;
    }
    pthread_mutex_lock(&s->wq_mu);
    s->wq_stop = 1;
    for (i = 0; i < s->writer_threads; i++) {
        pthread_cond_signal(&s->wq_slot_avail[i]);
    }
    pthread_mutex_unlock(&s->wq_mu);
    for (i = 0; i < s->writer_threads; i++) {
        (void)pthread_join(s->writers[i], NULL);
    }
    for (i = 0; i < s->writer_threads; i++) {
        (void)pthread_cond_destroy(&s->wq_slot_avail[i]);
    }
    pthread_mutex_destroy(&s->wq_mu);
    free(s->writer_bytes);
    s->writer_bytes = NULL;
    free(s->slots);
    s->slots = NULL;
    free(s->writers);
    free(s->wq_slot_avail);
    free(s->wq_slot_gen);
    free(s->wq_kick_pending);
    free(s->wq_wakes);
    s->writers = NULL;
    s->wq_slot_avail = NULL;
    s->wq_slot_gen = NULL;
    s->wq_kick_pending = NULL;
    s->wq_wakes = NULL;
    s->writers_started = 0;
}
