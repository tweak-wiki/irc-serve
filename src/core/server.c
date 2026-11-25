/* server.c -- server_t lifecycle and the bounded-queue wrapper. Sections 2.1,
 * 2.4 and 3.3 of docs/SERVER_DESIGN.md. The nick, channel and peer-link
 * registries (2.2, 2.3) are split out for #543 into core/server_registry.c,
 * the nonblocking dial FSM (3.4) into core/server_dial.c, and the listener
 * arms (bind/port/accept) into core/server_listen.c. */
#include "core/server.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

#include "core/channel.h"
#include "core/message.h"
/* Phase 10.1's account registry. Included for the same reason sasl_framework.h
 * below is: it is a teardown arm on a table this struct holds, so the pointer
 * belongs to the node and the layout belongs to the module that owns it. */
#include "account_store.h"
/* Phase 10.1's account_clear(), called from server_close_conn() beside the
 * nickname release for the reason account.h gives: the identity must not outlive
 * the connection that owns it, and server_close_conn() is the one function every
 * retirement goes through. */
#include "core/account.h"
/* The one include that points the other way. 4.3's inbound resync shadow is a
 * module global rather than a field on server_t, so the shutdown has to reach
 * into its owner to release it -- the same reason the dedup table below is freed
 * here rather than left to federation/dedup.c. core/fanout.c and
 * core/commands.c already include federation/ headers for the same class of
 * reason, so this is a direction this tree already has. */
#include "core/resume.h"
#include "federation/burst.h"
/* Phase 9's ADVERTISE / SHUTDOWN half, for the ONE thing server_shutdown() does
 * that is not a free: the goodbye at the top of the teardown. Same direction of
 * include as burst.h above and for the same class of reason -- a federation module's
 * entry point, called from the one function that ends every allocation on this
 * struct. It used to be reached only through federation/nickreg.h, which includes
 * this header, and that was an accident of include order rather than a decision:
 * a file calling fed_send_shutdown() should say so itself. */
#include "federation/link.h"
/* Phase 9's remote-nick registry. Included here rather than declared extern
 * because it is a teardown arm on a table this struct holds, exactly as
 * federation/burst.h is: the layout belongs to the module that owns it and the
 * pointer belongs to the node. */
#include "federation/nickreg.h"
#include "sasl_framework.h"
/* Phase 12: the TLS backend seam, and the ONE include that makes server_t's
 * `struct tls_node *tls` meaningful. Nothing else in this file names a TLS type:
 * the layout is the backend's, and the one thing this file asks of it is
 * "release it" (the shutdown arm; the accept arm lives in server_listen.c). */
#include "tls_backend.h"

/* The nick/channel string -> pointer map (open-addressed strtab):
 * split out for #543 into core/strtab.c; the registries that use it stay
 * here. */
#include "core/strtab.h"
/* The writer pool (demand-steal drain threads): split out for #543 into
 * core/server_writers.c; the lifecycle, link/dial registries and shutdown stay here. */
#include "core/server_writers.h"

/* The fd-indexed connection registry (accept/lookup/queue/reap): split out
 * for #543 into core/server_conns.c; the lifecycle, link/dial registries
 * and shutdown stay here. */
#include "core/server_conns.h"

/* server_find_link() compares with irc_ascii_same() (message.h, issue #181):
 * server names are case-insensitive in IRC, so the lookup must fold. */

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

void server_shutdown_phase1_say_goodbye(server_t *s)
{
    if (s == NULL) {
        return;
    }
    /* THE GOODBYE, AND IT IS FIRST because everything below closes the sockets it
     * would have to travel on. See server.h's server_shutdown() block for the whole
     * argument: without this arm a planned restart is a crash on every peer, and
     * the node that would have told them otherwise is the one that went away. It is
     * safe on the half-built server_t the four startup-failure paths hand it, which
     * is stated in the header because those paths are the reason it cannot sit
     * behind a "did we federate" guard.
     *
     * `NULL` rather than a reason string, and fed_send_shutdown() takes the reason
     * and does not send it: 4.3's verb list has no SHUTDOWN, so a field a second
     * implementation would have to guess at is a compatibility break bought for
     * nothing, and the receiver's log already names who left. */
    (void)fed_send_shutdown(s, NULL);
}

void server_shutdown_phase2_close(server_t *s)
{
    size_t i;

    if (s == NULL) {
        return;
    }
    /* MT 2.2 (#241): stop writers BEFORE the goodbye is drained below AND the
     * by_fd walk frees conns. Writers pump under wq_lock and may mark CLOSING,
     * but only the reaper closes; joining first means no writer can touch a
     * conn mid-teardown or race the single-threaded drain. Safe on a
     * never-started node (no-op). */
    server_writers_stop(s);
    /* Issue #173: unwrap the federation dispatch and forget the secret, so a
     * server_t that is shut down can be re-opened and no credential outlives
     * the node. Safe on a node that never called fed_open(). After the
     * goodbye above, which is queued through the node's own state rather than
     * the dispatch seam. */
    fed_close(s);
    for (i = 0; i < SERVER_FD_TABLE; i++) {
        if (s->by_fd != NULL && s->by_fd[i] != NULL) {
            server_close_conn(s, (int)i);
        }
    }
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    /* PHASE 12: THE IMPLICIT-TLS LISTENER, closed HERE and not by the reaper.
     *
     * It is not a connection and no conn_t ever rides it: an accepted implicit-TLS
     * socket becomes an ordinary conn_t at accept, with its own SSL* owned by
     * conn_free(). So this descriptor has no conn to be reaped along with, and
     * leaving it to the walk above -- which only sees by_fd -- would leak a
     * listening socket for the life of the process. It sits with the other listener
     * because it IS one, and because both must be closed before the contexts are:
     * SSL_CTX_free() below does not touch any socket.
     *
     * SAFE HERE AND AT ANY POINT ABOVE, and the argument is the one every
     * allocation arm in this function gives: the connection walk has already closed
     * every conn_t, so nothing can be holding an SSL* that references these
     * contexts. And it is safe on a node that never configured TLS, which is every
     * node in the default build -- the field is -1 until server_listen_tls(). */
    if (s->tls_listen_fd >= 0) {
        close(s->tls_listen_fd);
        s->tls_listen_fd = -1;
    }
    /* THE NODE'S TLS CONTEXTS, released LAST among the network state and for the
     * same reason the dedup table and the topic cache are released by this
     * function rather than by their owners: a teardown that could not see an
     * allocation would not be a teardown of everything on this struct.
     *
     * ASSERTED, NOT VERIFIED, ON THIS PLATFORM, and it is worth saying so plainly:
     * **LeakSanitizer does not run on Darwin.** The top-level CMakeLists.txt's
     * IRC_SANITIZE block records that an ASan binary with detect_leaks=1 HANGS on
     * macOS rather than reporting, so a missing free here is invisible locally and
     * caught only by the Linux CI job. The arm PRINTS whether TLS was open, so it
     * is at least ASSERTED on every platform -- a test can require the line -- and
     * Linux CI reads the same line next to its LSan run. See the arm for the
     * account registry, which does this and says why. */
    printf("[observable] tls_node_close: tls=%s insecure_conns=%llu\n",
           (s->tls != NULL) ? "OPEN" : "NONE",
           (unsigned long long)s->n_tls_handshake_failed);
    tls_backend_node_free(s->tls);
    s->tls = NULL;
    if (s->dials != NULL) {
        for (i = 0; i < s->ndials; i++) {
            if (s->dials[i].state == DIAL_CONNECTING ||
                s->dials[i].state == DIAL_CONNECTED) {
                close(s->dials[i].fd);
                s->dials[i].fd = -1;
            }
        }
        free(s->dials);
        s->dials = NULL;
    }
    s->ndials = 0;
    s->dials_cap = 0;
    /* The peer links. Nothing here closes a descriptor: a link only NAMES one,
     * and the conn the loop registered for that descriptor has already been
     * closed by the walk above, so dropping the name is the whole teardown. The
     * vector is a flat array of POD with no allocations of its own, which is
     * why it needs one free and no per-element destructor. */
    free(s->links);
    s->links = NULL;
    s->nlinks = 0;
    s->links_cap = 0;
    /* The dedup table, owned by federation/dedup.c but freed here. The two
     * modules are the same library, and a teardown arm that called into the
     * owner would mean a second entry point whose only job is to be called from
     * one place -- while the alternative, leaving it to the owner, means the
     * table's lifetime is not visible in the function that ends every other
     * allocation on this struct. It is NULL on a node that never received a
     * relayed message, which is the common case today.
     *
     * ASSERTED, NOT VERIFIED, ON THIS PLATFORM: LeakSanitizer does not exist on
     * Darwin, so a missing free here is invisible to the local sanitizer run
     * and is caught only by the Linux CI job. */
    free(s->dedup_tab);
    s->dedup_tab = NULL;
    s->dedup_head = NULL;
    s->dedup_tail = NULL;
    s->dedup_used = 0;
    s->dedup_swept_ms = 0;
    /* 4.3's resync shadow, the second federation allocation this function
     * releases and the only one it has to CALL rather than free. C4 declined to
     * add this arm because it could not be checked on Darwin; that reasoning was
     * backwards, and the correction is the reason this arm exists: an arm that
     * is unverifiable LOCALLY is exactly the one worth adding when LeakSanitizer
     * DOES run on the CachyOS Linux CI runner. A node stopped mid-transaction --
     * a SIGTERM while a peer is bursting -- was leaking up to
     * IRC_BURST_MAX_BYTES to the kernel, and the only evidence was a build nobody
     * ran locally.
     *
     * IT IS SAFE HERE AND AT ANY POINT in the walk above: the shadow is records
     * this node copied out of what a peer said. It holds no conn_t*, no chan_t*
     * and no server_link_t*, so nothing it can be holding has been freed yet.
     * And it is safe on a node that never called fed_open(), which is every
     * test that links this library without the federation fixture -- the field
     * is NULL until server_init() allocates it.
     *
     * ASSERTED, NOT VERIFIED, ON THIS PLATFORM -- and the arm prints an
     * `[observable] fed_burst_close: shadow=OPEN|NONE` line precisely so it is
     * ASSERTED here too: a test can prove the arm ran without a leak checker,
     * and Linux CI can read the same line next to its LSan run. */
    fed_burst_close(s);
    /* The client session window, the third optional store this function ends,
     * and the second one it has to CALL rather than free. Same reasoning as the
     * burst shadow above: the records are core/resume.c's, the pointer is here,
     * and a teardown that could not see this allocation would not be a teardown
     * of everything on this struct. It is SAFE at this point in the walk,
     * because a window holds no conn_t*, no chan_t* and no server_link_t* -- it
     * holds three strings and a bounded array of channel NAMES, and every
     * connection and channel the walk above released has already been copied
     * out as text.
     *
     * The arm PRINTS whether the table was OPEN, for the reason the shadow's
     * does: LeakSanitizer does not run on Darwin, so a missing free here is
     * invisible locally and the only local evidence is a line a test can assert
     * on. Linux CI reads the same line next to its own LSan run. */
    resume_close(s);
    /* Phase 7's topic cache: a plain free of a plain vector, which is the
     * simplest arm on this function and the newest. It sits HERE rather than at
     * the end because the ordering that matters on this struct is "the peer links
     * and the dedup table are federation state, and this is not" -- a reader
     * looking for where the federation allocations go will not pass it by, and
     * a reader looking for the topic cache will not go looking through the
     * federation arms for it. The cache holds three topic fields and a name per
     * entry and no conn_t*, no chan_t* and no server_link_t*, so it is safe at
     * any point in the walk above. */
    free(s->topics);
    s->topics = NULL;
    s->ntopics = 0;
    s->topics_cap = 0;
    /* Phase 8's credential store: a CALL rather than a free, for the same reason
     * fed_burst_close() is a call -- the layout and the passwords are
     * sasl_framework.c's, and the owner also overwrites the passwords before
     * releasing them. It sits with the other "a module's memory, released here"
     * arms for the same reason, and it is ASSERTED NOT VERIFIED on Darwin for the
     * same reason: LeakSanitizer runs only on the Linux CI job, so a missing
     * arm here is invisible locally and real there.
     *
     * Every connection is already closed by the walk above, so no sasl_ctx_t --
     * and no connection that borrowed this store -- can still be holding a
     * pointer into it. */
    account_store_free(s->sasl_store);
    s->sasl_store = NULL;
    /* Phase 10.1's account registry: the same SHAPE of obligation as the
     * credential store above and the same reason it is a call rather than a
     * free. The layout and the three-field file format are account_store.c's,
     * and the owner also OVERWRITES THE PASSWORDS before releasing them -- so a
     * free() here would be a different, weaker operation than the one the module
     * provides, which is the reason this is not `free(s->account_store)`.
     *
     * IT IS SAFE HERE, and the argument is the same one the burst shadow's and
     * the resume table's arms give: every connection was closed by the walk
     * above and every one of those closures called account_clear(), so no
     * conn_t::account -- and no connection that borrowed this registry -- can
     * still be pointing at anything inside it. And it is safe on a node that
     * never loaded one, which is every node started without --account-store:
     * the field is NULL until account_store_load() succeeds.
     *
     * THE ARM PRINTS whether a registry was OPEN, following
     * `fed_burst_close: shadow=OPEN|NONE` rather than inventing a second
     * convention, and for the reason that convention exists:
     * **LeakSanitizer does not run on Darwin**, so a missing free here is
     * invisible to every local run and is caught only by the Linux CI job. The
     * line makes the arm ASSERTED on every platform -- a test can require it --
     * and VERIFIED on the one that has a leak checker, from the same run.
     *
     * `store=OPEN` means a registry was loaded and has now been released with
     * its passwords overwritten; `store=NONE` means the node had no account
     * system, which is the state most deployments of this design are in and is
     * not an error. */
    printf("[observable] account_store_close: store=%s records=%zu\n",
           (s->account_store != NULL) ? "OPEN" : "NONE",
           account_store_count(s->account_store));
    account_store_free(s->account_store);
    s->account_store = NULL;
    /* Phase 9's remote-nick registry: 2.1's "which server holds the user called
     * X", the table that makes 3.1's last row resolvable. A CALL rather than a
     * free for the same reason as the two arms above -- the layout and the
     * least-recently-used ordering are federation/nickreg.c's, and the owner also
     * reports whether the table held anything.
     *
     * IT IS SAFE HERE AND AT ANY POINT in the walk above: an entry holds three
     * copied strings and two integers and no conn_t*, no chan_t* and no
     * server_link_t*, so nothing it can be holding has been freed yet. And it is
     * safe on a node that never called fed_open(), which is every test that links
     * this library without the federation fixture -- the table is a field on
     * server_t, so it is already NULL. */
    fed_nickreg_close(s);
    /* The advertise table is the same shape of obligation as the nick registry
     * above and for the same reason: server_t::advs is a lazily calloc()ed table
     * with no conn_t* in it, so it survives every per-connection teardown and only
     * server_shutdown() can reach it. Leaving it unfreed is a real LSan failure on
     * the Linux CI job -- and one no macOS run can see, which is why this arm
     * exists rather than being left to the next reader. Safe on a node that never
     * advertised: the field is NULL until the first calloc. */
    fed_advert_close(s);
    strtab_free(s->nicks);
    s->nicks = NULL;
    strtab_free(s->chans);
    s->chans = NULL;
    /* Every conn is already closed by the loop above, so no chan_t can still be
     * listed in a conn_t::chans that is about to be freed. What is left is the
     * channels themselves: a channel can outlive all of its members while a
     * peer still reports members for it, so this is a real list rather than
     * something server_close_conn() has already emptied. Freeing them in
     * creation order, and releasing the ordered index with them. */
    for (i = 0; i < s->nchan_objs; i++) {
        chan_free(s->chan_objs[i]);
        s->chan_objs[i] = NULL;
    }
    free(s->chan_objs);
    s->chan_objs = NULL;
    s->nchan_objs = 0;
    /* Same for the nick enumeration. Every conn was closed above and every one
     * of those closures released its nickname, so this is normally already
     * empty; it is freed unconditionally because a conn that never claimed a
     * nickname leaves nothing here either way, and a list that could still hold
     * a pointer to a freed conn_t must never survive shutdown. */
    free(s->nick_objs);
    s->nick_objs = NULL;
    s->nnick_objs = 0;
    s->nick_objs_cap = 0;    s->chan_objs_cap = 0;
    free(s->by_fd);
    s->by_fd = NULL;
    s->nconns = 0;
    /* The enumeration goes with the index it enumerates. Every conn above was
     * closed through server_close_conn(), so this is normally already empty;
     * freed unconditionally because a node that never held a connection holds
     * NULL here either way. */
    free(s->active_fds);
    s->active_fds = NULL;
    s->nactive = 0;
    s->active_cap = 0;
    /* MT 2.2: destroy reg_mu last among the registry arms -- every add/detach
     * above is done, and writers were joined before the by_fd walk. Guarded:
     * a half-built node from a failed init may never have started it. */
    if (s->reg_started) {
        pthread_mutex_destroy(&s->reg_mu);
        s->reg_started = 0;
    }
}

void server_shutdown(server_t *s)
{
    if (s == NULL) {
        return;
    }
    server_shutdown_phase1_say_goodbye(s);
    server_shutdown_phase2_close(s);
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

