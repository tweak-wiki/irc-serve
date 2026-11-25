/* server.c -- server_t lifecycle, the fd-indexed connection registry, the peer
 * link/dial registries, the bounded-queue wrapper, and the nonblocking dial
 * FSM. Sections 2.1, 2.3, 2.4, 3.3 and 3.4 of docs/SERVER_DESIGN.md. The nick
 * and channel registries (2.2) are split out for #543 into core/server_registry.c. */
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
/* Phase 12: the transport interface, for server_accept_tls_one()'s handoff. */
#include "core/transport.h"
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
 * the layout is the backend's, and the two things this file asks of it are "is
 * there one" (tls_listen_fd's accept arm) and "release it" (the shutdown arm
 * above). */
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

int server_listen(server_t *s, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    if (s == NULL || port < 0 || port > 65535) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    /* Nonblocking BEFORE the fd is reachable by the loop. 3.4: the loop never
     * blocks, and an fd that is briefly blocking is a stall for every other
     * client on the node. */
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    s->listen_fd = fd;
    return 0;
}

int server_port(const server_t *s)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    if (s == NULL || s->listen_fd < 0) {
        return -1;
    }
    if (getsockname(s->listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

int server_tls_port(const server_t *s)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    if (s == NULL || s->tls_listen_fd < 0) {
        return -1;
    }
    if (getsockname(s->tls_listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

/* ---------------------------------------------------------------------------
 * THE IMPLICIT-TLS LISTENER (Phase 12), and why it is a SECOND LISTENER
 * ---------------------------------------------------------------------------
 * server_listen_tls() is server_listen() again with two differences, and both of
 * them are load-bearing rather than incidental.
 *
 * THE SECOND LISTENER. IRCv3's `sts` specification is explicit that it does not
 * work over a STARTTLS-only port: "STS expects that servers instead offer a port
 * that directly services secure connections and it is incompatible with servers
 * that offer secure connections only via STARTTLS on an insecure port." So a node
 * that wants to advertise `sts` -- which is the mechanism that stops a client
 * being downgraded after the first connection, and therefore the only part of this
 * phase that protects a return visit -- needs a port a client can connect to and be
 * encrypted from the first byte. That is this listener, on RFC 7194's 6697.
 *
 * THE REFUSAL WHEN THERE IS NO TLS. Refused rather than started, because a node
 * whose --tls-port is bound and which then serves PLAINTEXT on it is the worst
 * possible outcome: the operator typed a TLS port, a client sees 6697 and expects
 * a handshake, and gets IRC in the clear instead. There is no configuration in
 * which this function binds a port it cannot encrypt, and that is the whole of
 * the safety property here.
 *
 * THE CODE IS server_listen()'S AND NOT A REFACTOR OF IT. Duplicating twenty lines
 * of bind/listen/nonblocking is cheaper than a `int is_tls` parameter on
 * server_listen(), because a parameter would make every existing caller think about
 * a mode it does not have, and this codebase's own convention
 * (server_conns_set_nonblocking()'s comment) is that a descriptor must be
 * nonblocking BEFORE it is reachable from the loop -- which is a sequence
 * worth reading in one piece at each site rather than branching inside. */
int server_listen_tls(server_t *s, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    if (s == NULL || port < 0 || port > 65535) {
        return -1;
    }
    /* THE REFUSAL, and it is checked BEFORE socket(). There is no point creating a
     * descriptor this node is not going to be able to use, and on a build without
     * TLS there is no point at all.
     *
     * IT IS DEFENCE IN DEPTH AND NO TEST COVERS IT, and both halves of that are
     * deliberate. main() already refuses `--tls-port` when no certificate was
     * supplied, so this branch is UNREACHABLE through the shipped binary --
     * tests/integration/test_tls.c deletes it and stays green, which is how it was
     * found. It is kept because this function is public and a future caller that
     * does not go through main() would otherwise bind a port it cannot encrypt.
     * See test_tls.c's case_one_named_gap() for why there is no inspection
     * assertion on it either. */
    if (s->tls == NULL) {
        printf("[observable] tls_listen: state=REFUSED port=%d "
               "reason=NO_TLS_CONFIGURED\n", port);
        return -1;
    }
    if (s->tls_listen_fd >= 0) {
        /* One implicit-TLS listener. A second one would be a second place an
         * operator's intent about this node's TLS surface is recorded, and this
         * struct already has one (`tls_listen_port`). */
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    s->tls_listen_fd = fd;
    s->tls_listen_port = port;
    return 0;
}

/* Accept ONE connection on the implicit-TLS listener and hand the socket straight
 * to the TLS transport. Returns 1 on success, 0 when nothing is pending, -1 on a
 * fatal accept error, or SERVER_ACCEPT_REJECTED for the FD_SETSIZE rejection --
 * the same vocabulary server_accept_one() uses, so the loop's drain loop over the
 * TLS listener is character-for-character the drain loop over the plain one.
 *
 * THE HANDSHAKE IS NOT DONE HERE, and the difference matters: this is a nonblocking
 * node and a TLS handshake is several round trips. So the connection is registered
 * with a TLS transport whose handshake has only been STARTED, and the loop carries
 * it to completion on its own schedule -- which is exactly the case conn_t::want_read
 * and the empty pass in conn_pump() exist for, and which could not be expressed at
 * all in a loop that derived its poll mask from data.
 *
 * THE ORDER IS: accept, nonblocking, conn_new, ADD THE CONNECTION, and only then
 * start TLS. server_add_conn() sets conn_t::owner, which the backend needs to find
 * the node's SSL_CTX, so starting TLS first would find a conn with no node. That is
 * why the two steps are not swapped, and why transport_starttls() reports
 * NOT_CONFIGURED rather than dereferencing NULL. */
int server_accept_tls_one(server_t *s)
{
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof peer;
    conn_t *c;
    int fd;

    if (s == NULL || s->tls_listen_fd < 0) {
        return -1;
    }
    for (;;) {
        fd = accept(s->tls_listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
#if defined(EMFILE) || defined(ENFILE)
            if (errno == EMFILE || errno == ENFILE) {
                return 0;
            }
#endif
            return -1;
        }
        break;
    }
    /* 3.4's explicit FD_SETSIZE check, for the same reason and with the same
     * consequence as at the plaintext accept site: poll() would silently drop it. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        printf("[observable] accept_rejected: fd=%d reason=fd_ge_fdsize limit=%d "
               "transport=tls\n", fd, FD_SETSIZE);
        return SERVER_ACCEPT_REJECTED;
    }
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    c = conn_new(fd, CONN_CLIENT);
    if (c == NULL) {
        close(fd);
        return -1;
    }
    server_conns_describe_peer(c, (const struct sockaddr *)&peer);
    if (server_add_conn(s, c) != 0) {
        conn_free(c);
        close(fd);
        return -1;
    }
    if (transport_starttls(c, 1) != 0) {
        /* The handshake could not even be STARTED, which on this build means the
         * node's TLS state went away between the listener being bound and this
         * accept. The connection is closed rather than left in the clear, and the
         * reason is counted and printed: a node that silently served a plaintext
         * connection on its TLS port is exactly the failure this whole phase
         * exists to prevent. */
        s->n_tls_handshake_failed++;
        printf("[observable] tls_handshake_failed: fd=%d reason=START_FAILED "
               "transport=implicit action=CLOSE\n", fd);
        conn_mark_closing(c);
        return 1;
    }
    printf("[observable] client_connect: fd=%d host=%s state=REG_PASS "
           "transport=tls\n", fd, c->host);
    return 1;
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

/* ---------------------------------------------------------------------------
 * The peer link registry (2.3)
 * ---------------------------------------------------------------------------
 * A vector, and the reason is at server_link_t. These three are the only ways
 * into it, so the layout never has to be known outside this file -- which is the
 * same bargain server_t::nick_objs makes with server_nick_at().
 */
server_link_t *server_find_link(const server_t *s, const char *name)
{
    size_t i;

    if (s == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < s->nlinks; i++) {
        if (irc_ascii_same(s->links[i].name, name)) {
            return &s->links[i];
        }
    }
    return NULL;
}

size_t server_link_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nlinks;
}

server_link_t *server_link_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nlinks) {
        return NULL;
    }
    return &s->links[i];
}

conn_t *server_link_conn(const server_t *s, const server_link_t *link)
{
    /* Every one of these is a real case and not defensive padding:
     *   link == NULL   the caller had no link, so there is nothing to name
     *   fd < 0          a link with no socket: between dial halves, or after a
     *                   peer was dropped. Common, not degenerate.
     *   fd out of range by_fd is indexed BY the descriptor, so an fd the table
     *                   cannot hold names no slot at all. */
    if (s == NULL || link == NULL || link->fd < 0 ||
        link->fd >= SERVER_FD_TABLE) {
        return NULL;
    }
    return s->by_fd[link->fd];
}

/* ---------------------------------------------------------------------------
 * Peer lookup by server name (2.3)
 * ---------------------------------------------------------------------------
 * A link, a state test and a by_fd index. The reasoning for all three -- and for
 * why this is no longer a scan of by_fd for a conn_t::peer_name -- is at
 * server_find_peer() in the header, which is where a caller of this function
 * will be reading.
 *
 * The ESTABLISHED comparison is an int against the link's single state field
 * rather than a switch on handshake_state_t, deliberately: the state is an
 * enum value held in an int, and -Weverything's -Wswitch-default and
 * -Wcovered-switch-default cannot both be satisfied by a switch over it, and
 * a two-way test does not need one. The field is written in exactly one
 * place (fed_link_set_state() in link.c), so the comparison cannot be reading
 * a field nothing has updated. */
conn_t *server_find_peer(const server_t *s, const char *name)
{
    const server_link_t *link;

    if (s == NULL || s->by_fd == NULL) {
        return NULL;
    }
    link = server_find_link(s, name);
    if (link == NULL || link->state != (int)ESTABLISHED) {
        return NULL;
    }
    return server_link_conn(s, link);
}

size_t server_dial_count(const server_t *s)
{
    return (s == NULL) ? 0 : s->ndials;
}

/* ---------------------------------------------------------------------------
 * Nonblocking dial (3.4)
 * ---------------------------------------------------------------------------
 * The address arrives already resolved: getaddrinfo() inside the loop would
 * stall every client on the node, and there is deliberately no resolution
 * helper here to tempt one into being added later.
 *
 * No caller exists yet -- peer sockets are Phase 6.
 */

int server_dial(server_t *s, const struct sockaddr *sa, socklen_t salen,
                const char *peer_name)
{
    dial_t *slot;
    int fd;

    if (s == NULL || sa == NULL || salen == 0) {
        return -1;
    }
    if (peer_name == NULL || strlen(peer_name) > IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(peer_name)) {
        return -1;
    }

    fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    /* The same explicit check as the accept site: 3.4 requires it at every
     * site that produces a descriptor, and a dial that cannot be registered is
     * closed here for the same reason an out-of-range accept is. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        return -1;
    }
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    /* SOCK_NONBLOCK was already set, so connect() returns immediately with
     * EINPROGRESS instead of blocking the loop. That is the whole point of the
     * state machine.
     *
     * A connect that returns 0 is ALSO put in DIAL_CONNECTING rather than being
     * declared connected here. Two things make that deliberate:
     *
     *  - Probing SO_ERROR at this instant does not prove anything. To a loopback
     *    port with nothing behind it, connect() can return EINPROGRESS and the
     *    RST has not arrived yet, so SO_ERROR reads 0 for a connection that is
     *    already doomed. Treating that as success strands a dead dial in a state
     *    nothing promotes.
     *  - There must be exactly one path from "connect initiated" to "registered
     *    connection", or a second one has to be maintained beside it. An
     *    already-connected socket reports writable on the very next poll with
     *    SO_ERROR 0, so the cost of the uniform path is at most one tick.
     */
    if (connect(fd, sa, salen) != 0 && errno != EINPROGRESS) {
        close(fd);
        s->n_dial_failed++;
        return -1;
    }

    /* The table is grown BEFORE the count is incremented. Testing
     * "ndials == dials_cap" after incrementing would be off by one on the very
     * first dial -- 1 != 0 -- so the growth block would be skipped and the slot
     * below would be a null dereference. */
    if (s->ndials == s->dials_cap) {
        size_t want = (s->dials_cap == 0) ? 4u : s->dials_cap * 2u;
        dial_t *grown = (dial_t *)realloc(s->dials, want * sizeof *grown);

        if (grown == NULL) {
            close(fd);
            s->n_dial_failed++;
            return -1;
        }
        memset(grown + s->dials_cap, 0, (want - s->dials_cap) * sizeof *grown);
        s->dials = grown;
        s->dials_cap = want;
    }
    s->ndials++;

    slot = &s->dials[s->ndials - 1u];
    slot->fd = fd;
    slot->state = DIAL_CONNECTING;
    slot->slot = s->ndials - 1u;
    /* The one clock the node has, taken HERE rather than by the tick later: a
     * tick that supplied the stamp would stamp every DIAL_CONNECTING entry on
     * the same tick, so a dial that had already been waiting would be handed
     * the timeout it had already used up. Taking it at the start makes the
     * deadline a property of the connect() rather than of the loop's cadence. */
    slot->started_ms = server_now_ms();
    memcpy(slot->peer_name, peer_name, strlen(peer_name) + 1u);
    return 0;
}

int server_dial_collect(server_t *s, struct pollfd *pfds, size_t cap,
                        nfds_t *nfds_out)
{
    size_t i;

    if (s == NULL || pfds == NULL || nfds_out == NULL) {
        return -1;
    }
    *nfds_out = 0;
    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state != DIAL_CONNECTING) {
            continue;
        }
        if (*nfds_out >= cap) {
            return -1;
        }
        pfds[*nfds_out].fd = s->dials[i].fd;
        pfds[*nfds_out].events = POLLOUT;
        pfds[*nfds_out].revents = 0;
        (*nfds_out)++;
    }
    return 0;
}

int server_dial_progress(server_t *s, const struct pollfd *pfds, size_t nfds)
{
    size_t i;

    if (s == NULL || pfds == NULL) {
        return -1;
    }
    for (i = 0; i < s->ndials; i++) {
        struct pollfd ready;
        conn_t *c;
        int err = 0;
        socklen_t errlen = sizeof err;
        size_t j;

        if (s->dials[i].state != DIAL_CONNECTING) {
            continue;
        }
        ready.fd = s->dials[i].fd;
        ready.events = POLLOUT;
        ready.revents = 0;
        for (j = 0; j < nfds; j++) {
            if (pfds[j].fd == ready.fd) {
                ready.revents = pfds[j].revents;
                break;
            }
        }
        if (ready.revents == 0) {
            continue;
        }
        if (getsockopt(s->dials[i].fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0) {
            err = errno;
        }
        if (err != 0) {
            close(s->dials[i].fd);
            s->dials[i].fd = -1;
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }

        c = conn_new(s->dials[i].fd, CONN_SERVER);
        if (c == NULL || server_add_conn(s, c) != 0) {
            conn_free(c);
            close(s->dials[i].fd);
            s->dials[i].fd = -1;
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }
        /* peer_name is owned by the conn from here; the dial slot's copy is
         * released when the table is torn down. */
        c->peer_name = (char *)malloc(strlen(s->dials[i].peer_name) + 1u);
        if (c->peer_name == NULL) {
            server_close_conn(s, s->dials[i].fd);
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }
        memcpy(c->peer_name, s->dials[i].peer_name,
               strlen(s->dials[i].peer_name) + 1u);
        s->dials[i].state = DIAL_CONNECTED;
        s->n_dial_connected++;

        /* --------------------------------------------------------------------
         * PHASE 12: THE OUTBOUND PEER LINK'S TLS, and where it starts
         * --------------------------------------------------------------------
         * HERE, and not in fed_tick's dial arm, because this is the only place the
         * socket is KNOWN to be connected. The dial arm has a descriptor that is
         * still DIAL_CONNECTING -- connect() may not have completed -- and starting
         * a handshake on it would write a ClientHello into a socket whose SYN is
         * unanswered. The connection exists and peer_name is on it; this is the
         * moment.
         *
         * THE NAME IS WHAT IS VERIFIED, not the address, and that is a decision
         * rather than an accident of what was to hand:
         *
         *   2.3 makes a peer's IDENTITY its server name -- name uniqueness is a
         *   handshake-time rejection and every rejection names a server. The
         *   certificate names a peer too. Verifying one against the other is what
         *   makes the link mean "this is irc.b", and irc.b is the thing the rest of
         *   this node believes about it: `nick@server`, `irc-serve-origin`, the
         *   hop path, every 2.4 tag.
         *
         *   The --peer HOST is only a DIAL HINT, and this codebase resolved it once
         *   at startup and threw the name away (node_main.c's resolve_peer() takes
         *   the first result and frees the rest, for the reason its comment gives).
         *   There is no hostname left to check a certificate against, and checking
         *   against the resolved IP instead would be both worse and more brittle: a
         *   certificate issued for `irc.example.com` would fail, and the failure
         *   would appear and disappear as DNS moved.
         *
         *   THE COST AN OPERATOR PAYS, stated so it is not a surprise: certificates
         *   for this mesh must be issued for the SERVER NAMES, not for the
         *   addresses. A node whose peers' certificates are for their hostnames
         *   cannot use --peer-tls, and the refusal names CERTIFICATE_VERIFY_FAILED
         *   rather than being mysterious.
         */
        {
            server_link_t *link = server_find_link(s, s->dials[i].peer_name);

            if (link != NULL && link->require_tls != 0) {
                if (s->tls == NULL) {
                    /* UNREACHABLE THROUGH THE SHIPPED BINARY, and refused anyway.
                     * main() refuses a --peer-tls on a node with no certificate, so
                     * a link cannot reach here with require_tls set and no TLS. The
                     * arm exists because the alternative is a null dereference if
                     * that check is ever moved, and because a link that is REQUIRING
                     * TLS and finds none must fail loudly rather than continue in the
                     * clear -- which is the downgrade this whole field exists to
                     * prevent. */
                    s->n_tls_handshake_failed++;
                    printf("[observable] tls_handshake_failed: peer=%s "
                           "reason=NO_TLS_CONFIGURED action=CLOSE\n", link->name);
                    server_close_conn(s, s->dials[i].fd);
                    s->dials[i].state = DIAL_FAILED;
                    s->n_dial_failed++;
                    continue;
                }
                if (transport_starttls_peer(c, 0, link->name) != 0) {
                    s->n_tls_handshake_failed++;
                    printf("[observable] tls_handshake_failed: peer=%s "
                           "reason=START_FAILED action=CLOSE\n", link->name);
                    server_close_conn(s, s->dials[i].fd);
                    s->dials[i].state = DIAL_FAILED;
                    s->n_dial_failed++;
                    continue;
                }
                /* NO LINK FIELD IS SET HERE, and that is the third of this phase's
                 * three "looks like TLS but is not" states removed.
                 *
                 * There used to be `link->tls_active = 1;` on exactly this line --
                 * set the moment the handshake STARTS, before a byte has been
                 * exchanged, and read NOWHERE in the tree. An optimistic flag with
                 * no reader is the shape a future reader trusts: the name says
                 * "this link is carrying TLS" and the value says the opposite of
                 * what the certificate will turn out to be.
                 *
                 * `link_tls_start` is the observable that replaces it, and it is
                 * honest about what it knows: a handshake has begun. Whether it
                 * COMPLETED is answered by `link_established` on the far side of the
                 * handshake, or by `tls_error` / `tls_handshake_failed` if it did
                 * not. A field written at the start could never carry the second
                 * half of that without a second writer, and the second writer is
                 * where this would have gone wrong.
                 *
                 * See server.h for why there is no such field. */
                printf("[observable] link_tls_start: peer=%s role=client\n",
                       link->name);
            }
        }
    }
    return 0;
}
