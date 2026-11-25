/* server_shutdown.c -- see core/server.h. The shutdown trio
 * (server_shutdown_phase1_say_goodbye/server_shutdown_phase2_close/
 * server_shutdown), verbatim out of server.c (issue #543); the lifecycle,
 * clock, tick and msg-id counter stay there. The three functions were
 * already declared in core/server.h and the block has no static helpers,
 * so there is no new header (server_listen.c/server_dial.c precedent).
 */
#include "core/server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "account_store.h"
#include "core/channel.h"
#include "core/resume.h"
#include "core/server_conns.h"
#include "core/server_writers.h"
#include "core/strtab.h"
#include "federation/burst.h"
#include "federation/link.h"
#include "federation/nickreg.h"
#include "tls_backend.h"

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
