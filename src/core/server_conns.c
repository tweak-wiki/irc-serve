/* server_conns.c -- see server_conns.h. The fd-indexed connection registry,
 * verbatim out of server.c (issue #543); the lifecycle, nick/channel
 * registries and shutdown stay there. The two accept-time helpers move with
 * the registry and drop `static` (TU-10 precedent: fanout_stamp), because the
 * listeners and dial that stay in server.c share them.
 */
#include "core/server_conns.h"

#include "core/server.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/account.h"
#include "core/channel.h"
#include "core/message.h"
#include "core/resume.h"
#include "core/transport.h"
#include "federation/link.h"
#include "federation/nickreg.h"

/* Put a descriptor into nonblocking mode. Called on the listener, on every
 * accepted socket and on every dialled socket BEFORE the descriptor becomes
 * reachable from the loop, so the loop cannot inherit a blocking fd and stall
 * every other client while it waits. */
int server_conns_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    if ((flags & O_NONBLOCK) != 0) {
        return 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Record what the accept told us about the peer. `host` is the address the
 * connection actually came from, which is a fact about the socket rather than
 * anything the peer asserted, so it is recorded at accept time. */
void server_conns_describe_peer(conn_t *c, const struct sockaddr *sa)
{
    struct sockaddr_in sin;
    char text[INET_ADDRSTRLEN];

    if (sa->sa_family != AF_INET) {
        return;
    }
    /* memcpy rather than a pointer cast: the caller's buffer is a
     * sockaddr_storage, and copying keeps this free of the aliasing and
     * alignment assumptions a cast would encode. */
    memcpy(&sin, sa, sizeof sin);
    if (inet_ntop(AF_INET, &sin.sin_addr, text, sizeof text) == NULL) {
        return;
    }
    if (strlen(text) < sizeof c->host) {
        memcpy(c->host, text, strlen(text) + 1u);
    }
}
/* ---------------------------------------------------------------------------
 * The fd-indexed connection registry
 * ---------------------------------------------------------------------------
 */

conn_t *server_conn(server_t *s, int fd)
{
    if (s == NULL || s->by_fd == NULL || fd < 0 || fd >= SERVER_FD_TABLE) {
        return NULL;
    }
    return s->by_fd[fd];
}

int server_add_conn(server_t *s, conn_t *c)
{
    int rc = -1;

    if (s == NULL || s->by_fd == NULL || c == NULL) {
        return -1;
    }
    if (c->fd < 0 || c->fd >= SERVER_FD_TABLE) {
        return -1; /* see SERVER_FD_TABLE: a descriptor poll() cannot name */
    }
    /* MT 2.2: serialize against writer scans (reg_mu -> wq_lock order; the
     * add path takes no wq_lock). */
    if (s->reg_started) {
        pthread_mutex_lock(&s->reg_mu);
    }
    if (s->by_fd[c->fd] != NULL) {
        goto out;
    }
    /* The active list grows BEFORE anything is registered, so a failed
     * realloc leaves the node exactly as it was: by_fd untouched, nconns
     * untouched. Growth is geometric, like dials. */
    if (s->nactive == s->active_cap) {
        size_t want = (s->active_cap == 0) ? 16u : s->active_cap * 2u;
        int *grown = (int *)realloc(s->active_fds, want * sizeof *grown);

        if (grown == NULL) {
            goto out;
        }
        s->active_fds = grown;
        s->active_cap = want;
    }
    /* Phase 12: the conn acquires its NODE here, which is the only writer. The TLS
     * backend needs the node's SSL_CTX and the call site that starts a handshake
     * -- conn_pump(), from inside the connection layer -- has no server_t. See
     * conn_t::owner's own comment. A conn_t that is never registered keeps NULL,
     * and the backend treats that as "not configured" rather than dereferencing. */
    c->owner = s;
    s->by_fd[c->fd] = c;
    /* #281(b): a recycled descriptor inherits no deadline. The slot is keyed
     * by fd NUMBER, so without this a new conn on an old fd would close early
     * on the previous holder's bound -- or hang 2 s extra on it. */
    s->wq_close_at[c->fd] = 0;
    s->active_fds[s->nactive++] = c->fd;
    s->nconns++;
    s->n_accepted++;
    rc = 0;
out:
    if (s->reg_started) {
        pthread_mutex_unlock(&s->reg_mu);
    }
    return rc;
}

int server_accept_one(server_t *s)
{
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof peer;
    conn_t *c;
    int fd;

    if (s == NULL || s->listen_fd < 0) {
        return -1;
    }
    for (;;) {
        fd = accept(s->listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; /* nothing pending */
            }
#if defined(EMFILE) || defined(ENFILE)
            if (errno == EMFILE || errno == ENFILE) {
                /* Out of descriptors. Returning 0 rather than -1 keeps the
                 * loop alive; the connection is refused by the kernel backlog
                 * and retried on the next accept. */
                return 0;
            }
#endif
            return -1;
        }
        break;
    }

    /* 3.4: "explicit if (fd >= FD_SETSIZE) reject at every accept/dial site".
     * The check has to be explicit and immediate. poll() would silently ignore
     * an out-of-range descriptor, and FD_SET on it is undefined behaviour --
     * so a connection that is merely "not registered" is not a harmless drop,
     * it is a write past the end of an fd_set on some paths. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        printf("[observable] accept_rejected: fd=%d reason=fd_ge_fdsize limit=%d\n",
               fd, FD_SETSIZE);
        return SERVER_ACCEPT_REJECTED;
    }

    /* ------------------------------------------------------------------------
     * PHASE 12: --tls-require, AND IT IS CHECKED BEFORE ANYTHING IS BUILT
     * ------------------------------------------------------------------------
     * A node told to require TLS refuses a PLAINTEXT client connection, and it
     * refuses it HERE -- at accept, before a conn_t exists -- rather than after
     * registration or on the first command.
     *
     * THE ORDER IS THE PROPERTY. Refusing late would mean the connection had been
     * registered, could be handed a nickname, could JOIN a channel and RECEIVE
     * messages before anything noticed it was in the clear; a client on a
     * --tls-require node would see a working IRC session that is secretly
     * unauthenticated and unencrypted, which is worse than a refusal because it
     * looks like success. Closing at accept means the client gets a FIN and no
     * bytes at all: no 001, no MOTD, no channel, nothing to mistake for a session.
     *
     * AND THE LISTENER IS STILL BOUND, which is the other half of the decision and
     * is deliberate. Not binding it would mean an operator's `--port` silently
     * became a no-op, the startup line would have no port to report, and every
     * fixture that waits on readiness would time out instead of learning why.
     * Binding it and closing each connection says the same thing to a client (it
     * gets nothing) and says it to an operator as a named line in the log.
     */
    if (s->tls_require != 0) {
        close(fd);
        s->n_tls_client_refused++;
        /* THE HINT NAMES ONLY WHAT IS ACTUALLY REACHABLE FROM HERE, and it used to
         * name two things of which one is a dead end. It said
         * `hint=use_the_tls_port_or_STARTTLS`, but STARTTLS cannot be reached from
         * this site at all: the refusal happens HERE, at accept, BEFORE a conn_t
         * exists, so there is no connection to answer 670 on and no line the client
         * could ever see. A client following that half of the hint would connect,
         * send STARTTLS, and get a FIN and zero bytes -- the same outcome as not
         * trying -- which is a worse answer than silence because it looks like the
         * command is broken.
         *
         * So the hint names the one thing that works. --tls-require is a refusal at
         * accept by design (see the paragraph above: a client refused late would
         * have a working, unencrypted session), and a client that cannot open the
         * implicit-TLS port has no route to this node at all -- which is the correct
         * consequence of the flag rather than a gap in the hint. */
        printf("[observable] client_refused: fd=%d reason=TLS_REQUIRED "
               "hint=connect_to_the_tls_port\n", fd);
        return 1;
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
    printf("[observable] client_connect: fd=%d host=%s state=REG_PASS\n",
           fd, c->host);
    return 1;
}

void server_close_conn(server_t *s, int fd)
{
    conn_t *c = server_conn(s, fd);
    size_t i;

    if (c == NULL) {
        return; /* unregistered: a second close is a no-op, not a double close */
    }

    /* THE SESSION WINDOW IS RECORDED HERE AND NOT BELOW, and the position is
     * the whole of what makes it work: chan_conn_gone() -- the very next call --
     * walks c->chans, parts the client out of every channel and disposes of any
     * that have run out of reasons to exist. A window noted after it would
     * record an empty channel list and restore nothing, SILENTLY, and a silent
     * no-op is the failure mode core/resume.h is arranged to avoid.
     *
     * IT IS BEFORE THE NICK IS RETIRED too, for the same reason and not by
     * accident: core/resume.c distinguishes a lost session from an explicit
     * QUIT by asking whether this connection still holds its nickname, and the
     * QUIT handler has already unclaimed it by the time a QUIT reaches here.
     * See resume_note() for why a QUIT is not a resumable session. */
    resume_note(s, c, server_now_ms());

    /* Take the connection out of its channels BEFORE it is detached, and
     * before conn_free() releases the array.
     *
     * The ordering is the whole point. A chan_t's member list holds conn_t
     * pointers, so a conn that is freed while still a member leaves every
     * remaining member of every channel it was in with a dangling pointer -- and
     * the node has no way to notice, because nothing dereferences it until the
     * next fan-out. This is the same class of hazard the fd detach below avoids
     * for a reused descriptor, and it is why the reaper is the place both
     * happen.
     *
     * chan_conn_gone() also emits the PART to whoever is left in each channel
     * and disposes of any channel that has run out of reasons to exist. It must
     * run while the conn is still a usable addressable object, which is exactly
     * now. */
    chan_conn_gone(s, c);

    /* Detach from the registry BEFORE closing, so a descriptor the OS reuses
     * between the close() and the next poll iteration cannot resolve to this
     * conn. The active list loses the fd in the same breath, by swap-remove:
     * order is insignificant, so the last entry fills the hole in O(1) with
     * no shift and no compaction pass.
     *
     * MT 2.2: under reg_mu -- the detach (by_fd NULL + swap-remove + nconns)
     * is the mutation writer scans race. Everything after the detach only
     * touches this conn's own teardown (nicks/channels already handled above
     * on the loop thread) and needs no registry lock. */
    if (s->reg_started) {
        pthread_mutex_lock(&s->reg_mu);
    }
    s->by_fd[fd] = NULL;
    /* #281(b): the bound dies with the holder. Every closer runs through here,
     * so the reaper and the dial/shutdown paths cannot leave a deadline behind
     * for the next conn the OS numbers this way. */
    if (fd >= 0 && fd < SERVER_FD_TABLE) {
        s->wq_close_at[fd] = 0;
    }
    s->nconns--;
    for (i = 0; i < s->nactive; i++) {
        if (s->active_fds[i] == fd) {
            s->active_fds[i] = s->active_fds[--s->nactive];
            break;
        }
    }
    if (s->reg_started) {
        pthread_mutex_unlock(&s->reg_mu);
    }

    /* Retire the connection from the nick index, and through the ONE function
     * that does it. This is the whole of issue #102: the close used to remove
     * the conn from the registry's TABLE and then free it, leaving the
     * ENUMERATION -- the vector WHO walks -- holding the pointer. The next bare
     * WHO dereferenced freed memory, and the count stayed one too high for the
     * rest of the process's life.
     *
     * One call, and deliberately not two. The guard that made the old code
     * safe -- "only if this conn is still the holder, or a conn that was denied
     * the nick evicts the one that has it" -- lived in the CALLER, wrapped
     * around one half of the index, so nothing stopped the other half from
     * being applied on its own. server_nick_unclaim() has no name argument at
     * all: it removes the table entries that map to THIS conn and the vector
     * entry that IS this conn, in that order, with no return in between. The
     * ownership question has become the deletion predicate instead of a test
     * somebody has to remember, and there is no longer a way to write half of
     * the operation.
     *
     * It is a no-op for a connection that never claimed a name, so this is not
     * conditional on c->nick -- that field is a display copy, and asking it
     * whether the connection is in the index is the mistake this paragraph is
     * about. */
    server_nick_unclaim(s, c);

    /* And the ACCOUNT, in the same place and for the same reason. Two
     * identities, two retirements, one function.
     *
     * The account is NOT in an index -- it is a field on the conn and nothing
     * else looks it up -- so this arm is belt to conn_free()'s braces rather
     * than the only thing holding them up, and it is here anyway for three
     * reasons that are all about a reader rather than about correctness:
     * server_nick_unclaim() is directly above, and a reader who is told "every
     * retirement releases the names" should be able to see the account go in the
     * same breath; account.h documents this call as the teardown's job, and a
     * teardown that did not do it would leave that claim false; and
     * account_clear() erases BOTH fields in one function, which is only
     * reachable if something calls it.
     *
     * A connection's account outlives the connection in the sense that matters
     * -- it outlives the SOCKET, so the same person gets it back on the next
     * connection -- and it must not outlive the conn_t. */
    account_clear(c);

    /* The counterpart of the loop's conn_close lines, and deliberately a
     * different word: those say a connection is ON ITS WAY OUT and why, this one
     * says it is GONE and what the node's indexes hold now that it is. The
     * nicks= is the whole reason this line exists -- "the nick was released" is
     * otherwise only checkable by sending a message to the name afterwards, and a
     * client that disconnects without QUIT leaves the question open for good,
     * because the node never receives a line saying the name is free.
     *
     * Printed BEFORE conn_free() because c->nick is read here, and before the
     * counter is bumped so the two bracket the teardown in a readable order. */
    printf("[observable] conn_reaped: fd=%d nick=%s nicks=%zu\n", fd,
           (c->nick[0] != '\0') ? c->nick : "-", server_nick_count(s));

    close(fd);
    s->n_closed++;
    conn_free(c);
}

int server_queue_quiet(server_t *s, conn_t *c, const char *data, size_t len)
{
    if (c == NULL || conn_queue(c, data, len) == 0) {
        /* #279: no kick here -- the caller coalesces one kick per emission
         * (server_writers_kick_slots) instead of one per member. A NULL conn
         * still reports success: it queued nothing and overflowed nothing. */
        return 0;
    }
    /* 3.4: bounded write queues, and a saturated link is DROPPED, not
     * buffered. Marking CLOSING is all the send path is allowed to do; the
     * reaper closes the fd at the next fixed point. */
    s->n_writeq_overflow++;
    /* The depth is sampled LOCKED (#293): this runs on the loop thread while a
     * writer may be advancing woff under wq_lock, and a torn size_t here is a
     * C11 race even though it is only a log line. */
    printf("[observable] writeq_overflow: fd=%d pending=%zu cap=%zu\n",
           c->fd, conn_write_pending_locked(c), CONN_WQ_MAX);
    conn_mark_closing(c);
    return -1;
}

int server_queue(server_t *s, conn_t *c, const char *data, size_t len)
{
    int rc = server_queue_quiet(s, c, data, len);

    if (rc == 0) {
        /* Issue #367: wake exactly this conn's owning writer, never all. */
        server_writers_kick_conn(s, c);
    }
    return rc;
}
/* #499: grace between the 2 s close deadline and the wedged-queue fence.
 * A slow-but-progressing drain (e.g. the 417 flush behind a shrunk send
 * buffer) still closes through the success branch below -- final pump, then
 * close -- so the fence must only fire on a conn no tick can close: a writer
 * pinning wq_lock at every reaper visit with bytes still queued. Five extra
 * seconds bounds that wedge while no legitimate drain ever reaches it.
 * shortcut: drop-on-deadline only, upgrade to progress-tracking if a live
 * drain ever trips this. */
#define WQ_WEDGED_FENCE_EXTRA_MS (5000u)

int server_reap(server_t *s)
{
    size_t i = 0;
    int closed = 0;

    if (s == NULL || s->by_fd == NULL) {
        return 0;
    }
    /* The reaper walks the active list, not the flat table: O(nconns) per
     * tick. server_close_conn() swap-removes, so after a close the index is
     * re-examined rather than advanced -- the entry now sitting there has not
     * been looked at yet. */
    while (i < s->nactive) {
        int fd = s->active_fds[i];
        conn_t *c = server_conn(s, fd);

        if (c != NULL && atomic_load_explicit(&c->state, memory_order_acquire) == CONN_CLOSING) {
            /* MT 2.3 (#242): structural close handoff. The reaper must never
             * close()+free() a conn while a writer holds its wq_lock mid-drain
             * (conn_pump). The 2 s wq_close_at deadline below still bounds the
             * deferral, but the guarantee is not timing-only: a non-blocking
             * trylock proves no writer is inside the pump right now, and a held
            * lock skips this tick, arming (not resetting) the 2 s deadline
            * (a draining writer is progress, not stalling, but the bound
            * still runs from the first deferral). Pending is read under that
             * same hold, so check and decision cannot race the queue. The
             * trylock never blocks, so reg_mu -> wq_lock order cannot invert. */
            if (s->writer_threads > 0) {
                size_t pending = 0;

                if (pthread_mutex_trylock(&c->wq_lock) != 0) {
                    /* #291: arm the deadline on the first trylock skip so a
                     * conn deferred tick after tick stops getting a fresh
                     * 2 s bound each time its lock frees. Only the first
                     * skip writes; expiry forces close via the normal
                     * fall-through below once the lock is free (never
                     * closed under a held lock: see #242 above). */
                    if (fd >= 0 && fd < SERVER_FD_TABLE &&
                        s->wq_close_at[fd] == 0) {
                        s->wq_close_at[fd] = server_now_ms() + 2000u;
                    }
                    /* #281(a): the bound fires even when the lock never frees.
                     * Past the deadline the holder is not draining but wedged,
                     * and waiting on it would pin the fd and its queue toward
                     * FD_SETSIZE. shutdown() neither detaches nor frees --
                     * #242 still holds -- it just fails the in-flight pump, so
                     * the writer drops the lock and the fall-through below
                     * closes on the next tick. */
                    if (fd >= 0 && fd < SERVER_FD_TABLE &&
                        s->wq_close_at[fd] != 0 &&
                        server_now_ms() >= s->wq_close_at[fd]) {
                        uint64_t now = server_now_ms();

                        (void)shutdown(fd, SHUT_RDWR);
                        /* #499: fence the queue so a wedged writer's slice
                         * loop terminates: with pending still > 0 the writer
                         * keeps slicing 32 KiB against EAGAIN without ever
                         * seeing a fatal error, stalling thin conns behind
                         * it. The drop waits until well past the 2 s close
                         * deadline above (which already closes every conn a
                         * tick can reach, final pump first), so it fires only
                         * on a writer-pinned wedge, never on a slow drain.
                         * Trylock only: a draining writer already holds the
                         * lock and will observe the shutdown failure
                         * itself. */
                        if (now >= s->wq_close_at[fd] +
                                     (uint64_t)WQ_WEDGED_FENCE_EXTRA_MS &&
                            pthread_mutex_trylock(&c->wq_lock) == 0) {
                            atomic_store_explicit(
                                &c->woff,
                                atomic_load_explicit(&c->wlen,
                                                     memory_order_acquire),
                                memory_order_release);
                            pthread_mutex_unlock(&c->wq_lock);
                        }
                    }
                    server_writers_kick_conn(s, c);
                    i++;
                    continue;
                }
                /* Lock is held: _held is the file's convention here, and the
                saturating form below makes even a torn snapshot yield 0. */
                pending = conn_write_pending_held(c);
                pthread_mutex_unlock(&c->wq_lock);
                if (pending > 0) {
                    uint64_t now = server_now_ms();

                    if (fd >= 0 && fd < SERVER_FD_TABLE) {
                        if (s->wq_close_at[fd] == 0) {
                            s->wq_close_at[fd] = now + 2000u;
                        }
                        if (now < s->wq_close_at[fd]) {
                            server_writers_kick_conn(s, c);
                            i++;
                            continue;
                        }
                        /* #292: deadline expired with bytes still queued (the
                         * 417 at N > 0). One last synchronous pump before the
                         * close below -- conn_pump takes wq_lock itself, so it
                         * cannot race a writer's slice, and it runs at most
                         * once per conn. The close still happens; the point is
                         * the reason goes out first. */
                        (void)conn_pump(c);
                    }
                }
            }
            /* The slot zeroing lives in server_close_conn() now (#281(b)), so a
             * non-reaper closer cannot leave a deadline behind either. */
            server_close_conn(s, fd);
            closed++;
        } else {
            i++;
        }
    }
    return closed;
}

