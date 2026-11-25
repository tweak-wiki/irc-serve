/* server_dial.c -- see core/server.h. The nonblocking outbound-dial FSM
 * (server_dial_count/server_dial/server_dial_collect/server_dial_progress),
 * verbatim out of server.c (issue #543); the lifecycle, link lookup, shutdown
 * and listen/accept arms stay there. The dial functions were already declared
 * in core/server.h and the block has no static helpers, so there is no new
 * header (fanout_deliver.c precedent).
 */
#include "core/server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Phase 12: the outbound peer link's TLS starts in server_dial_progress(). */
#include "core/transport.h"
/* Accept-time nonblocking helper, defined in server_conns.c. */
#include "core/server_conns.h"

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
