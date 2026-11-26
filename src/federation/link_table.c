/* link_table.c -- see federation/link.h. The peer-link table.
 *
 * Split verbatim out of link.c (issue #543 TU-39): the link-table family
 * (fed_link_set_state() + fed_link_of_conn() + fed_link_new() +
 * fed_link_set_tls() + fed_link_configure()). All five stay declared in
 * federation/link.h (tick.c/link_config.c/link_guard.c/link_accept.c/
 * link_dump.c/link_queue.c precedent, no new header); no static helpers move.
 * The reason spellings (FED_REASON_NAME) + fed_federate_reason() live in
 * federation/link_dump.c (issue #543 TU-41); the FEDERATE exchange sender
 * (fed_queue_federate()) is now in federation/link_queue.c (issue #543 TU-40).
 */
#include "federation/link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/connection.h"
#include "core/message.h"

/* ---------------------------------------------------------------------------
 * Link table
 * ---------------------------------------------------------------------------
 */

/* The link's own state transitions, inlined here. One implementation, one
 * field: every transition below writes server_link_t::state and nothing else
 * assigns it, so there is no mirror to go stale. The reusable
 * handshake_*() rules over a caller-owned context live in
 * federation/handshake.c (issue #543), for
 * tests/federation/test_federate_handshake.c and test_heartbeat.c, which
 * assert the rules directly. */
void fed_link_set_state(server_link_t *link, handshake_state_t state)
{
    if (link != NULL) {
        link->state = (int)state;
        /* Issue #676's sticky bit: the one transition that must be
         * remembered after the link leaves it. Every other transition
         * writes state and nothing else, and this one line is why that
         * sentence stays true. */
        if (state == ESTABLISHED) {
            link->ever_established = 1;
        }
    }
}

/* The link a CONNECTION belongs to, or NULL.
 *
 * NOT a lookup by descriptor, and the reason is a failure this phase's own test
 * suite found. Between a link's connection dying and something resetting the
 * link, link->fd is STALE: the reaper cleared by_fd[fd] but nothing cleared the
 * name the link kept. A descriptor is a small integer and the kernel hands the
 * same one out again immediately, so the next connection to be accepted gets
 * the very descriptor the dead link still names. A `link->fd == c->fd` lookup
 * then returns the DEAD link for a LIVE, UNRELATED connection, and the FSM
 * starts rejecting a stranger's claim against a link sitting in HANDSHAKE_SENT
 * with somebody else -- which is a real, observed failure, not a hypothetical
 * one.
 *
 * So the descriptor is necessary but not sufficient, and the second half of the
 * test is conn_t::peer_name: a connection that arrived on the listener has none
 * until fed_link_established() gives it one, and a connection the DIAL FSM
 * created already carries the name of the peer it was dialled for. Both halves
 * together identify the link -- the descriptor says which socket, the name says
 * which peer that socket is supposed to be speaking to -- and a recycled
 * descriptor fails the second half, because a fresh conn_new() has a NULL
 * peer_name.
 *
 * server_link_conn() in core/server.h has the same exposure and states it: a
 * link whose descriptor is stale is the case where by_fd[fd] hands back some
 * OTHER connection. This function is that same observation with a guard on it,
 * and the guard is what makes the lookup usable from the inbound path, where a
 * link with a stale descriptor is an ordinary state rather than an accident. */
server_link_t *fed_link_of_conn(const server_t *s, const conn_t *c)
{
    size_t i;

    if (s == NULL || c == NULL || c->peer_name == NULL) {
        return NULL;
    }
    for (i = 0; i < s->nlinks; i++) {
        if (s->links[i].fd == c->fd && irc_ascii_same(s->links[i].name, c->peer_name)) {
            return &s->links[i];
        }
    }
    return NULL;
}

/* Create a link for a name this node does not have one for. Used on the
 * accepting side, where 2.3 says a link exists once a peer is "configured" --
 * and an inbound claim is a configuration this node did not write and must
 * still accept, because either side may connect.
 *
 * `initiator` is 0 because an accepted link has nothing to dial: it has no
 * pre-resolved address, since this node never learned one. T7 checks the
 * address as well as the flag, so the two cannot come to disagree. */
server_link_t *fed_link_new(server_t *s, const char *name, int initiator)
{
    server_link_t *link;

    if (s == NULL || name == NULL) {
        return NULL;
    }
    /* The vector grows geometrically like the other registries on server_t, and
     * past IRC_FED_MAX_PEERS rather than refusing. The constant is that
     * vector's INITIAL capacity, not a limit on the number of peers a node may
     * be linked to, and refusing at it would make a capacity number a policy. */
    if (s->nlinks == s->links_cap) {
        size_t want = (s->links_cap == 0u) ? (size_t)IRC_FED_MAX_PEERS
                                           : s->links_cap * 2u;
        server_link_t *grown =
            (server_link_t *)realloc(s->links, want * sizeof *grown);

        if (grown == NULL) {
            /* A node that cannot allocate a link cannot have a peer, and
             * refusing here is better than a link table that is half a peer.
             * The caller reports it; this function has no verdict to give. */
            return NULL;
        }
        /* Zero the new slots. A link that is not zeroed would carry a
         * descriptor from the previous boot of this array, and a stale fd is
         * the one thing server_link_conn() cannot defend against -- it indexes
         * by_fd BY the descriptor. */
        memset(grown + s->links_cap, 0,
               (want - s->links_cap) * sizeof *grown);
        s->links = grown;
        s->links_cap = want;
    }
    link = &s->links[s->nlinks];
    memset(link, 0, sizeof *link);
    memcpy(link->name, name, strlen(name) + 1u);
    link->fd = -1;
    link->initiator = initiator;
    link->burst_done = 0;
    fed_link_set_state(link, INIT);
    s->nlinks++;
    return link;
}

/* See the header for the argument, and for why this is a separate call rather than
 * a parameter. The sticky property is enforced here by the ABSENCE of any clear:
 * the only statement that writes `require_tls` in the whole file is the one below,
 * and it only ever writes 1. That is the enforcement, and it is checkable by
 * inspection rather than by remembering. */
int fed_link_set_tls(server_t *s, const char *name, int require_tls)
{
    server_link_t *link = server_find_link(s, name);

    if (link == NULL) {
        return -1;
    }
    link->require_tls = (require_tls != 0) ? 1 : 0;
    /* THE INBOUND HALF IS ENFORCED ON THE HANDSHAKE, and an operator who read
     * an older version of this comment -- "NOT enforced here" -- should read
     * on. The accept site still cannot tell a peer from a client, and it still
     * does not sniff the plain port for a ClientHello: any client that sends
     * something other than a ClientHello first defeats a detector, and a
     * detector that guesses is a downgrade waiting to be asked for. What
     * changed (issue #221) is that the handshake itself refuses: a FEDERATE
     * arriving on a plaintext connection for a link with require_tls is
     * rejected as TLS_REQUIRED before the secret is compared. The secret has
     * already travelled at that point, so this does not unsend it -- what it
     * stops is the cleartext LINK, which would otherwise carry the mesh's
     * traffic in the clear against the operator's stated requirement. A
     * plaintext FEDERATE for a link WITHOUT require_tls is accepted exactly
     * as before, which is what keeps a mixed mesh working.
     *
     * An inbound peer link over TLS arrives on the implicit-TLS listener,
     * where every byte is TLS before anything is interpreted, so a peer that
     * points at --tls-port never trips the refusal above.
     *
     * TO CLOSE EVERY PLAINTEXT CONNECTION, the answer is still `--tls-require`,
     * which refuses them at accept and leaves the operator to point peers at
     * --tls-port.
     */
    printf("[observable] link_tls: peer=%s require_tls=%d enforced=%s inbound_hint=%s\n",
           link->name, link->require_tls,
           (link->initiator != 0) ? "outbound_dial"
                                  : "use_tls_port_or_tls_require",
           (link->initiator != 0) ? "n/a"
                                  : "accept_on_the_tls_port");
    return 0;
}

server_link_t *fed_link_configure(server_t *s, const char *name,
                                  const struct sockaddr *sa, socklen_t salen)
{
    server_link_t *link;

    if (s == NULL || name == NULL || sa == NULL || salen == 0) {
        return NULL;
    }
    /* 2.3's own reason, applied to a peer name rather than to this node's: a
     * name this node could not stamp on an irc-serve-origin tag is a name it
     * could not address, and a second link for a name already in the table is
     * the uniqueness rule enforced at the only point where it can be cheap. */
    if (strlen(name) > (size_t)IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(name)) {
        return NULL;
    }
    if (server_find_link(s, name) != NULL) {
        return NULL;
    }
    link = fed_link_new(s, name, 1);
    if (link == NULL) {
        return NULL;
    }
    /* The PRE-RESOLVED address, on the link rather than in a configuration
     * array: a link that is re-dialled after a failure carries the address it
     * failed to reach, and a reconnect therefore needs no lookup -- which is
     * 3.4's rule, not a convenience. */
    memcpy(&link->addr, sa, (size_t)salen);
    link->addrlen = salen;
    return link;
}
