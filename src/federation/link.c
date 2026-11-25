/* link.c -- see link.h. The link lifecycle and the FEDERATE exchange.
 *
 * Server-name comparison is message.h's irc_ascii_same() (issue #181): a server
 * name is case-insensitive (2.1, RFC 1459 2.3.2), so `IRC.A` and `irc.a` are
 * one server. ASCII-only, for the reason dedup.c gives: 005 has already told
 * every client that []\~ and {}|^ are not equivalent.
 */
#include "federation/link.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/poll_loop.h"
/* Phase 12: the drain in fed_send_shutdown() reads through the transport, so this
 * is the third of the tree's three I/O sites to name it. See the comment on that
 * block for what happens to the node's departure if it did not. */
#include "core/transport.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/departure.h"
/* Phase 9: 2.1's remote-nick registry, swept from fed_tick() because a store
 * whose owner never ticks it never expires anything. */
#include <arpa/inet.h>
#include <netinet/in.h>

#include "federation/nickreg.h"
#include "federation/verbs.h"

/* link_wipe(): split out for #543 into federation/link_config.c, whose
 * fed_close() is its sole caller. */

/* ---------------------------------------------------------------------------
 * Module state, and what it is allowed to hold (issue #173)
 * ---------------------------------------------------------------------------
 * NOTHING PER NODE. The secret, the wrapped dispatch, the four link timers,
 * the three reconnect intervals and the per-reason rejection breakdown all
 * used to be file-static here; they are fields on server_t now, seeded by
 * server_init() and stored by fed_open(), so two nodes in one process keep
 * separate secrets, timers and counters. What remains in this file is
 * stateless: the reason spellings (constant tables) and the pure checks.
 *
 * fed_open() therefore refuses only a SECOND open of the SAME node (which
 * would wrap the wrapper and recurse), and a second node in the same process
 * is an ordinary second caller rather than a diagnosed refusal. */

/* The stable spellings, and the dump keys. One table for both so that the
 * `reason=` on the rejection line and the `rej_*=` on the dump line cannot
 * drift apart, which is the failure a reader hits when they are two lists and
 * one of them has a typo: every count looks plausible and the name beside it
 * is the wrong one.
 *
 * THE INDEX IS THE VERDICT, and the comment on FED_RESULT_COUNT above is the
 * reason that is an invariant rather than a convention: the counter array and
 * this array are both indexed by fed_federate_result_t, so a member added to
 * the enum without a row here is a member whose counter is a neighbour's. The
 * two new rows therefore sit where link.h puts the two new members -- beside
 * the verdicts they belong with, which is FED_NO_SECRET next to the secret and
 * FED_NAME_MISMATCH next to the uniqueness verdicts. */
static const char *const FED_REASON_NAME[FED_RESULT_COUNT] = {
    "OK",         /* FED_OK            */
    "BAD_ARITY",  /* FED_BAD_ARITY     */
    "BAD_SECRET", /* FED_BAD_SECRET    */
    "NO_SECRET",  /* FED_NO_SECRET     */
    "SELF_NAME",  /* FED_SELF_NAME     */
    "NAME_IN_USE",/* FED_NAME_IN_USE   */
    "DUPLICATE_LINK",
    "NAME_MISMATCH",
    "BAD_NAME",   /* FED_BAD_NAME      */
    "BAD_EPOCH",  /* FED_BAD_EPOCH     */
    "BAD_VERSION", /* FED_BAD_VERSION   */
    "TLS_REQUIRED" /* FED_TLS_REQUIRED  */
};

/* The per-reason keys, for the dump. A table rather than ten literals in a
 * printf because fed_federate_reason() is the other half of the same
 * contract -- the `reason=` on a rejection line and the `rej_*=` beside a count
 * on the dump line are the same set of names, and two hand-written lists are
 * two lists that drift. Index FED_OK is an empty string and is never printed:
 * a line that was accepted is not a rejection. */
static const char *const FED_REASON_KEY[FED_RESULT_COUNT] = {
    "", "rej_arity=", "rej_secret=", "rej_nosecret=", "rej_self=",
    "rej_in_use=", "rej_dup=", "rej_mismatch=", "rej_name=", "rej_epoch=",
    "rej_version=", "rej_tls="
};

const char *fed_federate_reason(fed_federate_result_t result)
{
    /* Switched on an int rather than on the enum, and the reason is the
     * -Weverything pair that fanout.c documents: -Wswitch-default wants a
     * `default` on a switch over an enum and -Wcovered-switch-default reports
     * that `default` as redundant when every enumerator is listed, so a switch
     * written both ways cannot satisfy both. Reading the value into an int
     * satisfies both, the cases below are still one per enumerator, and a
     * reason added later lands in the `default` that says it has no name yet
     * rather than falling off the end of the function. */
    int which = (int)result;

    switch (which) {
    case (int)FED_OK:
    case (int)FED_BAD_ARITY:
    case (int)FED_BAD_SECRET:
    case (int)FED_NO_SECRET:
    case (int)FED_SELF_NAME:
    case (int)FED_NAME_IN_USE:
    case (int)FED_DUPLICATE_LINK:
    case (int)FED_NAME_MISMATCH:
    case (int)FED_BAD_NAME:
    case (int)FED_BAD_EPOCH:
    case (int)FED_BAD_VERSION:
    case (int)FED_TLS_REQUIRED:
        break;
    default:
        /* Unreachable while fed_federate_result_t is closed and every member
         * is listed. A BUG REPORT if it is ever reached, so it says so rather
         * than returning a name that does not correspond to anything. */
        printf("[observable] link_reason_unknown: reason=%d\n", which);
        return "UNKNOWN";
    }
    if (which < 0 || which >= FED_RESULT_COUNT) {
        return "UNKNOWN";
    }
    return FED_REASON_NAME[which];
}

/* secret_matches(): split out for #543 into federation/link_guard.c, whose
 * fed_check_federate() is its sole caller. */

/* The observable dump
 * ---------------------------------------------------------------------------
 * Three shapes, deliberately, because they answer three different questions.
 * The headline line says how many peers and how many rejections. The breakdown
 * line says WHICH rejections, and it is a separate line because eight
 * key=value pairs on one line is a line nobody reads the third field of. The
 * per-link lines say the FSM state and the two liveness stamps, which is the
 * split-brain evidence 8 asks for -- a single line per link that also carried
 * the totals would be unreadable past three peers.
 *
 * The reason SPELLINGS and the per-reason keys come from the one pair of
 * tables that fed_federate_reason() and the breakdown read, so the `reason=` on
 * a rejection line and the `rej_*=` beside a count cannot drift apart. That is
 * the failure a reader hits when the two are separate lists and one of them
 * has a typo: every count looks plausible and the name beside it is the wrong
 * one.
 */
static const char *fed_state_name(int state)
{
    /* Read into an int for the same reason fed_federate_reason() does: a
     * handshake_state_t is an enum, and -Weverything's -Wswitch-default and
     * -Wcovered-switch-default cannot both be satisfied by a switch over one. */
    int which = state;

    switch (which) {
    case (int)INIT:
        return "INIT";
    case (int)HANDSHAKE_SENT:
        return "HANDSHAKE_SENT";
    case (int)ESTABLISHED:
        return "ESTABLISHED";
    case (int)FAILED:
        return "FAILED";
    case (int)TIMED_OUT:
        return "TIMED_OUT";
    default:
        return "UNKNOWN";
    }
}

void fed_dump(const server_t *s, const char *why)
{
    uint64_t total_rejected = 0;
    size_t i;
    size_t established = 0;
    size_t links;

    if (s == NULL) {
        return;
    }
    links = server_link_count(s);
    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->state == (int)ESTABLISHED) {
            established++;
        }
    }
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        total_rejected += s->fed_rejected[i];
    }
    /* Why the dump is not gated on s->trace, unlike the per-line trace: a dump
     * is asked for because something is wrong, and the flag that produces the
     * high-volume per-line output is a volume control. The one who needs this
     * line is debugging, and a debug switch that is off in the deployment where
     * the bug reproduces is not a debug switch. */
    printf("[observable] link_dump: why=%s name=%s peers=%zu established=%zu "
           "rejected=%llu\n",
           (why != NULL) ? why : "?", s->name, links, established,
           (unsigned long long)total_rejected);
    /* The breakdown is walked, not listed: eight hand-written key=value pairs
     * would be eight places for a name to be mistyped and eight arguments for a
     * printf, and a loop over the one table cannot disagree with
     * fed_federate_reason(). The total is asserted to agree with the sum here
     * rather than in a test, because a dump whose parts do not add up is worse
     * than no dump -- and the arithmetic is two lines. */
    printf("[observable] link_reject_reasons: ");
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        printf("%s%s%llu", (i > 1u) ? " " : "", FED_REASON_KEY[i],
               (unsigned long long)s->fed_rejected[i]);
    }
    printf("\n");

    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link == NULL) {
            continue;
        }
        /* last_sent and last_recv are the two stamps T3 and T4 compare, and a
         * link dump that does not carry them makes "why did it think the peer
         * was dead" answerable only by reading the other node's log. */
        /* THE RECONNECT SCHEDULE IS ON THIS LINE, and it is here for the reason
         * the other four fields are: an operator reading "why is irc.b not being
         * dialled" needs the retry count, the budget that was spent and the
         * stamp the next attempt is waiting for, and they are all in the same
         * struct as the state they explain. A dump without them would say
         * `state=INIT fd=-1 initiator=1` for a link that is about to be dialled
         * and for one that has given up, and those two need different repairs.
         *
         * gave_up is printed as the COUNT 0/1 rather than as a token because it
         * shares the field with two numbers and a mixed vocabulary on one line
         * is the thing this dump has otherwise been careful to avoid. */
        printf("[observable] link: peer=%s state=%s fd=%d initiator=%d "
               "epoch=%llu last_sent=%llu last_recv=%llu burst_done=%d "
               "retries=%u gave_up=%d retry_at=%llu clean_leave=%d\n",
               link->name, fed_state_name(link->state), link->fd, link->initiator,
               (unsigned long long)link->epoch,
               (unsigned long long)link->last_sent_ms,
               (unsigned long long)link->last_recv_ms, link->burst_done,
               link->retries, link->gave_up,
               (unsigned long long)link->retry_at_ms, link->clean_leave);
    }
    fflush(stdout);
}

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

/* ---------------------------------------------------------------------------
 * The exchange
 * ---------------------------------------------------------------------------
 */

/* Queue this node's FEDERATE on a peer connection.
 *
 * It is built rather than formatted, because FEDERATE is not the S-verb of any
 * client verb and fed_send_sverb() takes a client verb and maps it (verbs.h is
 * explicit that the mapping is applied there so no caller can hand it an
 * already-mapped verb).
 *
 * It is ALSO not fed_queue_line(), and that is now a stated decision rather than
 * the leftover of one: fed_queue_line() stamps a 2.4 block, and a FEDERATE
 * carries none. Its epoch and its secret are PARAMETERS, because 2.4's block is
 * what a receiver needs in order to deduplicate and loop-check a message, and a
 * handshake is neither relayed nor looped -- the only thing that ever has to
 * read this line is the peer's handshake code, which is about to look at every
 * field of it. So this line goes through message_build() and message_format()
 * directly, and the three lines of overlap with fed_queue_line() below are the
 * part that has no block to stamp. The cost of not folding this one in is three
 * lines; the cost of folding it in would be a helper with a "no tags here" mode
 * that its other caller could reach by accident. */
int fed_queue_federate(server_t *s, server_link_t *link, conn_t *c)
{
    const char *params[4];
    char epoch[24];
    char secret[IRC_FED_MAX_SECRET];
    char line[IRC_MAX_LINE + 2];
    message_t m;
    size_t len;

    /* 24 bytes for a uint64_t in decimal: 20 digits at the maximum, plus the
     * NUL. The alternative -- a shared buffer sized by an estimate -- is a
     * truncation of the one field 2.4 exists so that a restarted peer is
     * distinguishable from the one it replaced. */
    (void)snprintf(epoch, sizeof epoch, "%llu", (unsigned long long)s->epoch);
    /* A NODE WITH NO SECRET REFUSES TO SEND A CLAIM, and it says so in its own
     * words rather than letting the claim go out with an empty parameter.
     *
     * The reason is the POLICY, and it is now stated on BOTH sides: an inbound
     * FEDERATE on a node with no configured secret is refused with
     * FED_NO_SECRET (fed_check_federate() step 2, which says so at length), so
     * an outbound claim from the same node would be refused by a correctly
     * configured peer with a reason its operator cannot act on -- "your secret
     * is wrong" for a node that has no secret. The operator of the
     * no-secret node is the one who can fix it, and the line that tells them is
     * the outbound one: this node is the one that cannot authenticate anybody.
     *
     * It is a separate reason and not a reuse of UNRENDERABLE because
     * UNRENDERABLE is a message.c failure -- "this line does not fit or does not
     * parse" -- and an operator reading it would go looking for a formatting bug
     * in a module that is behaving exactly as specified. The two are opposites
     * (a message that cannot be built versus a policy that forbids building it)
     * and they belong to different files. */
    if (s->fed_secret_len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=NO_SECRET "
               "configured=0\n",
               link->name);
        return -1;
    }
    memcpy(secret, s->fed_secret, s->fed_secret_len + 1u);

    params[0] = s->name;                        /* our own claim        */
    params[1] = epoch;                          /* our per-boot epoch   */
    params[2] = secret;                         /* the shared token     */
    params[3] = IRC_SERVE_VERSION;              /* the ONE version copy */

    if (message_build(&m, NULL, s->name, "FEDERATE", params, 4) != 0) {
        printf("[observable] link_send_failed: peer=%s reason=UNBUILDABLE\n",
               link->name);
        return -1;
    }
    /* The +2 is reply.c's arithmetic and the reason is the same: IRC_MAX_LINE
     * counts a legal line INCLUDING its CRLF and message_format() reserves a
     * byte for its NUL. */
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=UNRENDERABLE\n",
               link->name);
        return -1;
    }
    /* RFC 1459 2.3. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, c, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated link is DROPPED, not buffered (3.4). Not counted twice. */
        printf("[observable] link_send_failed: peer=%s reason=LINK_SATURATED\n",
               link->name);
        return -1;
    }
    return 0;
}

/* The accept half (fed_reject/count_reject + fed_link_established + fed_refuse +
 * fed_claim_accepted + fed_on_federate + fed_dispatch_hook) moved verbatim to
 * federation/link_accept.c (issue #543); fed_refuse/fed_on_federate/
 * fed_dispatch_hook stay declared in federation/link.h, and fed_link_new()
 * (defined above) went extern for the claim path that moved with them. */

/* The configuration family (fed_open/fed_close/fed_set_timeouts/fed_hs_due/
 * fed_set_retry, with link_wipe()) moved verbatim to federation/link_config.c
 * (issue #543); all five stay declared in federation/link.h. */

/* The dial/retry/tick half (fed_dial_for/fed_retry_arm/fed_dial_expired/
 * fed_link_promote/fed_send_keepalive/fed_dead/fed_tick) moved verbatim to
 * federation/tick.c (issue #543); it reaches this file's FEDERATE exchange
 * through link.h.
 */
