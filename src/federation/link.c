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

/* The number of members of fed_federate_result_t, and so the width of the
 * per-reason rejection counters. It is a number rather than a compile-time
 * assertion on purpose: -Wpre-c11-compat is in upstream clang's -Weverything
 * and objects to _Static_assert, and this project's answer to a diagnostic it
 * cannot satisfy without narrowing the warning set is never to narrow it (see
 * the warning block in the top-level CMakeLists.txt, and dedup.h for the same
 * argument about a struct size). Every write into the array is bounds-checked
 * against this number, so a reason added to the enum without a counter here is
 * a reason that is counted nowhere rather than a reason that writes past the
 * array -- and the dump prints "?" for it, which is how it gets noticed. */
#define FED_RESULT_COUNT 12

#if FED_RESULT_COUNT != IRC_FED_REJECT_REASONS
#error "link.c's FED_RESULT_COUNT and server.h's IRC_FED_REJECT_REASONS disagree"
#endif
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

static void count_reject(server_t *s, fed_federate_result_t result)
{
    int which = (int)result;

    if (s == NULL) {
        return;
    }
    if (which > 0 && which < FED_RESULT_COUNT) {
        s->fed_rejected[which]++;
    }
}

/* Constant-time secret comparison.
 *
 * The threat is specific and it is the reason this is not strcmp(): a
 * rejection closes the connection, so the TIME at which the close arrives is
 * observable to whoever opened it, and strcmp returns at the first differing
 * byte. That is a prefix oracle -- try a secret a byte at a time and the
 * close latency tells you when you are right -- and it needs no access to this
 * node beyond the ability to open a socket to it.
 *
 * So the diff is accumulated in an unsigned char and the loop runs to the end
 * with no early exit, and the accumulator is what is tested at the end. The
 * casts are explicit because an implicit char-to-unsigned-char conversion is
 * exactly the kind of thing -Wsign-conversion reports, and a diagnostic about
 * a secret comparison is a diagnostic worth having.
 *
 * The LENGTH is compared by the same walk rather than separately: the loop
 * runs to max(la, lb) and reads 0 for the side that has already ended. A C
 * string has no embedded NUL, so the byte past the end of the shorter one is
 * always non-zero on the longer side, and a length difference therefore shows
 * up as a differing byte like any other -- which is why there is no branch on
 * the lengths and no separate length term to fold in. */
static int secret_matches(const char *configured, const char *offered)
{
    size_t la;
    size_t lb;
    size_t n;
    size_t i;
    unsigned char diff = 0;

    if (configured == NULL || offered == NULL) {
        return 0;
    }
    la = strlen(configured);
    lb = strlen(offered);
    n = (la > lb) ? la : lb;
    for (i = 0; i < n; i++) {
        unsigned char a = (i < la) ? (unsigned char)configured[i] : (unsigned char)0;
        unsigned char b = (i < lb) ? (unsigned char)offered[i] : (unsigned char)0;

        diff |= (unsigned char)(a ^ b);
    }
    return (diff == 0u) ? 1 : 0;
}

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
static server_link_t *fed_link_new(server_t *s, const char *name, int initiator)
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

/* The whole of a rejection, in three steps and always in this order.
 *
 *   (a) print. NOT gated on s->trace, and the reason is the one this project
 *       uses for every refusal: a rejected handshake is a bug report or an
 *       attack, and a flag that can silence a bug report is not a flag that
 *       should be able to silence a bug report. The volume argument that
 *       justifies the per-line trace does not apply to a line that appears
 *       once per rejected connection.
 *   (b) FAILED, so the state records that this exchange ended wrongly.
 *       A link whose state still said HANDSHAKE_SENT after its connection is
 *       gone would sit in T2 until the timeout fired and would report a
 *       handshake timeout for something that was rejected in the first
 *       millisecond.
 *   (c) conn_mark_closing() and NEVER close(). 3.4 puts the close at one fixed
 *       point in the loop, and a second close path in a file that owns peer
 *       links is precisely how a descriptor gets closed twice. */
static void fed_reject(server_t *s, server_link_t *link, conn_t *c,
                       fed_federate_result_t result, const char *claim)
{
    const char *peer = (link != NULL) ? link->name : claim;

    printf("[observable] link_rejected: peer=%s reason=%s fd=%d\n",
           (peer != NULL && peer[0] != '\0') ? peer : "?",
           fed_federate_reason(result), (c != NULL) ? c->fd : -1);
    /* Counted whether or not there is a link to fail. An inbound claim that
     * arrives on the listener has no link yet -- that is the ordinary accepting
     * case -- and counting only the ones that did have one would make the
     * headline number report the minority and the per-reason breakdown report
     * everything, which is the kind of pair that reads as a bug in the other
     * module. */
    if (s != NULL) {
        s->n_link_rejected++;
        if (result == FED_DUPLICATE_LINK) {
            s->n_link_duplicate++;
        }
    }
    if (link != NULL && (link->state == (int)HANDSHAKE_SENT ||
                         link->state == (int)ESTABLISHED)) {
        fed_link_set_state(link, FAILED);
    }
    if (c != NULL) {
        conn_mark_closing(c);
    }
    count_reject(s, result);
    fed_dump(s, "rejected");
}

/* A link that has earned its place: the descriptor, the peer's epoch, and the
 * FSM. Split out of fed_federate_inbound() because both the accepting side and
 * the dialling side's promotion end here, and 2.3 wants them to be the same
 * transition. */
static void fed_link_established(server_t *s, server_link_t *link, conn_t *c,
                                 const char *claim, uint64_t peer_epoch)
{
    link->fd = c->fd;
    link->epoch = peer_epoch;
    /* The liveness stamps start now rather than at configuration: before this
     * point the link has no peer that could be alive or dead, and a stamp from
     * configuration time would make a slow handshake look like a silent one the
     * moment it completed. */
    link->last_sent_ms = server_now_ms();
    link->last_recv_ms = link->last_sent_ms;
    /* 2.3: a peer connection is exempt from the client registration state
     * machine. Changing `kind` here is what takes it out: reply.c refuses a
     * CONN_SERVER destination, so a numeric can no longer be written to this
     * connection even by a path that does not know it is a peer.
     *
     * peer_name stays a display copy and a NULL one if the allocation fails.
     * Nothing routes by it (core/server.h is explicit that the link is the
     * authority), so a missing copy costs a diagnostic field and no routing. */
    c->kind = CONN_SERVER;
    /* #540: the flood bucket was sized for a client when this connection's
     * first refill ran. Promote it to the peer cap now or the burst below
     * trips the limiter and the link flaps. */
    conn_flood_peer_promoted(c);
    if (c->peer_name == NULL) {
        char *copy = (char *)malloc(strlen(claim) + 1u);

        if (copy != NULL) {
            memcpy(copy, claim, strlen(claim) + 1u);
            c->peer_name = copy;
        }
    }
    /* THE BUDGET IS REFILLED HERE, and it is here rather than at the end of the
     * function for the same reason federation_resync() is below it: a link that
     * has just come up is a link that should be dialled AGAIN without waiting,
     * and a link that came up after a backoff still has that backoff's stamp on
     * it. Leaving it would mean a link that recovered keeps waiting out a
     * schedule earned for a failure it has already fixed.
     *
     * `retries` goes to 0 rather than being decremented, and the difference
     * matters: it is what makes the budget a budget of CONSECUTIVE failures
     * rather than a lifetime cap on a link, so a peer that flaps is retried
     * indefinitely (one fresh budget per success) while a peer that is simply
     * dead is not. `gave_up` is cleared for the same reason, and it is cleared
     * HERE rather than only in fed_link_reset() because a link cannot reach
     * ESTABLISHED without coming through this function -- so a link whose budget
     * ran out and which then succeeded has, by the fact of its success, been
     * fixed, and holding the give-up against it would be holding it against the
     * evidence. */
    link->retries = 0u;
    link->gave_up = 0;
    link->retry_at_ms = 0u;
    printf("[observable] link_established: peer=%s fd=%d initiator=%d "
           "epoch=%llu\n",
           link->name, link->fd, link->initiator,
           (unsigned long long)link->epoch);
    fed_dump(s, "established");
    /* THE RESYNC, and it goes HERE rather than in either of the two paths that
     * reach this function, because 2.3 wants the accepting side and the dialling
     * side's promotion to be the same transition and 4.3's "on every link
     * establishment" has to be true of both of them. A call in the accept path
     * only would be the INITIATOR's burst, which is 4.3's literal wording and is
     * not sufficient: a node only forwards to peers that already hold the
     * chan_t, so in a two-node fixture the RESPONDER's channels would never reach
     * the initiator, a user there would be invisible to the initiator for ever,
     * and 7/Phase 6's full-353 criterion would fail on one of the two nodes.
     *
     * BOTH SIDES BURSTING IS A DELIBERATE SUPERSET of the doc's sentence "the
     * initiator sends full state", and it costs one extra burst per link. What it
     * buys is that "on every link establishment" means what a reader of 4.3 would
     * expect it to mean, and that neither node's view of the other depends on
     * which of the two happened to dial. The asymmetry the doc describes is
     * real -- the initiator does have to send its state or the other node learns
     * nothing -- but it is a statement about the MINIMUM, and a minimum is not a
     * rule about what the responder may do.
     *
     * ONE ORDERING CONSTRAINT, and it is the reason this is not at the top of
     * the function: the burst needs the link's descriptor and the peer's epoch,
     * so it has to be after both are set. It does NOT wait for the peer's own
     * burst, and cannot: neither side is going to block on the other, so the two
     * transactions cross on the wire and each is applied on arrival. There is no
     * ordering to agree on because neither transaction depends on the other -- a
     * burst is a statement about the sender, and the sender's state does not
     * change because somebody received it. */
    (void)federation_resync(s, link);
    /* AND IT ADVERTISES ITSELF, ONCE, HERE. The first ADVERTISE has to go out on
     * ESTABLISHMENT and not on the first interval tick, because a peer that has
     * just arrived is the one peer that most needs to be told what this node looks
     * like -- and because a test with a short interval and a long dial would
     * otherwise have to wait out the interval to see the first one. Everything
     * after this is a refresh, driven from fed_tick() at
     * s->fed_advertise_ms. */
    (void)fed_send_advertise(s);
    s->advert_sent_ms = server_now_ms();
}

fed_federate_result_t fed_check_federate(const server_t *s,
                                         const server_link_t *self,
                                         const message_t *m, const char *secret,
                                         uint64_t *peer_epoch_out)
{
    const char *claim;
    uint64_t peer_epoch = 0;
    size_t i;

    if (s == NULL || m == NULL) {
        return FED_BAD_ARITY;
    }

    /* --- 1. shape ------------------------------------------------------- */
    /* A FEDERATE names the sender twice: once as the prefix and once as the
     * first parameter. The PARAMETER is the authority, and the prefix is
     * required to be present because a line that does not say who sent it is
     * not a handshake. They are deliberately not cross-checked against each
     * other here: the inbound prefix rules are fed_dispatch()'s, and a second
     * opinion about them in the link module is a second opinion somebody can
     * have. Until C3 exists, a peer whose prefix disagrees with its claim is
     * one the shape check accepts and the claim check then applies -- which is
     * the right way round, because the claim is the name that would have to be
     * unique. */
    if (m->nparams != 4 || m->prefix == NULL) {
        return FED_BAD_ARITY;
    }
    claim = m->params[0];
    if (claim == NULL || strlen(claim) > (size_t)IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(claim)) {
        return FED_BAD_NAME;
    }
    /* 2.4's epoch grammar, enforced by the shared overflow-safe
     * parse_decimal: 1..20 digits, no leading zero, <= UINT64_MAX. */
    if (m->params[1] == NULL ||
        parse_decimal(m->params[1], strlen(m->params[1]), UINT64_MAX,
                      &peer_epoch) != 0) {
        return FED_BAD_EPOCH;
    }
    if (strcmp(m->params[3], IRC_SERVE_VERSION) != 0) {
        return FED_BAD_VERSION;
    }

    /* --- 2. the secret -------------------------------------------------- */
    /* Before the identity checks, so that a node which is not allowed to be
     * here learns nothing about this node's name space. */
    /* AN EMPTY CONFIGURED SECRET REFUSES, AND THAT IS THE POLICY.
     *
     * `irc-serve 6667` has no --secret, so the secret is "", and the constant-
     * time compare below answers ACCEPT for an offered "" because two empty
     * strings are equal. On a default-configured node that made the secret step
     * a step nobody could fail: the ONLY thing standing between anyone who can
     * reach the TCP port and a peer link under a name of their choosing was an
     * equality between two empty strings.
     *
     * AN HONEST WORD ON HOW REACHABLE THAT WAS, because the difference matters
     * to whoever reads this later. An empty parameter cannot be put on the wire
     * in a non-final position by this node's parser: core/message.c skips an
     * empty token rather than counting it, and a `:` parameter swallows the rest
     * of the line. So `:x FEDERATE n 1 "" irc-serve-0.1.0` arrives with the
     * secret parameter set to the two characters quote-quote, and the line
     * `:x FEDERATE n 1 : irc-serve-0.1.0` arrives as three parameters and is
     * refused as BAD_ARITY. Checked against the shipped binary, not inferred.
     * The empty-vs-empty accept was therefore LATENT rather than open: what
     * stood between a default-configured node and a stranger was a parser rule
     * in a module that knows nothing about peers, not a check in this path.
     * A change to a parameter rule in core/message.c -- which is a
     * one-line-shaped change and is the kind this tree makes -- would have opened
     * it, and nothing in the link path would have said so. This check is the
     * link path's own answer, and it holds whatever a parser does with an empty
     * parameter.
     *
     * The alternative -- treating "no secret" as "no authentication" -- was
     * what the default used to mean, and it is not what an operator who reads
     * `secret=none` on the startup line is being told. Federation here is
     * OPT-IN: a node federates because it was given a secret, so a node with no
     * secret is a node that federates with nobody, and it says so on the wire
     * with a verdict of its own rather than folding the case into BAD_SECRET.
     * An operator reading `reason=` has to be able to tell "somebody guessed
     * wrong" from "this node is not configured to federate", because the fixes
     * are opposites: the first is a credential under attack, the second is a
     * missing --secret. BAD_SECRET on a node whose secret is empty would also be
     * a lie in the other direction -- it would say the offered value was wrong
     * when the truth is that no value is right.
     *
     * BEFORE secret_matches(), and deliberately so. secret_matches() is a
     * correct constant-time compare and stays one, unchanged; what it cannot do
     * is express a policy, and "is authentication switched on at all" is a
     * policy rather than an equality.
     *
     * It does not break backward compatibility, which is the thing that made it
     * look hard. `irc-serve 6667` still starts, binds, serves clients and
     * prints the same lines: the CLIENT surface is untouched, and this check is
     * reached only by a FEDERATE, a peer handshake that did not exist before
     * Phase 6 and therefore cannot be something a working deployment depended
     * on.
     *
     * The cost, stated exactly, and it is SMALLER than the argument above first
     * suggests: a node with no secret could not federate anyway, in either
     * direction. Its own claim never left the node -- fed_queue_federate()
     * renders a FEDERATE whose third parameter is the secret, and
     * message_format() refuses a parameter the wire cannot represent in a
     * non-final position, which an empty one is -- so a default-configured node
     * dialling a peer reports `link_send_failed: reason=UNRENDERABLE` and sends
     * nothing at all. Both of those were checked against the shipped binary,
     * not inferred. So there is no working all-`--secret`-less mesh for this to
     * break; what changes is that the INBOUND refusal now exists, is named, and
     * is counted, instead of depending on a parser in core/message.c to keep
     * an empty parameter off the wire.
     *
     * The one behaviour a deployment could notice is the one the policy is
     * ABOUT: a node with a --secret and a node without one can no longer link
     * to each other, which is correct, because one of them is not authenticating
     * anybody. The remaining cost is a diagnostic that used to say
     * UNRENDERABLE where it means "you gave me no secret", and that is a
     * follow-up on the OUTBOUND side of fed_queue_federate() rather than
     * something this check can fix. */
    if (secret == NULL || secret[0] == '\0') {
        return FED_NO_SECRET;
    }
    if (!secret_matches(secret, m->params[2])) {
        return FED_BAD_SECRET;
    }

    /* --- 3. not our own name -------------------------------------------- */
    if (irc_ascii_same(claim, s->name)) {
        return FED_SELF_NAME;
    }

    /* --- 4. uniqueness -------------------------------------------------- */
    /* The link this exchange is ON is skipped: it is not a rival claim on the
     * name it is handshaking about, and a dialling node has held one since the
     * moment the peer was configured. Every OTHER link with this name is a
     * rival, and the difference between the two verdicts is the whole of 2.3's
     * rule: a link that is ESTABLISHED is a live route to that name, and
     * admitting a second one is the split brain; a link that HOLDS A DESCRIPTOR
     * but is not established is a half-open exchange for the same name, and
     * admitting a second one would put two descriptors on one identity.
     *
     * AND A LINK WITH NO DESCRIPTOR IS NEITHER. That clause is the correction,
     * and it was missing until a re-link was tested: a link in INIT with fd == -1
     * is a NAME and a DESTINATION, not a claim on the name. It is what fed_dead()
     * leaves behind -- the peer went away, the descriptor is closed, the name is
     * kept so that T7 can dial it again and so that 2.2's fail-closed rule has an
     * origin to be unreachable FROM. Refusing a peer's re-claim because such a
     * link exists made 2.2's "re-linking a server of the same name resurrects the
     * channel" UNREACHABLE: the peer re-dialled, was told the name was in use by
     * a link that had no socket on it, and the mesh could never recover from a
     * partition without an operator deleting configuration.
     *
     * THE COST, and it is the reason this is about the DESCRIPTOR and not about
     * the state: a node can now hold at most one link per name whose fd is >= 0
     * and any number whose fd is -1, and only the first kind is a claim. A link
     * that is FAILED or TIMED_OUT WITH A DESCRIPTOR still holds one -- T2 leaves
     * the descriptor alone on purpose -- so a peer re-dialling into that state is
     * still refused with NAME_IN_USE, and clearing it is fed_link_reset()'s job.
     * That asymmetry is left as it is rather than papered over: it is the same
     * asymmetry link.h draws between a link that was established and went away
     * (resettable, because there is something to stop believing in) and one that
     * never completed (terminal, because there was never anything to believe). */
    for (i = 0; i < server_link_count(s); i++) {
        const server_link_t *other = server_link_at(s, i);

        if (other == NULL || other == self || !irc_ascii_same(other->name, claim)) {
            continue;
        }
        if (other->state == (int)ESTABLISHED) {
            return FED_DUPLICATE_LINK;
        }
        if (other->fd >= 0) {
            return FED_NAME_IN_USE;
        }
    }
    /* And the same answer reached through the function every router uses. It
     * is redundant with the scan above by construction, and it is here anyway:
     * server_find_peer() is the ESTABLISHED-narrowed predicate, so if the two
     * ever disagreed about what counts as established this would reject rather
     * than admit a second route to a name the node can already reach. */
    if (server_find_peer(s, claim) != NULL) {
        return FED_DUPLICATE_LINK;
    }
    /* A connection already on a link, presenting a DIFFERENT name.
     *
     * This had no verdict of its own and answered FED_DUPLICATE_LINK, which was
     * wrong and is retracted here: a node dialled a peer under one name and the
     * peer announced another is a MISCONFIGURATION -- one side's --peer or
     * --name disagrees with the other side's --name -- and not a split brain.
     * The two have opposite fixes and different shapes of aftermath, and
     * reporting a name disagreement as a duplicate route is exactly the
     * overloading this verdict was supposed to prevent. Split brain has its own
     * verdict above, and it is the one that increments n_link_duplicate.
     *
     * The rejection itself is unchanged and for the same reason as every other
     * rejection: a link has exactly one name (the table is keyed on it), so a
     * second identity presented on one socket cannot be adopted, and accepting
     * it would leave this node with a route whose name is not the one the
     * handshake was checked against. The line is closed, counted and dumped
     * like any other, under a name that says what happened. */
    if (self != NULL && !irc_ascii_same(self->name, claim)) {
        return FED_NAME_MISMATCH;
    }
    /* Only on the accepted path, and the out-parameter is why: the epoch is
     * parsed in the shape check because that is where the grammar belongs, and
     * the caller needs it to stamp the link. Returning it only on FED_OK means
     * a caller that ignores a verdict never has a half-validated epoch to
     * write onto a link, which is the one way this out-parameter could be
     * misused. A NULL out-parameter is fine -- it is optional. */
    if (peer_epoch_out != NULL) {
        *peer_epoch_out = peer_epoch;
    }
    return FED_OK;
}

/* A refusal that is NOT a verdict on the peer's line, and therefore is not
 * counted and does not appear in the per-reason breakdown.
 *
 * There are two of them, and both are this node's problem rather than the
 * peer's: the node could not make room for another link, and a transition the
 * FSM refused. A breakdown that mixed protocol verdicts with local failures
 * would not add up against n_link_rejected, and reporting an internal mistake
 * as BAD_ARITY -- which is what the first version of this file did -- is a lie
 * told to whoever reads the log: it names a malformed handshake where the truth
 * is a node that could not move its own state machine.
 *
 * Both still print, because a refusal nobody can see is a bug nobody reports,
 * and both still close through conn_mark_closing() and never close the
 * descriptor, because that part is 3.4 and does not depend on why. */
void fed_refuse(server_t *s, server_link_t *link, conn_t *c,
                       const char *claim, const char *why)
{
    (void)s;

    printf("[observable] link_refused: peer=%s reason=%s fd=%d\n",
           (link != NULL) ? link->name : claim, why, (c != NULL) ? c->fd : -1);
    if (c != NULL) {
        conn_mark_closing(c);
    }
}

/* An accepted claim, on either side. Creates the link if the connection
 * arrived on the listener, then runs INIT -> HANDSHAKE_SENT -> ESTABLISHED.
 *
 * On the ACCEPTING side both transitions happen here, in one step: the peer
 * has already proved itself, and waiting for our own claim to come back before
 * treating the link as a route would put establishment behind a peer's
 * scheduling for no security gain -- our claim is queued, and the peer's
 * silence is then its own T2 to discover.
 *
 * On the DIALLING side the link is already in HANDSHAKE_SENT -- this is the
 * peer's answer to the claim fed_link_promote() sent -- so only the second
 * transition applies. That is why the send below is conditional
 * rather than unconditional: the FSM has no HANDSHAKE_SENT -> HANDSHAKE_SENT
 * edge, and taking it anyway would be the dialling node rejecting the peer
 * that answered it correctly. */
static int fed_claim_accepted(server_t *s, server_link_t *link, conn_t *c,
                              const char *claim, uint64_t peer_epoch)
{
    if (link == NULL) {
        /* A RE-CLAIM FROM A PEER WHOSE LINK WENT AWAY REUSES THE LINK, and this
         * is the second half of the correction in fed_check_federate() step 4.
         * That check now admits a claim for a name this node still holds a link
         * for, and the link is a NAME and a DESTINATION rather than a rival
         * claim -- so the claim has to be applied to IT. Creating a second link
         * for the same name instead would leave two entries in the table for
         * one server, and the second one is a duplicate every uniqueness check
         * from then on has to think about.
         *
         * WHY IT IS SAFE, which is the part that has to be argued rather than
         * assumed: fed_check_federate() has already returned FED_OK, and that
         * now means no ESTABLISHED link and no link holding a descriptor claims
         * this name. So whatever is found here holds no socket, and taking it
         * over cannot displace a live route. It also cannot disturb the
         * dialling side, which finds its link by descriptor in
         * fed_link_of_conn() and never reaches this branch. */
        link = server_find_link(s, claim);
    }
    if (link == NULL) {
        link = fed_link_new(s, claim, 0);
        if (link == NULL) {
            fed_refuse(s, NULL, c, claim, "NO_LINK_ROOM");
            return -1;
        }
    }
    if (link->state == (int)ESTABLISHED) {
        /* The same link, naming itself again. A peer that re-sends its FEDERATE
         * on an already-established link is a bug on its side, and answering it
         * by re-authenticating would let anything that had once learned the
         * secret re-run the exchange forever. Nothing to do. */
        return 0;
    }
    if (link->state == (int)INIT) {
        fed_link_set_state(link, HANDSHAKE_SENT);
        /* created_ms is stamped here as well as at the dial. The dial stamp is
         * what makes the latch; this one is what makes the field mean "when
         * this link's current attempt began", and it is what 3.4's file map
         * describes. */
        link->created_ms = server_now_ms();
        (void)fed_queue_federate(s, link, c);
    } else if (link->state != (int)HANDSHAKE_SENT) {
        /* The link is FAILED or TIMED_OUT -- a terminal state, with the
         * exchange that put it there long since closed. Reached only if
         * something reuses a link that is still in a terminal state, and the
         * correct response is to refuse the connection rather than to drag the
         * FSM backwards: fed_link_reset() is the only reset, and it takes the
         * link back to INIT through fed_link_down(). */
        fed_refuse(s, link, c, claim, "LINK_TERMINAL");
        return -1;
    }
    /* HANDSHAKE_SENT -> ESTABLISHED, on both sides: the accepting side sent
     * its claim above (or already had), the dialling side is answering the
     * claim fed_link_promote() sent. Every FSM transition in this file goes
     * through fed_link_set_state() and no transition goes around it. */
    fed_link_set_state(link, ESTABLISHED);
    fed_link_established(s, link, c, claim, peer_epoch);
    return 0;
}

/* ---------------------------------------------------------------------------
 * The dispatch seam
 * ---------------------------------------------------------------------------
 */

/* Everything the module does about an inbound line. Three cases, in order:
 *
 *   1. FEDERATE -- the only verb this phase gives a peer connection, and the
 *      only one that may make a link. Claimed on ANY connection, not only on
 *      one that is already a link, because an inbound peer arrives on the
 *      listener as an ordinary connection: the accept site has no way to know
 *      it is a peer until it says so, and 2.3 makes the handshake -- not the
 *      accept -- the place a peer is identified. A client that types FEDERATE
 *      is refused by the same checks, which is the documented cost of a peer
 *      handshake being the only way in: the verb is internal (4.3) and a
 *      client has no business sending it.
 *   2. A line on a link that already exists. The stamp is the liveness signal
 *      and the line goes to fed_dispatch(), which reads the 2.4 tags, applies
 *      the hop ceiling and dispatches the verb. It goes through the CLIENT
 *      dispatch to get there -- commands_dispatch() sees src->kind and calls
 *      fed_dispatch() -- because 3's diagram says the peer path is the same
 *      dispatch and that dispatch never asks "is this local or remote?". Two
 *      doors into the guard chain is one too many, and the chain is the only
 *      place 2.4 is enforced.
 *   3. Anything else -- an ordinary client line. Untouched, and handed to the
 *      dispatch that was installed before fed_open(). */
void fed_on_federate(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *self = fed_link_of_conn(s, c);
    uint64_t peer_epoch = 0;
    fed_federate_result_t result;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    /* A FEDERATE in cleartext for a peer this node requires TLS for
     * (issue #221): the line carries the shared secret, so honoring it
     * would both trust a sniffable credential and establish the cleartext
     * link the operator said must be TLS. Refused BEFORE the secret is
     * compared, so the exchange answers nothing about it, and before any
     * link state moves. A plaintext FEDERATE for a peer with no such
     * requirement is untouched, which is what keeps a plaintext mesh
     * working exactly as before. */
    if (transport_is_tls(c) == 0 && m->nparams >= 1 && m->params[0] != NULL) {
        const server_link_t *claimed = server_find_link(s, m->params[0]);

        if (claimed != NULL && claimed->require_tls != 0) {
            fed_reject(s, self, c, FED_TLS_REQUIRED, m->params[0]);
            return;
        }
    }
    result = fed_check_federate(s, self, m, s->fed_secret, &peer_epoch);
    if (result != FED_OK) {
        fed_reject(s, self, c, result, m->params[0]);
        return;
    }
    (void)fed_claim_accepted(s, self, c, m->params[0], peer_epoch);
}

void fed_dispatch_hook(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *link;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* Answered HERE and not by the guard chain's G2, for one reason: at this
         * point the connection is still a CLIENT connection -- fed_link_established()
         * is what sets c->kind to CONN_SERVER -- so commands_dispatch()'s peer
         * branch has not been reached yet and there is nothing to hand the line
         * to. fed_dispatch()'s G2 calls this same function, so a FEDERATE that
         * arrives on an ALREADY-established link goes through both paths and is
         * answered identically: on such a link it is a re-claim, and
         * fed_check_federate() reports DUPLICATE_LINK or NAME_MISMATCH for it. */
        fed_on_federate(s, c, m);
        return;
    }

    link = fed_link_of_conn(s, c);
    if (link == NULL) {
        if (s->fed_inner != NULL) {
            s->fed_inner(s, c, m);
        }
        return;
    }
    /* A received line IS the liveness signal. Stamped HERE and not in
     * core/poll_loop.c so that the loop stays free of any peer concept; see the
     * header. */
    link->last_recv_ms = server_now_ms();
    /* Handed to the client dispatch, which routes a CONN_SERVER connection to
     * fed_dispatch(). THAT IS THE WHO OF IT, and it is one path rather than two:
     * section 3's diagram puts the peer read and the client read through the
     * same dispatch and says dispatch never asks "is this local or remote?" --
     * the only difference is src->kind. Routing from here straight into
     * fed_dispatch() would be a SECOND entry into the peer protocol, and the
     * guards would then have two doors. A line that reaches the client dispatch
     * and is not a peer line falls through to the client verb table, where
     * every S-verb is an unknown command -- which is the correct answer and is
     * counted, not the reason this routing exists. */
    if (s->fed_inner != NULL) {
        s->fed_inner(s, c, m);
    }
}

/* The configuration family (fed_open/fed_close/fed_set_timeouts/fed_hs_due/
 * fed_set_retry, with link_wipe()) moved verbatim to federation/link_config.c
 * (issue #543); all five stay declared in federation/link.h. */

/* The dial/retry/tick half (fed_dial_for/fed_retry_arm/fed_dial_expired/
 * fed_link_promote/fed_send_keepalive/fed_dead/fed_tick) moved verbatim to
 * federation/tick.c (issue #543); it reaches this file's FEDERATE exchange
 * through link.h.
 */
