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

/* The per-reason dump keys (FED_REASON_KEY): split out for #543 into
 * federation/link_dump.c, whose fed_dump() is their sole reader. */

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

/* The observable dump (fed_state_name() + fed_dump(), with the FED_REASON_KEY
 * table): split out for #543 into federation/link_dump.c; fed_dump() stays
 * declared in federation/link.h. */

/* The link table (fed_link_set_state() + fed_link_of_conn() + fed_link_new() +
 * fed_link_set_tls() + fed_link_configure()) moved verbatim to
 * federation/link_table.c (issue #543); all five stay declared in
 * federation/link.h. */

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
