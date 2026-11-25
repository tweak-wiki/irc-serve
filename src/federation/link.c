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

/* The FEDERATE exchange sender (fed_queue_federate()) moved verbatim to
 * federation/link_queue.c (issue #543); it stays declared in
 * federation/link.h. */

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
 * federation/tick.c (issue #543); it reaches link_queue.c's FEDERATE exchange
 * through link.h.
 */
