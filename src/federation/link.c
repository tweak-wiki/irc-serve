/* link.c -- see link.h. The link lifecycle and the FEDERATE exchange.
 *
 * Fully split for #543 (last family: FED_REASON_NAME + fed_federate_reason()
 * -> federation/link_dump.c, TU-41); this file now holds only the split map.
 * The open/close family lives in federation/link_config.c, the admission
 * guard in federation/link_guard.c, the accept half in
 * federation/link_accept.c, the observable dump and reason spellings in
 * federation/link_dump.c, the link table in federation/link_table.c, the
 * FEDERATE sender in federation/link_queue.c, and the dial/retry/tick half
 * in federation/tick.c.
 *
 * Server-name comparison is message.h's irc_ascii_same() (issue #181): a server
 * name is case-insensitive (2.1, RFC 1459 2.3.2), so `IRC.A` and `irc.a` are
 * one server. ASCII-only, for the reason dedup.c gives: 005 has already told
 * every client that []\~ and {}|^ are not equivalent.
 */
#include "federation/link.h"


/* link_wipe(): split out for #543 into federation/link_config.c, whose
 * fed_close() is its sole caller. */

/* Module state, and what it is allowed to hold (issue #173): NOTHING PER NODE.
 * The secret, the wrapped dispatch, the four link timers, the three reconnect
 * intervals and the per-reason rejection breakdown all used to be file-static
 * here; they are fields on server_t now, seeded by server_init() and stored by
 * fed_open(), so two nodes in one process keep separate secrets, timers and
 * counters. fed_open() therefore refuses only a SECOND open of the SAME node
 * (which would wrap the wrapper and recurse), and a second node in the same
 * process is an ordinary second caller rather than a diagnosed refusal. */

/* The stable spellings (FED_REASON_NAME) + fed_federate_reason(): split out for
 * #543 into federation/link_dump.c, beside the FED_REASON_KEY table that reads
 * alongside them; fed_federate_reason() stays declared in federation/link.h. */

/* secret_matches(): split out for #543 into federation/link_guard.c, whose
 * fed_check_federate() is its sole caller. */

/* The observable dump (FED_REASON_KEY + fed_state_name() + fed_dump()): split
 * out for #543 into federation/link_dump.c; fed_dump() stays declared in
 * federation/link.h. */

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
 * (now in link_table.c) went extern for the claim path that moved with them. */

/* The configuration family (fed_open/fed_close/fed_set_timeouts/fed_hs_due/
 * fed_set_retry, with link_wipe()) moved verbatim to federation/link_config.c
 * (issue #543); all five stay declared in federation/link.h. */

/* The dial/retry/tick half (fed_dial_for/fed_retry_arm/fed_dial_expired/
 * fed_link_promote/fed_send_keepalive/fed_dead/fed_tick) moved verbatim to
 * federation/tick.c (issue #543); it reaches link_queue.c's FEDERATE exchange
 * through link.h.
 */
