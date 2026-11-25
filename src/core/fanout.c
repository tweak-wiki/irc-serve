/* fanout.c -- see fanout.h. The 3.1 routing table, written down once.
 *
 * ---------------------------------------------------------------------------
 * THE TABLE, AND WHERE EACH ROW GOES
 * ---------------------------------------------------------------------------
 * 3.1 verbatim, with the single-node reachability of each row marked honestly
 * (fanout.h has the same table in prose):
 *
 *   local user            | either          | write to conn_t
 *   owned channel         | message         | write to each local member AND forward to
 *   owned channel         | state-change    | servers[] UNION the ESTABLISHED links
 *   non-owned channel     | message         | write to local members AND forward to owner
 *   non-owned channel     | state-change    | FORWARD ONLY -- never a local write
 *   remote user           | either          | forward to that server
 *
 * The two rows that are "forward only" and "write AND forward" are the ones
 * 3.1 exists to separate, and they are separated here by the class and by
 * nothing else. A node with local members in a channel it does not own still
 * WRITES for a message and still does NOT WRITE for a state change; that is the
 * whole content of the table, and it is decided in one switch so no handler can
 * be right while its sibling is wrong.
 *
 * THE OWNED/`message` ROW IS THE AMENDED ONE and it used to say "no forward",
 * because "the origin already holds every member". The reason was false: the
 * origin holds those members in a roster, and a roster entry is not a delivery
 * path. The two owned rows are now the same row, and the correction -- with the
 * cost and the loop it creates -- is at forward_channel_targets() below, which
 * is where the target set is actually decided. Read it there before changing the
 * line above; the table is transcribed from 3.1 and 3.1 carries the amendment.
 *
 * ---------------------------------------------------------------------------
 * THE FORWARD IS AN EXPLICIT REFUSAL, NOT A SILENT DROP
 * ---------------------------------------------------------------------------
 * fanout_forward_link() reports every refusal on the observable output, naming
 * the peer it wanted and the reason it could not reach it, rather than returning
 * quietly: a federated node that lost a message with no trace would look exactly
 * like a node whose peers were silent, and the two have opposite fixes. The
 * local leg of a non-owned `message` still happens first, because 3.1 says it
 * does and because a message is not state -- see fanout.h on the verb class.
 *
 * ---------------------------------------------------------------------------
 * carry, AND WHO PASSES ONE
 * ---------------------------------------------------------------------------
 * Three call sites, all of which pass NULL, and one that passes a real stamp: the
 * three are the local fan-out of a client's own action, where this node is
 * ORIGINATING, and the fourth is federation/verbs.c relaying a line it received
 * -- and it does that by handing its tags to fanout_deliver() rather than by
 * forwarding the line itself, because a relay that both fanned the line out and
 * forwarded it would forward every received `message` twice, once with a fresh
 * id. See fanout.h on the argument.
 * The stamp is minted where the identity is decided -- here, at the
 * forward, for the originating case -- and carried where the message already
 * has one, because a restamp would give a relayed copy an identity the far
 * side's dedup store has never seen, which is the loop. See fanout.h.
 *
 * ---------------------------------------------------------------------------
 * AND WHERE THE `account` TAG IS STAMPED, WHICH IS THE SAME QUESTION
 * ---------------------------------------------------------------------------
 * 2.4's (origin, epoch, id) and IRCv3's `account` are both properties of ONE
 * EMISSION, and both are resolved at the single point above the switch in
 * fanout_deliver(): `ident` by fanout_stamp(), and the account by
 * fanout_emitter_account() beside it. Neither is asked again per destination --
 * only the DECISION to render it is per destination, in fanout_tag_block().
 *
 * WHY PER-FORWARD-TARGET RESOLUTION WOULD BE A BUG RATHER THAN A WASTE. The
 * tempting wrong shape is to resolve the sender at each destination, which asks
 * "whoever is at the other end" rather than "who sent this". On the local leg the
 * two happen to agree, so the node looks correct; then a relayed SPRIVMSG -- prefix
 * `:bob@irc.b`, no local connection by that name -- resolves to nothing and the tag
 * silently disappears for exactly the messages whose sender identity is in
 * question. The value has to come from the ONE place that knows who sent it, and
 * there is one such place: fanout_deliver(), above the switch, where `ident`
 * already lives.
 */
#include "core/fanout.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* Resolution family (mask match, nick lookup, target resolve, membership):
 * split out for #543 into core/fanout_resolve.c; the forward leg
 * (forward_one_peer/forward_channel_targets + the fanout_forward_* entry
 * points) is split out into core/fanout_forward.c; the delivery leg
 * (emission helpers + write_to_members + the fanout_deliver_* entry points)
 * is split out into core/fanout_deliver.c. Cap and stamp stay here. */
#include "core/fanout_resolve.h"
#include "core/fanout_forward.h"


/* The worst-case client-visible tag block is FANOUT_TAG_BLOCK_MAX, and it now lives
 * in fanout.h rather than here: Phase 10.12's `batch=` tag is prepended to a block
 * THIS file renders, by reply.c, so the two modules have to agree on how wide one is
 * and the only way to arrange that is one declaration both can see. The derivation and
 * the argument for deriving it are at the definition. */

/* ---------------------------------------------------------------------------
 * 3.2's client-facing cap
 * ---------------------------------------------------------------------------
 * A relayed line is the client's own line PLUS the 2.4 internal tag block, so a
 * message this node accepted inbound can still be too long to send to anybody.
 * The bound is applied HERE, on the message text, rather than being discovered
 * by message_format() failing inside reply(): a render failure there is a
 * refusal counted on n_reply_refused, which reply.c documents as a bug report
 * and not a metric. A client that sent a long message is not a bug, it is a
 * limit, and a limit answers with a numeric.
 *
 * The number subtracted is 3.2's IRC_MAX_RELAY_LINE, and it is subtracted from the
 * FULL line rather than from the message alone. Two reasons that is the
 * conservative direction:
 *
 *   - the tag block is added on the relay path, which is Phase 6, so a message
 *     delivered locally now and forwarded later must be sized for the LARGER of
 *     the two. Sizing for today would mean a message this node happily delivers
 *     in Phase 5 becoming undeliverable in Phase 6 -- a behaviour change nobody
 *     would notice until it dropped a user's mail.
 *   - 3.2's own derivation is about the largest LEGAL tag set, and it says so
 *     explicitly ("the cap must equal the largest legal tag set rather than an
 *     average"). An average here would be the same error.
 *
 * The remaining envelope -- prefix, verb, target -- is charged at its maximum,
 * written as the struct widths the two of them come from, so raising
 * conn_t::nick or chan_t::name cannot leave the arithmetic short. */

int fanout_line_fits_n(const char *prefix, const char *verb, size_t target_len,
                       size_t params_bytes)
{
    /* message_format() reserves one byte for its NUL and emit_built() renders
     * into a buffer of IRC_MAX_LINE, so the CONTENT of a rendered line has to
     * be at most IRC_MAX_LINE - 1. 3.2 asks for one less than that again on the
     * relay path, and the budget is taken there rather than here:
     *
     *   content = ':' prefix ' ' VERB ' ' target ' ' params...
     *           = 1 + prefix_len + 1 + verb_len + 1 + target_len + 1 + params
     *
     * so the test is the same subtraction, with 3.2's IRC_MAX_RELAY_LINE as the
     * cap. prefix and target are charged at their REAL lengths: the line that
     * renders is built from these same strings, so measuring them cannot leave
     * the arithmetic short of a line that no longer fits. The struct widths
     * (CONN_HOSTMASK_MAX, CHAN_MAX_NAME + 1) survive only as the fallback for
     * a NULL prefix, where there is no string to measure and the relay
     * envelope still needs a worst-case bound. VERB is measured: it is a
     * fixed short list in this node, and guessing at it would be a second
     * opinion about code that already exists.
     *
     * `params_bytes` is the SUM of every parameter's length, separators
     * included by the fixed 1s above, and summing rather than charging only the
     * last one is what makes a line with several medium parameters -- an SKICK
     * with a member, a channel, a target and a long reason, which is the shape
     * 4.3 freezes for it -- come out the same size here as it would render. The
     * sum is a LOWER bound on the rendered size, never an over-estimate of it,
     * so the cap is approached from the conservative side. */
    size_t prefix_len;
    size_t charge;

    if (verb == NULL) {
        return 0;
    }
    /* No string to measure, so assume the widest envelope the relay path can
     * carry rather than the narrowest. */
    prefix_len = (prefix != NULL) ? strlen(prefix) : (size_t)CONN_HOSTMASK_MAX;
    charge = 1u /* ':' */ + 1u /* ' ' */ + 1u /* ' ' */ + 1u /* ' ' */
             + prefix_len + target_len;
    return (params_bytes + charge + strlen(verb)) <= (size_t)IRC_MAX_RELAY_LINE;
}

int fanout_line_fits(const char *prefix, const char *verb, const char *target,
                     const char *text)
{
    if (verb == NULL || text == NULL) {
        return 0;
    }
    /* THE CLIENT-FACING CAP CHARGES THE LARGEST CLIENT-VISIBLE TAG BLOCK, and
     * charging it is the only difference from fanout_line_fits_n(). The arithmetic
     * in that function is the shared envelope -- prefix, verb, target -- against
     * IRC_MAX_RELAY_LINE, which is IRC_MAX_LINE minus IRC_MAX_TAG_OVERHEAD: 3.2
     * reserves exactly that much for whatever tag block the outbound line carries,
     * and for a PEER line it is the 2.4 internal block, which is bounded by the
     * same reserve. A CLIENT line's block is a different one and it is NOT bounded
     * by that reserve: this node may write `msgid` AND `account`, and
     * FANOUT_TAG_BLOCK_MAX is larger than IRC_MAX_TAG_OVERHEAD.
     *
     * SO IT IS CHARGED HERE, in full, rather than left to the render. The
     * alternative -- discovering the overflow when message_format() refuses the
     * line -- is a refusal counted on n_reply_refused, which reply.c documents as
     * a bug report, and it would cost a user their message to save 250 bytes of
     * headroom. reply.c's comment already names this as the obligation: "whoever
     * adds such an emission must charge the tag against IRC_MAX_RELAY_LINE where
     * fanout_line_fits() is applied."
     *
     * The cost is a smaller maximum message: this charges 2 + FANOUT_TAG_BLOCK_MAX
     * (250 bytes today) against the 8013 of IRC_MAX_RELAY_LINE, so the longest
     * PRIVMSG this node relays is 250 bytes shorter than it was. That is a limit,
     * stated at the point it is applied, and the alternative is losing messages at
     * the cap. */
    return fanout_line_fits_n(prefix, verb, (target != NULL) ? strlen(target) : 0u,
                              strlen(text) + (2u + FANOUT_TAG_BLOCK_MAX));
}

/* ---------------------------------------------------------------------------
 * Delivery
 * ---------------------------------------------------------------------------
 */

/* ---------------------------------------------------------------------------
 * THE EMISSION'S 2.4 IDENTITY, COMPUTED ONCE
 * ---------------------------------------------------------------------------
 * One call, one stamp, and that is the whole point of it being here rather than
 * inside fanout_forward_sverb().
 *
 * WHY IT HAD TO MOVE. The forward leg is called ONCE PER TARGET, so a mint in
 * there is a mint per peer: an emission forwarded to two peers reached them
 * under two different (origin, epoch, id) pairs. For the dedup store that was
 * survivable -- the store is per node, and the two copies of one message to two
 * peers are not copies of one message arriving twice -- but it is fatal for the
 * IRCv3 `msgid`, which is derived from this same triple and is read by CLIENTS.
 * Two members of one channel on two nodes would see two different msgids for one
 * message, which is precisely the "two deliveries look like two messages" failure
 * the capability exists to remove, and it would be this node's own minting that
 * caused it.
 *
 * So the identity is computed once per EMISSION here, before the local write and
 * before the target walk, and both consume the same stamp. This is also the
 * argument fanout.h makes about why `carry` is an argument and not a field on
 * fanout_target_t: an identity is a property of one emission, and an emission is
 * what fanout_deliver() is given.
 *
 * WHAT CHANGED FOR THE FORWARD LEG, and it is worth stating because the hop
 * arithmetic moved with the mint. Before, fanout_forward_sverb() decided between
 * "mint" and "carry and add a hop" and so was the only place that knew either
 * answer. Now the stamp that goes on the wire is computed HERE, which means a
 * caller that already has the stamp must be able to say "this one is already
 * what the wire gets" -- and that is a second entry point onto the same static
 * body, not a second body. fanout_forward_sverb() keeps its public contract
 * exactly (tests/integration/test_fed_dedup.c pins it on the wire, carry in and
 * hops+1 out), so the +1 it did for itself is done by fanout_stamp() instead.
 *
 * `relayed` travels out of here rather than being re-derived at each use, because
 * the two facts it separates are genuinely different and each is checked at one
 * place: a stamp this node minted has origin == s->name and hops == 0 and is
 * EXACTLY what goes on the wire, while a stamp a peer sent is one hop old before
 * this node forwards it and 2.4's own-origin rule applies to it and not to the
 * other. */
void fanout_stamp(server_t *s, const irc_serve_tags_t *carry,
                         irc_serve_tags_t *out, int *relayed)
{
    if (carry == NULL) {
        /* ORIGINATING. This node minted the emission, so the identity is minted
         * with it: origin is this node's name -- which is what makes 2.4's
         * never-forward-own-origin rule decidable on the far side without any
         * extra state -- epoch is this node's per-boot value, and the id is the
         * next from the per-SERVER counter. hops is 0 because nothing has
         * forwarded it yet, and 2.4 counts forwards rather than hops travelled. */
        memset(out, 0, sizeof *out);
        memcpy(out->origin, s->name, strlen(s->name) + 1u);
        out->epoch = s->epoch;
        out->id = server_next_msg_id(s);
        out->hops = 0u;
        *relayed = 0;
        return;
    }
    /* RELAYING. origin/epoch/id carry through UNCHANGED and only hops moves. A
     * restamp here would give the copy a new identity, the far side's dedup
     * store would treat it as a message it has never seen, and the message would
     * come back -- that is the loop, and it is not bounded by the hop ceiling in
     * any useful sense because each pass would mint a fresh id. hops is the ONLY
     * field a forward may change, and this is the only place it changes.
     *
     * THE INCREMENT SATURATES, and that is not a detail. It is done in a wider
     * type on purpose: `carry->hops + 1u` in uint32_t wraps, and a stamp that
     * arrives carrying hops=UINT32_MAX would become hops=0 -- which is the one
     * value the hop ceiling refuses least, because it is the value that means
     * "nothing has forwarded this yet". A hostile or broken peer sending that
     * stamp would therefore get its message forwarded unboundedly, which is
     * exactly what 2.4's ceiling exists to prevent, and it would get there
     * through arithmetic rather than through a policy decision.
     * tests/integration/test_fed_dedup.c sends that stamp and requires it to be
     * refused; saturating at UINT32_MAX -- the largest value 2.4's value grammar
     * admits for hops -- keeps it refused for the right reason rather than by
     * accident. */
    *out = *carry;
    {
        const uint64_t hops = (uint64_t)carry->hops + 1u;

        out->hops = (hops > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)hops;
    }
    *relayed = 1;
}

