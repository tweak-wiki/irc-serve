/* fanout_forward.c -- see fanout_forward.h. The forward leg, verbatim out of
 * core/fanout.c; delivery stays there.
 */
#include "core/fanout_forward.h"

#include "core/fanout.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/reply.h"
#include "federation/verbs.h"

#include "core/fanout_resolve.h"

/* 3.1's forward target set for a CHANNEL, in one function.
 *
 * TWO CALLERS AND THAT IS THE POINT. fanout_deliver()'s two channel rows call
 * it for a local emission, and federation/verbs.c reaches it through
 * fanout_deliver()'s own `carry` argument when it relays a message it received.
 * The rows are 3.1's, and after the amendment they are:
 *
 *   owned channel     | message        | servers[ch] UNION every ESTABLISHED
 *   non-owned channel | message        | link                        (the owner)
 *   owned channel     | state-change   | servers[ch] UNION every ESTABLISHED
 *   non-owned channel | state-change   | link                        (the owner)
 *
 * and a second copy of that walk in verbs.c would be exactly the duplication
 * this module exists to prevent: chan_verbs.c's own broadcast was already a
 * second implementation of "tell the members" and had no forward arm at all,
 * which is how a missing forward gets lost. There is now one place that decides
 * where a channel's message goes, and every caller uses it.
 *
 * THE OWNED ROWS ARE ONE ROW NOW, and that is the amendment this pass records.
 * The table used to say an owned channel with a `message` forwards nothing,
 * because "the origin already holds every member" -- and the reason was false.
 * In a mesh of three or more nodes the origin does not hold those members as
 * LOCAL members; it holds them in a remote roster, and a roster entry is not a
 * delivery path. The origin forwards nothing, so a member sitting on a third
 * node never hears a message for a channel it is on, and 7/Phase 6's fifth
 * acceptance criterion -- "a node with zero local members in the channel still
 * relays that channel's SPRIVMSG to the owner" -- was unreachable from the code
 * as specified, because the only path a `message` took across a link was
 * leaf -> owner and no relay ever received one. So the two owned rows now share
 * this one target set, and the class no longer chooses between them.
 *
 * WHAT THAT COSTS, plainly: an owner re-broadcasts, so a channel whose members
 * sit on N member-servers costs N forwards per message where it cost 1, and a
 * node that owns a channel with no local member of it now spends a forward on a
 * message it delivers to nobody. That is the price of the mesh being able to
 * reach its own members, and it is paid per channel rather than per node.
 *
 * AND IT IS WHAT MAKES A LOOP POSSIBLE, which the old row made impossible and
 * which is why the guards matter more rather than less. An owner now forwards a
 * message it received, so owner and relay can hand one message back and forth;
 * 2.4's three rules are what bound that, and each has a job: the `hops` ceiling
 * bounds how far it spreads, never-forward-own-origin stops the copy returning
 * to the server whose client wrote it, and the per-node dedup store drops the
 * copy that comes back to a node that has already seen the (origin, epoch, id).
 * The first hop back is therefore EXPECTED and is visible in the counters --
 * test_fed_loop.c asserts it happens exactly once and then stops, which is a
 * stronger claim than the old row allowed it to make.
 *
 * THE UNION IN THE OWNED ROWS IS LOAD-BEARING, and without it the FIRST join to
 * a channel is invisible. servers[] is a set of servers that have REPORTED a
 * member, so a channel's first join has an empty set on both sides: neither node
 * has heard from the other, so neither has anything in servers[], and a forward
 * over servers[] alone would mean nothing is ever forwarded for a new channel,
 * so no member is ever reported, so nothing is ever forwarded. A peer could
 * never become a relay or answer a 353, and 7/Phase 6's first acceptance
 * criterion would be unimplementable.
 *
 * It IS a broadcast to every linked peer, and 3.1's topology paragraph already
 * concedes that ("Forwarding to each peer holding members *is* a broadcast").
 * What is avoided is the GLOBAL list: the target is the member-server set plus
 * the node's own links, never every node on the network. The cost is that a
 * three-node mesh sends each state change -- and now each message -- to all
 * three rather than to the two that need it, and 3.1 accepts it in exchange for
 * a first join that works and a member on the third node that is not silenced.
 *
 * A peer in BOTH sets is forwarded to ONCE, deduped by name (case-insensitively,
 * because 2.1/2.4 both make server names case-insensitive). "Exactly once" is
 * structural here rather than resting on the far side's dedup store catching a
 * second copy, which matters because the store is bounded and evictable and a
 * bound that can be reached is not a guarantee.
 *
 * Returns how many peers the line was queued to. Zero is a normal answer: a
 * channel with no member-server and no ESTABLISHED link has nowhere to send it,
 * and a leaf that does not own the channel and has no route to the owner gets
 * the NO_ROUTE report from fanout_forward_sverb() rather than a silent drop. */
/* ONE PEER, with the stamp ALREADY DECIDED. The target-set walk above and
 * fanout_forward_sverb() both reach this, and it is the only place the two
 * 2.4 forward-time guards and the render-and-queue live.
 *
 * `relayed` is the one fact that cannot be re-derived from `stamp` and it is a
 * parameter rather than a comparison because the comparison would be wrong. A
 * stamp this node MINTED has origin == s->name, and so does a stamp a peer sent
 * naming this node -- which federation/verbs.c's inbound guard already refuses
 * with `fed_own_origin_drop` before it could reach a forward. The two are told
 * apart by where the value came from, not by what it says, and guessing from the
 * bytes would either refuse every forward this node originates or forward back
 * the message that came home, which is the loop 2.4 exists to stop.
 *
 * NOT STATIC-BY-NECESSITY: it is static because the guards belong with the queue
 * call they report, and the two callers that reach it are the two halves of one
 * operation (a target-set walk, and a single named peer). A third caller would
 * be the moment to ask whether the walk wants the stamp too. */
static int forward_one_peer(server_t *s, const char *peer_name, const char *sverb,
                            const char *src, const char *const *params, int nparams,
                            const irc_serve_tags_t *stamp, int relayed)
{
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";
    conn_t *peer;
    fed_queue_why_t why = FED_QUEUE_OK;

    /* The link is resolved here rather than by the caller, because the refusals
     * below name the peer and because a caller that had to resolve it would have
     * two places deciding what a route is. server_find_peer() is the ESTABLISHED
     * predicate: a link that has not finished the handshake FSM is not a route,
     * and 2.3 requires the server-name uniqueness check to happen before
     * ESTABLISHED for the reason this would otherwise be a duplicate-name bug on
     * the wire. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               sverb, target, peer_name);
        return 0;
    }

    /* ---- 2.4's two forward-time guards, and they are RELAY guards ---- */
    if (relayed != 0) {
        if ((uint64_t)stamp->hops >= (uint64_t)IRC_MAX_HOPS) {
            /* 2.4: "irc-serve-hops increments per forward and the message is
             * dropped at 10." `stamp->hops` is already the value that WOULD go
             * on the wire -- fanout_stamp() did the increment -- so the test is
             * on it directly and not on hops + 1. It is unchanged in effect: the
             * largest value that may be FORWARDED is IRC_MAX_HOPS - 1. */
            printf("[observable] fanout_forward_dropped: verb=%s target=%s "
                   "peer=%s reason=hop_limit hops=%lu ceiling=%d\n",
                   sverb, target, peer_name, (unsigned long)stamp->hops,
                   IRC_MAX_HOPS);
            return 0;
        }
        if (irc_ascii_same(stamp->origin, s->name)) {
            /* 2.4: "A node never forwards a message whose irc-serve-origin is
             * itself." This is the second of the three loop rules, and it is the
             * one that stops the SHORT cycle -- two nodes bouncing one message
             * between them -- which the hop ceiling alone would only slow down.
             *
             * The comparison is ASCII case-insensitive, and message.h says
             * explicitly that this is the caller's job: server names are
             * case-insensitive (2.1, RFC 1459 2.3.2), so a peer that spells this
             * node's name `IRC.A` in a tag is naming THIS node, and treating it
             * as a different server would forward back into the sender for ever
             * up to the hop ceiling. */
            printf("[observable] fanout_forward_dropped: verb=%s target=%s "
                   "peer=%s reason=own_origin origin=%s self=%s\n",
                   sverb, target, peer_name, stamp->origin, s->name);
            return 0;
        }
    }

    /* The prefix is the caller's, and for two of the seven S-verbs that is the
     * whole point: SPRIVMSG and SNOTICE are about a USER, so the receiver needs
     * a `nick!user@host` to put on the message it delivers to its own members.
     * verbs.h documents the argument and the fallback.
     *
     * fed_queue_line() and NOT fed_send_sverb(), because the verb here is
     * ALREADY an S-verb: fed_send_sverb() exists to map a client verb and
     * refuses a name it cannot map, and a relay's verb is exactly such a name.
     * The mapping and the shared step are separated for the same reason they are
     * for the T3 keepalive. */
    if (fed_queue_line(s, peer, stamp, src, sverb, params, nparams, &why) != 0) {
        /* fed_queue_why_name() has already been printed by nothing, so this
         * function says it, once. Counting a second, vaguer refusal here would
         * give an operator two lines to read for one event. */
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=%s\n",
               sverb, target, peer_name, fed_queue_why_name(why));
        return 0;
    }
    return 1;
}

/* THE TARGET SET WALK, and the only copy of it. Static because both exported
 * entry points below reach it, and because a target set that two functions could
 * each implement is a target set with two answers. */
static int forward_channel_targets(server_t *s, const chan_t *ch,
                                   fanout_class_t vclass, const char *sverb,
                                   const char *prefix, const char *const *params,
                                   int nparams, const irc_serve_tags_t *stamp,
                                   int relayed)
{
    int queued = 0;
    int owned;

    if (s == NULL || ch == NULL || sverb == NULL) {
        return 0;
    }
    /* The verb class does NOT choose a target set, and that is the amendment
     * above: 3.1's two owned rows name the same one and 3.1's two non-owned rows
     * name the same one. It is still a parameter because this walk is where
     * 3.1's rows are implemented, and a row that does come to differ -- a
     * `message` that must not go back to the server it came from, say -- is
     * added HERE and not at each of the four callers that would otherwise each
     * have to notice it. Stated rather than left as an unused argument, because
     * an argument that used to matter and does not is exactly the kind of thing
     * a reader assumes is a bug. */
    (void)vclass;
    owned = chan_origin_is_self(s, ch);
    if (owned == 0) {
        /* Both non-owned rows go to the owner, and the two classes differ only
         * in whether the caller also wrote locally -- which is the caller's
         * half of the row, not this one's. */
        return forward_one_peer(s, ch->origin, sverb, prefix, params, nparams, stamp,
                                relayed);
    }
    /* servers[] first, because those are the peers this node KNOWS hold
     * members, and a name in that set with no ESTABLISHED link is a finding
     * worth reporting rather than a peer to skip quietly. */
    for (size_t i = 0; i < ch->nservers; i++) {
        queued += forward_one_peer(s, ch->servers[i].name, sverb, prefix, params,
                                   nparams, stamp, relayed);
    }
    for (size_t j = 0; j < s->nlinks; j++) {
        const server_link_t *lk = &s->links[j];
        int already = 0;

        if (lk->state != (int)ESTABLISHED) {
            continue;
        }
        for (size_t i = 0; i < ch->nservers; i++) {
            if (irc_ascii_same(ch->servers[i].name, lk->name)) {
                already = 1;
                break;
            }
        }
        if (already == 0) {
            queued += forward_one_peer(s, lk->name, sverb, prefix, params, nparams,
                                       stamp, relayed);
        }
    }
    return queued;
}

int fanout_forward_channel(server_t *s, const chan_t *ch, fanout_class_t vclass,
                           const char *client_verb, const char *prefix,
                           const char *const *params, int nparams,
                           const irc_serve_tags_t *stamp, int relayed)
{
    const char *sverb;
    const char *sp[FED_SVERB_MAX_PARAMS];
    fed_sverb_scratch_t scratch;
    int shaped;

    if (s == NULL || ch == NULL || client_verb == NULL) {
        return 0;
    }
    sverb = fed_sverb_for(client_verb);
    if (sverb == NULL) {
        /* 4.3's list is short enough that a verb arriving here that is not in
         * it means something upstream built a line it cannot forward. */
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=NO_SVERB\n",
               client_verb, ch->name);
        return 0;
    }
    /* Shaped ONCE, not once per peer. The shape is a function of the channel,
     * the verb and the source prefix, none of which vary across the target set,
     * and re-deriving it inside the walk would be work multiplied by the number
     * of peers for a value that cannot have changed. */
    shaped = fed_sverb_params(client_verb, ch->name, params, nparams, prefix,
                              s->name, ch, &scratch, sp, FED_SVERB_MAX_PARAMS);
    if (shaped < 0) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=BAD_SHAPE\n",
               client_verb, ch->name);
        return 0;
    }
    return forward_channel_targets(s, ch, vclass, sverb, prefix, sp, shaped, stamp,
                                   relayed);
}

int fanout_forward_channel_sverb(server_t *s, const chan_t *ch,
                                 fanout_class_t vclass, const char *sverb,
                                 const char *prefix, const char *const *params,
                                 int nparams, const irc_serve_tags_t *carry)
{
    /* The relay half: the line is ALREADY an S-verb in 4.3's frozen shape, so
     * there is nothing to re-shape and only the target set to decide. Same walk,
     * same rules, same refusals -- which is the whole reason it is a second
     * entry point onto one static function rather than a second function.
     *
     * AND IT COMPUTES THE STAMP ITSELF, rather than being handed one the way
     * fanout_forward_channel() above is. This one is called by
     * federation/verbs.c with the stamp a PEER sent, and its one obligation is
     * the same one fanout_forward_sverb() has: add this node's hop and change
     * nothing else. The stamp is computed once here rather than per target
     * because for a relay the arithmetic is idempotent -- every target of a walk
     * would compute the same three numbers -- and computing it once means the
     * value a local member sees and the value every peer sees are the same
     * triple even on a mesh where they are the same emission by two routes. */
    irc_serve_tags_t ident;
    int relayed;

    if (s == NULL) {
        return 0;
    }
    fanout_stamp(s, carry, &ident, &relayed);
    return forward_channel_targets(s, ch, vclass, sverb, prefix, params, nparams,
                                   &ident, relayed);
}

/* The shape-free forward: one ALREADY-SHAPED S-verb to one named peer, with the
 * 2.4 loop guard applied at forward time. fanout_forward_link() below is the
 * same function with the shaping step in front of it, and federation/verbs.c
 * calls THIS one when it relays a line that is already an S-verb.
 *
 * It is a separate entry point because re-shaping a relayed S-verb as though it
 * were a client emission would be a bug: fed_sverb_params() reads a client's
 * parameter order, and an SJOIN's order (channel, member, flags) is not JOIN's
 * order (channel). Running one through the other produces a line no peer can
 * parse, silently, which is the failure mode this module's whole design is
 * arranged against.
 *
 * EVERY REFUSAL IS REPORTED on the observable output, naming the peer it wanted
 * and the reason it could not reach it. A federated node that lost a message
 * with no trace would look exactly like a node whose peers were silent, and the
 * two have opposite fixes. */
int fanout_forward_sverb(server_t *s, const char *peer_name, const char *sverb,
                         const char *prefix, const char *const *params,
                         int nparams, const irc_serve_tags_t *carry)
{
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";
    conn_t *peer;
    irc_serve_tags_t tags;
    int relayed;
    size_t pbytes = 0;
    /* The prefix this line will carry. NULL means the caller had none, and the
     * fallback is this node's own name -- correct for the five state verbs,
     * whose subject IS the server, and wrong for SPRIVMSG/SNOTICE, whose
     * subject is a user. See fanout.h on the parameter for why it exists and
     * why a silent fallback is stated here rather than left to be discovered. */
    const char *src = (prefix != NULL && prefix[0] != '\0')
                          ? prefix
                          : ((s != NULL) ? s->name : "-");

    if (s == NULL || peer_name == NULL || peer_name[0] == '\0' || sverb == NULL ||
        params == NULL || nparams < 0 || nparams > IRC_MAX_PARAMS) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=unresolved_peer\n",
               (sverb != NULL) ? sverb : "?", target);
        return 0;
    }
    /* params[0] is charged SEPARATELY, at its maximum width, and only the
     * remaining parameters are summed. That is the same arithmetic the
     * single-string form used -- the target in the charge, the text as the
     * payload -- and it is right for the state verbs too: 4.3's frozen shapes
     * put either the channel or the member in the first slot, and both are
     * bounded by CHAN_MAX_NAME, which is exactly the width the charge uses. */
    for (int i = 0; i < nparams; i++) {
        if (params[i] == NULL) {
            printf("[observable] fanout_forward_skipped: verb=%s target=%s "
                   "reason=unresolved_peer\n", sverb, target);
            return 0;
        }
        if (i > 0) {
            pbytes += strlen(params[i]);
        }
    }

    /* 3.2's cap, applied to the PARAMETERS before anything is stamped or built,
     * for the reason fanout_line_fits() gives: a line that cannot be relayed is
     * a limit and answers with a numeric, not a render failure discovered deep
     * inside the send path where the only outcome is a refusal.
     *
     * It is here, above the stamp, for the same reason the peer lookup is: the
     * checks that can refuse a forward all run before anything is spent on it.
     * Originating takes the next id from the per-SERVER counter, and an id spent
     * on a line that is then refused is a hole in the sequence. Nothing requires
     * the sequence to be contiguous -- a peer's dedup only needs ids to be
     * unique, and to differ from a previous BOOT's ids, which is what epoch is
     * for -- but a hole per dropped forward is a hole per dropped forward, and
     * there is no reason to spend one. */
    if (fanout_line_fits_n(src, sverb, strlen(target), pbytes) == 0) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s "
               "peer=%s reason=too_long bytes=%zu\n",
               sverb, target, peer_name, pbytes);
        return 0;
    }

    /* The link is resolved before the message is stamped, for the reason above.
     * server_find_peer() is the "can this node route to that server" predicate,
     * and it is the ESTABLISHED one: a link that has not finished the handshake
     * FSM is not a route, and 2.3 requires the server-name uniqueness check to
     * happen before ESTABLISHED for the reason this would otherwise be a
     * duplicate-name bug on the wire.
     *
     * AND IT IS LOOKED UP TWICE, once here and once in forward_one_peer(). That is
     * deliberate rather than an oversight left for a reader to puzzle over: THIS
     * one is the pre-mint refusal, so a forward to a server with no route spends
     * no id -- and tests/integration/test_fed_dedup.c pins exactly that, by
     * refusing an originating forward down a link that is not ESTABLISHED and then
     * requiring the counter to be exactly one id further on. The second lookup is
     * needed because the target-set walk reaches forward_one_peer() with a NAME and
     * no resolved peer. The cost is one linear scan of the link table per forwarded
     * target, which is negligible beside the line render it precedes, and the
     * alternative -- resolving every target in the walk before spending anything --
     * would be a second copy of the target set to keep in step with the first. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               sverb, target, peer_name);
        return 0;
    }

    /* ---- 2.4: the stamp, and the loop guard, at forward time ----
     *
     * THE STAMP IS COMPUTED HERE AND NOT DELEGATED to fanout_stamp()'s callers,
     * because of WHERE it sits: below the size check and below the peer lookup,
     * both of which can refuse, and an id spent on a line that is then refused is
     * a hole in the per-SERVER sequence. That reasoning is the paragraph above and
     * it is why this function's public contract is unchanged even though the walk
     * above it now hands a pre-computed stamp to forward_one_peer(): a caller with
     * one target and no client-facing local write still gets the per-target mint
     * this has always done, and only fanout_deliver() -- which has an identity to
     * share with its own local members -- takes the other route. */
    fanout_stamp(s, carry, &tags, &relayed);
    return forward_one_peer(s, peer_name, sverb, src, params, nparams, &tags, relayed);
}

int fanout_forward_link(server_t *s, const char *peer_name,
                        const fanout_target_t *t, const char *verb,
                        const char *const *params, int nparams,
                        const char *prefix, const irc_serve_tags_t *carry)
{
    const char *sverb;
    const char *sp[FED_SVERB_MAX_PARAMS];
    fed_sverb_scratch_t scratch;
    int shaped;
    const char *target = (t != NULL) ? t->name : "-";

    if (s == NULL || peer_name == NULL || peer_name[0] == '\0' || verb == NULL) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=unresolved_peer\n",
               (verb != NULL) ? verb : "?", target);
        return 0;
    }
    /* Resolved before anything else that costs anything, because a verb with no
     * S-verb is a CALLER bug rather than a routing outcome, and 4.3's list is
     * short enough that a verb arriving here that is not in it means something
     * upstream built a line it cannot forward. */
    sverb = fed_sverb_for(verb);
    if (sverb == NULL) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=NO_SVERB\n",
               verb, target);
        return 0;
    }
    shaped = fed_sverb_params(verb, target, params, nparams, prefix, s->name,
                              (t != NULL) ? t->chan : NULL, &scratch, sp,
                              FED_SVERB_MAX_PARAMS);
    if (shaped < 0) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=BAD_SHAPE\n",
               verb, target);
        return 0;
    }
    return fanout_forward_sverb(s, peer_name, sverb, prefix, sp, shaped, carry);
}
