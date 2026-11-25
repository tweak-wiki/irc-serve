/* fanout_deliver.c -- see core/fanout.h. The delivery leg, verbatim out of
 * core/fanout.c; the 3.2 cap (fanout_line_fits*) and the shared
 * fanout_stamp() live in core/fanout_cap.c.
 */
#include "core/fanout.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* fanout_stamp() is defined in core/fanout_cap.c and declared here (same as the
 * forward leg's include): delivery mints the emission identity through it. */
#include "core/fanout_forward.h"

/* THE SENDER'S ACCOUNT, RESOLVED ONCE FOR THE EMISSION, or "" when this
 * emission has none to assert: a relay (see the decision below), a SERVER prefix
 * with no local connection behind it, or a local sender that is simply not logged
 * in.
 *
 * WHY THE PREFIX IS THE SUBJECT. Every emission this node ORIGINATES carries the
 * acting client's `nick!user@host` -- RFC 2812 3.3.1 requires it on the JOIN,
 * PART, TOPIC, KICK and MODE echoes and PRIVMSG/NOTICE carry it by the same rule,
 * and conn_hostmask() is the one renderer -- so the prefix IS the identity the
 * emission is about, and it is already an argument to this function. A `conn_t *`
 * parameter would have to be threaded through fanout_deliver(), write_to_members()
 * and every call site of the forward for one value this node can read from what
 * it was handed, and each of those additions is a chance for a caller to pass a
 * different connection than the one the prefix names.
 *
 * IT IS A CONNECTION-LOCAL LOOKUP AND NOT A REGISTRY ASK, for the same reason
 * fanout_resolve()'s local branch is: server_nick_lookup() holds exactly this
 * node's own clients, so a prefix naming a REMOTE user finds nothing and there is
 * nothing to say. That is the correct answer rather than a gap, and it is the
 * federation decision below arriving structurally instead of as a check.
 *
 * ---------------------------------------------------------------------------
 * `+account` DOES NOT CROSS TO PEERS. A deliberate decision, stated here because
 * the alternative is defensible and a reader deserves to know which was chosen.
 * ---------------------------------------------------------------------------
 * An account registry is PER NODE and PER OPERATOR: design 2.5.1 says so, and two
 * nodes whose operators each wrote their own --account-store will disagree about
 * who somebody is, with nothing to arbitrate. Forwarding one node's account claim
 * would hand the far side's clients an identity that no registry they can consult
 * holds, and the client has no way to check it -- the `account` tag is precisely
 * the assertion a client trusts. This node asserts only what IT verified.
 *
 * The cost is real and it is worth naming: a member of a shared channel on a peer
 * sees no `account` tag on the peer's messages, so per-message identity stops at
 * the node that authenticated the sender. `extended-join` (Phase 10.3) carries the
 * account as MEMBERSHIP state, which is the claim federation does have a channel
 * for, and closing the per-message gap needs an account authority both nodes trust
 * -- a services registry, not a tag.
 *
 * IT IS ENFORCED BY `relayed` RATHER THAN BY A STRING TEST, so the decision is one
 * branch rather than a property of which characters the prefix happens to hold: a
 * RELAYED emission is never stamped with an account, whatever its prefix says. */
static const char *fanout_emitter_account(server_t *s, const char *prefix,
                                          int relayed)
{
    char nick[IRC_MAX_NICK + 1];
    const char *bang;
    const conn_t *local;
    size_t nlen;

    if (relayed != 0 || s == NULL || prefix == NULL) {
        return "";
    }
    /* The nick is the part before '!', and a prefix with no '!' is the name itself
     * -- which is a SERVER prefix (a relayed state verb, or one forwarded with no
     * actor) and is looked up anyway and finds nothing. The lookup is one walk of
     * the nick table per EMISSION, not per destination, which is noise beside the
     * render it feeds. */
    bang = strchr(prefix, '!');
    nlen = (bang != NULL) ? (size_t)(bang - prefix) : strlen(prefix);
    if (nlen == 0u || nlen > (size_t)IRC_MAX_NICK) {
        return "";
    }
    memcpy(nick, prefix, nlen);
    nick[nlen] = '\0';
    local = server_nick_lookup(s, nick);
    if (local == NULL) {
        return "";
    }
    /* account_name() rather than the field, so the empty-means-anonymous
     * distinction is read through the predicate that owns it: an unidentified
     * client yields "" and an unidentified client gets no tag. */
    return account_name(local);
}

/* The tag block for ONE DESTINATION, or NULL when that destination gets none.
 *
 * PER DESTINATION, twice over and for the same reason both times: the capability
 * is per connection, so two members of one channel can disagree about whether
 * they want to be told who sent a message. The block is therefore written per
 * member INSIDE the member walk rather than once for the emission -- and that is a
 * statement about WHEN the bytes are rendered, not about where the ACCOUNT NAME
 * comes from. The name was resolved once, by fanout_emitter_account(), and every
 * destination below is handed that same value. That is the whole distinction and
 * it is the one a per-target lookup gets wrong.
 *
 * ORDER IS msgid THEN account, and it is fixed rather than incidental: the block
 * is a byte string, and a test that asserts one tag must not be sensitive to
 * which order the node happened to choose.
 *
 * The failure branch is a BUG REPORT and not a fallback. irc_serve_msgid_value()
 * returns 0 only for a stamp 2.4's grammar would refuse or a buffer one byte too
 * small, and both are impossible here (the stamp was just computed by
 * fanout_stamp() from s->epoch and the counter, so it is legal; the buffer is sized
 * from FANOUT_TAG_BLOCK_MAX above). Emitting the line with neither tag would be
 * the quiet half of a claim this file makes -- "a client that asked for msgids
 * gets them" -- so the refusal is reported loudly on the node's own output and the
 * block is left empty, which is what send_line_tagged() reads as "no block". The
 * MESSAGE still goes out: a decoration this node failed to render must never cost
 * a user their message, and the diagnostic is what turns an unreachable branch
 * into something a reader would notice rather than something to rediscover. */
static const char *fanout_tag_block(const conn_t *dst,
                                    const irc_serve_tags_t *ident,
                                    const char *account, char *out, size_t cap)
{
    char msgid[IRC_MAX_MSGTAG + 1u];
    char acct[ACCOUNT_TAG_MAX];
    size_t n = 0;

    if (out == NULL || cap == 0u) {
        return NULL;
    }
    out[0] = '\0';

    if (cap_message_ids_enabled(dst) != 0) {
        if (irc_serve_msgid_value(ident, msgid, sizeof msgid) == 0u) {
            printf("[observable] msgid_refused: fd=%d origin=%s id=%llu\n",
                   (dst != NULL) ? dst->fd : -1, ident->origin,
                   (unsigned long long)ident->id);
            out[0] = '\0';
            return NULL;
        }
        /* snprintf rather than a hand-rolled append, and its return is CHECKED
         * rather than cast: the length it reports is what says the block fits, and
         * an unchecked accumulation is the three-bugs-in-one-expression cap.h
         * documents for CAP_LS_MAX. */
        {
            const int w = snprintf(out, cap, "%s=%s", IRCV3_TAG_MSGTAG, msgid);

            if (w < 0 || (size_t)w >= cap) {
                out[0] = '\0';
                return NULL;
            }
            n = (size_t)w;
        }
    }

    /* NO ACCOUNT, NO TAG -- and the first test is on the VALUE, not on the sender's
     * logged-in flag. account_name() already returns "" for a connection that is
     * not identified, and the specification says the tag MUST NOT be sent for such
     * a user, so an empty name is a tag that must not EXIST rather than a tag with
     * an empty value. The capability gate is per DESTINATION and comes second, so
     * a client that did not ask is never asked about this node's internals. */
    if (account != NULL && account[0] != '\0' &&
        cap_account_tag_enabled(dst) != 0) {
        if (account_tag_block(account, acct, sizeof acct) == 0u) {
            /* The same shape as the msgid refusal above: a bug report, and the
             * message still goes out. account_tag_block() cannot fail for a name
             * account_name() produced -- it is non-empty and shorter than
             * ACCOUNT_MAX_NAME, which is half ACCOUNT_TAG_MAX's value budget even
             * with every byte escaped -- so this arm is a bound that moved. */
            printf("[observable] account_tag_refused: fd=%d\n",
                   (dst != NULL) ? dst->fd : -1);
            out[0] = '\0';
            return NULL;
        }
        /* The ';' goes in front of the pair rather than behind the one already
         * written, so a separator is only ever emitted when there is something on
         * BOTH sides of it -- which is the whole of why this is a branch and not a
         * constant prefix. */
        {
            const int w = snprintf(out + n, cap - n, "%s%s", (n > 0u) ? ";" : "", acct);

            if (w < 0 || (size_t)w >= cap - n) {
                out[0] = '\0';
                return NULL;
            }
            /* NOT dead: n carries the write offset into the NEXT pair block
             * (bounds via cap - n, separator via n > 0). */
            n += (size_t)w;
        }
    }
    return (out[0] != '\0') ? out : NULL;
}

/* WHICH OF TWO PARAMETER LISTS DOES THIS DESTINATION GET?
 *
 * One function, called from the member walk and from the single-user row, because
 * the two arms of the switch are two destinations in all but name and a capability
 * question answered twice is a capability question that can be answered two ways.
 *
 * A NULL or empty `extended` means there is only one shape, which is every
 * emission in this file except the extended JOIN. */
static void fanout_form_for(const conn_t *dst, const fanout_form_t *extended,
                            const char *const **params, int *nparams)
{
    if (extended == NULL || extended->params == NULL ||
        cap_enabled(dst, CAP_EXTENDED_JOIN) == 0) {
        return;
    }
    *params = extended->params;
    *nparams = extended->nparams;
}

/* ---------------------------------------------------------------------------
 * ST-2: THE PRE-FORMATTED EMISSION
 * ---------------------------------------------------------------------------
 * write_to_members() and fanout_deliver_union_local_gated() used to build AND
 * render a message once per member: a message_build() malloc plus a
 * message_format() scan for every destination of every emission. The bytes
 * were the same for almost every member -- the prefix, the verb and the
 * parameters are facts about the EMISSION, not about the destination -- so
 * the work is hoisted instead:
 *
 *   - the LINE BODY (":prefix VERB params...", no tags, no terminator) is
 *     rendered ONCE per shape (plain always, extended lazily on first use),
 *     by fanout_render_body() below;
 *   - the two tag VALUES (the `msgid` pair and the `account` pair) are
 *     computed ONCE per emission, by fanout_precompute_tags();
 *   - per member only the SELECTION still happens: which shape (plain or
 *     extended, the same fanout_form_for() question as before) and which of
 *     the block combinations the member's capabilities ask for.
 *
 * WHAT STAYS PER MEMBER, and why the hoist is a selection rather than a
 * single line: the CAPABILITY gates are per connection. Two members of one
 * channel may disagree about `message-tags`/`draft/message-ids`
 * (cap_message_ids_enabled()'s double gate) and about `account-tag`
 * (cap_account_tag_enabled()'s double gate plus the non-empty-name rule), so
 * the block is one of four combinations and picking it is per destination.
 * fanout_pick_block() asks the same two predicates fanout_tag_block() asks,
 * over the same precomputed values, so the bytes agree with the old path by
 * construction rather than by review.
 *
 * WHAT TAKES THE SLOW PATH, and why it is not a second behaviour: a member
 * carrying per-destination label/batch state -- a live `label` owed a
 * response (and not suppressed for a self-message), an open batch reference,
 * or a one-shot batch reference -- is rendered by today's per-member
 * send_line_tagged() call, unchanged. The label hook MINTS state (it opens
 * the labeled-response batch and queues the BATCH + line) and the batch hook
 * CONSUMES state (the one-shot reference), so their outcome cannot be
 * precomputed without performing it; and an open batch reference differs per
 * connection, so it is not one bucket but one per member. member_needs_slow_path()
 * reads the same three fields the two hooks read and routes those members to
 * the old code, which is why the gates are preserved EXACTLY rather than
 * approximately: the members that have any are never on the fast path.
 *
 * ECHO is not a tag and needs no bucket: it is the `exclude` parameter, asked
 * before any rendering here exactly as before (msg_verbs.c sets it from
 * CAP_ECHO_MESSAGE). There is no server-time tag in this tree to preserve;
 * the capability does not exist (see cap.h's list), so there is no gate for
 * it on either path.
 *
 * FAILURE FALLS BACK, never forward: when the shared body will not render
 * (an unrepresentable parameter -- a CR in a field -- which the per-member
 * path reports on n_reply_refused) or the tag values will not compute (the
 * unreachable stamp/escape failure both old arms report loudly), the hoist
 * marks itself unusable and every member takes the slow path -- which IS the
 * old code, so the refusals and their counts are the ones the suite already
 * pins. The fast path therefore only ever runs when it can produce bytes,
 * and it produces them by memcpy: "@" block " " body CRLF, or body CRLF.
 *
 * No wire text and no log text changes: the observables below are the same
 * strings, and the slow path emits them at the same sites. A hoist-time
 * failure prints nothing itself; the slow path it defers to reports exactly
 * as it always did.
 */

/* Render ":prefix VERB all..." with NO tags and NO terminator into `out`,
 * returning the byte count or 0 on failure. The same build-then-format the
 * per-member path performs, done once: a NULL prefix falls back to the
 * node's own name exactly as emit_built_ex() does, and `cap` keeps reply.c's
 * reserve-two for the CRLF the caller appends. */
static size_t fanout_render_body(server_t *s, const char *prefix, const char *verb,
                                 const char *const *all, int nall,
                                 char *out, size_t cap)
{
    message_t m;
    size_t len;

    if (s == NULL || verb == NULL || out == NULL || cap < 2u) {
        return 0;
    }
    if ((all == NULL && nall != 0) || nall < 0 || nall > IRC_MAX_PARAMS) {
        return 0;
    }
    if (message_build(&m, NULL, (prefix != NULL) ? prefix : s->name, verb,
                      all, nall) != 0) {
        return 0;
    }
    len = message_format(&m, out, cap - 2u);
    message_free(&m);
    return len;
}

/* Compute the emission's two client-visible tag values once: `msgid` holds
 * "msgid=<v>", `acct` holds the whole "account=<v>" pair, `both` holds them
 * joined -- each "" when there is nothing of that kind to say. Returns 1
 * when the values are usable and 0 when they are not, in which case every
 * caller routes all members to the slow path: the per-member renderer then
 * reports the failure exactly as it always did, so this function itself
 * prints nothing. */
static int fanout_precompute_tags(const irc_serve_tags_t *ident, const char *account,
                                  char *msgid, size_t mcap,
                                  char *acct, size_t acap,
                                  char *both, size_t bcap)
{
    char idval[IRC_MAX_MSGTAG + 1u];
    char acctpair[ACCOUNT_TAG_MAX];
    int w;

    if (msgid == NULL || acct == NULL || both == NULL ||
        mcap == 0u || acap == 0u || bcap == 0u) {
        return 0;
    }
    msgid[0] = '\0';
    acct[0] = '\0';
    both[0] = '\0';
    /* The same legality gate the per-member renderer stamps under: the stamp
     * came from fanout_stamp(), so this fails only for a stamp 2.4 would
     * refuse -- unreachable, and routed to the slow path rather than
     * believed. */
    if (irc_serve_msgid_value(ident, idval, sizeof idval) == 0u) {
        return 0;
    }
    w = snprintf(msgid, mcap, "%s=%s", IRCV3_TAG_MSGTAG, idval);
    if (w <= 0 || (size_t)w >= mcap) {
        return 0;
    }
    if (account == NULL || account[0] == '\0') {
        return 1; /* anonymous emission: the msgid pair is the whole block */
    }
    if (account_tag_block(account, acctpair, sizeof acctpair) == 0u) {
        return 0;
    }
    w = snprintf(acct, acap, "%s", acctpair);
    if (w <= 0 || (size_t)w >= acap) {
        return 0;
    }
    w = snprintf(both, bcap, "%s;%s", msgid, acctpair);
    if (w <= 0 || (size_t)w >= bcap) {
        return 0;
    }
    return 1;
}

/* WHICH OF THE PRECOMPUTED BLOCKS DOES THIS DESTINATION GET, or NULL for
 * none. The same two double-gates the per-member renderer asks -- msgids
 * need `message-tags` too, and the account tag needs a name to assert as
 * well as its own capability -- asked about this member, over the values
 * computed once above. An empty slot reads as "absent" so a combination
 * that was never built is never emitted. */
static const char *fanout_pick_block(const conn_t *m, const char *account,
                                     const char *tag_msgid, const char *tag_acct,
                                     const char *tag_both)
{
    int want_ids;
    int want_acct;

    if (m == NULL) {
        return NULL;
    }
    want_ids = cap_message_ids_enabled(m);
    want_acct = (account != NULL && account[0] != '\0' &&
                 cap_account_tag_enabled(m) != 0) ? 1 : 0;
    if (want_ids != 0 && want_acct != 0) {
        return (tag_both[0] != '\0') ? tag_both : NULL;
    }
    if (want_ids != 0) {
        return (tag_msgid[0] != '\0') ? tag_msgid : NULL;
    }
    if (want_acct != 0) {
        return (tag_acct[0] != '\0') ? tag_acct : NULL;
    }
    return NULL;
}

/* The block is always one of the three precomputed values (or NULL), so its
 * length is SELECTED, not measured: three strlen calls per emission instead
 * of one per member (#216). Pointer identity is exact here because
 * fanout_pick_block() returns exactly these pointers. */
static size_t fanout_block_len(const char *block,
                               const char *tag_msgid, size_t msgid_len,
                               const char *tag_acct, size_t acct_len,
                               const char *tag_both, size_t both_len)
{
    if (block == tag_both) {
        return both_len;
    }
    if (block == tag_msgid) {
        return msgid_len;
    }
    if (block == tag_acct) {
        return acct_len;
    }
    return 0;
}

/* Does this member's line carry per-destination label/batch state, which only
 * the per-member path can render? The three fields are the ones the two hooks
 * read: a live label owed a response (a self-message suppresses it with no
 * side effect, so it stays fast), an open batch reference (a pure read, but
 * a value that differs per connection), and a one-shot reference (consumed
 * by the line that carries it). Anything set routes the member to the slow
 * path, which performs -- not probes -- the hooks. */
static int member_needs_slow_path(const conn_t *m)
{
    if (m == NULL) {
        return 1;
    }
    if (m->label_live != 0 && m->label_self == 0) {
        return 1;
    }
    if (m->batch_ref[0] != '\0' || m->batch_once[0] != '\0') {
        return 1;
    }
    return 0;
}

/* Queue bytes that are already a complete wire line (CRLF included). The
 * guards are emit_to_client()'s -- a peer target and a CLOSING target never
 * take bytes -- without its reports: member selection above (chan_member_live()
 * filters CLOSING before any rendering) makes both arms unreachable, and an
 * unreachable arm that counted would be a counter that can only ever be
 * wrong. Saturation still travels the honest road: server_queue_quiet() marks
 * CLOSING, prints writeq_overflow and counts, exactly as the per-member
 * path reaches it -- with no kick; the member walk coalesces one kick per
 * emission (fanout_kicks) instead of one per member. */
static int queue_prebuilt(server_t *s, conn_t *m, const char *line, size_t len)
{
    if (m == NULL || line == NULL || len == 0u) {
        return -1;
    }
    if (m->kind == CONN_SERVER) {
        return -1;
    }
    if (atomic_load_explicit(&m->state, memory_order_acquire) == CONN_CLOSING) {
        return -1;
    }
    if (server_queue_quiet(s, m, line, len) != 0) {
        return -1;
    }
    return 0;
}

/* #279: one kick per emission, not per member. Each member walk below queues
 * quietly and notes its owner's slot here; the walk fires the set once at
 * the end (one wq_mu hold for the emission, duplicate slots once). A slot
 * noted without bytes behind it is a spurious wake -- one extra drain scan
 * that finds nothing -- so walks note only members they actually attempt. */
#define FANOUT_KICK_BATCH 64
struct fanout_kicks {
    server_t *s;
    int slots[FANOUT_KICK_BATCH];
    size_t n;
};
static void fanout_kick_note(struct fanout_kicks *k, int slot)
{
    size_t i;

    for (i = 0; i < k->n; i++) {
        if (k->slots[i] == slot) {
            return;
        }
    }
    if (k->n == FANOUT_KICK_BATCH) {
        server_writers_kick_slots(k->s, k->slots, k->n);
        k->n = 0;
    }
    k->slots[k->n++] = slot;
}
static void fanout_kick_fire(struct fanout_kicks *k)
{
    if (k->n > 0) {
        server_writers_kick_slots(k->s, k->slots, k->n);
        k->n = 0;
    }
}

/* Write one line to every local member of `t->chan`, minus `exclude`.
 *
 * The same chan_member_live() rule every other member walk applies, for the
 * same reason: a member whose conn the loop has already marked CLOSING cannot
 * be written to, and attempting it is a guaranteed n_reply_refused -- a
 * non-zero value of the counter reply.c keeps at zero precisely because a
 * non-zero value means a bug. A teardown that is correct in every other respect
 * must not manufacture one.
 *
 * `gate` IS ASKED HERE, PER MEMBER, and this is the whole of the third outcome:
 * a member it refuses is skipped before `all` is built, so it gets no line and
 * no tag block and is not counted. See fanout.h for why it is a predicate and
 * not a third shape, and for the order it is asked in relative to liveness and
 * `exclude` -- the three tests run in that order and each is cheaper than the
 * next. */
static int write_to_members(server_t *s, const fanout_target_t *t,
                            const char *prefix, const char *verb,
                            const char *const *params, int nparams,
                            conn_t *exclude, const irc_serve_tags_t *ident,
                            const char *account, const fanout_form_t *extended,
                            fanout_gate_fn gate, void *gate_ctx)
{
    /* THE SHAPE IS DECIDED PER MEMBER AND EVERYTHING ELSE IS NOT, which is the
     * whole of what `extended` adds to this function. The parameter list, the
     * verb, the prefix, the 2.4 stamp and the account name are one emission's
     * facts and are the same for every member; only the recipient's negotiation
     * decides which of two lists of parameters it will be handed. */

    /* The target is `t->name` -- 2.2's CANONICAL form -- and not whatever the
     * caller typed, PREPENDED to the caller's own parameters. That is why the
     * caller's list is the parameters AFTER the target: it is the same
     * substitution this function has always made, and folding it into the
     * parameter list instead would mean every call site had to remember to
     * canonicalise, which is the mistake fanout_resolve() exists to prevent.
     *
     * One slot over the 15-parameter cap, and THE CAP IS ENFORCED HERE rather
     * than left to message_build(). The test is `nparams >= IRC_MAX_PARAMS`, not
     * `>`, and it is `>=` because the array below is IRC_MAX_PARAMS + 1 LONG and
     * the target takes one of those: a caller that hands over 15 tail parameters
     * would get 16 with the target, which message_build() refuses, and the
     * honest outcome for that is ZERO WRITES rather than a line the formatter
     * refused deep inside send_line() -- where the only available outcome is a
     * refusal counted on n_reply_refused, the counter reply.c keeps at zero
     * because a non-zero value of it is a bug report.
     *
     * IT WAS `>` UNTIL C4, and the comment above it said `>` was enough because
     * the comment claimed 15 tail parameters gave "zero writes". It did not: 15
     * passed the guard, filled all 16 slots, and built a 16-parameter line that
     * message_build() refused. Nothing in this node ever passes 15 -- every
     * caller passes two or three -- so the bug was unreachable from any call
     * site, which is exactly how a defect of this shape survives a phase: the
     * comment was the only thing asserting the bound, and the comment and the
     * code disagreed, so neither could be checked. The FANOUT_LOCAL_USER arm
     * below had the same guard and the same comment, and is fixed the same way;
     * both are here rather than in one helper because they are two separate
     * emissions with two separate destinations. */
    const char *all[IRC_MAX_PARAMS + 1];
    int n = 0;
    /* ST-2: the emission rendered once -- the plain body on first fast-path
     * use, the extended body lazily on first use, the tag values once. The
     * hoist below runs lazily on the first member that can take the fast
     * path, so an emission whose members all need per-destination state (or
     * are all gated/dead) never pays for a render nobody reads. Any hoist
     * step that fails (or inputs it cannot render) leaves its flag clear
     * and every member takes the slow path below, which is the old code
     * verbatim. */
    const char *base[IRC_MAX_PARAMS + 1];
    char body[IRC_MAX_LINE + 2u];
    size_t bodylen = 0;
    int body_ok = 0;
    char extbody[IRC_MAX_LINE + 2u];
    size_t extlen = 0;
    int ext_state = 0; /* 0 unrendered, 1 ready, -1 failed */
    char tag_msgid[FANOUT_TAG_BLOCK_MAX + 1u];
    char tag_acct[FANOUT_TAG_BLOCK_MAX + 1u];
    char tag_both[FANOUT_TAG_BLOCK_MAX + 1u];
    size_t tag_msgid_len = 0;
    size_t tag_acct_len = 0;
    size_t tag_both_len = 0;
    int tags_ok = 0;
    int hoist_tried = 0;
    struct fanout_kicks kicks;

    if (t->chan == NULL || nparams < 0 || nparams >= IRC_MAX_PARAMS) {
        return 0;
    }
    /* The hoist renders only inputs it can: a NULL parameter list with a
     * non-zero count is today's per-member refusal (counted on
     * n_reply_refused), not a body, so it is left to the slow path -- as is
     * a NULL stamp, which the per-member renderer reports per member. The
     * render itself runs inside the walk, on first fast-path use. */
    kicks.s = s;
    kicks.n = 0;
    for (size_t i = 0; i < t->chan->nmembers; i++) {
        conn_t *m = t->chan->members[i].c;
        char tags[FANOUT_TAG_BLOCK_MAX + 1u];
        char line[IRC_MAX_LINE + FANOUT_TAG_BLOCK_MAX + 4u];
        const char *const *use = params;
        int nuse = nparams;

        if (!chan_member_live(&t->chan->members[i])) {
            continue;
        }
        if (exclude != NULL && m == exclude) {
            continue;
        }
        /* AND THE GATE, AFTER `exclude` AND BEFORE ANY RENDERING, which is the
         * order that matters twice over. Asking it last means a member this
         * emission was never going to reach is not asked a question about it,
         * and asking it before the shape is resolved means a gated-off member
         * cannot influence anything -- not the `use`/`nuse` locals, not the
         * arity report below, not the tag buffer. A node that asked the gate
         * LAST would still send the right bytes, but it would have rendered a
         * tag block and possibly reported a `fanout_unhandled_form` for a
         * destination that was never going to be written to, and the second of
         * those is a bug report on the node's observable output caused by a
         * member who was never in the conversation. */
        if (gate != NULL && gate(m, gate_ctx) == 0) {
            continue;
        }
        /* THE BLOCK IS SELECTED PER MEMBER, from values computed once above:
         * the capability is per connection, and two members of one channel
         * are free to disagree about it, so the CHOICE of combination is the
         * one thing the hoist does not make. What it does not do is RENDER
         * per member: the values under the choice are the emission's own,
         * identical for every destination here and for the forward below --
         * and a buffer re-used across the walk is now safe, because nothing
         * queued still points at it: each member's line is complete bytes
         * before the next member is considered.
         *
         * `account` IS NOT PER MEMBER, and that is the point of the whole
         * function: it is the SAME resolved name for every destination here and
         * for the forward below. What varies per member is whether it is rendered
         * at all. */
        /* THE SHAPE, RESOLVED. fanout_form_for() is the ONE place that asks a
         * destination which of two parameter lists it gets, and it is a function
         * rather than an inline test so that the user row below cannot answer the
         * question differently from this one. */
        fanout_form_for(m, extended, &use, &nuse);
        /* AND THE EXTENDED LIST IS ARITY-CHECKED PER MEMBER, because the guard
         * above ran on the PLAIN one and an extended list can be longer. Unreachable
         * today -- the only extended caller adds two parameters to a verb that had
         * none -- and reported rather than assumed, for the reason write_to_members()
         * reports its other refusals: a caller that outgrew the array is a bug and
         * this node does not silently drop a member's copy of a line to hide one. */
        if (nuse >= IRC_MAX_PARAMS) {
            printf("[observable] fanout_unhandled_form: verb=%s target=%s "
                   "nparams=%d\n", verb, t->name, nuse);
            continue;
        }
        /* ST-2 FAST PATH: the member's line is bytes already -- the shared
         * body in the member's shape, the selected block in front, CRLF
         * behind -- queued with no build and no render. The shared body and
         * tag blocks render here, once, on the first member that can use
         * them; members carrying per-destination label/batch state skip the
         * render entirely, and every member takes the slow path when the
         * hoist produces no bytes: the old per-member render, kept
         * verbatim so its refusals and counts are unchanged. */
        if (member_needs_slow_path(m) == 0) {
            if (hoist_tried == 0) {
                hoist_tried = 1;
                if ((params != NULL || nparams == 0) && ident != NULL) {
                    base[0] = t->name;
                    for (int k = 0; k < nparams; k++) {
                        base[k + 1] = params[k];
                    }
                    bodylen = fanout_render_body(s, prefix, verb, base, nparams + 1,
                                                 body, sizeof body);
                    body_ok = (bodylen > 0) ? 1 : 0;
                    tags_ok = fanout_precompute_tags(ident, account,
                                                     tag_msgid, sizeof tag_msgid,
                                                     tag_acct, sizeof tag_acct,
                                                     tag_both, sizeof tag_both);
                    /* #216: measured once per emission, selected per member below. */
                    tag_msgid_len = strlen(tag_msgid);
                    tag_acct_len = strlen(tag_acct);
                    tag_both_len = strlen(tag_both);
                }
            }
            if (body_ok != 0 && tags_ok != 0) {
            const char *shape = body;
            size_t shapelen = bodylen;
            int ready = 1;

            if (extended != NULL && use != params) {
                if (ext_state == 0) {
                    const char *xall[IRC_MAX_PARAMS + 1];

                    xall[0] = t->name;
                    for (int k = 0; k < nuse; k++) {
                        xall[k + 1] = use[k];
                    }
                    extlen = fanout_render_body(s, prefix, verb, xall, nuse + 1,
                                                extbody, sizeof extbody);
                    ext_state = (extlen > 0) ? 1 : -1;
                }
                if (ext_state == 1) {
                    shape = extbody;
                    shapelen = extlen;
                } else {
                    ready = 0;
                }
            }
            if (ready != 0) {
                const char *block = fanout_pick_block(m, account, tag_msgid,
                                                      tag_acct, tag_both);
                /* #216: length selected, not measured (see fanout_block_len). */
                const size_t taglen = fanout_block_len(block, tag_msgid, tag_msgid_len,
                                                       tag_acct, tag_acct_len,
                                                       tag_both, tag_both_len);

                /* Unfailable for bytes the hoist produced -- the body fits
                 * IRC_MAX_LINE by render and the block fits its own bound --
                 * and checked anyway, so a bound that ever moves degrades to
                 * the slow path rather than overrunning the frame. */
                if (taglen <= (size_t)FANOUT_TAG_BLOCK_MAX &&
                    shapelen + taglen + 4u <= sizeof line) {
                    char *w = line;

                    if (block != NULL) {
                        *w++ = '@';
                        memcpy(w, block, taglen);
                        w += taglen;
                        *w++ = ' ';
                    }
                    memcpy(w, shape, shapelen);
                    w += shapelen;
                    *w++ = '\r';
                    *w++ = '\n';
                    (void)queue_prebuilt(s, m, line, (size_t)(w - line));
                    fanout_kick_note(&kicks, server_writer_slot(s, m->fd));
                    n++;
                    continue;
                }
            }
            }
        }
        /* THE SLOW PATH: `all` IS BUILT PER MEMBER, and so is the line. It is
         * the target plus whichever of the two shapes this member gets --
         * hoisting it would have baked in whichever shape the function was
         * called with and quietly given every member the same one, which is
         * the bug fanout_form_for()'s comment says this shape decision exists
         * to prevent, reached by the other road. */
        all[0] = t->name;
        for (int k = 0; k < nuse; k++) {
            all[k + 1] = use[k];
        }
        (void)send_line_tagged_quiet(s, m, prefix, verb, all, nuse + 1,
                                     fanout_tag_block(m, ident, account, tags,
                                                      sizeof tags));
        fanout_kick_note(&kicks, server_writer_slot(s, m->fd));
        n++;
    }
    fanout_kick_fire(&kicks);
    return n;
}

int fanout_deliver_local(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const char *const *params, int nparams,
                         conn_t *exclude)
{
    const fanout_form_t plain = { params, nparams };

    /* ONE SHAPE, expressed as the two-shape call, for the reason fanout_deliver()
     * gives. */
    return fanout_deliver_local_forms(s, t, prefix, verb, &plain, NULL, exclude);
}

int fanout_deliver_local_forms(server_t *s, const fanout_target_t *t,
                               const char *prefix, const char *verb,
                               const fanout_form_t *plain,
                               const fanout_form_t *extended, conn_t *exclude)
{
    /* NO GATE, which is what "one shape for everybody" and "everybody gets it"
     * both mean here -- the two sentences are the same sentence now, and they
     * were two independent NULLs before the gate existed. */
    return fanout_deliver_local_gated(s, t, prefix, verb, plain, extended, NULL, NULL,
                                      exclude);
}

int fanout_deliver_local_gated(server_t *s, const fanout_target_t *t,
                               const char *prefix, const char *verb,
                               const fanout_form_t *plain,
                               const fanout_form_t *extended, fanout_gate_fn gate,
                               void *gate_ctx, conn_t *exclude)
{
    const char *const *params = (plain != NULL) ? plain->params : NULL;
    int nparams = (plain != NULL) ? plain->nparams : 0;
    irc_serve_tags_t ident;
    int relayed = 0;
    const char *account;

    if (s == NULL || t == NULL || verb == NULL || (params == NULL && nparams != 0) ||
        nparams < 0) {
        return 0;
    }

    /* THE STAMP IS MINTED AND THEN NOT USED, and that is deliberate: a local-only
     * emission still needs an identity because a member's client may be tracking
     * 2.4's msgid, and the one this function computes is the one the SAME
     * emission would have carried. It is discarded rather than not computed
     * because write_to_members() takes it as a parameter, and a NULL there would
     * be a second thing to decide about. */
    fanout_stamp(s, NULL, &ident, &relayed);
    /* AND THE ACCOUNT, resolved once for the same reason. IT RESOLVES TO NOTHING
     * for this function's only caller, and that is right independently of the
     * lookup: a rename echo is sent by the NODE, not by a user, and the
     * specification's rule is about commands sent BY A USER. (The lookup agrees --
     * nickreg.c passes the connection's OLD nickname as the prefix, because the
     * field has already been overwritten by then, and that name is no longer in
     * the registry.) Passing it through rather than hard-coding "" keeps the
     * answer a property of the emission rather than a thing this wrapper asserts. */
    account = fanout_emitter_account(s, prefix, relayed);

    switch ((int)t->kind) {
    case FANOUT_LOCAL_USER:
        /* The one-connection row, and it is the same code as fanout_deliver()'s
         * rather than a second rendering of it -- including the sender-excluded
         * case, which is why this is a function over the target rather than a
         * "loop over members". */
        if (t->user == NULL || nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        if (exclude != NULL && t->user == exclude) {
            return 0;
        }
        /* THE GATE IS ASKED HERE TOO, and it is the row where skipping it would
         * be least visible and most wrong: a `nick@server`-free direct delivery
         * writes to exactly one connection, so a node that honoured the gate for
         * channels and not for users would be a node whose unsolicited
         * notification reaches every member of a channel and one named
         * individual. "One question per destination" has to mean it for both
         * kinds of destination, or the contract is a contract about channels. */
        if (gate != NULL && gate(t->user, gate_ctx) == 0) {
            return 0;
        }
        {
            const char *all[IRC_MAX_PARAMS + 1];

            all[0] = t->name;
            for (int i = 0; i < nparams; i++) {
                all[i + 1] = params[i];
            }
            (void)send_line(s, t->user, prefix, verb, all, nparams + 1);
        }
        return 1;

    case FANOUT_LOCAL_CHANNEL:
    case FANOUT_REMOTE_CHANNEL:
        /* A REMOTE channel is here as well as a local one because the two share
         * the roster and the caller may not know which it has: 3.1's state-change
         * row for a non-owned channel is "forward only", and a caller that wanted
         * no forward has already decided it does not want one, so asking it which
         * kind of channel it resolved would be asking a question with no answer
         * that changes anything. */
        return write_to_members(s, t, prefix, verb, params, nparams, exclude, &ident,
                                account, extended, gate, gate_ctx);

    case FANOUT_REMOTE_USER:
    case FANOUT_NONE:
    default:
        /* NO LOCAL DESTINATION EXISTS, and a caller that reached here with one of
         * these has a bug: there is no connection on this node to write to, and
         * inventing one would be a delivery to nobody counted as a delivery to
         * somebody. Counting nothing is the honest outcome, exactly as
         * fanout_deliver()'s FANOUT_NONE arm states. */
        return 0;
    }
}

int fanout_deliver_union_local_gated(server_t *s, struct chan *const *chans,
                                     size_t nchans, const char *prefix,
                                     const char *verb, const fanout_form_t *plain,
                                     const fanout_form_t *extended,
                                     fanout_gate_fn gate, void *gate_ctx,
                                     conn_t *exclude)
{
    irc_serve_tags_t ident;
    int relayed = 0;
    const char *account;
    int n = 0;
    /* ST-2 hoist state; see write_to_members() for the contract. The extended
     * body renders lazily inside the walk; everything else renders above. */
    char body[IRC_MAX_LINE + 2u];
    size_t bodylen = 0;
    int body_ok = 0;
    char extbody[IRC_MAX_LINE + 2u];
    size_t extlen = 0;
    int ext_state = 0; /* 0 unrendered, 1 ready, -1 failed */
    char tag_msgid[FANOUT_TAG_BLOCK_MAX + 1u];
    char tag_acct[FANOUT_TAG_BLOCK_MAX + 1u];
    char tag_both[FANOUT_TAG_BLOCK_MAX + 1u];
    size_t tag_msgid_len = 0;
    size_t tag_acct_len = 0;
    size_t tag_both_len = 0;
    int tags_ok = 0;
    struct fanout_kicks kicks;
    /* #171: the union de-duplication set -- one bit per registrable fd, cleared
     * once per emission below and set channel-by-channel in the walk. */
    unsigned char seen[SERVER_FD_TABLE / 8];

    if (s == NULL || chans == NULL || verb == NULL || plain == NULL) {
        return 0;
    }
    /* THE ARITY GUARD IS write_to_members()'s, including its `>=` and the reason
     * the target slot is not counted here: this emission has NO target. Every
     * parameter the caller hands over is a parameter of the line, so the bound is
     * simply "as many as the builder takes" -- IRC_MAX_PARAMS, and no +1 for a
     * name that is not there. A caller that outgrew it gets zero writes rather
     * than a refusal counted on n_reply_refused, for the same reason. */
    if ((plain->params == NULL && plain->nparams != 0) || plain->nparams < 0 ||
        plain->nparams >= IRC_MAX_PARAMS) {
        return 0;
    }
    kicks.s = s;
    kicks.n = 0;
    memset(seen, 0, sizeof seen);
    /* ONE IDENTITY FOR THE WHOLE EMISSION, computed once above the loops for the
     * reason fanout_deliver_forms() computes it once above its switch: the 2.4
     * stamp and the account name are facts about the EMISSION, not about a
     * destination, and every copy of this line -- to a member of the first channel
     * and to a member of the last -- must be the same emission. Minting per
     * channel would give one SETNAME two msgids. */
    fanout_stamp(s, NULL, &ident, &relayed);
    account = fanout_emitter_account(s, prefix, relayed);
    /* ST-2: the emission rendered once, as in write_to_members() -- the plain
     * body up front, the extended body lazily, the tag values once. NO target
     * is prepended here (see below), so the plain body is the caller's list
     * itself. Any hoist step that fails leaves every member on the slow path,
     * which is the old code verbatim. */
    {
        char plainbody[IRC_MAX_LINE + 2u];
        size_t plainlen = fanout_render_body(s, prefix, verb, plain->params,
                                             plain->nparams, plainbody,
                                             sizeof plainbody);

        if (plainlen == 0) {
            body_ok = 0;
        } else {
            memcpy(body, plainbody, plainlen + 1u);
            bodylen = plainlen;
            body_ok = 1;
        }
        tags_ok = fanout_precompute_tags(&ident, account,
                                         tag_msgid, sizeof tag_msgid,
                                         tag_acct, sizeof tag_acct,
                                         tag_both, sizeof tag_both);
        /* #216: measured once per emission, selected per member below. */
        tag_msgid_len = strlen(tag_msgid);
        tag_acct_len = strlen(tag_acct);
        tag_both_len = strlen(tag_both);
    }

    for (size_t i = 0; i < nchans; i++) {
        chan_t *ch = chans[i];

        if (ch == NULL) {
            continue; /* a chan_t this node no longer holds: nothing to address */
        }
        for (size_t k = 0; k < ch->nmembers; k++) {
            conn_t *m = ch->members[k].c;
            const char *const *use = plain->params;
            int nuse = plain->nparams;
            char tags[FANOUT_TAG_BLOCK_MAX + 1u];
            char line[IRC_MAX_LINE + FANOUT_TAG_BLOCK_MAX + 4u];
            int already = 0;

            /* THE ORDER IS THE SAME FOUR QUESTIONS write_to_members() asks, in the
             * same order, and the new one is LAST of the pre-render checks: is this
             * member addressable, is it the excluded one, has this emission already
             * reached it under an earlier channel, and does the gate allow it. The
             * gate stays after `exclude` for the reason fanout.h gives -- asking it
             * last means a member the emission was never going to reach is not
             * asked a question about it -- and the de-duplication stays before the
             * gate for the same shape of reason: a member already written to needs
             * no capability question asked about a line it is not going to get. */
            if (!chan_member_live(&ch->members[k])) {
                continue;
            }
            if (exclude != NULL && m == exclude) {
                continue;
            }
            /* ONCE PER DESTINATION, and this is the whole reason this entry point
             * exists rather than a loop of fanout_deliver_local_gated() in the
             * handler. A SETNAME line is `:nick!user@host SETNAME :<realname>` --
             * the specification's shape has NO CHANNEL PARAMETER -- so a per-channel
             * emission would put a *channel name* where a client expects the
             * realname, and would hand a member of three shared channels three
             * byte-identical copies of one fact. Neither is the specification, and
             * the second is the same defect echo-message's fault was: one
             * announcement, delivered more than once.
             *
             * THE ANSWER IS A SET, NOT A SEARCH (#171). "Has this emission already
             * reached `m`?" is one bit-test in `seen`: every in-range member of
             * every earlier channel set its bit when its channel finished (see the
             * mark loop past the member walk), so the test is O(1) per member and
             * the emission is O(members) rather than O(channels^2 * members^2).
             * No allocation and no teardown arm -- the bytes live on the stack.
             *
             * IT IS EXACT RATHER THAN APPROXIMATE, and that is a property of liveness
             * rather than luck: `chan_member_live()` only ever goes from 1 to 0, so a
             * member that was addressable at an earlier channel was written to, and a
             * member that was not is not addressable now either -- so the bit set by
             * that earlier visit is sufficient and needs no second liveness test. */
            if (m != NULL && m->fd >= 0 && m->fd < SERVER_FD_TABLE) {
                const unsigned bit = (unsigned)m->fd;

                if ((seen[bit / 8u] & (unsigned char)(1u << (bit % 8u))) != 0) {
                    already = 1;
                }
            } else {
                /* A descriptor poll() cannot name (a synthetic test conn): the
                 * bitmap has no slot for it, so the old bounded search stands
                 * for exactly these members and no others. */
                for (size_t j = 0; j < i && already == 0; j++) {
                    chan_t *earlier = chans[j];

                    if (earlier == NULL) {
                        continue;
                    }
                    for (size_t q = 0; q < earlier->nmembers; q++) {
                        if (earlier->members[q].c == m) {
                            already = 1;
                            break;
                        }
                    }
                }
            }
            if (already != 0) {
                continue;
            }
            if (gate != NULL && gate(m, gate_ctx) == 0) {
                continue;
            }
            /* THE SHAPE AND THE ARITY, per destination, from the same two helpers
             * every other row uses -- so a per-destination form cannot answer the
             * shape question differently here than it does in a channel emission. */
            fanout_form_for(m, extended, &use, &nuse);
            if (nuse >= IRC_MAX_PARAMS) {
                printf("[observable] fanout_unhandled_form: verb=%s target=UNION "
                       "nparams=%d\n", verb, nuse);
                continue;
            }
            /* ST-2 FAST PATH: the member's line is bytes already -- the shared
             * body in the member's shape, the selected block in front, CRLF
             * behind. NO `all[]`, and the absence is the point: there is no
             * target to prepend, so the caller's list IS the line. Members
             * with per-destination label/batch state, and every member when
             * the hoist above produced no bytes, take the slow path. */
            if (body_ok != 0 && tags_ok != 0 && member_needs_slow_path(m) == 0) {
                const char *shape = body;
                size_t shapelen = bodylen;
                int ready = 1;

                if (extended != NULL && use != plain->params) {
                    if (ext_state == 0) {
                        extlen = fanout_render_body(s, prefix, verb, use, nuse,
                                                    extbody, sizeof extbody);
                        ext_state = (extlen > 0) ? 1 : -1;
                    }
                    if (ext_state == 1) {
                        shape = extbody;
                        shapelen = extlen;
                    } else {
                        ready = 0;
                    }
                }
                if (ready != 0) {
                    const char *block = fanout_pick_block(m, account, tag_msgid,
                                                          tag_acct, tag_both);
                    /* #216: length selected, not measured (see fanout_block_len). */
                    const size_t taglen = fanout_block_len(block, tag_msgid, tag_msgid_len,
                                                           tag_acct, tag_acct_len,
                                                           tag_both, tag_both_len);

                    if (taglen <= (size_t)FANOUT_TAG_BLOCK_MAX &&
                        shapelen + taglen + 4u <= sizeof line) {
                        char *w = line;

                        if (block != NULL) {
                            *w++ = '@';
                            memcpy(w, block, taglen);
                            w += taglen;
                            *w++ = ' ';
                        }
                        memcpy(w, shape, shapelen);
                        w += shapelen;
                        *w++ = '\r';
                        *w++ = '\n';
                        (void)queue_prebuilt(s, m, line, (size_t)(w - line));
                        fanout_kick_note(&kicks, server_writer_slot(s, m->fd));
                        n++;
                        continue;
                    }
                }
            }
            /* THE SLOW PATH: today's per-member render, kept verbatim -- queued
             * quietly, with the slot noted for the emission's single kick. */
            (void)send_line_tagged_quiet(s, m, prefix, verb, use, nuse,
                                         fanout_tag_block(m, &ident, account, tags,
                                                          sizeof tags));
            fanout_kick_note(&kicks, server_writer_slot(s, m->fd));
            n++;
        }
        /* #171: publish this channel's members to `seen` AFTER its walk, so the
         * bit-test above sees exactly the earlier channels -- the same set the
         * old search compared against, including members this pass skipped. */
        for (size_t k = 0; k < ch->nmembers; k++) {
            conn_t *done = ch->members[k].c;

            if (done != NULL && done->fd >= 0 && done->fd < SERVER_FD_TABLE) {
                const unsigned bit = (unsigned)done->fd;

                seen[bit / 8u] |= (unsigned char)(1u << (bit % 8u));
            }
        }
    }
    fanout_kick_fire(&kicks);
    return n;
}

int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *const *params, int nparams,
                   conn_t *exclude, const irc_serve_tags_t *carry)
{
    const fanout_form_t plain = { params, nparams };

    /* THE WHOLE OF THIS FUNCTION IS ONE LINE, and it is here so that the single
     * shape case is expressed in terms of the two-shape one rather than the other
     * way round: a NULL `extended` IS "one shape for everybody", and a caller that
     * reached fanout_deliver() gets exactly the behaviour it had before the
     * extension existed. */
    return fanout_deliver_forms(s, t, prefix, verb, &plain, NULL, exclude, carry);
}

int fanout_deliver_forms(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const fanout_form_t *plain,
                         const fanout_form_t *extended, conn_t *exclude,
                         const irc_serve_tags_t *carry)
{
    const char *const *params;
    int nparams;
    const char *account;
    /* Switched on an int, not on the enum, and that is deliberate rather than
     * lazy.
     *
     * -Weverything turns on BOTH -Wswitch-default (a switch over an enum must
     * carry a `default`) and -Wcovered-switch-default (a `default` is redundant
     * when every enumerator is listed). Writing 3.1's table both ways therefore
     * cannot satisfy both diagnostics at once, and the alternatives are both
     * worse: adding a suppression narrows a warning set this project has
     * deliberately kept maximal (see the top-level CMakeLists.txt), and dropping
     * the `default` means a kind added to fanout_kind_t later would compile
     * cleanly and fall through to the bottom of the function with no report --
     * which, in a routing table, is the one failure mode worth engineering
     * against.
     *
     * Reading the kind into an int satisfies both: the compiler can no longer
     * know the switch is exhaustive, so neither diagnostic fires, while the
     * cases below are still written out one per enumerator and a new one still
     * lands in the `default` that says it is unhandled. The two properties the
     * warnings were after are preserved and the warning set is untouched. */
    int kind;
    /* THE EMISSION'S IDENTITY, computed once for every row. It has to be above
     * the switch rather than inside the arms that need it, because the two
     * things it feeds -- the local write and the forward -- live in DIFFERENT
     * arms, and a stamp minted per arm would be a different identity for the
     * copy the members on this node see and the copy the peers see. That is the
     * same "one emission, one identity" argument fanout.h makes about `carry`
     * being an argument and not a field, and it is why the number is spent here
     * and nowhere else. */
    irc_serve_tags_t ident;
    int relayed;

    if (s == NULL || t == NULL || verb == NULL || plain == NULL) {
        return 0;
    }
    params = plain->params;
    nparams = plain->nparams;
    if ((params == NULL && nparams != 0) || nparams < 0) {
        return 0;
    }
    kind = (int)t->kind;
    fanout_stamp(s, carry, &ident, &relayed);
    /* AND THE `account` NAME, AT THE SAME POINT AND FOR THE SAME REASON: it is the
     * other property of THIS emission that both the local write and the forward
     * consume, and both must be handed the same value. `relayed` decides it, so a
     * relay stamps nothing and the decision is one branch rather than a property
     * of the prefix's bytes. See fanout_emitter_account(). */
    account = fanout_emitter_account(s, prefix, relayed);

    switch (kind) {
    case FANOUT_LOCAL_USER: {
        const char *all[IRC_MAX_PARAMS + 1];
        char tags[FANOUT_TAG_BLOCK_MAX + 1u];
        int n = 0;

        /* The same `>=` and the same reason as write_to_members() above: the
         * array is one longer than the cap because the target takes one slot, so
         * 15 tail parameters would be 16 and would be refused by the builder.
         * See the comment there for why the claim and the code used to disagree
         * without anything noticing. */
        if (t->user == NULL || nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        /* THE SHAPE IS RESOLVED BEFORE `all` IS BUILT, and for the same reason it
         * is resolved per member in write_to_members(): this row is a destination
         * like any other, and a capability question answered in one arm of this
         * switch and not the other is a JOIN that changes shape depending on
         * whether the caller resolved a channel or a nickname. No current caller
         * passes `extended` for a user target -- a JOIN never has one -- and
         * resolving it here anyway costs one AND rather than leaving the question
         * open for the next caller. The arity check is repeated afterwards because
         * the extended list can be longer than the plain one and `all` is one slot
         * longer than the cap. */
        fanout_form_for(t->user, extended, &params, &nparams);
        if (nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        all[0] = t->name;
        for (int i = 0; i < nparams; i++) {
            all[i + 1] = params[i];
        }
        if (exclude != NULL && t->user == exclude) {
            /* The sender addressed itself. For NOTICE that is 3.1's row applied
             * to the "never echoed to the sender" rule and the message is
             * simply not sent -- NOT a refusal, and not a numeric: a client
             * that NOTICEd itself has not done anything wrong. For PRIVMSG
             * `exclude` is NULL and the user hears its own message, which is
             * what lets a client confirm delivery without a second command. */
            return 0;
        }
        /* The tag gate, asked about THIS destination, which is the one connection
         * this row writes to. A PRIVMSG to a user rather than to a channel is still
         * one emission with one 2.4 identity, and the stamp the identity came from
         * is the same one a channel row would have forwarded, so the value a user
         * sees and the value a peer would see for the same message are the same
         * string -- and the account name, resolved once above, is the same string
         * too. */
        (void)send_line_tagged(s, t->user, prefix, verb, all, nparams + 1,
                               fanout_tag_block(t->user, &ident, account, tags,
                                                sizeof tags));
        n = 1;
        return n;
    }

    case FANOUT_LOCAL_CHANNEL: {
        /* NO GATE, and the reason is fanout.h's: a gate is asked about a LOCAL
         * DESTINATION and this row also forwards, so the two questions have
         * different destinations and a gate here would be set by a caller
         * believing it reached the members rather than the peers. */
        int n = write_to_members(s, t, prefix, verb, params, nparams, exclude,
                                 &ident, account, extended, NULL, NULL);

        /* 3.1's two owned rows, AND THEY NOW SHARE ONE FORWARD ARM.
         *
         * AND THE FORWARD GETS `params`, NEVER `extended`. That is not an
         * oversight and it is the whole of fanout.h's argument for this entry
         * point: the peer-facing shape of a JOIN is 4.3's SJOIN, built by
         * federation/verbs.c from the channel's membership, and it is one frozen
         * shape for every peer. Which of a node's CLIENTS negotiated
         * `extended-join` must not change what that node says to a peer.
         *
         * The local write is the only thing the verb class changes here, and the
         * forward is unconditional for both. The forward half is
         * fanout_forward_channel()'s, and it is CALLED rather than written out
         * for the reason the rest of this function is a single switch: the target
         * set is 3.1's, and 3.1's target set has a second caller --
         * federation/verbs.c relaying a state change it received -- which would
         * otherwise be a second walk over servers[] and the links, and the exact
         * duplication this module exists to prevent. See fanout.h on that
         * function. */
        /* AND IT IS HANDED THE EMISSION'S STAMP rather than `carry`, which is the
         * whole of the change this pass makes to the forward leg: the identity a
         * local member has just seen rendered as a `msgid` and the identity that
         * goes on the wire are the same three numbers, because they are the same
         * stamp. A `carry` of NULL here would mint a SECOND id for one emission,
         * and the two clients -- one on this node, one on the peer -- would then be
         * told two different things about one message. */
        (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                     nparams, &ident, relayed);
        return n;
    }

    case FANOUT_REMOTE_CHANNEL:
        if (t->vclass == FANOUT_STATE_CHANGE) {
            /* "FORWARD ONLY -- never a local write." 2.2's single-writer rule
             * is why the local write is the thing that is FORBIDDEN here rather
             * than the thing that is merely insufficient: a node that applied a
             * state change it could not route would hold a copy no one can
             * reconcile, permanently.
             *
             * The verb handlers ASK authority_ok() first, and since C3 the
             * answer for a linked non-owned channel is CHAN_VERDICT_FORWARD
             * rather than 437 -- which is this row reached deliberately. The
             * difference from the previous version is that the row now has a
             * caller, so "FORWARD ONLY" is what the node does rather than a
             * comment promising it would. */
            (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                         nparams, &ident, relayed);
            return 0;
        }
        /* "message": write to local members AND forward to the owner. Both
         * halves, and the local half is not conditional on the forward
         * succeeding -- a message is not state, so delivering it to the members
         * this node does have cannot create a divergence, whereas dropping it
         * would lose it.
         *
         * AND THE FORWARD IS UNCONDITIONAL, which is the whole of 7/Phase 6's
         * fifth acceptance criterion: "a node with ZERO LOCAL MEMBERS in the
         * channel still relays that channel's SPRIVMSG to the owner".
         * write_to_members() returns 0 for a channel with no local members and
         * also returns 0 when every member it had was the sender, so `n` cannot
         * distinguish "nobody to tell" from "told nobody" from "told somebody
         * and the write failed". Gating the forward on it would mean a node
         * with zero members in a channel it does not own silently swallows that
         * channel's traffic -- which is precisely the relay hop the design's
         * topology paragraph is built on, and the membership a node has is not
         * evidence about whether the message should travel.
         *
         * The same argument now applies to the OWNED row above, and that is the
         * amendment recorded in 3.1: a node that owns a channel and holds no
         * member of it still has to carry that channel's message to the servers
         * that do. */
        {
            int n = write_to_members(s, t, prefix, verb, params, nparams, exclude,
                                     &ident, account, extended, NULL, NULL);

            (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                         nparams, &ident, relayed);
            return n;
        }

    case FANOUT_REMOTE_USER:
        /* "remote user nick@server | either | forward to that server". 2.1
         * splits a qualified name at the LAST '@' -- not the first, because '@'
         * is not a legal nick character (2.1's own charset rule) but a
         * server name is an opaque string and may itself contain one. The
         * split is therefore the same one 2.1 specifies, and getting it wrong
         * here would name a peer that does not exist.
         *
         * Nothing resolves the name to a peer yet (fanout.h, on
         * FANOUT_REMOTE_USER), so the report below is what makes the attempt
         * visible instead of a message that vanished. */
        {
            const char *at = strrchr(t->name, '@');
            char server[IRC_MAX_SERVER_NAME + 1];
            size_t n;

            if (at == NULL || at == t->name || at[1] == '\0') {
                (void)fanout_forward_link(s, "", t, verb, params, nparams, prefix,
                                          NULL);
                break;
            }
            n = strlen(at + 1);
            if (n > (size_t)IRC_MAX_SERVER_NAME) {
                n = (size_t)IRC_MAX_SERVER_NAME;
            }
            memcpy(server, at + 1, n);
            server[n] = '\0';
            (void)fanout_forward_link(s, server, t, verb, params, nparams, prefix,
                                      NULL);
        }
        break;

    case FANOUT_NONE:
        /* An unresolved target never reaches delivery -- fanout_resolve() has
         * already answered the client -- so this is a caller bug rather than a
         * protocol case. Counting nothing and saying nothing is the honest
         * outcome; emitting something would be guessing. */
        return 0;

    default:
        /* Unreachable while fanout_kind_t is closed and every value is listed
         * above. It is a BUG REPORT if it is ever reached -- a kind this table
         * does not know how to route -- so it says so rather than returning
         * quietly. */
        printf("[observable] fanout_unhandled_kind: verb=%s target=%s kind=%d\n",
               (verb != NULL) ? verb : "?", t->name, kind);
        return 0;
    }
    return 0;
}

