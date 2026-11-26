/* chan_verbs.c -- see chan_verbs.h. The seven channel commands, and the one
 * function every state change goes through to learn whether it may happen.
 *
 * Authority: docs/SERVER_DESIGN.md 2.2, 3.1, 4.1 and 4.4.
 *
 * ---------------------------------------------------------------------------
 * THE SINGLE-WRITER RULE, AND WHY IT IS CHECKED BEFORE ANYTHING IS TOUCHED
 * ---------------------------------------------------------------------------
 * 2.2: "A node never applies a channel state change it cannot route to the
 * channel's origin; it refuses the action (437). It does not queue and apply
 * later."
 *
 * "It does not queue and apply later" is the half that is easy to get wrong and
 * the half this file is shaped around. There is deliberately NO deferred queue,
 * NO pending-mutation list and NO "apply when the link comes back" path here,
 * because any of those is a mechanism for producing exactly the permanent
 * divergence the rule exists to prevent: the local copy and the origin's copy
 * both mutate, in a different order, and the node has no way to reconcile them.
 * The absence is the feature, and a grep for a pending-queue in this file
 * finding nothing is the evidence.
 *
 * The consequence, stated so the code below reads correctly: a refused action
 * leaves the channel EXACTLY as it was. No partial application, no half-added
 * member, no topic written before the refusal is noticed, and no clock field
 * advanced. Every handler therefore answers its local preconditions first and
 * resolves authority before it has touched anything -- and the test that a
 * refused TOPIC left topic, topic_who and topic_when all untouched is a test
 * of that ordering, not of a detail.
 *
 * ---------------------------------------------------------------------------
 * WHAT "CANNOT ROUTE TO THE ORIGIN" MEANS ON ONE NODE
 * ---------------------------------------------------------------------------
 * On a single node, origin == self for every channel the node created, so
 * authority_ok() takes the CHAN_ORIGIN_SELF branch and the refusal is
 * unreachable from the wire. That is the degenerate case section 1 promises, and
 * it is exactly why the rule is tested by CONSTRUCTING a channel whose origin is
 * another server: a rule that can only be observed once a second node exists is a
 * rule that ships unverified.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/account.h"
/* For conn_text_logsafe(), conn_text_bad_count() and CONN_LOG_FIELD_MAX -- the 472s
 * render a client-supplied mode CHARACTER, which has no consumer beyond the line it
 * appears on, so it is measured rather than filtered. See mode_refusal_render(). */
#include "core/connection.h"
#include "core/fanout.h"
#include "federation/verbs.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * Argument handling
 * ------------------------------------------------------------------------- */

int chan_split_list(char *store, size_t dstcap, const char *src,
                    const char **names, int max)
{
    const size_t stride = (size_t)CHAN_MAX_NAME + 1u;
    const char *p = src;
    int n = 0;

    if (store == NULL || dstcap == 0 || src == NULL || names == NULL ||
        max <= 0) {
        return -1;
    }
    if (dstcap < stride * (size_t)max) {
        return -1; /* the caller's buffer cannot hold `max` names */
    }
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = (comma != NULL) ? (size_t)(comma - p) : strlen(p);

        if (len == 0) {
            /* Empty element: skip (spec channels, Verb arity). A wholly-empty
             * list still yields n == 0, which the caller refuses with 461. */
        } else {
            if (n >= max || len >= stride) {
                /* An over-long element or more names than `max` still refuses the
                 * whole list, because the caller cannot honour it in part. */
                return -1;
            }
            memcpy(store + (size_t)n * stride, p, len);
            store[(size_t)n * stride + len] = '\0';
            names[n] = store + (size_t)n * stride;
            n++;
        }
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    return n;
}

/* Canonicalise and validate one channel-name argument. Replies 403 and returns
 * 0 when it is not a channel name this node can speak about. `command` is the
 * client's verb, carried for the FAIL line: a client that negotiated
 * `standard-replies` gets `FAIL <command> ERR_NOSUCHCHANNEL` where it used to
 * get 403 (reply_refused(), #727), and anyone else gets the byte-identical 403.
 *
 * Split out from resolve_existing() because the two differ in exactly one way
 * and conflating them was a real bug during this phase: "canonicalise and
 * validate" is needed before a lookup, and "look up what already exists" is
 * needed for every verb EXCEPT JOIN. JOIN is the only verb that may find
 * nothing and create it. */
int canonical_channel(server_t *s, conn_t *c, const char *command, const char *arg,
                      char *out, size_t cap)
{
    (void)chan_name_upper(out, cap, arg);
    if (chan_name_valid(out)) {
        return 1;
    }
    /* RFC 2812 3.3.2: 403 is "<client> <channel> :No such channel" -- the
     * channel is a MIDDLE parameter, and a client reading by position takes
     * the trailing text as the complaint and the parameter as the subject. With
     * it omitted the client can only say "no such something", which is the
     * complaint 403 is specifically not. */
    (void)reply_refused(s, c, command, NULL, "403",
                        (const char *const[]){ out }, 1, "No such channel");
    return 0;
}

/* Resolve a channel the client must ALREADY be a member of.
 *
 * Two distinct failures, and conflating them is how this function's first
 * version dropped a reply on the floor:
 *
 *   the name is not a channel     403
 *   the channel does not exist    442, because "you are not there" is the
 *                                 actionable answer and 403 would send a client
 *                                 looking for a channel that may well exist
 *                                 somewhere it cannot see
 *   the channel exists, client is not a member   442
 *
 * Every path REPLIES before returning NULL, so a caller that returns on NULL has
 * said something. A resolve that returns NULL silently is worse than one that
 * does not exist, because the client waits. */
chan_t *resolve_joined(server_t *s, conn_t *c, const char *command,
                       const char *arg)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (!canonical_channel(s, c, command, arg, canonical, sizeof canonical)) {
        return NULL;
    }
    ch = server_chan_get(s, canonical);
    if (ch == NULL || chan_find_member(ch, c) == NULL) {
        /* RFC 2812 3.3.2: 442 is "<client> <channel> :You're not on that
         * channel", so the channel is a MIDDLE parameter. Without it a client
         * cannot tell WHICH channel it is not on, and this function answers on
         * behalf of every verb that needs a channel the caller is on -- JOIN is
         * the only exception, and it does not come through here. */
        (void)reply_refused(s, c, command, NULL, "442",
                            (const char *const[]){ canonical }, 1,
                            "You're not on that channel");
        return NULL;
    }
    return ch;
}

/* ---------------------------------------------------------------------------
 * The authority decision -- ONE function
 * ---------------------------------------------------------------------------
 * 2.2's single-writer rule is easy to honour in seven places and impossible to
 * keep honest in seven places, so the handlers ask a question instead of
 * answering it.
 *
 * `stateful` says whether this call MUTATES channel state. A query is answered
 * from whatever cache the node holds and is never refused: refusing to tell a
 * client who is in a channel is not a divergence risk, it is a stale answer that
 * a later SJOIN corrects -- and transient, self-healing divergence is precisely
 * what section 1 says the single-writer rule converts permanent divergence into.
 *
 * THREE ANSWERS, and the middle one is why this is no longer an int:
 *
 *   OK        proceed. This node owns the channel, or the call is a query.
 *   FORWARD   do not write locally; hand it to 3.1's forward arm. The origin is
 *             somewhere this node can reach, so the request is carryable.
 *   REFUSED   437, already sent, nothing modified. The origin is unreachable.
 *
 * The pre-C3 version returned 0 for BOTH of the last two and printed one
 * observable line for them with a `state=` field to tell them apart. That was
 * the same information, but the CALLER could only act on it as "do nothing",
 * which is why 3.1's state-change forward arm had no caller at all: the only
 * thing a boolean verdict could say about a non-owned channel was no.
 *
 * AND THE CLIENT IS NOT TOLD. A FORWARD is answered with the verb's own success
 * numeric exactly as an OK would be, because the origin performs the action:
 * the client asked a server to make a change to a channel and the mesh will make
 * it. 437 there would tell a client its own operator status was not accepted,
 * which is a lie about something that is about to be true. The one thing a
 * client is told that is a lie, and it was already a lie before this change --
 * a forward can still be refused further along, at the peer's 437 or at a NO_ROUTE
 * -- so the honest statement is that the node accepted the request and is not
 * promising the mesh accepted it. */
chan_verdict_t authority_ok(server_t *s, conn_t *c, const chan_t *ch,
                            const char *verb, int stateful)
{
    chan_origin_state_t st = chan_origin_state(s, ch);

    if (st == CHAN_ORIGIN_SELF) {
        return CHAN_VERDICT_OK;
    }
    if (stateful == 0) {
        /* A query against a channel this node does not own. The answer may be
         * incomplete -- the remote members are in the origin's records -- and it
         * is given anyway, because the alternative is refusing to answer. */
        printf("[observable] chan_query: channel=%s verb=%s origin=%s "
               "state=LINKED_CACHE nservers=%zu\n",
               ch->name, verb, ch->origin, ch->nservers);
        return CHAN_VERDICT_OK;
    }

    if (st == CHAN_ORIGIN_LINKED) {
        /* FORWARD, not 437. 3.1's "non-owned channel | state-change | forward
         * ONLY" has a real destination here: a link bears the origin's name and
         * is ESTABLISHED, which is precisely what server_find_peer() means by a
         * route. The pre-C3 comment here said "there is no forward path in this
         * phase, because 4.3's SJOIN/SPART/STOPIC/SSMODE/SKICK are Phase 6" --
         * that is now FALSE and is retracted: the forward path is
         * fanout_deliver()'s, 4.3's verbs are in federation/verbs.c, and the
         * arm is reachable.
         *
         * NO LOCAL WRITE, and the reason is 2.2's rather than 3.1's: a node that
         * applied a state change on a channel it does not own holds a copy the
         * origin will not reconcile, permanently. Applying it because the action
         * "looks harmless" is the exact failure the single-writer rule exists to
         * prevent, and the node would have no way to notice it had done it. */
        printf("[observable] chan_state_forward: channel=%s verb=%s origin=%s\n",
               ch->name, verb, ch->origin);
        return CHAN_VERDICT_FORWARD;
    }

    /* The refusal, and now only the refusal: 2.2's LOCALLY ORPHANED case, with
     * no ESTABLISHED link bearing the origin's name. This is fail-closed in the
     * whole sense -- local members still see each other, and nothing that needs
     * the origin is permitted. */
    printf("[observable] chan_state_refused: channel=%s verb=%s origin=%s "
           "state=ORPHANED numeric=437\n", ch->name, verb, ch->origin);
    (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                "Cannot change %s: this server is not its origin (%s)", ch->name,
                ch->origin);
    return CHAN_VERDICT_REFUSED;
}

/* ---------------------------------------------------------------------------
 * 353 -- the names list
 * ---------------------------------------------------------------------------
 * 7/Phase 4 fixes the order: "nicks, then ops, then voiced". The alternative --
 * "whatever order members[] happens to be in" -- makes the roster depend on join
 * history, so two clients on one channel with the same members could receive
 * different bytes, and the acceptance criterion could not be asserted at all.
 *
 * Three passes over a small array, no sort, no allocation, no comparison
 * function. O(3n) rather than O(n log n), and it is the same cost a counting
 * sort would be.
 */

/* Which of the three groups a member belongs to: 0 plain, 1 op, 2 voice.
 *
 * The tests are EXCLUSIVE, and that is the whole reason the order is well
 * defined. +o and +v are independent bits, so a member can hold both; an
 * independent test per group would render such a member twice. Op is tested
 * first, so it renders in the op group and nowhere else. */
static int names_group(const struct member *m)
{
    if (chan_member_is(m, CHAN_MEMBER_OP)) {
        return 1;
    }
    if (chan_member_is(m, CHAN_MEMBER_VOICE)) {
        return 2;
    }
    return 0;
}

/* The same three groups for a REMOTE member, as a flag word rather than a
 * `struct member *`. The two lists are walked by the same render below and the
 * grouping has to agree, which is why it is derived from the same two bits
 * rather than being a second rule written somewhere else. */
static int names_group_flags(unsigned flags)
{
    if ((flags & CHAN_MEMBER_OP) != 0u) {
        return 1;
    }
    if ((flags & CHAN_MEMBER_VOICE) != 0u) {
        return 2;
    }
    return 0;
}

/* The sigils drawn in front of `nick`, in the order 005's `PREFIX=(ov)@+` names
 * them, into `out`. Two bytes plus a NUL is the whole of what this node can draw
 * -- the two prefix modes are +o and +v and channel.h says so -- so `out` is
 * sized by that and not by a guess.
 *
 * MULTI-PREFIX OFF IS EXACTLY ONE SIGIL, and it is the HIGHEST the member holds.
 * RFC 2812 4.4.2 describes a prefix as "one or more" but every client that has
 * not negotiated `multi-prefix` indexes the first character it finds and looks
 * it up in PREFIX, so handing it two characters hands it a nickname it cannot
 * resolve. Op outranks voice, which is what names_group() says about the ORDER and
 * what this says about the DRAWING: an op+voice member is one entry in the op
 * group and one '@'.
 *
 * MULTI-PREFIX ON IS THE WHOLE SET, `@+nick`, in PREFIX order rather than in a
 * member-flag order. That order is not taste: a client reading the run left to
 * right and indexing into PREFIX has to reach the same answer this node did, and
 * 005 is where it reads PREFIX from. It is also the order that makes the drawn run
 * self-describing -- the leftmost sigil is the highest status, so a client that
 * only wants one can take the first byte and be right.
 *
 * WHY THE GATE IS A PARAMETER rather than read from `dst` here. It COULD be read
 * from `dst`, and it is passed instead for the reason the rest of this function
 * takes (nick, flags) rather than reading either roster: one decision, taken once
 * per list by the caller that knows the destination, so that a 353 assembled from
 * six passes cannot disagree with itself. `send_names_list()` asks once. */
static const char *names_signs(unsigned flags, int multiprefix, char *out,
                               size_t cap)
{
    size_t n = 0;

    if (out == NULL || cap < 2u) {
        return "";
    }
    out[0] = '\0';
    if (multiprefix == 0) {
        if ((flags & CHAN_MEMBER_OP) != 0u) {
            out[n++] = '@';
        } else if ((flags & CHAN_MEMBER_VOICE) != 0u) {
            out[n++] = '+';
        }
    } else {
        if ((flags & CHAN_MEMBER_OP) != 0u) {
            out[n++] = '@';
        }
        if ((flags & CHAN_MEMBER_VOICE) != 0u) {
            out[n++] = '+';
        }
    }
    out[n] = '\0';
    return out;
}

/* The ROSTER ENTRY for one member, drawn in the shape this DESTINATION asked
 * for, into `out`. Returns `out`, or "" when nothing fits.
 *
 * ---------------------------------------------------------------------------
 * THE PRIVACY DECISION IS IN THIS FUNCTION, NOT IN ITS CALLER
 * ---------------------------------------------------------------------------
 * IRCv3's `userhost-in-names` says a `353` may carry `nick!user@host` rather than
 * a bare nickname. What that means is that **every member's ident and observed
 * host address is disclosed to every other member of the channel**, to clients
 * that member has never spoken to and to clients who joined after them. There is
 * no per-member consent anywhere in it: one client asking puts the whole roster's
 * hostmasks on the wire to that client.
 *
 * So the shape is decided per DESTINATION and nowhere else, and it is decided
 * here rather than in `send_names_list()` so that the LOCAL roster and the REMOTE
 * roster -- two separate arrays walked by two separate loops -- cannot answer the
 * question differently. That was already the reason `multiprefix` is a parameter
 * of `names_signs()`; the difference is the cost of getting it wrong. One sigil
 * drawn in the wrong shape is cosmetic; one hostmask disclosed to a client that
 * did not ask is not.
 *
 * ---------------------------------------------------------------------------
 * WHAT HAPPENS WHEN THE NODE DOES NOT HAVE A HOSTMASK TO DRAW
 * ---------------------------------------------------------------------------
 * It draws the BARE NICK, which is the historical shape and which every client
 * parses, and the asymmetry is genuine rather than an oversight:
 *
 *   - a LOCAL member always has both halves. `c->host` was filled by accept()
 *     before the connection had a nickname, and `c->user` by USER.
 *   - a REMOTE member has them only if 4.3's SBURSTN announced them or a live
 *     SJOIN carried them. The 4.3 extension (#563) widened SJOIN to six
 *     parameters with `<user> <host>` appended, so a member learned from one now
 *     normally HAS both -- channel.h says so at `chan_remote_t`. An empty half
 *     remains possible (the sender spells "not told" as `-`), and still renders
 *     as the bare nick.
 *
 * The alternative would be to put `*` in place of a missing half, and that is
 * refused on purpose: `*` would be a byte on the wire that reads as part of a
 * hostmask and means nothing. A client that negotiated this capability and still
 * sees a bare nickname learns exactly the true thing -- that this node has not been
 * told -- and RFC 2812 3.3.5 permits a `353` to hold bare nicknames, so the mixed
 * roster is parseable rather than surprising.
 *
 * THE BUFFER IS PER MEMBER AND NOT HOISTED, for the reason `write_to_members()`
 * gives for its tag buffer: this renders inside the loop because the decision is
 * per destination, and a buffer shared across iterations is one whose contents
 * change under a line already queued. CONN_HOSTMASK_MAX is written from the three
 * struct widths rather than picked, so raising any of `nick`, `user` or `host`
 * cannot leave this one byte short. */
static const char *names_entry(const conn_t *dst, const char *nick,
                               const char *ident, const char *host, char *out,
                               size_t cap)
{
    const int long_form = cap_enabled(dst, CAP_USERHOST_IN_NAMES);

    if (out == NULL || cap == 0u || nick == NULL) {
        return "";
    }
    if (long_form == 0 || ident == NULL || ident[0] == '\0' ||
        host == NULL || host[0] == '\0') {
        if (strlen(nick) >= cap) {
            return "";
        }
        memcpy(out, nick, strlen(nick) + 1u);
        return out;
    }
    /* `nick!ident@host` is exactly conn_hostmask()'s own shape, so the local arm
     * could have called it -- and it deliberately does not, because this function
     * also renders REMOTE members, which have no conn_t and therefore no
     * conn_hostmask(). One renderer for both lists is why a remote entry and a local
     * one cannot come out in different shapes, which is the failure this whole
     * capability would otherwise have. */
    {
        const int w = snprintf(out, cap, "%s!%s@%s", nick, ident, host);

        /* snprintf returns what it WOULD have written, so the check is on the
         * return and a truncation is the negative side of it: a half-written
         * hostmask is worse than no hostmask, because a client parses what it is
         * given. Returning "" makes the caller SKIP the member rather than draw it
         * short, which would be a roster entry naming nobody. Unreachable with the
         * current bounds -- a 353 line is CHAN_NAMES_LINE (400) and the widest
         * entry is CONN_HOSTMASK_MAX (259) -- and stated rather than assumed
         * because the roster is the one place a silent omission is invisible. */
        if (w < 0 || (size_t)w >= cap) {
            out[0] = '\0';
            return "";
        }
    }
    return out;
}

/* Emit `nick` into the 353 line under construction, flushing first if it will not
 * fit. Returns the new `used`. The flush is RFC 2819 3.3.5's "a 353 MAY be
 * split across lines" and 3.2's "never deliver a shortened value" together: a
 * half-written nickname is worse than one more line.
 *
 * `entry` is the ALREADY-RENDERED member name: the sigils are drawn by the
 * caller's `names_signs()` because they are 005's PREFIX and `multi-prefix`'s, and
 * the name itself is drawn by `names_entry()` because it is 353's shape and
 * `userhost-in-names`'s. Two decisions about two different things, kept apart so
 * that a caller cannot render a name and forget the gate -- which is the defect
 * `userhost-in-names` invites, and the same one `extended-join` had to be careful
 * about for the same reason.
 *
 * This is the ONE place a name is rendered into a 353, and it takes the two
 * lists as (nick, flags) rather than reading either of them itself. That is what
 * makes 7/Phase 4's fixed order -- nicks, then ops, then voiced -- a property of
 * this function rather than of whichever list a member happens to be in, and it
 * is what lets the LOCAL roster and the REMOTE roster share one order instead of
 * two that could disagree.
 *
 * `flags` is the member's FULL prefix set, and it is what the sigils are derived
 * from. It used to be an `int group` -- the ORDER this member is drawn in, 0 plain
 * 1 op 2 voice -- and that is precisely why a member holding both modes could only
 * ever be drawn with one of them: the order is three exclusive buckets and a
 * member in two of them belongs to exactly one. The ORDER is still decided by the
 * caller's loop and this function still renders the members it is handed in the
 * order it is handed them, so dropping the parameter changes nothing about where a
 * name lands -- only about how much is drawn in front of it. */
static size_t names_emit(server_t *s, conn_t *dst, const char *const *mid,
                         unsigned flags, const char *entry, char *line,
                         size_t used, int *produced, int multiprefix)
{
    char signs[4];
    size_t slen = strlen(names_signs(flags, multiprefix, signs, sizeof signs));
    size_t elen = strlen(entry);
    size_t need = slen + elen + 1u; /* +1 for the joining space */

    if (elen == 0u) {
        /* A member this node cannot draw at all. `names_entry()` returns "" only
         * when the entry would not fit its buffer, which the current bounds make
         * unreachable -- a 353 line is CHAN_NAMES_LINE (400) and the widest entry
         * is CONN_HOSTMASK_MAX (259) -- and it is handled rather than assumed,
         * because the alternative is a silent omission from a names list, and a
         * names list is exactly where a silent omission is invisible.
         *
         * IT IS REPORTED RATHER THAN DRAWN SHORT. Falling back to the bare nick
         * here would be a second opinion about the shape, taken in a function that
         * does not have the capability gate, and it would produce a roster entry
         * asserting that this node does not know a host it does. The refusal goes
         * to the node's own output and the member is left out. */
        printf("[observable] names_entry_refused: channel=%s\n",
               (mid != NULL && mid[1] != NULL) ? mid[1] : "?");
        return used;
    }
    if (used != 0 && used + need > (size_t)CHAN_NAMES_LINE) {
        (void)reply(s, dst, "353", mid, 2, "%s", line);
        *produced = 1;
        used = 0;
    }
    if (used != 0) {
        line[used++] = ' ';
    }
    /* TWO bytes copied rather than one char written twice: with multi-prefix the
     * run is a variable-length string and a `line[used++] = sign[0]` here would
     * silently drop the second sigil, which is the defect this whole change is
     * about. */
    memcpy(line + used, signs, slen);
    used += slen;
    memcpy(line + used, entry, elen);
    used += elen;
    line[used] = '\0';
    return used;
}

/* Six passes over two small arrays, no sort, no allocation, no comparison
 * function. O(6n) rather than O(n log n), and it is the same cost a counting
 * sort would be.
 *
 * WHY SIX AND NOT THREE. The grouping is a property of the RENDER and the two
 * rosters are separate storage, so the order has to be computed across both:
 * every group is walked over members[] and then over remotes[]. The alternative
 * -- two separate 353s, one per roster -- would put the local names before the
 * remote ones regardless of their flags, so a channel with a remote op and a
 * local plain member would render in an order Phase 4 does not specify and
 * 7/Phase 6's acceptance criterion cannot be asserted. Within a group the local
 * list keeps join order and the remote list keeps arrival order, and both are
 * deterministic. */
void send_names_list(server_t *s, conn_t *dst, const chan_t *ch)
{
    const char *const mid[2] = { "=", ch->name };
    /* ASKED ONCE, and this is the whole of the per-destination decision. A 353 is
     * a line to ONE client, and two clients on this node may disagree about
     * `multi-prefix`; the roster is shared, the rendering is not. 005's
     * `PREFIX=(ov)@+` is what says which sigils exist and what they mean, and it
     * is true either way -- multi-prefix changes how MANY are drawn, not which
     * sigils exist. See cap.h. */
    const int multiprefix = cap_enabled(dst, CAP_MULTIPREFIX);
    int produced = 0;

    for (int group = 0; group < 3; group++) {
        /* +1 for the NUL, and the budget is CHAN_NAMES_LINE rather than
         * REPLY_TEXT_MAX so the rendered text always fits reply()'s buffer. */
        char line[CHAN_NAMES_LINE + 1];
        size_t used = 0;

        for (size_t i = 0; i < ch->nmembers; i++) {
            const struct member *m = &ch->members[i];
            /* PER MEMBER, and the buffer is per member rather than hoisted for the
             * reason `write_to_members()` gives for its tag buffer: the shape is
             * decided per destination inside the walk, and a buffer shared across
             * iterations is one whose contents change under a line already queued. */
            char entry[CONN_HOSTMASK_MAX];

            if (m->c == NULL || m->c->nick[0] == '\0') {
                continue;
            }
            if (names_group(m) != group) {
                continue;
            }
            used = names_emit(s, dst, mid, m->flags,
                              names_entry(dst, m->c->nick, m->c->user, m->c->host,
                                          entry, sizeof entry),
                              line, used, &produced, multiprefix);
        }
        for (size_t i = 0; i < ch->nremotes; i++) {
            const chan_remote_t *r = &ch->remotes[i];
            /* AND THE SAME RENDERER FOR A REMOTE MEMBER, which is the whole reason
             * `names_entry()` takes (nick, ident, host) rather than a conn_t: a
             * remote member has no conn_t, so a renderer that read one could not
             * have drawn it at all and the roster would carry two shapes by
             * construction. An empty ident or host (a peer that sent `-` for
             * "not told") still renders as the bare nick rather than as a
             * half-built hostmask. */
            char entry[CONN_HOSTMASK_MAX];

            if (r->nick[0] == '\0' || names_group_flags(r->flags) != group) {
                continue;
            }
            used = names_emit(s, dst, mid, r->flags,
                              names_entry(dst, r->nick, r->user, r->host, entry,
                                          sizeof entry),
                              line, used, &produced, multiprefix);
        }
        if (used != 0) {
            (void)reply(s, dst, "353", mid, 2, "%s", line);
            produced = 1;
        }
    }
    if (produced == 0) {
        /* Exactly one 353, with an empty trailing parameter, for a channel this
         * node has no local members of. That is the honest answer for a channel
         * whose members are all remote -- and on a node that knows a peer's
         * members exist, it is the answer 2.2's servers[] cache makes possible
         * rather than the answer of pretending the channel does not exist. */
        (void)reply(s, dst, "353", mid, 2, "%s", "");
    }
}

/* 366 terminates a names list, and 7/Phase 4's requirement is that it is LAST.
 * It is emitted after every 353 and after the topic numerics, so nothing this
 * node sends in answer to a JOIN, NAMES or TOPIC query can follow it.
 *
 * EVERY 366 on this node goes through here. It took a direct reply() with NULL, 0
 * to answer a bare NAMES on a channel-less node, which is the only way the field
 * could be absent from a 366 -- there is one way to render this numeric and this
 * is it. */
void send_end_of_names(server_t *s, conn_t *dst, const char *channel)
{
    (void)reply(s, dst, "366", (const char *const[]){ channel }, 1,
                "End of /NAMES list");
}

/* ---------------------------------------------------------------------------
 * Topic numerics
 * ---------------------------------------------------------------------------
 * 331 when there is no topic, otherwise 332 then 333. 333 carries the setter AND
 * the time, and both are required: a 333 without a time is not a 333, and a time
 * taken from 3.4's monotonic tick would be meaningless to a client.
 *
 * The parameter placement follows RFC 1459 2.3.1 rather than convenience. 332 is
 *   :<server> 332 <nick> <channel> :<topic>
 * so the channel is a MIDDLE parameter and the topic is the trailing one. The
 * same holds for 331. Putting the channel in the trailing text would be
 * representable and wrong, and a client parsing by position would read the
 * channel as the topic. */
void send_topic(server_t *s, conn_t *dst, const chan_t *ch)
{
    char when[24];

    if (ch->topic[0] == '\0') {
        (void)reply(s, dst, "331", (const char *const[]){ ch->name }, 1,
                    "No topic is set");
        return;
    }
    (void)reply(s, dst, "332", (const char *const[]){ ch->name }, 1, "%s", ch->topic);
    /* 333 is  :<server> 333 <nick> <channel> <setter> <time> :<topic>
     * so the setter AND the time are middle parameters and the topic is
     * repeated as the trailing one. The time is a Unix timestamp in decimal,
     * rendered into a buffer first because it is a middle parameter and
     * message_format() will not format one in place. */
    (void)snprintf(when, sizeof when, "%lld", (long long)ch->topic_when);
    (void)reply(s, dst, "333", (const char *const[]){ ch->name, ch->topic_who, when },
                3, "%s", ch->topic);
}

/* The joiner is told the channel's creation time after its names, as RFC 1459
 * 2.3.1's JOIN reply sequence does. 329 is RPL_CREATIONTIME, so it carries
 * created_at and nothing else -- reusing topic_when for it would be a numeric
 * lying about what it is. */
static void send_creation_time(server_t *s, conn_t *dst, const chan_t *ch)
{
    char stamp[24];

    (void)snprintf(stamp, sizeof stamp, "%lld",
                   (long long)chan_created_at(ch));
    (void)reply(s, dst, "329", (const char *const[]){ ch->name, stamp }, 2,
                "Channel creation time");
}

/* ---------------------------------------------------------------------------
 * 3.1's state-change arm, and the reason every state verb goes through it
 * ---------------------------------------------------------------------------
 * WHY THE FIVE STATE VERBS NO LONGER BROADCAST FOR THEMSELVES.
 *
 * This file used to have its own broadcast() -- the helper above -- and so did
 * core/fanout.c, and the two implemented the same half of 3.1's table with only
 * one of them having a forward arm. That is not tidiness, it is the shape a
 * missing forward takes: a JOIN that reaches every local member and reaches no
 * peer is indistinguishable, from the log, from a JOIN that reached every peer
 * and was refused by all of them. The duplication is where a forward gets lost,
 * so it is gone: these five verbs now resolve their channel, apply the change
 * locally, and hand the EMISSION to fanout_deliver() under
 * FANOUT_STATE_CHANGE, which is the one place that decides "local write, forward
 * to the owner, forward to servers[] -- or all of them".
 *
 * The verb class is NOT a parameter here, and that is what makes "delivered
 * exactly once" structural rather than a convention: fanout_resolve() recorded
 * the class in the resolved target and fanout_deliver() reads it out of that
 * same struct, so a handler cannot resolve a target as a `message` and deliver
 * it as a `state-change`. The row a target took when it was resolved is the row
 * it is delivered by, and there is no second decision in between to disagree
 * with the first.
 *
 * `params` are the CLIENT parameters after the target, which is 3.1's target
 * already resolved and canonicalised. `exclude` is NULL for all five: RFC 1459
 * 2.3.1 has the actor see its own JOIN, PART, TOPIC, MODE and KICK, and
 * excluding anyone would be a second, different rule per verb.
 *
 * THE WHOLE PARAMETER LIST IS DELIVERED, and it used to be possible to say
 * otherwise. There was an `nvisible` argument here, added by C3 to preserve
 * byte-exact Phase 4 assertions -- two of them, both in test_channels.c's
 * test_topic(), on the echo a setter and a second member see. Its only user was
 * TOPIC: the client-facing channel echo was rendered as the bare `:setter TOPIC
 * #chan` with the topic dropped, which RFC 2812 3.3.1 does not describe -- the
 * topic is the trailing parameter of the TOPIC command, and the peer-side STOPIC
 * already carries it. A parameter that exists only to preserve a wrong output is
 * a permanent tax on every future caller in exchange for a one-time migration of
 * our own tests, so it is gone, the echo is RFC-correct, and those two
 * assertions were updated to the RFC form.
 *
 * A verb that ever needs a shorter view wants a DIFFERENT FUNCTION for it,
 * named for the shorter view, rather than a count threaded through the one that
 * routes -- because "how much of this list the client sees" and "where does this
 * line go" are unrelated questions and a caller that can answer the second
 * wrongly by answering the first creatively is a bug waiting for a second verb.
 *
 * IT IS SAFE TO CALL WHEN NOTHING WAS APPLIED LOCALLY. On a CHAN_VERDICT_FORWARD
 * the caller applies nothing -- 2.2 forbids it -- and still calls this, because
 * the non-owned `state-change` row is "forward only, never a local write" and
 * forwarding IS the action. A caller that treated FORWARD as "do nothing" would
 * answer every client on a non-owned channel with success and change nothing
 * anywhere. */
static void deliver_state_change_forms(server_t *s, conn_t *c, chan_t *ch,
                                      const char *verb, const char *prefix,
                                      const fanout_form_t *plain,
                                      const fanout_form_t *extended)
{
    fanout_target_t t;

    if (ch == NULL || !fanout_resolve_cmd(s, c, verb, ch->name, FANOUT_STATE_CHANGE, &t)) {
        /* fanout_resolve() answers 403/401 on failure and the channel is one
         * this node holds, so this is a caller that lost its chan_t. Nothing is
         * counted here: it is a bug, and fanout_resolve() has already said
         * something to the client. */
        return;
    }
    /* `carry` is NULL because this is an ORIGINATING emission: a client sent the
     * command and this node is minting its 2.4 identity at the forward. The
     * relay path is federation/verbs.c, and it hands its own tags to
     * fanout_deliver() instead. */
    (void)fanout_deliver_forms(s, &t, prefix, verb, plain, extended, NULL, NULL);
}

/* The one-shape form, and every state change except JOIN uses it: the extension
 * is a JOIN extension, so there is exactly one caller of the two-shape entry point
 * and this wrapper is what the other five get. */
void deliver_state_change(server_t *s, conn_t *c, chan_t *ch,
                                 const char *verb, const char *prefix,
                                 const char *const *params, int nparams)
{
    const fanout_form_t plain = { params, nparams };

    deliver_state_change_forms(s, c, ch, verb, prefix, &plain, NULL);
}

/* Refuse a JOIN because the connection already holds CONN_MAX_CHANNELS, in the
 * ONE spelling both call sites use.
 *
 * IT IS A HELPER RATHER THAN TWO PRINTFS because the message, the numeric and the
 * observable are one fact: a client has hit the per-connection cap. The cap is
 * checked once in handle_join(), BEFORE a new channel is created, and again in
 * chan_admit(), which is the one place local membership is written and therefore
 * covers an EXISTING channel and resume's re-join. Both refusals must be
 * indistinguishable on the wire and in the log, or an operator reading one cannot
 * tell which check fired.
 *
 * THE CHANNEL NAME GOES THROUGH conn_text_logsafe(). The name is now guaranteed
 * renderable by chan_name_valid() -- that is the point of asking
 * conn_text_display_check() there -- but this line is a diagnostic, and a
 * diagnostic that is safe only because an invariant established elsewhere still
 * holds is the shape this tree has removed from every other log site. The
 * helper withholds rather than filters, so a name with a byte the log cannot
 * carry prints as `-` beside the true held/cap numbers. */
static void refuse_join_too_many(server_t *s, conn_t *c, const char *name)
{
    char shown[CONN_LOG_FIELD_MAX + 1u];

    (void)reply(s, c, "405", (const char *const[]){ name }, 1,
                "You have joined too many channels");
    (void)conn_text_logsafe(shown, sizeof shown, name);
    printf("[observable] chan_join_refused: channel=%s nick=%s held=%zu cap=%d "
           "reason=TOO_MANY_CHANNELS\n",
           shown, c->nick, c->nchans, CONN_MAX_CHANNELS);
}

/* ---------------------------------------------------------------------------
 * JOIN
 * ---------------------------------------------------------------------------
 * The only verb that CREATES a channel, and therefore the only place a creation
 * race can begin.
 *
 * On a single node this node is the first server to see the channel, so it is
 * the origin and there is nothing to race against. chan_new() is called with
 * s->name and s->epoch -- 2.2's (creation_epoch, server_name) pair with both
 * halves real, because server_t's epoch is the per-boot value and it is what
 * makes the tie-break in chan_origin_wins() meaningful across a restart.
 *
* While a peer link that was up is down again, creation itself is refused
* (437, issue #676): this node cannot perform a "another server may already
* own this name" check, because it has not heard from the other node, and
* SBURST only carries what the far side knew before the partition. So the
* live-link race is decided by the tie-break, exercised as the pure function
* it is (7/Phase 4), and the partitioned case never starts -- fail closed
* rather than fork the name.
 */
void handle_join(server_t *s, conn_t *c, const message_t *m)
{
    char store[CHAN_MAX_LIST_ARGS * (CHAN_MAX_NAME + 1u)];
    const char *names[CHAN_MAX_LIST_ARGS];
    int n;

    if (m->nparams != 1) {
        /* Keys (+k) are not implemented, so a second JOIN parameter cannot be
         * honoured: refusing rather than silently joining without checking it. */
        const char *flag = (m->nparams < 1) ? NULL : "TOO_MANY_PARAMS";
        (void)reply_refused(s, c, "JOIN", flag, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* RFC 2812 3.2.1: a bare `JOIN 0` parts the client from every channel it
     * is on. Exact single parameter only, checked before list splitting so
     * `JOIN 0,#x` still takes the list path and refuses the 0 element. */
    if (strcmp(m->params[0], "0") == 0) {
        /* Snapshot: each departure detaches from c->chans while iterating. */
        chan_t *leaving[CONN_MAX_CHANNELS];
        size_t total = c->nchans < CONN_MAX_CHANNELS ? c->nchans
                                                     : CONN_MAX_CHANNELS;
        for (size_t k = 0; k < total; k++) {
            leaving[k] = c->chans[k];
        }
        for (size_t k = 0; k < total; k++) {
            chan_t *ch = leaving[k];
            char prefix[CONN_HOSTMASK_MAX];
            chan_verdict_t verdict = authority_ok(s, c, ch, "PART", 1);
            if (verdict == CHAN_VERDICT_REFUSED) {
                continue;
            }
            if (verdict == CHAN_VERDICT_FORWARD &&
                conn_hostmask(c, prefix, sizeof prefix) != 0) {
                /* No reason: the 0-param PART shape, as in handle_part. */
                deliver_state_change(s, c, ch, "PART", prefix, NULL, 0);
            }
            chan_member_leave(s, ch, c, 1, NULL);
            (void)chan_detach_conn(c, ch);
            (void)chan_dispose_if_empty(s, ch);
        }
        return;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        /* An over-long element fails the split exactly like an empty one, but
         * 461 ("not enough") lies about a name that was too LONG (#677). The
         * bound is CHAN_MAX_NAME, the same one chan_name_valid() enforces, so
         * the scan below and the per-name check cannot disagree about which
         * names fit. Anything else that failed the split -- empty elements,
         * more names than the list holds -- keeps its 461 below. */
        const char *p = m->params[0];
        size_t over_len = 0;

        for (;;) {
            const char *comma = strchr(p, ',');
            size_t len = (comma != NULL) ? (size_t)(comma - p) : strlen(p);

            if (len > (size_t)CHAN_MAX_NAME) {
                over_len = len;
                break;
            }
            if (comma == NULL) {
                break;
            }
            p = comma + 1;
        }
        if (over_len > 0) {
            (void)reply_refused(s, c, "JOIN", NULL, "417", NULL, 0,
                                "Channel name is too long");
            printf("[observable] chan_join_refused: nick=%s reason=name_too_long "
                   "len=%zu max=%d\n",
                   c->nick, over_len, CHAN_MAX_NAME);
            return;
        }
        /* ALSO "TOO FEW", and deliberately NOT a different code: a bare `:` names
         * no channel, so from the client's side it sent nothing usable and
         * NEED_MORE_PARAMS is the true statement. Splitting it would invent a
         * distinction between "no parameters" and "an empty one" that this node
         * has no reason to make. */
        (void)reply_refused(s, c, "JOIN", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;
        int created = 0;
        chan_verdict_t verdict;

        if (!canonical_channel(s, c, "JOIN", names[i], canonical, sizeof canonical)) {
            continue; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            /* THE CAP BOUNDS CREATION AS WELL AS MEMBERSHIP, and this check has
             * to be BEFORE chan_new() for that sentence to be true. The same
             * check remains inside chan_admit() because it is the one place local
             * membership is written and it also has to cover an EXISTING channel
             * and resume's re-join. But a check that lives only there is too late
             * for a channel that does not exist yet: the creation, the registry
             * attach and the topic restore all happen above admission, so every
             * refused JOIN would leave a zero-member chan_t attached for ever --
             * the cap would bound membership while the ghost registry entries
             * kept growing. A repeat JOIN is unaffected: a client already in the
             * channel is short-circuited below, and a channel this node already
             * holds does not take this branch.
             *
             * THE SAME 405 AND THE SAME OBSERVABLE as chan_admit()'s refusal, via
             * one helper, so a client and an operator cannot tell which of the two
             * checks refused them. */
            if (c->nchans >= CONN_MAX_CHANNELS) {
                refuse_join_too_many(s, c, canonical);
                continue;
            }
            /* THE NODE-WIDE CAP (issue #169), and it is checked HERE, before
             * chan_new(), for the same reason the per-connection one is: a
             * check that lived in chan_admit() would be too late, because the
             * creation and the registry attach happen above admission and every
             * refused JOIN would leave a zero-member ghost behind. s->nchan_objs
             * is the count -- no new state, it is the enumeration server.h
             * already keeps -- and only CREATION is refused: a JOIN of a channel
             * the node already holds does not take this branch. 437, the same
             * numeric the attach-failure arm below uses, with an observable that
             * names the reason so a refused creation is findable. */
            if (s->nchan_objs >= SERVER_MAX_CHANNELS) {
                char shown[CONN_LOG_FIELD_MAX + 1u];

                (void)reply(s, c, "437",
                            (const char *const[]){ canonical }, 1,
                            "Cannot create channel: too many channels");
                (void)conn_text_logsafe(shown, sizeof shown, canonical);
                printf("[observable] chan_create_refused: channel=%s nick=%s "
                       "nchan=%zu cap=%d reason=TOO_MANY_CHANNELS\n",
                       shown, c->nick, s->nchan_objs, SERVER_MAX_CHANNELS);
                continue;
            }
            /* PARTITIONED CREATION IS REFUSED (issue #676), and it is checked
             * HERE, after the local caps and before chan_new(), for the same
             * ghost-entry reason those are: a refusal must leave no channel
             * behind. A peer link that was up and is down again means this node
             * cannot rule out a same-name creation on the far side, and the
             * resync has no verdict for that collision -- origin is immutable
             * -- so minting an origin here would fork the name permanently.
             * 437, the orphan rule extended to creation: only CREATION is
             * refused, and a JOIN of a channel the node already holds does not
             * take this branch. The partition test is chan_partitioned() in
             * channel.c, shared with the disposal delay so the two agree. */
            if (chan_partitioned(s) != 0) {
                char shown[CONN_LOG_FIELD_MAX + 1u];

                (void)reply(s, c, "437",
                            (const char *const[]){ canonical }, 1,
                            "Cannot create channel: a peer link is down");
                (void)conn_text_logsafe(shown, sizeof shown, canonical);
                printf("[observable] chan_create_refused: channel=%s nick=%s "
                       "reason=PARTITIONED\n",
                       shown, c->nick);
                continue;
            }
            /* CREATE. The first server to see a channel owns it (2.2), and on a
             * single node that is always this one -- so origin is s->name and
             * creation_epoch is s->epoch, which is the per-boot value server_t
             * already carries. Both halves of 2.2's (creation_epoch,
             * server_name) pair are therefore real from the first channel, which
             * is what makes a later re-key a comparison between two genuine
             * values rather than between a value and a placeholder. */
            ch = chan_new(canonical, s->name, s->epoch);
            if (ch == NULL || server_chan_attach(s, ch) != 0) {
                chan_free(ch);
                (void)reply(s, c, "437", (const char *const[]){ canonical }, 1,
                            "Cannot create that channel");
                continue;
            }
            created = 1;
            printf("[observable] chan_create: channel=%s origin=%s epoch=%llu "
                   "creator=%s\n", ch->name, ch->origin,
                   (unsigned long long)ch->origin_epoch, c->nick);
        }
        /* Authority BEFORE membership and BEFORE the ban check.
         *
         * A refusal that had already added the member would be the exact failure
         * 2.2 warns about, and it would be invisible: the client would be in a
         * channel this node has refused to manage, and nothing would later
         * remove it except its own teardown.
         *
         * The ban check is here and not earlier BECAUSE this node is the origin
         * -- authority_ok() has just established that. A non-owner's modes[] and
         * ban list are a CACHE, and a cache cannot refuse a join: doing so would
         * make this node's divergence from the origin permanent and
         * user-visible, which is the failure the single-writer rule exists to
         * prevent. The authority check is therefore what makes the enforcement
         * below legitimate rather than a cache pretending to enforce. */
        /* A FORWARD VERDICT DOES NOT STOP A JOIN, and this is the ONE exception
         * to "an origin-requiring state change on a non-owned channel applies
         * nothing here", and the exception is the whole of JOIN's meaning.
         *
         * A JOIN is a LOCAL MEMBERSHIP FACT: this node has just decided that one
         * of its own clients is on a channel, and that fact is true whether or
         * not this node owns the channel. The channel's STATE -- its topic, its
         * modes, who is an op -- belongs to the origin, and a JOIN adds none of
         * those except the creator's +o. So the local half runs (chan_add_member,
         * the broadcast, the joiner's own numerics) AND the SJOIN is forwarded,
         * and the origin is the one that decides what the membership means.
         *
         * WRITING THIS AS THE GENERAL RULE INSTEAD GIVES AN EMPTY PEER ROSTER.
         * If a JOIN on a non-owned channel applied nothing locally, then a user
         * who joins a channel their own server does not own would not be a
         * member of it as far as 353 is concerned, would not receive that
         * channel's messages, and the SJOIN that would have told the origin
         * about them would never be sent -- because the forwarding is part of
         * the same call. The user would be on a channel they cannot see and
         * cannot talk in, and the only trace would be their own 366. That is
         * the single most visible way to get this wrong, which is why it is
         * spelled out at the call rather than left to the general rule. */
        verdict = authority_ok(s, c, ch, "JOIN", 1);
        if (verdict == CHAN_VERDICT_REFUSED) {
            if (created != 0) {
                (void)chan_dispose_if_empty(s, ch);
            }
            continue; /* 437 already sent; nothing has been touched */
        }
        if (chan_banned(ch, c->nick, c->user, c->host)) {
            (void)reply_refused(s, c, "JOIN", NULL, "474",
                                (const char *const[]){ ch->name }, 1,
                                "Cannot join channel (banned)");
            printf("[observable] chan_ban_enforced: channel=%s nick=%s host=%s\n",
                   ch->name, c->nick, c->host);
            if (created != 0) {
                (void)chan_dispose_if_empty(s, ch);
            }
            continue;
        }
        if (chan_find_member(ch, c) != NULL) {
            /* A repeat JOIN is not an error and it is answered with the topic,
             * the names and 366, so a client that re-issues JOIN (which several
             * do on reconnect) can still learn the roster. The membership is
             * left exactly as it is, flags included: a repeat JOIN must not
             * silently revoke an operator's +o. */
            printf("[observable] chan_join_repeat: channel=%s nick=%s\n", ch->name,
                   c->nick);
            send_topic(s, c, ch);
            send_names_list(s, c, ch);
            send_end_of_names(s, c, ch->name);
            continue;
        }

        if (created != 0) {
            (void)server_topic_restore(s, ch);
        }
        /* The member goes on the channel, the channel goes on the connection,
         * and the mesh is told. All three are ONE function -- chan_admit() --
         * and Phase 9 is why that matters: core/resume.c re-joins a client to
         * its channels from a window, and a restore that had its own copy of
         * this sequence would be a second place deciding what "this client is
         * now a member" means. See chan_admit() for the extraction. */
        if (chan_admit(s, c, ch, (created != 0) ? CHAN_MEMBER_OP : 0u) == 0) {
            printf("[observable] chan_join: channel=%s nick=%s members=%zu "
                   "origin=%s\n",
                   ch->name, c->nick, ch->nmembers, ch->origin);
        } else if (created != 0) {
            (void)chan_dispose_if_empty(s, ch);
        }
    }
}

/* ---------------------------------------------------------------------------
 * chan_admit() -- the ONE definition of "this client is now a member here"
 * ---------------------------------------------------------------------------
 *
 * Four things, in this order, and the order is the correctness argument:
 *
 *   1. THE MEMBER RECORD AND THE CONNECTION'S OWN LIST. Neither derives from the
 *      other -- a channel outlives a connection and a connection outlives a
 *      channel -- so both are written, and a failure of the second ROLLS BACK
 *      the first. A member record with no matching entry in conn_t::chans would
 *      never be removed on teardown: a leak and a dangling pointer, and the two
 *      indexes disagreeing is the failure mode server.h warns about.
 *
 *   2. THE JOIN ECHO, to every member INCLUDING the joiner and BEFORE the
 *      joiner's own numerics, so a client watching the channel sees the join
 *      arrive before the roster that includes it. It goes through 3.1's table
 *      rather than through broadcast(): on an OWNED channel this writes to the
 *      members and forwards to servers[] UNION the ESTABLISHED links, and on a
 *      non-owned one it forwards to the owner without a second local write --
 *      the local one already happened, and the non-owned row is "forward ONLY"
 *      precisely so that the ORIGIN is the node that emits to its members.
 *
 *   3. THE AWAY-NOTIFY ANNOUNCEMENT, IF THE JOINER IS AWAY. `away-notify` says a
 *      user joining with an away message set is announced to the users it shares the
 *      channel with. It goes out AFTER the JOIN echo and BEFORE the joiner's own
 *      numerics, which is the order a client renders: first that the person arrived,
 *      then that they are away, then the joiner's own view of the channel.
 *
 *      IT IS A SEPARATE EMISSION AND NOT ANOTHER PARAMETER, and the specification
 *      requires that rather than this file preferring it. The two messages have
 *      different grammars and different audiences: the extended JOIN is
 *      `:nick!user@host JOIN #chan <account> :<realname>` and is a statement about
 *      the roster, while the announcement is `:nick!user@host AWAY #chan [:message]`
 *      and is a statement about ONE user's away STATE. Folding the away message into
 *      the JOIN would make a line a client parses as a roster carry a fourth field,
 *      and would mean every member learned the away message whether or not it
 *      negotiated `away-notify` -- which is exactly the unsolicited-notification
 *      defect Phase 10.8a's gate exists to prevent.
 *
 *      THE JOINER IS EXCLUDED, for msg_verbs.c's notify_away() reason: a user should
 *      not be sent an AWAY message about their own away status, and on this node they
 *      have `301` and `305` for that. It is `exclude` rather than the gate -- a
 *      different question from "did this destination ask?", which is why both exist.
 *
 *      GATED ON `c->away[0] != '\0'` AND NOTHING ELSE. There is no "is anybody
 *      currently away" question to ask: `conn_t::away` exists on every connection from
 *      accept(), so the only question is whether THIS joiner has a message, and a
 *      joiner with none produces no line at all. A third shape -- an `AWAY` with an
 *      empty trailing parameter -- would render as `AWAY #chan :`, which 3.2 does not
 *      represent in a non-final position and the formatter would refuse.
 *
 *   4. THE JOINER'S OWN FOUR NUMERICS, in the order a client parses them:
 *      topic, names, creation time, end of names. This is what makes a JOIN
 *      self-describing, and it is why a restore can hand a client back its
 *      channels without the client having to ask for anything.
 *
 * RETURNS 0 when the member is on the channel and has been told about it, and
 * -1 with a 437 already sent otherwise. A caller that wants to count its own
 * successes uses the return value rather than re-deriving it.
 *
 * WHY IT IS EXPOSED. core/resume.c's restore is a JOIN that nobody typed, and
 * the alternative -- a resume that re-implemented the sequence -- would be a
 * second definition of local membership, with its own ban check to forget and
 * its own idea of which mesh to tell. Both callers ask the same question of the
 * same channel, so both ask it here. */
static void announce_join_away(server_t *s, conn_t *c, chan_t *ch, const char *prefix);

int chan_admit(server_t *s, conn_t *c, chan_t *ch, unsigned flags)
{
    char prefix[CONN_HOSTMASK_MAX];
    /* THE TWO JOIN SHAPES, BUILT ONCE PER ADMISSION.
     *
     * `plain` is RFC 2812 3.3.1's JOIN echo, with no parameters at all -- the
     * channel name is the target, which fanout prepends. `extended` adds the two
     * parameters `extended-join` defines:
     *
     *   :nick!user@host JOIN #chan <account> :<realname>
     *   :nick!user@host JOIN #chan * :<realname>
     *
     * THE ACCOUNT IS `<account>` OR `*` AND NEVER EMPTY, and the rule is
     * account_logged_in() rather than `c->account[0]`, because the `*` form is the
     * specification's way of saying "this user has not logged in to an account
     * prior to channel ingress" -- and on a node with NO REGISTRY nobody ever is,
     * so `*` is not an absence of information here, it is the information. A node
     * that emitted an empty account field would be sending a parameter that reads
     * as an empty one, which is the exact confusion 2.1.1's invariant exists to
     * prevent, moved from a struct field to the wire.
     *
     * THE REALNAME IS `c->realname` AND MAY BE EMPTY, which is legal: it is the
     * trailing parameter, 3.2 colons it, and an empty one renders as a bare `:`
     * -- the one representation of "no text here". USER fills the field at
     * registration and a client that sent none has an empty realname, which is a
     * fact about the client rather than a limit this node imposes.
     *
     * BOTH LIVES ARE IN THIS FRAME, which is the same reason the hostmask is: the
     * emission happens inside fanout, so the values have to outlive the call that
     * builds them. */
    const char *extended_params[2];
    char acct_token[CONN_MAX_ACCOUNT + 2];
    fanout_form_t plain;
    fanout_form_t extended;

    if (s == NULL || c == NULL || ch == NULL) {
        return -1;
    }
    /* THE PER-CONNECTION CHANNEL CAP, AND IT IS CHECKED HERE BECAUSE THIS IS THE
     * ONE PLACE LOCAL MEMBERSHIP IS CREATED. Both `JOIN` and resume's re-join
     * come through chan_admit(), so both are bounded by the same number and a
     * resume cannot rejoin what a JOIN would have been refused -- see
     * CONN_MAX_CHANNELS for the number and the argument behind it.
     *
     * 405 is RFC 1459's ERR_TOOMANYCHANNELS: the number the specification defines
     * for exactly this, and one no other site on this node emits, so a client
     * cannot confuse it with 437 ("cannot join channel") or 474 ("banned").
     *
     * THE COUNT IS ON THE CONNECTION AND NOT ON THE CHANNEL, and that is
     * deliberate: the bound is about how much of the node's shared channel
     * registry one connection may occupy, and the registry is what a JOIN
     * consumes. A channel the client is ALREADY in is not refused -- chan_
     * attach_conn() reports it as already listed and this check is above that
     * resolution, so a client at the cap may still PART and re-JOIN. */
    if (c->nchans >= CONN_MAX_CHANNELS) {
        refuse_join_too_many(s, c, ch->name);
        return -1;
    }
    if (chan_add_member(ch, c, flags) != 0) {
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    if (chan_attach_conn(c, ch) != 0) {
        (void)chan_remove_member(ch, c);
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    memcpy(acct_token, account_logged_in(c) != 0 ? c->account : "*",
           strlen(account_logged_in(c) != 0 ? c->account : "*") + 1u);
    /* NEITHER LIST CARRIES THE CHANNEL NAME, because fanout prepends the resolved
     * target: 3.1's row is "write the target, then the caller's parameters", and
     * putting the name in the caller's list as well would render it twice. That is
     * why the plain list is EMPTY rather than holding one entry. */
    extended_params[0] = acct_token;
    extended_params[1] = c->realname;
    plain.params = NULL;
    plain.nparams = 0;
    extended.params = extended_params;
    extended.nparams = 2;
    deliver_state_change_forms(s, c, ch, "JOIN", prefix, &plain, &extended);
    if (chan_origin_is_self(s, ch) == 0) {
        /* The actor's own echo is not a local write (3.1): the non-owned row
         * forwarded without addressing anyone local, so say it to the joiner. */
        const char *echo[1];

        echo[0] = ch->name;
        (void)send_line(s, c, prefix, "JOIN", echo, 1);
    }

    announce_join_away(s, c, ch, prefix);
    send_topic(s, c, ch);
    send_names_list(s, c, ch);
    send_creation_time(s, c, ch);
    send_end_of_names(s, c, ch->name);
    return 0;
}

/* The AWAY-NOTIFY announcement for a user who JOINED while away. Called only from
 * chan_admit(), immediately after the JOIN echo, and the header above carries the
 * argument for its position, its separate shape and its two exclusions.
 *
 * IT IS NOT msg_verbs.c's notify_away() CALLED DIFFERENTLY, and the reason is the
 * count again: notify_away() walks `c->chans` and emits once per channel, which is
 * right for the away STATE CHANGE -- its line names the channel, so a member of three
 * shared channels gets three lines about three different channels, all of them true.
 * Here there is exactly one channel and one fact, so the walk would be a loop of one
 * and the helper would have grown a parameter for a case it does not have. One
 * `fanout_deliver_local_gated()` call is the whole of it, and the gate and the
 * liveness question are inside fanout.c where every other emission asks them.
 *
 * THE PARAMETER LIST IS BUILT HERE, IN THE CALLER'S FRAME, because the emission
 * happens inside fanout: `c->away` is read there and `message_format()` renders
 * there, so a pointer into this frame has to outlive this function, and it does
 * because the call is synchronous. That is the same reason chan_admit()'s extended
 * JOIN parameters are locals. */
static void announce_join_away(server_t *s, conn_t *c, chan_t *ch, const char *prefix)
{
    const char *params[1];
    fanout_form_t plain;
    fanout_target_t t;
    int delivered;

    if (c->away[0] == '\0') {
        return; /* not away: the specification announces an AWAY MESSAGE, not a JOIN */
    }
    if (fanout_resolve(s, c, ch->name, FANOUT_MESSAGE, &t) == 0) {
        return; /* a chan_t this node no longer holds: nothing to address */
    }
    params[0] = c->away;
    plain.params = params;
    plain.nparams = 1;
    /* The class is `message` and not `state_change` for the reason notify_away()
     * gives: this is not a change to the channel's state -- the roster already says
     * the user is on it -- it is an observation about that user. The class decides
     * the forward arm, and the local-only entry point has none to decide. */
    /* The joiner IS excluded from the join-time announcement: passing `c` here
     * is the correct value. Changing this argument to NULL is the mutation
     * test_away_notify.c catches (it would deliver the joiner's own AWAY back
     * to itself). */
    delivered = fanout_deliver_local_gated(s, &t, prefix, "AWAY", &plain, NULL,
                                            cap_gate_away_notify, NULL, c);
    printf("[observable] away_notify: nick=%s join=1 channel=%s recipients=%d\n",
           c->nick, ch->name, delivered);
}

/* handle_part(): split out for #543 (TU-49) into core/chan_verbs_part.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_topic(): split out for #543 (TU-50) into core/chan_verbs_topic.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_names(): split out for #543 (TU-51) into core/chan_verbs_names.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_list(): split out for #543 (TU-46) into core/chan_verbs_list.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_kick(): split out for #543 (TU-52) into core/chan_verbs_kick.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* ---------------------------------------------------------------------------
 * MODE
 * ---------------------------------------------------------------------------
 * Three forms, by arity, and they are different operations:
 *
 *   MODE #chan                 a query -> 324 plus 329, answered from modes[].
 *   MODE #chan +o nick         a member privilege change.
 *   MODE #chan +b mask         a ban, which 2.2 reserves to the origin.
 *
 * The ban path is what makes channel-mode AUTHORITY visible rather than
 * asserted, and the shape is deliberate:
 *
 *   1. 442 first (in resolve_joined): membership is the precondition for having
 *      any standing in a channel at all.
 *   2. 461/472 for a malformed mode string, then 482 for a non-operator.
 *      Privilege is asked before evaluation AND before routing, so on an
 *      orphaned channel a non-operator is told it lacks privilege (482)
 *      rather than being told the origin is unreachable (437).
 *   3. The single-writer check, because +b IS a state change. 437 is reserved
 *      for the case the checks above all passed and the origin is unreachable.
 *   4. chan_mode_is_origin_only() -- and it is checked as a SEPARATE question
 *      from step 3, because they are different questions. Step 3 asks whether
 *      this node may MANAGE the channel; this asks whether it may EVALUATE this
 *      particular mode. 2.2's list is exactly {b, e, I}, and the two only come
 *      apart once Phase 6's forward path exists.
 *
 * +o and +v are NOT origin-only: they are prefix modes, they are in 005's
 * PREFIX=(ov)@+, and relaying a membership fact is forwarding rather than
 * deciding. That is exactly why 2.2 names three modes and not five.
 *
 * Anything this node does not evaluate is answered 472 ERR_UNKNOWNMODE. 004
 * advertises b,k,l,imnpst and this node acts on b alone; answering 421 would be
 * a lie about the verb, and silence is the failure mode 4.4's numerics exist to
 * prevent. 472 says "that mode character means nothing to me", which is true.
 */
/* ---------------------------------------------------------------------------
 * ONE RENDERING OF A REFUSED MODE CHARACTER, shared by both 472 sites
 * ---------------------------------------------------------------------------
 * The two 472s below print the character they refused twice: once as the numeric's
 * `<char>` parameter and once in the observable line's `reason=` field. Both copies
 * used to be the client's raw byte, and both had to change together -- which is the
 * argument for this helper rather than two copies of the same four lines. The field
 * list and the placeholder MUST NOT VARY between the two sites (see each site's
 * comment for why the field list matters), and the only way to make two copies of a
 * rule agree is not to have two copies.
 *
 * WHY A HELPER AND NOT A FLAG, since the previous version's comment argued the two
 * sites should stay separate: that argument was about the CHARACTER being a
 * different expression at each site (the mode string's first byte up there, one byte
 * of a mode string here) and it is still true. It was never about the rendering.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE CLIENT GETS, and why it is `?`
 * ---------------------------------------------------------------------------
 * `?` -- one byte, printable ASCII, and not a mode character this node knows.
 *
 *   - ONE BYTE, because the field is the RFC's `<char>` and a client that parses 472
 *     by position reads exactly one character out of it. A two-character placeholder
 *     would move every field after it, and an empty one would remove it.
 *   - PRINTABLE, because the whole point is that a terminal must never see the byte.
 *   - NOT `+` OR `-`, because those are the two characters whose meaning the mode
 *     grammar gives, and a client reading `472 <client> -` would conclude the node
 *     rejected a sign rather than a mode.
 *   - NOT IN `004`/`005`'s CHANMODES, so a client that compares the refused
 *     character against what this node advertises finds nothing it claims to
 *     understand -- which is the truth. The branch is reached BECAUSE the character
 *     is not a mode this node evaluates, so no character it could print here would
 *     name a mode this node knows.
 *
 * The cost, stated rather than assumed: a client that sent a printable mode this node
 * does not evaluate is answered with that character, exactly as before, and a client
 * that sent a control byte is answered with `?` and cannot tell from the wire WHICH
 * byte it was. That is deliberate -- the byte is not going back onto a terminal, and
 * the log is where the diagnosis belongs.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE OPERATOR GETS: Rule 1, MEASURED
 * ---------------------------------------------------------------------------
 * `conn_text_logsafe()` and `conn_text_bad_count()` on the one-byte string, and the
 * length beside them. The value has no consumer beyond the line itself, so it is
 * WITHHELD rather than filtered: `reason=-` says "there was a value and it was not
 * safe to print", `reason_len=1` says how long it was, and `reason_byte=0x..` says
 * which byte it was -- all three printable, and all three needed to tell the three
 * withheld cases apart (`-` also means absent, and also means too long for the
 * field).
 *
 * COST: one pass over one byte, on a path that runs once per refused mode character.
 */
static char mode_refusal_wire(char mode)
{
    const unsigned char u = (unsigned char)mode;

    /* `conn_byte_is_bad()` alone would be enough for 0x00-0x1f and DEL, but the
     * placeholder also has to be printable in the sense the wire cares about, which
     * excludes 0x7f and the 0x80-0xff range -- and a byte above 0x7e is exactly what
     * `conn_text_logsafe()` refuses. One range, stated once, rather than the
     * predicate plus a second opinion about DEL. */
    return ((u >= 0x21u && u <= 0x7eu)) ? mode : '?';
}

static void mode_refusal_render(char mode, char *wire, size_t wire_cap,
                                char *shown, size_t shown_cap, size_t *len_out,
                                size_t *bad_out)
{
    char raw[2];

    raw[0] = mode;
    raw[1] = '\0';
    (void)snprintf(wire, wire_cap, "%c", mode_refusal_wire(mode));
    (void)conn_text_logsafe(shown, shown_cap, raw);
    if (len_out != NULL) {
        *len_out = strlen(raw);
    }
    if (bad_out != NULL) {
        *bad_out = conn_text_bad_count(raw);
    }
}


/* ---------------------------------------------------------------------------
 * ONE REFUSAL ANSWER FOR `MODE #chan +b`, and it is a FUNCTION because there are
 * four of them and they differ in NUMERIC, in ARITY and in REASON (#133).
 * ---------------------------------------------------------------------------
 *
 * WHY FOUR AND NOT ONE. `chan_ban_add()` used to return -1 for an empty mask, an
 * over-long mask, a full list and an allocation failure, and every one of those
 * was answered 478 ERR_BANLISTFULL. That numeric's RFC 2812 5.1 text is
 * "channel :Cannot list bans, list is full", so the two bad-mask cases told a
 * client its ban list was full when the list was empty and the mask was the
 * problem. The recovery that implies -- remove a ban -- does not exist for a
 * client that sent nothing, which is why this is a wire behaviour and not a
 * diagnostic nit: `MODE #chan +b` with no mask at all is a plausible client bug
 * and it is the more likely of the two.
 *
 * THE NUMERICS, AND WHERE EACH ONE COMES FROM:
 *
 *   461 ERR_NEEDMOREPARAMS  an empty mask. RFC 2812 5.1's field list is
 *       "<command> :Not enough parameters", and this node already answers 461
 *       with that text on this very verb for a genuinely too-few-params MODE
 *       (see the arity arms above). Sending the same numeric and the same text
 *       for "you sent the parameter and it was empty" is the smallest truthful
 *       answer available: nothing in 2812 names the empty-string case, and
 *       inventing a numeric nobody has would be worse than reusing one this node
 *       already means.
 *
 *   417 ERR_INPUTTOOLONG  an over-long mask. What chan_verbs.c already answers
 *       for an over-long KICK reason, and what `reply_refused(..., "417", ...)`
 *       exists for. A value past a documented bound is precisely its subject.
 *
 *   478 ERR_BANLISTFULL  the full list, and ONLY this. RFC 2812 3.3.4's own name
 *       for the condition. THIS USED TO BE 696, and two things were wrong with
 *       that: 696 is not in RFC 2812 5.1 at all (it is RPL_ENDOFMODES from the
 *       historical MODE draft, an end-of-list marker with no meaning about
 *       capacity, so a client holding it rendered "End of MODE list" for a
 *       refusal to add a ban and a client not holding it showed nothing at all),
 *       and the arity was wrong even for its own numeric -- it sent the channel
 *       and nothing else, so the <char> the RFC's field list names was absent and
 *       a client parsing positionally read the channel name as the mode letter.
 *       Both are why the field list below sends the channel AND the letter.
 *
 *   368, NOT A NUMERIC. An allocation failure or a copy failure is not the
 *       client's doing and is not a condition any numeric describes, so it is
 *       answered 368 -- "Ban mask is not set on this channel" -- which is true,
 *       actionable in the only sense that matters (the ban did not take, and the
 *       client can retry), and is the same numeric the `-b` arm already sends for a
 *       mask that was not there. It is the fourth distinct answer, which is the
 *       point: collapsing it into one of the other three would put a number on the
 *       wire that describes a condition the client cannot act on.
 *
 * ARITY, WHICH IS NOT THE SAME FOR ALL THREE NUMERICS, and that is checked by
 * reply.c's own rule rather than by this function's memory of it. 478 is the only
 * one whose RFC field list names the mode letter, so only it sends two parameters.
 * 461 and 417 name the command and not the argument, so they send none -- sending
 * them the mask would put a value in a field the RFC does not define, and reply.c
 * counts rendered lines against the budget on what it is given.
 *
 * THE LOG, AND WHY IT NAMES A REASON RATHER THAN A COUNT -- including the answer
 * to "what should this be counted as", which is NOBODY, and why.
 *
 * IT IS NOT `n_reply_refused`. That counter is incremented by reply.c's private
 * `refuse()`, which fires when a reply this node tried to DELIVER could not be
 * delivered at all; reply.h says so and calls it a bug report rather than a
 * metric. `reply_refused()` -- the wrapper the 461 and 417 arms above use -- does
 * not touch it, and this node holds it at zero. So a malformed mask is correctly
 * absent from that counter, and the two are not in competition.
 *
 * IT IS NOT `n_burst_refused` either: that is the peer's burst, which has no
 * client path into it.
 *
 * AND IT IS NOT A NEW COUNTER IN THIS CHANGE. This node has no counter for a
 * client-caused refusal, which is the real gap the issue names, and adding one is
 * not a one-line change: a counter on `server_t` is published in the single
 * `[fixture] stats ...` line that every integration test parses and several of
 * them assert against, so its shape is a contract with the suite rather than with
 * this function. What this pass does instead is make the refusal OBSERVABLE on the
 * node's own output with a `reason=` field naming which of the four conditions
 * occurred, so an operator can tell a malformed request from a full list and a
 * test can assert on it. That is a record rather than an aggregate, and the
 * difference is worth being explicit about: an operator asking "how many malformed
 * masks did this node see today" still cannot answer it.
 *
 * THE MASK IS MEASURED rather than printed, per connection.h's Rule 1 --
 * `conn_text_logsafe()` and `conn_text_bad_count()`, so a mask made mostly of
 * control characters is reportable without a control character being printed. This
 * is the same shape as the `who:` line in msg_verbs.c, which is the other place a
 * least-constrained client parameter is logged.
 */
static void ban_refusal(server_t *s, conn_t *c, chan_t *ch, const char *mask,
                        chan_ban_verdict_t verdict)
{
    char shown[CONN_LOG_FIELD_MAX + 1u];

    (void)conn_text_logsafe(shown, sizeof shown, mask);
    /* SWITCHED THROUGH AN int, and that is this tree's established shape for an
     * enum switch rather than a choice: `-Wswitch-enum` and
     * `-Wcovered-switch-default` together forbid both "every enumerator listed"
     * and "every enumerator listed plus a default", which between them would make
     * an exhaustive switch on a named enum unwritable. Casting to int satisfies
     * both and leaves `default:` covering the two values a caller must not pass --
     * see fanout.c's fanout_deliver(), which switches the same way for the same
     * reason. */
    switch ((int)verdict) {
    case CHAN_BAN_EMPTY:
        /* `INVALID_PARAMS` and not a code of this pass's own: reply.c's map sends
         * 461 to `NEED_MORE_PARAMS`, and an OVERRIDE wins over the table -- so an
         * override here is a second answer for a numeric that already has one.
         * `INVALID_PARAMS` is the IRCv3 reply-code registry's own code for a
         * parameter this node will not accept, it is what chan_verbs.c already
         * passes for INVITE's 461, and it is what a `standard-replies` client
         * switches on. A code invented for this pass would be an unregistered code
         * this node made up, which reply.c's own note says is the thing that marker
         * exists to avoid confusing. */
        (void)reply_refused(s, c, "MODE", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] chan_ban_refused: channel=%s by=%s reason=empty_mask "
               "mask=%s mask_len=%zu mask_bad_bytes=%zu nbans=%zu\n",
               ch->name, c->nick, shown, strlen(mask), conn_text_bad_count(mask),
               ch->nbans);
        return;
    case CHAN_BAN_TOO_LONG:
        /* NULL override, so the map's own `ERR_INPUTTOOLONG` is used -- which is
         * what the 417 KICK-reason arm above does, and a mask past a bound and a
         * reason past a bound are the same condition. */
        (void)reply_refused(s, c, "MODE", NULL, "417", NULL, 0,
                            "Input line was too long");
        printf("[observable] chan_ban_refused: channel=%s by=%s reason=mask_too_long "
               "mask=%s mask_len=%zu mask_bad_bytes=%zu max_mask=%d\n",
               ch->name, c->nick, shown, strlen(mask), conn_text_bad_count(mask),
               CHAN_MAX_BAN);
        return;
    case CHAN_BAN_FULL:
        (void)reply(s, c, "478", (const char *const[]){ ch->name, "b" }, 2,
                    "Channel list is full");
        printf("[observable] chan_ban_refused: channel=%s by=%s "
               "reason=ban_list_full nbans=%zu max=%d\n",
               ch->name, c->nick, ch->nbans, CHAN_MAX_BANS);
        return;
    case CHAN_BAN_NOMEM:
        /* The store could not take the mask: the array would not grow, or a copy
         * this function's own length bound says cannot fail did. Not the client's
         * doing and not a condition any numeric describes. */
    default:
        /* CHAN_BAN_OK is in here too and NOT as a listed arm, because a caller
         * that hands it here has a bug and this function must still be a total
         * function. `-Wcovered-switch-default` objects to a `default` beside an
         * exhaustive list, so the two arms a caller cannot reach are the two this
         * one covers rather than the two it names. The comment on the enum says OK
         * is tested by the caller; this is what happens if that ever stops being
         * true. */
        (void)reply(s, c, "368", (const char *const[]){ ch->name, mask }, 2,
                    "Ban mask is not set on this channel");
        printf("[observable] chan_ban_refused: channel=%s by=%s reason=not_stored "
               "mask=%s mask_len=%zu mask_bad_bytes=%zu nbans=%zu\n",
               ch->name, c->nick, shown, strlen(mask), conn_text_bad_count(mask),
               ch->nbans);
        return;
    }
}

/* ---------------------------------------------------------------------------
 * 367 RPL_BANLIST and 368 RPL_ENDOFBANLIST: `MODE <channel> +b` with no mask.
 * ---------------------------------------------------------------------------
 * RFC 2812 3.3.2 names this as a QUERY and not a change, in the same sentence
 * that defines the whole verb: "If the <modestring> parameter is given with a
 * list of mode arguments, then a list of mode arguments is returned for channel
 * modes b, e and I. ... +b, +e and +I are always passed to the server." So
 *
 *     MODE #chan +b          -> one 367 per mask, then 368
 *     MODE #chan -b          -> the same list, because the RFC does not
 *                               distinguish the signs for the LIST form
 *
 * and the mask is absent in both, which is the whole signal. Before this phase a
 * `+b` with no mask was answered 461 ERR_NEEDMOREPARAMS, which is the exact
 * opposite of the RFC: the client did not send too few parameters, it sent the
 * form that ASKS the question, and the answer it got was "you sent too few
 * parameters".
 *
 * WHY THAT MATTERS TO A REAL CLIENT, and it is why this is not a cosmetic fix.
 * irssi, weechat and hexchat all send `MODE <channel> b` when a window is
 * opened, precisely so the client's ban list is populated before the user
 * touches it. A node that answers 461 to that query leaves the client showing an
 * error in a status window and an EMPTY ban list, on a channel where the node is
 * enforcing bans perfectly well -- and a user who then types `/mode +b` on a mask
 * that is already set is told nothing useful, because there was never a list to
 * check against. The ban feature worked and was unreadable, which is the same
 * failure Phase 5 named for 301.
 *
 * THE GRAMMAR, from RFC 2812 5.1:
 *
 *   367 RPL_BANLIST  "<channel> <banmask>"
 *   368 RPL_ENDOFBANLIST "<channel> :End of channel ban list"
 *
 * so 367 has NO trailing field and 368 has one. 367 is emitted with an empty
 * trailing parameter -- `reply()` takes a trailing parameter by construction and
 * `message_format()` renders an empty one as a bare ':' -- which is the same
 * choice `send_names_list()` already makes for the empty 353, and the same
 * reason: a value in the final position is always representable and never has to
 * be invented. A 367 that appended the mask a second time in the text would be
 * one field the RFC does not have, on a numeric some clients read positionally.
 *
 * AND ONE 367 PER MASK, ALWAYS, WITH NO CHUNKING. The mask is a MIDDLE parameter
 * here, so the only bound is the wire line cap and reply() refuses rather than
 * reshapes (3.2). A mask is CHAN_MAX_BAN (63) bytes and a channel name is
 * CHAN_MAX_NAME (63), so one 367 is about 140 bytes -- inside IRC_MAX_LINE with
 * room for a second one, and well inside REPLY_TEXT_MAX. The list cannot be
 * chunked the way a 353 or a 319 is, and does not need to be: RFC 2812 3.3.4
 * permits 367 to repeat, but a loop over a bounded array of bounded strings
 * cannot produce a value the formatter refuses, so nothing is dropped and
 * nothing is truncated.
 *
 * THE AUTHORITY QUESTION IS NOT ASKED AGAIN. This is a QUERY about a channel the
 * caller has already been shown to be on (resolve_joined() sent 442 otherwise) and
 * whose modes 324 already answered from the same array -- and 324 is answered to
 * any member, not only to an operator. Asking "are you an operator" here would
 * make the ban list LESS readable than the mode list beside it, and RFC 2812
 * 3.3.2 attaches no privilege requirement to reading a list that the server is
 * publishing anyway. The masks in `ch->bans` are this node's own state and 2.2
 * puts the origin's ban list in the same struct every member's 353 is drawn from.
 */
static void send_ban_list(server_t *s, conn_t *dst, const chan_t *ch)
{
    for (size_t i = 0; i < ch->nbans; i++) {
        if (ch->bans[i].mask[0] == '\0') {
            continue;
        }
        (void)reply(s, dst, "367", (const char *const[]){ ch->name, ch->bans[i].mask },
                    2, "%s", "");
    }
    /* 368 ALWAYS, including for an empty list, and that is RFC 2812 3.3.4's rule
     * for this family rather than an inference from 353's: "a server is required
     * to send the list back using the RPL_BANLIST and RPL_ENDOFBANLIST messages
     * ... After the banmasks have been listed ... a RPL_ENDOFBANLIST MUST be
     * sent." A client that asked for the list and got no terminator is a client
     * still waiting for it, and the empty-list case is precisely the one where
     * silence and "no bans" are indistinguishable. */
    (void)reply(s, dst, "368", (const char *const[]){ ch->name }, 1,
                "End of channel ban list");
    printf("[observable] chan_ban_list: channel=%s by=%s masks=%zu\n", ch->name,
           dst->nick, ch->nbans);
}
/* MODE <nickname>: RFC 2812 3.1.5 answers a user-mode query with 221, a bad
 * flag with 501 and another user's modes with 502. The only user mode this
 * node evaluates is +i, kept on conn_t::invisible; every other letter is 501
 * rather than a silent accept, so a 221 never disagrees with the bit. The
 * letters are validated before the bit is touched, so a `+iz` changes nothing.
 * An empty or sign-only modestring is 461, the same too-FEW shape the channel
 * path answers it with. Surplus parameters are ignored, not refused: #662
 * owns MODE's arity and this path must not pre-empt it. */
static void handle_user_mode(server_t *s, conn_t *c, conn_t *who,
                             const message_t *m)
{
    const char *ms;
    int plus;

    if (who != c) {
        (void)reply(s, c, "502", NULL, 0, "Cannot change mode for other users");
        printf("[observable] user_mode: nick=%s target=%s reason=other\n",
               c->nick, who->nick);
        return;
    }
    if (m->nparams < 2) {
        (void)reply(s, c, "221", NULL, 0, "%s", c->invisible ? "+i" : "+");
        printf("[observable] user_mode: nick=%s modes=%s query=1\n", c->nick,
               c->invisible ? "+i" : "+");
        return;
    }
    ms = m->params[1];
    if (ms[0] != '+' && ms[0] != '-') {
        (void)reply(s, c, "501", NULL, 0, "Unknown MODE flag");
        printf("[observable] user_mode: nick=%s reason=no_sign\n", c->nick);
        return;
    }
    if (ms[1] == '\0') {
        (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    for (size_t i = 1; ms[i] != '\0'; i++) {
        if (ms[i] != 'i') {
            (void)reply(s, c, "501", NULL, 0, "Unknown MODE flag");
            printf("[observable] user_mode: nick=%s reason=bad_flag\n", c->nick);
            return;
        }
    }
    plus = (ms[0] == '+');
    c->invisible = plus;
    (void)reply(s, c, "221", NULL, 0, "%s", plus ? "+i" : "+");
    printf("[observable] user_mode: nick=%s modes=%s query=0\n", c->nick,
           plus ? "+i" : "+");
}

void handle_mode(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    chan_verdict_t verdict;
    int plus;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[3];

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* A nickname is answered on the user-mode path, never the channel one.
     * Channel names begin with # or & and nicknames cannot hold either byte,
     * so the first byte routes with no lookup on the channel side. A name
     * that is neither a channel sigil nor a connected nick falls through to
     * resolve_joined() and its 403, exactly as before. */
    if (m->params[0][0] != CHAN_TYPE1 && m->params[0][0] != CHAN_TYPE2) {
        conn_t *who = server_nick_lookup(s, m->params[0]);

        if (who != NULL) {
            handle_user_mode(s, c, who, m);
            return;
        }
    }
    ch = resolve_joined(s, c, "MODE", m->params[0]);
    if (ch == NULL) {
        return;
    }

    if (m->nparams < 2) {
        /* The query form. modes[] is what 324 shows, and on a non-origin node it
         * is a CACHE -- so the answer is as complete as this node's knowledge
         * is, and a later SSMODE from the origin corrects it. Refusing to
         * answer would be worse than answering partially, for the reason
         * authority_ok() documents. */
        char modes[CHAN_MAX_MODES + 2];

        (void)authority_ok(s, c, ch, "MODE", 0);
        if (ch->modes[0] == '\0') {
            (void)snprintf(modes, sizeof modes, "-");
        } else {
            (void)snprintf(modes, sizeof modes, "+%s", ch->modes);
        }
        (void)reply(s, c, "324", (const char *const[]){ ch->name, modes }, 2,
                    "Channel modes");
        send_creation_time(s, c, ch);
        return;
    }
    /* Local preconditions first, routing last (§2.2): 461/472/482 are answerable
     * from this node's own state, so on an orphaned channel they beat 437. The
     * verdict is ASKED HERE AND HELD, because the forward arm below needs it and
     * a caller that re-asked would report `chan_state_forward` twice. */
    if (m->params[1][0] == '\0' ||
        ((m->params[1][0] == '+' || m->params[1][0] == '-') &&
         m->params[1][1] == '\0')) {
        /* A MODE STRING WITH NO LETTERS -- "" or a lone "+" or "-": the client
         * sent the mode argument and none of the argument that goes with it, so
         * this is a too-FEW case rather than a malformed one, and NEED_MORE_PARAMS
         * says exactly that. The empty string is checked FIRST, because an empty
         * first byte is not '+' or '-' and the sign test below would otherwise
         * answer 472 for a missing argument. A bare letter with no sign (`k`)
         * still falls through to 472: it names a character, just not a signed one. */
        (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->params[1][0] != '+' && m->params[1][0] != '-') {
        /* 472 ERR_UNKNOWNMODE, and RFC 2812 5.2's field list for it is
         *
         *     472  "<client> <char> :is unknown mode char to me for <channel>"
         *
         * -- so the MODE CHARACTER is the middle parameter and the CHANNEL is named
         * in the text. RFC 1459 4.4 words the same sentence the same way, and this
         * is the better of the two available spellings for the reason the call site
         * used to get wrong: it is the only one that leaves the channel in the line.
         *
         * THIS USED TO SEND ch->name AS THE MIDDLE PARAMETER AND NAME NO CHARACTER
         * AT ALL, which is two faults in one field:
         *
         *   - the field the RFC calls <char> held a channel, so a client parsing
         *     472 by position read `#MO` as the rejected mode character and
         *     concluded the node had refused the sigil `#`;
         *   - and because no character was named anywhere, a user who mistyped
         *     `+k` was told "unknown mode character" without being told which one.
         *
         * `ch` HAS A BUFFER because message_format() refuses a value it cannot
         * represent in a non-final position, and a bare `char` would be one past
         * the end of an object rather than a NUL-terminated string. The character
         * here is params[1][0] -- the mode string's first byte -- because that is
         * the byte that is not '+' or '-', which is the whole condition. */
        char wire[2];
        char shown[CONN_LOG_FIELD_MAX + 1u];
        size_t len;
        size_t bad;

        /* THE MEASUREMENT IS TAKEN FIRST, because the byte is the client's and this
         * block is about to stop referring to it. Everything below prints `wire` or
         * `shown`, and neither of them can carry a control byte. */
        mode_refusal_render(m->params[1][0], wire, sizeof wire, shown, sizeof shown,
                            &len, &bad);
        (void)reply_refused(s, c, "MODE", NULL, "472",
                            (const char *const[]){ wire }, 1,
                            "is unknown mode char to me for channel %s", ch->name);
        printf("[observable] chan_mode_refused: channel=%s nick=%s reason=%s "
               "reason_len=%zu reason_byte=0x%02x reason_bad_bytes=%zu\n",
               ch->name, c->nick, shown, len, (unsigned char)m->params[1][0], bad);
        return;
    }
    /* Surplus parameters are 461 with nothing applied or forwarded (#662):
     * each o/v/b letter consumes one argument, so more supplied arguments
     * than such letters is a shape no mode string can use. Counted up front
     * because the loop below applies per letter -- checking after would leave
     * a prefix applied. Only asked of strings this node evaluates: a string
     * naming an unknown letter is the loop's 472. */
    {
        size_t need = 0;
        int known_only = 1;

        for (size_t k = 1; m->params[1][k] != '\0'; k++) {
            char lm = m->params[1][k];

            if (lm == 'o' || lm == 'v' || lm == 'b') {
                need++;
            } else {
                known_only = 0;
            }
        }
        if (known_only && (size_t)m->nparams - 2u > need) {
            (void)reply_refused(s, c, "MODE", "TOO_MANY_PARAMS", "461", NULL, 0,
                                "Not enough parameters");
            return;
        }
    }

    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        (void)reply_refused(s, c, "MODE", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_mode_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }
    verdict = authority_ok(s, c, ch, "MODE", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }

    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }
    plus = (m->params[1][0] == '+');

    /* A multi-letter mode string is legal ("+ovb"), so this is a loop and not a
     * single-letter parse, and each letter is applied in the order given. Each
     * letter that takes a parameter consumes the NEXT one: params[2] serves the
     * first such letter, params[3] the second, and so on, which is what RFC 1459
     * 2.3.1 specifies ("+ov" takes two parameters, one per letter).
     * `next_arg` below holds that cursor. */
    /* THE FORWARD ARM, AND IT USED TO BE A 437 (#141).
     *
     * WHAT IT WAS, and why the reasoning was wrong. The comment here said a
     * forwarded SMODES "would have to name a node this one is not", because 4.3's
     * frozen shape puts the EVALUATING server first and this node does not evaluate
     * +b. Both halves of that are true and the conclusion does not follow:
     * `fed_sverb_params()` fills that field with `self` -- the forwarding node's own
     * name -- and the node IS the evaluator, on a member's behalf, in exactly the
     * sense the field was designed to record. The line it refused to send was the
     * honest one.
     *
     * THE CONSEQUENCE WAS THAT A DOCUMENTED 2.2 FIELD WAS UNREACHABLE FROM HALF THE
     * NETWORK. `MODE #chan +b mask` is one of the three fields 2.2 reserves to the
     * origin, so refusing to forward it meant a ban set by an operator on any node
     * that does not own the channel never took effect anywhere -- the same class of
     * defect as #132, in which no topic set by any client not attached to the origin
     * took effect on any mesh. #141.
     *
     * NOW IT FORWARDS, and the shape is TOPIC's: nothing is applied locally (2.2
     * forbids writing a cache field), the peer line carries `params[0] = self`, and
     * the origin's own client gets the mode change. The client is NOT answered 437
     * here, for TOPIC's reason: the origin performs the action, so a 437 would tell
     * a client its operator status was not accepted, which is false about something
     * that is about to be true. The honest limits are TOPIC's too -- the forward can
     * still be refused further along -- and what this node promises is that it
     * ACCEPTED the request.
     *
     * THE MASK IS STRIPPED, and the raw-length rule is the locally-owned path's
     * verbatim, because it must be: the origin applies its own bound to whatever
     * arrives, so a 400-byte mask of which 200 bytes are control characters would
     * strip to 200 here, fit, and be stored there -- where the same 400 bytes
     * unstripped were refused. Checking the RAW length first keeps the origin's
     * answer a function of what the client sent rather than of which bytes
     * happened to be in it.
     *
     * COST: one bounded copy and one extra pass over the mask, on a path that runs
     * once per client MODE against a channel this node does not own. */
    if (verdict == CHAN_VERDICT_FORWARD) {
        const char *fwd[1 + IRC_MAX_PARAMS];
        char clean[IRC_MAX_PARAMS][CHAN_MAX_BAN + 1u];
        int nfwd = 1;
        size_t kept = 0;
        size_t in_len = 0;

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        fwd[0] = m->params[1];
        for (size_t k = 1; m->params[1][k] != '\0'; k++) {
            char lm = m->params[1][k];
            const char *arg;
            size_t idx;

            if (lm != 'o' && lm != 'v' && lm != 'b') {
                continue;
            }
            idx = (size_t)(nfwd - 1);
            if (2 + idx >= (size_t)m->nparams) {
                break;
            }
            arg = m->params[2 + idx];
            if (arg[0] == '\0') {
                continue;
            }
            if (strlen(arg) > (size_t)CHAN_MAX_BAN) {
                /* NOT FORWARDED, AND SAID SO -- to the client, not just the log.
                 * The owned path answers 417 for the same condition, and
                 * a forwarding node that stayed silent left the client waiting
                 * for a change the origin would refuse (#273). */
                (void)reply_refused(s, c, "MODE", NULL, "417", NULL, 0,
                                    "Input line was too long");
                printf("[observable] chan_mode_forward: channel=%s nick=%s modes=%s "
                       "in_len=%zu kept_len=0 forwarded=0 reason=MASK_TOO_LONG\n",
                       ch->name, c->nick, m->params[1], strlen(arg));
                return;
            }
            kept += conn_text_strip(clean[idx], sizeof clean[idx], arg, STRIP_STORED);
            in_len += strlen(arg);
            fwd[nfwd] = clean[idx];
            nfwd++;
        }
        deliver_state_change(s, c, ch, "MODE", prefix, fwd, nfwd);
        /* The actor's own echo (3.1): the forward reached no local member. */
        {
            const char *echo[2 + IRC_MAX_PARAMS];
            int necho = 0;

            echo[necho++] = ch->name;
            for (int k = 0; k < nfwd; k++) {
                echo[necho++] = fwd[k];
            }
            (void)send_line(s, c, prefix, "MODE", echo, necho);
        }
        printf("[observable] chan_mode_forward: channel=%s nick=%s modes=%s "
               "in_len=%zu kept_len=%zu forwarded=1 reason=CONTROL_BYTES\n",
               ch->name, c->nick, m->params[1], in_len, kept);
        return;
    }

    /* Which parameter the next letter that takes one consumes: params[2] is the
     * first argument, so this starts there and advances one slot per o/v/b
     * letter. Letters that run past the supplied parameters answer 461.
     * `next_arg - 2` only ever reaches 2 + 15 at most, and nparams is bounded
     * by IRC_MAX_PARAMS, so the arithmetic below cannot wrap. */
    size_t next_arg = 2;
    for (size_t i = 1; m->params[1][i] != '\0'; i++) {
        char mode = m->params[1][i];
        char rendered[4];

        /* THE ALLOWLIST IS ASKED, NOT FALLEN THROUGH TO.
         *
         * This loop's shape has always been "act on `b`, act on `o`/`v`, and answer
         * 472 for whatever is left", and the 472 at the bottom was the fall-through.
         * That is a rule expressed as an ABSENCE, and an absence is not something a
         * second path can ask the same question of -- which is exactly how the peer
         * `SMODES` path came to have no such rule at all and how a peer ended up able
         * to write a control byte into `ch->modes[]`.
         *
         * So it is asked now, here, at the top of the loop. The answer is
         * non-deterministic from this loop's point of view -- the arms below still
         * decide what `b` does -- so it is asked as a GATE rather than as a dispatch,
         * and a letter this node does not implement leaves the loop by the 472 arm at
         * the bottom instead of by reaching it. One predicate, three callers
         * (`SMODES`, `chan_mode_set()` and here) and a test that the client path
         * refuses exactly its complement. */
        if (chan_mode_implemented(mode) == 0) {
            char wire[2];
            char shown[CONN_LOG_FIELD_MAX + 1u];
            size_t len;
            size_t bad;

            mode_refusal_render(mode, wire, sizeof wire, shown, sizeof shown, &len,
                                &bad);
            (void)reply_refused(s, c, "MODE", NULL, "472",
                                (const char *const[]){ wire }, 1,
                                "is unknown mode char to me for channel %s", ch->name);
            printf("[observable] chan_mode_refused: channel=%s nick=%s reason=%s "
                   "reason_len=%zu reason_byte=0x%02x reason_bad_bytes=%zu\n",
                   ch->name, c->nick, shown, len, (unsigned char)mode, bad);
            return;
        }

        if (chan_mode_is_origin_only(mode) && !chan_origin_is_self(s, ch)) {
            /* Unreachable while authority_ok() gates every state change, and
             * deliberately still here: authority_ok() decides whether the node
             * may MANAGE this channel, this decides whether it may EVALUATE this
             * mode. Phase 6's forward path is the case where they differ, and a
             * check that only exists on the path that reaches it today is a check
             * that will be missing on the path that needs it. */
            (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                        "Only the origin of this channel may evaluate that mode");
            return;
        }

        if (mode == 'o' || mode == 'v') {
            struct member *target;
            const char *nick;

            if (next_arg >= (size_t)m->nparams) {
                (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                                    "Not enough parameters");
                return;
            }
            nick = m->params[next_arg];
            next_arg++;
            target = chan_find_nick(ch, nick);
            if (target == NULL) {
                /* A peer member of THIS channel is on the channel (#606). */
                chan_remote_t *rm = chan_remote_by_nick(ch, nick);
                unsigned flag = (mode == 'o') ? CHAN_MEMBER_OP : CHAN_MEMBER_VOICE;

                if (rm == NULL) {
                    /* 441/401 for the same reason as in KICK: "real but not here"
                     * and "does not exist" are different facts. A MODE +o naming a
                     * nickname that is not on the channel is a client bug, and 441
                     * says precisely which bug. */
                    if (server_nick_lookup(s, nick) != NULL) {
                        (void)reply_refused(s, c, "MODE", NULL, "441",
                                    (const char *const[]){ nick, ch->name }, 2,
                                    "They're not on that channel");
                    } else {
                        (void)reply_refused(s, c, "MODE", NULL, "401",
                                    (const char *const[]){ nick },
                                    1, "No such nick/channel");
                    }
                    return;
                }
                if (plus) {
                    rm->flags |= flag;
                } else {
                    rm->flags &= ~flag;
                }
                nick = rm->nick;
            } else {
                (void)chan_set_member_flags(
                    ch, target->c, plus,
                    (mode == 'o') ? CHAN_MEMBER_OP : CHAN_MEMBER_VOICE);
                nick = target->c->nick;
            }
            /* The echo, in RFC 1459 2.3.1's order: prefix, channel, mode, nick.
             * Four parameters, not three with a space in the last -- the wire has
             * no compound parameter, and message_format() would REFUSE one
             * containing a space rather than reshape it. */
            rendered[0] = plus ? '+' : '-';
            rendered[1] = mode;
            rendered[2] = '\0';
            /* The four-parameter echo, split into the two the fan-out wants: the
             * rendered mode is a MIDDLE parameter and the nickname is the
             * trailing one, which is why they are two array slots and not one
             * string with a space in it -- 3.2 refuses to deliver a value
             * containing a separator in a non-final position rather than
             * reshaping it, and RFC 1459 2.3.1 has them as two. */
            params[0] = rendered;
            params[1] = nick;
            deliver_state_change(s, c, ch, "MODE", prefix, params, 2);
            printf("[observable] chan_member_mode: channel=%s by=%s nick=%s "
                   "mode=%c set=%d\n", ch->name, c->nick, nick, mode,
                   plus);
            continue;
        }

        if (mode == 'b') {
            /* Declared here rather than at the top of the function because this is
             * the only branch that uses them, and a loop over up to MAXPARAMS modes
             * reuses one buffer per iteration rather than holding four per mode. */
            char clean_mask[CHAN_MAX_BAN + 1u];
            const char *effective;
            size_t kept_mask;

            const char *mask;

            if (next_arg >= (size_t)m->nparams) {
                /* THE QUERY FORM, not a too-few-params case. RFC 2812 3.3.2:
                 * "If the <modestring> parameter is given with a list of mode
                 * arguments, then a list of mode arguments is returned for
                 * channel modes b, e and I." The client sent the mode argument
                 * and no argument to go with it, which is the QUESTION, and
                 * 461 answered it with "you sent too few parameters" -- a
                 * refusal that told the client its own question was malformed.
                 * See send_ban_list() for the full argument. Only the bare
                 * single-letter form queries: a longer string that runs out of
                 * arguments mid-loop is a client that under-supplied. */
                if (m->params[1][1] == 'b' && m->params[1][2] == '\0') {
                    send_ban_list(s, c, ch);
                    return;
                }
                (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                                    "Not enough parameters");
                return;
            }
            mask = m->params[next_arg];
            next_arg++;
            /* A BAN MASK IS RELAYED, SO IT IS STRIPPED, and the store and the
             * broadcast MUST get the SAME COPY. That is the whole shape of this
             * fix and it is the one `handle_topic()` got wrong on the locally-owned
             * path: there the stored copy was filtered and the announced copy was
             * the client's bytes, so every member got the raw value. Here the mask
             * is stored by `chan_ban_add()` AND announced in the MODE echo, so a
             * strip applied to only one of them leaves the other raw.
             *
             * ONE COPY, CHOSEN ABOVE BOTH CALLS, is what makes that impossible to
             * get wrong from here: `effective` is computed once and is what the
             * store sees, what the broadcast sends, and what the log prints.
             *
             * `CHAN_MAX_BAN + 1` IS EXACT, and the over-long case is DELIBERATELY
             * NOT STRIPPED. Stripping could take a 200-byte mask inside the bound
             * and have it stored, where the same mask unstripped is refused today --
             * so the refusal would become a function of which bytes were in the mask
             * rather than of how long it was. An over-long mask goes to
             * `chan_ban_add()` unchanged and gets the refusal it gets today.
             *
             * AN ALL-REFUSED MASK LANDS ON 461 NOW (#133). A mask that strips to
             * nothing is EMPTY, and `chan_ban_add()` refuses an empty mask as
             * CHAN_BAN_EMPTY -- which is answered 461, because a required parameter
             * that is absent is exactly what 461 says and exactly what this node
             * already uses it for on this very verb (see the query arm above). The
             * comment this replaces argued that 478's text did not fit the case and
             * that adding a numeric was "a wire change this pass is not making". An
             * inaccurate error is a wire behaviour too, and the recovery it implies
             * -- remove a ban you never added -- is the wrong one for a client that
             * sent nothing. The over-long case moves with it, to 417.
             *
             * THE BOUND IS CHECKED ON THE RAW LENGTH, AND WHICH OF THE TWO
             * LENGTHS THAT IS CANNOT BE OBSERVED -- so it is worth saying why
             * rather than leaving it to whichever branch runs first.
             *
             * `conn_text_strip()` only ever REMOVES bytes, so a mask that is
             * inside CHAN_MAX_BAN raw cannot become over-long stripped, and a mask
             * that is over-long raw is refused by the branch below before the strip
             * is ever called. The two predicates therefore coincide exactly: there
             * is no input for which "measure after the strip" would accept what
             * "measure before" refuses. An earlier draft of this comment claimed
             * the opposite -- that a 300-byte mask of which 200 are control bytes
             * strips to 100 and is accepted -- and that is FALSE, and the test that
             * was written to pin it failed on the code rather than on the test.
             *
             * So the raw length is what binds, and the reason it is the RAW one is
             * the argument the paragraph above makes: a client can predict a raw
             * length bound from the bytes it sent, and cannot predict a bound on a
             * filtered value it has never been shown. What the strip DOES change is
             * the STORED value and the ANNOUNCED value, and the one-copy rule above
             * is what keeps those two the same string.
             */
            if (strlen(mask) > (size_t)CHAN_MAX_BAN) {
                effective = mask;
                kept_mask = strlen(mask);
            } else {
                kept_mask = conn_text_strip(clean_mask, sizeof clean_mask, mask, STRIP_STORED);
                effective = clean_mask;
            }
            if (plus) {
                /* NOT NAMED `verdict`: handle_mode() already has a `chan_verdict_t`
                 * verdict of its own from authority_ok(), and a second one in an
                 * inner scope is a shadow that -Wshadow rightly complains about and
                 * that a reader has to disambiguate. */
                const chan_ban_verdict_t bverdict = chan_ban_add(ch, effective);

                if (bverdict != CHAN_BAN_OK) {
                    ban_refusal(s, c, ch, effective, bverdict);
                    return;
                }
                /* chan_ban_add() deliberately does not touch modes[]: a caller
                 * that adds a mask and forgets the letter has two bugs, and
                 * hiding one inside the other makes both harder to find. */
                (void)chan_mode_set(ch, 'b', 1);
            } else {
                if (chan_ban_remove(ch, effective) != 0) {
                    (void)reply(s, c, "368",
                                (const char *const[]){ ch->name, effective }, 2,
                                "Ban mask is not set on this channel");
                    return;
                }
                if (ch->nbans == 0) {
                    (void)chan_mode_set(ch, 'b', 0);
                }
            }
            rendered[0] = plus ? '+' : '-';
            rendered[1] = 'b';
            rendered[2] = '\0';
            params[0] = rendered;
            params[1] = effective;
            deliver_state_change(s, c, ch, "MODE", prefix, params, 2);
            printf("[observable] chan_ban_mode: channel=%s by=%s mask=%s set=%d "
                   "nbans=%zu origin=%s\n", ch->name, c->nick, effective, plus,
                   ch->nbans, ch->origin);
            if (kept_mask != strlen(mask)) {
                printf("[observable] chan_ban_mask_stripped: channel=%s by=%s "
                       "in_len=%zu kept_len=%zu reason=CONTROL_BYTES\n",
                       ch->name, c->nick, strlen(mask), kept_mask);
            }
            continue;
        }

        /* 004 advertises b,k,l,imnpst; this node evaluates b, and o/v are prefix
         * modes rather than channel modes. A node that accepted a mode it does
         * not act on would have a 324 that disagrees with its behaviour, so the
         * unevaluated ones are refused by name.
         *
         * IT IS `chan_mode_implemented()` THAT GOT HERE, not a `switch` arm that
         * happened not to match. `SMODES` asks the same predicate on the peer path --
         * see channel.c -- and the point of it being a function rather than a
         * fall-through is that the two paths cannot drift: a mode letter this node
         * does not evaluate is a 472 for a client and a refusal for a peer, and both
         * answers come from one switch. `test_fed_guards.c` asserts they agree.
         *
         * THE SAME FIELD LIST AS THE OTHER 472 ABOVE, and for the same reasons:
         * RFC 2812 5.2 is "<client> <char> :is unknown mode char to me for
         * <channel>", so the middle parameter is the CHARACTER the client asked
         * for and the channel goes in the sentence. Sending ch->name there -- which
         * is what this did -- is the field-list error docs/RFC2812_CONFORMANCE.md
         * section 6.5 recorded: a client parsing 472 by position reads the channel
         * as the mode character it got wrong.
         *
         * The two sites are separate because the character is a different
         * expression at each: here it is the LOOP variable, one byte of a
         * multi-letter string like "+oks", and up there it is the mode string's
         * first byte. Sharing a helper would need both passed in, and the one thing
         * that must not vary between them is the field list -- which is why both
         * carry the same comment rather than a shared function. */
        char wire[2];
        char shown[CONN_LOG_FIELD_MAX + 1u];
        size_t len;
        size_t bad;

        /* The same rendering as the 472 above, through the same helper, and for the
         * same reason: the field list and the placeholder must not be able to differ
         * between two sites that answer the same numeric. */
        mode_refusal_render(mode, wire, sizeof wire, shown, sizeof shown, &len, &bad);
        (void)reply_refused(s, c, "MODE", NULL, "472",
                            (const char *const[]){ wire }, 1,
                            "is unknown mode char to me for channel %s", ch->name);
        (void)chan_mode_implemented(mode); /* the predicate that routed us here */
        printf("[observable] chan_mode_refused: channel=%s nick=%s reason=%s "
               "reason_len=%zu reason_byte=0x%02x reason_bad_bytes=%zu\n",
               ch->name, c->nick, shown, len, (unsigned char)mode, bad);
        return;
    }
}

/* handle_invite(): split out for #543 (TU-48) into core/chan_verbs_invite.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */

/* handle_knock(): split out for #543 (TU-45) into core/chan_verbs_knock.c; it
 * stays declared in core/chan_verbs.h (no new header), reached through it by
 * the dispatch table in core/commands_dispatch.c. */
