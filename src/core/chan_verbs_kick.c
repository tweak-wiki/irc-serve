/* chan_verbs_kick.c -- see core/chan_verbs.h. 4.1's KICK.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-52): the KICK
 * section (handle_kick() plus its section header; chan_remote_by_nick() moves
 * with it and is shared through core/chan_verbs.h -- handle_mode()'s +o/+v
 * path is its second caller (canonical_channel TU-45 / authority_ok TU-46 /
 * resolve_joined TU-48 precedent, no new header). It stays declared in
 * core/chan_verbs.h (no new header), reached through it by the dispatch
 * table in core/commands_dispatch.c. Its in-TU dependencies are
 * resolve_joined()/authority_ok()/deliver_state_change() (shared since
 * TU-48/46/49); the rest -- chan_find_nick/chan_remove_member/
 * chan_detach_conn/chan_remote_remove/chan_dispose_if_empty,
 * conn_hostmask/conn_text_strip, server_nick_lookup, send_line/reply_refused --
 * already arrive through headers.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * KICK
 * ---------------------------------------------------------------------------
 * The verb that makes member.flags load-bearing. Without the +o bit there is no
 * way to tell an operator from a plain member and 482 is unimplementable, which
 * is why 2.2's `struct member` had to grow a field in this phase.
 *
 * Check order, and it is not arbitrary:
 *
 *   442  the KICKER is not on the channel. Without this a non-member would be
 *        told 482 about a channel it is not in, which answers a question the
 *        client did not ask.
 *   482  the kicker holds no privilege -- 7/Phase 4's acceptance criterion, and
 *        meaningful only because +o is what sets it.
 *   401  the target is not a nickname this node knows.
 *   441  the target exists but is not on this channel.
 *   437  the node may not manage this channel. Routing is asked LAST: 482/401/441
 *        are answerable from this node's own state, so on an orphaned channel
 *        they beat the "origin unreachable" answer, which would never clear.
 *
 * 441 is checked after 401 and the two are different facts: "they are not here"
 * is more specific than "no such nick", and a client that acted on 401 would go
 * looking for a user who is simply elsewhere.
 */
/* The federated half of target resolution (#606). chan_find_nick() walks only
 * ch->members[] (local conns); a member on a peer lives in ch->remotes[].
 * Shared through core/chan_verbs.h (issue #543 TU-52): handle_mode()'s +o/+v
 * path is the second caller, and WHOIS/WHO/ISON need the same union (#607) --
 * the first helper to land wins, and this one got there first.
 * Returns the entry or NULL; the caller owns nothing. */
chan_remote_t *chan_remote_by_nick(chan_t *ch, const char *nick)
{
    size_t i;

    if (ch == NULL || nick == NULL) {
        return NULL;
    }
    for (i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].nick, nick)) {
            return &ch->remotes[i];
        }
    }
    return NULL;
}

void handle_kick(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    struct member *target;
    chan_remote_t *remote;
    const char *reason;
    char clean_reason[CHAN_MAX_KICK_REASON + 1u];
    size_t kept_reason;
    size_t raw_reason_len;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[4];
    chan_verdict_t verdict;

    if (m->nparams < 2) {
        (void)reply_refused(s, c, "KICK", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 3) {
        (void)reply_refused(s, c, "KICK", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* RFC 1459 2.3.1: the reason is optional, and a KICK without one names the
     * kicker, which is the most useful default available -- it is in the message
     * already and it is what the target will see. */
    reason = (m->nparams > 2) ? m->params[2] : c->nick;
    raw_reason_len = strlen(reason);

    /* ------------------------------------------------------------------------
     * THE REASON BOUND, AND WHY IT IS CHECKED HERE AND NOT AT THE END
     * ------------------------------------------------------------------------
     * Immediately after the arity test, which is where a parameter's validity
     * belongs: a KICK carrying a parameter this node will not accept is refused
     * as malformed whatever the sender's standing on the channel, and a node that
     * answered 482 for a client who simply sent too many bytes would be reporting
     * a privilege problem for a syntax problem. Nothing below has run, so nothing
     * below has to be undone.
     *
     * IT WAS MISSING, AND THE CONSEQUENCE WAS WORSE THAN A MISSING 005 TOKEN. With
     * no test here the reason went straight into `deliver_state_change()` ->
     * `fanout_deliver()` -> `send_line()` -> `message_format()`, which refuses a
     * line it cannot represent rather than reshaping it -- and the only outcome at
     * that depth is a refusal counted on `n_reply_refused`, the counter `reply.c`
     * holds at zero because a non-zero value is a bug report. So one client
     * command was a reachable way to put a non-zero on it. Phase 10.4 recorded that
     * as a finding in two places (this bound, and `KICKLEN`'s absence from 005) and
     * named this as the fix for both; this is it.
     *
     * 417 is the numeric this node already uses for "that parameter is longer than
     * I will store" -- msg_verbs.c's AWAY and PRIVMSG and commands.c's SETNAME --
     * and reusing it is the point: a client that has learned one over-long
     * parameter refusal has learned all of them. For a client that negotiated
     * `standard-replies` this is `FAIL KICK ERR_INPUTTOOLONG` instead; the legacy
     * numeric and its text are byte-identical to what they would otherwise be,
     * which is the whole of reply.c's `reply_refused()` contract.
     *
     * THE DEFAULT REASON CANNOT FAIL, and that is worth saying rather than leaving
     * to be checked: it is `c->nick`, and a nickname is bounded by IRC_MAX_NICK
     * (63), so the substituted value is always inside this bound. A future change
     * that defaulted the reason to something client-supplied would have to move
     * this test. */
    if (raw_reason_len > (size_t)CHAN_MAX_KICK_REASON) {
        (void)reply_refused(s, c, "KICK", NULL, "417", NULL, 0,
                            "Kick reason is too long");
        /* MEASURED, and the ORDERING is what makes it necessary: this line names
         * `m->params[0]` -- the CHANNEL -- and it is printed BEFORE
         * `resolve_joined()` has run `chan_name_valid()` over it. Every other
         * `channel=%s` in this file prints `ch->name`, which is a stored name that
         * passed the validator; this one is the exception and it was the raw path.
         *
         * Not a strip: the value is log-only, and a channel name is an identifier
         * whose diagnostic value is that it is readable. Withheld when a byte in it
         * would execute, with the length and the count beside it.
         *
         * THE 417 IS UNAFFECTED. The reason was rejected for being over-long, which
         * is the fact the numeric reports, and the channel name plays no part in
         * it -- so nothing here changes which numerics a client sees. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, m->params[0]);
            printf("[observable] chan_kick_refused: channel=%s channel_len=%zu "
                   "channel_bad_bytes=%zu nick=%s reason=too_long len=%zu max=%d\n",
                   shown, strlen(m->params[0]), conn_text_bad_count(m->params[0]),
                   c->nick, strlen(reason), CHAN_MAX_KICK_REASON);
        }
        return;
    }

    /* ------------------------------------------------------------------------
     * THE REASON IS RELAYED, SO IT IS STRIPPED -- AND IT IS STRIPPED HERE, AFTER
     * THE BOUND ABOVE AND NOT BEFORE IT
     * ------------------------------------------------------------------------
     * The strip closes the last raw relay of a client-controlled string left on the
     * node: `handle_kick()` puts the client's own `<reason>` into the KICK it
     * broadcasts to every member of the channel, so `KICK #c nick :<ESC>[2J`
     * reached every member's terminal with the ESC intact. The bound above is a
     * LENGTH bound and said nothing about which bytes.
     *
     * AFTER THE BOUND, and that ordering is the whole of it. Stripping first would
     * have been a REGRESSION, and test_standard_replies.c's 256-byte case caught it:
     * `CHAN_MAX_KICK_REASON + 1` holds exactly 255 characters plus a terminator, so
     * a 256-character reason stripped into it is TRUNCATED to 255, and the length
     * check that follows would then see 255 and accept the very input the 417
     * exists to refuse. Stripping after the bound means the strip can only ever run
     * on a value already known to fit, so `clean_reason` is exact and the refusal is
     * a function of what the client sent. (The same ordering is load-bearing in the
     * TOPIC forward arm and in the MODE mask below, and it is why all three test
     * the RAW length before stripping.)
     *
     * `clean_reason` IS WHAT IS BROADCAST, announced and stored nowhere else -- there
     * is no stored reason, which is why this is a strip and not a "send the stored
     * field". The default, `c->nick`, is a nickname that passed `valid_nick()`, so
     * the common no-reason KICK is unchanged: the strip is idempotent on it and
     * announces nothing.
     *
     * IT COSTS, and the cost is the same one the away message and the topic
     * accepted: the members see a shorter sentence than the kicker wrote, and the
     * log line below is the only record of the difference. */
    kept_reason = conn_text_strip(clean_reason, sizeof clean_reason, reason, STRIP_STORED);
    reason = clean_reason;
    ch = resolve_joined(s, c, "KICK", m->params[0]);
    if (ch == NULL) {
        return;
    }

    /* Local preconditions first, routing last (§2.2): 482 (below) and 441/401
     * are answerable from this node's own state, so on an orphaned channel
     * they beat 437 -- whose answer ("the origin is unreachable") would be a
     * lie about a refusal that will never clear. A well-formed KICK falls
     * through to authority_ok() and is still refused 437 there. */
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        /* 482, not 481. 481 is "you need to be a channel operator to do this"
         * for a mode the client may not set at all; 482 is "you are not
         * privileged enough for this action", which is the situation. */
        (void)reply_refused(s, c, "KICK", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_kick_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }
    target = chan_find_nick(ch, m->params[1]);
    /* A member of THIS channel on a peer is on the channel (#606): the local
     * walk above misses it, so the remote roster is asked before 441/401. */
    remote = (target == NULL) ? chan_remote_by_nick(ch, m->params[1]) : NULL;
    if (target == NULL && remote == NULL) {
        /* 441 versus 401, and the difference is a fact about the node rather
         * than about the channel. A nickname this node has NEVER heard of is
         * 401. A nickname it holds -- registered, somewhere -- that simply is
         * not on THIS channel is 441, and the two are genuinely different
         * answers: 401 sends a client looking for a user who does not exist,
         * while 441 tells it the user is real and is elsewhere. Conflating them
         * is how a client ends up trying to invite someone it already has. */
        if (server_nick_lookup(s, m->params[1]) != NULL) {
            (void)reply_refused(s, c, "KICK", NULL, "441",
                                (const char *const[]){ m->params[1], ch->name },
                                2, "They're not on that channel");
        } else {
            (void)reply_refused(s, c, "KICK", NULL, "401",
                                (const char *const[]){ m->params[1] }, 1,
                                "No such nick/channel");
        }
        return;
    }
    verdict = authority_ok(s, c, ch, "KICK", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }
    /* NOT A FORWARD CASE, and the reason is 2.2 rather than 3.1. A KICK is only
     * meaningful on a channel this node ORIGINATES, because the kicker has to be
     * an operator OF THAT CHANNEL and the operator set is the origin's record;
     * a cache cannot decide who may remove whom. So a KICK on a non-owned but
     * linked channel is answered 437 by the verdict path below rather than
     * forwarded -- the privilege check above is the origin's rule only on an
     * owned channel, and everywhere else it is the local precondition §2.2
     * orders before routing. */
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }
    printf("[observable] chan_kick: channel=%s by=%s target=%s\n", ch->name, c->nick,
           (target != NULL) ? target->c->nick : remote->nick);

    /* The echo, in RFC 1459 2.3.1's parameter order: prefix, channel, target,
     * reason. */
    /* Through 3.1's table, and the target is included in the parameter list
     * because the CLIENT shape of a KICK is (channel, target, reason) and 3.1's
     * target is prepended by the fan-out. The frozen SKICK shape puts the
     * KICKER first and the channel second; the re-shaping is fed_sverb_params()'s
     * job and is not something this handler knows about. */
    params[0] = (target != NULL) ? target->c->nick : remote->nick;
    params[1] = reason;
    deliver_state_change(s, c, ch, "KICK", prefix, params, 2);
    if (verdict == CHAN_VERDICT_FORWARD) {
        /* The actor's own echo (3.1): the forward reached no local member. */
        const char *echo[3];

        echo[0] = ch->name;
        echo[1] = (target != NULL) ? target->c->nick : remote->nick;
        echo[2] = reason;
        (void)send_line(s, c, prefix, "KICK", echo, 3);
    }
    /* ANNOUNCED, on the same rule as the away message and the topic: silent
     * mutation is its own defect, and the member who sees a shortened reason has no
     * way to know the kicker wrote something longer. The count is what separates
     * "one stray byte" from "the reason was mostly control characters". */
    if (kept_reason != raw_reason_len) {
        printf("[observable] chan_kick_stripped: channel=%s nick=%s in_len=%zu "
               "kept_len=%zu reason=CONTROL_BYTES\n",
               ch->name, c->nick, raw_reason_len, kept_reason);
    }

    if (target != NULL) {
        conn_t *kicked = target->c;

        /* Remove, then detach from the kicked connection. The broadcast above
         * addressed the target while it was still a member, and the detach is
         * what keeps teardown from trying to remove it a second time. */
        (void)chan_remove_member(ch, kicked);
        (void)chan_detach_conn(kicked, ch);
    } else {
        /* A peer member: the fan-out above already carried the SKICK to the
         * member's node, so this is the local half -- drop the roster entry. */
        (void)chan_remote_remove(ch, remote->server, remote->nick);
    }
    (void)chan_dispose_if_empty(s, ch);
}
