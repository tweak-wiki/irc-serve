/* chan_verbs_mode.c -- see core/chan_verbs.h. 4.1's MODE.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-53): the MODE
 * section (handle_mode() plus its section header; mode_refusal_wire() +
 * mode_refusal_render() + ban_refusal() + send_ban_list() + handle_user_mode()
 * move with it as its sole-user helpers). It stays declared in
 * core/chan_verbs.h (no new header), reached through it by the dispatch
 * table in core/commands_dispatch.c. Its in-TU dependencies are
 * resolve_joined()/authority_ok()/deliver_state_change() (shared since
 * TU-48/46/49) and chan_remote_by_nick() (shared since TU-52); the rest --
 * chan_mode/ban helpers, server_nick_lookup, conn_hostmask, conn_text_xxx,
 * send_line/reply/reply_refused -- already arrive through headers.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/reply.h"

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
