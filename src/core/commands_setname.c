/* commands_setname.c -- see commands_setname.h. The SETNAME family
 * (IRCv3 `setname` + the common-channel notify), verbatim out of
 * commands.c; the dispatch table that calls handle_setname() still lives
 * there.
 */
#include "core/commands_setname.h"

#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/fanout.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* ---------------------------------------------------------------------------
 * SETNAME -- IRCv3's `setname`, and the three gates in front of it
 * ---------------------------------------------------------------------------
 * `SETNAME :<realname>` changes `conn_t::realname` on a live connection. Three
 * gates, in this order, and the order is the argument:
 *
 *   1. REGISTERED. 451 if not. Not `pre_reg` in k_commands[], so this is answered
 *      by the dispatch table's own rule rather than here -- and it has to be a gate
 *      rather than an accident of the field being empty, because a pre-registration
 *      connection HAS an empty realname and would otherwise "succeed" at setting it
 *      to something, which is a command acting on state that does not exist yet.
 *
 *   2. THE CAPABILITY. Refused SILENTLY, with no reply and no change.
 *
 *      This is the specification's own instruction and it is the opposite of what
 *      every other capability in cap.h does, so it is worth being explicit: `setname`
 *      says a server MUST support the command even while the capability is not
 *      negotiated, and that a SETNAME from a client which did not negotiate it
 *      SHOULD be handled silently. "Silently" IS the refusal -- nothing arrives and
 *      nothing changes -- and it is observable, because a protocol test can assert
 *      that nothing arrived.
 *
 *      THE SILENCE IS NOT BECAUSE `standard-replies` WAS ABSENT. It used to be
 *      justified that way and that justification was WRONG the moment the
 *      capability landed in Phase 10.9: `FAIL SETNAME CANNOT_CHANGE_REALNAME` is
 *      now expressible, and sending it would still be wrong, because the
 *      specification asks for SILENCE here and a `FAIL` is a response. The reason
 *      for silence is the specification's instruction and nothing else. (The other
 *      half of that sentence is now handled: the refusal below for an
 *      unacceptable VALUE is a `FAIL` for a client that negotiated
 *      `standard-replies`, which is a different refusal from not being permitted to
 *      try.)
 *
 *   3. VALIDATION, through conn_realname_check() -- the SAME predicate handle_user()
 *      runs, which is what makes this not a looser path than registration. A
 *      refusal is 417 and the previous realname is left exactly as it was. It is
 *      NOT truncated: 3.2's rule, and the reason is that this value is then shown
 *      to every member of every channel the user is on as though it were theirs.
 *
 *      417 IS STILL THE NUMERIC, and for a client that negotiated
 *      `standard-replies` it is `FAIL SETNAME ERR_INPUTTOOLONG` or
 *      `ERR_INVALID_PARAM` depending on which of the two refusals this was -- a
 *      distinction the number never carried and the verdict `v` already knows.
 *      reply.c's `reply_refused()` is what makes the swap per destination, so a
 *      client that negotiated nothing still receives the 417 and the same text.
 *
 * THE CONFIRMATION. On success this node sends the server-to-client form back to
 * the originating client:
 *
 *     :nick!user@host SETNAME :<new realname>
 *
 * which is the specification's MUST for "to all clients in common channels, as well
 * as to the client from which it originated" -- PARTIALLY. The originating client
 * gets it; **the common-channel fan-out does not happen**, and that is a named
 * limit rather than an oversight. `core/fanout.c`'s per-destination decision is a
 * choice between two wire SHAPES (the `fanout_form_t` the extended JOIN
 * introduced), and "send this member NOTHING" is a THIRD outcome that the form
 * cannot express; adding it is a contract change to the routing module, and the
 * alternative -- a second member walk inside a handler -- is the exact duplication
 * fanout.c exists to prevent. So the originating client is told, and a member of a
 * shared channel is not. SPEC_TRACKING 10.5 records it.
 *
 * THE PREFIX IS THE ACTING CLIENT'S OWN HOSTMASK, which is the specification's
 * server-to-client shape and is also what makes the line trustworthy: it names who
 * changed, and `conn_hostmask()` renders it from the fields §2.1 owns (including the
 * OBSERVED host, which USER does not touch). */

/* THE COMMON-CHANNEL FAN-OUT, and the disclosure decision is the whole of it.
 *
 * The specification: "they MUST send the server-to-client version of the SETNAME
 * message **to all clients in common channels**, as well as to the client from which
 * it originated" and "The SETNAME message **MUST NOT** be sent to clients which do
 * not have the `setname` capability negotiated."
 *
 * THE GATE IS THE RECIPIENT'S, which is the specification's condition read
 * literally ("clients", plural) and the answer that agrees with `cap.h`'s existing
 * rule for the CONFIRMATION above. Gating on the SENDER -- which is the other thing
 * one could implement, and which is one line -- would let a client who negotiated
 * `setname` put a member's realname on the wire to every other member of a shared
 * channel by asking for a capability those members never requested, and would
 * contradict the confirmation's own rule in the same handler. A realname is personal
 * data; the per-destination answer is the only one that does not require trusting
 * the person disclosing it to be careful about who finds out.
 *
 * THE ORIGIN IS EXCLUDED, and the reason is the ORDER rather than a rule about
 * authors: the confirmation above has ALREADY delivered this line to the client that
 * asked, and the specification counts that as the origin's half of the MUST. Leaving
 * the origin in the audience would give it two byte-identical `SETNAME` lines for one
 * command, which is the same double-delivery defect `echo-message` has a fault for.
 * So `exclude` is `c`, exactly as msg_verbs.c's notify_away() excludes the away
 * setter because 306/305 are that user's own answer.
 *
 * IT IS THE UNION, NOT ONE CALL PER CHANNEL, and the SHAPE is why:
 * `:nick!user@host SETNAME :<realname>` has no channel parameter, so a per-channel
 * emission would put a `#channel` where a client expects the realname, and would hand
 * a member of three shared channels three copies of one fact. fanout.h's
 * `fanout_deliver_union_local_gated()` is the one walk that gets both right, and its
 * de-duplication is a search over the caller's own `conn_t::chans` rather than a
 * cache -- which is why there is no bounded store here with a teardown arm to forget.
 *
 * MESH-REACHABLE THROUGH SSETNAME, while the notify itself stays local-only: this
 * is an originating emission through the local-only entry point, and the
 * `handle_setname()` line above carries the change across the mesh as
 * `:hostmask SSETNAME <nick> :<realname>` (#563). A resync still rebuilds only
 * what 4.3's `SBURSTN` carries, but a live change now reaches the mesh as it
 * happens.
 */
static void setname_notify_channels(server_t *s, conn_t *c)
{
    const char *params[1];
    fanout_form_t plain;
    char prefix[CONN_HOSTMASK_MAX];
    int delivered;

    /* NO CHANNELS MEANS NO AUDIENCE, and that is `c->nchans` rather than a check
     * anywhere else: the audience is "users sharing a channel", so with no channels
     * there is nobody to tell. The confirmation above has already reached the only
     * client the specification requires an answer to. */
    if (c->nchans == 0u) {
        printf("[observable] setname_notify: nick=%s recipients=0 "
               "reason=NO_SHARED_CHANNEL\n",
               c->nick);
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        /* Unrenderable is a bug report rather than a refusal, and it cannot have
         * happened: the caller rendered this same prefix a few lines ago and got here
         * because it succeeded. Reported rather than assumed, because the alternative
         * is a silent reason for a notification that never went out. */
        printf("[observable] setname_notify: nick=%s reason=UNRENDERABLE\n", c->nick);
        return;
    }
    params[0] = c->realname;
    plain.params = params;
    plain.nparams = 1;
    delivered = fanout_deliver_union_local_gated(s, c->chans, c->nchans, prefix,
                                                 "SETNAME", &plain, NULL,
                                                 cap_gate_setname, NULL, c);
    printf("[observable] setname_notify: nick=%s channels=%zu recipients=%d\n",
           c->nick, c->nchans, delivered);
}

void handle_setname(server_t *s, conn_t *c, const message_t *m)
{
    conn_realname_verdict_t v;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[1];

    /* Arity before anything else, and the gate order above says why: a malformed
     * command from a client that cannot use it is answered 461 rather than
     * silently, because 461 is the shape the specification's own "handle silently"
     * does NOT apply to -- silence is for a well-formed SETNAME, not for a missing
     * parameter. */
    if (m->nparams != 1) {
        (void)reply_refused(s, c, "SETNAME", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] setname_refused: fd=%d nick=%s reason=ARITY nparams=%d\n",
               c->fd, c->nick, m->nparams);
        return;
    }
    if (cap_enabled(c, CAP_SETNAME) == 0) {
        /* THE SILENT REFUSAL. No reply, no change, and the only trace is this line,
         * which is the same observable output every other refusal in this file uses.
         * It is deliberately NOT a 417 and NOT a 482: a client that did not ask for
         * `setname` has not done anything wrong, and the specification asks for
         * silence rather than for an error a client cannot act on. */
        printf("[observable] setname_ignored: fd=%d nick=%s "
               "reason=NOT_NEGOTIATED len=%zu\n",
               c->fd, c->nick, strlen(m->params[0]));
        return;
    }
    v = conn_realname_check(m->params[0]);
    if (v != CONN_REALNAME_OK) {
        /* THE DISTINCTION THE NUMBER NEVER CARRIED, and it is the clearest small
         * argument for the migration: `v` already knows whether the realname was
         * too long or held a byte this node will not store, and both were 417
         * carrying the same text. For a client that negotiated `standard-replies`
         * they are now two codes, and only the length one is the numeric's own
         * complaint. */
        (void)reply_refused(s, c, "SETNAME",
                            (v == CONN_REALNAME_TOO_LONG) ? "ERR_INPUTTOOLONG"
                            : "ERR_INVALID_PARAM",
                            "417", NULL, 0, "Realname is not acceptable");
        printf("[observable] setname_refused: fd=%d nick=%s reason=%s len=%zu "
               "max=%d\n",
               c->fd, c->nick,
               (v == CONN_REALNAME_TOO_LONG) ? "TOO_LONG" : "BAD_BYTE",
               strlen(m->params[0]), CONN_MAX_REALNAME);
        return;
    }
    /* NOT copy_field(), and the difference is the point of gate 3. copy_field()
     * truncates; this must not, because the stored value is one this node will
     * report to third parties. The length has just been checked against
     * CONN_MAX_REALNAME, which is sizeof(conn_t::realname) - 1, so this copy
     * cannot truncate -- and it is written out rather than delegated so that a
     * future change to the bound cannot silently reintroduce the truncation
     * through the helper. */
    memcpy(c->realname, m->params[0], strlen(m->params[0]) + 1u);
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        /* The value is already stored at this point, because the check happened
         * first and the store is unconditional once it passed. A connection whose
         * hostmask will not render is a bug report rather than a refusal, and the
         * honest outcome is that the change happened and could not be confirmed. */
        printf("[observable] setname_unconfirmed: fd=%d nick=%s reason=UNRENDERABLE\n",
               c->fd, c->nick);
        return;
    }
    params[0] = c->realname;
    (void)send_line(s, c, prefix, "SETNAME", params, 1);
    setname_notify_channels(s, c);
    /* Originated SSETNAME: the mesh half of this change. The nick rides in
     * params[0] because the inbound half resolves the subject from there, not
     * from the prefix. Runs even with no local audience, for the same reason
     * away_federate() does -- a relay carries it to members this node never
     * sees. */
    { const char *sp[2]; sp[0] = c->nick; sp[1] = c->realname; (void)fed_forward_all(s, "SSETNAME", prefix, sp, 2); }
    printf("[observable] setname: fd=%d nick=%s len=%zu\n", c->fd, c->nick,
           strlen(c->realname));
}

