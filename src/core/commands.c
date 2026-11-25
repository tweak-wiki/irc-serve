/* commands.c -- see commands.h. The commands that need no channel and no
 * other user, and THE DISPATCH SEAM that both a client line and a peer line
 * arrive at. The welcome burst (001-005 + MOTD) lives in
 * core/commands_welcome.c (#543). Registration (PASS/NICK/USER) lives in
 * core/commands_register.c (#543), and the connection-lifecycle handlers
 * (PING/PONG/QUIT) in core/commands_conn.c.
 */
#include "core/commands.h"

/* Account-registration family (REGISTER/ACCOUNT/UNREGISTER): split out for
 * #543; the table below is its only caller. */
#include "core/commands_account.h"
/* AUTHENTICATE family (SASL PLAIN): split out for #543; the dispatch table
 * below is its only caller. */
#include "core/commands_auth.h"
/* Server-info family (LUSERS/ADMIN/INFO): split out for #543; the table below
 * is their only caller. */
#include "core/commands_info.h"
/* Registration family (PASS/NICK/USER): split out for
 * #543; the table below is its only caller. */
#include "core/commands_register.h"
/* SETNAME family (IRCv3 `setname`): split out for #543; the table below is
 * its only caller. */
#include "core/commands_setname.h"
/* Connection-lifecycle handlers (PING/PONG/QUIT): split out for #543; the
 * table below is their only caller. */
#include "core/commands_conn.h"
/* Welcome burst (001-005 + MOTD): split out for #543; commands_state_update()
 * and handle_motd() below are its only callers. */
#include "core/commands_welcome.h"
#include "core/batch.h"
#include "core/label.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/fanout.h"
#include "core/msg_verbs.h"
#include "core/resume.h"
#include "core/reply.h"
/* For transport_is_tls() -- the one question handle_authenticate() asks about a
 * connection before accepting a PLAIN credential (#167). */
#include "core/transport.h"
#include "federation/dispatch.h"
#include "federation/nickreg.h"
#include "federation/verbs.h"
#include "account_store.h"
#include "sasl_framework.h"
/* Phase 12: one question -- is TLS compiled in -- and the transport, for nothing here:
 * handle_starttls() sets a flag and conn_pump() does the handoff, so this file
 * never calls into OpenSSL and never names an SSL. */
#include "tls_backend.h"

/* ---------------------------------------------------------------------------
 * THE STATE ENUM IS A PROJECTION OF TWO FACTS
 * ---------------------------------------------------------------------------
 * conn_t's shape is final as of Phase 2 (2.1), so the state enum has to carry
 * both facts, and it can, because there are four combinations and four states:
 *
 *   no nick,  no  user  ->  CONN_REG_PASS   the entry state
 *   nick,     no  user  ->  CONN_REG_NICK
 *   no nick,  user      ->  CONN_REG_USER   USER sent before NICK; the state
 *                                           exists for exactly this client
 *   nick,     user      ->  CONN_REG_READY  and the welcome burst has gone
 *
 * The underlying facts are the fields -- c->nick[0] for the nick and
 * c->user_seen for the user -- so the projection is recomputed after every
 * command rather than incremented, and a client that sends its lines in an
 * unusual order ends up in the same state as one that does not. Reading it the
 * other way round ("the state counts how far it has got") is what makes a
 * "USER before NICK" client regress, and this enum has no value to regress
 * INTO.
 *
 * PASS does not appear in the table because it is neither fact. It is
 * recorded, not remembered: see handle_pass().
 *
 * AND the user check ASKS A FLAG RATHER THAN THE FIELD, which is a change to the
 * two-facts shape and the reason is above: an ident can now be REFUSED at
 * ingest (nickreg_ident_ok(), the hostmask-component rule), and a client whose
 * ident was refused registers with an EMPTY one. Reading `c->user[0]` for "a
 * USER arrived" would then mean that client never reaches CONN_REG_READY --
 * no 001, no refusal, and no way to tell it apart from a client that stopped
 * mid-registration. `c->user_seen` is set on the same path that stores the
 * ident, in handle_user(), so the flag and the field are written together and
 * cannot disagree. */
int commands_registered(const conn_t *c)
{
    return c != NULL && atomic_load_explicit(&c->state, memory_order_acquire) == CONN_REG_READY;
}

/* ---------------------------------------------------------------------------
 * Node identity, and how much of it exists yet
 * ---------------------------------------------------------------------------
 * 005's NETWORK= and 001's wording both need a network name, and 002/004/PONG
 * need the node's own name. server_t already carries `name`, validated at
 * server_init() against the 2.4 tag grammar, so that is used directly and no
 * new field is added.
 *
 * The NETWORK name is a DEPLOYMENT property rather than a node property -- a
 * mesh has many nodes and one network name -- and a second per-server field
 * would be the first half of a server-identity system. So it is a single
 * compile-time constant (NODE_NETWORK in core/commands_info.h), and the honest
 * limitation is stated rather than papered over: a node serving more than one
 * network is not expressible in Phase 3, and Phase 6's server identity is
 * where that belongs.
 */

/* Welcome burst (001-005 + MOTD): split out for #543 into
 * core/commands_welcome.c; send_welcome()/send_motd() are declared in
 * core/commands_welcome.h and called below by commands_state_update() and
 * handle_motd(). */

/* Recompute the state from the two facts, and emit the welcome burst on the
 * transition into CONN_REG_READY.
 *
 * Idempotent by construction: a repeated NICK or a second USER line leaves both
 * facts true, the projection is unchanged, and nothing is re-sent. A nickname
 * CHANGE after registration also leaves both facts true, so a nick change never
 * produces a second welcome burst -- which matters, because the burst is what a
 * client uses to decide it has connected. */
void commands_state_update(server_t *s, conn_t *c)
{
    int state;

    if (c->nick[0] != '\0' && c->user_seen != 0) {
        state = CONN_REG_READY;
    } else if (c->nick[0] != '\0') {
        state = CONN_REG_NICK;
    } else if (c->user_seen != 0) {
        state = CONN_REG_USER;
    } else {
        state = CONN_REG_PASS;
    }
    if (state == atomic_load_explicit(&c->state, memory_order_acquire)) {
        return;
    }
    /* ------------------------------------------------------------------------
     * THE CAP END GATE, and it is here rather than in cap.c because this is the
     * ONE place a connection becomes CONN_REG_READY.
     * ------------------------------------------------------------------------
     * A client that sent `CAP LS` or `CAP REQ` has a negotiation in flight, and
     * registration is HELD until `CAP END` arrives. Getting this wrong is not a
     * compatibility detail: a server that completes registration as soon as it
     * holds NICK and USER sends 001-005 in the middle of the client's CAP
     * exchange, every current client reads the burst as the answer to something
     * else, and the connection hangs with nothing in either log. cap_do_end()
     * calls back into this function, so the release is the same code path as a
     * NICK and a USER rather than a second promotion.
     *
     * The state field is left ALONE while negotiation is open, rather than being
     * set to something like CONN_REG_CAP: the enum is a projection of the two
     * facts the file header describes ("no nick, no user", ...), and inventing a
     * fourth combination for a fact that is not either of those would break that
     * projection. A connection held by CAP is a connection whose projection
     * says REG_NICK or REG_USER and whose gate says no, and the two answers are
     * about different questions.
     */
    if (state == CONN_REG_READY && cap_negotiating(c) != 0) {
        printf("[observable] reg_held: fd=%d reason=CAP_NEGOTIATING\n", c->fd);
        return;
    }
    /* And a client whose SASL exchange FAILED never registers at all. The
     * alternative -- registering it unauthenticated -- would make a client that
     * mistyped a password indistinguishable from one that chose not to
     * authenticate, and it is the second of those two that a server must be
     * able to tell apart from the first. Only the malformed-payload arm of
     * handle_authenticate() marks the connection CLOSING; the bad-credential
     * arm leaves it open so the 904 is actually written (poll_loop.c does not
     * pump the write queue of a CLOSING connection). This arm therefore holds
     * for the credential-failure path, which is the one that reaches here. */
    if (state == CONN_REG_READY && c->sasl == (int)SASL_FAILED) {
        printf("[observable] reg_held: fd=%d reason=SASL_FAILED\n", c->fd);
        return;
    }
    atomic_store_explicit(&c->state, state, memory_order_release);
    if (state == CONN_REG_READY) {
        send_welcome(s, c);
        /* THE SESSION WINDOW IS APPLIED HERE AND NOWHERE ELSE, and the position
         * is the whole of what makes it possible: this is the one place a
         * connection has all three of nick, ident and host -- the window's key
         * -- AND is about to be addressed as a client, which is what a re-join
         * needs because 3.1's table is keyed on the connection's class. Applying
         * it at NICK time would compare an EMPTY ident against every window and
         * match none; applying it at USER time would be a second place that
         * promotes a connection to ready.
         *
         * IT IS AFTER THE WELCOME BURST, and that is a client-visible ordering
         * choice rather than an accident: 001-005 and the MOTD are the server
         * introducing itself, and a client that has not been told what it
         * connected to should not be told what it is already a member of. Every
         * real client parses 376 as "the server has finished talking", and the
         * JOINs and rosters that follow read as the session coming back rather
         * than as part of the handshake.
         *
         * IT IS A NO-OP FOR EVERY CONNECTION THAT DID NOT COME BACK FROM A DROP,
         * which is every connection on a node whose clients never drop, and it
         * costs one pointer comparison when there is no table. */
        (void)resume_apply(s, c, server_now_ms());
    }
}

/* SETNAME family (IRCv3 `setname` + common-channel notify): split out for
 * #543 into core/commands_setname.c; handle_setname() is declared in
 * core/commands_setname.h and named by the table below. */

/*
 * ---------------------------------------------------------------------------
 * EVERY LOG LINE IN THIS FILE THAT NAMES A CLIENT-SUPPLIED STRING
 * ---------------------------------------------------------------------------
 * `conn_text_logsafe()` is the one rule for all of them, and it exists because
 * there were fourteen of them and each had been written as `%s`.
 *
 * A command word, a PING token, a QUIT reason, a server mask, a nickname a client
 * offered and a SASL mechanism are all bytes off a socket, and every one of them
 * reached this node's own stdout unfiltered. The reachable ones needed no
 * credential and no registration: one unrecognised verb carrying ESC in its word,
 * one `PING`, one `QUIT`. `0x07` rings a terminal's bell and ESC `[` is a CSI
 * sequence any terminal executes, so this was a way for anyone who could open a
 * socket to rewrite an operator's screen.
 *
 * WHY NOT STRIP THESE. A STRIP is for a field that is RELAYED to other people --
 * an away message, a topic, a kick reason -- where removing the byte changes what
 * they read. Every value below is LOG-ONLY: nothing else ever sees it, so there is
 * nothing to protect by rewriting it and a great deal to lose. `cmd_unknown:
 * command=NICK` is the entire diagnostic; printed with a byte removed it would
 * name a verb the client never sent. So these are MEASURED: the value is kept when
 * every byte is printable ASCII, withheld when one is not, and the length and the
 * bad-byte count go beside it either way.
 *
 * NOT ALL FOURTEEN WERE BROKEN, and the ones that were not are named at their own
 * definitions rather than here. `commands.c` prints `c->nick`, `c->user`,
 * `c->host`, `c->realname`, `c->account` and `ch->name` throughout: every one of
 * those passed `valid_nick()`, `chan_name_valid()`, `conn_realname_check()` or
 * `account_name_wire_safe()` on the way in, and a field that cannot hold a byte
 * from the set needs no second opinion on the way out.
 * ---------------------------------------------------------------------------
 */

/* Connection-lifecycle handlers (PING/PONG/QUIT): split out for #543 into
 * core/commands_conn.c; the table below is their only caller. */

static void handle_motd(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    send_motd(s, c);
}

/* ---------------------------------------------------------------------------
 * 4.2's CHOPER, and the REFUSAL POLICY for operator commands
 * ---------------------------------------------------------------------------
 * RFC 2812 3.4.1: `CHOPER <user> <password>`, answered with 381 RPL_YOUREOPER
 * on success. This node cannot produce that, and the reason is a capability
 * rather than a configuration:
 *
 *   - There is no OPERATOR anywhere in the tree. conn_t (2.1) has no operator
 *     field, `struct member` (2.2) carries +o and +v and those are CHANNEL
 *     privileges, and 004's user-mode set is "i" with nothing evaluating it.
 *   - There is no CREDENTIAL STORE. handle_pass() above is the honest version of
 *     this: PASS is recorded and never checked, and s->n_pass_seen is the whole
 *     of the record. A node with nothing to compare a password against cannot
 *     authenticate one, so it must not pretend to have tried.
 *
 * The alternative -- a CHOPER that answers 381 and grants an operator flag that
 * does not exist -- would be the single most damaging thing this command could
 * do: a client would show its owner as an IRCop, every access decision the owner
 * makes would be made by a client acting on a flag the node never set, and
 * nothing in the node's state would contradict it. So the answer is a refusal
 * whose trailing text says what is missing, and 381 is never emitted.
 *
 * ---------------------------------------------------------------------------
 * 464, AND WHY NOT 481/482
 * ---------------------------------------------------------------------------
 * 4.4's error list has 462, 464 and 482 among the numerics a CHOPER could use.
 * 461 answers the arity, because that is the numeral every handler in this node
 * uses and 4.4 lists it; 462 means the same thing and is not the house wording.
 *
 * Between 464 and 481/482 the choice is 464, and the argument is about whose
 * claim each numeric makes:
 *
 *   481 / 482  "you need to be a channel operator to use this" / "you're not a
 *              channel operator". Both are about the CALLER's privileges, and both
 *              are about CHANNEL privilege. handle_kick() uses 482 that way and
 *              is right to: there, a client with no +o really is under-privileged
 *              and the fix is real.
 *   464        "the credentials did not match". The FAILURE is not a fact about
 *              the caller, it is a fact about the SERVER: the same caller would
 *              get this with every password because there is no password. The
 *              trailing text says exactly that, and 464 is also what RFC 2812
 *              3.4.1 names for a CHOPER that did not take effect.
 *
 * Reporting it as a privilege problem would be the false claim, and a false claim
 * in a numeric that a client acts on is what this node has refused to ship
 * everywhere else -- see the 324 that must agree with the node's modes, the 432
 * that must not claim a malformed nick is taken, and the 401 that must not claim
 * an absent user is elsewhere.
 *
 * 401 IS STILL CHECKED, and it comes first, because it is a real question with a
 * real answer and a different failure: CHOPER names a person, and this node
 * either holds that nickname or does not. A node that answered 464 to every
 * CHOPER without looking would be refusing a request about a user who is
 * demonstrably here, and 464's text would be about the wrong thing entirely.
 *
 * THE PASSWORD IS NOT LOGGED, on either path. The 401 and 464 lines name the
 * target and never the password, and the observable line does the same -- the
 * same discipline handle_pass() follows, and for the same reason: a node that
 * printed a secret to its own stdout would leak it into every log collector
 * downstream of it.
 */
static void handle_choper(server_t *s, conn_t *c, const message_t *m)
{
    conn_t *who;

    if (m->nparams != 2) {
        (void)reply_refused(s, c, "CHOPER", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* fanout_find_nick() rather than server_nick_lookup(): both are the same
     * folded registry, and the wrapper is the one that carries the NULL and
     * empty-name guards. The empty-name guard is DEFENCE IN DEPTH and not a
     * reachable case from this command: 3.2 has no way to express an empty
     * middle parameter -- 4.3.1 says the same about a wire format -- so a
     * `CHOPER :<password>` reaches the arity check as a message with ONE
     * parameter and is refused there, and any name that gets past it is
     * non-empty by construction. The wrapper is used rather than the raw lookup
     * because it is the one that would be correct if that ever stopped being
     * true, and because a caller must not have to know it. */
    who = fanout_find_nick(s, m->params[0]);
    if (who == NULL) {
        (void)reply(s, c, "401", (const char *const[]){ m->params[0] }, 1,
                    "No such nick/channel");
        /* Measured, for the reason every other log-only value here is: this
         * branch is reached precisely when the name is one this node does NOT
         * hold, so it is the one place a nickname-shaped string arrives that has
         * not been through `valid_nick()`. The 401 above still names it back to
         * its sender. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, m->params[0]);
            printf("[observable] choper_refused: by=%s target=%s target_len=%zu "
                   "target_bad_bytes=%zu reason=NO_SUCH_NICK\n",
                   c->nick, shown, strlen(m->params[0]),
                   conn_text_bad_count(m->params[0]));
        }
        return;
    }

    /* 464, WHICH ANSWERS ONLY THIS: a failed SASL exchange is 904, never 464,
     * so the number alone tells a client this was an operator refusal. For a
     * client that negotiated `standard-replies` this is
     * `FAIL CHOPER ERR_NOPRIVILEGES`, which says "you are not an operator" outright. */
    (void)reply_refused(s, c, "CHOPER", NULL, "464", NULL, 0,
                        "%s cannot become an operator: this server holds no "
                        "operator flags and no operator credentials",
                        who->nick);
    printf("[observable] choper_refused: by=%s target=%s reason=NO_OPER_FLAGS "
           "oper=0 pass_seen=%llu\n",
           c->nick, who->nick, (unsigned long long)s->n_pass_seen);
}

/* CAP. A one-line pass-through to cap.c, and it is here rather than a function
 * pointer straight into cap_handle() so that the dispatch table's entry has the
 * same shape as every other entry in it. The logic is cap.c's; this says only
 * that `CAP` reaches it. */
/* ---------------------------------------------------------------------------
 * STARTTLS, and THE FOUR REFUSALS ARE THE FEATURE
 * ---------------------------------------------------------------------------
 * The upgrade itself is three lines: queue 670, flush it, let the transport take
 * over the socket. Everything that matters is in what this refuses, and each
 * refusal is a rule from a specification rather than a judgement call.
 *
 * ---------------------------------------------------------------------------
 * FIRST: THERE IS NO STARTTLS IN RFC 2812
 * ---------------------------------------------------------------------------
 * This project's Phase 11 pass built an RFC 2812 conformance table by reading the
 * RFC. RFC 2812 defines NO STARTTLS: the string does not appear in it, nor do the
 * numerics 670 and 691, and neither does the word TLS. STARTTLS is an IRCv3
 * extension -- the `tls` capability specification, which is DEPRECATED in favour
 * of `sts` -- and it is the normative source for everything below. Saying so here
 * rather than leaving a future reader to assume the RFC says it is the difference
 * between a documented citation and a plausible one, and the `sts` specification's
 * own relationship section is what makes the point: STS "is incompatible with
 * servers that offer secure connections only via STARTTLS on an insecure port."
 * STARTTLS is implemented because the command is real and clients use it; `sts` is
 * advertised because it is the mechanism that actually protects anything.
 *
 * ---------------------------------------------------------------------------
 * THE REFUSALS, in the order they are checked, and why that order
 * ---------------------------------------------------------------------------
 *   1. NOT CONFIGURED     this build has no TLS, or this node has no certificate.
 *                         691. Checked FIRST because it is the only one that is a
 *                         permanent property of the node: everything below is a
 *                         statement about this connection.
 *
 *   2. ALREADY TLS        691. Refusing is not politeness -- it is arithmetic. A
 *                         second STARTTLS would mean a second handshake layered
 *                         inside the first one's session, and a client that
 *                         expected one would read the ServerHello as IRC and hang.
 *
 *   3. AFTER A CREDENTIAL 691, AND THIS IS THE ONE THAT IS EASY TO GET WRONG. The
 *                         whole point of upgrading is that what follows is private.
 *                         If a client has already sent a password, upgrading does
 *                         not un-send it: an attacker who has been reading the
 *                         plaintext prefix has the credential, and everything after
 *                         the upgrade being encrypted is a very comfortable
 *                         theatre. So a connection that has carried a PASS value or
 *                         an AUTHENTICATE payload is REFUSED -- including when the
 *                         credential was refused, which is what
 *                         conn_t::credential_seen's comment is about.
 *
 *                         IT IS CHECKED BEFORE THE REGISTRATION RULE BELOW, and
 *                         that is a decision rather than an ordering accident: see
 *                         the comment at the check.
 *
 *   4. AFTER REGISTRATION 691. The `tls` specification: "To use STARTTLS a client
 *                         simply sends the STARTTLS command to the server BEFORE
 *                         THE CLIENT REGISTERS WITH THE SERVER USING THE NICK AND
 *                         USER COMMANDS". After registration this node has already
 *                         emitted 001-005, MOTD and possibly a JOIN; a client that
 *                         re-handshakes mid-registration has a burst half-sent in
 *                         the clear and the rest encrypted, and a peer relaying
 *                         those lines sees two different transports on one
 *                         connection. There is no version of this that is safe to
 *                         allow, and the specification's position is that it is not
 *                         a thing to allow.
 *
 * A legitimate client costs nothing by this: every current client that wants TLS
 * either connects to the implicit-TLS port (RFC 7194) or sends STARTTLS first
 * thing, before NICK and USER. The order is not an inconvenience; it is the
 * specification's.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DISCARDED ON SUCCESS, and it is a security step rather than a tidy-up
 * ---------------------------------------------------------------------------
 * `c->rlen = 0` below. The read buffer may hold lines the client PIPELINED behind
 * its STARTTLS -- `STARTTLS\r\nJOIN #x\r\n` in one segment, which every capable
 * client library will do -- and those lines arrived IN THE CLEAR, before the peer
 * proved anything. Leaving them in the buffer would mean dispatching them after the
 * handshake, as though they had arrived over the encrypted connection: an attacker
 * who could inject into the plaintext prefix could have them executed on a
 * connection the operator believes is authenticated and encrypted.
 *
 * The write queue is NOT cleared, and the asymmetry is deliberate: everything in it
 * was queued before the upgrade and is being sent in the clear legitimately (the
 * 670 itself is in there), and the node has nothing it would be ashamed to send
 * before a handshake.
 *
 * ---------------------------------------------------------------------------
 * 670 AND 691 ARE NOT IN RFC 2812 EITHER
 * ---------------------------------------------------------------------------
 * They come from the same deprecated `tls` extension, which gives them verbatim:
 * "the server then sends numeric 670 (RPL_STARTTLS)" and "If there is an error
 * with setting up TLS on the server side, the server must send numeric 691
 * (ERR_STARTTLS) containing a human-readable description of the error as its
 * parameter." RFC 2812 4.5 assigns 6xx to ERR_* and 670/691 fall in that range, so
 * the shape is the RFC's even though the two numbers are not. Every 691 below
 * carries a distinct text, because the specification says the text is for a human
 * and a client cannot machine-parse it: an operator reading the log needs to know
 * WHICH rule fired, and one shared "STARTTLS failed" would be the least useful
 * thing in the file. */
static void handle_starttls(server_t *s, conn_t *c, const message_t *m)
{
    /* ARITY FIRST, and it is 461 rather than 691. A STARTTLS with a parameter is a
     * malformed command, and 461 is this node's answer for that everywhere else; a
     * 691 here would claim the server tried and failed at TLS on a line that never
     * named TLS. */
    if (m->nparams > 0) {
        (void)reply_refused(s, c, "STARTTLS", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (tls_backend_available() == 0 || s->tls == NULL) {
        (void)reply(s, c, "691", NULL, 0, "STARTTLS failed: TLS is not available "
                                            "on this server");
        printf("[observable] starttls_refused: fd=%d reason=TLS_NOT_CONFIGURED\n",
               c->fd);
        return;
    }
    if (c->tls_active != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: this connection is already using TLS");
        printf("[observable] starttls_refused: fd=%d reason=ALREADY_TLS\n", c->fd);
        return;
    }
    /* THE CREDENTIAL CHECK COMES BEFORE THE REGISTRATION CHECK, and the order is
     * the point.
     *
     * Both are refusals and both are correct, so the only question is which reason
     * an operator and a client are told -- and a client that has sent a password
     * AND then registered has done both things, and the one it needs to hear about
     * is that its password went out in the clear. "it is only available before
     * registration" would be true and would hide the finding that matters: that this
     * node is being asked to make an encrypted connection out of a socket that has
     * already leaked a credential, and that somebody needs to go and change it.
     *
     * Checking registration first was the first version, and it produced exactly
     * that: a client which sent PASS, NICK, USER, STARTTLS -- which is what a
     * client that has decided to authenticate does -- was told it was too late,
     * with no mention of the password. A refusal that is true and incomplete is
     * worse than one that is verbose. */
    if (c->credential_seen != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: a credential has already been sent on this "
                    "connection in the clear");
        printf("[observable] starttls_refused: fd=%d "
               "reason=AFTER_CREDENTIAL\n", c->fd);
        return;
    }
    if (atomic_load_explicit(&c->state, memory_order_acquire) != CONN_REG_PASS) {
        int st = atomic_load_explicit(&c->state, memory_order_acquire);
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: it is only available before registration");
        printf("[observable] starttls_refused: fd=%d reason=AFTER_REGISTRATION "
               "state=%d\n", c->fd, st);
        return;
    }
    /* THE DISCARD, before the confirmation and not after it: a line that arrived
     * in the clear must never be dispatched after the handshake. */
    c->rlen = 0;
    /* The 670, in the clear, with the specification's own wording. It is QUEUED
     * and not sent, and this handler never touches the socket -- which is not a
     * style preference but reply.c's whole rule, the one
     * tests/integration/test_reply_guard.c asserts by inspection: a handler that
     * reaches past reply() into the transport is a second place that decides what
     * reaches a connection.
     *
     * THE ORDERING IS NONE THE WORSE FOR IT, and that is the part worth checking.
     * conn_queue() raises want_write, so the loop's very next poll set asks for
     * POLLOUT; conn_on_writable() drains the queue through conn_pump(); and
     * conn_pump() starts the handshake only once the queue is EMPTY. So the 670 is
     * on the wire before the first byte of the handshake by construction, and it is
     * on the wire because the LOOP put it there.
     *
     * An earlier version of this handler called conn_pump() directly, to make the
     * 670 prompt. That cost test_reply_guard's invariant for no benefit: the loop
     * flushes within one tick either way, because the socket is writable. That is
     * what a suite is for -- the rule was written before this handler existed and
     * it was right. */
    c->starttls_pending = 1;
    (void)reply(s, c, "670", NULL, 0, "STARTTLS successful, proceed with TLS "
                                      "handshake");
    printf("[observable] starttls_agreed: fd=%d\n", c->fd);
}

static void handle_cap_wrapper(server_t *s, conn_t *c, const message_t *m)
{
    cap_handle(s, c, m);
}

/* ---------------------------------------------------------------------------
 * CAP and AUTHENTICATE (Phase 8)
 * ---------------------------------------------------------------------------
 * Both are pre-registration verbs, and BOTH HAVE TO BE: the protocol puts CAP
 * before NICK and USER, and RFC 4422's SASL is answered inside the registration
 * burst rather than after it. Marking either `pre_reg = 0` would answer 451 to a
 * client that is doing exactly what the specification says, which is the failure
 * that hangs every modern client.
 *
 * The handlers live here rather than in cap.c and a new sasl handler file because
 * this is the dispatch table and a verb with no entry here cannot be reached at
 * all. The LOGIC lives in cap.c and sasl_framework.c; these two functions are the
 * wire. */

/* ---------------------------------------------------------------------------
 * The command table
 * ------------------------------------------------------------------------ */

/* Every verb 4.1 lists is HERE, with a NULL handler for the ones a later phase
 * implements. That is not padding: it is what lets the node tell "I have never
 * heard of JOIN" (421) from "JOIN arrives in Phase 4" (also 421, because the
 * wire has no numeric for "not yet"), and the [observable] line records which of
 * the two it was. Without the table, a verb could only be answered by falling
 * through to the unknown-command path -- the quiet failure the 421 test exists
 * to catch. */
typedef struct {
    const char *verb;
    void (*fn)(server_t *, conn_t *, const message_t *);
    int pre_reg; /* legal before CONN_REG_READY */
} command_t;

static const command_t k_commands[] = {
    { "PASS",    handle_pass,  1 },
    /* 7/Phase 8. Both are pre-registration verbs: CAP is sent BEFORE NICK and
     * USER by every current client, and SASL is answered inside the registration
     * burst. `pre_reg = 1` on both is load-bearing -- see the comment above
     * handle_cap() and handle_authenticate(). */
    { "CAP",     handle_cap_wrapper, 1 },
    { "AUTHENTICATE", handle_authenticate, 1 },
    /* Phase 12: STARTTLS. `pre_reg = 1` is the whole of the specification's rule
     * and it is enforced a second time inside the handler, because a client that
     * sends STARTTLS after NICK and USER must be answered 691 rather than 451 --
     * "you have not registered" is a lie about a connection that HAS registered,
     * and the honest answer names the real problem. So `pre_reg = 1` gets the
     * command to the handler on a registered connection, and the handler decides.
     * That is why this row sits with CAP and AUTHENTICATE and not with MOTD: it
     * is a command whose legality DEPENDS ON HOW FAR REGISTRATION GOT, and a
     * connection in the middle of registering is the case it exists for. */
    { "STARTTLS", handle_starttls, 1 },
    { "NICK",    handle_nick,  1 },
    { "USER",    handle_user,  1 },
    { "PING",    handle_ping,  1 },
    { "PONG",    handle_pong,  1 },
    { "QUIT",    handle_quit,  1 },
    { "MOTD",    handle_motd,  0 },
    /* 7/Phase 4: the channel surface. LIST is here rather than being left for
     * Phase 7, because a channel this node will not tell a client about is a
     * channel whose origin, members and topic are all invisible, and the whole
     * 2.2 data model would be observable only from the [observable] log. */
    { "LIST",    handle_list,  0 },
    /* 4.1, later phases. */
    { "JOIN",    handle_join,  0 },
    { "PART",    handle_part,  0 },
    { "TOPIC",   handle_topic, 0 },
    { "NAMES",   handle_names, 0 },
    { "MODE",    handle_mode,  0 },
    { "KICK",    handle_kick,  0 },
    { "KILL",    NULL,         0 },
    /* 7/Phase 5: the messaging surface, and the point at which the node becomes
     * usable. PRIVMSG and NOTICE are 4.1 MUST; WHO, WHOIS, ISON and AWAY are
     * 4.2 SHOULD, pulled forward here because 4.2's own list puts them in the
     * same phase as the message path and a client that cannot ask "who is here"
     * or "is this nick online" is a client this milestone has not delivered.
     *
     * The table is ordered by the RFC's 4.1/4.2 order, and 3.3.2's grouping, so
     * the surface reads as the specification does. */
    { "PRIVMSG", handle_privmsg, 0 },
    { "NOTICE",  handle_notice,  0 },
    { "WHO",     handle_who,     0 },
    { "WHOIS",   handle_whois,   0 },
    { "ISON",    handle_ison,    0 },
    { "AWAY",    handle_away,    0 },
    /* 7/Phase 7: the rest of 4.2, in 4.2's own order. INVITE and KNOCK are in
     * chan_verbs.c because both are about a channel; USERHOST is in
     * msg_verbs.c because it has no channel in it; the server-info family is
     * below, next to the MOTD it belongs with. The order in the table is
     * 4.2's and not the order of the files, for the same reason the table is
     * ordered by the RFC's rather than by the history: a reader comparing the
     * surface against the specification should be able to do it down this list
     * without a map. */
    { "INVITE",  handle_invite,  0 },
    { "USERHOST", handle_userhost, 0 },
    { "KNOCK",   handle_knock,   0 },
    /* 7/Phase 7, the rest of 4.2: the server-info family, which lives next to
     * the MOTD above because it is the same question -- what is this node -- and
     * CHOPER, which is the operator half of the same surface and is answered by
     * a refusal policy rather than a feature. */
    { "LUSERS",  handle_lusers,  0 },
    { "ADMIN",   handle_admin,   0 },
    { "INFO",    handle_info,    0 },
    { "CHOPER",  handle_choper,   0 },
    /* 7/Phase 10.1: the account-registration pair, REFUSED rather than
     * unimplemented, and in the table rather than left to the 421 path for the
     * reason handle_register()/handle_unregister() give. A client that sends
     * REGISTER and gets 421 would read "this server has never heard of
     * REGISTER"; this node HAS heard of it and has decided. The distinction is
     * the whole of what a refusal is, and 421 cannot express it. */
    { "REGISTER",   handle_register,   0 },
    { "UNREGISTER", handle_unregister, 0 },
    /* 7/Phase 10.6: IRCv3's `setname`. NOT `pre_reg`, which is gate 1 of the three
     * in handle_setname() -- an unregistered connection has an EMPTY realname, so
     * without the gate a SETNAME would "succeed" at setting state that does not
     * exist yet. The verb is IN the table even though the capability gates what it
     * does, because the specification requires the command to be supported whether
     * or not the client negotiated it: a client that sent SETNAME and got 421 would
     * read "this server has never heard of it". */
    { "SETNAME",    handle_setname,    0 },
    /* 7/Phase 10.12: IRCv3 `batch`. `pre_reg`, and that is a decision worth the
     * comment: a client that batches its OWN registration lines is legal -- the
     * reference tags are a property of any command -- and holding the gate closed
     * until `001` would mean the `001`-`005` burst escaped the batch a client had
     * legitimately opened around it. The batch state is per connection and lives in
     * conn_t, so nothing here can reach another client's. */
    { "BATCH",      handle_batch,      1 },
    /* 7/Phase 10.2b: the account-notify query. NOT `pre_reg`, because the answer
     * carries this connection's hostmask and a pre-registration connection has no
     * nickname to put in it -- an unregistered client sending ACCOUNT gets 451,
     * which is the RFC's own answer for "you have not registered yet". */
    { "ACCOUNT",    handle_account,    0 }
};

static const command_t *lookup(const char *verb)
{
    if (verb == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof k_commands / sizeof k_commands[0]; i++) {
        if (strcmp(k_commands[i].verb, verb) == 0) {
            return &k_commands[i];
        }
    }
    return NULL;
}

void commands_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const command_t *cmd;

    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* 3: the peer path is the SAME dispatch, and dispatch "never asks 'is this
     * local or remote?' -- src->kind is the only difference". So a peer line is
     * not routed around this function; it arrives here and is handed to the
     * guard chain on the strength of src->kind and nothing else. That is the
     * whole of the difference between the two paths, and putting it here rather
     * than in poll_loop.c's read step is what keeps there ONE door into a
     * command: a second entry point into fed_dispatch() would be a second way
     * for a future line to arrive without passing 2.4's guards.
     *
     * ABOVE THE CONN_CLOSING CHECK, deliberately and specifically. A peer link
     * is a TCP connection like any other, so one segment can carry a peer's last
     * line AND its close; the close marks the conn CLOSING, and the check below
     * would then drop the line that arrived in the same read. Losing a peer's
     * final state change because it happened to share a segment with a FIN is
     * exactly the kind of loss 2.2's cache is supposed to self-heal from and
     * usually does not: there is no later burst to correct it until Phase 9.
     * The check itself still applies to CLIENTS, where a dropped line after a
     * QUIT is correct behaviour.
     *
     * The `c == NULL` guard above means a peer line cannot reach here without a
     * connection, and fed_dispatch() repeats it. */
    if (c->kind == CONN_SERVER) {
        fed_dispatch(s, c, m);
        return;
    }

    /* A connection on its way out gets nothing. The reaper closes it at the
     * next fixed point, so a reply here would be queued onto a socket the loop
     * has already dropped from its poll set. Reachable: one TCP segment
     * carrying "QUIT :bye" and "PING :are you there" hands this function a
     * second line after the first has already marked the conn CLOSING. */
    if (atomic_load_explicit(&c->state, memory_order_acquire) == CONN_CLOSING) {
        /* Measured, like poll_loop.c's `line:` and for the same reason: this is a
         * verb off a socket and a verb is an identifier, so the value is kept when
         * it is printable and withheld when it is not. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_dropped: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu reason=closing\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    cmd = lookup(m->command);

    /* The registration gate comes BEFORE the unknown-command check, which is
     * the order RFC 2812 3.1 specifies and the one clients expect: an
     * unrecognised verb from an unregistered connection is 451, because "you
     * have not registered" is both true and actionable, while "unknown command"
     * would be neither. */
    if (!commands_registered(c) && (cmd == NULL || cmd->pre_reg == 0)) {
        (void)reply(s, c, "451", NULL, 0, "You have not registered");
        return;
    }

    if (cmd == NULL) {
        const char *mid[1];

        /* THE 421 ECHOES THE VERB BACK VERBATIM AND THAT STAYS. The verb is going
         * to the client that sent it, so there is no second reader and no hazard,
         * and RFC 2812 3.3.4's 421 names the command precisely so a client can
         * match it. It is the LOG that needed the measurement, and only the log.
         *
         * This is also the most exposed single line on the node: an unrecognised
         * verb is answerable before registration, needs no credential, and nothing
         * examined the word before it was printed. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unknown: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }
    if (cmd->fn == NULL) {
        const char *mid[1];

        /* A known 4.1 verb this build does not implement. 421 is a slight lie
         * about the reason -- the wire has no numeric for "not yet" -- but the
         * alternative is silence, and silence is the failure mode these
         * numerics exist to prevent. The [observable] line says which of the
         * two it was, so a log reader is not misled. */
        /* As `cmd_unknown` above, and for the same reason: the 421's <command> field
         * is rendered by `emit_numeric_ex()` in reply.c -- the single place a
         * numeric's parameters are filtered -- and the LOG measures the value rather
         * than printing it raw. `KILL` is the verb that reaches this branch on this
         * build, so the line is not hypothetical. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unimplemented: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* THE `batch` HOOK, AND WHY IT BRACKETS THE HANDLER RATHER THAN PRECEDING IT.
     *
     * `batch_begin_command()` is what turns an inbound line's `@`/`+` reference tags
     * into two things this dispatch then makes true: a `batch=` tag on the response
     * (a one-shot, consumed by the reply path) and a SUPPRESSION that lasts exactly as
     * long as the command. Both have to be set BEFORE `cmd->fn` runs -- a handler's
     * first byte of output is already too late for the first, and the second would be
     * cleared by `batch_end_command()` before it was ever set.
     *
     * AND `batch_end_command()` IS NOT OPTIONAL ON ANY PATH, which is why it is after
     * the call rather than inside an error branch: a suppressed flag that survived a
     * command would swallow the NEXT command's replies too, and the symptom would be
     * a client that goes silent for no reason it can see. There is exactly one exit
     * from `cmd->fn()` that is not a `return`, because every handler returns.
     *
     * IT IS HERE AND NOT IN reply.c, because reply.c cannot know when a command
     * starts: it only sees outbound lines, and "which of them is the FIRST line of
     * this command's response" is not a property of any one of them. */
    batch_begin_command(c, m);
    label_begin_command(c, m);
    cmd->fn(s, c, m);
    /* THE TAIL. Two things have to happen after the handler and not inside it, and both
     * are "what remains to be said" questions that a handler cannot answer because it
     * does not know what the handler emitted:
     *
     *   label_finish_command()  closes the `labeled-response` batch if one was opened,
     *                           or answers `ACK` if the command produced nothing. A
     *                           handler returning early on a refusal has still produced
     *                           a response -- the refusal -- so the label goes on THAT,
     *                           which is why the tail asks what was emitted rather than
     *                           asking whether the handler returned.
     *   batch has no tail       a client batch is closed by the client.
     *
     * IT IS NOT OPTIONAL ON ANY PATH, and every path here ends in this call: a
     * `label_live` that outlived its command would label the NEXT command's first line
     * with a value the client was already told was finished.
     */
    label_finish_command(s, c);
}
