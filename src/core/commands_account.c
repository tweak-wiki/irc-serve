/* commands_account.c -- see commands_account.h. The account-registration
 * family, verbatim out of commands.c; the table that calls the handlers still
 * lives there.
 */
#include "core/commands_account.h"

#include <stdio.h>

#include "core/account.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * REGISTER and UNREGISTER -- REFUSED, and this is the decision rather than the
 * omission. Read the argument before changing the answer.
 * ---------------------------------------------------------------------------
 * The IRCv3 `account-registration` specification is in k_caps[]' absence and in
 * both of these handlers. Four independent reasons, and each of them is
 * sufficient on its own; they are given in the order they would stop a reviewer.
 *
 * 1. THE SPECIFICATION SAYS NOT TO. `account-registration` is a
 *    work-in-progress document whose own header says implementations "MUST NOT
 *    use the unprefixed account-registration capability name", SHOULD use
 *    `draft/account-registration` instead, and that the specification "may change
 *    at any time and we do not recommend implementing it in a production
 *    environment". Shipping a stable command named `REGISTER` that a draft will
 *    later redefine is how a server ends up un-upgradable without anyone noticing.
 *
 * 2. ITS WIRE FORM WAS NOT AVAILABLE WHEN THIS WAS WRITTEN, and half of that
 *    reason has since expired. The draft answers with the standard replies
 *    framework -- `FAIL ACCOUNT_REGISTER <reason>` -- and this node had no FAIL at
 *    the time, so there was no numeric a real client parses as a registration
 *    answer. Phase 10.9 landed `standard-replies`, so the form EXISTS now and the
 *    refusal below renders as `FAIL REGISTER ERR_ACCOUNTREGISTRATIONDISABLED` for
 *    a client that negotiated it.
 *
 *    WHAT THE ARRIVAL DID NOT CHANGE IS THE DECISION, and that is worth being
 *    blunt about rather than leaving a reader to wonder whether reason 2 quietly
 *    expired and took the refusal with it: **being able to say the right thing is
 *    not a reason to say it.** Reasons 3 and 4 are the ones that hold, and neither
 *    mentions the wire form. A node that could answer the command truthfully
 *    should still refuse it, and the refusal is now the more precise of the two
 *    renderings rather than a compromise.
 *
 * 3. OPEN REGISTRATION IS NOT A FEATURE HERE, IT IS A NAME-CLAIMING PRIMITIVE.
 *    REGISTER takes a password and an optional email and, without a verification
 *    mail and without a rate limit, the ONLY thing stopping an unauthenticated
 *    client from taking any name is the speed of the connection. And taking a
 *    name is not a nuisance here: once `account-tag` exists, an account name is
 *    stamped on every message a client sends, and the entire value of the tag is
 *    that it means "this is who this is". An open registry makes that value
 *    worthless to every honest user while remaining perfectly usable as an
 *    impersonation tool against them -- so the failure mode is not "the feature
 *    is half-built", it is "the feature actively harms the people it was built
 *    for". There is no rate limiter, no captcha and no mail path in this tree,
 *    and the account store is READ-ONLY after startup: there is no write in this
 *    tree that could record a registration even if one were allowed.
 *
 * 4. UNREGISTER IS WORSE THAN NOTHING, which is why it is refused too and not
 *    implemented. The store is an operator's file, loaded once before the loop
 *    (3.4 forbids a blocking write inside it), so an in-memory removal would
 *    vanish on the next restart. A client told "your account has been deleted"
 *    and then finding it intact after a restart has been told a falsehood by a
 *    server that is supposed to be the authority on whether an account exists --
 *    and account deletion is precisely the case where a user is relying on the
 *    answer. Refusing is the only answer that is true at every moment.
 *
 * THE THREAT MODEL, stated once and plainly: on a node with this pair of
 * commands refused, an attacker can still connect, register a nickname, send
 * messages, and join channels -- everything this node has always allowed. What
 * they CANNOT do is assert an account identity, because the only writer of
 * conn_t::account is account_set() and it requires a credential the operator's
 * credential store holds AND a registry entry the operator's registry holds.
 * That is the whole of the model, and the cost of it is that accounts on this
 * node are created by an operator editing a file. That cost is stated rather than
 * hidden: it is real, it is the reason a deployment with open registration
 * should not use this node, and it is cheaper than the alternative.
 *
 * ---------------------------------------------------------------------------
 * 482, AND WHY IT IS WRONG
 * ---------------------------------------------------------------------------
 * 482 ERR_CHANOPRIVSNEEDED. Not in RFC 1459's sense -- it is not about a channel
 * -- but its own RFC text is "Permission Denied- You're not an IRC operator",
 * and that is the truest available answer: this node has NO operator concept at
 * all, so a client that has not been made one is being told the truth. It is also
 * the numeric CHOPER already answers with, for the same reason, and reusing it
 * keeps "there is no operator here" to one numeric.
 *
 * The honest numeric is `FAIL ACCOUNT_REGISTRATION NOT_ENABLED`, and it does not
 * exist until standard-replies does. That gap is recorded in the design rather
 * than papered over, and it is the third of the four reasons above.
 */
static void account_refuse(server_t *s, conn_t *c, const char *verb,
                           const char *text)
{
    /* 482, WHICH ON THIS NODE ALSO MEANS "NOT A CHANNEL OPERATOR" (KICK, MODE,
     * INVITE) and "NOT AN IRC OPERATOR" (KNOCK). A REGISTER refused because the
     * deployment has no open registration is a third fact wearing the same number,
     * and `verb` is already the command word the `FAIL` needs -- which is why this
     * site's code is an override rather than the table's. */
    (void)reply_refused(s, c, verb, "ERR_ACCOUNTREGISTRATIONDISABLED", "482", NULL, 0,
                        "%s", text);
    printf("[observable] account_cmd_refused: fd=%d nick=%s verb=%s "
           "reason=OPERATOR_SIDE_REGISTRY registry=%s\n",
           c->fd, (c->nick[0] != '\0') ? c->nick : "*", verb,
           (s->account_store != NULL) ? "loaded" : "none");
}

/* REGISTER <password> [email]. Refused unconditionally and without reading the
 * arguments, and the arity is NOT checked first: a `REGISTER` with no password
 * and a `REGISTER` with one both get the same answer, because answering one of
 * them differently would be a way to probe which inputs the node recognises --
 * which is the shape of every oracle this tree has refused to build. */
void handle_register(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    account_refuse(s, c, "REGISTER",
                   "REGISTER is not available: this node's accounts are created "
                   "by its operator in a registry file");
}

/* ---------------------------------------------------------------------------
 * ACCOUNT -- the account-notify query, and the collision that had to be resolved
 * deliberately rather than by accident
 * ---------------------------------------------------------------------------
 * `ACCOUNT` was, in the retired draft, the NICKNAME-CHANGE command: a client
 * changed its nick and supplied a password in one command, and `ACCOUNT
 * <password>` is the shape every server of that era accepted.
 *
 * **WHAT THIS NODE DISPATCHED BEFORE THIS PASS: NOTHING.** There was no
 * `ACCOUNT` row in k_commands[] at all, so a client that sent it got 421 -- "I
 * have never heard of this verb" -- and a nickname change was, and still is, `NICK
 * <newnick>` and nothing else (handle_nick(), above). So there was no live
 * nick-change verb to collide with, and adding this row cannot break a nick
 * change: the two words have never reached the same switch.
 *
 * The IRCv3 position is that the nick-change MEANING is gone rather than merely
 * unfashionable: an account association changed through the account service, not
 * through the server, and a server that took a password on a nickname change was
 * a server asking for a credential it had no way to verify. What survives is the
 * name, reused by `account-notify` for a completely different fact.
 *
 * THE TWO SHAPES ARE ALSO DISJOINT, which is worth saying because it is the reason
 * the collision costs nothing rather than merely nothing today:
 *
 *   the retired nick-change form  ACCOUNT <password>   ONE parameter
 *   the query below               ACCOUNT              ZERO parameters
 *
 * So a client still speaking the retired dialect gets 461 for a verb with a
 * parameter, not a nickname change. That is the right answer and it is also the
 * reason a future phase that wanted a one-parameter ACCOUNT would have to decide
 * to take it back rather than find it already spoken for.
 *
 * WHAT IS *NOT* HERE, and is the honest limit of this implementation:
 * `ACCOUNT <account> FAIL`. There is no logout on this node -- SASL PLAIN has no
 * logout and there is no account service to log out of, and account_clear() runs
 * only from server_close_conn(), where the connection is already gone -- so there
 * is no event the form describes. account.h says where an emitter would go if a
 * phase adds one. */
void handle_account(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams != 0) {
        (void)reply_refused(s, c, "ACCOUNT", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] account_cmd_refused: fd=%d nick=%s verb=ACCOUNT "
               "reason=arity nparams=%d\n", c->fd, c->nick, m->nparams);
        return;
    }
    /* ANSWERED REGARDLESS OF THE CAPABILITY, because the client ASKED. The
     * capability governs the unsolicited line at the end of the welcome burst;
     * refusing a question a client put on the wire would be a node that knows the
     * answer and will not give it. */
    account_notify_current(s, c);
}

/* UNREGISTER [password]. Refused unconditionally, for reason 4 above. */
void handle_unregister(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    account_refuse(s, c, "UNREGISTER",
                   "UNREGISTER is not available: this node's accounts are created "
                   "by its operator in a registry file");
}
