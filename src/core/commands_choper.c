/* commands_choper.c -- see commands_choper.h. 4.2's CHOPER and the refusal
 * policy for operator commands, verbatim out of commands.c; the dispatch
 * table that calls handle_choper() still lives there.
 */
#include "core/commands_choper.h"

#include <stdio.h>
#include <string.h>

#include "core/connection.h"
#include "core/reply.h"

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
 * NO NICK LOOKUP HAPPENS, and no 401 is emitted (#673). params[0] names an
 * account in a credential store, not an online nick, and there is no store to
 * resolve it against -- so a lookup in the nick table answers a question
 * nobody asked, and its 401 makes the refusal depend on who happens to be
 * online (a user-enumeration oracle on top of a wrong numeric). The flow never
 * needs an online target, so the handler answers 464 unconditionally; when an
 * oper model lands, the lookup target becomes the store, not the nick table.
 *
 * THE PASSWORD IS NOT LOGGED. The 464 line names the target and never the
 * password, and the observable line does the same -- the
 * same discipline handle_pass() follows, and for the same reason: a node that
 * printed a secret to its own stdout would leak it into every log collector
 * downstream of it.
 */
void handle_choper(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams != 2) {
        (void)reply_refused(s, c, "CHOPER", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* No nick lookup: params[0] names a credential account, not an online
     * nick, and there is no credential store to check it against -- so the
     * only honest answer is the 464 refusal, whether or not the name is
     * online. The name echoes back verbatim: with no registry involved there
     * is nothing to canonicalise its case against. */
    (void)reply_refused(s, c, "CHOPER", NULL, "464", NULL, 0,
                        "%s cannot become an operator: this server holds no "
                        "operator flags and no operator credentials",
                        m->params[0]);
    /* Logged through conn_text_logsafe(): unlike the old online-target path,
     * this name never passed through valid_nick(), so it is untrusted log
     * input. The password is never logged. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, m->params[0]);
        printf("[observable] choper_refused: by=%s target=%s target_len=%zu "
               "target_bad_bytes=%zu reason=NO_OPER_FLAGS oper=0 pass_seen=%llu\n",
               c->nick, shown, strlen(m->params[0]),
               conn_text_bad_count(m->params[0]),
               (unsigned long long)s->n_pass_seen);
    }
}

/* KILL, refused. RFC 2812 3.7.1 gates KILL on an IRC operator, and this node
 * has none (see the file comment), so every KILL from a client is 481. No
 * arity check: the answer does not depend on the parameters. */
void handle_kill(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    (void)reply_refused(s, c, "KILL", NULL, "481", NULL, 0,
                        "You're not an IRC operator");
    printf("[observable] kill_refused: by=%s reason=NO_OPER_FLAGS\n",
           c->nick);
}
