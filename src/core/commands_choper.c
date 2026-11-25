/* commands_choper.c -- see commands_choper.h. 4.2's CHOPER and the refusal
 * policy for operator commands, verbatim out of commands.c; the dispatch
 * table that calls handle_choper() still lives there.
 */
#include "core/commands_choper.h"

#include <stdio.h>
#include <string.h>

#include "core/fanout.h"
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
void handle_choper(server_t *s, conn_t *c, const message_t *m)
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
