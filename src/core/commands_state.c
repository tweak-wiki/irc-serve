/* commands_state.c -- see commands_state.h. The registration projection
 * (commands_registered() and commands_state_update()): the two facts every
 * handler reads and the one promotion to CONN_REG_READY, verbatim out of
 * commands.c; the welcome burst they trigger lives in commands_welcome.c.
 */
#include "core/commands_state.h"

/* Welcome burst (001-005 + MOTD): split out for #543 into
 * core/commands_welcome.c; commands_state_update() below calls in through
 * this header. */
#include "core/commands_welcome.h"

#include <stdatomic.h>
#include <stdio.h>

#include "core/cap.h"
#include "core/resume.h"
#include "sasl_framework.h"

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
