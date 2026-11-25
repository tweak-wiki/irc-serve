/* commands.c -- see commands.h. The registration projection
 * (commands_registered() and commands_state_update()): the two facts every
 * handler reads and the one promotion to CONN_REG_READY. The welcome burst
 * (001-005 + MOTD) lives in core/commands_welcome.c (#543), registration
 * (PASS/NICK/USER) in core/commands_register.c (#543), the
 * connection-lifecycle handlers (PING/PONG/QUIT) in core/commands_conn.c,
 * and the dispatch seam (the command table both a client line and a peer
 * line arrive at) in core/commands_dispatch.c (#543).
 */
#include "core/commands.h"

/* Welcome burst (001-005 + MOTD): split out for #543;
 * commands_state_update() below calls in through this header. */
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
 * core/commands_welcome.h and called below by commands_state_update(). */

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
 * core/commands_setname.h and named by the table in commands_dispatch.c. */

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
 * core/commands_conn.c; the table in commands_dispatch.c is their only
 * caller. */

/* MOTD handler: split out for #543 into core/commands_welcome.c;
 * handle_motd() is declared in core/commands_welcome.h and named by the
 * table in commands_dispatch.c. */

/* 4.2's CHOPER, and the REFUSAL POLICY for operator commands: split out for
 * #543 into core/commands_choper.c; handle_choper() is declared in
 * core/commands_choper.h and named by the table in commands_dispatch.c. */

/* STARTTLS family (upgrade refusals + CAP pass-through): split out for
 * #543 into core/commands_starttls.c; handle_starttls() and
 * handle_cap_wrapper() are declared in core/commands_starttls.h and named
 * by the table in commands_dispatch.c. */

/* The dispatch seam (command table + lookup + commands_dispatch()): split
 * out for #543 into core/commands_dispatch.c; declared in
 * core/commands_dispatch.h and re-exported through core/commands.h. */

