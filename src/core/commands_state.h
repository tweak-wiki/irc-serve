/* commands_state.h -- the registration projection.
 *
 * Split out of core/commands.c (#543): commands_registered() and
 * commands_state_update() moved verbatim. commands.h includes this so all
 * existing consumers work untouched. No static helpers move: every callee
 * (cap_negotiating, send_welcome, resume_apply, server_now_ms) is already
 * extern.
 */
#ifndef IRC_CORE_COMMANDS_STATE_H
#define IRC_CORE_COMMANDS_STATE_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* Is this connection past the registration gate? CONN_REG_READY is the only
 * state in which a client command other than the registration verbs is legal,
 * and it is the state the welcome burst has already been sent for. Exposed
 * because the rule "a command before registration is 451, not silence" is a
 * property of the state encoding rather than of any one handler, and a test
 * that cannot ask the question cannot check it. */
int commands_registered(const conn_t *c);

/* Recompute this connection's registration state from its two facts and emit the
 * welcome burst if the transition into CONN_REG_READY happened.
 *
 * EXPOSED, and it is one function rather than the static it was, because Phase 8
 * has a second caller: `CAP END` releases the negotiation hold, and a client that
 * sent NICK, USER, CAP LS and then CAP END must register from THAT call. Exposing
 * it keeps one promotion to CONN_REG_READY in the tree rather than two, and the
 * two gates it enforces -- the CAP hold and the SASL failure hold -- stay in one
 * place for the same reason. Idempotent: a repeated NICK or USER leaves both
 * facts true, the projection is unchanged, and nothing is re-sent. */
void commands_state_update(server_t *s, conn_t *c);

#endif /* IRC_CORE_COMMANDS_STATE_H */
