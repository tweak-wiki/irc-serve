/* commands_register.h -- the registration family (PASS/NICK/USER).
 *
 * Split out of core/commands.c (#543): copy_field() and handle_pass()/
 * handle_nick()/handle_user() moved verbatim. The dispatch table stays in
 * commands.c; the three handlers are exposed so the table can name them.
 * copy_field() stays static: nothing outside commands_register.c calls it.
 */
#ifndef IRC_CORE_COMMANDS_REGISTER_H
#define IRC_CORE_COMMANDS_REGISTER_H

#include "core/commands.h"

void handle_pass(server_t *s, conn_t *c, const message_t *m);
void handle_nick(server_t *s, conn_t *c, const message_t *m);
void handle_user(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_REGISTER_H */
