/* commands_account.h -- the account-registration family (REGISTER/ACCOUNT/
 * UNREGISTER).
 *
 * Split out of core/commands.c (#543): the refusal policy -- account_refuse()
 * and handle_register()/handle_account()/handle_unregister() -- moved verbatim.
 * The dispatch table stays in commands.c; the three handlers are exposed so the
 * table can name them. account_refuse() stays static: nothing outside
 * commands_account.c calls it.
 */
#ifndef IRC_CORE_COMMANDS_ACCOUNT_H
#define IRC_CORE_COMMANDS_ACCOUNT_H

#include "core/commands.h"

void handle_register(server_t *s, conn_t *c, const message_t *m);
void handle_account(server_t *s, conn_t *c, const message_t *m);
void handle_unregister(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_ACCOUNT_H */
