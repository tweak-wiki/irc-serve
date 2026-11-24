/* commands_auth.h -- the AUTHENTICATE family (SASL PLAIN exchange).
 *
 * Split out of core/commands.c (#543): the credential path -- auth_wipe(),
 * auth_wipe_credential(), auth_try_spend() and handle_authenticate() -- moved
 * verbatim. The dispatch table stays in commands.c; handle_authenticate() is
 * exposed so the table can name it. The three helpers stay static: nothing
 * outside commands_auth.c calls them.
 */
#ifndef IRC_CORE_COMMANDS_AUTH_H
#define IRC_CORE_COMMANDS_AUTH_H

#include "core/commands.h"

void handle_authenticate(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_AUTH_H */
