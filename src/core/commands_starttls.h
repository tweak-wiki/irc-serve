/* commands_starttls.h -- the STARTTLS family (upgrade refusals + CAP pass-through).
 *
 * Split out of core/commands.c (#543): handle_starttls() and
 * handle_cap_wrapper() moved verbatim. The dispatch table stays in
 * commands.c and names the handlers through this header. No static helpers
 * move: every callee (reply/reply_refused, tls_backend_available,
 * cap_handle) is already extern.
 */
#ifndef IRC_CORE_COMMANDS_STARTTLS_H
#define IRC_CORE_COMMANDS_STARTTLS_H

#include "core/commands.h"

void handle_starttls(server_t *s, conn_t *c, const message_t *m);
void handle_cap_wrapper(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_STARTTLS_H */
