/* commands_setname.h -- the SETNAME family (IRCv3 `setname`).
 *
 * Split out of core/commands.c (#543): handle_setname() moved verbatim.
 * The dispatch table stays in commands.c and names the handler through
 * this header. setname_notify_channels() stays static in
 * commands_setname.c: its only caller is handle_setname(), which moved
 * with it.
 */
#ifndef IRC_CORE_COMMANDS_SETNAME_H
#define IRC_CORE_COMMANDS_SETNAME_H

#include "core/commands.h"

void handle_setname(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_SETNAME_H */
