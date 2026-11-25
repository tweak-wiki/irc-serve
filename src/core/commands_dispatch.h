/* commands_dispatch.h -- the command table and the dispatch seam.
 *
 * Split out of core/commands.c (#543): command_t/k_commands/lookup() and
 * commands_dispatch() moved verbatim, with the MOTD handler's declaration
 * (handle_motd() lives in commands_welcome.c). commands.h includes this so
 * all existing consumers work untouched. No static helpers move: every
 * callee (reply, fed_dispatch, batch/label hooks, conn_text_*) is already
 * extern.
 */
#ifndef IRC_CORE_COMMANDS_DISPATCH_H
#define IRC_CORE_COMMANDS_DISPATCH_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* The Phase 3 command surface: PASS, NICK, USER, PING, PONG, QUIT, MOTD, and
 * the pre-registration gate plus 451/421 for everything else. Matches
 * server_dispatch_fn, so it is installed by assigning it:
 *
 *     srv.dispatch = commands_dispatch;
 *
 * `c` is the connection the command arrived ON and `m` is owned by the caller
 * and released as soon as this returns, so a handler that needs a field later
 * must copy it. */
void commands_dispatch(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_DISPATCH_H */
