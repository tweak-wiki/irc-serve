/* commands_conn.h -- the connection-lifecycle family (PING/PONG/QUIT).
 *
 * Split out of core/commands.c (#543): handle_ping()/handle_pong()/
 * handle_quit() moved verbatim. The dispatch table stays in commands.c;
 * the three handlers are exposed so the table can name them. No static
 * helpers move: every callee (send_pong, server_nick_unclaim, conn_*,
 * fanout_*) is already extern.
 */
#ifndef IRC_CORE_COMMANDS_CONN_H
#define IRC_CORE_COMMANDS_CONN_H

#include "core/commands.h"

void handle_ping(server_t *s, conn_t *c, const message_t *m);
void handle_pong(server_t *s, conn_t *c, const message_t *m);
void handle_quit(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_CONN_H */
