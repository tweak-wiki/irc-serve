/* commands_info.h -- the server-info family (LUSERS, ADMIN, INFO).
 *
 * Split out of core/commands.c (#543): these three answer questions about the
 * NODE rather than about a channel or a person, and they share the
 * server-mask helpers. The dispatch table stays in commands.c; these are
 * exposed so the table can name them.
 */
#ifndef IRC_CORE_COMMANDS_INFO_H
#define IRC_CORE_COMMANDS_INFO_H

#include "core/commands.h"

/* The network name 005's NETWORK= and 257 carry. A DEPLOYMENT property rather
 * than a node property -- a mesh has many nodes and one network name -- so a
 * single compile-time constant here, and both commands.c and commands_info.c
 * spell it this way rather than retyping it. */
#define NODE_NETWORK "irc-serve"

void handle_lusers(server_t *s, conn_t *c, const message_t *m);
void handle_admin(server_t *s, conn_t *c, const message_t *m);
void handle_info(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_INFO_H */
