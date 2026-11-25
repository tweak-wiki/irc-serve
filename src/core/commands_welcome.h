/* commands_welcome.h -- the welcome burst (001-005 + MOTD).
 *
 * Split out of core/commands.c (#543): k_005/k_motd/boot_stamp() and
 * send_motd()/send_welcome() moved verbatim, with handle_motd() (whose only
 * caller is the dispatch table). commands_state_update() lives in
 * commands_state.c and calls in; the two send functions are exposed so it
 * can, and handle_motd() is exposed for the table in commands_dispatch.c. The
 * tables and boot_stamp() stay static: nothing outside commands_welcome.c
 * uses them.
 */
#ifndef IRC_CORE_COMMANDS_WELCOME_H
#define IRC_CORE_COMMANDS_WELCOME_H

#include "core/commands.h"

void send_motd(server_t *s, conn_t *c);
void send_welcome(server_t *s, conn_t *c);
void handle_motd(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_WELCOME_H */
