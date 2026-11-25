/* commands_choper.h -- the CHOPER refusal family (RFC 2812 3.4.1).
 *
 * Split out of core/commands.c (#543): handle_choper() moved verbatim.
 * The dispatch table stays in commands.c and names the handler through
 * this header. No static helpers move: every callee (reply/refused,
 * fanout_find_nick, conn_text_*) is already extern.
 */
#ifndef IRC_CORE_COMMANDS_CHOPER_H
#define IRC_CORE_COMMANDS_CHOPER_H

#include "core/commands.h"

void handle_choper(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_COMMANDS_CHOPER_H */
