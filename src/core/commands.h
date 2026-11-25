/* commands.h -- the client command surface, and the registration state machine.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (the identity fields and the state
 * enum), 2.3 (a peer link is exempt from this state machine entirely), 3 (the
 * dispatch seam and the reply-path invariants), 3.3 (the message path ends at
 * dispatch), 4.1 (PASS NICK USER PING PONG QUIT MOTD) and 4.4 (numerics).
 *
 * ---------------------------------------------------------------------------
 * THIS IS THE FIRST PHASE WHERE THE NODE ANSWERS
 * ---------------------------------------------------------------------------
 * Phases 1 and 2 built the tokenizer and the loop. Nothing had ever called
 * valid_nick(), so the rule that 2.1's whole `nick@server` identity scheme
 * depends on was specified and tested but not enforced anywhere at runtime, and
 * a nickname could in principle have been any bytes at all. Registration is
 * where a nickname is chosen, so it is the only place that call belongs.
 *
 * Everything here answers through reply()/send_pong() (see reply.h) and never
 * touches a socket. A handler states what it wants to say; reply.h decides
 * where it is allowed to be said.
 */
#ifndef IRC_CORE_COMMANDS_H
#define IRC_CORE_COMMANDS_H

#include "core/commands_dispatch.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

 /* commands_dispatch() lives in core/commands_dispatch.c (#543) and is
  * re-exported here so all existing consumers work untouched. */
 
 /* The registration projection (commands_registered() and
  * commands_state_update()) lives in core/commands_state.c (#543) and is
  * re-exported here so all existing consumers work untouched. */
 #include "core/commands_state.h"

#endif /* IRC_CORE_COMMANDS_H */
