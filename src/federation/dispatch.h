/* dispatch.h -- the inbound guard chain: fed_dispatch().
 *
 * Split out of federation/verbs.c (#543): fed_in_message() moves with the
 * chain as static (fed_dispatch() is its only caller); the INBOUND table,
 * inbound_index(), the DEFERRED table, is_deferred() and fed_dispatch() moved
 * verbatim and fed_dispatch() is extern so the client dispatch in
 * core/commands.c can reach it. The vocabulary the chain reports through
 * (fed_obs(), the n_fed_* counters, fed_queue_line()) stays in verbs.c and
 * is extern via federation/verbs.h.
 */
#ifndef IRC_FEDERATION_DISPATCH_H
#define IRC_FEDERATION_DISPATCH_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* fed_dispatch() -- the guard chain. The G1-G10 chain and the four G4 cases
 * are documented in federation/verbs.h, where the vocabulary it reports
 * through lives. */
void fed_dispatch(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_FEDERATION_DISPATCH_H */
