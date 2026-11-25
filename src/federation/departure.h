/* departure.h -- the departure half: the SQUIT announcement, the link teardown,
 * the clean-leave latch, the shutdown drain and the operator's reset door.
 *
 * Split out of federation/link.c (#543): fed_send_squit_named(),
 * fed_link_down(), fed_mark_clean_leave(), fed_drain_writes(),
 * fed_send_shutdown() and fed_link_reset() moved verbatim into departure.c;
 * the five public functions stay declared in federation/link.h and
 * fed_link_down() is extern here so link.c's exchange and tick arms can reach
 * it. fed_link_set_state() stays in link.c and is extern via federation/link.h.
 */
#ifndef IRC_FEDERATION_DEPARTURE_H
#define IRC_FEDERATION_DEPARTURE_H

#include "core/connection.h"
#include "core/server.h"

/* Take a link down, announcing this node's departure when asked. */
void fed_link_down(server_t *s, server_link_t *link, int announce);

#endif
