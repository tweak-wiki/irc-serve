/* server.c -- see core/server.h. The server_t lifecycle, the clock, the tick
 * and the msg-id counter.
 *
 * Fully split for #543 (last family: lifecycle + clock/tick/msg-id ->
 * core/server_lifecycle.c, TU-44); this file now holds only the split map.
 * The lifecycle (server_init plus the msgid seed helpers), the clock
 * (server_now_ms), the tick (server_tick) and the msg-id counter
 * (server_next_msg_id) live in core/server_lifecycle.c, the shutdown trio in
 * core/server_shutdown.c, the writer pool in core/server_writers.c, the
 * fd-indexed connection registry in core/server_conns.c, the nick/channel
 * and peer-link registries in core/server_registry.c, the nonblocking
 * outbound-dial FSM in core/server_dial.c, and the listener arms in
 * core/server_listen.c. All functions stay declared in core/server.h.
 */
#include "core/server.h"


/* Lifecycle (server_init plus the server_msgid_seed/fallback helpers), the
 * clock (server_now_ms), the tick (server_tick) and the msg-id counter
 * (server_next_msg_id): split out for #543 into core/server_lifecycle.c;
 * all four stay declared in core/server.h. */

/* The shutdown trio (server_shutdown_phase1_say_goodbye/
 * server_shutdown_phase2_close/server_shutdown): split out for #543 into
 * core/server_shutdown.c; all three stay declared in core/server.h. */

/* The writer pool (demand-steal drain threads): split out for #543 into
 * core/server_writers.c; the pool functions stay declared in
 * core/server_writers.h. */

/* The fd-indexed connection registry (accept/lookup/queue/reap): split out
 * for #543 into core/server_conns.c; the registry functions stay declared
 * in core/server_conns.h. */

/* The nick, channel and peer-link registries (claim/release/lookup/
 * enumeration, attach/get/detach, find_link/link_at/find_peer): split out
 * for #543 into core/server_registry.c; all stay declared in
 * core/server.h. */

/* The nonblocking outbound-dial FSM (dial/collect/progress/count): split out
 * for #543 into core/server_dial.c; the dial functions stay declared in
 * core/server.h. */

/* The listener arms (listen/port/listen_tls/accept_tls_one): split out for
 * #543 into core/server_listen.c; all stay declared in core/server.h. */
