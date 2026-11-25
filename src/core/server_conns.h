/* server_conns.h -- the fd-indexed connection registry.
 *
 * Split out of core/server.c (#543): these own the by_fd registry (accept,
 * lookup, queue, reap) while the lifecycle, nick/channel registries and
 * shutdown stay in server.c. The dispatch-side declarations live in
 * core/server.h -- the registry functions were already declared there -- so
 * this header only declares the two accept-time helpers shared with the
 * listeners and dial that stay in server.c, and marks the seam.
 */
#ifndef IRC_CORE_SERVER_CONNS_H
#define IRC_CORE_SERVER_CONNS_H

#include <sys/socket.h>

#include "core/server.h"

/* Accept-time helpers, defined in server_conns.c. Namespaced (TU-10
 * precedent) because leaving server.c's file-statics meant global linkage. */
int server_conns_set_nonblocking(int fd);
void server_conns_describe_peer(conn_t *c, const struct sockaddr *sa);

#endif /* IRC_CORE_SERVER_CONNS_H */
