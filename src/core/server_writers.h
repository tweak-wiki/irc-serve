/* server_writers.h -- the writer-pool family (demand-steal drain threads).
 *
 * Split out of core/server.c (#543): these own the writer threads that pump
 * conn write queues, while the lifecycle, registries and shutdown stay in
 * server.c. The dispatch-side declarations live in core/server.h -- the
 * public functions were already declared there -- so this header is only the
 * seam marker.
 */
#ifndef IRC_CORE_SERVER_WRITERS_H
#define IRC_CORE_SERVER_WRITERS_H

#include "core/server.h"

#endif /* IRC_CORE_SERVER_WRITERS_H */
