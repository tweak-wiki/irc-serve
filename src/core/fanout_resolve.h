/* fanout_resolve.h -- the resolution family (mask match, nick lookup,
 * target resolve, membership).
 *
 * Split out of core/fanout.c (#543): these answer "what did this name refer
 * to", while delivery and forwarding stay in fanout.c. The dispatch-side
 * declarations live in core/fanout.h -- the public functions were already
 * declared there -- so this header is only the seam marker.
 */
#ifndef IRC_CORE_FANOUT_RESOLVE_H
#define IRC_CORE_FANOUT_RESOLVE_H

#include "core/fanout.h"

#endif /* IRC_CORE_FANOUT_RESOLVE_H */
