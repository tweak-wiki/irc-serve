/* verbs.c -- see verbs.h. The shared emit helpers the decode side reports
 * through: fed_touch_server(), fed_actor_prefix(), fed_local_emit() and
 * fed_forward_all().
 *
 * Fully split for #543 (last family: the emit helpers -> federation/verbs_emit.c,
 * TU-42); this file now holds only the split map. fed_obs() lives in
 * federation/obs.c, the encoder in federation/encode.c, the frozen shapes in
 * federation/shapes.c, the ADVERTISE store in federation/advertise.c, the
 * inbound notify half in federation/notify.c, the inbound membership half in
 * federation/membership.c, the inbound channel-state half in
 * federation/state.c, and the guard chain in federation/dispatch.c.
 */
#include "federation/verbs.h"


/* The DECODE side: the handlers G10 reaches -- split out for #543 (see above);
 * every one of them applies the fact to this node's local state and passes
 * the line on. */

/* Keep a channel's member-server set in step with the roster: split out for
 * #543 into federation/verbs_emit.c; declared in federation/verbs.h. */

/* The actor an inbound state line renders with: split out for #543 into
 * federation/verbs_emit.c; declared in federation/verbs.h. */

/* The local half of an inbound state verb: split out for #543 into
 * federation/verbs_emit.c; declared in federation/verbs.h. */

/* Advertise family (ADVERTISE store + collision check): split out for #543 into
 * federation/advertise.c; the store readers stay declared in federation/link.h. */

/* fed_forward_all(): split out for #543 into federation/verbs_emit.c;
 * declared in federation/verbs.h. */
