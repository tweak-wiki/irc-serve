/* fanout.c -- see core/fanout.h. The 3.1 routing table, written down once.
 *
 * Fully split for #543 (last family: 3.2 cap + emission stamp ->
 * core/fanout_cap.c, TU-47); this file now holds only the split map.
 * Resolution lives in core/fanout_resolve.c, the forward leg in
 * core/fanout_forward.c, the delivery leg in core/fanout_deliver.c, and the
 * 3.2 client-facing cap (fanout_line_fits_n()/fanout_line_fits(), in
 * core/fanout.h) plus the shared emission identity (fanout_stamp(), in
 * core/fanout_forward.h) in core/fanout_cap.c.
 */
#include "core/fanout.h"


/* Resolution family (mask match, nick lookup, target resolve, membership):
 * split out for #543 into core/fanout_resolve.c; all functions stay declared
 * in core/fanout.h. */

/* Forward leg (forward_one_peer/forward_channel_targets + the
 * fanout_forward_* entry points): split out for #543 into
 * core/fanout_forward.c; the entry points stay declared in
 * core/fanout_forward.h. */

/* Delivery leg (emission helpers, write_to_members, the fanout_deliver_*
 * entry points): split out for #543 into core/fanout_deliver.c; the entry
 * points stay declared in core/fanout.h. */

/* 3.2's client-facing cap (fanout_line_fits_n()/fanout_line_fits(), declared in
 * core/fanout.h) and the shared emission identity (fanout_stamp(), declared
 * in core/fanout_forward.h): split out for #543 into core/fanout_cap.c. */
