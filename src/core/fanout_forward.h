/* fanout_forward.h -- the forward leg split out of core/fanout.c for #543.
 * Verbatim move: forward_one_peer/forward_channel_targets (static in
 * fanout_forward.c) plus the four public fanout_forward_* entry points
 * (declared in core/fanout.h); fanout_stamp() is shared with delivery and is
 * declared here.
 */
#ifndef IRC_SERVE_CORE_FANOUT_FORWARD_H
#define IRC_SERVE_CORE_FANOUT_FORWARD_H

#include "core/message.h"
#include "core/server.h"

/* Compute one emission's 2.4 identity (defined in fanout.c; shared by
 * delivery there and the forward leg in fanout_forward.c). */
void fanout_stamp(server_t *s, const irc_serve_tags_t *carry,
                  irc_serve_tags_t *out, int *relayed);

#endif
