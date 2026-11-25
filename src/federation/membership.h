/* membership.h -- the inbound membership half: SJOIN/SNICK.
 *
 * Split out of federation/verbs.c (#543): fed_parse_flags() moves with the
 * handlers as static (fed_in_sjoin() is its only caller); fed_in_channel(),
 * fed_in_sjoin() and fed_in_snick() moved verbatim and are extern so
 * fed_dispatch() in dispatch.c can reach them. fed_touch_server(),
 * fed_actor_prefix(), fed_local_emit() and fed_obs() stay in verbs.c and are
 * extern via federation/verbs.h.
 */
#ifndef IRC_FEDERATION_MEMBERSHIP_H
#define IRC_FEDERATION_MEMBERSHIP_H

#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* The channel an inbound S-verb names, canonicalised, or NULL. Creates it
 * from an SJOIN only; every other verb refuses an unknown channel. */
chan_t *fed_in_channel(server_t *s, server_link_t *link, const char *name,
                       int create);

/* SJOIN: <channel> <member> <flags> <account> <user> <host>. */
void fed_in_sjoin(server_t *s, server_link_t *link, chan_t *ch,
                  const char *prefix, const irc_serve_tags_t *tags,
                  const char *const *params, int nparams);

/* SNICK: <old nick> <new nick>. */
void fed_in_snick(server_t *s, server_link_t *link, const char *prefix,
                  const irc_serve_tags_t *tags, const char *const *params,
                  int nparams);

#endif /* IRC_FEDERATION_MEMBERSHIP_H */
