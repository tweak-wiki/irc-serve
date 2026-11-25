/* notify.h -- the 4.3 extension's inbound notify half: SSETNAME, SAWAY, SINVITE.
 *
 * Split out of federation/verbs.c (#543): fed_relay_notify(),
 * fed_notify_prefix(), fed_notify_channels(), fed_in_ssetname(),
 * fed_in_saway() and fed_in_sinvite() moved verbatim. fed_dispatch() stays in
 * verbs.c and reaches the three handlers through this header; the three
 * helpers stay static: nothing outside notify.c calls them.
 */
#ifndef IRC_FEDERATION_NOTIFY_H
#define IRC_FEDERATION_NOTIFY_H

#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* SSETNAME <nick> :<realname>. */
void fed_in_ssetname(server_t *s, server_link_t *link,
                     const irc_serve_tags_t *tags,
                     const char *const *params, int nparams);

/* SAWAY <nick> [:<message>]. */
void fed_in_saway(server_t *s, server_link_t *link,
                  const irc_serve_tags_t *tags,
                  const char *const *params, int nparams);

/* SINVITE <channel> <target>: the inviter's hostmask is the prefix. */
void fed_in_sinvite(server_t *s, server_link_t *link,
                    const irc_serve_tags_t *tags, const char *prefix,
                    const char *const *params, int nparams);

#endif /* IRC_FEDERATION_NOTIFY_H */
