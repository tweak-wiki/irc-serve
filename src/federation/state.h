/* state.h -- the inbound channel-state and departure half: SHUTDOWN, SPART,
 * STOPIC, SMODES, SKICK, SQUIT.
 *
 * Split out of federation/verbs.c (#543): fed_emit_departure_quits() stays
 * static in state.c (only the two departures call it); fed_in_shutdown(),
 * fed_in_spart(), fed_in_stopic(), fed_in_smodes(), fed_in_skick() and
 * fed_in_squit() moved verbatim and are extern so fed_dispatch() in verbs.c
 * can reach them. fed_touch_server() and fed_actor_prefix() stay in verbs.c
 * and are extern via federation/verbs.h: SJOIN/SNICK still use them.
 */
#ifndef IRC_FEDERATION_STATE_H
#define IRC_FEDERATION_STATE_H

#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* SHUTDOWN [:reason]. */
void fed_in_shutdown(server_t *s, server_link_t *link, const char *prefix,
                     const irc_serve_tags_t *tags, const char *const *params,
                     int nparams);

/* SPART: <member> <channel> [<reason>]. */
void fed_in_spart(server_t *s, server_link_t *link, chan_t *ch,
                  const char *prefix, const irc_serve_tags_t *tags,
                  const char *const *params, int nparams);

/* STOPIC: <member> <channel> <topic>. */
void fed_in_stopic(server_t *s, server_link_t *link, chan_t *ch,
                   const char *prefix, const irc_serve_tags_t *tags,
                   const char *const *params, int nparams);

/* SMODES: <server> <channel> <modes> [<arg>]. */
void fed_in_smodes(server_t *s, server_link_t *link, chan_t *ch,
                   const char *prefix, const irc_serve_tags_t *tags,
                   const char *const *params, int nparams);

/* SKICK: <member> <channel> <target> [<reason>]. */
void fed_in_skick(server_t *s, server_link_t *link, chan_t *ch,
                  const char *prefix, const irc_serve_tags_t *tags,
                  const char *const *params, int nparams);

/* SQUIT: <server> [<reason>]. */
void fed_in_squit(server_t *s, server_link_t *link,
                  const irc_serve_tags_t *tags, const char *const *params,
                  int nparams);

#endif /* IRC_FEDERATION_STATE_H */
