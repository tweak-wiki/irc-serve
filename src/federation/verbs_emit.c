/* verbs_emit.c -- the shared emit helpers the decode side reports through,
 * split out of federation/verbs.c for #543 (TU-42): fed_touch_server(),
 * fed_actor_prefix(), fed_local_emit() and fed_forward_all(). All four stay
 * declared in federation/verbs.h (no new header). */
#include "federation/verbs.h"

/* snprintf() / strchr(). */
#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/fanout.h"
#include "core/server.h"
#include "federation/link.h"

/* Keep a channel's member-server set in step with the roster, where the set is
 * a refcount the ORIGIN keeps and the only count this node can take locally is
 * of its own cache.
 *
 * THE COST, stated because it is a real one: a member the origin has and this
 * node has not been told about is invisible here, so an SPART for the last
 * KNOWN member from a server that still has others behind it removes the
 * servers[] entry early -- and the channel is then no longer in that peer's
 * forward set, so a state change for it stops reaching them until the origin
 * re-reports a member. 2.2 says a non-owner's state is a cache and that caches
 * are allowed to be incomplete and self-healing; the alternative -- never
 * decrementing -- makes the set grow for the life of the channel and turns 3.1's
 * target set into "every server this node has ever heard of", which is the
 * global list the design explicitly rejects. */
void fed_touch_server(chan_t *ch, const char *server, int adding)
{
    if (adding != 0) {
        (void)chan_server_add(ch, server);
        return;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].server, server)) {
            return; /* somebody from that server is still known */
        }
    }
    (void)chan_server_remove(ch, server);
}

/* The actor an inbound state line renders with. An S-verb's raw prefix is a
 * peer-chosen string: a hostmask on a well-formed mesh, a server name on a
 * relayed line or the s->name fallback, arbitrary bytes from a malicious
 * peer. Rendering it raw puts `:irc.x JOIN #T` -- unparseable as an actor --
 * on clients, so the prefix is trusted only when it IS a hostmask (`!`
 * before `@`). Otherwise the burst-populated roster record speaks:
 * `nick!user@host` from stored fields. A known member with no record yet
 * renders as the bare nick -- the same rule 353 uses for empty-host entries
 * -- except for JOIN, which withholds entirely: gap 2's burst completion
 * emits the held JOIN, and `nick!*@*` is forbidden. A NULL nick (SMODES,
 * whose subject is the evaluating server) has no roster identity and no
 * bare form: NULL means withhold, and that caller falls back to the subject
 * server explicitly rather than through here. Returns a pointer valid for
 * the immediate fed_local_emit() call only when it returns `out`. */
const char *fed_actor_prefix(const chan_t *ch, const char *nick,
                                    const char *prefix, int withhold_bare,
                                    char *out, size_t cap)
{
    if (prefix != NULL) {
        const char *bang = strchr(prefix, '!');

        if (bang != NULL && strchr(bang + 1, '@') != NULL) {
            return prefix; /* observed hostmask: the only attribution on the wire */
        }
    }
    if (nick != NULL && ch != NULL) {
        for (size_t i = 0; i < ch->nremotes; i++) {
            const chan_remote_t *m = &ch->remotes[i];

            if (!chan_same_name(m->nick, nick)) {
                continue;
            }
            if (m->user[0] != '\0' && m->host[0] != '\0') {
                (void)snprintf(out, cap, "%s!%s@%s", m->nick, m->user,
                               m->host);
                return out;
            }
        }
    }
    if (withhold_bare || nick == NULL) {
        return NULL;
    }
    return nick;
}

/* The local half of an inbound state verb: resolve the channel and write the
 * client-shaped line to local members, with NO forward. The forward is the
 * handler's existing fanout_forward_channel_sverb() call, which is untouched:
 * this only adds the local emission fed_in_message() has always had. One
 * helper rather than inline code in seven handlers, so the resolve class
 * cannot drift between them: every state verb resolves FANOUT_STATE_CHANGE,
 * and deliver_local writes to members of either channel kind without
 * forwarding, which is exactly the half that was missing. */
void fed_local_emit(server_t *s, chan_t *ch, const char *prefix,
                     const char *verb, const char *const *params, int nparams)
{
    fanout_target_t t;

    if (ch == NULL || verb == NULL) {
        return;
    }
    if (fanout_resolve(s, NULL, ch->name, FANOUT_STATE_CHANGE, &t) == 0) {
        return;
    }
    (void)fanout_deliver_local(s, &t, prefix, verb, params, nparams, NULL);
}

/* fed_forward_all() -- verbs.h states why this exists and what the two shapes of
 * 4.3's verb set are. The body is SQUIT's broadcast loop with SQUIT's two
 * exclusions left at ITS call site, which is what keeps the general function free
 * of a verb it has no business naming. */
int fed_forward_all(server_t *s, const char *sverb, const char *prefix,
                    const char *const *params, int nparams)
{
    int carried = 0;

    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *lk = server_link_at(s, k);

        if (lk == NULL || lk->state != (int)ESTABLISHED) {
            continue;
        }
        /* == 0 IS SUCCESS, which is the shape fanout_forward_sverb() returns and
         * the shape every call site in this file tests. Inverting it here would
         * make the count mean the opposite of the one a reader expects. */
        if (fanout_forward_sverb(s, lk->name, sverb, prefix, params, nparams, NULL) ==
            0) {
            carried++;
        }
    }
    return carried;
}
