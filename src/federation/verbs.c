/* verbs.c -- see verbs.h. The shared helpers the decode side reports through:
 * fed_touch_server(), fed_actor_prefix(), fed_local_emit() and fed_forward_all().
 * fed_obs() lives in federation/obs.c. The encoder lives in
 * federation/encode.c, the guard chain in federation/dispatch.c. */
#include "federation/verbs.h"

/* snprintf()/strchr() below. */
#include <stdio.h>
#include <string.h>

#include "account_store.h"
#include "core/account.h"
/* For conn_text_logsafe() and conn_text_bad_count() -- a peer string this node
 * PRINTS is log-only and is therefore measured rather than filtered, for the same reason a
 * client string printed on this node's stdout is. A peer string this node STORES goes
 * through the field's own policy, and SMODES through chan_mode_implemented(). */
#include "core/connection.h"
#include "core/channel.h"
#include "core/message.h"
#include "core/fanout.h"
#include "core/cap.h"
#include "core/reply.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/link.h"
/* Phase 9: 2.1's remote-nick registry. SNICK rekeys it, which is what makes a
 * rename network-visible -- see fed_in_snick() for the three places it has to
 * land and why all three are needed. */
#include <stdlib.h>

#include "federation/nickreg.h"
#include "federation/membership.h"
#include "federation/notify.h"
#include "federation/state.h"

/* fed_obs(): split out for #543 into federation/obs.c; declared in
 * federation/obs.h and re-exported through federation/verbs.h. */

/* ---------------------------------------------------------------------------
 * The DECODE side: the handlers G10 reaches
 * ---------------------------------------------------------------------------
 *
 * Every one of them does the same two things and nothing else: apply the fact to
 * this node's local state, and pass the line on. Neither is optional -- an
 * inbound state change that is applied but not relayed stops the mesh
 * converging, and one that is relayed but not applied leaves this node's cache
 * permanently behind the origin's.
 *
 * WHY THERE IS NO LOCAL CLIENT EMISSION, and it is a gap rather than a decision.
 * An inbound SJOIN names a member but carries only a SERVER prefix, because the
 * member's hostmask is not on the wire and 4.3's burst vocabulary is where it
 * belongs. A client cannot be shown ":bob!user@host JOIN #T" from a prefix that
 * says only "irc.b", and a JOIN with a server prefix is a line no client
 * understands. So a local member learns about a remote member through the
 * ROSTER -- 353, which 7/Phase 6's acceptance criterion is about -- and not yet
 * through a channel echo. The gap closes when SBURST carries the per-member host
 * and realname (4.3, driven in Phase 9). Writing a JOIN with an invented host
 * would be worse than the gap: 2.1's whole point is that a hostmask is OBSERVED
 * rather than asserted.
 */

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

/* Advertise family (ADVERTISE store + collision check): split out for #543 into
 * federation/advertise.c; the store readers stay declared in federation/link.h. */

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

