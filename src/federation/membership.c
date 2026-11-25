/* membership.c -- see membership.h. The inbound membership half: SJOIN/SNICK,
 * verbatim out of federation/verbs.c (issue #543). */
#include "federation/membership.h"

#include "federation/verbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/server.h"
#include "federation/link.h"
#include "federation/nickreg.h"

/* Parse the SJOIN flags token back into a flag word. The token is 4.3's frozen
 * single token (see fed_flag_token()), so this is a two-letter scan and not a
 * grammar: `+`, then `o` and/or `v`, or the literal `-`. A duplicate letter is
 * refused rather than collapsed, because a flags word this node does not
 * understand is a membership it would render wrongly in 353 and a line whose
 * author we could not describe. */
static int fed_parse_flags(const char *tok, unsigned *out)
{
    unsigned f = 0u;

    if (tok == NULL || tok[0] == '\0' || out == NULL) {
        return -1;
    }
    if (strcmp(tok, "-") == 0) {
        *out = 0u;
        return 0;
    }
    if (tok[0] != '+') {
        return -1;
    }
    for (size_t i = 1; tok[i] != '\0'; i++) {
        if (tok[i] == 'o' && (f & CHAN_MEMBER_OP) == 0u) {
            f |= CHAN_MEMBER_OP;
        } else if (tok[i] == 'v' && (f & CHAN_MEMBER_VOICE) == 0u) {
            f |= CHAN_MEMBER_VOICE;
        } else {
            return -1;
        }
    }
    if ((f & (CHAN_MEMBER_OP | CHAN_MEMBER_VOICE)) == 0u) {
        return -1; /* `+` with no letters names nothing */
    }
    *out = f;
    return 0;
}
/* The channel an inbound S-verb names, canonicalised, or NULL.
 *
 * A channel this node has never heard of is created HERE, from an SJOIN only,
 * and that is the one place a channel enters a federated node other than through
 * a local JOIN: an SJOIN proves the SENDER has a member, so by 2.2's "first
 * server to see a channel owns it" the origin is the sender. The other four state
 * verbs do not create -- they describe a change to a channel that already exists,
 * and a peer that could invent a channel here by parting from it could make this
 * node hold channels nobody joined. It is created with
 * the link's own epoch as its origin_epoch, which is the one field the wire
 * gives us about the creating boot and is what makes a later creation-race
 * comparison between two real values rather than between a value and a
 * placeholder.
 *
 * 2.2's full tie-break also needs the (epoch, name) of the FIRST creator, which
 * a bare SJOIN cannot distinguish from a relayed one -- that is 4.3's SBURST
 * vocabulary and 4.3 says the burst REPLACES rather than merges. So a
 * re-keying decision is NOT made here and a node that receives two SJOINs for
 * the same channel from two peers keeps the first origin it learned. That is a
 * known gap with a known owner (Phase 9's resync), and it is stated here rather
 * than left to be discovered as a split-brain. */
chan_t *fed_in_channel(server_t *s, server_link_t *link, const char *name,
                              int create)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (s == NULL || link == NULL || name == NULL || !chan_name_valid(name)) {
        return NULL;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    ch = server_chan_get(s, canonical);
    if (ch == NULL && create == 0) {
        /* Only SJOIN creates. An SPART, STOPIC, SMODES or SKICK for a channel
         * this node has never heard of is REFUSED rather than creating it: those
         * verbs describe a change to a channel that already exists, and a peer
         * that could invent a channel here by parting from it would be able to
         * make this node hold channels nobody joined. */
        return NULL;
    }
    if (ch == NULL) {
        ch = chan_new(canonical, link->name, link->epoch);
        if (ch == NULL || server_chan_attach(s, ch) != 0) {
            chan_free(ch);
            return NULL;
        }
        fed_obs("[observable] chan_create: channel=%s origin=%s epoch=%llu "
               "creator=%s\n",
               ch->name, ch->origin, (unsigned long long)ch->origin_epoch,
               link->name);
    }
    return ch;
}
/* SJOIN: <channel> <member> <flags> <account> <user> <host>. */
void fed_in_sjoin(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    unsigned flags = 0u;

    /* SIX PARAMETERS NOW, not four: `<channel> <member> <flags> <account> <user>
     * <host>`, and the arity is the FORMAT's and is enforced here rather than
     * guessed at, which is the reason the table in this file carries an SJOIN
     * row of 6,6. A peer running a build without the 4.3 extension sends four
     * and is refused, which is a loud incompatibility rather than a member
     * silently recorded with no host -- and the same direction 4.3.1 chose for
     * `<server>`, which was added before a second implementation existed rather
     * than after. The version bump is what keeps the two builds from linking at
     * all, so this refusal is a backstop rather than a case that happens. */
    if (nparams != 6 || fed_parse_flags(params[2], &flags) != 0 ||
        strlen(params[4]) > (size_t)CONN_USER_MAX ||
        strlen(params[5]) > (size_t)CHAN_MAX_REMOTE_HOST ||
        /* NULL for the HOLDER, and that absence is the whole of what an SJOIN can
         * say about one: 4.3's SJOIN carries no server field, so the holder is
         * unknown and is recorded as such ("not told", which chan_remote_add()
         * stores as empty). Writing the link's name here would file a guess as a
         * fact: exact on a two-node mesh, a relay's name on a larger one, and a
         * fact the next burst from whoever holds the member then has to
         * overwrite. The burst corrects it -- SBURSTM carries the holder, and
         * install overwrites the empty one -- and a repeat SJOIN must not clobber
         * what the burst established. It does not: chan_remote_add() only
         * overwrites the holder when the repeat carries one, and the send path's
         * fallback to the key stays a best effort that a burst replaces rather
         * than a stored answer. */
        chan_remote_add(ch, link->name, NULL, params[1], params[3], flags) != 0) {
        /* The `nparams > 1` guard is why the measurement comes from the SAME ternary
         * rather than from `params[1]`: on the branch where the guard failed,
         * params[1] does not exist. */
        if (chan_remote_count(ch) >= (size_t)CHAN_MAX_REMOTE_MEMBERS) {
            s->n_remote_roster_full++;
        }
        fed_obs("[observable] fed_sjoin_reject: channel=%s member=%s server=%s "
                "member_len=%zu member_bad_bytes=%zu\n",
               ch->name, (nparams > 1) ? params[1] : "?", link->name,
               strlen((nparams > 1) ? params[1] : "?"),
               conn_text_bad_count((nparams > 1) ? params[1] : "?"));
        return;
    }
    /* <user> and <host>, the 4.3 extension's fields: `-` is "not told" (the
     * sender's spelling of an empty ident or host), translated to "" on receipt
     * the way the account's `*` is. Set SEPARATELY from the add above, the way
     * burst.c installs them from its shadow records: the two have different
     * failure modes, and a refusal of one must not cost the other. The length
     * check above means the setters cannot fail on width here. */
    (void)chan_remote_set_user(ch, link->name, params[1],
                               (params[4][0] == '-' && params[4][1] == '\0')
                                   ? ""
                                   : params[4]);
    (void)chan_remote_set_host(ch, link->name, params[1],
                               (params[5][0] == '-' && params[5][1] == '\0')
                                   ? ""
                                   : params[5]);
    /* 2.1's REGISTRY, on the LIVE path and not only on the burst path, and the
     * reason is that a burst is per link ESTABLISHMENT: a member who joined this
     * node's mesh ten minutes after the last one would be unknown to a registry
     * fed only by SBURST, and 2.1's scoped `nick@server` would 401 a user who is
     * right there. SJOIN is the only verb that reports a user joining, so it is
     * the only place a live registry entry can come from. The registry's holder
     * is the LINK -- 4.3's SJOIN carries no server field, and a registry with no
     * answer cannot route, so the link is the best available -- while the roster
     * above records the absence and waits for a burst. The two disagree only for
     * a relaying peer's own best guess, which the next burst corrects. */
    fed_nickreg_learn_member(s, params[1], link->name, link->name, server_now_ms());
    /* 2.1's POLICY, ON THE LEARNING SIDE, and the reason it is a second call site
     * rather than a detail of the learn above: a user can register `zed` on a node
     * whose registry is empty and only later learn that a peer holds it, and a
     * node that checked only at claim time would leave that user holding the name
     * for ever. The far side of the same pair runs the same function against the
     * same two names, so between the two of them exactly one renames -- which is
     * the convergence fed_nickreg_local_loses() exists to make possible. */
    (void)fed_nickreg_resolve_local(s, params[1], server_now_ms());
    fed_touch_server(ch, link->name, 1);
    fed_obs("[observable] fed_sjoin: channel=%s member=%s server=%s flags=%u "
           "local=%zu remote=%zu origin=%s owned=%d member_len=%zu member_bad_bytes=%zu\n",
           ch->name, params[1], link->name, flags, ch->nmembers, ch->nremotes,
           ch->origin, chan_origin_is_self(s, ch), strlen(params[1]), conn_text_bad_count(params[1]));

    /* The JOIN this node's own clients see. The actor is the observed hostmask
     * when the line carries one; otherwise the burst-described roster record --
     * and when the member has no record yet, nothing at all: the next burst
     * that completes the record emits the held JOIN, and neither a guessed
     * `nick` nor a forbidden `nick!*@*` ever reaches a client. */
    {
    char actor[CONN_HOSTMASK_MAX];
    const char *who = fed_actor_prefix(ch, params[1], prefix, 1, actor,
                                       sizeof actor);

    if (who != NULL) {
        fed_local_emit(s, ch, who, "JOIN", NULL, 0);
    }
}
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SJOIN", prefix,
                                       params, nparams, tags);
}
/* SNICK: <old nick> <new nick>.
 *
 * IT NAMES NO CHANNEL, which is why it is NOT IN INBOUND: every row of that
 * table is dispatched with its channel read from a fixed parameter position, and
 * a two-parameter verb whose second parameter is a nickname has no position that
 * is a channel. See the dispatch in fed_handle_message() for how SQUIT solves the
 * same problem, and for why SNICK is asked in the same place rather than given a
 * position that lies.
 *
 * THE EFFECT IS IN THREE PLACES, and all three are needed or a rename is only
 * half-applied:
 *   - 2.1's registry: the entry that answered `<old>`@<this peer> must answer
 *     `<new>` instead, or every subsequent `old@peer` on this node still routes
 *     here and every `new@peer` is a 401.
 *   - the CHANNEL ROSTERS: the member is keyed (server, nick), so a rekeyed
 *     member whose roster row still says the old name is a member the roster
 *     cannot render and SPART cannot later remove.
 *   - the LOCAL CLIENTS: an SJOIN/SPART fanout is what teaches a client's view
 *     of the roster, and a rename that skips it leaves a client showing a name
 *     the server no longer holds.
 *
 * AND IT IS NOT A STATE-DESTROYING VERB, which is the reason it is not routed
 * through the same refusal chain a SQUIT is: nothing here ends, and a peer that
 * sends it for a name this node never held is a peer with a stale view rather
 * than one trying to remove a channel's member. It is still a 401-free silent
 * accept, because "I do not have that nick" is not an error worth breaking a
 * link over -- the next SBURST is the authority, and this node will correct
 * itself then.
 */
void fed_in_snick(server_t *s, server_link_t *link, const char *prefix,
                         const irc_serve_tags_t *tags, const char *const *params,
                         int nparams)
{
    int renamed = 0;

    if (nparams != 2) {
        return;
    }
    /* THE PREFIX IS IGNORED, and that is load-bearing rather than lazy. SNICK is
     * forwarded to every established peer EXCEPT the one it came from, so on a
     * three-node mesh a rename the middle node performed is seen by the third
     * node as a rename the MIDDLE node performed. Attributing it to the prefix
     * instead would move the member to a different server's roster, which is the
     * misattribution 4.3.1 added `<server>` to SBURSTM to prevent. The member's
     * server is the LINK, because a rename does not move anybody between servers
     * -- it changes what this one calls them. */
    (void)prefix;

    fed_nickreg_rename(s, link->name, params[0], params[1], server_now_ms());
    fed_obs("[observable] fed_nickreg_rename: server=%s from=%s to=%s to_len=%zu to_bad_bytes=%zu\n", link->name,
           params[0], params[1], strlen(params[1]), conn_text_bad_count(params[1]));

    /* THE ROSTERS, one channel at a time. There is no index from nickname to
     * channel, and there must not be: a member's name is not a global key, so a
     * node-wide map would be a second registry whose only use is this walk and
     * whose staleness would then be a second thing to reconcile. The walk is
     * O(channels) and this node has a bounded number of them. */
    for (size_t ci = 0, nch = server_chan_count(s); ci < nch; ci++) {
        chan_t *ch = server_chan_at(s, ci);

        if (ch == NULL || ch->nremotes == 0) {
            continue;
        }
        if (chan_remote_rename(ch, link->name, params[0], params[1]) == 1) {
            renamed++;
            fed_touch_server(ch, link->name, 0);
            /* THE CHANNEL'S OWN CLIENTS, and the prefix is the LINK because the
             * line as it arrives names the link; fanout_forward_channel_sverb()
             * renders the prefix itself and this is the shape every other
             * state-change verb uses. A member's rename inside a channel is
             * something a client watching the channel must be told, and the
             * fanout is the only path to a client that exists. */
            (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SNICK",
                                               link->name, params, nparams, tags);
            /* The NICK the channel's own clients see: old nick as the prefix
             * with the new nick as the parameter, exactly the shape nickreg.c
             * renders for a local rename. */
            {
                const char *lp[1];

                lp[0] = params[1];
                fed_local_emit(s, ch, params[0], "NICK", lp, 1);
            }
        }
    }
    if (renamed == 0) {
        /* NO ROSTER HELD IT, which is the ordinary case for a user who is
         * connected but not in any channel this node knows about -- the common
         * case on a relay. The registry is still updated above, and a rename
         * that reaches nobody is not a failure: there was nothing to tell. */
        fed_obs("[observable] fed_snick: server=%s from=%s to=%s rosters=0 to_len=%zu to_bad_bytes=%zu\n",
               link->name, params[0], params[1], strlen(params[1]), conn_text_bad_count(params[1]));
    } else {
        fed_obs("[observable] fed_snick: server=%s from=%s to=%s rosters=%d to_len=%zu to_bad_bytes=%zu\n",
               link->name, params[0], params[1], renamed, strlen(params[1]), conn_text_bad_count(params[1]));
    }
}
