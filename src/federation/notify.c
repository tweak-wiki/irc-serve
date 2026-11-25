/* notify.c -- see notify.h. The 4.3 extension's inbound notify half, verbatim out
 * of federation/verbs.c (issue #543). */
#include "federation/notify.h"

#include "federation/verbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/reply.h"
#include "core/server.h"
#include "federation/link.h"

/* ---------------------------------------------------------------------------
 * THE 4.3 EXTENSION'S INBOUND HALF (#563): SSETNAME, SAWAY, SINVITE
 * ---------------------------------------------------------------------------
 *
 * These three name NO server and fit no INBOUND row: SSETNAME and SAWAY name
 * only a nick (like SNICK), and SINVITE names a channel AND a user (like
 * nothing in the table -- the rows resolve a target and relay a channel state
 * change, and an invite is neither). So they are asked beside SQUIT/SNICK,
 * after the burst family and before the table, and the whole guard chain above
 * -- G1's link state, G4's identity, G5's hop ceiling, G6's own-origin refusal
 * and G7's dedup -- has already run for them. A handler below that applied
 * nothing and forwarded nothing would be a verb-shaped hole in the mesh.
 *
 * THE SUBJECT'S SERVER IS THE ARRIVAL LINK, exactly as SNICK's member server
 * is: a rename does not move anybody between servers, and neither does a
 * realname change, an away transition or an invitation. A peer can therefore
 * only ever report on nicks attributed to itself, and a lying peer's blast
 * radius is its own roster entries -- the same bound SNICK's prefix rule gives.
 * The prefix is IGNORED for attribution (it is the origin's render of the
 * setter's hostmask, for the log and for nothing else), with one exception:
 * SINVITE's prefix is PRESERVED on relay because the delivered client line is
 * prefixed with it, and a relay that rewrote it would deliver a lie about who
 * invited.
 *
 * STATELESS EXCEPT FOR THE ROSTER THEY STAND ON. Neither SSETNAME nor SAWAY
 * stores anything: there is no remote WHOIS in this build (nickreg.h records
 * the decision), so a stored realname or away text would have no reader, and a
 * field with no reader is a field whose staleness nobody can observe. What
 * they do is notify: the local members this node holds in a channel with the
 * remote member get the same client line the origin's own members got, through
 * the same capability gates. A member who joins afterwards learns nothing --
 * the same limit the local emissions already disclose, and the burst does not
 * close it either (frozen SBURSTN carries away but no realname). Stated rather
 * than solved: solving it is a roster field per channel per member, which is
 * the next change and not this one. */

/* The relay: every ESTABLISHED link except the one this arrived on, with the
 * SAME tags. SQUIT's broadcast loop with SQUIT's exclusions, minus the
 * departed-server one (these verbs name no server). Carrying the tags is what
 * keeps the loop from running for ever: the arrival link's echo would arrive
 * with an id this node already recorded, and G7 drops it as a duplicate. The
 * exclusion is still written out rather than relied on dedup for, because a
 * counter that must move for correctness and a counter that moves by accident
 * read the same on a dashboard. */
static void fed_relay_notify(server_t *s, server_link_t *link, const char *sverb,
                             const char *prefix, const char *const *params,
                             int nparams, const irc_serve_tags_t *tags)
{
    size_t k;

    for (k = 0; k < server_link_count(s); k++) {
        server_link_t *lk = server_link_at(s, k);

        if (lk == NULL || lk == link || lk->state != (int)ESTABLISHED) {
            continue;
        }
        (void)fanout_forward_sverb(s, lk->name, sverb, prefix, params, nparams,
                                   tags);
    }
}

/* The notifier's hostmask as this node renders it: `nick!user@host` from the
 * remote roster entry this node holds for (nick, link). Mirrors conn_hostmask()
 * byte for byte -- the same snprintf, the same truncation refusal -- because
 * the line it prefixes is the same line the origin's own members got, and a
 * second rendering rule would put a different author on the two halves of one
 * event. Returns NULL when this node holds no entry (a user in no channel this
 * node knows): the caller notifies nothing then, and still relays -- the
 * downstream node may hold the channel. */
static const char *fed_notify_prefix(server_t *s, server_link_t *link,
                                     const char *nick, char *out, size_t cap)
{
    size_t ci;
    int n;

    for (ci = 0; ci < server_chan_count(s); ci++) {
        chan_t *ch = server_chan_at(s, ci);
        size_t i;

        if (ch == NULL) {
            continue;
        }
        for (i = 0; i < ch->nremotes; i++) {
            const chan_remote_t *r = &ch->remotes[i];

            if (!chan_same_name(r->server, link->name) ||
                !chan_same_name(r->nick, nick)) {
                continue;
            }
            n = snprintf(out, cap, "%s!%s@%s", r->nick, r->user, r->host);
            if (n < 0 || (size_t)n >= cap) {
                out[0] = '\0';
                return NULL;
            }
            return out;
        }
    }
    return NULL;
}

/* Collect the channels whose roster holds (nick, link->name) into `found`.
 * Returns how many, capped at `cap`. The caller notifies that set: the local
 * members of every channel the subject shares with them. A member of three
 * shared channels is reached through the union once for SETNAME (whose line
 * names no channel) and three times for AWAY (whose line names each one),
 * which is why this returns the SET rather than notifying inside the walk. */
static size_t fed_notify_channels(server_t *s, server_link_t *link,
                                 const char *nick, chan_t **found, size_t cap)
{
    size_t n = 0u;
    size_t ci;

    for (ci = 0; ci < server_chan_count(s); ci++) {
        chan_t *ch = server_chan_at(s, ci);
        size_t i;

        if (ch == NULL) {
            continue;
        }
        for (i = 0; i < ch->nremotes; i++) {
            if (!chan_same_name(ch->remotes[i].server, link->name) ||
                !chan_same_name(ch->remotes[i].nick, nick)) {
                continue;
            }
            if (n < cap) {
                found[n++] = ch;
            }
            break;
        }
    }
    return n;
}

/* SSETNAME <nick> :<realname>. */
void fed_in_ssetname(server_t *s, server_link_t *link,
                            const irc_serve_tags_t *tags,
                            const char *const *params, int nparams)
{
    char prefix[CONN_HOSTMASK_MAX];
    const char *pp;
    (void)tags;
    fanout_form_t plain;
    const char *rp[1];
    chan_t **channels;
    size_t nchans;
    size_t nfound;
    int delivered;

    /* The realname is last and always present: an SSETNAME naming no value is
     * a peer running a different format, and G9's arity rule for the table
     * verbs applies here in prose -- refuse rather than guess. The value runs
     * the same predicate both client writers ran, because a value with two
     * writers needs the writers to agree (connection.h). */
    if (nparams != 2 || conn_realname_check(params[1]) != CONN_REALNAME_OK) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=SSETNAME field=%s "
               "nparams=%d nick_len=%zu nick_bad_bytes=%zu\n",
               link->fd, (nparams != 2) ? "arity" : "realname", nparams,
               strlen((nparams > 0) ? params[0] : "?"),
               conn_text_bad_count((nparams > 0) ? params[0] : "?"));
        return;
    }
    if (!valid_nick(params[0])) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=SSETNAME field=nick "
               "nparams=%d nick_len=%zu nick_bad_bytes=%zu\n",
               link->fd, nparams, strlen(params[0]),
               conn_text_bad_count(params[0]));
        return;
    }
    /* THE RELAY FIRST, and the order is deliberate: the notify below walks
     * this node's roster, and a relay that ran after it would still run -- the
     * two do not interact -- but a reader checking "did this node forward what
     * it applied" should find the forward unconditional on whether this node
     * had anything to notify. A relay that shares no channel with the subject
     * still carries the line onward. */
    fed_relay_notify(s, link, "SSETNAME", NULL, params, nparams, NULL);
    pp = fed_notify_prefix(s, link, params[0], prefix, sizeof prefix);
    if (pp == NULL) {
        fed_obs("[observable] fed_ssetname: server=%s nick=%s rosters=0\n",
               link->name, params[0]);
        return;
    }
    nchans = server_chan_count(s);
    channels = (chan_t **)malloc((nchans > 0u ? nchans : 1u) * sizeof *channels);
    if (channels == NULL) {
        return;
    }
    nfound = fed_notify_channels(s, link, params[0], channels, nchans);
    rp[0] = params[1];
    plain.params = rp;
    plain.nparams = 1;
    delivered = fanout_deliver_union_local_gated(s, channels, nfound, pp,
                                                 "SETNAME", &plain, NULL,
                                                 cap_gate_setname, NULL, NULL);
    free(channels);
    fed_obs("[observable] fed_ssetname: server=%s nick=%s channels=%zu "
           "recipients=%d realname_len=%zu realname_bad_bytes=%zu\n",
           link->name, params[0], nfound, delivered, strlen(params[1]),
           conn_text_bad_count(params[1]));
}

/* SAWAY <nick> [:<message>]. */
void fed_in_saway(server_t *s, server_link_t *link,
                         const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    char prefix[CONN_HOSTMASK_MAX];
    const char *pp;
    size_t ci;
    int delivered = 0;
    size_t nchans = 0u;

    /* One parameter is "back", two is "away with this message" -- the client's
     * own AWAY grammar, applied to a nick. An empty trailing parameter is not
     * a third shape: 3.2 drops empty middle tokens and `AWAY #c :` parses to
     * one parameter, so the cleared edge arrives as one parameter here too. */
    if ((nparams != 1 && nparams != 2) || !valid_nick(params[0])) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=SAWAY field=%s "
               "nparams=%d nick_len=%zu nick_bad_bytes=%zu\n",
               link->fd,
               (nparams != 1 && nparams != 2) ? "arity" : "nick", nparams,
               strlen((nparams > 0) ? params[0] : "?"),
               conn_text_bad_count((nparams > 0) ? params[0] : "?"));
        return;
    }
    fed_relay_notify(s, link, "SAWAY", NULL, params, nparams, tags);
    pp = fed_notify_prefix(s, link, params[0], prefix, sizeof prefix);
    if (pp == NULL) {
        fed_obs("[observable] fed_saway: server=%s nick=%s rosters=0\n",
               link->name, params[0]);
        return;
    }
    /* PER CHANNEL, like the local notify_away(): the client's own AWAY line
     * names each channel (`AWAY #chan :message`), so a member of three shared
     * channels gets three true lines, and the gate is asked per destination
     * the same way. The walk is over the channels that hold the subject, not
     * over the subject's membership -- a remote member has no conn_t whose
     * channel list could be walked. */
    for (ci = 0; ci < server_chan_count(s); ci++) {
        chan_t *ch = server_chan_at(s, ci);
        fanout_form_t plain;
        const char *ap[1];
        fanout_target_t t;
        size_t i;
        int holds = 0;

        if (ch == NULL || ch->name[0] == '\0') {
            continue;
        }
        for (i = 0; i < ch->nremotes; i++) {
            if (chan_same_name(ch->remotes[i].server, link->name) &&
                chan_same_name(ch->remotes[i].nick, params[0])) {
                holds = 1;
                break;
            }
        }
        if (holds == 0) {
            continue;
        }
        if (conn_text_display_check(ch->name) != CONN_DISPLAY_OK) {
            continue;
        }
        nchans++;
        memset(&t, 0, sizeof t);
        t.kind = FANOUT_LOCAL_CHANNEL;
        t.vclass = FANOUT_MESSAGE;
        t.chan = ch;
        memcpy(t.name, ch->name, sizeof t.name);
        if (nparams == 2) {
            ap[0] = params[1];
            plain.params = ap;
            plain.nparams = 1;
        } else {
            plain.params = NULL;
            plain.nparams = 0;
        }
        delivered += fanout_deliver_local_gated(s, &t, pp, "AWAY", &plain, NULL,
                                                cap_gate_away_notify, NULL,
                                                NULL);
    }
    fed_obs("[observable] fed_saway: server=%s nick=%s channels=%zu "
           "recipients=%d state=%s\n",
           link->name, params[0], nchans, delivered,
           (nparams == 2) ? "set" : "cleared");
}

/* SINVITE <channel> <target>: the inviter's hostmask is the prefix. */
void fed_in_sinvite(server_t *s, server_link_t *link,
                           const irc_serve_tags_t *tags, const char *prefix,
                           const char *const *params, int nparams)
{
    chan_t *ch;
    conn_t *target;
    const char *ip[2];
    fanout_form_t plain;
    chan_t *one[1];
    int delivered;

    /* The channel this node must hold: an invite names one, and a channel this
     * node has never heard of is the ordinary "not a member of my mesh" case
     * the message verbs count as malformed rather than create from. The target
     * is a nickname by the same charset the roster enforces. */
    if (nparams != 2 || !chan_name_valid(params[0]) ||
        !valid_nick(params[1])) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=SINVITE field=%s "
               "nparams=%d channel_len=%zu channel_bad_bytes=%zu\n",
               link->fd,
               (nparams != 2) ? "arity"
                              : (!chan_name_valid(params[0]) ? "channel"
                                                             : "target"),
               nparams, strlen((nparams > 0) ? params[0] : "?"),
               conn_text_bad_count((nparams > 0) ? params[0] : "?"));
        return;
    }
    ch = server_chan_get(s, params[0]);
    if (ch == NULL) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=SINVITE field=channel "
               "nparams=%d channel_len=%zu channel_bad_bytes=%zu\n",
               link->fd, nparams, strlen(params[0]),
               conn_text_bad_count(params[0]));
        return;
    }
    /* Relay first, unconditional on whether this node holds the invitee --
     * the downstream node may, and the line must reach it. The prefix is
     * PRESERVED: it is the inviter's hostmask and the delivered line carries
     * it, so a relay that replaced it would name the wrong author. */
    fed_relay_notify(s, link, "SINVITE", prefix, params, nparams, tags);
    /* THE INVITEE, if local: the same `:inviter INVITE <target> <channel>`
     * line the local handler delivers, through the same door. A remote
     * invitee is the relay's business, which just ran. */
    target = server_nick_lookup(s, params[1]);
    if (target != NULL) {
        ip[0] = params[1];
        ip[1] = params[0];
        (void)send_line(s, target,
                        (prefix != NULL && prefix[0] != '\0') ? prefix
                                                              : link->name,
                        "INVITE", ip, 2);
    }
    /* THE CHANNEL'S OWN MEMBERS, with the invite-notify gate: the same
     * audience the local handler notifies, minus the inviter exclusion (the
     * inviter is not local -- its 341 was the origin's business). */
    one[0] = ch;
    ip[0] = params[1];
    ip[1] = params[0];
    plain.params = ip;
    plain.nparams = 2;
    delivered = fanout_deliver_union_local_gated(
        s, one, 1u, (prefix != NULL && prefix[0] != '\0') ? prefix : link->name,
        "INVITE", &plain, NULL, cap_gate_invite_notify, NULL, NULL);
    fed_obs("[observable] fed_sinvite: server=%s channel=%s target=%s "
           "local=%d recipients=%d\n",
           link->name, params[0], params[1], (target != NULL) ? 1 : 0,
           delivered);
}
