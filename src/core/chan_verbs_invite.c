/* chan_verbs_invite.c -- see core/chan_verbs.h. 4.2's INVITE.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-48): the INVITE
 * section (handle_invite() plus its notify_invite() helper and both section
 * headers). It stays declared in core/chan_verbs.h (no new header), reached
 * through it by the dispatch table in core/commands_dispatch.c. Its in-TU
 * dependency is resolve_joined(), now shared through core/chan_verbs.h
 * (canonical_channel TU-45 / authority_ok TU-46 precedent); notify_invite()
 * moves with its sole caller.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "federation/verbs.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * INVITE
 * ---------------------------------------------------------------------------
 * 4.2's INVITE, RFC 2812 3.3.6. Two replies and one line to somebody else:
 *
 *   341  RPL_INVITING, to the INVITER: "you have invited them"
 *   INVITE  to the INVITEE, prefixed with the inviter's hostmask
 *
 * THE TWO REPLIES GO TO DIFFERENT CLIENTS, and that is the whole reason the
 * first one is not redundant. reply() addresses one connection (see reply.h), so
 * a 341 is by construction only ever seen by the inviter -- the numerics in 3's
 * reply path are "never written to a peer link and never relayed", and the same
 * one-enforcement-point discipline is what keeps a 341 off the invitee's socket.
 * The invitee is not answered with a numeric at all; it gets an INVITE, which is
 * an ordinary client-to-client line and therefore goes out through 3.1's table
 * rather than through reply().
 *
 * ---------------------------------------------------------------------------
 * WHY authority_ok() IS ASKED WITH `stateful` = 1 EVEN THOUGH INVITE CHANGES
 * NOTHING
 * ---------------------------------------------------------------------------
 * An INVITE adds no member, sets no topic and no mode, so by 2.2's own words it
 * is not a channel state change and the single-writer rule does not apply to it
 * in the way it applies to KICK or MODE. And yet it is asked as though it does,
 * and the reason is the OTHER thing it reads: the +o it checks.
 *
 * member.flags is the origin's record of who is an operator (2.2: the operator
 * set belongs to the origin, which is why MODE +o is a prefix mode and not an
 * origin-only one). So on a channel this node does not own, the +o that decides
 * 482 is a CACHE, and a cache cannot refuse anybody -- a node that let a cached
 * non-op invite would be the origin's policy being decided by a relay, which is
 * the exact failure the single-writer rule exists to prevent. Asking with
 * `stateful` = 1 is what turns that into an explicit 437 rather than a silently
 * wrong answer.
 *
 * And the FORWARD verdict is REFUSED here for the same reason handle_mode()
 * refuses it: 4.3's frozen S-verb table has no SINVITE, so there is no honest
 * line to put on a peer link, and the trailing text names the missing verb rather
 * than pretending the request succeeded somewhere it did not. The cost, stated:
 * on a federated mesh an invite into a channel this node does not own does not
 * work until 4.3 grows an SINVITE, and a client gets a 437 saying so rather than
 * a 341 that may not come true.
 *
 * ---------------------------------------------------------------------------
 * BOTH PARAMETER ORDERS ARE ACCEPTED
 * ---------------------------------------------------------------------------
 * RFC 1459 2.4.7 gave INVITE `<channel> <nick>` and RFC 2812 3.3.6 gave it
 * `<nick> <channel>`. Both are in the field -- the second is what current
 * clients send, the first is what older ones and a fair number of scripts still
 * send -- and a node that implements only one of them 401s half the clients that
 * use it, on a verb whose whole job is to be issued. So the two are told apart by
 * the NAME rather than by position: 4.4 advertises CHANTYPES=#& and this node
 * publishes 005's CHANTYPES=#&, so a parameter that is a valid channel name is
 * the channel. That is the same predicate the channel registry uses, so there is
 * one definition of "that is a channel name" and not two.
 *
 * The cost of accepting both is that `INVITE #a #b` is read as "invite #a to
 * #b" and 401s on #a, where reading it positionally would have produced the
 * nonsense invite of one channel to another either way. No legal line is
 * misread.
 */
static void notify_invite(server_t *s, conn_t *c, chan_t *ch, const char *prefix,
                           const char *target);

void handle_invite(server_t *s, conn_t *c, const message_t *m)
{
    const char *nick_arg;
    const char *chan_arg;
    const char *invitee;
    chan_t *ch;
    fanout_target_t t;
    chan_verdict_t verdict;
    char prefix[CONN_HOSTMASK_MAX];
    char nick[IRC_MAX_NICK + 1];
    const char *params[1];

    if (m->nparams != 2) {
        (void)reply_refused(s, c, "INVITE", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (chan_name_valid(m->params[0])) {
        /* RFC 1459 2.4.7's <channel> <nick>: the channel comes first. */
        chan_arg = m->params[0];
        nick_arg = m->params[1];
    } else {
        /* RFC 2812 3.3.6's <nick> <channel>. */
        nick_arg = m->params[0];
        chan_arg = m->params[1];
    }

    /* 442 for a channel the inviter is not on, 403 for a name this node will not
     * speak about, and -- less obviously -- 442 for a channel this node has
     * never heard of, because resolve_joined() answers that with 442 too and on
     * purpose. All three come from that one primitive rather than from three
     * checks here, so every channel verb in the node answers "you are not on
     * that channel" in the same words; the reasoning for the missing-channel
     * case is in resolve_joined()'s own comment. They are all about the
     * request rather than about the invitee, so they come before anything the
     * invitee is told. */
    ch = resolve_joined(s, c, chan_arg);
    if (ch == NULL) {
        return;
    }
    verdict = authority_ok(s, c, ch, "INVITE", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent; nothing has been touched */
    }
    if (verdict == CHAN_VERDICT_FORWARD) {
        printf("[observable] chan_invite_refused: channel=%s nick=%s "
               "reason=INVITE_NEEDS_ORIGIN\n",
               ch->name, c->nick);
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot invite to %s: this server is not its origin (%s)",
                    ch->name, ch->origin);
        return;
    }
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        /* 482, for the RFC's reason: "Only channel operators may invite new
         * users to a channel" (3.3.6). The same numeric KICK and MODE use for
         * the same situation, and 4.4 has nothing better to say about "you
         * lack privilege for this action". */
        (void)reply_refused(s, c, "INVITE", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_invite_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }

    /* Resolved through 3.1 rather than through a direct registry lookup, so the
     * target is carried as a resolved target with its class already decided --
     * the same discipline every other emitter in the tree follows, and the
     * reason a second write path cannot grow here. A name that resolves to a
     * CHANNEL is 401: an invite names a person, and "no such nick" is the
     * honest answer for a name that is not one. A REMOTE_USER is a person too,
     * on a server this node holds a link to (fanout_resolve refused every
     * other shape of that already), so it proceeds: the mesh half below is
     * what reaches them. */
    if (fanout_resolve(s, c, nick_arg, FANOUT_MESSAGE, &t) == 0) {
        return; /* 401 or 403 already sent */
    }
    if (t.kind != FANOUT_LOCAL_USER && t.kind != FANOUT_REMOTE_USER) {
        (void)reply(s, c, "401", (const char *const[]){ t.name }, 1,
                    "No such nick/channel");
        printf("[observable] chan_invite_refused: nick=%s target=%s kind=%d "
               "reason=not_a_nick\n",
               c->nick, t.name, (int)t.kind);
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }

    /* The channel is the ONLY parameter after the target: 3.1's target is
     * prepended by the fan-out, and the client's own shape is
     * `INVITE <target> [:<channel>]`. It is sent whether or not the invitee is
     * already on the channel -- 3.3.6 says the invitee is invited "regardless of
     * its modes" and says nothing about suppressing the channel for somebody who
     * is already there, so the unconditional form is the one that is always
     * answerable by a client. */
    if (t.kind == FANOUT_REMOTE_USER) {
        /* No local delivery: the invitee is not here, and INVITE has no
         * targeted forward (SINVITE rides the mesh flood below, which the
         * inbound half relays first and delivers from if the invitee is
         * local there). t.name is `nick@server`, split at the LAST '@' per
         * 2.1's scoped identity; the bare nick is what the 341, the notify
         * and the SINVITE all name, because a `nick@server` in SINVITE's
         * nickname parameter would be malformed on the receiving node. The
         * holder lookup resolved this exact nick against the registry, so it
         * fits a nick field. */
        const char *at = strrchr(t.name, '@');
        size_t nlen = (at != NULL) ? (size_t)(at - t.name) : strlen(t.name);
        if (nlen >= sizeof nick) {
            nlen = sizeof nick - 1;
        }
        memcpy(nick, t.name, nlen);
        nick[nlen] = '\0';
        invitee = nick;
    } else {
        params[0] = ch->name;
        (void)fanout_deliver(s, &t, prefix, "INVITE", params, 1, NULL, NULL);
        invitee = t.user->nick;
    }

    /* The inviter is told, and only the inviter. `invitee` is the spelling
     * the INVITEE chose (2.1: the registry folds the key and the display case is
     * the user's), so the 341 names them the way every other numeric does. */
    (void)reply(s, c, "341", (const char *const[]){ ch->name, invitee }, 2,
                "%s has invited you to channel %s", c->nick, ch->name);
    notify_invite(s, c, ch, prefix, invitee);
    /* Originated SINVITE: the mesh half of this invite. The inviter's hostmask
     * rides as the prefix because the inbound half delivers from it. */
    { const char *sip[2]; sip[0] = ch->name; sip[1] = invitee; (void)fed_forward_all(s, "SINVITE", prefix, sip, 2); }
    printf("[observable] chan_invite: channel=%s by=%s target=%s\n", ch->name,
           c->nick, invitee);
}

/* ---------------------------------------------------------------------------
 * invite-notify: THE CHANNEL IS TOLD
 * ---------------------------------------------------------------------------
 * `:nick!user@host INVITE <target> <channel>`, per destination, to the members of the
 * channel that negotiated the capability. The SOURCE is the inviter -- which is why this
 * is not a separate `send_line` but a fan-out carrying the inviter's own hostmask, the
 * same prefix the invitee's own copy carries and the same prefix `away-notify` uses.
 *
 * THE AUDIENCE IS THE CHANNEL, and RFC 2812 3.3.6 is the rule this relaxes: "Other
 * channel members SHOULD NOT be notified." The specification's whole purpose is to be the
 * opt-in that lets a client say it wants them, which is why the gate is the RECIPIENT's
 * negotiation and not the inviter's -- a sender-gated notification would put the fact on
 * the wire to members who never asked, which is the defect Phase 10.8a's gate was built
 * to prevent and which §9's risk row names.
 *
 * THE INVITER IS EXCLUDED, and it is excluded rather than gated because the gate would
 * have let it through if it negotiated. Two reasons: the `341` above IS the inviter's
 * answer -- "You have invited <nick> to <channel>" says exactly what this line would say
 * -- and the specification's own phrase is "a standard way that allows clients to learn
 * when ANOTHER client does an /INVITE". One line per event, to the audience it is for.
 *
 * MESH-REACHABLE THROUGH SINVITE, while the notify itself stays local-only: this
 * is an originating emission through the local-only entry point, and the
 * `handle_invite()` line above carries it across the mesh as
 * `:inviter SINVITE <channel> <target>`. A mesh member's clients learn of an
 * invitation two ways -- by sharing the channel, and by the SINVITE relay.
 *
 * PER CHANNEL, NOT OVER A UNION, and the reason is the shape: the line's own grammar is
 * `:<inviter> INVITE <target> <channel>` and it NAMES its channel, so a member of three
 * shared channels gets three true statements about three channels. That is the same
 * distinction `setname`'s fan-out turned on, in the other direction. */
static void notify_invite(server_t *s, conn_t *c, chan_t *ch, const char *prefix,
                          const char *target)
{
    const char *params[2];
    fanout_form_t plain;
    struct chan *one[1];
    int delivered;

    /* ONE CHANNEL HANDED TO THE UNION ENTRY POINT, and the reuse is deliberate rather
     * than convenient. `fanout_deliver_local_gated()` PREPENDS the resolved target, so a
     * channel-addressed emission renders `:inv!u@h INVITE #chan <target>` -- and this
     * specification's grammar is `:<inviter> INVITE <target> <channel>`, the other way
     * round. The first version of this used the channel entry point and the line on the
     * wire was `INVITE #I in_g` with the parameters the wrong way round.
     *
     * `fanout_deliver_union_local_gated()`'s CONTRACT IS ABOUT THE AUDIENCE -- "the local
     * members of these channels, each written once, with NO target prepended" -- and a
     * one-element list of one channel is exactly the members of that channel. What it
     * takes is a list of `chan_t *`, not a connection's own list; the de-duplication it
     * does inside the walk is a no-op for one channel. So no new entry point and no new
     * parameter is needed for a line whose shape does not match 3.1's row.
     *
     * (This is the second user of that entry point and it is worth noting that the two
     * have opposite requirements: `setname` needs it because its line names NO channel
     * and would otherwise carry one, and this needs it because its line names the channel
     * in a position 3.1's row would have filled with the channel. Both are the same fact
     * -- the emission's grammar and the routing table's row disagree -- seen from two
     * sides. `away-notify` is the case where they agree, because `AWAY #chan :message`
     * happens to put the target first.) */
    params[0] = target;
    params[1] = ch->name;
    plain.params = params;
    plain.nparams = 2;
    one[0] = ch;
    delivered = fanout_deliver_union_local_gated(s, one, 1u, prefix, "INVITE", &plain,
                                                 NULL, cap_gate_invite_notify, NULL, c);
    printf("[observable] invite_notify: channel=%s by=%s target=%s recipients=%d\n",
           ch->name, c->nick, target, delivered);
}
