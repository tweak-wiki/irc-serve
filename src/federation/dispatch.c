/* dispatch.c -- see dispatch.h. The inbound guard chain, split out of
 * federation/verbs.c (#543). */
#include "federation/dispatch.h"

#include "federation/verbs.h"

#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/server.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/link.h"
#include "federation/membership.h"
#include "federation/notify.h"
#include "federation/state.h"

/* SPRIVMSG / SNOTICE: <target> <text>.
 *
 * A `message` class line, so 3.1 applies both channel rows at once: write to
 * local members AND forward -- to the owner if this node does not own the
 * channel, to servers[] UNION the ESTABLISHED links if it does. The local write
 * goes through fanout_deliver() with the CLIENT verb (a client is never sent an
 * S-verb) and the prefix is the one the line arrived with, which for a
 * peer-relayed SPRIVMSG is a real hostmask and is therefore the only thing this
 * node could put on the message for its own clients.
 *
 * AND THIS FUNCTION FORWARDS NOTHING ITSELF. It used to: it wrote locally
 * through fanout_deliver() and then called fanout_forward_channel_sverb() with
 * the received `tags`. That was a SECOND forward of the same emission, and it
 * was invisible until 3.1's owned/`message` row was amended, because until then
 * the only node that received a `message` was the owner and an owner had no
 * forward arm for the first of the two to double up on. With the amendment every
 * node that receives a `message` has a forward arm, and the two calls together
 * would have sent the owner TWO copies of one client message: one from
 * fanout_deliver()'s forward, which had no `carry` and therefore MINTED A FRESH
 * id, and one from here, which carried the real one. The fresh id is the worse
 * of the two -- 2.4 says a relay changes hops and nothing else, and a restamp is
 * how a message comes back.
 *
 * So the tags go INSTEAD, as fanout_deliver()'s `carry`, and the forward happens
 * once, in the one place 3.1's table is transcribed. What that argument buys is
 * not tidiness: it is that the local write and the forward cannot be given
 * different identities, which is the failure this whole function is shaped to
 * make unrepresentable. */
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams);
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams)
{
    int delivered = fanout_deliver(s, t, prefix, client_verb, params, nparams, NULL,
                                   tags);

    /* The LOCAL half, reported. The client-side path reports its own
     * deliveries in msg_verbs.c's `msg:` line, and a relayed message has no
     * such line anywhere -- it arrives on a peer link and is fanned out from
     * here -- so without this a node's log shows a message arriving from a
     * peer and nothing about what it did with it. The count is the number of
     * local members written to, which is 0 on a node that is purely a relay,
     * and that zero is the interesting value rather than a disappointing one.
     *
     * It is also the countable line a loop shows up in: a message that keeps
     * circulating prints this again, so "delivered exactly once" can be
     * asserted from the node as well as from the client. */
    /* `from_len=` is measured from the SAME ternary that is printed, not from the bare
     * `prefix`: on the fallback branch `prefix` is NULL and strlen(NULL) is the crash
     * this measurement sits next to a guard to avoid. The reported 1 is the length of
     * the `?` the reader can actually see. */
    fed_obs("[observable] fed_message: channel=%s from=%s delivered=%d "
           "origin=%s hops=%lu channel_len=%zu channel_bad_bytes=%zu "
           "origin_len=%zu origin_bad_bytes=%zu from_len=%zu from_bad_bytes=%zu\n",
           t->name, (prefix != NULL) ? prefix : "?", delivered, tags->origin,
           (unsigned long)tags->hops, strlen(t->name), conn_text_bad_count(t->name),
           strlen(tags->origin), conn_text_bad_count(tags->origin),
           strlen((prefix != NULL) ? prefix : "?"),
           conn_text_bad_count((prefix != NULL) ? prefix : "?"));
}

/* ---------------------------------------------------------------------------
 * The inbound table, and the verbs it does not have
 * ---------------------------------------------------------------------------
 *
 * G8 asks this table for the VERB the peer sent, which is an S-verb -- the
 * encode direction's output is this table's input, which is what makes the two
 * halves of this file one format rather than two. A table rather than a switch
 * for the reason fed_sverb_for() gives: a switch duplicates every name in the
 * source, so a typo in one arm compiles cleanly and returns the wrong thing at
 * run time.
 *
 * `min`/`max` are the parameter bounds, and they are the FROZEN shapes' bounds
 * rather than a range: an SJOIN is always six parameters, an SPART is two to
 * four (issue #663's quit marker and reason extend the frozen two-or-three),
 * and a verb arriving with a different count is a peer running a different
 * format and is REFUSED rather than guessed at. Refusing is the safe
 * direction because the alternative -- reading params[1] of a two-parameter
 * SPRIVMSG -- is a read of a field that does not exist.
 */
static const struct {
    const char *verb;
    int min;
    int max;
    void (*fn)(server_t *, server_link_t *, fanout_target_t *, const char *,
               const irc_serve_tags_t *, const char *const *, int);
    int vclass; /* what the target is resolved under, and the row it takes */
    const char *client_verb; /* what a RELAY of it is called */
} INBOUND[] = {
    { "SPRIVMSG", 2, 2, NULL, FANOUT_MESSAGE,  "PRIVMSG" },
    { "SNOTICE",  2, 2, NULL, FANOUT_MESSAGE,  "NOTICE"  },
    { "SJOIN",    6, 6, NULL, FANOUT_STATE_CHANGE, "JOIN"  },
    { "SPART",    2, 4, NULL, FANOUT_STATE_CHANGE, "PART"  },
    { "STOPIC",   3, 3, NULL, FANOUT_STATE_CHANGE, "TOPIC" },
    { "SMODES",   3, 4, NULL, FANOUT_STATE_CHANGE, "MODE"  },
    { "SKICK",    3, 4, NULL, FANOUT_STATE_CHANGE, "KICK"  }
};

static int inbound_index(const char *verb)
{
    if (verb == NULL) {
        return -1;
    }
    for (size_t i = 0; i < sizeof INBOUND / sizeof INBOUND[0]; i++) {
        if (strcmp(INBOUND[i].verb, verb) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* The 4.3 words this build does not speak yet, and WHY THAT IS NOT "unknown".
 *
 * SNAMES and SHASH are in 4.3's list and are not in INBOUND, because they are
 * later commits of this phase. They are listed here so that a peer sending one
 * is told this node has not implemented it rather than that it is not a verb -- a
 * distinction an operator needs, because the first means "a peer is running a
 * build I do not have" and the second means "a peer is talking nonsense".
 * Reporting them through n_fed_unknown_verb would make the counter mean two
 * incompatible things and stop being evidence of anything.
 *
 * SQUIT IS NOT HERE ANY MORE, and its removal is the change C5 made: the
 * departure announcement landed, so a peer sending one gets the purge rather than
 * a version fact. A verb that arrives and is handled must not leave its name in a
 * table that says it is not handled, or the table becomes a place where a reader
 * learns which half of the phase is finished -- which is what the list said about
 * SBURST before C4 removed it, and is why this paragraph exists.
 *
 * FEDERATE is NOT here: it never reaches G8, because G2 consumes it, and it is
 * the verb that ESTABLISHES the epoch every other tag rule is stated against. */
static const char *const DEFERRED[] = { "SNAMES", "SHASH" };

static int is_deferred(const char *verb)
{
    for (size_t i = 0; i < sizeof DEFERRED / sizeof DEFERRED[0]; i++) {
        if (strcmp(DEFERRED[i], verb) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * fed_dispatch -- the guard chain
 * ---------------------------------------------------------------------------
 */
void fed_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    irc_serve_tags_t tags;
    server_link_t *link;
    fanout_target_t t;
    char peer[IRC_MAX_SERVER_NAME + 1];
    const char *pserver;
    /* message_t::params is `char *[]` and every handler here takes
     * `const char *const *`, and C will not add that qualification silently to
     * an array of pointers. A local array is the copy that makes it legal, and
     * it does the arity bound as a side effect: G9 has already checked nparams
     * against the verb's frozen shape, so nothing past cap can be written and
     * the handlers cannot be handed a longer list than the wire shape allows. */
    const char *sp[IRC_MAX_PARAMS];
    int idx;

    /* --- G0: NULL args, no command -------------------------------------- */
    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* THE LINK IS LOOKED UP BY THE CONNECTION'S PEER NAME, and that is safe
     * here for a reason the connection's name being a display copy does not
     * obviously give. A connection only becomes CONN_SERVER in
     * fed_link_established(), which sets peer_name from the claim the handshake
     * accepted, and 2.3's uniqueness check guarantees at most one link holds
     * that name. So a CONN_SERVER conn names exactly one link, and
     * server_find_link() is that link. It is deliberately NOT a search by
     * descriptor: federation/link.c's fed_link_of_conn() documents the
     * recycled-descriptor trap a `link->fd == c->fd` lookup falls into, and this
     * path does not have it. */
    link = (c->peer_name != NULL) ? server_find_link(s, c->peer_name) : NULL;

    /* --- G1: pre-auth ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") != 0 &&
        (link == NULL || link->state != (int)ESTABLISHED)) {
        /* Dropped, and the link is NOT torn down. A line on a connection that is
         * not an established peer link is a stranger talking, and the answer to
         * a stranger is the handshake, not a closed socket: the same connection
         * is one second away from sending a FEDERATE. Tearing it down here would
         * make a peer that speaks before it says hello permanently
         * unconnectable, and the handshake FSM has no way to recover from that.
         *
         * Counted, because a node whose pre-auth drops climb is a node that is
         * being spoken to by something that is not a peer, and that is a finding
         * rather than a statistic. */
        s->n_fed_preauth_drop++;
        fed_obs("[observable] fed_preauth_drop: fd=%d command=%s state=%s command_len=%zu command_bad_bytes=%zu\n", c->fd,
               m->command,
               (link != NULL) ? ((link->state == (int)ESTABLISHED) ? "ESTABLISHED"
                                                                     : "PENDING")
                              : "NONE", strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G2: FEDERATE ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* The one verb that is exempt from every tag rule below, and it is
         * exempt BY CONSTRUCTION rather than by a special case: the epoch this
         * line is about to be judged against is the one it ESTABLISHES. A
         * FEDERATE carries no 2.4 block because 2.4's block is what a receiver
         * needs in order to deduplicate and loop-check a message, and a
         * handshake is neither relayed nor looped. */
        fed_on_federate(s, c, m);
        return;
    }

    /* --- G3: still not ESTABLISHED --------------------------------------- */
    if (link == NULL || link->state != (int)ESTABLISHED) {
        /* UNREACHABLE after G1, and kept as the assertion that the two cannot
         * disagree. A counted return rather than a silent one, so an edit that
         * reorders G1 and G3 leaves a number behind instead of a hole. */
        s->n_fed_preauth_drop++;
        fed_obs("[observable] fed_preauth_drop: fd=%d command=%s state=UNREACHABLE command_len=%zu command_bad_bytes=%zu\n",
               c->fd, m->command, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G4: the 2.4 tag block, and the trust boundary -------------------- */
    if (irc_serve_tags_parse(m, &tags) != 0) {
        pserver = fed_prefix_server(m->prefix, peer, sizeof peer);

        if (pserver == NULL) {
            /* CASE D. A prefix that is not a usable server name at all: absent,
             * empty, over-long, or a name the 2.4 tag grammar would refuse. There
             * is no identity to synthesise and no server to say it belongs to
             * someone else, so this is malformed rather than a relay -- and
             * counting it as a relay would tell an operator their peer is
             * misbehaving in a specific way when the line is simply not a line
             * this node can reason about. */
            s->n_fed_malformed++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "prefix=%s reason=BAD_PREFIX command_len=%zu command_bad_bytes=%zu "
                   "prefix_len=%zu prefix_bad_bytes=%zu\n",
                   c->fd, link->name, m->command,
                   (m->prefix != NULL) ? m->prefix : "(none)", strlen(m->command),
                   conn_text_bad_count(m->command),
                   strlen((m->prefix != NULL) ? m->prefix : "(none)"),
                   conn_text_bad_count((m->prefix != NULL) ? m->prefix : "(none)"));
            return;
        }

        if (is_deferred(m->command)) {
            /* CASE C. A 4.3 verb this build does not speak, arriving untagged.
             * Refused, but reported as what it is: a peer running a build with
             * the resync verbs is a version fact, and calling it an untagged
             * relay would send the operator looking for a loop. */
            s->n_fed_verb_deferred++;
            fed_obs("[observable] fed_verb_deferred: fd=%d peer=%s command=%s command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }

        if (fed_burst_verb(m->command) != 0) {
            /* CASE E, AND IT EXISTS BECAUSE A BURST IS NOT A MESSAGE. Every other
             * verb in this chain is happy to have its identity MINTED for it by
             * case A below, because a message's identity is per line and a
             * missing one costs that line. A burst is O(n) lines forming ONE
             * transaction, and case A mints a fresh id PER LINE -- which is
             * exactly right for dedup and exactly wrong for the thing the
             * transaction is for. A peer that could send an untagged burst would
             * therefore be able to make this node replace its entire view of
             * that origin, as often as it liked, with lines whose 2.4 identity
             * this node invented. So the one verb family that is state REPLACEMENT
             * is required to carry its identity on the wire, and the refusal is
             * counted as malformed rather than as a relay: a peer sending it is
             * not relaying somebody else's burst, it is sending a burst it did
             * not stamp. */
            s->n_fed_malformed++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "reason=BURST_UNTAGGED command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }

        if (!chan_same_name(pserver, link->name)) {
            /* CASE B. The peer is RELAYING and did not stamp the line. REFUSED,
             * and the link is NOT torn down.
             *
             * Every 2.4 guard is unavailable on this line: there is no origin to
             * check against our own name, no hop count to apply the ceiling to,
             * and no (origin, epoch, id) to record, so a store that "saw" it
             * would be recording a key it invented. A node that accepts untagged
             * relays therefore has NO loop prevention at all, and 2.4's three
             * rules are the whole of what stops two nodes bouncing a message for
             * ever. There is no partial acceptance available: either the
             * identity is on the wire or it is not.
             *
             * The discriminator is THE PREFIX and never the verb, and a peer
             * relaying a message it received FOR A CHANNEL IT HAS A MEMBER IN
             * sends `SPRIVMSG` with a REMOTE prefix -- so any rule keyed on the
             * verb would accept exactly the dangerous case and refuse the
             * harmless one. */
            s->n_fed_untagged_relay++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s prefix=%s "
                   "reason=RELAY_UNTAGGED command_len=%zu command_bad_bytes=%zu prefix_len=%zu prefix_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, pserver, strlen(m->command), conn_text_bad_count(m->command), strlen(pserver), conn_text_bad_count(pserver));
            return;
        }

        /* CASE A. The peer ORIGINATED the line: its prefix is its own server
         * name. Accepted, with the identity SUPPLIED rather than read.
         *
         * MINTING THE ID LOCALLY IS THE POINT. An untagged originated line has
         * no identity of its own, and a node that forwarded it with a
         * synthesised one has to invent an id; inventing it from the
         * per-SERVER counter is what makes the invented value unique to this
         * node and therefore safe to put in a key the far side will store.
         *
         * AND IT IS THE PEER'S EPOCH, not s->epoch, and the reason is subtle
         * enough to be worth the paragraph. The key is (origin, epoch, id) and
         * the origin here is the PEER, so the epoch has to be the boot the
         * peer's own id stream belongs to: a key whose epoch belongs to a
         * different boot than its id is a key that aliases. If this node stamped
         * s->epoch here, every relay node on a path would pair ITS counter with
         * an epoch that is not the counter's, and two of them relaying the same
         * untagged line would mint two DIFFERENT keys for one message -- so a
         * third node would accept both copies and deliver the message twice, with
         * dedup unable to collapse them because there is nothing shared to
         * collapse on. With the peer's epoch, both relayers mint into the SAME
         * (peer, peer-boot) id space, two relays of one untagged line collapse
         * onto one key, and the second copy is dropped as the duplicate it is.
         *
         * THE COST, because a bound that cannot be reached is not a bound: the
         * id is drawn from THIS node's counter while the epoch is the peer's, so
         * a synthetic id can in principle collide with the peer's own id of the
         * same number, and the peer would then have its genuine message dropped
         * as a duplicate. That is the recoverable direction: dedup.h states it,
         * that a dropped message is one lost message whereas a store that failed
         * to record is a loop, and it is reachable only by a peer that sent an
         * untagged line in the first place. A colliding key is the correct
         * answer to a line that claims to be from a boot we cannot see the
         * counter of. */
        memset(&tags, 0, sizeof tags);
        memcpy(tags.origin, link->name, strlen(link->name) + 1u);
        tags.epoch = link->epoch;
        tags.id = server_next_msg_id(s);
        tags.hops = 0u;
        fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu reason=ORIGINATED_UNTAGGED command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id, strlen(m->command), conn_text_bad_count(m->command));
    }

    /* --- G5: the hop ceiling --------------------------------------------- */
    if (tags.hops >= (uint32_t)IRC_MAX_HOPS) {
        /* 2.4: "irc-serve-hops increments per forward and the message is dropped
         * at 10." Checked on RECEIPT as well as at forward time, and the two are
         * not the same check: the forward-time one refuses to SPREAD a message
         * that is at the ceiling, and this one refuses to ACT on one that
         * arrived at it. A node that only checked at forward time would apply a
         * message that some other node had already decided to stop. */
        s->n_fed_hop_drop++;
        fed_obs("[observable] fed_hop_drop: fd=%d peer=%s command=%s hops=%lu "
               "ceiling=%d command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, (unsigned long)tags.hops, IRC_MAX_HOPS, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G6: never act on our own origin ---------------------------------- */
    if (chan_same_name(tags.origin, s->name)) {
        /* 2.4: "A node never forwards a message whose irc-serve-origin is
         * itself." The INBOUND half of it, and the half that makes "a two-node
         * ping-pong does not loop" true: a message this node originated came
         * back, and applying it would re-deliver to the local members it was
         * already delivered to and then forward it onward again. On a two-node
         * mesh that is the whole cycle; on a three-node mesh it is the short one
         * inside a longer one.
         *
         * The comparison is ASCII case-insensitive because server names are
         * (2.1, RFC 1459 2.3.2) and a peer that spells this node's name `IRC.A`
         * is naming THIS node. Treated as a different server, the hop ceiling
         * would be the only thing left and it is ten, so a two-node mesh would
         * bounce one message ten times before it stopped.
         *
         * IT IS REDUNDANT WITH G7, and it stays anyway. The dedup store is
         * bounded (IRC_DEDUP_MAX slots) and evictable (IRC_DEDUP_TTL_MS), so a
         * bound that CAN be reached is not a loop guard -- a node that has been
         * up for a while, or one on a busy mesh, can legitimately have evicted
         * the very entry that would have caught this. A rule that is a
         * belt-and-braces today is the only rule left when the braces are
         * dropped, and the hop ceiling is the second belt rather than the first:
         * it bounds the damage, it does not stop the loop. */
        s->n_fed_own_origin++;
        fed_obs("[observable] fed_own_origin_drop: fd=%d peer=%s command=%s "
               "origin=%s self=%s hops=%lu command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin, s->name,
               (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G7: the dedup store --------------------------------------------- */
    {
        int dedup = fed_dedup_seen(s, &tags, server_now_ms());

        if (dedup < 0) {
            /* THE STORE FAILED, and the message is dropped WITHOUT being
             * counted as a duplicate (#174). An allocation failure reported as
             * a duplicate would read on every dashboard as replay traffic,
             * and the memory pressure behind it would be invisible. */
            s->n_fed_dup_drop++;
            s->n_fed_dedup_error++;
            fed_obs("[observable] fed_dedup_error: fd=%d peer=%s command=%s origin=%s "
                   "epoch=%llu id=%llu hops=%lu command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, tags.origin,
                   (unsigned long long)tags.epoch, (unsigned long long)tags.id,
                   (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }
        if (dedup != 0) {
        /* RECORDED HERE, AT THE GUARD, AND NOT AFTER THE HANDLER.
         *
         * Dedup is a statement about the WIRE, not about whether this node
         * handled the message: a peer is not obliged to be correct, and nothing
         * stops a buggy or hostile one from sending the same id twice, once
         * well-formed and once not. A store that recorded only successfully
         * handled messages would take the second as new and act on it. So the
         * key is recorded on SIGHT, which is why this guard is above the verb
         * lookup and above the field validation: a message dropped by G8 or G9
         * is already recorded, and a peer cannot retry the same line under a new
         * id and get a different answer. A retry with a NEW id is a different
         * message, and 2.4's epoch exists so that a restarted peer is told to
         * use different ids.
         *
         * The two counters are incremented together because they are the same
         * event read at two levels -- the guard's drop and the store's duplicate
         * -- and a difference between them is either a store error
         * (n_fed_dedup_error, the <0 arm above) or a bug in the chain rather
         * than a number nobody looked at. */
        s->n_fed_dup_drop++;
        s->n_fed_dedup_dup++;
        fed_obs("[observable] fed_duplicate: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu hops=%lu command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id,
               (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
        return;
        } /* dedup != 0: a real duplicate */
    }

    /* --- G8: the verb ----------------------------------------------------- */
    /* THE BURST FAMILY IS ASKED BEFORE THE TABLE, and it is a separate branch
     * rather than five rows because it is not this kind of verb. INBOUND's rows
     * all describe a line about a CHANNEL, at a position the verb fixes, within
     * a two-or-three parameter arity; SBURSTC names the channel first and
     * carries six parameters, SBURSTM carries three, and SBURST carries two
     * numerics and names no channel at all. Rows for them would have arity ranges
     * that are individually correct and collectively a lie, and the handler
     * dispatch below reads the channel out of a position that means something
     * different for each verb.
     *
     * THEY ARE STILL GATED BY EVERYTHING ABOVE, which is the point of asking
     * here rather than earlier: a burst is state REPLACEMENT, so it is
     * hop-checked, own-origin-checked and deduplicated like anything else, and a
     * REPLAYED burst is the worst case this phase has. G9's arity check is not
     * applied to these five -- their shapes are five different shapes and the
     * format is where they are stated -- so each arm validates its own, and
     * federation/burst.c owns that because federation/burst.c is where the wire
     * format is. */
    if (fed_burst_verb(m->command) != 0) {
        (void)fed_burst_apply(s, link, m);
        return;
    }

    /* SQUIT, and the same placement argument one paragraph up: it names no
     * channel, so INBOUND's position-indexed read cannot reach it, and it is
     * asked HERE -- after the burst family and before the table -- so that
     * everything above still applies to it. That is the load-bearing part. A
     * SQUIT is the most state-destroying line in 4.3, and it is deduplicated
     * (G7), hop-checked (G5) and own-origin-checked (G6) by the same chain as an
     * SJOIN, which is why it is here and not in a second entry point. */
    if (strcmp(m->command, "SQUIT") == 0) {
        /* The same local array the table arms below use, and for the same reason
         * (message_t::params is `char *[]` and the handler takes a qualified
         * one). It is filled here rather than handed over as `m->params` because
         * the handler reads up to two entries and the wire can carry fifteen. */
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_squit(s, link, &tags, sp, m->nparams);
        return;
    }

    /* SNICK, in SQUIT's place in the chain, for SQUIT's reason: it names no
     * channel, so INBOUND's position-indexed read cannot reach it. It is asked
     * AFTER the SQUIT arm and BEFORE the table, so a SQUIT's own-origin
     * refusal and the burst family's ownership checks are all unaffected -- a
     * rename arriving on a link this node does not hold a member for is
     * unremarkable, and the two verbs must not be able to shadow each other. */
    if (strcmp(m->command, "SNICK") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_snick(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }

    /* SSETNAME, SAWAY and SINVITE, in SNICK's place in the chain, for SNICK's
     * reason: none of them fits INBOUND's position-indexed read. SSETNAME and
     * SAWAY name no channel at all, and SINVITE names a channel AND a user --
     * a row for it would resolve the wrong target and relay it as a channel
     * state change, which an invite is not. They are asked AFTER the SNICK arm
     * and BEFORE the table, so the guard chain above has already run: G1, G4,
     * G5, G6 and G7 all apply, and a peer replaying one line under a new id
     * is recorded rather than re-applied. */
    if (strcmp(m->command, "SSETNAME") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_ssetname(s, link, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SAWAY") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_saway(s, link, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SINVITE") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_sinvite(s, link, &tags, m->prefix, sp, m->nparams);
        return;
    }

    /* ADVERTISE AND SHUTDOWN, asked HERE for SQUIT's reason: neither names a
     * channel, so INBOUND's position-indexed read cannot reach either, and a row
     * for them would have to lie about what it reads. They are asked AFTER the
     * SNICK arm and BEFORE the table, so the whole of the guard chain above has
     * already run for them: G1 has refused a line from a link that is not
     * ESTABLISHED, G4 has resolved the 2.4 identity, G5 has checked the hop
     * ceiling, G6 has refused a line this node originated, and G7 has recorded the
     * key so a peer cannot retry the same line under a new id.
     *
     * IT MATTERS FOR ADVERTISE SPECIFICALLY, and that is why these two are here
     * rather than handled before the chain: an ADVERTISE carries a dial hint, and
     * a dial hint is the one thing on this node's wire that must never reach the
     * dial path. Handling it before the chain would mean accepting a hint from
     * anything that opened a TCP connection, which is a stranger, and the secret
     * in FEDERATE is the only thing that makes a peer a peer. */
    if (strcmp(m->command, "ADVERTISE") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_advertise(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SHUTDOWN") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_shutdown(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }

    idx = inbound_index(m->command);
    if (idx < 0) {
        if (is_deferred(m->command) != 0) {
            s->n_fed_verb_deferred++;
            fed_obs("[observable] fed_verb_deferred: fd=%d peer=%s command=%s command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }
        s->n_fed_unknown_verb++;
        fed_obs("[observable] fed_unknown_verb: fd=%d command=%s peer=%s command_len=%zu command_bad_bytes=%zu\n", c->fd,
               m->command, link->name, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G9: arity and fields -------------------------------------------- */
    /* Every field is validated with the SAME rule the local surface uses, and
     * that is the point rather than a detail: a nickname arrives here from a
     * network for the first time, and 2.1's charset exists because later phases
     * build on it. chan_remote_add() applies it to the nickname and the 2.4
     * grammar to the server name, so the roster cannot hold a name this node
     * could not qualify or render. */
    if (m->nparams < INBOUND[idx].min || m->nparams > INBOUND[idx].max) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=%s field=arity "
               "nparams=%d want=%d..%d command_len=%zu command_bad_bytes=%zu\n",
               c->fd, m->command, m->nparams, INBOUND[idx].min, INBOUND[idx].max, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }
    /* --- G10: the handler -------------------------------------------------- */
    if (INBOUND[idx].vclass == FANOUT_MESSAGE) {
        /* The message verbs name the TARGET first, and there is nothing to
         * create: a SPRIVMSG does not prove a channel exists, it only says
         * somebody spoke in it. A channel this node does not hold is the
         * ordinary "not a member of my mesh" case, counted as malformed rather
         * than created, because creating a channel from a message would let any
         * peer invent channels on this node by talking in them.
         *
         * fanout_resolve() is asked with a NULL sender: the numerics it would
         * send have no client to go to, and asking for one would put a non-zero
         * on the counter server.h says should be zero forever. It is still the
         * one resolver, and `t.vclass` is still what it decides the row from. */
        if (fanout_resolve(s, NULL, m->params[0], FANOUT_MESSAGE, &t) == 0) {
            s->n_fed_malformed++;
            fed_obs("[observable] fed_malformed: fd=%d command=%s field=target "
                   "target=%s reason=NO_SUCH_TARGET command_len=%zu command_bad_bytes=%zu target_len=%zu target_bad_bytes=%zu\n",
                   c->fd, m->command, m->params[0], strlen(m->command), conn_text_bad_count(m->command), strlen(m->params[0]), conn_text_bad_count(m->params[0]));
            return;
        }
        /* The TEXT is the second parameter and it is the whole payload; the
         * target is the first and fanout_deliver() prepends t->name itself. */
        for (int i = 0; i < m->nparams - 1; i++) {
            sp[i] = m->params[i + 1];
        }
        /* ------------------------------------------------------------------
         * THE INBOUND HALF OF fed_relay_clean(), AND THE PEER SWEEP FOUND IT.
         * ------------------------------------------------------------------
         *
         * WHAT WAS MISSING, and it is a whole half of one line's journey. Three
         * filters already existed and none of them is on this path:
         *
         *   - `msg_verbs.c` filters a CLIENT's message text before fanning it out,
         *     with `conn_text_strip()` under STRIP_RELAY;
         *   - `fed_relay_clean()` below `fed_queue_line()` filters the same text
         *     again on the way to a PEER, with the same policy;
         *   - `write_to_members()` -> `send_line_tagged()` filters NOTHING, and it
         *     is what writes to a local client.
         *
         * So a message a PEER originated went peer -> this node -> a person's
         * terminal with its bytes untouched, while the identical message a client
         * on this same node originated was stripped. `test_peer_terminal_sweep`
         * found it on Linux as `:irc.b PRIVMSG #P549 :marker \x9f text` -- a bare
         * C1 control, which on an 8-bit terminal IS CSI -- and macOS reported the
         * same sweep clean, which turned out to be the sweep's own blind spot
         * rather than a platform difference (it drained the client buffer once per
         * marker and then swept only what arrived after the last drain).
         *
         * WHY HERE AND NOT IN `fed_in_message()`. Same reason `fed_relay_clean()`
         * sits below the verb table rather than in each verb: this is BELOW G9's
         * arity check, so a message verb added to INBOUND later cannot forget it,
         * and a table row that knows a verb's parameter layout is a site that can
         * be written wrong -- which the sweep has already caught once, with the
         * channel in the wrong slot of an SMODES row.
         *
         * WHICH POLICY, and it is the SAME one for the same reason the outbound
         * table uses it: this field is RELAYED MESSAGE TEXT, and the eight mIRC
         * formatting bytes in it are semantics a client renders rather than hazard.
         * The stored-value policy (`conn_text_strip()`, used for a topic or a kick
         * reason) would strip a colour code off every message on the network. So
         * the call below and the row above it name the same function, and a change
         * to the rules is a change to both halves.
         *
         * WHY THE STATE VERBS ARE NOT HERE. `STOPIC`, `SKICK` and `SMODES` reach a
         * local client only through `fanout_forward_channel_sverb()`, which writes
         * to PEERS and does not emit locally at all -- the gap `fed_dispatch`'s own
         * header names. So the peer->client exposure this fix closes is the message
         * path, and the state verbs' exposure is the forward path, which
         * `fed_relay_clean()` already covers. That is worth stating because the
         * difference is invisible from the table: the two halves of INBOUND look
         * identical and are filtered by different functions for that reason.
         *
         * THE MEASUREMENT IS REPORTED, for `fed_relay_clean()`'s reason: stripping
         * a peer's text is invisible on the wire -- the far side sees a shorter
         * field and cannot tell anything happened -- so a node that silently
         * shortened relayed text would be indistinguishable from one that mangled
         * it. `n_msg_stripped` is the same counter the client path increments,
         * because it is the same decision about the same field; the line below it
         * says which half of the node did it.
         *
         * COST: one extra pass over the text and one bounded copy, on the peer path
         * for the two message verbs, and only when the peer's line was accepted.
         * The 8 KiB arena is scoped to this block so it is not held for the state
         * verbs below, and it is `IRC_MAX_LINE` because the line is already bounded
         * by the framing layer -- stripping only removes bytes, so the filtered
         * value always fits in what the unfiltered one occupied.
         *
         * AND THE DELIVERY IS INSIDE THE BLOCK, which the first version of this was
         * NOT and which the sanitizer cell caught as a stack-use-after-scope. `sp[0]`
         * is a POINTER, and it was left pointing at `clean` while the closing brace
         * ended `clean`'s lifetime; `fed_in_message()` then read it back through
         * `message_build()` and got whatever the frame had become. It passed all
         * twelve build cells and every local test, because a dead stack read is only a
         * wrong answer when the reused bytes are not the right ones -- which is the
         * same reason this project's leak and use-after-free work keeps coming back to
         * Linux. The arena's scope and the pointer's scope are now the same scope, and
         * that is stated here because "the block ends after the call" is the kind of
         * thing a later edit tidies away. */
        {
            char clean[IRC_MAX_LINE];
            const size_t in_len = strlen(sp[0]);
            const size_t kept = conn_text_strip(clean, sizeof clean, sp[0], STRIP_RELAY);

            sp[0] = clean;
            if (kept != in_len) {
                s->n_msg_stripped++;
                fed_obs("[observable] fed_message_stripped: verb=%s kept=%zu "
                       "removed=%zu verb_len=%zu verb_bad_bytes=%zu\n",
                       m->command, kept, in_len - kept, strlen(m->command), conn_text_bad_count(m->command));
            }
            fed_in_message(s, &t, m->prefix, &tags, INBOUND[idx].client_verb, sp,
                           m->nparams - 1);
        }
        return;
    }
    {
        /* The state verbs name the channel in DIFFERENT PARAMETER POSITIONS --
         * first for SJOIN, second for the rest -- which is 4.3's frozen shape
         * and the reason this lookup is here rather than a single index. A
         * handler that read the wrong position would apply a state change to the
         * wrong channel, and "the wrong channel" is not a crash, it is a
         * divergence. */
        size_t at = (strcmp(m->command, "SJOIN") == 0) ? 0u : 1u;
        /* The node-wide cap (#542): refused HERE, before fed_in_channel() fails
         * it, because the NULL arm below reports that as fed_malformed and a
         * capacity refusal is not a peer protocol error. No client to numeric on
         * this path, so the observable IS the refusal, in handle_join's spelling. */
        if (strcmp(m->command, "SJOIN") == 0 &&
            chan_name_valid(m->params[at]) &&
            server_chan_get(s, m->params[at]) == NULL &&
            s->nchan_objs >= SERVER_MAX_CHANNELS) {
            fed_obs("[observable] chan_create_refused: channel=%s peer=%s "
                   "nchan=%zu cap=%d reason=TOO_MANY_CHANNELS "
                   "channel_len=%zu channel_bad_bytes=%zu\n",
                   m->params[at], link->name, s->nchan_objs, SERVER_MAX_CHANNELS,
                   strlen(m->params[at]), conn_text_bad_count(m->params[at]));
            return;
        }
        chan_t *ch = fed_in_channel(s, link, m->params[at],
                                    strcmp(m->command, "SJOIN") == 0);

        if (ch == NULL) {
            s->n_fed_malformed++;
            fed_obs("[observable] fed_malformed: fd=%d command=%s field=channel "
                   "channel=%s command_len=%zu command_bad_bytes=%zu channel_len=%zu channel_bad_bytes=%zu\n",
                   c->fd, m->command, m->params[at], strlen(m->command), conn_text_bad_count(m->command), strlen(m->params[at]), conn_text_bad_count(m->params[at]));
            return;
        }
        for (int i = 0; i < m->nparams; i++) {
            sp[i] = m->params[i];
        }
        if (strcmp(m->command, "SJOIN") == 0) {
            fed_in_sjoin(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SPART") == 0) {
            fed_in_spart(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "STOPIC") == 0) {
            fed_in_stopic(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SMODES") == 0) {
            fed_in_smodes(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SKICK") == 0) {
            fed_in_skick(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else {
            /* Unreachable: every enumerator of INBOUND is named above, and
             * G8 is the only way here. It is a BUG REPORT rather than a silent
             * return, because a table row with no arm is a verb this node
             * advertises by handling and does not do. */
            fed_obs("[observable] fed_unhandled_verb: command=%s command_len=%zu command_bad_bytes=%zu\n", m->command, strlen(m->command), conn_text_bad_count(m->command));
        }
    }
}
