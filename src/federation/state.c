/* state.c -- see state.h. The inbound channel-state and departure half,
 * verbatim out of federation/verbs.c (issue #543). */
#include "federation/state.h"

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
#include "federation/nickreg.h"

/* One QUIT per local member per departed member; defined beside fed_in_squit,
 * which shares it. Forward-declared because fed_in_shutdown() below calls it
 * and the definition lives with the SQUIT half it was extracted from. */
static void fed_emit_departure_quits(server_t *s, const char *gone,
                                     const char *reason);

/* SHUTDOWN [:reason].
 *
 * "I am leaving DELIBERATELY", and the whole of the handler is about what that
 * sentence is NOT allowed to mean. The three things it must not do:
 *
 *   1. IT MUST NOT LEAVE A LINK THAT LOOKS RETRYABLE FOR EVER. A peer that went
 *      away is a peer whose socket closed, and item 1's T4 turns that into a
 *      backoff and a budget and a redial -- BOUNDED (#666): a peer that restarted
 *      answers inside one backoff window, and a peer that never comes back costs
 *      three attempts and an exhausted report. Suppressing the redial until an
 *      operator reset the link partitioned the mesh on every peer restart, and
 *      there is no operator reset path in the shipped binary. So
 *      fed_mark_clean_leave() records the graceful departure for the log and the
 *      dump, and the retry budget is what bounds the redial.
 *      The distinction is in a FIELD rather than in a new handshake state,
 *      because the handshake FSM is 2.1's frozen four states and adding a
 *      fifth to it would be a change to a spec this phase does not own.
 *
 *   2. IT MUST NOT LEAVE THE MESH HOLDING STATE FOR A SERVER THAT IS GONE. The
 *      same purge a SQUIT performs, keyed on this peer, and for the same reason:
 *      4.3's roster for a server that is not coming back is state an operator
 *      cannot explain. The purge is per-ORIGIN (chan_remote_purge is keyed on the
 *      reporting origin), so nothing another origin contributed is touched.
 *
 *   3. IT MUST NOT BE SILENT, AND IT MUST NOT BE A CLIENT NOTICE. There is no
 *      client NOTICE here, and the reason is that no client's session is affected
 *      by which server left: the affected party is the MESH. A NOTICE would have
 *      to name a server the client cannot reach, cannot ask about, and has no way
 *      to do anything with -- it is noise aimed at the wrong audience. Per-member
 *      QUIT is the carved-out exception: a departed member IS a client's
 *      session fact, and the local members of its channels are the audience
 *      for it. Silence there is the symptom #559 was filed for. What the
 *      surviving node does instead is three things an operator
 *      can act on: it prints the line with the peer and the reason, it tells
 *      its OTHER peers (below), and it leaves the dump saying the departure
 *      was graceful and what the bounded redial decided.
 *
 * AND IT IS TOLD ONWARD, which is the half that makes it a mesh feature rather
 * than a local one. The forwarding is a `SQUIT <peer>` -- not a `SHUTDOWN`, and
 * the difference is the point: SQUIT is the verb the receiving side already knows
 * how to act on, it is the one 4.3's list has, and a third node that has never
 * heard of SHUTDOWN still purges correctly. A peer that predates this build counts
 * an unknown verb and applies nothing, which is a stale roster -- the same
 * degradation the SNICK argument makes, and the reason the forwarding reuses a
 * verb that already exists rather than introducing a second departure signal. */
void fed_in_shutdown(server_t *s, server_link_t *link, const char *prefix,
                            const irc_serve_tags_t *tags, const char *const *params,
                            int nparams)
{
    const char *reason = "-";
    size_t purged = 0u;
    size_t chans = 0u;
    size_t i;
    int relayed = 0;

    (void)prefix;
    (void)tags;

    if (nparams != 0 && nparams != 1) {
        s->n_fed_shutdown_refused++;
        fed_obs("[observable] fed_shutdown_refused: peer=%s reason=ARITY nparams=%d\n",
               link->name, nparams);
        /* The line is unusable, but the LINK carried it: a peer speaking the
         * wrong SHUTDOWN shape is a peer this node can no longer trust to
         * speak 4.3, so the link goes down with the line instead of staying
         * ESTABLISHED with a stale roster until T4. */
        {
            conn_t *c = server_link_conn(s, link);

            if (c != NULL) {
                conn_mark_closing(c);
            }
        }
        return;
    }
    if (nparams == 1) {
        reason = params[0];
    }

    /* 1. FIRST, BEFORE ANY OBSERVABLE, so a reader of the log sees the decision
     * before the consequences of it. The ordering also means that a purge which
     * somehow re-entered the tick could not find a dialable link. */
    (void)fed_mark_clean_leave(s, link, 1);

    /* 1b. THE QUIT EACH MEMBER SEES, before the purge forgets the names. On a
     * two-node mesh the relay below has no audience, so without this a
     * graceful leave renders nothing anywhere -- the symptom #559 was filed
     * for. Same helper SQUIT uses, same per-member hostmask-or-bare rule. */
    fed_emit_departure_quits(s, link->name, (nparams == 1) ? params[0] : NULL);

    /* 2. THE PURGE, AND IT IS PER-ORIGIN AND IT IS THE SQUIT BODY'S. The walk
     * shape is fed_in_squit()'s exactly, including the "do not advance past a
     * disposed channel" rule, and reusing the shape rather than the function is
     * deliberate: the two departures purge the same things for the same reason,
     * and the one difference between them -- the retry policy, above -- is
     * decided before this runs. */
    for (i = 0; i < server_chan_count(s);) {
        chan_t *ch = server_chan_at(s, i);
        int disposed;

        if (ch == NULL) {
            i++;
            continue;
        }
        purged += chan_remote_purge(ch, link->name);
        if (chan_server_remove(ch, link->name) > 0) {
            chans++;
        }
        disposed = chan_dispose_if_empty(s, ch);
        if (disposed == 0) {
            i++;
        }
    }
    fed_nickreg_purge_server(s, link->name);

    /* 3. TELL THE OTHERS, and the excluded link is this one because its socket is
     * about to close. Everything else ESTABLISHED gets a SQUIT for the departing
     * server, stamped once for the whole fan-out so 2.4's per-node dedup drops
     * the second copy on a node reachable by two of this node's peers -- the same
     * one-id argument fed_send_squit() makes for the identical fan-out. */
    relayed = fed_send_squit_named(s, link->name, link);
    s->n_fed_shutdown++;
    if (relayed > 0) {
        s->n_fed_shutdown_relayed++;
    }
    fed_obs("[observable] fed_shutdown: peer=%s reason=%s chans=%zu purged=%zu "
           "relayed=%d clean_leave=1 retried=0\n",
           link->name, reason, chans, purged, relayed);
    /* AND THE LINK ITSELF IS CLOSED, because a peer that said it is leaving and
     * then kept the socket open would be a peer whose word and whose behaviour
     * disagree, and this node has no way to make the word true. Marking the
     * connection CLOSING (rather than closing the descriptor) is the 3.4
     * invariant: the reaper is the only place an fd is closed, and the reaper
     * runs at the end of this iteration. */
    {
        conn_t *c = server_link_conn(s, link);

        if (c != NULL) {
            conn_mark_closing(c);
        }
    }
}

/* SPART: <member> <channel> [<reason>]. */
void fed_in_spart(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    if (nparams < 2 || nparams > 3) {
        return;
    }
    /* The actor BEFORE the removal below: the roster record is the only
     * place this node's burst-described hostmask lives, and the purge
     * forgets it. */
    char actor[CONN_HOSTMASK_MAX];
    const char *who = fed_actor_prefix(ch, params[0], prefix, 0, actor,
                                       sizeof actor);

    (void)chan_remote_remove(ch, link->name, params[0]);
    /* #608: the registry entry the SJOIN for this member learned, keyed the
     * same way the learn was (holder = the link it arrived on), so a departed
     * member stops answering nick@server here instead of haunting it until
     * the next burst. A PARTed-but-present nick re-learns on its next SJOIN. */
    fed_nickreg_forget(s, params[0], link->name);
    fed_touch_server(ch, link->name, 0);
    fed_obs("[observable] fed_spart: channel=%s member=%s server=%s remote=%zu\n",
           ch->name, params[0], link->name, ch->nremotes);
    /* The PART this node's own clients see, with the reason stripped the way
     * the local PART path strips it -- announced nowhere else, stored nowhere. */
    if (nparams > 2) {
        char clean[CHAN_MAX_PART_REASON + 1u];
        const char *lp[1];

        (void)conn_text_strip(clean, sizeof clean, params[2], STRIP_STORED);
        lp[0] = clean;
        fed_local_emit(s, ch, who, "PART", lp, 1);
    } else {
        fed_local_emit(s, ch, who, "PART", NULL, 0);
    }
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SPART", prefix,
                                       params, nparams, tags);
    (void)chan_dispose_if_empty(s, ch);
}

/* STOPIC: <member> <channel> <topic>. */
void fed_in_stopic(server_t *s, server_link_t *link, chan_t *ch,
                          const char *prefix, const irc_serve_tags_t *tags,
                          const char *const *params, int nparams)
{
    if (nparams != 3) {
        return;
    }
/* ------------------------------------------------------------------------
     * ONLY THE ORIGIN'S TOPIC IS TAKEN (#132), AND THE SUBJECT IS READ FROM
     * THE LINE RATHER THAN FROM THE SOCKET IT ARRIVED ON.
     * ------------------------------------------------------------------------
     *
     * WHAT WAS WRONG, and it was not a narrow edge case. The test was
     * `chan_same_name(link->name, ch->origin)`, and `link->name` is the server
     * THIS NODE IS SPEAKING TO -- the transport -- not the server whose opinion
     * the line carries. Those are the same name in one arrangement only:
     *
     *   - A client's TOPIC on the OWNING node is applied locally there and
     *     forwarded to every peer. Each peer receives it on a link named the
     *     origin, so the old test passed on a two-node mesh and looked right.
     *
     *   - A client's TOPIC on a NON-OWNING node is NOT applied locally: 2.2
     *     makes the topic cache, and chan_verbs.c's authority_ok() answers
     *     CHAN_VERDICT_FORWARD, so fanout.c forwards it to the origin. It arrives
     *     at the ORIGIN on a link named the NON-OWNER, and `ch->origin` is this
     *     node. The old test compared the sender against itself and said no. So
     *     the origin NEVER accepted a topic set by a client of a node it does not
     *     hold directly -- the one arrangement a federated network spends all
     *     its time in.
     *
     *   - Beyond two nodes the same false negative silences the relay hop: a
     *     node reachable only through a relay receives the origin's own topic
     *     over a link named the RELAY, drops it, and -- because the forward is
     *     below this `return` -- does not pass it on either, so the divergence is
     *     permanent for everything behind it.
     *
* THE TEST THAT REPLACES IT, and it is ONE test with two terms rather than two
     * tests, because the evidence about authority is the same in both
     * topologies and only the answer differs.
     *
     * THE EVIDENCE IS THE SUBJECT, and it is `tags.origin` -- 2.4's
     * `irc-serve-origin`, validated by irc_serve_tags_parse() in G4 and carried
     * through every relay hop unchanged except for the `hops` increment (see
     * fanout_stamp(), which mints an identity only for an ORIGINATING emission
     * and relays one otherwise). `tags.origin` is read here rather than
     * `link->name` for the whole of the reason above: the link is the transport
     * and the subject is who spoke.
     *
     * A SUBJECT IS ENTITLED TO THE TOPIC when it is either
     *
     *   (a) THE CHANNEL'S ORIGIN. 2.2 reserves `topic` to the origin, so the
     *       origin's own opinion is the authority at any distance -- this is the
     *       case a relay hop exists for, and it is the term that makes a
     *       three-node mesh converge.
     *
     *   (b) A SERVER THE CHANNEL'S ROSTER RECORDS AS HOLDING A MEMBER
     *       (`chan_server_has()` over `servers[]`). This is the case a
     *       non-owner forwards on a member's behalf, and it has to be allowed for
     *       a reason that is about the WIRE rather than about trust: the forward
     *       a non-owner sends to the origin carries the REQUESTING server's stamp,
     *       because `fanout_stamp()` treats the emission as a relay and relays an
     *       identity rather than re-minting one -- re-minting would be a lie about
     *       whose line this is, and would give the far side a dedup key it has
     *       never seen. So on the origin, the subject of a legitimate forwarded
     *       topic is the MEMBER-SERVER, never the origin, and a rule that accepted
     *       only term (a) would refuse every topic any client on a non-owning node
     *       has ever set. It is also the term that stops at the next hop being a
     *       member-server rather than the origin, which is what makes the onward
     *       emission from the origin applyable further along the mesh.
     *
     * WHY THAT SECOND TERM IS NOT A HOLE THIS CHANGE OPENS, because it looks
     * like one and the argument is worth having: 2.2's single-writer rule exists
     * to stop two nodes holding DIFFERENT values for one field. Every value that
     * reaches a cache under term (b) has already been accepted by the origin,
     * because a non-owner's forward goes to `ch->origin` and nowhere else
     * (fanout.c's `forward_channel_targets()` owned row), so the nodes agree by
     * construction. What an authenticated peer CAN do -- forge a topic to a
     * non-origin node naming a member-server as its subject -- is write one field
     * on one node until the origin's next statement or the next 4.3 resync, and
     * it costs a completed handshake and the shared secret to try. The cost of
     * NOT having term (b) is that no topic set by any client not directly
     * attached to the origin has ever taken effect anywhere, which is a mesh in
     * which the topic feature does not work at all. That is a worse trade, and it
     * is the trade the old condition made.
     *
     * WHAT THE REFUSAL LOGS. The old line printed `from=` and `origin=` and
     * nothing else, so the reader had to guess which of the two names in the
     * line was believed. `subject=` goes on the line beside them, and the reason
     * names which of the two terms failed.
     *
     * COST: one call to `chan_server_has()` per STOPIC -- a linear scan of a
     * bounded set of at most CHAN_MAX_MEMBER_SERVERS names -- plus one string
     * comparison against `ch->origin`. Nothing is allocated, no lock is taken,
     * and the scan is on the peer path for one verb rather than on any client's.
     */
    if (!chan_same_name(tags->origin, ch->origin) &&
        !chan_server_has(ch, tags->origin)) {
        fed_obs("[observable] fed_topic_ignored: channel=%s from=%s subject=%s "
                "origin=%s reason=NOT_THE_ORIGIN_OR_A_MEMBER_SERVER subject_len=%zu subject_bad_bytes=%zu\n",
                ch->name, link->name, tags->origin, ch->origin, strlen(tags->origin), conn_text_bad_count(tags->origin));
        return;
    }
    if (chan_set_topic(ch, params[2], params[0]) != 0) {
        fed_obs("[observable] fed_topic_ignored: channel=%s reason=too_long\n",
               ch->name);
        return;
    }
    fed_obs("[observable] fed_topic: channel=%s member=%s len=%zu\n", ch->name,
           params[0], strlen(ch->topic));
    /* ch->topic, NOT params[2]: the stored value is the stripped one, and the
     * local echo of a locally-set topic renders the same stored field. The
     * actor is the setter: the observed hostmask, else the roster record. */
    {
        char actor[CONN_HOSTMASK_MAX];
        const char *lp[1];
        const char *who = fed_actor_prefix(ch, params[0], prefix, 0, actor,
                                           sizeof actor);

        lp[0] = ch->topic;
        fed_local_emit(s, ch, who, "TOPIC", lp, 1);
    }
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "STOPIC", prefix,
                                       params, nparams, tags);
}

/* SMODES: <server> <channel> <modes> [<arg>]. */
void fed_in_smodes(server_t *s, server_link_t *link, chan_t *ch,
                          const char *prefix, const irc_serve_tags_t *tags,
                          const char *const *params, int nparams)
{
    if (nparams < 3 || nparams > 4) {
        return;
    }
    /* ------------------------------------------------------------------------
     * WHO IS ENTITLED TO SET A MODE, READ FROM THE LINE (#141), AND IT IS THE
     * SAME TWO TERMS `fed_in_stopic()` ASKS (#132).
     * ------------------------------------------------------------------------
     *
     * WHAT WAS WRONG. The test was `chan_same_name(params[0], ch->origin)` alone --
     * "the evaluating server is the origin" -- and `MODE #chan +b mask` is one of the
     * three fields 2.2 reserves to the origin, so a ban set by an operator on a node
     * that does not own the channel never took effect anywhere. It is #132's defect
     * in the opposite half: there, a field that does not carry the authority was
     * read as if it did; here, the field that DOES carry the authority was read as
     * the whole of it.
     *
     * THE SUBJECT IS `params[0]`, and the reason is the one the issue asked about:
     * 4.3's frozen SMODES shape DOES carry the evaluating server, unlike STOPIC,
     * and that makes the fix simpler than #132's in one way and exposes a different
     * question in another.
     *
     * SIMPLER, because there is no transport standing in for the subject. STOPIC had
     * to read `tags->origin`, the 2.4 stamp, because the line carries no field naming
     * who acted and `link->name` -- the socket -- was the only other candidate and
     * was wrong. SMODES carries the answer in its own first parameter, which is what
     * the field is FOR, so the test reads the line rather than the wire.
     *
     * AND THAT EXPOSES THE QUESTION #132 HAD TO ANSWER BY ARGUMENT: a subject is
     * entitled when it is
     *
     *   (a) THE CHANNEL'S ORIGIN. 2.2 reserves the three mask modes to the origin,
     *       so the origin's own opinion is the authority at any distance -- the case a
     *       relay hop exists for.
     *
     *   (b) A SERVER THE ROSTER RECORDS AS HOLDING A MEMBER
     *       (`chan_server_has()`). This is the case a non-owner forwards in, and it
     *       is the term that was missing. `fed_sverb_params()` stamps
     *       `params[0] = self`, so a non-owner forwarding a member's `+b` names
     *       ITSELF, and the origin compared that against itself and said no.
     *
     * TERM (b) IS NOT A HOLE, for #132's reason and because the argument is the
     * same one: every value that reaches a cache under (b) has already been accepted
     * by the origin, because a non-owner's forward goes to `ch->origin` and nowhere
     * else (fanout.c's owned row), so the nodes agree by construction. What an
     * authenticated peer can do -- forge an SMODES naming a member-server as its
     * subject -- is write one mode letter on one node until the origin's next
     * statement or the next 4.3 resync, at the cost of a completed handshake and the
     * shared secret. The cost of NOT having (b) is that no `MODE +b` set by any
     * operator on any node but the origin's has ever taken effect anywhere, which is
     * the trade the old condition made and the one #141 exists to reverse.
     *
     * COST: one `chan_server_has()` per SMODES -- a linear scan of a bounded set of
     * at most CHAN_MAX_MEMBER_SERVERS names -- plus one comparison against
     * `ch->origin`. Nothing allocated, no lock, and it is on the peer path for one
     * verb rather than on any client's. */
    if (!chan_same_name(params[0], ch->origin) &&
        !chan_server_has(ch, params[0])) {
        char subj[CONN_LOG_FIELD_MAX + 1u];

        /* THE SUBJECT IS A PEER-CHOSEN STRING AND IT IS PRINTED MEASURED. `by=`
         * below has always printed this field raw, and `params[0]` is on
         * check-peer-log-sites.py's allowlist -- for the SQUIT `<server>`, which this
         * node builds from its own name and which therefore cannot carry a byte a
         * peer chose. SMODES' first field is not that field: it is whatever the peer
         * put in the `<server>` slot, and nothing between the socket and this printf
         * has looked at it. A peer that sends `SMODES <ESC>[2J #chan +o carol` puts
         * a CSI sequence in an operator's terminal, which is the whole of #135's log
         * half in a verb the sweep's SMODES row never puts its marker in. So both
         * lines go through `conn_text_logsafe()` and carry the count beside them,
         * which is connection.h's Rule 1 and what every other peer-chosen field on
         * this node does. */
        (void)conn_text_logsafe(subj, sizeof subj, params[0]);
        fed_obs("[observable] fed_modes_ignored: channel=%s from=%s subject=%s "
                "subject_len=%zu subject_bad_bytes=%zu origin=%s "
                "reason=NOT_THE_ORIGIN_OR_A_MEMBER_SERVER\n",
                ch->name, link->name, subj, strlen(params[0]),
                conn_text_bad_count(params[0]), ch->origin);
        return;
    }
    /* THE MODE STRING IS WALKED TWICE AND THAT IS NOT REDUNDANT.
     *
     * ONCE TO DECIDE, and the decision is `chan_mode_implemented()` -- the SAME
     * predicate the client `MODE` path asks, which answers 472 for a letter this node
     * does not evaluate. That predicate is the whole of this handler's change: before
     * it, this loop called `chan_mode_set()` on every byte that was not a sign, so a
     * peer could put a control byte into `ch->modes[]` and have it reach 324, the
     * SBURST shadow and every other node on the mesh. The client's rule was always
     * "reject a mode letter you do not implement" and the peer's was nothing, and an
     * inconsistency between two paths is not fixed by describing it.
     *
     * ONCE TO APPLY, and only over the letters that passed. Applying in the same pass
     * would have meant a mode string whose FOURTH letter is unimplemented had already
     * written its first three into the cache before the refusal -- and a partial
     * application is harder to reason about than either applying or refusing, because
     * the peer's next SMODES would have to mean "and also this".
     *
     * WHAT IS FORWARDED. The forward below carries `params` unchanged, so an
     * unimplemented letter still reaches the NEXT node -- which is correct, because
     * this node's opinion about which modes exist is not the next node's, and 4.3's
     * shape has no room for a per-node verdict. What does not happen is this node
     * STORING it, which is the part that was a hazard. */
    {
        char applied[CHAN_MAX_MODES + 1u];
        char refused[CHAN_MAX_MODES + 1u];
        size_t napplied = 0u;
        size_t nrefused = 0u;
        int on = 1;
        char shown[CONN_LOG_FIELD_MAX + 1u];
        /* The `<server>` field, measured ONCE and printed through one buffer, for the
         * reason the refusal line above gives: `params[0]` is a peer-chosen string and
         * `check-peer-log-sites.py` allowlists it for the SQUIT field, which is a
         * different field with a different provenance. Four sites below print it, so
         * four copies of that reasoning would be four places to forget one. */
        char shown_by[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown_by, sizeof shown_by, params[0]);
        applied[0] = '\0';
        refused[0] = '\0';
        for (size_t i = 0; params[2][i] != '\0'; i++) {
            const char m = params[2][i];
            int verdict;

            if (m == '+' || m == '-') {
                on = (m == '+');
                continue; /* the sign, not a mode */
            }
            verdict = chan_mode_implemented(m);
            if (verdict == 0) {
                /* NAMED BY BYTE, IN HEX, and that is the whole diagnostic. The letter
                 * itself is the peer's byte and cannot be printed: a peer's mode
                 * string is unvalidated text and this is an operator's terminal, which
                 * is the same reason every other log-only client or peer field on this
                 * node goes through conn_text_logsafe(). */
                if (nrefused + 3u < sizeof refused) {
                    (void)snprintf(refused + nrefused, sizeof refused - nrefused,
                                   "%02x", (unsigned char)m);
                    nrefused += 2u;
                }
                continue;
            }
            if ((m == 'o' || m == 'v') && nparams == 4 && params[3][0] != '\0') {
                /* A prefix mode names a MEMBER, not a channel property (#606):
                 * without this a peer's `SMODES +o nick` fell through to
                 * chan_mode_set() and cached `o` in ch->modes[] -- visible in
                 * 324, invisible in 353. The origin already applied this to its
                 * own roster; here the cache converges: a local member takes it
                 * through chan_set_member_flags(), a roster entry in place. */
                struct member *tm = chan_find_nick(ch, params[3]);
                unsigned flag = (m == 'o') ? CHAN_MEMBER_OP : CHAN_MEMBER_VOICE;

                if (tm != NULL && tm->c != NULL) {
                    (void)chan_set_member_flags(ch, tm->c, on, flag);
                } else {
                    for (size_t k = 0; k < ch->nremotes; k++) {
                        if (!chan_same_name(ch->remotes[k].nick, params[3])) {
                            continue;
                        }
                        if (on) {
                            ch->remotes[k].flags |= flag;
                        } else {
                            ch->remotes[k].flags &= ~flag;
                        }
                        break;
                    }
                }
                if (napplied + 1u < sizeof applied) {
                    applied[napplied++] = m;
                    applied[napplied] = '\0';
                }
                continue;
            }
            if (chan_mode_set(ch, m, on) > 0 && napplied + 1u < sizeof applied) {
                applied[napplied++] = m;
                applied[napplied] = '\0';
            }
            /* ----------------------------------------------------------------
             * THE BAN LIST, AND ONLY WHERE 2.2 SAYS IT LIVES.
             * ----------------------------------------------------------------
             *
             * WITHOUT THIS the fix above is cosmetic. `+b` is a MASK mode: 2.2
             * gives the origin a ban LIST, not a letter in `ch->modes[]`, and
             * `chan_mode_set()` writes the letter. So with the entitlement test
             * widened and nothing else changed, a non-owner's operator's `+b` would
             * set a letter on the origin's cache and the origin's ban list would
             * still be empty -- which is not a ban, and 367 would tell the origin's
             * own clients there is none.
             *
             * WHY ONLY WHEN THIS NODE IS THE ORIGIN. A cache records the letter and
             * nothing more: `modes[]` is what a non-owner is entitled to hold, and a
             * node that enforced a ban out of its own cache would be applying a state
             * change 2.2 reserves to the origin -- the same local-write the
             * forward arm above refuses to do. The mask is still forwarded below, so
             * every cache converges on the origin's list rather than deriving one.
             *
             * THE MASK IS THE FOURTH PARAMETER, `params[3]`, and its absence is
             * ordinary rather than an error: `SMODES +b` with no argument is a
             * letter change on a channel that has bans, which is legal and is what
             * `ch->modes[]` alone can express. So a missing or empty mask applies the
             * letter and touches no list, and the refusal below is the one the
             * client path already answers with 478/461/417.
             *
             * COST: one `chan_origin_is_self()` per SMODES and, at the origin, one
             * bounded copy plus one list operation for a `+b`/`-b`. */
            if (m == 'b') {
                const char *mask = (nparams == 4) ? params[3] : NULL;

                if (mask != NULL && mask[0] != '\0' &&
                    !chan_origin_is_self(s, ch)) {
                    /* A CACHE, AND IT IS WORTH SAYING SO OUT LOUD. This is the
                     * single place the ban-list policy is decided, and the decision
                     * has a half that produces no observable at all: a cache that
                     * correctly declines to enforce a ban is indistinguishable from a
                     * cache that never received one. So the refusal is recorded, with
                     * the mask measured, rather than left as the absence of a line.
                     *
                     * It is one line per `+b`/`-b` a cache is told about, which is a
                     * mode change rather than a message, so the rate is the mesh's mode
                     * rate and not anything higher. */
                    char shown_mask[CONN_LOG_FIELD_MAX + 1u];

                    (void)conn_text_logsafe(shown_mask, sizeof shown_mask, mask);
                    fed_obs("[observable] fed_modes_ban_cached: channel=%s "
                            "subject=%s mask=%s mask_len=%zu mask_bad_bytes=%zu "
                            "on=%d origin=%s subject_len=%zu subject_bad_bytes=%zu\n",
                            ch->name, shown_by, shown_mask, strlen(mask),
                            conn_text_bad_count(mask), on, ch->origin, strlen(shown_by), conn_text_bad_count(shown_by));
                } else if (mask != NULL && mask[0] != '\0') {
                    char clean[CHAN_MAX_BAN + 1u];
                    const char *effective = mask;
                    size_t mask_kept = 0;

                    if (strlen(mask) <= (size_t)CHAN_MAX_BAN) {
                        mask_kept = conn_text_strip(clean, sizeof clean, mask, STRIP_STORED);
                        effective = clean;
                    }
                    /* The raw length binds, exactly as the client path's does: a
                     * mask the origin would refuse must not become one this node
                     * shortened into its bound. */
                    if (strlen(mask) > (size_t)CHAN_MAX_BAN) {
                        fed_obs("[observable] fed_modes_ban_ignored: channel=%s "
                                "subject=%s reason=MASK_TOO_LONG len=%zu subject_len=%zu "
                                "subject_bad_bytes=%zu\n",
                                ch->name, shown_by, strlen(mask), strlen(params[0]),
                                conn_text_bad_count(params[0]));
                    } else if (on) {
                        const chan_ban_verdict_t bv = chan_ban_add(ch, effective);

                        if (bv != CHAN_BAN_OK) {
                            fed_obs("[observable] fed_modes_ban_ignored: "
                                    "channel=%s subject=%s verdict=%d subject_len=%zu "
                                    "subject_bad_bytes=%zu\n", ch->name, shown_by, (int)bv,
                                    strlen(params[0]), conn_text_bad_count(params[0]));
                        } else if (mask_kept != strlen(mask)) {
                            fed_obs("[observable] fed_modes_ban_mask_stripped: "
                                    "channel=%s subject=%s in_len=%zu kept_len=%zu subject_len=%zu "
                                    "subject_bad_bytes=%zu\n", ch->name, shown_by,
                                    strlen(mask), mask_kept, strlen(params[0]),
                                    conn_text_bad_count(params[0]));
                        }
                    } else if (chan_ban_remove(ch, effective) == 0) {
                        fed_obs("[observable] fed_modes_ban_ignored: channel=%s "
                                "subject=%s reason=NOT_BANNED subject_len=%zu "
                                "subject_bad_bytes=%zu\n", ch->name, shown_by,
                                strlen(params[0]), conn_text_bad_count(params[0]));
                    }
                }
            }
        }
        /* MEASURED, NOT PRINTED: `modes=` is the peer's own string and the line's
         * subject is what an operator needs to see. `refused=` is the hex list above,
         * which is a rendering of the same value that cannot be executed. */
        (void)conn_text_logsafe(shown, sizeof shown, params[2]);
        fed_obs("[observable] fed_modes: channel=%s by=%s by_len=%zu "
               "by_bad_bytes=%zu modes=%s modes_len=%zu "
               "modes_bad_bytes=%zu applied=%s refused=%s cached=%s cached_len=%zu cached_bad_bytes=%zu\n",
               ch->name, shown_by, strlen(params[0]),
               conn_text_bad_count(params[0]), shown, strlen(params[2]),
               conn_text_bad_count(params[2]),
               (applied[0] != '\0') ? applied : "-",
               (refused[0] != '\0') ? refused : "-", ch->modes, strlen(ch->modes), conn_text_bad_count(ch->modes));
    }
    /* The MODE this node's own clients see: the mode string and the optional
     * mask, stripped the way the stored values are. Both are peer-chosen, and
     * the client line is a second reader the forward path's filter does not
     * cover -- a control byte in either would otherwise reach a terminal.
     * The actor has no nick to look up -- the subject IS the evaluating
     * server, authority-checked above -- so a hostmask prefix renders as-is
     * and anything else renders as the subject server itself. That is the
     * server speaking, not a user actor, which is why a server name is
     * renderable HERE and nowhere else on this path. */
    {
        char actor[CONN_HOSTMASK_MAX];
        char clean_modes[CHAN_MAX_MODES + 1u];
        char clean_mask[CHAN_MAX_BAN + 1u];
        const char *lp[2];
        const char *who;
        int nlp = 1;

        (void)conn_text_strip(clean_modes, sizeof clean_modes, params[2],
                              STRIP_STORED);
        lp[0] = clean_modes;
        if (nparams > 3) {
            (void)conn_text_strip(clean_mask, sizeof clean_mask, params[3],
                                  STRIP_STORED);
            lp[1] = clean_mask;
            nlp = 2;
        }
        who = fed_actor_prefix(ch, NULL, prefix, 1, actor, sizeof actor);
        fed_local_emit(s, ch, (who != NULL) ? who : params[0], "MODE", lp,
                       nlp);
    }
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SMODES", prefix,
                                       params, nparams, tags);
}

/* SKICK: <member> <channel> <target> [<reason>].
 *
 * ---------------------------------------------------------------------------
 * WHY BOTH PRINTED FIELDS ARE MEASURED, AND IT IS NOT THE INJECTION
 * ---------------------------------------------------------------------------
 * `fed_obs()` withholds a value holding a byte in the strip set, so this line was
 * never an injection: `conn_text_logsafe()` runs on every `%s` it renders, and a peer
 * that sent `SKICK <ESC>[2J ...` printed `by=-` rather than a CSI sequence in an
 * operator's terminal. What it WAS is a line that cannot be read. `by=-` means two
 * different things -- "the peer sent nothing" and "the peer sent something this node
 * would not print" -- and the line carried no length and no bad-byte count to tell
 * them apart, so the one an operator actually needs (a peer sending bytes it should
 * not) is indistinguishable from a peer with nothing to say.
 *
 * `fed_in_smodes()` prints `subject_len=` and `subject_bad_bytes=` beside the same
 * kind of field for the same reason, and this line is the one that was left out. The
 * convention is now uniform for the two verbs whose `<member>`/`<server>` fields are
 * peer-chosen, and tests/integration/test_fed_skick_log.c asserts the measurement is
 * present -- a `fed_skick:` line with no `by_len=` is a failure, not a shorter line.
 *
 * MEASURED RATHER THAN STRIPPED, and the reason is that this is a LOG: nothing
 * downstream reads it, so the bytes were already withheld by `fed_obs()` and the
 * measurement is what an operator is left with. It costs two walks of a bounded
 * peer-supplied string (`conn_text_logsafe()` and `strlen()`) plus one of the same
 * length inside `conn_text_bad_count()`, on a path that runs once per SKICK rather
 * than once per packet.
 *
 * WHAT THIS DOES NOT CLAIM: that `<member>` and `<target>` are STORED safely, and
 * they are not read as safe by anything here. `chan_remote_remove()` is handed
 * `params[2]` and looks it up in a roster; it stores nothing. The reason at
 * connection.h's policy table -- a field that is stored goes through its own policy,
 * a field that is only logged goes through this one -- is the whole reason the two
 * are separate decisions, and naming it here is what stops a reader from taking the
 * measurement as a sanitiser. */
void fed_in_skick(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    char shown_by[CONN_LOG_FIELD_MAX + 1u];
    char shown_target[CONN_LOG_FIELD_MAX + 1u];

    if (nparams < 3 || nparams > 4) {
        return;
    }
    (void)conn_text_logsafe(shown_by, sizeof shown_by, params[0]);
    (void)conn_text_logsafe(shown_target, sizeof shown_target, params[2]);
    (void)chan_remote_remove(ch, link->name, params[2]);
    fed_touch_server(ch, link->name, 0);
    fed_obs("[observable] fed_skick: channel=%s by=%s by_len=%zu by_bad_bytes=%zu "
            "target=%s target_len=%zu target_bad_bytes=%zu\n",
            ch->name, shown_by, strlen(params[0]), conn_text_bad_count(params[0]),
            shown_target, strlen(params[2]), conn_text_bad_count(params[2]));
    /* The KICK this node's own clients see: target, then the reason stripped
     * the way the local KICK path strips it. The actor is the kicker: the
     * observed hostmask, else the kicker's roster record. Removal above took
     * the TARGET, so the kicker's record is still here to render from. */
    {
        char actor[CONN_HOSTMASK_MAX];
        const char *who = fed_actor_prefix(ch, params[0], prefix, 0, actor,
                                           sizeof actor);

        if (nparams > 3) {
            char clean[CHAN_MAX_KICK_REASON + 1u];
            const char *lp[2];

            (void)conn_text_strip(clean, sizeof clean, params[3],
                                  STRIP_STORED);
            lp[0] = params[2];
            lp[1] = clean;
            fed_local_emit(s, ch, who, "KICK", lp, 2);
        } else {
            fed_local_emit(s, ch, who, "KICK", &params[2], 1);
        }
    }
    /* The victim may be LOCAL here (#606): a KICK names a member of the
     * channel, and on the victim's own node that member is a conn, not a
     * roster entry, so the remote removal above missed it. AFTER the emit --
     * the victim has to see the KICK -- and before the forward, mirroring the
     * local KICK path's remove-then-detach (which keeps teardown from removing
     * it twice). A SKICK for a nick this node does not hold is a no-op. */
    {
        struct member *victim = chan_find_nick(ch, params[2]);

        if (victim != NULL && victim->c != NULL) {
            conn_t *vc = victim->c;

            (void)chan_remove_member(ch, vc);
            (void)chan_detach_conn(vc, ch);
        }
    }
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SKICK", prefix,
                                       params, nparams, tags);
    (void)chan_dispose_if_empty(s, ch);
}

/* One QUIT per local member per departed member, and it is shared because the
 * two graceful departures end the same way. A SQUIT names a server whose
 * every member is gone; a SHUTDOWN names the peer itself, which this node
 * then relays onward as SQUIT -- and on a two-node mesh that relay has no
 * audience, so without this call a graceful leave renders nothing anywhere.
 * Call BEFORE the purge: this is the only point the names are still known,
 * and the channels themselves may be disposed in the walk, so a line for a
 * member of a channel about to vanish still reaches the members who stay.
 * The prefix is the stored hostmask where the burst path described the
 * member, else the bare nick -- the same rule 353 renders by, and for the
 * same reason. `reason` is the peer's own and is stripped once, outside the
 * walk: one reason for every channel, and the client line is a reader the
 * forward path's filter does not cover. NULL reason renders a bare QUIT. */
static void fed_emit_departure_quits(server_t *s, const char *gone,
                                     const char *reason)
{
    char clean_reason[IRC_MAX_LINE];
    const char *qp[1] = { NULL };
    int nqp = 0;

    if (s == NULL || gone == NULL) {
        return;
    }
    if (reason != NULL) {
        (void)conn_text_strip(clean_reason, sizeof clean_reason, reason,
                              STRIP_STORED);
        qp[0] = clean_reason;
        nqp = 1;
    }
    for (size_t ci = 0, nch = server_chan_count(s); ci < nch; ci++) {
        chan_t *qch = server_chan_at(s, ci);

        if (qch == NULL) {
            continue;
        }
        for (size_t r = 0; r < qch->nremotes; r++) {
            const chan_remote_t *m = &qch->remotes[r];
            char mask[CONN_HOSTMASK_MAX];

            if (!chan_same_name(m->server, gone)) {
                continue;
            }
            if (m->user[0] != '\0' && m->host[0] != '\0') {
                (void)snprintf(mask, sizeof mask, "%s!%s@%s", m->nick,
                               m->user, m->host);
            } else {
                (void)snprintf(mask, sizeof mask, "%s", m->nick);
            }
            fed_local_emit(s, qch, mask, "QUIT", qp, nqp);
        }
    }
}

/* ---------------------------------------------------------------------------
 * SQUIT: <server> [<reason>]
 * ---------------------------------------------------------------------------
 * "That server is gone; forget everything you learned through it."
 *
 * WHY IT IS NOT A ROW IN INBOUND, and the answer is the same one the burst family
 * gets at G8 with one difference in the reasoning. Every INBOUND row describes a
 * line ABOUT A CHANNEL, at a parameter position the verb fixes, and the
 * dispatch reads the channel out of that position -- position 0 for SJOIN, 1 for
 * the rest. A SQUIT names no channel at all, and a row for it would have to lie
 * about that. The burst family is the other shape the table cannot hold, and it
 * is asked separately for the same structural reason.
 *
 * IT IS NOT THE BURST CASE EITHER, and that is the part worth stating because a
 * reader who has just read case E will assume the resemblance is deliberate. Case
 * E refuses an UNTAGGED burst because case A would mint a fresh identity PER
 * LINE for it, and a burst is O(n) lines forming one transaction -- so a peer
 * could replace this node's entire view of an origin, as often as it liked, on
 * lines whose 2.4 identity this node invented. A SQUIT is ONE line destroying
 * ONE origin's state, and the authority to do that is the authority the peer
 * already has: any peer may report a roster, and may report a smaller one. So a
 * SQUIT is allowed the same untagged-originated treatment as any other state
 * change, and it is a RELAYED one that is refused (case B), because a claim that
 * somebody ELSE is gone is a claim about a third party's memory. No case of its
 * own, and the chain is unchanged above this point -- which is the point: a
 * SQUIT is deduplicated, hop-checked and own-origin-checked like every other
 * state-destroying line, and a REPLAYED SQUIT is refused by G7 rather than
 * purging twice.
 *
 * 3.1: it is a state change, so it is applied to this node's cache and FORWARDED
 * onward, exactly as the table's rows are. See the forwarding note at the end of
 * the function for what "onward" means when the subject of the change is a server
 * rather than a channel.
 */
void fed_in_squit(server_t *s, server_link_t *link,
                         const irc_serve_tags_t *tags, const char *const *params,
                         int nparams)
{
    const char *gone;
    size_t purged = 0;
    size_t chans = 0;
    size_t i = 0;

    if (s == NULL || params == NULL) {
        return;
    }
    /* Arity here rather than in G9's table, for the reason the burst verbs give:
     * this shape is not a table row, so there is no row to hold its bounds. One
     * or two -- the reason is the OPTIONAL trailing parameter SPART and SKICK
     * also carry, and it is never acted on. A line with any other count is a peer
     * running a different format and is refused rather than guessed at. */
    if (nparams < 1 || nparams > 2) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: command=SQUIT field=arity nparams=%d "
               "want=1..2\n",
               nparams);
        /* Same as SHUTDOWN's ARITY arm above: the line is refused AND the link
         * that carried it goes down, or a departed peer haunts the roster. */
        if (link != NULL) {
            conn_t *c = server_link_conn(s, link);

            if (c != NULL) {
                conn_mark_closing(c);
            }
        }
        return;
    }
    gone = params[0];

    /* A SQUIT NAMES THIS NODE, and it is REFUSED, and the link is NOT torn down.
     *
     * This is the one line a peer can send that, taken literally, would have a
     * listening node delete itself from the mesh, and 2.3's uniqueness rule is
     * what makes it worse than a nuisance: 2.3 calls two nodes with one name
     * "catastrophic and undetectable later", and a peer announcing that name is
     * the announcement a re-joining node would act on. So the claim is refused on
     * the only evidence available -- this node is here, and it is answering --
     * and the LINK SURVIVES, because a peer sending this is either broken or
     * hostile and neither of those is a reason to hang up on a peer that is
     * otherwise the only route to half the network.
     *
     * It is counted separately from n_fed_malformed because the two say opposite
     * things to an operator: a malformed line is a peer that does not implement
     * 4.3, and this is a peer that implements 4.3 and is telling this node it no
     * longer exists. The first is a version fact and the second is a finding. */
    if (chan_same_name(gone, s->name)) {
        s->n_fed_squit_self++;
        fed_obs("[observable] fed_squit_refused: fd=%d peer=%s server=%s self=%s "
               "reason=SELF_NOT_GONE server_len=%zu server_bad_bytes=%zu\n",
               (link != NULL) ? link->fd : -1, (link != NULL) ? link->name : "?",
               gone, s->name, strlen(gone), conn_text_bad_count(gone));
        return;
    }

    /* THE PURGE, AND IT IS PER ORIGIN. Everything this node learned THROUGH the
     * departed server goes, and nothing else does: chan_remote_purge() is keyed
     * by the reporting origin -- the same key SBURSTM's records are installed
     * under, which federation/burst.c's install step states -- so a member that
     * arrived from some other server is untouched.
     *
     * THE GLOBAL WIPE IS THE BUG THIS SHAPE IS SHAPED AGAINST, and it is worth
     * naming because it is the obvious shortcut: "a server is gone, drop the
     * rosters" reads as one loop with no key, and it destroys every other
     * origin's members on this node in the same pass. On a two-node mesh the two
     * are indistinguishable, which is exactly why tests/integration/
     * test_fed_resync.c gives the receiving node two origins over two different
     * links.
     *
     * servers[] LOSES THE NAME, unlike a link that merely went down (2.2's
     * fail-closed note, and fed_link_down()'s neighbours): a SQUIT is positive
     * evidence that the server is gone rather than a socket this node cannot
     * reach, so keeping the name would keep a channel alive for the rest of the
     * process for a server that has said it is finished. The two cases are
     * different facts and are treated differently on purpose.
     *
     * THE WALK DOES NOT ADVANCE PAST A DISPOSED CHANNEL, and the reason is
     * server_chan_detach()'s: it shifts the array down, so an index that is
     * incremented after a removal skips the channel that moved into the hole --
     * silently, and a channel that silently survives a purge is a roster the
     * operator is told is gone. chan_remote_purge() walks the same way for the
     * same reason. */
    /* The QUIT each remaining local member sees: one per departed member, via
     * the shared departure helper, BEFORE the purge below. */
    fed_emit_departure_quits(s, gone, (nparams > 1) ? params[1] : NULL);
    while (i < server_chan_count(s)) {
        chan_t *ch = server_chan_at(s, i);
        int disposed;

        if (ch == NULL) {
            i++;
            continue;
        }
        purged += chan_remote_purge(ch, gone);
        if (chan_server_remove(ch, gone) > 0) {
            chans++;
        }
        /* The same disposition the burst's replace arm does: a channel left with
         * no local member and no member-server has nothing left to remember, and
         * holding it for the life of the process is a channel LIST reports and
         * NAMES answers for, forever. One this node still holds members in is
         * kept, which is 2.2's locally-orphaned case: the members still see each
         * other and origin-requiring actions are refused with 437. */
        disposed = chan_dispose_if_empty(s, ch);
        if (disposed == 0) {
            i++;
        }
    }
    /* 2.1's REGISTRY PURGE, and it is here for the reason the roster purge is
     * here and not in chan_remote_purge(): a SQUIT is positive evidence that
     * every user of that server is gone, and a registry entry left behind
     * would be one more claim about a server that announced its own
     * departure. It is a separate call rather than a side effect of the
     * roster purge because the two tables are keyed by different things --
     * (server, nick) versus (nick, server) -- and only the caller knows
     * which one a given line is about. */
    fed_nickreg_purge_server(s, gone);
    fed_obs("[observable] fed_squit: server=%s chans=%zu purged=%zu remote=%zu server_len=%zu server_bad_bytes=%zu\n", gone,
           chans, purged, (size_t)server_chan_count(s), strlen(gone), conn_text_bad_count(gone));

    /* 3.1's non-owner row: apply here, forward onward. "Onward" for a
     * server-scoped state change is the OTHER ESTABLISHED LINKS, and the two
     * exclusions are the whole of the rule:
     *
     *   - the link it arrived on, because it came from there. Forwarding it back
     *     is 2.4's never-forward-own-origin rule in the only shape that applies
     *     here: the sender already has it.
     *   - a link whose name IS the departed server, because that node is by
     *     definition not gone and the line would arrive there as a SQUIT naming
     *     itself, which the arm above refuses. Skipping it saves a line and does
     *     not change any outcome.
     *
     * THE COST, because a reader deserves it: this is a broadcast, and it is
     * bounded by 2.4 rather than by the hop ceiling alone. A node two hops away
     * receives the same (origin, epoch, id) by two paths, and the per-node dedup
     * store drops the second; a node three hops away never receives it at all,
     * because the ceiling is ten hops and a full mesh is two. So on a large mesh
     * the announcement reaches a bounded neighbourhood rather than the whole
     * network, and what it does not reach is corrected by the next burst -- which
     * is Phase 9's to drive, and is stated rather than relied on here. */
    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *lk = server_link_at(s, k);

        if (lk == NULL || lk == link || lk->state != (int)ESTABLISHED ||
            chan_same_name(lk->name, gone)) {
            continue;
        }
        (void)fanout_forward_sverb(s, lk->name, "SQUIT", NULL, params, nparams, tags);
    }
}
