/* tick.c -- see federation/link.h. The link tick and its dial/retry arms.
 *
 * Split verbatim out of link.c (issue #543 TU-26): the dial lookup, the
 * reconnect schedule, the dial-expiry/promotion/keepalive/dead arms and
 * fed_tick() itself. The FEDERATE exchange (fed_queue_federate/fed_refuse/
 * fed_link_of_conn) stays in link.c and is reached through link.h.
 */
#include "federation/link.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/poll_loop.h"
#include "core/transport.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/departure.h"
#include <arpa/inet.h>
#include <netinet/in.h>

#include "federation/nickreg.h"
#include "federation/verbs.h"

/* ---------------------------------------------------------------------------
 * The tick
 * ---------------------------------------------------------------------------
 */

/* The live dial for a peer name, or NULL. Read out of server_t::dials directly
 * rather than through an accessor, and the reason is that there is none: the
 * three functions server.h offers for the dial table (collect, progress, count)
 * are the ones the LOOP needs, and the one thing this file needs -- "has a
 * dial for this peer, and what state is it in" -- has no entry point. Adding
 * one is a change to core/server.h for a single caller; reading the POD the
 * struct already exposes is not. s->dials is a public field precisely because
 * the layout is part of server.h's contract. */
static dial_t *fed_dial_for(server_t *s, const char *peer_name)
{
    size_t i;

    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state == DIAL_CONNECTING ||
            s->dials[i].state == DIAL_CONNECTED) {
            if (irc_ascii_same(s->dials[i].peer_name, peer_name)) {
                return &s->dials[i];
            }
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * THE RECONNECT SCHEDULE
 * ---------------------------------------------------------------------------
 * Three questions, one function, and the reason they are a function rather than
 * three comparisons at three call sites is the reason EVERY refusal in this file
 * goes through one place: the counter, the next attempt's stamp, and the "this
 * node has stopped trying" report are three numbers that must agree, and three
 * call sites are three chances for them to disagree.
 *
 * `why` is a short stable token naming the failure that armed the schedule, and
 * it is on the observable line because the operator's question is "why is it
 * trying again" and the answer is which arm fired.
 *
 * THE BUDGET IS CHECKED FIRST AND IS NOT REARMED, and that ordering is the whole
 * of "a node that retries forever is a leak": once the budget is spent the
 * schedule is left where it was and `gave_up` is set, so T7's condition is false
 * for the rest of the process. Nothing wakes it and nothing clears it but
 * fed_link_reset().
 */
static void fed_retry_arm(server_t *s, server_link_t *link, uint64_t now_ms,
                          const char *why)
{
    uint64_t delay;
    unsigned step;

    if (s == NULL || link == NULL) {
        return;
    }
    if (link->gave_up != 0) {
        /* Already spent, and NOT re-reported. The exhaustion is reported once at
         * the moment it happens; a line per tick for a link that will never be
         * dialled again would be a log that fills up at 20 lines per second on
         * a node with a dead peer, which is the opposite of reporting. */
        return;
    }
    /* ALREADY SCHEDULED, AND THAT IS NOT A NO-OP WORTH SKIPPING SILENTLY. The
     * ladder is armed by several arms of the tick and a single failure can reach
     * two of them -- a peer that is down produces a dial that completes and a
     * handshake that then times out, and a peer that is unreachable produces a
     * dial that is retired by T1 on one tick and observed by the DIAL_FAILED arm
     * on the next. Arming twice for one failure would double the wait and spend
     * two of a three-attempt budget on one dead peer.
     *
     * The test is "a schedule is already running", which is `retry_at_ms` in the
     * future -- NOT "retry_at_ms is non-zero", because a link whose last schedule
     * has EXPIRED also has a non-zero stamp and is exactly the link that needs
     * re-arming. Getting that backwards would make a link that had exhausted its
     * ladder refuse to arm again, which is the opposite of the intent. */
    if (link->retry_at_ms > now_ms) {
        return;
    }
    if (link->retries >= s->fed_retry_budget) {
        link->gave_up = 1;
        s->n_fed_retry_exhausted++;
        printf("[observable] link_retry_exhausted: peer=%s attempts=%u budget=%u "
               "reason=AFTER_%s\n",
               link->name, link->retries, s->fed_retry_budget, (why != NULL) ? why : "?");
        return;
    }

    /* THE LADDER: the base doubled once per attempt already made, capped at the
     * ceiling. The shift is bounded by the step constant rather than by
     * `retries`, so a link that somehow accumulated a large retry count cannot
     * shift an integer out of its own width -- which is a real hazard and not a
     * theoretical one, because `retries` counts events a peer can drive by
     * refusing a handshake. */
    step = link->retries;
    if (step >= (unsigned)IRC_FED_RETRY_MAX_STEPS) {
        step = (unsigned)IRC_FED_RETRY_MAX_STEPS;
    }
    delay = s->fed_retry_base_ms * ((uint64_t)1u << step);
    if (delay > s->fed_retry_max_ms) {
        delay = s->fed_retry_max_ms;
    }
    link->retries++;
    link->retry_at_ms = now_ms + delay;
    printf("[observable] link_retry: peer=%s attempt=%u/%u delay_ms=%llu after=%s\n",
           link->name, link->retries, s->fed_retry_budget,
           (unsigned long long)delay, (why != NULL) ? why : "?");
}

/* T1. A connect() that poll() will never report on.
 *
 * The one close() in this file, and it closes a DIAL rather than a connection:
 * a DIAL_CONNECTING descriptor is not in by_fd and has no conn_t, so the reaper
 * has nothing to reap and no other code path can close it. server.c already
 * closes exactly these descriptors on the same grounds (a DIAL_FAILED arm in
 * server_dial_progress(), and the shutdown walk), so this is the third of the
 * three places that may close a socket which never became a connection and the
 * first that is not in server.c.
 *
 * The stamp is dial_t::started_ms and it was taken at the connect() rather
 * than by a later tick precisely so that this deadline is a property of the
 * connect and not of the loop's cadence. */
static void fed_dial_expired(server_t *s, size_t i, uint64_t now_ms)
{
    uint64_t waited = now_ms - s->dials[i].started_ms;
    char peer[IRC_MAX_SERVER_NAME + 1];

    memcpy(peer, s->dials[i].peer_name, strlen(s->dials[i].peer_name) + 1u);
    printf("[observable] dial_timeout: peer=%s ms=%llu\n", peer,
           (unsigned long long)waited);
    close(s->dials[i].fd);
    s->dials[i].fd = -1;
    s->dials[i].state = DIAL_FAILED;
    s->n_dial_failed++;
    /* A CONNECT THAT NEVER COMPLETED IS THE FAILURE A RETRY BUDGET IS MOST
     * OBVIOUSLY FOR, and T1 is the only arm that reaches it: a black-holed host
     * produces no FIN, no ESTABLISHED, and therefore no T4, so a peer that is
     * down rather than unreachable never gets there. The link is found by NAME
     * because the dial table is keyed by nothing and holds a display copy, and
     * this is the one place where the link and the dial for the same peer are
     * related by that name rather than by a pointer -- which is why the lookup
     * is a scan of a vector this small rather than a stored back-pointer.
     *
     * The link is left in INIT by this arm (a dial that never completed never
     * promoted it), so the schedule armed here is the one T7 reads. */
    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *link = server_link_at(s, k);

        if (link != NULL && irc_ascii_same(link->name, peer) &&
            link->state == (int)INIT) {
            fed_retry_arm(s, link, now_ms, "DIAL_TIMEOUT");
            break;
        }
    }
}

/* The dial completed: the link gets its descriptor and starts its exchange.
 * INIT -> HANDSHAKE_SENT, and it is the SAME transition the accepting side
 * performs, which is what 2.3 means by the FSM being per-peer rather than
 * per-direction. */
static void fed_link_promote(server_t *s, server_link_t *link, dial_t *d)
{
    conn_t *c = server_conn(s, d->fd);

    if (c == NULL) {
        /* The connection went away between the dial completing and this tick.
         * The reaper has already closed the descriptor, so there is nothing to
         * close here and nothing to reap: the slot is retired rather than left
         * DIAL_CONNECTED, because DIAL_CONNECTED is what T7 and the next
         * promotion scan read, and a slot that stays there is a promotion
         * attempted on every tick for the life of the process.
         *
         * It is retired as FAILED rather than as anything else because FAILED
         * is the one dial state the shutdown walk does NOT close -- so a slot
         * left FAILED can never be double-closed -- and because a dial whose
         * connection was reaped before it was ever used has not delivered
         * anything, which is what FAILED means everywhere else in this file. */
        printf("[observable] link_promote_failed: peer=%s fd=%d "
               "reason=CONNECTION_GONE\n", link->name, d->fd);
        d->fd = -1;
        d->state = DIAL_FAILED;
        s->n_dial_failed++;
        return;
    }
    /* THE DIAL SLOT IS RETIRED HERE, and it did not used to be, and the reason it
     * has to be is that fed_dial_for() treats a DIAL_CONNECTED slot as a LIVE
     * DIAL. Before this line, the slot stayed DIAL_CONNECTED for the rest of the
     * link's life, and that produced two distinct defects once a link could be
     * re-dialled:
     *
     *   - T7's live-dial guard saw a live dial for a link that was already
     *     promoted, so a link that had just come back from HANDSHAKE_SENT to
     *     INIT could not dial for another whole dial timeout.
     *   - On the tick after the promotion, if the connection had been reaped in
     *     the meantime, fed_link_promote() ran again on the same slot and
     *     reported `link_promote_failed: reason=CONNECTION_GONE` for a link that
     *     had in fact been up and had simply been taken down. That is a
     *     MISLEADING line about a link that was not failing, and an operator
     *     reading it would chase a peer that was fine.
     *
     * DIAL_CONNECTED is retired as DIAL_FAILED rather than as anything else, and
     * for the reason fed_link_promote()'s CONNECTION_GONE arm gives: FAILED is
     * the one state the shutdown walk does not close, so a slot left in it can
     * never be double-closed. It is not a claim that this dial failed -- the
     * promotion below is what says whether it worked -- it is the state that
     * means "this slot holds nothing you may close". */
    d->state = DIAL_FAILED;
    d->fd = -1;

    link->fd = c->fd;
    fed_link_set_state(link, INIT);
    link->created_ms = server_now_ms();
    /* INIT -> HANDSHAKE_SENT, unconditional: the state was just set above, so
     * there is no precondition left to refuse. */
    fed_link_set_state(link, HANDSHAKE_SENT);
    link->last_sent_ms = link->created_ms;
    link->last_recv_ms = link->created_ms;
    (void)fed_queue_federate(s, link, c);
    printf("[observable] link_dialled: peer=%s fd=%d state=HANDSHAKE_SENT\n",
           link->name, link->fd);
}

/* T3. The keepalive, and what it costs.
 *
 * BUILT HERE rather than through fed_send_sverb(), and the reason is a frozen
 * wire format rather than a preference. That table maps CLIENT verbs a node is
 * RELAYING, and tests/integration/test_fed_wire.c asserts that PING has no
 * S-verb because "4.3's list is the forwarded vocabulary, and adding to it is a
 * wire-format change". A link-liveness probe is not a relay of anything, so
 * there is no client verb to map -- and inventing one would put a word into the
 * forwarded vocabulary that an implementation written from 4.3 would refuse.
 * verbs.h records the same conclusion from the other side, and the table is
 * still closed: this function names PING itself and nothing else had to change.
 *
 * The part that is NOT unique to a keepalive -- stamp the 2.4 block, build the
 * message, render it, bound-check it, terminate it, queue it -- is
 * fed_queue_line() in verbs.c, which this function and fed_send_sverb() both
 * call, and the two files point at each other rather than each explaining the
 * overlap. What stays here is what is specific to a keepalive: which line it
 * sends, the stamps it puts on it, and the refusal words a reader of this
 * module expects to see. The failure is still reported as THIS node failing to
 * probe, not as a verb that has no S-verb, which is the more useful of the two
 * reports.
 *
 * hops=0 because this node ORIGINATED the line, and 2.4's rule is that a node
 * never forwards a message whose origin it is -- so the hop count of an
 * originated message starts at zero and becomes one on the far side's first
 * forward. A fresh id from the per-SERVER counter, because 2.4 is explicit that
 * a per-connection counter is what this format replaced.
 *
 * The peer does not answer in this phase: there is no inbound PING handling
 * until C3. That is harmless, because a received line is the liveness signal
 * rather than an answer, and the PEER's own keepalives are what refresh this
 * side. The cost of it not being harmless would be a link with no responses,
 * which is a different design and C3's to make. */
static int fed_send_keepalive(server_t *s, server_link_t *link, conn_t *c,
                              uint64_t now_ms)
{
    irc_serve_tags_t tags;
    const char *params[2];
    fed_queue_why_t why = FED_QUEUE_OK;

    memset(&tags, 0, sizeof tags);
    memcpy(tags.origin, s->name, strlen(s->name) + 1u);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0;

    params[0] = link->name; /* the peer being probed */
    params[1] = s->name;    /* who is asking                                  */
    /* The stamps above are validated inside fed_queue_line(), and the reason
     * that is checked rather than trusted is the same: a stamp that fails the
     * 2.4 grammar cannot be put on the wire in a form a peer would accept, and a
     * keepalive a peer refuses to parse is a link that goes dead for want of a
     * probe. s->epoch is at least 1 and server_next_msg_id() never returns 0,
     * so this cannot fail; it is checked because the alternative is a tagless
     * line on a peer link.
     *
     * BOTH tag refusals are reported as BAD_TAGS, which is what this module
     * has always printed for them. fed_queue_line() separates the two because
     * fed_send_sverb() has a second word for a block that will not fit, and
     * splitting one unreachable case in two here would add a word to this
     * module's vocabulary for a condition that cannot arise: a stamp this
     * function just built is either valid or it is a bug in the values above. */
    if (fed_queue_line(s, c, &tags, s->name, "PING", params, 2, &why) != 0) {
        printf("[observable] keepalive_refused: peer=%s reason=%s\n",
               link->name,
               (why == FED_QUEUE_TAG_TOO_LONG)
                   ? "BAD_TAGS"
                   : fed_queue_why_name(why));
        return -1;
    }
    link->last_sent_ms = now_ms;
    return 0;
}

/* T4. A peer that has stopped talking. */
static void fed_dead(server_t *s, server_link_t *link, conn_t *c,
                     uint64_t now_ms)
{
    uint64_t silent = now_ms - link->last_recv_ms;

    printf("[observable] link_dead: peer=%s silent_ms=%llu\n", link->name,
           (unsigned long long)silent);
    if (link->state == (int)HANDSHAKE_SENT || link->state == (int)ESTABLISHED) {
        fed_link_set_state(link, FAILED);
    }
    s->n_fed_dead++;
    /* THE FAILOVER ARM, and it is here rather than at the end of the tick for a
     * reason that is about the order of events: fed_link_down() is what clears
     * the link's descriptor and hands the state back to INIT, and T7 runs in
     * the SAME tick's switch. Arming before the teardown means the schedule is
     * already stamped by the time this link reaches the INIT arm, so a link that
     * has been dead for a whole IRC_FED_DEAD_MS is re-dialled on the NEXT tick
     * rather than one tick after that. */
    fed_retry_arm(s, link, now_ms, "DEAD");
    /* ANNOUNCED, because this link WAS a route: every other peer holding this
     * node's name learned it through here, and cannot reach it here any more. */
    fed_link_down(s, link, 1);
    if (c != NULL) {
        conn_mark_closing(c);
    }
}

void fed_tick(server_t *s, uint64_t now_ms)
{
    size_t i;

    if (s == NULL) {
        return;
    }

    /* --- T5: the dedup sweep ------------------------------------------- */
    /* Only the occupancy is gated here. The time part of "is it due" is inside
     * fed_dedup_sweep(), because the property is the store's age rather than
     * the caller's, and there are two call sites (this one and
     * fed_dedup_seen()'s). */
    if (s->dedup_used > (uint64_t)(IRC_DEDUP_MAX / 2u)) {
        (void)fed_dedup_sweep(s, now_ms);
    }

    /* --- the 2.1 nick registry sweep ------------------------------------ */
    /* HERE AND NOT BESIDE THE DEDUP SWEEP'S OCCUPANCY TEST, and the reason is
     * what each gate measures. The dedup sweep is gated on OCCUPANCY because a
     * dedup store that is half empty cannot be expiring anything: the time is
     * inside it. The nick registry is gated on the TABLE existing at all, and
     * the time is inside it too (fed_nickreg_sweep() owns the throttle, the same
     * way fed_dedup_sweep() does). So the test here is the cheap one -- "has this
     * node ever learned a remote nick" -- and a node with no peers and a node
     * whose mesh has no remote users both pay one pointer comparison per tick.
     *
     * IT IS BEFORE THE ZERO-LINK RETURN and that placement is deliberate: the
     * return below is justified by "a node with no peers has no federation work",
     * and an entry learned from a peer that has since gone would never be swept
     * if the sweep lived after it. A SQUIT purges, so a departed peer's entries
     * are gone by the time the count reaches zero -- but a node that LOST a link
     * without a SQUIT (T4's path) keeps the count, and its table would grow stale
     * entries forever on a mesh that never comes back. */
    if (s->rnicks != NULL) {
        (void)fed_nickreg_sweep(s, now_ms);
    }

    /* #327: a burst shadow left open by a peer that went silent must not hold
     * BUSY forever. The sweep discards it past the 30s timeout (counted
     * abandoned) whether or not any link is up. */
    fed_burst_sweep(s, now_ms);

    /* A node with no peers pays four integer comparisons and returns: this
     * one, the burst sweep's open test, the occupancy test above, and the
     * pointer test just here. */
    if (server_link_count(s) == 0u) {
        return;
    }

    /* --- T1: dials that will never complete ---------------------------- */
    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state == DIAL_CONNECTING &&
            (uint64_t)(now_ms - s->dials[i].started_ms) >= s->fed_dial_ms) {
            fed_dial_expired(s, i, now_ms);
        }
    }

    /* --- per link ------------------------------------------------------ */
    for (i = 0; i < server_link_count(s); i++) {
        server_link_t *link = server_link_at(s, i);
        conn_t *c;
        dial_t *d;

        if (link == NULL) {
            continue;
        }
        /* The link pointer is re-derived from the index on every use because
         * fed_link_reset() and fed_link_configure() can grow the vector, and a
         * pointer into an array that another call may realloc is exactly the
         * habit that turns a growth into a use-after-free. */
        c = server_link_conn(s, link);

        /* --- promotion: the dial completed ----------------------------- */
        if (link->fd < 0) {
            d = fed_dial_for(s, link->name);
            if (d != NULL && d->state == DIAL_CONNECTED) {
                fed_link_promote(s, link, d);
                c = server_link_conn(s, link);
            }
        }

        switch (link->state) {
        case (int)INIT:
            /* --- T7: dial it, if the schedule says so ------------------- */
            /* FIVE CONDITIONS, AND EVERY ONE OF THEM IS LOAD-BEARING. The
             * count is the price of replacing a single latch with a policy.
             *
             *   initiator        an ACCEPTED link has no address, and
             *                   server_dial() would be handed a zeroed sockaddr.
             *   addrlen != 0     same, stated separately because a link with a
             *                   zero length is a different defect from a link
             *                   that never dialled and the two are worth telling
             *                   apart in a dump.
             *   gave_up == 0     the budget. Checked HERE rather than inside a
             *                   helper so that the whole refusal is visible in
             *                   one place: this is the line a reader comes to
             *                   when a link is not being dialled.
             *   due              the backoff. retry_at_ms == 0 means DUE NOW,
             *                   which is the state a freshly configured link is
             *                   in, so a healthy mesh's first dial is immediate
             *                   and only a failed one waits.
             *   no live dial     UNCHANGED from Phase 6 and still the arm with
             *                   the subtlest failure: between this call to
             *                   server_dial() and the dial resolving there is no
             *                   state change on the link at all, so a link whose
             *                   stamp is already in the past opens a SECOND
             *                   socket to the same peer on the very next tick.
             *                   The backoff does not fix this -- the schedule
             *                   says the link is due and it stays due until the
             *                   attempt resolves.
             *   clean_leave == 0  PHASE 9 ITEM 4, and it is checked HERE and not
             *                   inside fed_retry_arm() for a reason that is about
             *                   direction rather than placement: this arm is the
             *                   only place a link becomes DIALABLE, so a flag set
             *                   anywhere in the module has to be cleared here for
             *                   the suppression to be complete. A peer that sent
             *                   SHUTDOWN said goodbye, and dialling it would spend
             *                   a budget of three attempts and a two-minute
             *                   ceiling rediscovering a message that already
             *                   arrived -- and would leave a link that looks
             *                   retryable in the dump, so an operator reading it
             *                   would go looking for a flaky peer where there is a
             *                   departed one. An operator who resets the link gets
             *                   the dial back, because fed_link_reset() clears the
             *                   flag and nothing else does.
             *
             * created_ms is stamped here and is NOT read as a latch any more
             * (the header retracts that claim); what it is for now is T2's
             * comparison against IRC_FED_HS_TIMEOUT_MS and for the dump, where
             * "when did this attempt begin" is one of the two numbers an
             * operator needs to tell a slow handshake from a dead link. */
            if (link->initiator != 0 && link->addrlen != 0 && link->gave_up == 0 &&
                link->clean_leave == 0 &&
                (link->retry_at_ms == 0u || now_ms >= link->retry_at_ms) &&
                fed_dial_for(s, link->name) == NULL) {
                /* Gate, don't encrypt (#167): a link with require_tls is never
                 * dialled without TLS, so its FEDERATE -- which carries the
                 * shared secret -- can never go out in the clear. Unreachable
                 * through the shipped binary (main() refuses --peer-tls with no
                 * certificate), so this is the backstop for any caller that set
                 * the flag another way: no socket, no FEDERATE, and the backoff
                 * armed so the refusal does not spin. */
                if (link->require_tls != 0 && s->tls == NULL) {
                    fed_refuse(s, link, NULL, link->name, "TLS_REQUIRED");
                    fed_retry_arm(s, link, now_ms, "TLS_REQUIRED");
                    break;
                }
                link->created_ms = now_ms;
                if (server_dial(s, (const struct sockaddr *)&link->addr,
                                link->addrlen, link->name) == 0) {
                    printf("[observable] link_dial: peer=%s\n", link->name);
                } else {
                    /* A DIAL THAT COULD NOT BE STARTED AT ALL -- an exhausted
                     * descriptor table, or a socket() the kernel refused -- is a
                     * failed attempt and must cost budget, or a node in that
                     * state dials on every tick for ever. server_dial() has
                     * already counted it on n_dial_failed; this counts the
                     * LINK's side, which is the different fact. */
                    fed_retry_arm(s, link, now_ms, "DIAL_REFUSED");
                }
            }
            break;

        case (int)HANDSHAKE_SENT:
            /* --- T2: the handshake never answered ----------------------- */
            /* AND THE OTHER WAY IT IS NEVER ANSWERED, which is the same defect
             * T4a above finds on an established link and which cost this test
             * eleven seconds.
             *
             * T2's own question is "has the peer had fed_hs_ms to answer?". The
             * answer is also NO -- for ever -- when the socket this attempt was
             * made on is gone: fed_link_promote() queued the FEDERATE and the peer
             * will never see it, because there is no socket left to carry it. And
             * the socket can be gone: a nonblocking connect() that completes into
             * a peer that has already gone reports writable with SO_ERROR still
             * reading zero (server_dial() says so where it declines to probe
             * SO_ERROR at connect time), the descriptor is registered as a live
             * connection, and the write of the claim that follows either fails
             * into a socket the kernel has already reset or succeeds into a buffer
             * nobody will ever read. Either way the exchange cannot complete, and
             * T2 waits out the whole IRC_FED_HS_TIMEOUT_MS before admitting it.
             *
             * SO THE SOCKET IS CHECKED, and it is checked with the same identity
             * test T4a uses rather than by descriptor number, because a reaped
             * descriptor is a number the very next accept() can hand to something
             * else entirely. On the wire this is a twelve-second partition on a
             * link that was already dead, followed by a retry budget spent
             * rediscovering a message that had arrived and been discarded.
             *
             * AND IT IS ONLY ASKED OF A LINK THAT WAS DIALLING. link->fd is
             * stamped by fed_link_established() and by fed_link_promote() and by
             * nothing else, so a link that is HANDSHAKE_SENT because an INBOUND
             * FEDERATE arrived -- fed_claim_accepted() moves the state to
             * HANDSHAKE_SENT on the way to fed_link_established() -- has
             * fd == -1 for the whole of the exchange while holding a perfectly
             * live conn_t. Reading fd == -1 there as "the socket is gone" would
             * tear down every inbound handshake in flight on its first tick,
             * which is why this is gated on fd >= 0 rather than written as
             * c == NULL. The accepting side's own liveness is T2's clock, which
             * is already the next line. */
            /* ------------------------------------------------------------------------
             * THE CLOCK HALF IS GUARDED AGAINST A STAMP IN THE FUTURE, and this is
             * a defect that cost a handshake per tick that took a millisecond.
             *
             * `now_ms` is the value poll_loop_step() sampled with
             * server_now_ms() BEFORE it called server_tick(), and it is the value
             * every deadline in this switch is measured against. fed_link_promote()
             * runs INSIDE that same tick -- the promotion is at the top of this
             * per-link walk and this switch is at the bottom of it -- and it stamps
             * created_ms from a FRESH server_now_ms() of its own. So on any tick
             * where at least one millisecond elapses between step 8's clock read and
             * the promotion, created_ms is one or more milliseconds NEWER than the
             * now_ms being compared against it, which is not a clock going
             * backwards at all: CLOCK_MONOTONIC cannot do that, and both readings
             * are in the right order in real time.
             *
             * `now_ms - link->created_ms` is an UNSIGNED subtraction, so a stamp one
             * millisecond in the future underflows to 2^64-1, that is >= fed_hs_ms on
             * any clock, and T2 fires ON THE VERY TICK THAT PROMOTED THE LINK: the
             * handshake is declared timed out, the connection is marked CLOSING with
             * the FEDERATE still sitting in its write queue, the peer sees a clean
             * close having read nothing, and the link sits in HANDSHAKE_SENT until
             * the reconnect it never gets to make. Measured on this tree:
             *
             *   promote peer=irc.b fd=5 queue_rc=0 pending=80 now=4044447577
             *   T2       peer=irc.b fd=5 created=4044447577 now=4044447576
             *            age=18446744073709551615 hs=1000 c=0x... match=1
             *   MARK_CLOSING fd=5 kind=1
             *
             * `match=1` is the socket half of the test saying the connection WAS
             * this link's, so the printed cause was NO_ANSWER: the second mechanism
             * PR #119 explicitly declined to fix, and it was never a second
             * mechanism at all. It is this one, wearing the other cause's name.
             *
             * WHY IT NEEDED A MILLISECOND TO SHOW and why it looked like a
             * timeout problem: a tick that gets from step 8's clock read to the
             * promotion in under the same millisecond produces age == 0 and the
             * arm is correctly not taken. It is a race on the tick's own
             * duration, so it needs a loaded machine to lose -- which is why it
             * survived a timeout increase (Phase 8 raised the budget 5000 -> 6000
             * -> 12000 and changed nothing) and why raising fed_hs_ms is not the fix:
             * the age is 2^64-1, and no budget is larger than that.
             *
             * THE CLOCK HALF IS fed_hs_due(), and the rule it applies is the
             * PROJECT'S OWN, from server_tick() and resume_sweep(): a stamp that is
             * not yet in the past is not due. It lives in a named predicate rather
             * than inline here so that tests/federation/test_hs_deadline.c can
             * assert it directly -- a defect that can only be observed by losing a
             * race on the tick's duration cannot be regression-tested at all, and
             * exporting the predicate is the whole of what makes it testable.
             *
             * THE TWO HALVES ARE NOT GUARDED ALIKE, on purpose. The clock half is
             * suppressed while the stamp is in the future; the socket half below is
             * NOT, because "this link's descriptor is gone" is not a question about
             * elapsed time and is true whenever it is true. PR #119's fix therefore
             * still fires exactly when it should.
             * ------------------------------------------------------------------------ */
            if (fed_hs_due(s, link->created_ms, now_ms) ||
                (link->fd >= 0 &&
                 (c == NULL || fed_link_of_conn(s, c) != link))) {
                fed_link_set_state(link, TIMED_OUT);
                s->n_fed_hs_timeout++;
                printf("[observable] link_timeout: peer=%s state=TIMED_OUT "
                       "cause=%s\n",
                       link->name,
                       (link->fd >= 0 &&
                        (c == NULL || fed_link_of_conn(s, c) != link))
                           ? "SOCKET_GONE"
                           : "NO_ANSWER");
                /* T2 ARMS THE SCHEDULE AND TAKES THE LINK BACK TO INIT, and
                 * both halves were corrections rather than new behaviour. Phase 6
                 * left TIMED_OUT terminal on the reasoning that a handshake which
                 * never completed has nothing to tear down -- which is true of the
                 * ANNOUNCEMENT and was then over-applied to the STATE, with the
                 * consequence that a peer accepting TCP and then going silent
                 * cost this node one dial and no retry for the life of the
                 * process. That is the same silent resource leak the budget
                 * exists to bound, reached by a different road, and a test
                 * (test_failover_reconnect.c) found it by freezing a peer whose
                 * kernel still completes the handshake: the retry arrived, the
                 * FEDERATE was unanswered, and the link sat in a terminal state
                 * that nothing dials out of.
                 *
                 * SO THE ARM IS NOT OPTIONAL HERE and the teardown below is what
                 * makes it readable: without returning the link to INIT the
                 * schedule would be stamped by a path that never dials again,
                 * which is worse than not arming at all -- a reader would see a
                 * `link_retry:` line and conclude a retry was coming.
                 *
                 * NOT ANNOUNCED (fed_link_down's third argument), and that is the
                 * load-bearing part of the correction: no peer ever learned
                 * anything about this node through a handshake that never
                 * finished, and the node's OTHER links are still up, so a SQUIT
                 * here would tell a healthy mesh that a live node had departed. */
                fed_retry_arm(s, link, now_ms, "HANDSHAKE_TIMEOUT");
                fed_link_down(s, link, 0);
                if (c != NULL) {
                    conn_mark_closing(c);
                }
            }
            break;

        case (int)ESTABLISHED:
            /* --- T4a: a route with no socket -------------------------- */
            /* THE ARM T4 DOES NOT COVER, and it is the one that decides whether a
             * partitioned mesh can heal itself.
             *
             * T4 below asks whether the PEER has stopped talking.  It cannot see
             * the other way round, and that is the direction that matters here: a
             * link is ESTABLISHED, its name is claimed, and the descriptor it is
             * ESTABLISHED ON IS GONE.
             *
             * HOW A LINK GETS INTO THAT STATE. server_reap() is the one place a
             * descriptor is closed, and it closes it when the conn_t is reaped --
             * on an EOF, on a read error, on a reset.  Nothing on that path tells
             * the federation module, so link->fd keeps naming a descriptor the
             * node no longer owns and link->state stays ESTABLISHED.  Until T4
             * eventually fires, this node is running on the belief that it has a
             * live route to a peer whose socket it closed itself.
             *
             * WHY THAT IS NOT COSMETIC. fed_check_federate() refuses a second
             * claim on a name with FED_DUPLICATE_LINK when some link is
             * ESTABLISHED, and that refusal is correct for a link that HAS a
             * socket.  It is wrong for one that does not: the peer on the far
             * side has, quite correctly, already declared its own side dead and is
             * dialling again -- that is what T4 is FOR -- and it is told the name
             * is in use by a route that is not there.  The re-dial then sits in
             * HANDSHAKE_SENT until IRC_FED_HS_TIMEOUT_MS expires, T2 arms the
             * ladder, and the peer spends a second attempt rediscovering a message
             * that had already arrived.  Under the shipped 5 s handshake timeout
             * that is a five-second partition on a link whose socket died; with
             * this test's 12 s one it is twelve.
             *
             * SO THE LINK IS TAKEN DOWN HERE, by the same path T4 uses, at the
             * moment the socket is found to be gone rather than up to one dead
             * interval later.  fed_dead() is the right function for it and not a
             * near miss: this link WAS a route (it is in this arm), so the
             * announcement fed_link_down() makes is the same true statement, and
             * the arm it stamps is the same one a peer that went quiet would
             * stamp.
             *
             * THE IDENTITY CHECK IS THE PART THAT IS NOT DEFENSIVE PADDING, and
             * fd reuse is why.  server_reap() closes the descriptor, and the very
             * next accept() can hand the same NUMBER to an unrelated connection --
             * a client, or the peer's own re-dial.  s->by_fd[link->fd] is then a
             * live conn_t that has nothing to do with this link, and a bare
             * "is there a conn on link->fd" test would report a healthy link as
             * socket-less and take down a route that is up.  fed_link_of_conn()
             * answers the question that is actually being asked -- IS THIS
             * CONNECTION THIS LINK -- and it is the same function the dialling
             * side already finds its link with. */
            {
                conn_t *own = (c != NULL && fed_link_of_conn(s, c) == link)
                                  ? c
                                  : NULL;

                if (own == NULL) {
                    fed_dead(s, link, NULL, now_ms);
                    break;
                }
                /* The descriptor this link is ESTABLISHED on is a different
                 * connection's, so the link is down even though by_fd has
                 * something on the number. */
                c = own;
            }

            /* --- T3: keepalive, then T4: dead ------------------------- */
            /* Both tests are on this link's own stamps, and both are
             * subtractions: 3.4's clock is monotonic, and a subtraction is the
             * shape that stays correct if it ever is not. */
            if ((uint64_t)(now_ms - link->last_sent_ms) >= s->fed_keepalive_ms) {
                if (c != NULL) {
                    /* On failure last_sent_ms is NOT advanced, which is the
                     * point of returning the status: server_queue() has already
                     * marked the link CLOSING for a saturated queue and counted
                     * it, and T4 will notice the silence. Advancing the stamp
                     * anyway would tell T4 the peer had been spoken to when it
                     * had not, and the link would sit there for another full
                     * dead interval before anything was said about it. */
                    (void)fed_send_keepalive(s, link, c, now_ms);
                }
            }
            /* THE ADVERTISEMENT REFRESH, and it is HERE rather than at the top of
             * the tick because it is per LINK and the loop is already walking
             * them. The stamp is PER NODE rather than per link on purpose: every
             * link gets the same line at the same moment, so the node spends one
             * id per link at one point in its life rather than four ids spread
             * across four intervals, and a dump of a link's ids is easier to read.
             *
             * AND IT IS BELOW T4, not above it, which is the ordering that keeps
             * the two liveness questions from interfering: T4 asks "is this peer
             * still there" from the link's own silence, and this asks "is the load
             * figure still worth sending" from a clock. A node whose peer has
             * gone quiet gets no advertisement at all, because the arm is inside
             * the ESTABLISHED case and T4 has not yet moved the link out of it --
             * so a dead peer is never told this node's load. */
            if (s->fed_advertise_ms > 0u && (s->advert_sent_ms == 0u ||
                                        now_ms >= s->advert_sent_ms) &&
                (uint64_t)(now_ms - s->advert_sent_ms) >= s->fed_advertise_ms) {
                (void)fed_send_advertise(s);
                s->advert_sent_ms = now_ms;
            }
            if ((uint64_t)(now_ms - link->last_recv_ms) > s->fed_dead_ms) {
                /* THE FAILOVER ARM, once. T4 is the only place a link that was
                 * ESTABLISHED can be declared dead, so the heartbeat is the only
                 * thing that drives a redial of a link that WAS up: there is no
                 * other event in this node that means "this peer is gone" for a
                 * link that had a descriptor and a route. That is the whole of
                 * "heartbeat-driven failover" -- the liveness signal does not
                 * merely close the link, it ARMS the redial, and the arm happens
                 * in fed_retry_arm() above rather than being a decision T4
                 * delegates to the next tick. */
                fed_dead(s, link, c, now_ms);
            }
            break;

        default:
            /* FAILED and TIMED_OUT. Both are terminal until something resets
             * them, and in C2 nothing does: a link that failed stays failed and
             * is reported by the dump, which is the honest state. No state of
             * its own is tracked here beyond this switch, so there is nothing
             * to disagree with it. */
            break;
        }

        /* --- T8: this peer says it is shedding, so SAY SO ---------------- */
        /* ONE COMPARISON PER ESTABLISHED LINK PER TICK, and it is gated on the
         * operator having set a threshold at all (server.h's shed_pct), which is
         * 0 in the shipped state. So the cost on a node with no threshold is two
         * integer comparisons per link, on a mesh whose busiest node is nowhere near
         * this. On a node that HAS set one it is three, and the line it may print is
         * one per crossing rather than one per tick.
         *
         * IT IS OUTSIDE THE SWITCH ON PURPOSE, because the figure belongs to the
         * PEER rather than to the link's state: a peer that is shedding is a fact
         * this node learned over an ESTABLISHED link and it stays true through T4's
         * transition to INIT, so gating the report on ESTABLISHED would drop the
         * report of a peer that crossed the threshold and died in the same tick --
         * which is precisely the moment an operator most wants to hear about it.
         * The latch makes that harmless: the crossing is reported once, from
         * whichever state the link happens to be in when the tick runs.
         *
         * `load_seen_ok` IS CHECKED AND NOT ASSUMED, because an unset figure is not
         * a zero figure: without it a peer that has never advertised would be
         * reported as an idle 0% peer the moment the operator set a threshold above
         * zero, and this node would be making a claim about a peer it has never
         * heard from. */
        if (s->shed_pct != 0u && link->load_seen_ok != 0 &&
            link->load_seen >= s->shed_pct && link->shed_reported == 0) {
            link->shed_reported = 1;
            s->n_fed_shed++;
            /* THE LINE, and action=REPORT_ONLY is load-bearing rather than
             * documentation: it is on the wire, so an operator grepping a mesh for
             * "who is busy" gets an unambiguous answer about what this node did
             * about it, and a reader cannot mistake a report for a routing change
             * that this codebase does not make. The refusal reason is spelled out
             * because "and then what?" is the question a reader of a mesh-load
             * feature always asks, and the answer being "nothing, and here is why"
             * is the honest one. */
            printf("[observable] fed_shed: peer=%s load=%u%% threshold=%u%% "
                   "action=REPORT_ONLY rebalance=NO reason=NO_MOVE_MECHANISM\n",
                   link->name, link->load_seen, s->shed_pct);
        }
    }
}
