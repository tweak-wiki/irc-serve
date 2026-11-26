/* link_accept.c -- see federation/link.h. The FEDERATE accept half.
 *
 * Split verbatim out of link.c (issue #543 TU-36): the rejection arm
 * (fed_reject(), with its per-reason counter), the establishment arm
 * (fed_link_established()), the non-verdict refusal (fed_refuse()), the claim
 * application (fed_claim_accepted()) and the inbound seam (fed_on_federate()
 * plus fed_dispatch_hook()). fed_refuse()/fed_on_federate()/
 * fed_dispatch_hook() stay declared in federation/link.h (tick.c precedent,
 * no new header); fed_reject()/fed_link_established()/fed_claim_accepted()
 * stay static (their sole callers move with them). fed_link_new() is shared
 * with link_table.c's fed_link_configure() and goes extern through link.h.
 */
#include "federation/link.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/poll_loop.h"
/* Phase 12: the drain in fed_send_shutdown() reads through the transport, so this
 * is the third of the tree's three I/O sites to name it. See the comment on that
 * block for what happens to the node's departure if it did not. */
#include "core/transport.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/departure.h"
/* Phase 9: 2.1's remote-nick registry, swept from fed_tick() because a store
 * whose owner never ticks it never expires anything. */
#include <arpa/inet.h>
#include <netinet/in.h>

#include "federation/nickreg.h"
#include "federation/verbs.h"

static void count_reject(server_t *s, fed_federate_result_t result)
{
    int which = (int)result;

    if (s == NULL) {
        return;
    }
    if (which > 0 && which < FED_RESULT_COUNT) {
        s->fed_rejected[which]++;
    }
}

/* The whole of a rejection, in three steps and always in this order.
 *
 *   (a) print. NOT gated on s->trace, and the reason is the one this project
 *       uses for every refusal: a rejected handshake is a bug report or an
 *       attack, and a flag that can silence a bug report is not a flag that
 *       should be able to silence a bug report. The volume argument that
 *       justifies the per-line trace does not apply to a line that appears
 *       once per rejected connection.
 *   (b) FAILED, so the state records that this exchange ended wrongly.
 *       A link whose state still said HANDSHAKE_SENT after its connection is
 *       gone would sit in T2 until the timeout fired and would report a
 *       handshake timeout for something that was rejected in the first
 *       millisecond.
 *   (c) conn_mark_closing() and NEVER close(). 3.4 puts the close at one fixed
 *       point in the loop, and a second close path in a file that owns peer
 *       links is precisely how a descriptor gets closed twice. */
static void fed_reject(server_t *s, server_link_t *link, conn_t *c,
                       fed_federate_result_t result, const char *claim)
{
    const char *peer = (link != NULL) ? link->name : claim;

    printf("[observable] link_rejected: peer=%s reason=%s fd=%d\n",
           (peer != NULL && peer[0] != '\0') ? peer : "?",
           fed_federate_reason(result), (c != NULL) ? c->fd : -1);
    /* Counted whether or not there is a link to fail. An inbound claim that
     * arrives on the listener has no link yet -- that is the ordinary accepting
     * case -- and counting only the ones that did have one would make the
     * headline number report the minority and the per-reason breakdown report
     * everything, which is the kind of pair that reads as a bug in the other
     * module. */
    if (s != NULL) {
        s->n_link_rejected++;
        if (result == FED_DUPLICATE_LINK) {
            s->n_link_duplicate++;
        }
    }
    if (link != NULL && (link->state == (int)HANDSHAKE_SENT ||
                         link->state == (int)ESTABLISHED)) {
        fed_link_set_state(link, FAILED);
    }
    if (c != NULL) {
        conn_mark_closing(c);
    }
    count_reject(s, result);
    fed_dump(s, "rejected");
}

/* A link that has earned its place: the descriptor, the peer's epoch, and the
 * FSM. Split out of fed_federate_inbound() because both the accepting side and
 * the dialling side's promotion end here, and 2.3 wants them to be the same
 * transition. */
static void fed_link_established(server_t *s, server_link_t *link, conn_t *c,
                                 const char *claim, uint64_t peer_epoch)
{
    link->fd = c->fd;
    link->epoch = peer_epoch;
    /* The liveness stamps start now rather than at configuration: before this
     * point the link has no peer that could be alive or dead, and a stamp from
     * configuration time would make a slow handshake look like a silent one the
     * moment it completed. */
    link->last_sent_ms = server_now_ms();
    link->last_recv_ms = link->last_sent_ms;
    /* 2.3: a peer connection is exempt from the client registration state
     * machine. Changing `kind` here is what takes it out: reply.c refuses a
     * CONN_SERVER destination, so a numeric can no longer be written to this
     * connection even by a path that does not know it is a peer.
     *
     * peer_name stays a display copy and a NULL one if the allocation fails.
     * Nothing routes by it (core/server.h is explicit that the link is the
     * authority), so a missing copy costs a diagnostic field and no routing. */
    c->kind = CONN_SERVER;
    /* #540: the flood bucket was sized for a client when this connection's
     * first refill ran. Promote it to the peer cap now or the burst below
     * trips the limiter and the link flaps. */
    conn_flood_peer_promoted(c);
    if (c->peer_name == NULL) {
        char *copy = (char *)malloc(strlen(claim) + 1u);

        if (copy != NULL) {
            memcpy(copy, claim, strlen(claim) + 1u);
            c->peer_name = copy;
        }
    }
    /* THE BUDGET IS REFILLED HERE, and it is here rather than at the end of the
     * function for the same reason federation_resync() is below it: a link that
     * has just come up is a link that should be dialled AGAIN without waiting,
     * and a link that came up after a backoff still has that backoff's stamp on
     * it. Leaving it would mean a link that recovered keeps waiting out a
     * schedule earned for a failure it has already fixed.
     *
     * `retries` goes to 0 rather than being decremented, and the difference
     * matters: it is what makes the budget a budget of CONSECUTIVE failures
     * rather than a lifetime cap on a link, so a peer that flaps is retried
     * indefinitely (one fresh budget per success) while a peer that is simply
     * dead is not. `gave_up` is cleared for the same reason, and it is cleared
     * HERE rather than only in fed_link_reset() because a link cannot reach
     * ESTABLISHED without coming through this function -- so a link whose budget
     * ran out and which then succeeded has, by the fact of its success, been
     * fixed, and holding the give-up against it would be holding it against the
     * evidence. */
    link->retries = 0u;
    link->gave_up = 0;
    link->retry_at_ms = 0u;
    /* #666: a link that has just come up is a link whose goodbye -- if it ever
     * sent one -- is stale. Leaving clean_leave set would hide the NEXT
     * departure's log line (fed_mark_clean_leave() prints only on transition)
     * behind this generation's. */
    link->clean_leave = 0;
    printf("[observable] link_established: peer=%s fd=%d initiator=%d "
           "epoch=%llu\n",
           link->name, link->fd, link->initiator,
           (unsigned long long)link->epoch);
    fed_dump(s, "established");
    /* THE RESYNC, and it goes HERE rather than in either of the two paths that
     * reach this function, because 2.3 wants the accepting side and the dialling
     * side's promotion to be the same transition and 4.3's "on every link
     * establishment" has to be true of both of them. A call in the accept path
     * only would be the INITIATOR's burst, which is 4.3's literal wording and is
     * not sufficient: a node only forwards to peers that already hold the
     * chan_t, so in a two-node fixture the RESPONDER's channels would never reach
     * the initiator, a user there would be invisible to the initiator for ever,
     * and 7/Phase 6's full-353 criterion would fail on one of the two nodes.
     *
     * BOTH SIDES BURSTING IS A DELIBERATE SUPERSET of the doc's sentence "the
     * initiator sends full state", and it costs one extra burst per link. What it
     * buys is that "on every link establishment" means what a reader of 4.3 would
     * expect it to mean, and that neither node's view of the other depends on
     * which of the two happened to dial. The asymmetry the doc describes is
     * real -- the initiator does have to send its state or the other node learns
     * nothing -- but it is a statement about the MINIMUM, and a minimum is not a
     * rule about what the responder may do.
     *
     * ONE ORDERING CONSTRAINT, and it is the reason this is not at the top of
     * the function: the burst needs the link's descriptor and the peer's epoch,
     * so it has to be after both are set. It does NOT wait for the peer's own
     * burst, and cannot: neither side is going to block on the other, so the two
     * transactions cross on the wire and each is applied on arrival. There is no
     * ordering to agree on because neither transaction depends on the other -- a
     * burst is a statement about the sender, and the sender's state does not
     * change because somebody received it. */
    /* Issue #676: collect the empty own-origin shells the partition held.
     * chan_dispose_if_empty() delays disposal of those while partitioned so a
     * re-JOIN revives the existing channel instead of minting a second
     * origin; once any link is whole again the shells nobody revived are
     * garbage, and leaving them would pin cap slots. Backward over the
     * registry, because detach shifts the tail down and only indices already
     * visited move. Before the resync, so our own burst does not carry the
     * shells it is about to drop. */
    {
        size_t i = server_chan_count(s);

        while (i-- > 0u) {
            chan_t *ch = server_chan_at(s, i);

            if (ch != NULL) {
                (void)chan_dispose_if_empty(s, ch);
            }
        }
    }
    (void)federation_resync(s, link);
    /* AND IT ADVERTISES ITSELF, ONCE, HERE. The first ADVERTISE has to go out on
     * ESTABLISHMENT and not on the first interval tick, because a peer that has
     * just arrived is the one peer that most needs to be told what this node looks
     * like -- and because a test with a short interval and a long dial would
     * otherwise have to wait out the interval to see the first one. Everything
     * after this is a refresh, driven from fed_tick() at
     * s->fed_advertise_ms. */
    (void)fed_send_advertise(s);
    s->advert_sent_ms = server_now_ms();
}

/* fed_check_federate(): split out for #543 into federation/link_guard.c with
 * its secret_matches() helper; still declared in federation/link.h. */

/* A refusal that is NOT a verdict on the peer's line, and therefore is not
 * counted and does not appear in the per-reason breakdown.
 *
 * There are two of them, and both are this node's problem rather than the
 * peer's: the node could not make room for another link, and a transition the
 * FSM refused. A breakdown that mixed protocol verdicts with local failures
 * would not add up against n_link_rejected, and reporting an internal mistake
 * as BAD_ARITY -- which is what the first version of this file did -- is a lie
 * told to whoever reads the log: it names a malformed handshake where the truth
 * is a node that could not move its own state machine.
 *
 * Both still print, because a refusal nobody can see is a bug nobody reports,
 * and both still close through conn_mark_closing() and never close the
 * descriptor, because that part is 3.4 and does not depend on why. */
void fed_refuse(server_t *s, server_link_t *link, conn_t *c,
                       const char *claim, const char *why)
{
    (void)s;

    printf("[observable] link_refused: peer=%s reason=%s fd=%d\n",
           (link != NULL) ? link->name : claim, why, (c != NULL) ? c->fd : -1);
    if (c != NULL) {
        conn_mark_closing(c);
    }
}

/* An accepted claim, on either side. Creates the link if the connection
 * arrived on the listener, then runs INIT -> HANDSHAKE_SENT -> ESTABLISHED.
 *
 * On the ACCEPTING side both transitions happen here, in one step: the peer
 * has already proved itself, and waiting for our own claim to come back before
 * treating the link as a route would put establishment behind a peer's
 * scheduling for no security gain -- our claim is queued, and the peer's
 * silence is then its own T2 to discover.
 *
 * On the DIALLING side the link is already in HANDSHAKE_SENT -- this is the
 * peer's answer to the claim fed_link_promote() sent -- so only the second
 * transition applies. That is why the send below is conditional
 * rather than unconditional: the FSM has no HANDSHAKE_SENT -> HANDSHAKE_SENT
 * edge, and taking it anyway would be the dialling node rejecting the peer
 * that answered it correctly. */
static int fed_claim_accepted(server_t *s, server_link_t *link, conn_t *c,
                              const char *claim, uint64_t peer_epoch)
{
    if (link == NULL) {
        /* A RE-CLAIM FROM A PEER WHOSE LINK WENT AWAY REUSES THE LINK, and this
         * is the second half of the correction in fed_check_federate() step 4.
         * That check now admits a claim for a name this node still holds a link
         * for, and the link is a NAME and a DESTINATION rather than a rival
         * claim -- so the claim has to be applied to IT. Creating a second link
         * for the same name instead would leave two entries in the table for
         * one server, and the second one is a duplicate every uniqueness check
         * from then on has to think about.
         *
         * WHY IT IS SAFE, which is the part that has to be argued rather than
         * assumed: fed_check_federate() has already returned FED_OK, and that
         * now means no ESTABLISHED link and no link holding a descriptor claims
         * this name. So whatever is found here holds no socket, and taking it
         * over cannot displace a live route. It also cannot disturb the
         * dialling side, which finds its link by descriptor in
         * fed_link_of_conn() and never reaches this branch. */
        link = server_find_link(s, claim);
    }
    if (link == NULL) {
        link = fed_link_new(s, claim, 0);
        if (link == NULL) {
            fed_refuse(s, NULL, c, claim, "NO_LINK_ROOM");
            return -1;
        }
    }
    if (link->state == (int)ESTABLISHED) {
        /* The same link, naming itself again. A peer that re-sends its FEDERATE
         * on an already-established link is a bug on its side, and answering it
         * by re-authenticating would let anything that had once learned the
         * secret re-run the exchange forever. Nothing to do. */
        return 0;
    }
    if (link->state == (int)INIT) {
        fed_link_set_state(link, HANDSHAKE_SENT);
        /* created_ms is stamped here as well as at the dial. The dial stamp is
         * what makes the latch; this one is what makes the field mean "when
         * this link's current attempt began", and it is what 3.4's file map
         * describes. */
        link->created_ms = server_now_ms();
        (void)fed_queue_federate(s, link, c);
    } else if (link->state != (int)HANDSHAKE_SENT) {
        /* The link is FAILED or TIMED_OUT -- a terminal state, with the
         * exchange that put it there long since closed. Reached only if
         * something reuses a link that is still in a terminal state, and the
         * correct response is to refuse the connection rather than to drag the
         * FSM backwards: fed_link_reset() is the only reset, and it takes the
         * link back to INIT through fed_link_down(). */
        fed_refuse(s, link, c, claim, "LINK_TERMINAL");
        return -1;
    }
    /* HANDSHAKE_SENT -> ESTABLISHED, on both sides: the accepting side sent
     * its claim above (or already had), the dialling side is answering the
     * claim fed_link_promote() sent. Every FSM transition in this file goes
     * through fed_link_set_state() and no transition goes around it. */
    fed_link_set_state(link, ESTABLISHED);
    fed_link_established(s, link, c, claim, peer_epoch);
    return 0;
}

/* ---------------------------------------------------------------------------
 * The dispatch seam
 * ---------------------------------------------------------------------------
 */

/* Everything the module does about an inbound line. Three cases, in order:
 *
 *   1. FEDERATE -- the only verb this phase gives a peer connection, and the
 *      only one that may make a link. Claimed on ANY connection, not only on
 *      one that is already a link, because an inbound peer arrives on the
 *      listener as an ordinary connection: the accept site has no way to know
 *      it is a peer until it says so, and 2.3 makes the handshake -- not the
 *      accept -- the place a peer is identified. A client that types FEDERATE
 *      is refused by the same checks, which is the documented cost of a peer
 *      handshake being the only way in: the verb is internal (4.3) and a
 *      client has no business sending it.
 *   2. A line on a link that already exists. The stamp is the liveness signal
 *      and the line goes to fed_dispatch(), which reads the 2.4 tags, applies
 *      the hop ceiling and dispatches the verb. It goes through the CLIENT
 *      dispatch to get there -- commands_dispatch() sees src->kind and calls
 *      fed_dispatch() -- because 3's diagram says the peer path is the same
 *      dispatch and that dispatch never asks "is this local or remote?". Two
 *      doors into the guard chain is one too many, and the chain is the only
 *      place 2.4 is enforced.
 *   3. Anything else -- an ordinary client line. Untouched, and handed to the
 *      dispatch that was installed before fed_open(). */
void fed_on_federate(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *self = fed_link_of_conn(s, c);
    uint64_t peer_epoch = 0;
    fed_federate_result_t result;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    /* A FEDERATE in cleartext for a peer this node requires TLS for
     * (issue #221): the line carries the shared secret, so honoring it
     * would both trust a sniffable credential and establish the cleartext
     * link the operator said must be TLS. Refused BEFORE the secret is
     * compared, so the exchange answers nothing about it, and before any
     * link state moves. A plaintext FEDERATE for a peer with no such
     * requirement is untouched, which is what keeps a plaintext mesh
     * working exactly as before. */
    if (transport_is_tls(c) == 0 && m->nparams >= 1 && m->params[0] != NULL) {
        const server_link_t *claimed = server_find_link(s, m->params[0]);

        if (claimed != NULL && claimed->require_tls != 0) {
            fed_reject(s, self, c, FED_TLS_REQUIRED, m->params[0]);
            return;
        }
    }
    result = fed_check_federate(s, self, m, s->fed_secret, &peer_epoch);
    if (result != FED_OK) {
        fed_reject(s, self, c, result, m->params[0]);
        return;
    }
    (void)fed_claim_accepted(s, self, c, m->params[0], peer_epoch);
}

void fed_dispatch_hook(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *link;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* Answered HERE and not by the guard chain's G2, for one reason: at this
         * point the connection is still a CLIENT connection -- fed_link_established()
         * is what sets c->kind to CONN_SERVER -- so commands_dispatch()'s peer
         * branch has not been reached yet and there is nothing to hand the line
         * to. fed_dispatch()'s G2 calls this same function, so a FEDERATE that
         * arrives on an ALREADY-established link goes through both paths and is
         * answered identically: on such a link it is a re-claim, and
         * fed_check_federate() reports DUPLICATE_LINK or NAME_MISMATCH for it. */
        fed_on_federate(s, c, m);
        return;
    }

    link = fed_link_of_conn(s, c);
    if (link == NULL) {
        if (s->fed_inner != NULL) {
            s->fed_inner(s, c, m);
        }
        return;
    }
    /* A received line IS the liveness signal. Stamped HERE and not in
     * core/poll_loop.c so that the loop stays free of any peer concept; see the
     * header. */
    link->last_recv_ms = server_now_ms();
    /* Handed to the client dispatch, which routes a CONN_SERVER connection to
     * fed_dispatch(). THAT IS THE WHO OF IT, and it is one path rather than two:
     * section 3's diagram puts the peer read and the client read through the
     * same dispatch and says dispatch never asks "is this local or remote?" --
     * the only difference is src->kind. Routing from here straight into
     * fed_dispatch() would be a SECOND entry into the peer protocol, and the
     * guards would then have two doors. A line that reaches the client dispatch
     * and is not a peer line falls through to the client verb table, where
     * every S-verb is an unknown command -- which is the correct answer and is
     * counted, not the reason this routing exists. */
    if (s->fed_inner != NULL) {
        s->fed_inner(s, c, m);
    }
}
