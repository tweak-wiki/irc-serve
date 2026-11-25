/* departure.c -- the departure half: the SQUIT announcement, the link teardown,
 * the clean-leave latch, the shutdown drain and the operator's reset door.
 *
 * Split out of federation/link.c (issue #543). Verbatim moves; the public
 * functions are declared in federation/link.h, fed_link_down() in
 * federation/departure.h. */
#include "federation/departure.h"

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
/* Phase 9: 2.1's remote-nick registry, swept from fed_tick() because a store
 * whose owner never ticks it never expires anything. */
#include <arpa/inet.h>
#include <netinet/in.h>

#include "federation/nickreg.h"
#include "federation/verbs.h"
/* ---------------------------------------------------------------------------
 * THE DEPARTURE ANNOUNCEMENT, AND WHY IT IS NOT A ROW IN THE S-VERB TABLE
 * ---------------------------------------------------------------------------
 * Tell this node's remaining peers that THIS NODE'S OWN NAME is going away,
 * because a link just went down. It is a SQUIT -- 4.3's word for exactly this --
 * and it is emitted from the link LIFECYCLE rather than from any of the five
 * fan-out arms, because there is no client emission to fan out: nothing on this
 * node asked for anything, a socket did.
 *
 * IT IS NOT IN S_VERBS, and that is the same conclusion the T3 keepalive reaches
 * from the other side, for the same reason and with the same citation:
 * tests/integration/test_fed_wire.c asserts the contents of that table, and 4.3's
 * list is the FORWARDED vocabulary -- verbs a node relays. A node announcing its
 * own departure relays nothing. Putting `{"SQUIT", "SQUIT"}` in that table would
 * also be meaningless, because the column on the left is a CLIENT verb and no
 * client sends one; a row there would claim that a client's SQUIT is forwarded,
 * which is a claim about the client surface that this node does not implement
 * and would not implement. So the verb is named here and the shared
 * render-and-queue step (fed_queue_line(), stamp the 2.4 block, build, render,
 * bound-check, terminate, queue) is the same one T3 and fed_send_sverb() use.
 *
 * ONE ID FOR THE WHOLE FAN-OUT, which is a deliberate difference from
 * fanout_forward_sverb()'s per-target minting, and the reason is 2.4's dedup
 * scope. The store is PER NODE, not per peer, so a node reachable by two of this
 * node's peers sees the same (origin, epoch, id) twice and MUST drop the second:
 * that is what the per-node rule is for. Minting per peer would make the two
 * copies two different keys, so the third node would apply the purge twice and
 * store two entries for one message. This is one message with several targets.
 *
 * THE COST, stated because it is a real one: the fan-out is a broadcast to every
 * ESTABLISHED link, which is 3.1's amended owned/`state-change` row rather than
 * a unicast, so on a large mesh one link failure costs one line per peer. It is
 * paid on a link event, which is rare, and the alternative -- telling nobody --
 * leaves every peer holding a roster for a server that is not there until the
 * next burst, and driving bursts is Phase 9.
 *
 * AND THE SENTENCE THIS SENDS IS WIDER THAN THE EVENT, which is a property of
 * the TRIGGER rather than of this function: the event is ONE link going down,
 * and the sentence is "this node's name is gone". On a mesh where this node is
 * still reachable by somebody else, a peer told here purges a roster for a
 * server that is still there, and the roster comes back from a later SJOIN or
 * the next burst -- which Phase 9 owns. That is the price of telling anybody at
 * all, and it is bounded only by that policy, so it is written down here rather
 * than left for a reader to discover as a stale roster on a live server. A reader
 * who thinks it should be "my link to you is down" instead should read
 * 7/Phase 9, which is where the answer belongs.
 */
/* fed_send_squit_named() -- the departure announcement, for a NAMED server.
 *
 * IT IS THE BODY OF THE OLD fed_send_squit() WITH ONE PARAMETER ADDED, and the
 * parameter is which server the sentence is about rather than which link died.
 * There are now two callers and they say different things:
 *
 *   fed_send_squit(s, dying)          "THIS node's name is gone" -- from
 *                                     fed_link_down(), when one of this node's
 *                                     links has gone away.
 *   fed_send_squit_named(s, name, l)  "THE SERVER CALLED `name` is gone" -- from
 *                                     the SHUTDOWN handler, when a peer told this
 *                                     node it is leaving.
 *
 * The second is new in Phase 9 and it is the same sentence with a different
 * subject, so it is the same function. Writing a second one would be a second
 * implementation of "one id for the whole fan-out, skip the link it came from,
 * skip the link named by the line", and that is the part that has to be right:
 * two implementations of 2.4's per-node dedup is how a node ends up purging the
 * same origin twice.
 *
 * AND THE `victim != NULL` CASE IS WHAT A SHUTDOWN NEEDS, because a SQUIT naming
 * this node is refused by the receiver (fed_in_squit's own-origin check) and a
 * SQUIT naming the departing peer is not: the receiver is not that peer, and the
 * claim is true. That asymmetry is the whole of why forwarding a SQUIT rather
 * than relaying a SHUTDOWN is correct -- see fed_in_shutdown()'s comment. */
int fed_send_squit_named(server_t *s, const char *server,
                         const server_link_t *dying)
{
    irc_serve_tags_t tags;
    const char *params[1];
    fed_queue_why_t why = FED_QUEUE_OK;
    size_t targets = 0;
    int sent = 0;

    if (s == NULL) {
        return 0;
    }
    /* COUNTED FIRST, AND THE COUNT IS WHAT MAKES THE "NO ID SPENT" DECISION.
     * core/fanout.c says the same about a forward that is refused before it is
     * stamped: the ids come from a per-SERVER counter and a hole in that sequence
     * is a hole in the sequence, and nothing requires it to be contiguous. It is
     * still not free, so a node whose only ESTABLISHED link is the one that just
     * went -- the ordinary TWO-NODE mesh, where this announcement has nobody to
     * go to -- spends no id and prints nothing. */
    for (size_t i = 0; i < s->nlinks; i++) {
        if (&s->links[i] == dying) {
            /* The link that died is NOT a peer this is told through, and the
             * reason is the wire rather than taste: its caller is about to mark
             * that connection CLOSING, so a line queued onto it is a line nobody
             * will read, and counting it as a peer told would be a claim the wire
             * does not support. The far side of a dead link learns this node is
             * gone from the link, which is the channel the event arrived on. */
            continue;
        }
        if (s->links[i].state == (int)ESTABLISHED &&
            server_link_conn(s, &s->links[i]) != NULL) {
            targets++;
        }
    }
    if (targets == 0u) {
        return 0;
    }

    memset(&tags, 0, sizeof tags);
    memcpy(tags.origin, s->name, strlen(s->name) + 1u);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0; /* originated here, so it leaves at zero (2.4) */

    /* SQUIT <server>: the name of the server that is going away. verbs.h freezes
     * the shape; the [optional reason] is not sent because nothing on this node
     * has one to give for its own departure, and an unused field on a wire format
     * is a field a second implementation has to guess about. The SHUTDOWN
     * forwarder DOES have a reason and deliberately does not send it: the reason
     * is in the receiving node's log, and a second implementation of this line
     * would have to decide whether to forward it too. */
    params[0] = (server != NULL) ? server : s->name;

    for (size_t i = 0; i < s->nlinks; i++) {
        conn_t *c;

        if (&s->links[i] == dying || s->links[i].state != (int)ESTABLISHED) {
            continue;
        }
        c = server_link_conn(s, &s->links[i]);
        if (c == NULL) {
            continue;
        }
        if (fed_queue_line(s, c, &tags, s->name, "SQUIT", params, 1, &why) != 0) {
            /* Reported, not swallowed, for the reason every other refusal in
             * this module is: a node that failed to announce its departure and
             * says nothing looks exactly like a node whose peers are all silent,
             * and the two have opposite fixes. server_queue() has already
             * counted a saturated link and marked it CLOSING (3.4), so this is
             * the report and not a second count. */
            printf("[observable] fed_squit_send_failed: self=%s peer=%s reason=%s\n",
                   s->name, s->links[i].name, fed_queue_why_name(why));
            continue;
        }
        sent++;
    }
    printf("[observable] fed_squit_sent: self=%s peers=%d id=%llu server=%s\n",
             s->name, sent, (unsigned long long)tags.id, params[0]);
    return sent;
}

/* The link back to INIT, keeping `initiator` and the address.
 *
 * `announce` says whether this node's own departure is announced to its OTHER
 * peers, and the parameter exists because the two callers that arrive here
 * without a route having ever existed MUST NOT announce, and the reason is a
 * hazard rather than a tidiness concern.
 *
 * A SQUIT for this node's own name tells every peer holding it to purge this
 * node's roster and its name from its channels' servers[]. A link that was
 * ESTABLISHED and has gone away genuinely means those peers should do that --
 * they cannot reach this node through that link any more. A link whose HANDSHAKE
 * NEVER COMPLETED means the opposite: it is a socket that was opened and never
 * authenticated, so no peer ever received a burst attributed to this node
 * through it, and the other links are still up. Announcing on that path would
 * tell the whole mesh that a node is gone when it is serving, and every peer
 * would purge a live node's roster. That is not a smaller version of the
 * announcement; it is a different and wrong statement, and it is the reason the
 * flag is a parameter rather than something every caller inherits from the
 * shared body.
 *
 * The cost of the parameter is one argument at three call sites and the
 * possibility of a caller passing the wrong value -- which is why each call site
 * carries the argument in the name at its call and not only in the comment here. */
void fed_link_down(server_t *s, server_link_t *link, int announce)
{
    if (link == NULL) {
        return;
    }
    /* THE DEPARTURE GOES OUT FIRST, while the other links are still up, and the
     * order is the whole point: this announcement is queued onto peers' write
     * queues, and every step below either closes a descriptor or forgets that a
     * peer existed. A SQUIT emitted afterwards would be a line on a link the node
     * has already stopped believing in. */
    if (announce != 0) {
        (void)fed_send_squit_named(s, NULL, link);
    }
    /* Everything below is a no-op on a link that never established, which is
     * what made it safe to share the body in the first place: the epoch is
     * already 0, burst_done is already 0, the stamps are already 0, and
     * fed_burst_abandon() on a link with no transaction open returns at once. */
    fed_link_set_state(link, INIT);
    link->fd = -1;
    /* A link that has gone down has learned nothing about its peer's current
     * boot, and 4.3's burst carries the origin's epoch, so leaving the old one
     * here would be a resync attributing a burst to the wrong boot. The
     * re-linking server of the same name is a fresh handshake and says so
     * again. */
    link->epoch = 0;
    /* A link that reconnects has not applied its burst, whatever this one did.
     * 4.3 says a resync REPLACES rather than merges, and the flag is what makes
     * that true of a link that comes back. */
    link->burst_done = 0;
    /* AND THE IN-FLIGHT TRANSACTION GOES WITH IT. A burst that never reached its
     * terminator because the link died has nothing to compare its counts against,
     * and leaving the shadow open would mean the next burst on this link's name
     * started by appending to a half-built one -- which is a state this node
     * cannot explain and no reader of the counters could. The BEGIN in the next
     * burst would discard it anyway; discarding it here means the discard is
     * reported against the link that went down rather than against the next
     * burst, which is where an operator looking for a flapping link will look. */
    fed_burst_abandon(s, link);
    link->last_sent_ms = 0;
    link->last_recv_ms = 0;
    /* AND THE PEER'S LAST ADVERTISED FIGURE GOES WITH IT. A link that has gone down
     * has learned nothing about its peer's CURRENT load, and leaving the number here
     * would make T8 report a busy peer from a link that is no longer up -- the same
     * category of error as leaving the old epoch behind a few lines above, where the
     * comment gives the reason. `load_seen_ok` goes with it so a re-established link
     * is a link that has heard nothing, rather than one whose silence is inherited
     * from the previous connection.
     *
     * The shed LATCH is not cleared here, and that asymmetry is deliberate: it is
     * cleared by fed_link_reset() (the operator's door) and by an advertisement that
     * arrives BELOW the threshold, and not by the link going down. A link that dies
     * while its peer is busy has not been contradicted -- T4 is about to declare the
     * peer dead and report that far more loudly -- so re-arming the latch here would
     * buy one extra line per link cycle on a mesh that is already printing a dead
     * peer, which is noise rather than information. */
    link->load_seen = 0u;
    link->load_seen_ok = 0;
    fed_dump(s, "link_down");
}

/* ---------------------------------------------------------------------------
 * Phase 9 item 4: the two verbs, and the three functions they need
 * ---------------------------------------------------------------------------
 */

/* Mark (or unmark) a link as CLEANLY DEPARTED, and tell the caller whether
 * anything changed.
 *
 * IT SETS `clean_leave` AND NOTHING ELSE, and the narrowness is the point: this
 * function does not close a socket, does not purge a roster and does not arm or
 * disarm a retry. Those are three other pieces of the departure, they happen in
 * three different places, and the flag is the one thing they have in common --
 * so putting the flag in its own function means the OTHER two cannot
 * accidentally depend on it and start skipping the purges.
 *
 * `clear` exists for exactly one caller, fed_link_reset(), and it is a parameter
 * rather than two functions because the two are the same statement with a sign.
 * A caller that wants to clear it has to say so at the call, which is the same
 * reasoning the `announce` parameter of fed_link_down() makes. */
int fed_mark_clean_leave(server_t *s, server_link_t *link, int set)
{
    int was;

    if (s == NULL || link == NULL) {
        return 0;
    }
    (void)s;
    was = link->clean_leave;
    if (set != 0) {
        if (was == 0) {
            printf("[observable] link_clean_leave: peer=%s reason=PEER_SHUTDOWN\n",
                   link->name);
        }
        link->clean_leave = 1;
    } else {
        link->clean_leave = 0;
    }
    return (was != link->clean_leave) ? 1 : 0;
}

/* Bounded write drain for one link's goodbye, and the local mark when the
 * budget runs out. conn_pump_locked() moves whatever the socket takes RIGHT
 * NOW and stops at the first RETRY; on a saturated peer that leaves the
 * SHUTDOWN queued behind a backlog, and the close() a few lines later in
 * the caller discards it. So the goodbye waits for writability: poll(POLLOUT)
 * for what is left of the shared deadline, pump again, stop when the queue
 * is empty or the budget is spent. EINTR counts as spent -- a signal during
 * teardown is not a reason to wait longer.
 *
 * The caller holds c->wq_lock across the call, for the #326/#290 reason the
 * pump's own comment gives: at N > 0 a writer's SSL_write on the same conn
 * would otherwise race this pump's SSL_write. The deadline is one per
 * goodbye shared by every link (FED_SHUTDOWN_FLUSH_MS), so ten slow peers
 * cost no more than one.
 *
 * UNDRAINABLE MEANS MARKED, NOT RETRIED: returns 0 with link->clean_leave
 * set and an observable printed when bytes are still queued, because a
 * server_t that is shut down can be re-opened (see fed_close()) and a
 * reopened node must not spend a retry budget redialling a peer it
 * intentionally left. fed_mark_clean_leave() is not used because its line
 * names the PEER's shutdown; here the announcer is the one leaving. 1 means
 * the queue is on the wire. */
int fed_drain_writes(server_t *s, server_link_t *link, conn_t *c,
                     uint64_t flush_stop)
{
    if (s == NULL || link == NULL || c == NULL) {
        return 0;
    }
    for (;;) {
        uint64_t now;
        struct pollfd pfd;

        if (conn_write_pending_held(c) == 0u) {
            return 1; /* the queue is on the wire: nothing to wait for */
        }
        now = server_now_ms();
        if (now >= flush_stop) {
            break; /* budget spent: close() carries what it carries */
        }
        if (c->fd < 0) {
            break; /* no descriptor to wait on */
        }
        memset(&pfd, 0, sizeof pfd);
        pfd.fd = c->fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1u, (int)(flush_stop - now)) <= 0) {
            break; /* timeout or error: no writability within budget */
        }
        if (conn_pump_locked(c) < 0) {
            conn_mark_closing(c);
            break;
        }
    }
    link->clean_leave = 1;
    printf("[observable] fed_shutdown_undrained: self=%s peer=%s "
           "pending=%zu\n",
           s->name, link->name,
           conn_write_pending_held(c));
    return 0;
}

/* Send `SHUTDOWN [:reason]` to every ESTABLISHED link. Returns how many carried
 * it.
 *
 * IT IS CALLED FROM server_shutdown() AND FROM NOWHERE ELSE, which is the
 * definition of a graceful leave: this node is going away, it says so, and then it
 * goes. The alternative -- saying nothing and letting every peer discover it by
 * timeout -- is what the mesh already does for a CRASH, and making a clean exit
 * look like a crash is how a planned restart turns into a burst of retry budgets
 * and redials on every peer on the mesh.
 *
 * AND IT IS BEST EFFORT, with the limit stated because it is a real one: the
 * line is QUEUED and the write queue is flushed by fed_drain_writes() -- a
 * bounded poll(WRITE) wait -- after the first pump, so a peer that stays
 * unwritable past the budget still loses the SHUTDOWN. That degradation is
 * correct rather than a defect: the peer that does not hear it treats the closed
 * socket as a failure, applies its retry policy, and finds the node gone. The
 * cost of the message is that a clean leave occasionally reads as a failure, and
 * the cost of not sending it is that EVERY clean leave reads as one. */
int fed_send_shutdown(server_t *s, const char *reason)
{
    irc_serve_tags_t tags;
    const char *params[1];
    fed_queue_why_t why = FED_QUEUE_OK;
    size_t targets = 0u;
    int sent = 0;
    uint64_t flush_stop;

    if (s == NULL) {
        return 0;
    }
    for (size_t i = 0; i < s->nlinks; i++) {
        if (s->links[i].state == (int)ESTABLISHED &&
            server_link_conn(s, &s->links[i]) != NULL) {
            targets++;
        }
    }
    if (targets == 0u) {
        return 0;
    }
    /* THE WRITE-DRAIN BUDGET, ONE DEADLINE FOR EVERY LINK. The per-link loop
     * below polls a saturated socket until it turns writable, and an
     * unbounded wait there would hang teardown on one dead peer -- while a
     * per-link budget would let ten slow peers cost ten times the wait. So
     * the deadline is taken once, here, and every link drains against what
     * is left of it. */
    flush_stop = server_now_ms() + FED_SHUTDOWN_FLUSH_MS;
    memset(&tags, 0, sizeof tags);
    memcpy(tags.origin, s->name, strlen(s->name) + 1u);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0;
    /* The reason is omitted rather than sent, and the reason is worth stating
     * because a reader will look for it: 4.3's verb list does not have SHUTDOWN,
     * so its shape is this phase's to choose, and a field a second implementation
     * has to guess about is a compatibility break bought for nothing. The
     * receiver's log says WHO left, which is the fact a reader wants. */
    (void)params;
    for (size_t i = 0; i < s->nlinks; i++) {
        conn_t *c;
        int ok;

        if (s->links[i].state != (int)ESTABLISHED) {
            continue;
        }
        c = server_link_conn(s, &s->links[i]);
        if (c == NULL) {
            continue;
        }
        ok = fed_queue_line(s, c, &tags, s->name, "SHUTDOWN", NULL, 0, &why);
        if (ok == 0) {
            sent++;
            /* MT 3.2 (#326): THE PUMP JOINS THE DRAIN UNDER c->wq_lock, and the
             * lock below covers BOTH transport calls. conn_pump() takes the
             * lock itself, so this site calls the _locked variant: at N > 0 a
             * writer's SSL_write on the same conn would otherwise race this
             * pump's SSL_write (and the drain's SSL_read) with no
             * serialization, corrupting the SSL* or truncating the goodbye.
             * The drain's own comment carries the lock-order argument; it holds
             * here unchanged (this site takes wq_lock alone, writers are
             * joined only after). N = 0 is unchanged: an uncontended lock. */
            pthread_mutex_lock(&c->wq_lock);
            if (conn_pump_locked(c) < 0) {
                conn_mark_closing(c);
            }
            /* THE BOUNDED WRITE DRAIN: what makes the goodbye leave a busy
             * socket, and the local clean_leave mark when the budget runs
             * out. See fed_drain_writes() for the whole argument. */
            (void)fed_drain_writes(s, &s->links[i], c, flush_stop);
            /* THE DRAIN, AND IT IS WHAT MAKES THE GOODBYE SURVIVE ITS OWN CLOSE.
             *
             * server_shutdown() closes this socket a few lines of C later, and a
             * close() on a socket whose RECEIVE queue still holds unread data makes
             * the kernel send RST instead of FIN. An RST discards whatever the peer
             * has not yet read -- which here is the SHUTDOWN just pumped above, in
             * flight, not yet delivered. The departing node then announces its
             * departure and the peer never hears it, marks nothing clean, and arms
             * the whole retry ladder: the exact outcome this function exists to
             * prevent, arriving through the goodbye itself.
             *
             * It IS NOT HYPOTHETICAL, and it was found by this phase's own test
             * rather than reasoned about: with the peer sending keepalives every
             * 60 ms, a peer link closed with a PING still unread reproduced it in
             * roughly one run in fifteen, and the symptom was a receiver reporting
             * `conn_close: reason=read_error` and a link declared DEAD rather than
             * cleanly departed. One in fifteen is a flaky test, and behind it is a
             * goodbye that fails one time in fifteen in the field.
             *
             * WHAT IS DISCARDED, and why that is safe: whatever the peer sent in the
             * last few milliseconds, on a link this node is about to stop having. It
             * cannot be acted on -- there is no loop left to act in it -- and reading
             * it into the conn's own buffer would be worse, because the conn is freed
             * a few lines later and the bytes would go with it unframed. Draining to a
             * scratch and forgetting them is the honest description of what happens to
             * a peer's last words during a shutdown.
             *
             * THERE IS NO BYTE CAP ON THIS LOOP, and removing the old 8 KiB one
             * is the fix: one TLS record is 16 KiB, so a peer with more than 8 KiB
             * pending stopped the drain early and the close that followed was an
             * RST that ate the SHUTDOWN. The loop stops on EAGAIN (empty queue),
             * on EOF, or on a read error -- every one of those means there is
             * nothing left that a close() could RST over. It cannot spin on an
             * idle peer (RETRY breaks), and a peer streaming faster than a
             * nonblocking drain during our own shutdown is not a case that
             * exists. The cost is a recv() per pending chunk on the way out,
             * on a path that runs once per process.
             *
             * MSG_DONTWAIT rather than relying on the socket's flags: the drain must
             * not be able to block a teardown even if some other code path made this
             * descriptor blocking, and a blocking recv() in server_shutdown() would be
             * a hang rather than a missed goodbye.
             *
             * PHASE 12: IT READS THROUGH transport_recv(), AND THAT IS THE WHOLE
             * REASON THIS BLOCK IS NOT A recv(). This is the third and last of the
             * tree's three I/O sites, and it is the one most easily left behind because
             * it is a read into a sink rather than a read into the connection: on a
             * TLS peer link a raw recv() would pull CIPHERTEXT into a stack buffer and
             * count it as "drained", which is at best a wrong number on a log line and
             * at worst a handshake failure on the way out of the node. The transport
             * answers in its own four-value vocabulary -- bytes, EOF, TRANSPORT_RETRY,
             * TRANSPORT_FATAL -- and TRANSPORT_FATAL is the one case this loop must not
             * spin on: it breaks, which is what the old `break` on a non-EINTR error
             * did. The cost of this path on a plaintext mesh is one function
             * call per pending chunk on a path that runs once per process.
             *
             * MT 3.1 (#290): THIS DRAIN RUNS UNDER c->wq_lock, and that is the
             * fix rather than decoration. transport_recv() on a TLS link is
             * SSL_read on the conn's SSL*, and OpenSSL forbids concurrent use
             * of one SSL* -- so at N > 0 a writer's SSL_write on the same conn
             * would race this call and corrupt the SSL state or crash inside
             * libssl. conn_fill() and conn_pump() already hold wq_lock across
             * their transport calls (connection.c, caller-holds contract); this
             * drain is the third transport_recv site and holds the same lock.
             * NO DEADLOCK: the loop breaks on TRANSPORT_RETRY, so it never
             * waits on a writer, and the only caller is server_shutdown(),
             * which holds neither wq_lock nor reg_mu here (writers are stopped
             * AFTER, and the order reg_mu -> wq_lock is never inverted because
             * this site takes wq_lock alone). */
            {
                char sink[512];
                size_t drained = 0u;

                for (;;) {
                    ssize_t got = transport_recv(c, sink, sizeof sink);

                    if (got > 0) {
                        drained += (size_t)got; /* counted for the log line only */
                        continue; /* more may be pending: stop only on RETRY/EOF */
                    }
                    /* BREAK ON TRANSPORT_RETRY, AND THAT IS NOT AN INVERSION OF
                     * THE OLD LOOP -- IT IS THE OLD LOOP.
                     *
                     * The pre-Phase-12 code was `if (got < 0 && errno == EINTR)
                     * continue; break;`, so it retried ONLY on EINTR and BROKE on
                     * EAGAIN, because EAGAIN is the kernel saying the peer's queue
                     * is empty -- which is the very condition the drain exists to
                     * reach. An earlier version of this block treated every
                     * TRANSPORT_RETRY as "try again", which made an idle peer link
                     * spin here for ever: six federation tests hung at nf_stop()
                     * until the harness's own 15 s deadline killed them, with the
                     * node reporting perfectly healthy counters the whole time.
                     * The transport cannot distinguish "empty" from "parked on a
                     * write", and for a drain both mean the same thing: stop. */
                    break; /* EOF, EAGAIN, or a fatal transport error: stop */
                }
                if (drained > 0u) {
                    /* PRINTED, because "the goodbye was discarded by the close" is
                     * otherwise indistinguishable from "the peer was deaf", and the
                     * two have completely different fixes. A non-zero figure here
                     * means this node's departure nearly went unannounced. */
                    printf("[observable] fed_shutdown_drained: self=%s peer=%s "
                           "bytes=%zu before=RST_avoided\n",
                           s->name, s->links[i].name, drained);
                }
            }
            pthread_mutex_unlock(&c->wq_lock);
        } else {
            printf("[observable] fed_shutdown_send_failed: self=%s peer=%s reason=%s\n",
                   s->name, s->links[i].name, fed_queue_why_name(why));
        }
    }
    if (sent > 0) {
        s->n_fed_shutdown_announced += (uint64_t)sent;
        printf("[observable] fed_shutdown_sent: self=%s peers=%d\n", s->name, sent);
    }
    (void)reason;
    return sent;
}

void fed_link_reset(server_t *s, server_link_t *link)
{
    if (link == NULL) {
        return;
    }
    /* A FULL second chance, not one more attempt against a spent budget. The
     * budget is a count of consecutive failures and the reset spends a fresh
     * one, so an operator who resets a link has not decided to allow exactly one
     * more knock -- they have decided the node was wrong and should try again
     * from the start. retry_at_ms goes to 0 as well, which is what makes the
     * next tick dial IMMEDIATELY rather than after a backoff the operator did
     * not ask for: this is the escape hatch, and an escape hatch that made you
     * wait would be a second-class one. */
    link->retries = 0u;
    link->gave_up = 0;
    link->retry_at_ms = 0u;
    /* created_ms is NOT the latch any more -- see the retraction block in the
     * header -- but it is cleared here anyway, and the reason is that T2
     * compares against it. A reset that left the attempt stamp in place would
     * put a link that has just been told to try again straight into the
     * handshake timeout on the tick after it dials, because the stamp would
     * already be older than IRC_FED_HS_TIMEOUT_MS. */
    link->created_ms = 0;
    /* AND THE SHED LATCH IS CLEARED, and it is here because this is the operator's
     * door and nothing else clears it. An operator who resets a link after seeing a
     * busy peer wants to hear about it again if it happens again, and a latch that
     * outlived the operator's reset would report a crossing once per PROCESS rather
     * than once per event. The stored figure itself is deliberately KEPT: what that
     * peer advertised is still true and T8 re-evaluates it against the live
     * threshold, so a peer that is still above the line is reported again on the
     * next tick -- which is the correct reading of "reset this link and tell me
     * again", as opposed to forgetting what the peer said. */
    link->shed_reported = 0;
    /* #541: the resync fingerprint goes with the reset. The operator is saying
     * "start over with this peer", and a skip would be the opposite of that:
     * the next establishment bursts in full and re-earns its ack. (The
     * ordinary link-down path deliberately does NOT clear this -- surviving
     * the drop is what makes a flap cheap.) */
    link->burst_valid = 0;
    link->burst_ack_id = 0u;
    /* AND THE CLEAN LEAVE IS UNDONE, which is the ONLY thing that undoes it, and
     * the reason is the OPERATOR. A peer that said goodbye is not dialled again,
     * so an operator who resets the link is the only way back -- and that is the
     * right asymmetry: a mesh should not re-adopt a departing server on its own,
     * and an operator who has decided otherwise should not have to edit a
     * configuration file to say so. */
    (void)fed_mark_clean_leave(s, link, 0);
    printf("[observable] link_retry_reset: peer=%s\n", link->name);
    /* ANNOUNCED, and deliberately so even when the link being reset never
     * established: fed_link_reset() is the OPERATOR's door, and an operator who
     * resets a link is saying "I am taking this node off this peer for now" --
     * which is a departure from the mesh's point of view whatever the link's own
     * state was, and peers that keep a roster for a node its operator has
     * declared off-link are holding state that is wrong. The automatic path (T2)
     * does NOT announce, and the difference is fed_link_down()'s parameter. */
    fed_link_down(s, link, 1);
}
