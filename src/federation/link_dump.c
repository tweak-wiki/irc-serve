/* link_dump.c -- see federation/link.h. The observable link dump.
 *
 * Split verbatim out of link.c (issue #543 TU-38): the per-reason dump keys
 * (FED_REASON_KEY) and the dump itself (fed_state_name() + fed_dump()).
 * fed_dump() stays declared in federation/link.h (tick.c/link_config.c/
 * link_guard.c/link_accept.c precedent, no new header); FED_REASON_KEY and
 * fed_state_name() stay static (their sole user moves with them). The stable
 * spellings (FED_REASON_NAME) and fed_federate_reason() stay in link.c.
 */
#include "federation/link.h"

#include <stdio.h>

/* The per-reason keys, for the dump. A table rather than ten literals in a
 * printf because fed_federate_reason() is the other half of the same
 * contract -- the `reason=` on a rejection line and the `rej_*=` beside a count
 * on the dump line are the same set of names, and two hand-written lists are
 * two lists that drift. Index FED_OK is an empty string and is never printed:
 * a line that was accepted is not a rejection. */
static const char *const FED_REASON_KEY[FED_RESULT_COUNT] = {
    "", "rej_arity=", "rej_secret=", "rej_nosecret=", "rej_self=",
    "rej_in_use=", "rej_dup=", "rej_mismatch=", "rej_name=", "rej_epoch=",
    "rej_version=", "rej_tls="
};

/* The observable dump
 * ---------------------------------------------------------------------------
 * Three shapes, deliberately, because they answer three different questions.
 * The headline line says how many peers and how many rejections. The breakdown
 * line says WHICH rejections, and it is a separate line because eight
 * key=value pairs on one line is a line nobody reads the third field of. The
 * per-link lines say the FSM state and the two liveness stamps, which is the
 * split-brain evidence 8 asks for -- a single line per link that also carried
 * the totals would be unreadable past three peers.
 *
 * The reason SPELLINGS and the per-reason keys come from the one pair of
 * tables that fed_federate_reason() and the breakdown read, so the `reason=` on
 * a rejection line and the `rej_*=` beside a count cannot drift apart. That is
 * the failure a reader hits when the two are separate lists and one of them
 * has a typo: every count looks plausible and the name beside it is the wrong
 * one.
 */
static const char *fed_state_name(int state)
{
    /* Read into an int for the same reason fed_federate_reason() does: a
     * handshake_state_t is an enum, and -Weverything's -Wswitch-default and
     * -Wcovered-switch-default cannot both be satisfied by a switch over one. */
    int which = state;

    switch (which) {
    case (int)INIT:
        return "INIT";
    case (int)HANDSHAKE_SENT:
        return "HANDSHAKE_SENT";
    case (int)ESTABLISHED:
        return "ESTABLISHED";
    case (int)FAILED:
        return "FAILED";
    case (int)TIMED_OUT:
        return "TIMED_OUT";
    default:
        return "UNKNOWN";
    }
}

void fed_dump(const server_t *s, const char *why)
{
    uint64_t total_rejected = 0;
    size_t i;
    size_t established = 0;
    size_t links;

    if (s == NULL) {
        return;
    }
    links = server_link_count(s);
    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->state == (int)ESTABLISHED) {
            established++;
        }
    }
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        total_rejected += s->fed_rejected[i];
    }
    /* Why the dump is not gated on s->trace, unlike the per-line trace: a dump
     * is asked for because something is wrong, and the flag that produces the
     * high-volume per-line output is a volume control. The one who needs this
     * line is debugging, and a debug switch that is off in the deployment where
     * the bug reproduces is not a debug switch. */
    printf("[observable] link_dump: why=%s name=%s peers=%zu established=%zu "
           "rejected=%llu\n",
           (why != NULL) ? why : "?", s->name, links, established,
           (unsigned long long)total_rejected);
    /* The breakdown is walked, not listed: eight hand-written key=value pairs
     * would be eight places for a name to be mistyped and eight arguments for a
     * printf, and a loop over the one table cannot disagree with
     * fed_federate_reason(). The total is asserted to agree with the sum here
     * rather than in a test, because a dump whose parts do not add up is worse
     * than no dump -- and the arithmetic is two lines. */
    printf("[observable] link_reject_reasons: ");
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        printf("%s%s%llu", (i > 1u) ? " " : "", FED_REASON_KEY[i],
               (unsigned long long)s->fed_rejected[i]);
    }
    printf("\n");

    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link == NULL) {
            continue;
        }
        /* last_sent and last_recv are the two stamps T3 and T4 compare, and a
         * link dump that does not carry them makes "why did it think the peer
         * was dead" answerable only by reading the other node's log. */
        /* THE RECONNECT SCHEDULE IS ON THIS LINE, and it is here for the reason
         * the other four fields are: an operator reading "why is irc.b not being
         * dialled" needs the retry count, the budget that was spent and the
         * stamp the next attempt is waiting for, and they are all in the same
         * struct as the state they explain. A dump without them would say
         * `state=INIT fd=-1 initiator=1` for a link that is about to be dialled
         * and for one that has given up, and those two need different repairs.
         *
         * gave_up is printed as the COUNT 0/1 rather than as a token because it
         * shares the field with two numbers and a mixed vocabulary on one line
         * is the thing this dump has otherwise been careful to avoid. */
        printf("[observable] link: peer=%s state=%s fd=%d initiator=%d "
               "epoch=%llu last_sent=%llu last_recv=%llu burst_done=%d "
               "retries=%u gave_up=%d retry_at=%llu clean_leave=%d\n",
               link->name, fed_state_name(link->state), link->fd, link->initiator,
               (unsigned long long)link->epoch,
               (unsigned long long)link->last_sent_ms,
               (unsigned long long)link->last_recv_ms, link->burst_done,
               link->retries, link->gave_up,
               (unsigned long long)link->retry_at_ms, link->clean_leave);
    }
    fflush(stdout);
}
