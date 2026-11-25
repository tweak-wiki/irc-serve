/* link_queue.c -- see federation/link.h. The outbound FEDERATE sender.
 *
 * Split verbatim out of link.c (issue #543 TU-40): the FEDERATE exchange
 * sender (fed_queue_federate()). It stays declared in federation/link.h
 * (tick.c/link_config.c/link_guard.c/link_accept.c/link_dump.c/link_table.c
 * precedent, no new header); no static helpers move. Reached through link.h
 * by fed_tick() in tick.c and the establishment arm in link_accept.c. The
 * reason spellings (FED_REASON_NAME) + fed_federate_reason() stay in link.c.
 */
#include "federation/link.h"

#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * The exchange
 * ---------------------------------------------------------------------------
 */

/* Queue this node's FEDERATE on a peer connection.
 *
 * It is built rather than formatted, because FEDERATE is not the S-verb of any
 * client verb and fed_send_sverb() takes a client verb and maps it (verbs.h is
 * explicit that the mapping is applied there so no caller can hand it an
 * already-mapped verb).
 *
 * It is ALSO not fed_queue_line(), and that is now a stated decision rather than
 * the leftover of one: fed_queue_line() stamps a 2.4 block, and a FEDERATE
 * carries none. Its epoch and its secret are PARAMETERS, because 2.4's block is
 * what a receiver needs in order to deduplicate and loop-check a message, and a
 * handshake is neither relayed nor looped -- the only thing that ever has to
 * read this line is the peer's handshake code, which is about to look at every
 * field of it. So this line goes through message_build() and message_format()
 * directly, and the three lines of overlap with fed_queue_line() below are the
 * part that has no block to stamp. The cost of not folding this one in is three
 * lines; the cost of folding it in would be a helper with a "no tags here" mode
 * that its other caller could reach by accident. */
int fed_queue_federate(server_t *s, server_link_t *link, conn_t *c)
{
    const char *params[4];
    char epoch[24];
    char secret[IRC_FED_MAX_SECRET];
    char line[IRC_MAX_LINE + 2];
    message_t m;
    size_t len;

    /* 24 bytes for a uint64_t in decimal: 20 digits at the maximum, plus the
     * NUL. The alternative -- a shared buffer sized by an estimate -- is a
     * truncation of the one field 2.4 exists so that a restarted peer is
     * distinguishable from the one it replaced. */
    (void)snprintf(epoch, sizeof epoch, "%llu", (unsigned long long)s->epoch);
    /* A NODE WITH NO SECRET REFUSES TO SEND A CLAIM, and it says so in its own
     * words rather than letting the claim go out with an empty parameter.
     *
     * The reason is the POLICY, and it is now stated on BOTH sides: an inbound
     * FEDERATE on a node with no configured secret is refused with
     * FED_NO_SECRET (fed_check_federate() step 2, which says so at length), so
     * an outbound claim from the same node would be refused by a correctly
     * configured peer with a reason its operator cannot act on -- "your secret
     * is wrong" for a node that has no secret. The operator of the
     * no-secret node is the one who can fix it, and the line that tells them is
     * the outbound one: this node is the one that cannot authenticate anybody.
     *
     * It is a separate reason and not a reuse of UNRENDERABLE because
     * UNRENDERABLE is a message.c failure -- "this line does not fit or does not
     * parse" -- and an operator reading it would go looking for a formatting bug
     * in a module that is behaving exactly as specified. The two are opposites
     * (a message that cannot be built versus a policy that forbids building it)
     * and they belong to different files. */
    if (s->fed_secret_len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=NO_SECRET "
               "configured=0\n",
               link->name);
        return -1;
    }
    memcpy(secret, s->fed_secret, s->fed_secret_len + 1u);

    params[0] = s->name;                        /* our own claim        */
    params[1] = epoch;                          /* our per-boot epoch   */
    params[2] = secret;                         /* the shared token     */
    params[3] = IRC_SERVE_VERSION;              /* the ONE version copy */

    if (message_build(&m, NULL, s->name, "FEDERATE", params, 4) != 0) {
        printf("[observable] link_send_failed: peer=%s reason=UNBUILDABLE\n",
               link->name);
        return -1;
    }
    /* The +2 is reply.c's arithmetic and the reason is the same: IRC_MAX_LINE
     * counts a legal line INCLUDING its CRLF and message_format() reserves a
     * byte for its NUL. */
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=UNRENDERABLE\n",
               link->name);
        return -1;
    }
    /* RFC 1459 2.3. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, c, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated link is DROPPED, not buffered (3.4). Not counted twice. */
        printf("[observable] link_send_failed: peer=%s reason=LINK_SATURATED\n",
               link->name);
        return -1;
    }
    return 0;
}
