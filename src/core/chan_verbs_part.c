/* chan_verbs_part.c -- see core/chan_verbs.h. 4.1's PART.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-49): the PART
 * section (handle_part() plus its section header). It stays declared in
 * core/chan_verbs.h (no new header), reached through it by the dispatch
 * table in core/commands_dispatch.c. Its in-TU dependencies are
 * resolve_joined()/authority_ok() (shared since TU-46/48) and
 * deliver_state_change() (shared since this split, same precedent); the
 * rest -- chan_split_list/chan_member_leave/chan_detach_conn/
 * chan_dispose_if_empty, conn_hostmask/conn_text_strip, reply_refused --
 * already arrive through headers.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * PART
 * ---------------------------------------------------------------------------
 * PART of a channel the client is not in is 442, and the arity check keeps that
 * distinct from 461: "you did not name a channel" and "that is not a channel you
 * are in" are different complaints, and only the second tells a client where it
 * stands.
 */
void handle_part(server_t *s, conn_t *c, const message_t *m)
{
    char store[CHAN_MAX_LIST_ARGS * (CHAN_MAX_NAME + 1u)];
    const char *names[CHAN_MAX_LIST_ARGS];
    const char *reason = (m->nparams > 1) ? m->params[1] : NULL;
    /* THE REASON IS RELAYED, SO IT IS BOUND AND THEN STRIPPED, in that order.
     *
     * `chan_member_leave()` puts a PART's `<reason>` on the wire to every member of
     * the channel, and the FORWARD arm below puts the same string on the link to
     * the origin. With no bound the reason went straight into
     * `deliver_state_change()` -> `fanout_deliver()` -> `send_line()` ->
     * `message_format()`, which refuses a line it cannot represent -- and the only
     * outcome at that depth is a refusal counted on `n_reply_refused`, the counter
     * `reply.c` holds at zero because a non-zero value is a bug report. So one
     * client command was a reachable way to put a non-zero on it.
     *
     * The bound is CHAN_MAX_PART_REASON (255), the same sentence-sized cap as the
     * kick reason, the topic, the away message and the realname. Refused with 417,
     * the numeric this node already uses for "that parameter is longer than I
     * will store". Stripping first would be a regression: a 256-byte reason
     * stripped into a 255-byte buffer truncates to 255 and the check that follows
     * accepts the very input the 417 exists to refuse -- the same ordering
     * `handle_kick()` documents, so the refusal is a function of what the client
     * sent. IT IS DONE ONCE, BEFORE THE LOOP: the same reason goes to up to
     * CHAN_MAX_LIST_ARGS channels, and a strip inside the loop would mean N
     * separate buffers for one string. */
    char clean[CHAN_MAX_PART_REASON + 1u];
    size_t kept_reason = 0;
    size_t raw_reason_len = 0;
    int n;

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "PART", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 2) {
        (void)reply_refused(s, c, "PART", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (reason != NULL) {
        raw_reason_len = strlen(reason);
        if (raw_reason_len > (size_t)CHAN_MAX_PART_REASON) {
            (void)reply_refused(s, c, "PART", NULL, "417", NULL, 0,
                                "Part message is too long");
            printf("[observable] chan_part_refused: nick=%s reason=too_long "
                   "len=%zu max=%d\n",
                   c->nick, raw_reason_len, CHAN_MAX_PART_REASON);
            return;
        }
        kept_reason = conn_text_strip(clean, sizeof clean, reason, STRIP_STORED);
        reason = clean;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        (void)reply_refused(s, c, "PART", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        chan_t *ch = resolve_joined(s, c, "PART", names[i]);
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];
        chan_verdict_t verdict;

        if (ch == NULL) {
            continue;
        }
        verdict = authority_ok(s, c, ch, "PART", 1);
        if (verdict == CHAN_VERDICT_REFUSED) {
            continue; /* 437 already sent */
        }
        if (verdict == CHAN_VERDICT_FORWARD) {
            /* No local write, and the client is NOT told: it left a channel it
             * was on, locally, and that is a fact about this node's membership
             * that no origin can undo. A PART is not a state change to the
             * channel's state -- it is a withdrawal from it -- and 2.2's
             * single-writer rule is about the channel's state, so the local half
             * runs on both paths. What differs is the forward: on a non-owned
             * channel the departure has to reach the origin too, or its roster
             * keeps a member this node no longer has. */
            if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
                continue;
            }
            params[0] = (reason != NULL) ? reason : c->nick;
            deliver_state_change(s, c, ch, "PART", prefix, params,
                                 (reason != NULL) ? 1 : 0);
        }
        /* The echo reaches the parting client too because it is still a usable
         * connection and RFC 1459 2.3.1 has it see its own departure -- which is
         * the SAME emission the origin gets, so the local write is the forwarding
         * row's write on an owned channel and this explicit one on a non-owned
         * one, where 3.1 forbids a second pass through the table. */
        chan_member_leave(s, ch, c, 1, reason);
        (void)chan_detach_conn(c, ch);
        if (kept_reason != raw_reason_len) {
            /* Once per channel the client left, and only when something was
             * dropped. A client that names five channels in one PART gets five
             * lines, which is the right count: each is a separate channel's
             * departure and each was a separate relay. */
            printf("[observable] chan_part_stripped: channel=%s nick=%s in_len=%zu "
                   "kept_len=%zu reason=CONTROL_BYTES\n",
                   ch->name, c->nick, raw_reason_len, kept_reason);
        }
        /* Disposal AFTER the departure, and this is the only place a PART frees
         * a channel. A channel with no local members AND no remote members has
         * nothing left to be authoritative about; one with remote members
         * survives, which is the servers[] cache earning its place. */
        (void)chan_dispose_if_empty(s, ch);
    }
}
