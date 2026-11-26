/* chan_verbs_names.c -- see core/chan_verbs.h. 4.1's NAMES.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-51): the NAMES
 * section (handle_names() plus its section header). It stays declared in
 * core/chan_verbs.h (no new header), reached through it by the dispatch
 * table in core/commands_dispatch.c. Its in-TU dependencies are
 * canonical_channel()/authority_ok() (shared since TU-45/46) and
 * send_names_list()/send_end_of_names() (shared since this split, same
 * precedent; still defined in chan_verbs.c for handle_join()); the rest --
 * server_chan_get/server_chan_count/server_chan_at, reply/reply_refused --
 * already arrive through headers. NAMES_NO_CHANNEL moves with its sole user.
 */
#include "core/chan_verbs.h"

#include <stdio.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/reply.h"

/* The <channel> field of a 366 that answers a bare NAMES on a node with no
 * channels. RFC 2812 5.1 NAMES 366's field list is "<channel> :End of NAMES
 * list" and its own prose for the no-channel case says only "then only
 * RPL_ENDOFNAMES is returned" -- it does NOT say what the channel field holds
 * there, so the RFC defines no value and this is a decision about what a client
 * sees rather than a substitution. It is `*`, and the argument is in
 * docs/RFC2812_CONFORMANCE.md 6.11; the short of it is that the field is where a
 * client looks for the channel a list belongs to, so it must EXIST on every 366
 * or the one reply a client is parsing positionally has three parameters where
 * RFC 2812 promises four. `*` is one byte, is representable in a non-final
 * position (message_format() refuses anything else), and is RFC 1459 2.3's own
 * wildcard -- so a client reading it positionally gets a parseable line and can
 * label the answer "no channels" instead of finding the channel field absent.
 *
 * NAMED so the decision is greppable: this is the only 366 on the node that has
 * no channel to name, and a future site that needs the same answer should pass
 * this rather than spell "*" and re-decide it. */
#define NAMES_NO_CHANNEL "*"

/* ---------------------------------------------------------------------------
 * NAMES
 * ---------------------------------------------------------------------------
 * NAMES on a channel the client is not in is legal: 353 answers with what THIS
 * node knows, which on a single node is the whole roster. The names of members
 * the origin holds are not available until SNAMES carries them (Phase 6), and
 * 2.2's own argument -- the roster belongs to the origin to answer -- is why
 * answering from the local cache is the right shape and not a shortcut.
 */
void handle_names(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams > 1) {
        (void)reply_refused(s, c, "NAMES", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 0) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        if (!canonical_channel(s, c, "NAMES", m->params[0], canonical, sizeof canonical)) {
            return; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            /* 366 with no 353, rather than 403. NAMES is a discovery command:
             * a client calls it to find out whether something is there, and
             * "nobody" is a legitimate answer to exactly that question. RFC 1459
             * 2.3.1 has an unknown channel answered with an empty list. */
            (void)reply(s, c, "366", (const char *const[]){ canonical }, 1,
                        "End of /NAMES list");
            return;
        }
        (void)authority_ok(s, c, ch, "NAMES", 0);
        /* The remote cache is reported whenever a roster is built, because a
         * 353 that lists local members only is incomplete BY DESIGN here and the
         * log is where that fact is visible. Phase 6 fills the rest in. */
        printf("[observable] chan_names: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
        send_names_list(s, c, ch);
        send_end_of_names(s, c, ch->name);
        return;
    }

    /* NAMES with no argument: every channel on the node, in creation order, each
     * with its own 366. */
    if (server_chan_count(s) == 0) {
        /* No channel, and NAMES_NO_CHANNEL rather than no field: 366's field list
         * is "<channel> :End of NAMES list" and the reply still has to carry one,
         * because this is the ONLY line a client gets when it asks a channel-less
         * node what channels there are. See send_end_of_names() for why the value
         * is `*`. */
        send_end_of_names(s, c, NAMES_NO_CHANNEL);
        return;
    }
    {
        size_t sent = 0u;
        size_t truncated = 0u;
        /* Exact live count up front, so the LAST 366 this reply may emit can
         * carry the flag: a capped bare NAMES is wire-visible, uncapped
         * per-channel 366s are byte-identical. */
        size_t live = 0u;

        for (size_t i = 0; i < server_chan_count(s); i++) {
            if (server_chan_at(s, i) != NULL) {
                live++;
            }
        }
        for (size_t i = 0; i < server_chan_count(s); i++) {
            chan_t *ch = server_chan_at(s, i);

            if (ch == NULL) {
                continue;
            }
            if (sent >= (size_t)CHAN_ENUM_MAX) {
                truncated++;
                continue;
            }
            (void)authority_ok(s, c, ch, "NAMES", 0);
            printf("[observable] chan_names: channel=%s local=%zu servers=%zu\n",
                   ch->name, ch->nmembers, ch->nservers);
            send_names_list(s, c, ch);
            if (live > (size_t)CHAN_ENUM_MAX &&
                sent + 1u >= (size_t)CHAN_ENUM_MAX) {
                (void)reply(s, c, "366", (const char *const[]){ ch->name }, 1,
                            "%s", "End of /NAMES list (truncated)");
            } else {
                send_end_of_names(s, c, ch->name);
            }
            sent++;
        }
        if (truncated != 0u) {
            printf("[observable] names_truncated: nick=%s sent=%zu truncated=%zu cap=%d\n",
                   c->nick, sent, truncated, CHAN_ENUM_MAX);
        }
    }
}
