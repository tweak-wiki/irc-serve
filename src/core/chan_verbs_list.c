/* chan_verbs_list.c -- see core/chan_verbs.h. 4.1's LIST.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-46): the LIST
 * section (handle_list()). It stays declared in core/chan_verbs.h (no new
 * header), reached through it by the dispatch table in
 * core/commands_dispatch.c. Its in-TU dependencies are canonical_channel()
 * (shared since TU-45) and authority_ok(), now shared through
 * core/chan_verbs.h (chan_split_list/chan_admit precedent).
 */
#include "core/chan_verbs.h"

#include <stdio.h>

#include "core/channel.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * LIST
 * ---------------------------------------------------------------------------
 * Enumerates EVERY channel on the node, joined or not, and shows a locally
 * orphaned one normally. Both decisions are argued in chan_verbs.h; what matters
 * here is that neither is accidental.
 *
 * 322's count is the LOCAL member count. On a single node that is the whole
 * membership, so the number is exact; on a federated node it excludes members
 * this node has not been told about, and the log line above each row says how
 * many servers hold members it cannot enumerate, so the gap is visible rather
 * than implied. Inventing a total the node cannot know would be the one thing
 * worse than reporting a partial one honestly.
 */
void handle_list(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams > 1) {
        (void)reply_refused(s, c, "LIST", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    char count[24];

    if (m->nparams > 0) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        if (!canonical_channel(s, c, m->params[0], canonical, sizeof canonical)) {
            return; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            (void)reply(s, c, "403", (const char *const[]){ canonical }, 1,
                        "No such channel");
            return;
        }
        (void)authority_ok(s, c, ch, "LIST", 0);
        (void)snprintf(count, sizeof count, "%zu", ch->nmembers);
        (void)reply(s, c, "322", (const char *const[]){ ch->name, count }, 2, "%s",
                    ch->topic);
        printf("[observable] chan_list: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
        (void)reply(s, c, "323", NULL, 0, "End of LIST");
        return;
    }

    (void)reply(s, c, "321", (const char *const[]){ "Channel" }, 1, "Users  Name");
    {
        size_t sent = 0u;
        size_t truncated = 0u;

        for (size_t i = 0; i < server_chan_count(s); i++) {
            chan_t *ch = server_chan_at(s, i);

            if (ch == NULL) {
                continue;
            }
            if (sent >= (size_t)CHAN_ENUM_MAX) {
                truncated++;
                continue;
            }
            (void)snprintf(count, sizeof count, "%zu", ch->nmembers);
            (void)reply(s, c, "322", (const char *const[]){ ch->name, count }, 2, "%s",
                        ch->topic);
            printf("[observable] chan_list: channel=%s local=%zu servers=%zu\n",
                   ch->name, ch->nmembers, ch->nservers);
            sent++;
        }
        if (truncated != 0u) {
            printf("[observable] list_truncated: nick=%s sent=%zu truncated=%zu cap=%d\n",
                   c->nick, sent, truncated, CHAN_ENUM_MAX);
        }
    }
    (void)reply(s, c, "323", NULL, 0, "End of LIST");
}
