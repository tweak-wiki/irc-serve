/* chan_verbs_knock.c -- see core/chan_verbs.h. 4.2's KNOCK.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-45): the KNOCK
 * section (handle_knock()). It stays declared in core/chan_verbs.h (no new
 * header), reached through it by the dispatch table in
 * core/commands_dispatch.c. Its only in-TU dependency is canonical_channel(),
 * now shared through core/chan_verbs.h (chan_split_list/chan_admit precedent).
 */
#include "core/chan_verbs.h"

#include <stdio.h>

#include "core/channel.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * KNOCK
 * ---------------------------------------------------------------------------
 * 4.2's KNOCK, and the answer is a refusal. Everything below is why, because a
 * verb whose entire behaviour is one numeric is exactly the kind of thing that
 * looks like a stub and is not.
 *
 * THE GATE IS AN IRC OPERATOR, NOT A CHANNEL ONE, and this node has no operator
 * flags at all. KNOCK asks the ORIGIN to extend an invitation to a client that
 * is not on the channel, so a client has to be able to ask for a favour the
 * origin will not grant to everybody -- and the only thing the RFC names as that
 * authority is an IRC operator. There is no IRCop concept anywhere in this tree:
 * conn_t has no operator field, 004 advertises a user-mode set of "i" that
 * nothing evaluates, and 5's operator model does not exist. A node that answered
 * KNOCK with 704 RPL_KNOCK would be telling a client that a request was lodged
 * with an origin that has never heard of it, which is the 341-without-the-invite
 * failure this file's INVITE comment describes.
 *
 * SO THE ANSWER DOES NOT DEPEND ON THE CHANNEL, and no +k check is performed.
 * The RFC also allows a server to refuse knocks on a channel with +k set, and
 * that is the check this handler looks like it should have. It is not here
 * because it cannot change the answer on this build: nothing in the tree ever
 * records a 'k' in modes[], so chan_mode_has(ch, 'k') is 0 for every channel
 * this node holds, and a check whose answer is constant is not a check. The
 * observable line prints k_mode anyway, so the log says which gate fired and a
 * reader does not have to guess.
 *
 * WHAT WOULD REPLACE IT, and why it is not here: on a federated mesh the honest
 * implementation is a SKNOCK forwarded to the channel's origin, which then
 * decides. 4.3's frozen S-verb table has no SKNOCK, and §7/Phase 6's own
 * statement that a wire format cannot be invented later is the reason it is not
 * improvised here.
 *
 * 482 rather than 480 ERR_KNOCKPROHIBIT, and neither is in 4.4's list. 482 is
 * the numeric 4.4 does have for "you are not privileged enough for this action"
 * -- the same one KICK and MODE use -- and the trailing text says what the
 * privilege is. A client that receives it has been told the truth about why.
 */
void handle_knock(server_t *s, conn_t *c, const message_t *m)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (m->nparams != 1) {
        (void)reply_refused(s, c, "KNOCK", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* A channel-name check and an existence check, both 403, and both BEFORE the
     * refusal -- so `KNOCK nosuch` and `KNOCK not-a-channel` are answered about
     * the thing the client got wrong rather than about the capability it lacks.
     * That distinction is the only difference a client can act on: one of them
     * is fixable by typing a different channel. */
    if (!canonical_channel(s, c, m->params[0], canonical, sizeof canonical)) {
        return;
    }
    ch = server_chan_get(s, canonical);
    if (ch == NULL) {
        (void)reply(s, c, "403", (const char *const[]){ canonical }, 1,
                    "No such channel");
        return;
    }

    /* 482, WHICH ELSEWHERE ON THIS NODE MEANS "NOT A CHANNEL OPERATOR" and here
     * means "not an IRC operator". That is not a near miss: it is the clearest
     * single piece of evidence for the migration, which is why this site overrides
     * the code. For a negotiating client this is `FAIL KNOCK ERR_NOPRIVILEGES` --
     * which is also the right rendering for the CHOPER refusal in commands.c,
     * because it is the same fact. */
    (void)reply_refused(s, c, "KNOCK", "ERR_NOPRIVILEGES", "482",
                        (const char *const[]){ ch->name }, 1,
                        "You're not an IRC operator");
    printf("[observable] knock_refused: channel=%s nick=%s reason=NO_OPER_FLAGS "
           "k_mode=%d local=%zu\n",
           ch->name, c->nick, chan_mode_has(ch, 'k'), ch->nmembers);
}

