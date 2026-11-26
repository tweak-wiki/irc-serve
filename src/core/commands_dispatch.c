/* commands_dispatch.c -- see commands_dispatch.h. The command table and the
 * dispatch seam both a client line and a peer line arrive at, verbatim out of
 * commands.c; handle_motd() lives in commands_welcome.c and is named through
 * commands_welcome.h.
 */
#include "core/commands_dispatch.h"

/* Every handler family below is named by the table through its own header;
 * the table is their only caller. */
#include "core/commands_account.h"
#include "core/commands_auth.h"
#include "core/commands_conn.h"
#include "core/commands_choper.h"
#include "core/commands_info.h"
#include "core/commands_register.h"
#include "core/commands_setname.h"
#include "core/commands_starttls.h"
#include "core/commands_welcome.h"
#include "core/batch.h"
#include "core/label.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/fanout_forward.h"
#include "core/msg_verbs.h"
#include "core/reply.h"
#include "core/server.h"
#include "federation/dispatch.h"

/* ---------------------------------------------------------------------------
 * CAP and AUTHENTICATE (Phase 8)
 * ---------------------------------------------------------------------------
 * Both are pre-registration verbs, and BOTH HAVE TO BE: the protocol puts CAP
 * before NICK and USER, and RFC 4422's SASL is answered inside the registration
 * burst rather than after it. Marking either `pre_reg = 0` would answer 451 to a
 * client that is doing exactly what the specification says, which is the failure
 * that hangs every modern client.
 *
 * The handlers live here rather than in cap.c and a new sasl handler file because
 * this is the dispatch table and a verb with no entry here cannot be reached at
 * all. The LOGIC lives in cap.c and sasl_framework.c; these two functions are the
 * wire. */

/* ---------------------------------------------------------------------------
 * The command table
 * ------------------------------------------------------------------------ */

/* Every verb 4.1 lists is HERE, with a NULL handler for the ones a later phase
 * implements. That is not padding: it is what lets the node tell "I have never
 * heard of JOIN" (421) from "JOIN arrives in Phase 4" (also 421, because the
 * wire has no numeric for "not yet"), and the [observable] line records which of
 * the two it was. Without the table, a verb could only be answered by falling
 * through to the unknown-command path -- the quiet failure the 421 test exists
 * to catch. */
typedef struct {
    const char *verb;
    void (*fn)(server_t *, conn_t *, const message_t *);
    int pre_reg; /* legal before CONN_REG_READY */
} command_t;

/* ---------------------------------------------------------------------------
 * TAGMSG (#672, #724)
 * ---------------------------------------------------------------------------
 * IRCv3 message-tags' TAGMSG: `@+typing=active TAGMSG #chan`. The tags ARE the
 * payload, so fanout_deliver() cannot carry it -- it mints the emission's own
 * msgid/account block and takes no client block. The walk below is therefore
 * PRIVMSG-shaped routing (resolve, membership, member walk) with the client's
 * tag block relayed verbatim. Only members that negotiated `message-tags` get
 * it (a tagless TAGMSG is meaningless). Non-channel targets are 403: for this
 * verb a nick is genuinely "no such channel".
 * #724: one fanout_stamp() per emission (the same path PRIVMSG mints its msgid
 * through), rendered per destination so only draft/message-ids members carry
 * `@msgid`; and an echo to the sender when it negotiated `echo-message` (also
 * gated on `message-tags`, which the echo without tags would be meaningless
 * without). Non-negotiated members still get nothing.
 * shortcut: no cross-server TAGMSG forward (no STAGMSG verb); remote targets
 * are 403 until the mesh has one.
 */
/* One destination's TAGMSG tag block: the client's tags verbatim, prefixed
 * with this emission's `msgid` when the destination negotiated
 * draft/message-ids (cap_message_ids_enabled's double gate, the same one
 * PRIVMSG's path applies). NULL when there is no block at all. */
static const char *tagmsg_block(conn_t *dst, const irc_serve_tags_t *ident,
                                const char *tags, char *out, size_t cap)
{
    char mid[IRC_MAX_MSGTAG + 1u];

    if (cap_message_ids_enabled(dst) == 0 ||
        irc_serve_msgid_value(ident, mid, sizeof mid) == 0u) {
        return tags;
    }
    if (tags == NULL) {
        (void)snprintf(out, cap, "%s=%s", IRCV3_TAG_MSGTAG, mid);
    } else {
        (void)snprintf(out, cap, "%s=%s;%s", IRCV3_TAG_MSGTAG, mid, tags);
    }
    return (out[0] != '\0') ? out : tags;
}
static void handle_tagmsg(server_t *s, conn_t *c, const message_t *m)
{
    fanout_target_t t;
    irc_serve_tags_t ident;
    char prefix[CONN_HOSTMASK_MAX];
    /* Room for the client's block plus this emission's `msgid=` pair: the tags
    * arrived inside a legal line, so the pair always fits and snprintf below
    * never truncates a valid input. */
    char block[IRC_MAX_LINE + 1u + IRC_MAX_MSGTAG + 8u];
    const char *params[1];
    const char *tags;
    int slots[64];
    int relayed = 0;
    size_t nslots = 0;
    size_t i;
    int delivered = 0;

    if (m->nparams != 1) {
        (void)reply_refused(s, c, "TAGMSG", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        (void)reply(s, c, "404", NULL, 0, "Cannot send to channel");
        return;
    }
    if (fanout_resolve(s, c, m->params[0], FANOUT_MESSAGE, &t) == 0) {
        return; /* 401 or 403 already sent */
    }
    if (t.kind != FANOUT_LOCAL_CHANNEL) {
        (void)reply(s, c, "403", (const char *const[]){ t.name }, 1,
                    "No such channel");
        return;
    }
    if (fanout_is_member(&t, c) == 0) {
        (void)reply(s, c, "404", (const char *const[]){ t.name }, 1,
                    "Cannot send to channel");
        printf("[observable] tagmsg_refused: nick=%s target=%s reason=not_on_channel\n",
               c->nick, t.name);
        return;
    }
    params[0] = t.name;
    tags = (m->tags != NULL && m->tags[0] != '\0') ? m->tags : NULL;
    fanout_stamp(s, NULL, &ident, &relayed);
    if (cap_enabled(c, CAP_ECHO_MESSAGE) != 0 &&
        cap_enabled(c, CAP_MESSAGE_TAGS) != 0) {
        int slot = server_writer_slot(s, c->fd);
        (void)send_line_tagged_quiet(s, c, prefix, "TAGMSG", params, 1,
                                     tagmsg_block(c, &ident, tags, block,
                                                  sizeof block));
        server_writers_kick_slots(s, &slot, 1);
        delivered++;
    }
    for (i = 0; i < t.chan->nmembers; i++) {
        conn_t *dst = t.chan->members[i].c;
        int slot;
        size_t k;

        if (chan_member_live(&t.chan->members[i]) == 0 || dst == c) {
            continue;
        }
        if (cap_enabled(dst, CAP_MESSAGE_TAGS) == 0) {
            continue;
        }
        (void)send_line_tagged_quiet(s, dst, prefix, "TAGMSG", params, 1,
                                     tagmsg_block(dst, &ident, tags, block,
                                                  sizeof block));
        slot = server_writer_slot(s, dst->fd);
        for (k = 0; k < nslots; k++) {
            if (slots[k] == slot) {
                break;
            }
        }
        if (k == nslots) {
            if (nslots == 64) {
                server_writers_kick_slots(s, slots, nslots);
                nslots = 0;
            }
            slots[nslots++] = slot;
        }
        delivered++;
    }
    server_writers_kick_slots(s, slots, nslots);
    printf("[observable] tagmsg: from=%s target=%s members=%zu delivered=%d\n",
           c->nick, t.name, t.chan->nmembers, delivered);
}

static const command_t k_commands[] = {
    { "PASS",    handle_pass,  1 },
    /* 7/Phase 8. Both are pre-registration verbs: CAP is sent BEFORE NICK and
     * USER by every current client, and SASL is answered inside the registration
     * burst. `pre_reg = 1` on both is load-bearing -- see the comment above
     * handle_cap() and handle_authenticate(). */
    { "CAP",     handle_cap_wrapper, 1 },
    { "AUTHENTICATE", handle_authenticate, 1 },
    /* Phase 12: STARTTLS. `pre_reg = 1` is the whole of the specification's rule
     * and it is enforced a second time inside the handler, because a client that
     * sends STARTTLS after NICK and USER must be answered 691 rather than 451 --
     * "you have not registered" is a lie about a connection that HAS registered,
     * and the honest answer names the real problem. So `pre_reg = 1` gets the
     * command to the handler on a registered connection, and the handler decides.
     * That is why this row sits with CAP and AUTHENTICATE and not with MOTD: it
     * is a command whose legality DEPENDS ON HOW FAR REGISTRATION GOT, and a
     * connection in the middle of registering is the case it exists for. */
    { "STARTTLS", handle_starttls, 1 },
    { "NICK",    handle_nick,  1 },
    { "USER",    handle_user,  1 },
    { "PING",    handle_ping,  1 },
    { "PONG",    handle_pong,  1 },
    { "QUIT",    handle_quit,  1 },
    { "MOTD",    handle_motd,  0 },
    /* 7/Phase 4: the channel surface. LIST is here rather than being left for
     * Phase 7, because a channel this node will not tell a client about is a
     * channel whose origin, members and topic are all invisible, and the whole
     * 2.2 data model would be observable only from the [observable] log. */
    { "LIST",    handle_list,  0 },
    /* 4.1, later phases. */
    { "JOIN",    handle_join,  0 },
    { "PART",    handle_part,  0 },
    { "TOPIC",   handle_topic, 0 },
    { "NAMES",   handle_names, 0 },
    { "MODE",    handle_mode,  0 },
    { "KICK",    handle_kick,  0 },
    { "KILL",    NULL,         0 },
    /* 7/Phase 5: the messaging surface, and the point at which the node becomes
     * usable. PRIVMSG and NOTICE are 4.1 MUST; WHO, WHOIS, ISON and AWAY are
     * 4.2 SHOULD, pulled forward here because 4.2's own list puts them in the
     * same phase as the message path and a client that cannot ask "who is here"
     * or "is this nick online" is a client this milestone has not delivered.
     *
     * The table is ordered by the RFC's 4.1/4.2 order, and 3.3.2's grouping, so
     * the surface reads as the specification does. */
    { "PRIVMSG", handle_privmsg, 0 },
    { "NOTICE",  handle_notice,  0 },
    { "WHO",     handle_who,     0 },
    { "WHOIS",   handle_whois,   0 },
    { "ISON",    handle_ison,    0 },
    { "AWAY",    handle_away,    0 },
    /* 7/Phase 7: the rest of 4.2, in 4.2's own order. INVITE and KNOCK are in
     * chan_verbs.c because both are about a channel; USERHOST is in
     * msg_verbs.c because it has no channel in it; the server-info family is
     * below, next to the MOTD it belongs with. The order in the table is
     * 4.2's and not the order of the files, for the same reason the table is
     * ordered by the RFC's rather than by the history: a reader comparing the
     * surface against the specification should be able to do it down this list
     * without a map. */
    { "INVITE",  handle_invite,  0 },
    { "USERHOST", handle_userhost, 0 },
    { "KNOCK",   handle_knock,   0 },
    /* 7/Phase 7, the rest of 4.2: the server-info family, which lives next to
     * the MOTD above because it is the same question -- what is this node -- and
     * CHOPER, which is the operator half of the same surface and is answered by
     * a refusal policy rather than a feature. */
    { "LUSERS",  handle_lusers,  0 },
    { "ADMIN",   handle_admin,   0 },
    { "INFO",    handle_info,    0 },
    { "CHOPER",  handle_choper,   0 },
    /* 7/Phase 10.1: the account-registration pair, REFUSED rather than
     * unimplemented, and in the table rather than left to the 421 path for the
     * reason handle_register()/handle_unregister() give. A client that sends
     * REGISTER and gets 421 would read "this server has never heard of
     * REGISTER"; this node HAS heard of it and has decided. The distinction is
     * the whole of what a refusal is, and 421 cannot express it. */
    { "REGISTER",   handle_register,   0 },
    { "UNREGISTER", handle_unregister, 0 },
    /* 7/Phase 10.6: IRCv3's `setname`. NOT `pre_reg`, which is gate 1 of the three
     * in handle_setname() -- an unregistered connection has an EMPTY realname, so
     * without the gate a SETNAME would "succeed" at setting state that does not
     * exist yet. The verb is IN the table even though the capability gates what it
     * does, because the specification requires the command to be supported whether
     * or not the client negotiated it: a client that sent SETNAME and got 421 would
     * read "this server has never heard of it". */
    { "SETNAME",    handle_setname,    0 },
    /* 7/Phase 10.12: IRCv3 `batch`. `pre_reg`, and that is a decision worth the
     * comment: a client that batches its OWN registration lines is legal -- the
     * reference tags are a property of any command -- and holding the gate closed
     * until `001` would mean the `001`-`005` burst escaped the batch a client had
     * legitimately opened around it. The batch state is per connection and lives in
     * conn_t, so nothing here can reach another client's. */
    { "BATCH",      handle_batch,      1 },
    /* 7/Phase 10.2b: the account-notify query. NOT `pre_reg`, because the answer
     * carries this connection's hostmask and a pre-registration connection has no
     * nickname to put in it -- an unregistered client sending ACCOUNT gets 451,
     * which is the RFC's own answer for "you have not registered yet". */
    { "ACCOUNT",    handle_account,    0 },
    /* #672: IRCv3 `TAGMSG`. NOT `pre_reg`: the relay renders the sender's
     * hostmask into the prefix, and a pre-registration connection has no
     * nickname for it -- so pre-registration gets 451, the RFC's own answer
     * for "you have not registered yet". */
    { "TAGMSG",     handle_tagmsg,     0 }
};

static const command_t *lookup(const char *verb)
{
    if (verb == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof k_commands / sizeof k_commands[0]; i++) {
        if (strcmp(k_commands[i].verb, verb) == 0) {
            return &k_commands[i];
        }
    }
    return NULL;
}

void commands_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const command_t *cmd;

    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* 3: the peer path is the SAME dispatch, and dispatch "never asks 'is this
     * local or remote?' -- src->kind is the only difference". So a peer line is
     * not routed around this function; it arrives here and is handed to the
     * guard chain on the strength of src->kind and nothing else. That is the
     * whole of the difference between the two paths, and putting it here rather
     * than in poll_loop.c's read step is what keeps there ONE door into a
     * command: a second entry point into fed_dispatch() would be a second way
     * for a future line to arrive without passing 2.4's guards.
     *
     * ABOVE THE CONN_CLOSING CHECK, deliberately and specifically. A peer link
     * is a TCP connection like any other, so one segment can carry a peer's last
     * line AND its close; the close marks the conn CLOSING, and the check below
     * would then drop the line that arrived in the same read. Losing a peer's
     * final state change because it happened to share a segment with a FIN is
     * exactly the kind of loss 2.2's cache is supposed to self-heal from and
     * usually does not: there is no later burst to correct it until Phase 9.
     * The check itself still applies to CLIENTS, where a dropped line after a
     * QUIT is correct behaviour.
     *
     * The `c == NULL` guard above means a peer line cannot reach here without a
     * connection, and fed_dispatch() repeats it. */
    if (c->kind == CONN_SERVER) {
        fed_dispatch(s, c, m);
        return;
    }

    /* A connection on its way out gets nothing. The reaper closes it at the
     * next fixed point, so a reply here would be queued onto a socket the loop
     * has already dropped from its poll set. Reachable: one TCP segment
     * carrying "QUIT :bye" and "PING :are you there" hands this function a
     * second line after the first has already marked the conn CLOSING. */
    if (atomic_load_explicit(&c->state, memory_order_acquire) == CONN_CLOSING) {
        /* Measured, like poll_loop.c's `line:` and for the same reason: this is a
         * verb off a socket and a verb is an identifier, so the value is kept when
         * it is printable and withheld when it is not. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_dropped: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu reason=closing\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    cmd = lookup(m->command);

    /* The registration gate comes BEFORE the unknown-command check, which is
     * the order RFC 2812 3.1 specifies and the one clients expect: an
     * unrecognised verb from an unregistered connection is 451, because "you
     * have not registered" is both true and actionable, while "unknown command"
     * would be neither. */
    if (!commands_registered(c) && (cmd == NULL || cmd->pre_reg == 0)) {
        (void)reply(s, c, "451", NULL, 0, "You have not registered");
        return;
    }

    if (cmd == NULL) {
        const char *mid[1];

        /* THE 421 ECHOES THE VERB BACK VERBATIM AND THAT STAYS. The verb is going
         * to the client that sent it, so there is no second reader and no hazard,
         * and RFC 2812 3.3.4's 421 names the command precisely so a client can
         * match it. It is the LOG that needed the measurement, and only the log.
         *
         * This is also the most exposed single line on the node: an unrecognised
         * verb is answerable before registration, needs no credential, and nothing
         * examined the word before it was printed. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unknown: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }
    if (cmd->fn == NULL) {
        const char *mid[1];

        /* A known 4.1 verb this build does not implement. 421 is a slight lie
         * about the reason -- the wire has no numeric for "not yet" -- but the
         * alternative is silence, and silence is the failure mode these
         * numerics exist to prevent. The [observable] line says which of the
         * two it was, so a log reader is not misled. */
        /* As `cmd_unknown` above, and for the same reason: the 421's <command> field
         * is rendered by `emit_numeric_ex()` in reply.c -- the single place a
         * numeric's parameters are filtered -- and the LOG measures the value rather
         * than printing it raw. `KILL` is the verb that reaches this branch on this
         * build, so the line is not hypothetical. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unimplemented: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* THE `batch` HOOK, AND WHY IT BRACKETS THE HANDLER RATHER THAN PRECEDING IT.
     *
     * `batch_begin_command()` is what turns an inbound line's `@`/`+` reference tags
     * into two things this dispatch then makes true: a `batch=` tag on the response
     * (a one-shot, consumed by the reply path) and a SUPPRESSION that lasts exactly as
     * long as the command. Both have to be set BEFORE `cmd->fn` runs -- a handler's
     * first byte of output is already too late for the first, and the second would be
     * cleared by `batch_end_command()` before it was ever set.
     *
     * AND `batch_end_command()` IS NOT OPTIONAL ON ANY PATH, which is why it is after
     * the call rather than inside an error branch: a suppressed flag that survived a
     * command would swallow the NEXT command's replies too, and the symptom would be
     * a client that goes silent for no reason it can see. There is exactly one exit
     * from `cmd->fn()` that is not a `return`, because every handler returns.
     *
     * IT IS HERE AND NOT IN reply.c, because reply.c cannot know when a command
     * starts: it only sees outbound lines, and "which of them is the FIRST line of
     * this command's response" is not a property of any one of them. */
    batch_begin_command(c, m);
    label_begin_command(c, m);
    cmd->fn(s, c, m);
    /* THE TAIL. Two things have to happen after the handler and not inside it, and both
     * are "what remains to be said" questions that a handler cannot answer because it
     * does not know what the handler emitted:
     *
     *   label_finish_command()  closes the `labeled-response` batch if one was opened,
     *                           or answers `ACK` if the command produced nothing. A
     *                           handler returning early on a refusal has still produced
     *                           a response -- the refusal -- so the label goes on THAT,
     *                           which is why the tail asks what was emitted rather than
     *                           asking whether the handler returned.
     *   batch has no tail       a client batch is closed by the client.
     *
     * IT IS NOT OPTIONAL ON ANY PATH, and every path here ends in this call: a
     * `label_live` that outlived its command would label the NEXT command's first line
     * with a value the client was already told was finished.
     */
    label_finish_command(s, c);
}
