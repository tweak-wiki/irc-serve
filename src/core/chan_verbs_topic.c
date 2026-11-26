/* chan_verbs_topic.c -- see core/chan_verbs.h. 4.1's TOPIC.
 *
 * Split verbatim out of core/chan_verbs.c (issue #543 TU-50): the TOPIC
 * section (handle_topic() plus its section header). It stays declared in
 * core/chan_verbs.h (no new header), reached through it by the dispatch
 * table in core/commands_dispatch.c. Its in-TU dependencies are
 * resolve_joined()/authority_ok()/deliver_state_change() (shared since
 * TU-46/48/49) and send_topic() (shared since this split, same precedent;
 * still defined in chan_verbs.c for handle_join()); the rest --
 * chan_set_topic/CHAN_MAX_TOPIC, conn_hostmask/conn_text_strip, reply/
 * reply_refused/send_line -- already arrive through headers.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * TOPIC
 * ---------------------------------------------------------------------------
 * Two commands in one verb, distinguished by arity: TOPIC #chan queries,
 * TOPIC #chan :text sets. 2.2 makes topic/topic_who/topic_when remote-originated
 * cache, so the same three fields serve a locally set topic and one learned from
 * the origin, and 333 exposes all three to a client either way.
 */
void handle_topic(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    chan_verdict_t verdict;
    int setting;

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "TOPIC", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 2) {
        (void)reply_refused(s, c, "TOPIC", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    setting = (m->nparams > 1);
    ch = resolve_joined(s, c, "TOPIC", m->params[0]);
    if (ch == NULL) {
        return;
    }
    /* A query takes the query arm: a question about a channel this node does not
     * own is answered from the cache and never refused. */
    if (setting == 0) {
        verdict = authority_ok(s, c, ch, "TOPIC", 0);
        send_topic(s, c, ch);
        return;
    }
    /* Local preconditions first, routing last (§2.2): the length bound is
     * answerable from the parameter alone, so on an orphaned channel an
     * over-long topic is 417 rather than 437. Asked ONCE and HELD, because
     * authority_ok() reports on the observable output and a reader seeing two
     * `chan_state_forward` lines for one TOPIC would reasonably ask what the
     * second one was. */
    if (strlen(m->params[1]) > (size_t)CHAN_MAX_TOPIC) {
        /* NOT FORWARDED, AND SAID SO -- to the client, not just the log. The
         * origin would refuse a topic longer than its own bound, and a node
         * that quietly shortened its way inside that bound would be answering
         * for a message the origin never accepted. */
        (void)reply_refused(s, c, "TOPIC", NULL, "417", NULL, 0,
                            "Topic is too long for this channel");
        printf("[observable] chan_topic_refused: channel=%s nick=%s reason=too_long "
               "len=%zu max=%d\n",
               ch->name, c->nick, strlen(m->params[1]), CHAN_MAX_TOPIC);
        return;
    }
    verdict = authority_ok(s, c, ch, "TOPIC", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }
    if (verdict == CHAN_VERDICT_FORWARD) {
        /* THE FORWARD PATH, and it is the clearest case of the two consequences
         * this change has. Nothing is applied locally -- a topic this node does
         * not own is a CACHE, and writing a cache field on a client's say-so is
         * the permanent divergence 2.2 forbids -- and the client is still
         * answered 332/333 with whatever the node currently holds.
         *
         * THE CLIENT IS NOT LIED TO, and that is the point. The origin performs
         * the action, so the client asked a server to change a channel and the
         * mesh will change it; answering 437 would tell the client its own
         * request was rejected, which is false. The honest limits are stated
         * rather than hidden: the forward can still be refused further along --
         * at the peer's 437, or at a NO_ROUTE if the origin's link went down
         * between the authority check and the queue -- so what this node promises
         * is that it ACCEPTED the request, not that the mesh accepted it. */
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        /* The topic IS the parameter, and it goes out to the members as well as
         * to the peer. RFC 2812 3.3.1's TOPIC is `<channel> [:<topic>]`, so the
         * client-facing echo is `:setter TOPIC #CHAN :<topic>` and dropping the
         * trailing parameter would leave every member to re-read 332 to learn
         * what a line it was just sent says. A peer cannot rebuild a topic from a
         * bare `STOPIC #chan` either, which is why the same parameter serves
         * both renderings. */
        /* STRIPPED, AND THE BUFFER IS EXACT. This is the arm the locally-owned
         * path does not have, and it was the last raw relay of a client-controlled
         * string left on the node: a `TOPIC` on a channel this node does not own
         * put the client's bytes on the wire to every local member of the cache and
         * to the origin. Nothing is stored here -- 2.2 forbids writing a cache field
         * on a client's say-so -- so there is no "broadcast the stored field" to fix
         * and the strip is the whole of it.
         *
         * `CHAN_MAX_TOPIC + 1` IS EXACT rather than a convenience, and the reason
         * is that stripping must not silently WIDEN what the node accepts. The
         * origin applies its own bound to whatever arrives over the link, so a
         * 400-byte topic of which 200 bytes are control characters would strip to
         * 200 here, fit, and be stored by the origin -- where the same 400 bytes
         * unstripped were refused. Checking the RAW length first keeps the origin's
         * answer a function of what the client sent rather than of which bytes
         * happened to be in it. */
        char clean[CHAN_MAX_TOPIC + 1u];
        size_t in_len = strlen(m->params[1]);

        /* The bound above guarantees this fits, so the strip cannot widen what the
         * node accepts and `clean` is exact. */
        {
            size_t kept = conn_text_strip(clean, sizeof clean, m->params[1],
                                          STRIP_STORED);

            params[0] = clean;
            deliver_state_change(s, c, ch, "TOPIC", prefix, params, 1);
            /* The actor's own echo (3.1): the forward reached no local member. */
            {
                const char *echo[2];

                echo[0] = ch->name;
                echo[1] = clean;
                (void)send_line(s, c, prefix, "TOPIC", echo, 2);
            }
            printf("[observable] chan_topic_forward: channel=%s nick=%s in_len=%zu "
                   "kept_len=%zu forwarded=1 reason=CONTROL_BYTES\n",
                   ch->name, c->nick, in_len, kept);
        }
        send_topic(s, c, ch);
        return;
    }

    /* The write. chan_set_topic() still checks the bound itself, and the check
     * above means it cannot fail on length here; the branch stays so a future
     * bound change fails closed with the right numeric instead of 437. */
    if (chan_set_topic(ch, m->params[1], c->nick) != 0) {
        (void)reply_refused(s, c, "TOPIC", NULL, "417", NULL, 0,
                            "Topic is too long for this channel");
        return;
    }
    printf("[observable] chan_topic: channel=%s nick=%s len=%zu when=%lld\n",
           ch->name, c->nick, strlen(ch->topic), (long long)ch->topic_when);
    /* THE STRIP IS ANNOUNCED (#121). chan_set_topic() removed any control bytes,
     * so the length on the line above is the length that was STORED rather than
     * the length that arrived; a reader comparing a member's terminal against the
     * setter's screen needs to know they can differ, and needs to know by how
     * much. Deriving the count from the two strings rather than measuring it again
     * keeps the strip one pass and keeps this line and the stored value from being
     * able to disagree.
     *
     * ONLY WHEN IT HAPPENED. A `TOPIC` of ordinary text takes neither branch, so
     * the common case adds one comparison and no line -- and a needle that fires
     * for every topic change would be a needle a test could not use to tell a
     * strip from an ordinary set. */
    if (strlen(m->params[1]) != strlen(ch->topic)) {
        printf("[observable] chan_topic_stripped: channel=%s nick=%s "
               "in_len=%zu kept_len=%zu reason=CONTROL_BYTES\n",
               ch->name, c->nick, strlen(m->params[1]), strlen(ch->topic));
    }

    {
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        /* `ch->topic`, NOT `m->params[1]` (#121). This used to echo the client's
         * own bytes to every member of the channel, which meant the strip inside
         * chan_set_topic() would have changed what the node STORES while leaving
         * what it RELAYS untouched -- the stored copy stripped, the announced copy
         * raw, and a member's terminal the only place the ESC still arrived. The
         * broadcast is a second copy of the field and the copy on the wire is the
         * one that executes, so it is the copy that has to be the stored one. It is
         * also more correct for a reason that predates the strip: what a member is
         * told the topic is, should be what the node holds rather than what the
         * setter typed. */
        params[0] = ch->topic;
        deliver_state_change(s, c, ch, "TOPIC", prefix, params, 1);
    }
    /* The setter is told the topic back as 332/333, which is how it learns the
     * canonical form and the server's clock. */
    send_topic(s, c, ch);
}
