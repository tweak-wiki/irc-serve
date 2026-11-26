/* fanout_resolve.c -- see fanout_resolve.h. The resolution family, verbatim
 * out of fanout.c (issue #543); delivery, forwarding, cap and stamp live in
 * core/fanout_deliver.c, core/fanout_forward.c and core/fanout_cap.c.
 */
#include "core/fanout_resolve.h"

#include <string.h>

/* Phase 9: 2.1's remote-nick registry, which is what turns 3.1's `nick@server`
 * row from a shape this node recognises into a target it can resolve. See the
 * resolution comment at the branch below. */
#include "federation/nickreg.h"
#include "core/reply.h"
/* Reply only when there is a client to refuse to. Federation callers pass
 * from==NULL, and replying to NULL would increment n_reply_refused, the
 * counter reply.c holds at zero forever. A refusal this node migrates goes
 * through reply_refused(): `command` is fanout_resolve_cmd()'s own parameter
 * (NULL from the plain wrapper), read here rather than passed at each of the
 * eleven sites because every one of them is inside that function and would take
 * the same argument. A NULL command keeps the legacy numeric: those callers have
 * no verb to name here (federation passes no client at all, and TAGMSG's own
 * verb lines migrate with its handler under #724, not from inside resolution).
 */
#define REPLY_IF(s, from, ...) \
    do { if ((from) != NULL) { \
        if ((command) != NULL) \
            (void)reply_refused((s), (from), (command), NULL, __VA_ARGS__); \
        else \
            (void)reply((s), (from), __VA_ARGS__); \
    } } while (0)


/* The 2.4 never-forward-own-origin test is irc_ascii_same() (message.h, issue
 * #181), and mask matching folds with irc_ascii_fold(): 005 advertises
 * CASEMAPPING=ascii, so this node has already told every client that []\~ and
 * {}|^ are NOT equivalent. */

int fanout_mask_match(const char *mask, const char *value)
{
    const char *m;
    const char *v;
    const char *star;
    const char *retry;

    if (mask == NULL || value == NULL) {
        return 0;
    }
    /* Iterative backtracking, not recursion: a mask arrives from a client, so
     * a pathological one must not be able to make this exponential. Same
     * shape as chan_mask_match(), which this is a sibling of rather than a
     * call to -- see the note in fanout.h. */
    m = mask;
    v = value;
    star = NULL;
    retry = NULL;
    while (*v != '\0') {
        if (*m == '*') {
            star = m++;
            retry = v;
        } else if (*m == '?' || irc_ascii_fold(*m) ==
                                    irc_ascii_fold(*v)) {
            m++;
            v++;
        } else if (star != NULL) {
            m = star + 1;
            v = ++retry;
        } else {
            return 0;
        }
    }
    while (*m == '*') {
        m++;
    }
    return *m == '\0';
}

/* Resolve a nickname to a connection.
 *
 * This used to be a workaround rather than a lookup: it asked the registry
 * exactly, and only on a miss walked the whole enumeration comparing
 * case-folded -- which is how `PRIVMSG BOB :hi` found a client registered as
 * `bob` while the registry stayed case-sensitive underneath it. It printed
 * `[observable] nick_resolve ... match=case_folded` when it took that path,
 * because a case-folded hit was evidence of the registry's defect.
 *
 * The registry folds now, so that scan was dead code, and it is gone: a
 * mitigation left standing after the bug is fixed is how the bug comes back.
 * The extra O(n) walk on every miss -- on the message-delivery hot path -- went
 * with it. `bob` and `BOB` can no longer both be held either, which the scan
 * itself could never have prevented: it resolved the ambiguity, it did not
 * remove it. */
conn_t *fanout_find_nick(server_t *s, const char *nick)
{
    if (s == NULL || nick == NULL || nick[0] == '\0') {
        return NULL;
    }
    return server_nick_lookup(s, nick);
}

/* ---------------------------------------------------------------------------
 * Resolution
 * ---------------------------------------------------------------------------
 */

/* ---------------------------------------------------------------------------
 * fanout_name_store(): THE ONE WAY A BYTE GETS INTO `out->name`
 * ---------------------------------------------------------------------------
 * `fanout_target_t::name` is the target as the client wrote it, and it is
 * printed -- at `msg_verbs.c`'s `[observable] msg:` line, at every refusal that
 * names the target, and at every reply that echoes it. So it is a field a
 * client-supplied byte can reach, and `fanout_resolve()` used to write it with
 * three bare `memcpy()` calls guarded by a chain of three conditions: the name
 * resolves as a channel, or as `nick@server` against the nickname registry, or
 * as a local nick.
 *
 * That chain works. It is also exactly the shape that stops working: each guard
 * is a fact about a DIFFERENT question ("is this a channel", "does the registry
 * hold it", "is that a local user"), none of them is a fact about RENDERING, and
 * the day one of them is loosened -- a channel name charset widened for a
 * federation feature, a registry lookup made case-insensitive on the wrong axis,
 * a "be lenient about what you accept" edit -- the byte lands in a struct with
 * nothing between it and a log line. A guard whose safety depends on three
 * unrelated conditions holding at once is a guard nobody can review.
 *
 * SO THE VALIDATION IS AT THE STRUCT, which is the same decision `handle_user()`
 * made for `conn_t::user` and the reason is the same: the safety lives in ONE
 * place that every write to the field must go through, not in a chain of
 * preconditions a reader has to reconstruct. `fanout_name_store()` is the only
 * writer of `out->name`, and it refuses rather than copies, so a future refactor
 * that loosens a guard produces a 401 rather than a stored byte.
 *
 * THE PREDICATE IS `conn_text_display_check()`, the same walk `valid_nick()` asks
 * for `conn_t::nick` and `conn_realname_check()` asks for `conn_t::realname` --
 * because those two fields are also stored and re-rendered into every line their
 * owner sends, which is the property `out->name` shares. It is about CODE POINTS
 * rather than bytes, so a UTF-8 target is accepted and a raw C1 byte is not;
 * `connection.h` argues at length why the byte-range direction is the one that
 * mangles a legitimate user silently.
 *
 * THE WIDTH IS CHECKED HERE RATHER THAN ONLY AT THE TOP OF fanout_resolve(),
 * and that is not redundancy for its own sake: the caller's check bounds the
 * whole `arg`, while this bounds what is being STORED, and the two have been
 * different lengths in this function for as long as it has existed (`nick` is
 * split out of `arg` at the last '@'). A store that cannot overflow does not
 * need its caller to be right about the arithmetic.
 *
 * COST: one pass over at most FANOUT_NAME_MAX bytes, on the message-delivery hot
 * path, once per resolution. The walk is the same one `valid_nick()` runs on
 * every NICK, so it is not a new class of work for this node.
 */
static int fanout_name_store(fanout_target_t *out, const char *src)
{
    size_t n;

    if (out == NULL || src == NULL) {
        return 0;
    }
    n = strlen(src);
    if (n == 0u || n >= sizeof out->name) {
        return 0;
    }
    if (conn_text_display_check(src) != CONN_DISPLAY_OK) {
        return 0;
    }
    memcpy(out->name, src, n + 1u);
    return 1;
}

/* The one store, for callers outside this file. `notify_away` builds its target
 * directly from the chan_t in hand instead of resolving, so it stores the name
 * through the same predicate rather than a bare memcpy(). */
int fanout_target_store_name(fanout_target_t *out, const char *src)
{
    return fanout_name_store(out, src);
}

int fanout_resolve_cmd(server_t *s, conn_t *from, const char *command,
                       const char *arg, fanout_class_t vclass, fanout_target_t *out)
{
    conn_t *user;
    size_t len;

    if (out == NULL) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    out->kind = FANOUT_NONE;
    out->vclass = vclass;

    /* `from` MAY BE NULL, and that is not a loophole: it means "a caller with
     * nobody to answer", which is what federation/verbs.c's guard chain is when
     * a peer names a channel this node does not hold. A numeric would be refused
     * to a CONN_SERVER connection anyway (3, and reply.c's emit_to_client), so
     * asking for one here would be a guaranteed n_reply_refused -- the counter
     * server.h says should be zero forever because a non-zero value is a bug
     * report. So the refusals below are conditional on there being a client to
     * refuse to, and the resolution itself is identical either way; that is what
     * keeps this the ONE place that answers "is this a channel or a nick". */
    if (s == NULL || arg == NULL || arg[0] == '\0') {
        return 0;
    }
    /* A name longer than either thing it could be cannot be one, and copying it
     * would overflow `name` -- so it is refused as an unresolvable target
     * rather than silently truncated into something that resolves. 401 is the
     * right complaint: this node has no such user, whatever the client meant. */
    len = strlen(arg);
    if (len >= sizeof out->name) {
        if (from != NULL) {
            REPLY_IF(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                        "No such nick/channel");
        }
        return 0;
    }

    if (chan_name_valid(arg)) {
        /* A channel. 2.2 canonicalises the name, so the two spellings are one
         * channel and every reply, log line and future SBURST has to use the
         * same bytes. */
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        chan_name_upper(canonical, sizeof canonical, arg);
        if (fanout_name_store(out, canonical) == 0) {
            /* Unreachable through the current guards: a channel name that
             * reached here passed `chan_name_valid()`, and a name holding a
             * control byte is not one this node resolves. It is here so that the
             * store's own rule is the thing that says so -- see the block above
             * fanout_name_store() for why the guard chain is not left to carry
             * that on its own. */
            if (from != NULL) {
                REPLY_IF(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                            "No such nick/channel");
            }
            return 0;
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            if (from != NULL) {
                REPLY_IF(s, from, "403", (const char *const[]){ canonical }, 1,
                            "No such channel");
            }
            return 0;
        }
        out->chan = ch;
        out->kind = chan_origin_is_self(s, ch) ? FANOUT_LOCAL_CHANNEL
                                                : FANOUT_REMOTE_CHANNEL;
        return 1;
    }

    /* A `nick@server` target. 2.1's scoped identity splits at the LAST '@', and
     * a client may send one at any time.
     *
     * AND NOW IT IS RESOLVED rather than merely recognised, which is the
     * difference Phase 9's registry makes and the reason this branch reads a
     * module rather than parsing a string. Before the registry existed there was
     * nothing to ask "does that server hold that nick" and the row resolved to a
     * target with no destination; now the answer is a server this node has an
     * ESTABLISHED link to, or nothing at all.
     *
     * THE REFUSAL IS 401 AND IT IS RIGHT, and the reason it is a refusal rather
     * than a forward-anyway is the difference 3.1's note draws between "this node
     * cannot reach that server" and "that user does not exist": on a federated
     * node only one of those is ever true, and a node that forwards to a server
     * which has never heard of the nick is a node that cannot tell a client why
     * its message went nowhere. A client is owed the difference.
     *
     * THE TWO HALVES THAT CAN FAIL, and they fail differently:
     *   - the REGISTRY does not know the nick at all, or does not know that server
     *     holding it: 401, because nobody told this node about that user.
     *   - the registry knows, but there is no ESTABLISHED link: still 401, and
     *     deliberately not a different numeric. 4.4 has no numeric for "the user
     *     exists and the node cannot reach them", and 402 (ERR_NOSUMSERVER) is
     *     LUSERS's and ADMIN's `<server>` mask. Inventing one here would be a
     *     numeric every client has to be taught, and 401 is the answer a client
     *     already handles by telling the user.
     */
    if (strrchr(arg, '@') != NULL) {
        const char *at = strrchr(arg, '@');
        char nick[FANOUT_NAME_MAX + 1];
        char server[IRC_MAX_SERVER_NAME + 1];
        char holder[IRC_MAX_SERVER_NAME + 1];
        size_t nlen = (size_t)(at - arg);

        /* THE SPLIT IS AT THE LAST '@' and not the first, and that is 2.1's rule
         * rather than this function's: '@' is not a legal nick character (2.1's
         * own charset rule) but a server name is an opaque string and may itself
         * contain one. Splitting at the first would name a peer that does not
         * exist. */
        if (nlen == 0u || nlen > sizeof nick - 1u) {
            /* A name this node could not be given, or an empty nick: no holder
             * can answer for it, so 401 rather than a parse error the client has
             * no way to act on. */
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        memcpy(nick, arg, nlen);
        nick[nlen] = '\0';
        if (strlen(at + 1) == 0u || strlen(at + 1) > (size_t)IRC_MAX_SERVER_NAME) {
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        memcpy(server, at + 1, strlen(at + 1) + 1u);

        /* THE SCOPE NAMES THIS NODE, and that is a LOCAL user and not a
         * forwarding failure. 2.1's scoped identity is "the user called nick on
         * the server called server", and nothing in it says the server has to be
         * a different one -- a client writing `zed@irc.b` from irc.b is naming a
         * user of its own node through the qualified form, and the honest answer
         * is to deliver it. Refusing it would make the qualified form unusable for
         * exactly the server where the name is unambiguous, and a node that
         * answered 401 there would be telling a client that a user standing next to
         * it does not exist.
         *
         * IT IS A LOCAL LOOKUP AND NOT A REGISTRY ASK, because the registry holds
         * only REMOTE nicks by construction (a local name is server_t::nicks'
         * business, and 2.1's "bob@a and bob@b are distinct registry keys" is a
         * statement about names on DIFFERENT servers). Asking the registry here
         * would find nothing and 401 a user this node is holding.
         *
         * AND THE PARAMETERS ARE REBUILT, not reused: the local rows are addressed
         * by the bare nickname with the client's own parameters, and `name` is the
         * qualified string. Passing the qualified string to a local row would
         * render ":router!u@h PRIVMSG zed@irc.b :text" to a client, which is not
         * what any client parses as a target. */
        if (chan_same_name(server, s->name)) {
            conn_t *lu = server_nick_lookup(s, nick);

            if (lu == NULL) {
                REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                            "No such nick/channel");
                return 0;
            }
            if (fanout_name_store(out, lu->nick) == 0) {
                /* Unreachable through the current guards for the same reason:
                 * `valid_nick()` asks conn_text_display_check() at NICK time, so
                 * a local user's nick is already a value this node renders. */
                REPLY_IF(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                            "No such nick/channel");
                return 0;
            }
            out->user = lu;
            out->kind = FANOUT_LOCAL_USER;
            return 1;
        }

        /* THE REGISTRY IS ASKED ABOUT THE NICK, NOT ABOUT THE PAIR, and the
         * difference is the whole of a duplicate. A client naming
         * `bob@irc.c` where two servers hold bob is naming one of them
         * SPECIFICALLY, so the pair is what it gets: this asks for a holder equal
         * to the named server, and a name nobody holds is a 401 rather than a
         * silent redirect to whichever of two holders came first in the table. */
        if (fed_nickreg_holder(s, nick, holder, sizeof holder, NULL) == NULL) {
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        /* The named server is the CLIENT'S claim about where the user is, and
         * the registry is this node's claim. When they disagree the client is
         * wrong, and this node says so rather than forwarding to a server that
         * does not hold the nick -- which is the "silently redirecting" failure
         * the comment above names. It is 401 rather than a redirect because a
         * client that wanted the redirect should send the name it means. */
        if (!chan_same_name(holder, server)) {
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        /* AND THE LAST THING BEFORE IT IS A ROUTE, so the refusal above names
         * the real reason rather than a derived one. There is deliberately no
         * attempt to reach the server: 3.4 forbids a name lookup in the event
         * loop, and the only addresses this node can dial are the ones its
         * operator configured (3.4's "pre-resolved peer addresses"). A server
         * nobody has a link to is a server this node cannot route to, and that
         * is the same answer for every reason it has no link. */
        if (server_find_peer(s, server) == NULL) {
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        /* THE SITE THE AUDIT NAMED, and the reason it is the one that matters:
         * this is the only branch that stores the client's own BYTES rather than
         * a value this node already validated -- the channel branch stores a
         * canonicalised name and the local branch stores a nick `valid_nick()`
         * accepted. The three guards above (the registry holds the nick, the
         * holder is the server the client named, an established link exists) are
         * all facts about ROUTING, none of them is a fact about what the value
         * looks like, and a byte that satisfies all three still has to be
         * renderable before it is stored and logged. So this one asks
         * fanout_name_store(), which is the same one predicate the other two
         * ask. */
        if (fanout_name_store(out, arg) == 0) {
            REPLY_IF(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                        "No such nick/channel");
            return 0;
        }
        out->kind = FANOUT_REMOTE_USER;
        return 1;
    }

    user = fanout_find_nick(s, arg);
    if (user == NULL) {
        if (from != NULL) {
            REPLY_IF(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
        }
        return 0;
    }
    /* AND THE LAST BRANCH, which is the one a bare nickname takes: the registry
     * resolved it, so the target is a local user and the name stored is that
     * user's own nick rather than what the client typed. `valid_nick()` already
     * asked conn_text_display_check() about it, so this store cannot fail on a
     * nick this node holds -- and it goes through fanout_name_store() anyway,
     * because "this cannot fail" is a property of a guard three files away and
     * the store is the thing that has to be right about its own buffer. */
    if (fanout_name_store(out, user->nick) == 0) {
        if (from != NULL) {
            REPLY_IF(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                        "No such nick/channel");
        }
        return 0;
    }
    out->user = user;
    out->kind = FANOUT_LOCAL_USER;
    return 1;
}

/* The verb-less entry: resolution for a caller with no command to name. A NULL
 * command keeps every refusal on the legacy numeric (see REPLY_IF), so
 * federation and TAGMSG (#724 owns the verb lines) are byte-identical while
 * callers that know their verb reach for fanout_resolve_cmd(). */
int fanout_resolve(server_t *s, conn_t *from, const char *arg,
                   fanout_class_t vclass, fanout_target_t *out)
{
    return fanout_resolve_cmd(s, from, NULL, arg, vclass, out);
}

int fanout_is_member(const fanout_target_t *t, const conn_t *c)
{
    if (t == NULL || c == NULL) {
        return 0;
    }
    if (t->kind != FANOUT_LOCAL_CHANNEL && t->kind != FANOUT_REMOTE_CHANNEL) {
        return 0;
    }
    return (t->chan != NULL && chan_find_member(t->chan, c) != NULL) ? 1 : 0;
}
