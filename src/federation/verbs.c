/* verbs.c -- see verbs.h. Both sides of 4.3's S-verbs: the encoder that builds
 * them and the guard chain that decides whether an inbound one may act. */
#include "federation/verbs.h"

/* For fed_obs() below, which is printf for a log line whose %s arguments are peer
 * strings and has to walk a format string and a va_list to do it. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "account_store.h"
#include "core/account.h"
/* For conn_text_logsafe() and conn_text_bad_count() -- a peer string this node
 * PRINTS is log-only and is therefore measured rather than filtered, for the same reason a
 * client string printed on this node's stdout is. A peer string this node STORES goes
 * through the field's own policy, and SMODES through chan_mode_implemented(). */
#include "core/connection.h"
#include "core/channel.h"
#include "core/message.h"
#include "core/fanout.h"
#include "core/cap.h"
#include "core/reply.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/link.h"
/* Phase 9: 2.1's remote-nick registry. SNICK rekeys it, which is what makes a
 * rename network-visible -- see fed_in_snick() for the three places it has to
 * land and why all three are needed. */
#include <stdlib.h>

#include "federation/nickreg.h"
#include "federation/membership.h"
#include "federation/notify.h"
#include "federation/state.h"

/* ---------------------------------------------------------------------------
 * fed_obs: printf for a log line whose %s arguments are PEER strings
 * ---------------------------------------------------------------------------
 * WHY IT EXISTS, and it is the same argument reply.c's `emit_numeric_ex()` makes for
 * numerics. This file had thirty-odd `[observable]` lines and most of them printed a
 * value the peer chose -- a member name, a mode string, a reason, an advertised host
 * -- with a bare `%s` and no filter between the socket and an operator's terminal. A
 * policy with thirty enforcement points is a policy with twenty-nine chances to be
 * forgotten, and the one this tree already wrote ("there is no second reader") was
 * wrong: the operator reading this log IS the reader, and there is no argument that an
 * operator's terminal is not one.
 *
 * SO IT IS ONE FUNCTION AND EVERY SITE SAYS `fed_obs`. Since #135 it is NOT static:
 * `federation/burst.c` is the other large peer-path logger in the node and could not
 * reach it, which meant the policy this function documents was in force in one file
 * out of five that logs peer data. It is declared in verbs.h, and
 * `scripts/check-peer-log-sites.py` is the sweep that keeps every site honest --
 * including this one, which a reader of the other four files would otherwise have
 * no reason to believe in. A `%s` argument is rendered
 * through `conn_text_logsafe()` before it reaches stdout: kept verbatim when every
 * byte is printable ASCII, and WITHHELD as `-` when one is not, which is the tree's
 * standing convention for a log-only field (`cmd_unknown: command=-` beside a
 * `command_len=`). Every other conversion -- `%d`, `%zu`, `%llu`, `%02x`, `%c` --
 * is passed straight through, because a length or a count is this node's own number and
 * filtering it would make the line lie.
 *
 * WHAT IT DOES NOT DO, and the two things a caller still owns:
 *
 *   - IT DOES NOT MEASURE. `conn_text_logsafe()` withholds and the caller decides
 *     whether the line also carries `len=` and `bad_bytes=`. A site that is reporting
 *     a refusal wants the measurement -- `fed_advertise_refused:` and `fed_modes:`
 *     below print it, because an operator reading "this peer was refused" needs to
 *     know what it sent -- and a site that is reporting progress does not.
 *   - IT DOES NOT FILTER STORED STATE. A peer string this node STORES goes through
 *     that field's own policy: a roster name through `valid_nick()`, a topic through
 *     `chan_set_topic()`, a mode letter through `chan_mode_implemented()`. This
 *     function is about what this node PRINTS, and the distinction is the same one
 *     connection.h's policy table draws between a field that is stored and a field that
 *     is only logged.
 *
* THE FIELD BUFFER IS ONE 256-BYTE BUFFER, reused per field, because each field is
* written out before the next one is read and nothing here outlives its own `fputs()`.
* A peer string longer than the buffer prints `-`, which is a loss of text and never a
* loss of safety -- and the sites whose values can be long print a length beside them.
*
 * COST: one pass per `%s` argument, on a path that runs once per peer line. The
 * walker is a format-string scan rather than a `printf`, so it is not the libc's
 * formatter and does not inherit its behaviour. Every conversion is pulled off the
 * va_list BY THIS FUNCTION and rendered with `snprintf()`, and that is a correctness
 * requirement rather than a style preference: an earlier version handed the built spec
 * to `vfprintf()` for the non-`%s` conversions and read the `%s` ones with `va_arg()`.
 * Mixing the two on one `va_list` compiled, passed the format attribute at every call
 * site, and then had `vfprintf()` consume NOTHING at -O2 -- so every `%s` after a `%d`
 * on the same line read the *previous* argument. It surfaced as a segfault in
 * `conn_text_logsafe()` on `fd=%d command=%s state=%s`, which is the luckiest possible
 * symptom: it faulted rather than printing a number where a string belonged. So there
 * is no `vfprintf()` here, and the closed set of conversions below is what makes that
 * safe -- `%s`, `%d`, `%i`, `%u`, `%o`, `%x`, `%X`, `%c`, and `%%`, with `h`, `l`, `ll`
 * and `z` honoured for width. Anything else ends the line instead of guessing.
 */
#define FED_OBS_FIELD 256
/* The characters that may sit between the `%` and the conversion letter, split into the
 * ones that only shape the output and the ones that decide the argument's WIDTH. Kept as
 * two lists because conflating them is how a format walker ends up reading a `size_t` as
 * an `int`. */
#define FED_OBS_SPEC "-+ #0123456789.*hlLqjzt"
#define FED_OBS_LEN "hlLqjzt"

void fed_obs(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

void fed_obs(const char *fmt, ...)
{
    /* One field buffer, 256 bytes so a whole topic (CHAN_MAX_TOPIC is 255) or a
     * hostmask fits without being withheld for length. It is ONE buffer rather than
     * one per field because every field is written out before the next one is read:
     * nothing here outlives its own fputs(). The first version kept four slots and
     * held each rendered field until the line was done, which made a line with five
     * CONVERSIONS -- not five `%s`, five, `fed_advertise:`'s `load=%u` and
     * `fed_shutdown:`'s `relayed=%d` among them -- print `-` for everything past the
     * fourth. A separate array per field was the wrong shape for a writer that never
     * reads a field twice. */
    char out[FED_OBS_FIELD];
    const char *q;
    char len[3];
    va_list ap;
    size_t nlen;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    for (const char *p = fmt; *p != '\0'; p++) {
        if (*p != '%') {
            const char *span = p;

            while (p[1] != '\0' && p[1] != '%') {
                p++;
            }
            (void)fwrite(span, 1u, (size_t)(p - span + 1), stdout);
            continue;
        }
        if (p[1] == '%') {
            (void)fputc('%', stdout);
            p++;
            continue;
        }
        /* Split the spec into "flags and width" and "length modifiers", because the
         * length modifier is what decides how WIDE the argument is, and reading the
         * wrong width off a va_list is undefined rather than merely wrong. `z` and `ll`
         * and `l` are the three in use here and are checked by name below. */
        nlen = 0u;
        q = p + 1;
        while (*q != '\0' && strchr(FED_OBS_SPEC, *q) != NULL) {
            if (strchr(FED_OBS_LEN, *q) != NULL && nlen + 1u < sizeof len) {
                len[nlen++] = *q;
            }
            q++;
        }
        len[nlen] = '\0';

        /* `%s` IS THE POINT OF THE FUNCTION. */
        if (*q == 's') {
            const char *v = va_arg(ap, const char *);

            (void)conn_text_logsafe(out, sizeof out, v);
        } else if (*q == 'd' || *q == 'i') {
            long long v = (strchr(len, 'z') != NULL)   ? (long long)va_arg(ap, size_t)
                          : (nlen >= 2u && len[0] == 'l' && len[1] == 'l')
                              ? va_arg(ap, long long)
                              : (len[0] == 'l') ? (long long)va_arg(ap, long)
                                                 : (long long)va_arg(ap, int);

            (void)snprintf(out, sizeof out, "%lld", v);
        } else if (*q == 'u' || *q == 'o' || *q == 'x' || *q == 'X') {
            unsigned long long v = (strchr(len, 'z') != NULL)
                                       ? (unsigned long long)va_arg(ap, size_t)
                                   : (nlen >= 2u && len[0] == 'l' && len[1] == 'l')
                                       ? va_arg(ap, unsigned long long)
                                   : (len[0] == 'l') ? (unsigned long long)va_arg(ap, unsigned long)
                                                      : (unsigned long long)va_arg(ap, unsigned int);

            (void)snprintf(out, sizeof out, (len[0] == 'h') ? "%llx" : "%llu", v);
        } else if (*q == 'c') {
            unsigned char v = (unsigned char)va_arg(ap, int);

            /* A peer byte is NOT printed here even as a character: `cmd_unknown:` prints
             * `command_len=` and `bad_bytes=` for that, and this exists for the one
             * ASCII control the logsafe helper itself reports. */
            if (v < 0x20u || v > 0x7eu) {
                (void)snprintf(out, sizeof out, "-");
            } else {
                (void)snprintf(out, sizeof out, "%c", (int)v);
            }
        } else {
            /* NOT A CONVERSION THIS FUNCTION KNOWS. The line ends here rather than
             * continuing, because a conversion that was not pulled off the va_list has
             * left it misaligned and every later field would name the wrong argument.
             * The `printf` attribute above means no call site in the tree can reach this,
             * so the branch is a statement about what happens if one ever does -- a
             * terminated line with a withheld field is a readable defect; a line whose
             * fields name the wrong values is not. */
            (void)fputc('-', stdout);
            (void)fputc('\n', stdout);
            va_end(ap);
            return;
        }
        (void)fputs(out, stdout);
        p = q;
    }
    va_end(ap);
}


/* The map, once, in the order 4.3 lists the client verbs rather than in the
 * order of the S-verbs, so that a reader comparing this against the design does
 * it by eye and in the same sequence. A `switch` would be the other way to do
 * it and would be worse for a table this small: it duplicates the name of every
 * verb in the source, so a typo in one arm compiles cleanly and returns the
 * wrong thing at run time, and it makes "is this verb forwarded at all" a
 * question about a switch's coverage rather than about one array. */
static const struct {
    const char *client;
    const char *sverb;
} S_VERBS[] = {
    { "PRIVMSG", "SPRIVMSG" },
    { "NOTICE",  "SNOTICE"  },
    { "JOIN",    "SJOIN"    },
    { "PART",    "SPART"    },
    { "TOPIC",   "STOPIC"   },
    /* SMODES, not 4.3's SSMODE and not the obvious SMODE. See verbs.h. */
    { "MODE",    "SMODES"   },
    { "KICK",    "SKICK"    },
    /* SNICK, which 4.3's list does not name and Phase 9 adds. 2.1's
     * rename-the-loser policy cannot be network-visible without it: a rename this
     * node performs on its own client is invisible to every peer, and a peer that
     * does not learn it keeps resolving the old name to this server. The two
     * problems are the same problem -- 2.1 says the loser must be told "on the
     * wire, not silently renamed locally" -- and the wire is what SNICK is.
     *
     * IT IS A SIXTEENTH VERB AND NOT A CHANGE TO AN EXISTING ONE, which is the
     * compatibility argument: 4.3.1's frozen format is the BURST family, and a
     * rename is not a burst record, so nothing about SBURST is touched. A peer
     * that predates this counts it in n_fed_unknown_verb and applies no rename --
     * which is a stale nickname rather than a corrupted roster, and is the
     * failure this one-liner is worth. */
    { "NICK",    "SNICK"    }
};

const char *fed_sverb_for(const char *client_verb)
{
    size_t i;

    if (client_verb == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof S_VERBS / sizeof S_VERBS[0]; i++) {
        if (strcmp(S_VERBS[i].client, client_verb) == 0) {
            return S_VERBS[i].sverb;
        }
    }
    return NULL;
}

const char *fed_queue_why_name(fed_queue_why_t why)
{
    /* Read into an int, and given a `default`, because of the pair upstream
     * clang's -Weverything puts in one switch: -Wswitch-default wants a
     * `default` on a switch over an enum and -Wcovered-switch-default reports
     * that `default` as redundant when every enumerator is listed, so a switch
     * written both ways satisfies neither. Reading the value into an int
     * satisfies both, and a reason added later lands in the `default` that says
     * it has no name yet rather than off the end of the function. fanout.c
     * documents the pair; fed_federate_reason() in federation/link.c is the
     * same shape. */
    int which = (int)why;

    switch (which) {
    case (int)FED_QUEUE_OK:
        return "OK";
    case (int)FED_QUEUE_BAD_TAGS:
        return "BAD_TAGS";
    case (int)FED_QUEUE_TAG_TOO_LONG:
        return "TAG_BLOCK_TOO_LONG";
    case (int)FED_QUEUE_UNBUILDABLE:
        return "UNBUILDABLE";
    case (int)FED_QUEUE_UNRENDERABLE:
        return "UNRENDERABLE";
    case (int)FED_QUEUE_SATURATED:
        return "LINK_SATURATED";
    default:
        /* Unreachable while fed_queue_why_t is closed and every member is
         * listed. A BUG REPORT if it is ever reached, so it says so rather than
         * returning a name that does not correspond to anything. */
        fed_obs("[observable] fed_queue_unknown: why=%d\n", which);
        return "UNKNOWN";
    }
}

/* A refusal, and the only way out of fed_queue_line() other than the queue
 * succeeding. It exists so that every refusal in that function is one line and
 * so that the out-parameter is written in one place: a function with five
 * refusal paths and five `*why_out = ...; return -1;` pairs is a function where
 * one of the five can forget to set it, and a caller reading a stale reason is
 * worse than a caller reading no reason. */
static int fed_queue_refuse(fed_queue_why_t *why_out, fed_queue_why_t why)
{
    if (why_out != NULL) {
        *why_out = why;
    }
    return -1;
}

/* ---------------------------------------------------------------------------
 * fed_relay_clean(): THE ONE PLACE A PEER-BOUND LINE IS FILTERED
 * ---------------------------------------------------------------------------
 * WHY IT EXISTS. `conn_text_strip` appeared NOWHERE in this file, in
 * federation/link.c or in core/fanout.c: a message a peer sent arrived on one link
 * and was written to another with its bytes untouched. The peer-path sweep found
 * it -- 64 marker bytes reaching a peer socket on one run, from
 * `: irc.b SPRIVMSG #P19 :marker \x04 text` -- and `relay_byte_kept()` is what
 * should have removed that `0x04`, because it keeps exactly the eight mIRC bytes
 * and drops every other C0 byte including ESC and BEL.
 *
 * WHY IT IS HERE AND NOT AT EACH VERB. Three reasons, and the first two are the
 * whole of it:
 *
 *   1. IT IS BELOW THE VERB TABLE, so a verb added later cannot forget it. Every
 *      other site that could have filtered this is a site that knows a verb's
 *      parameter layout, and the peer sweep has already caught one row written with
 *      the channel in the wrong slot -- a generator bug that a filter's withholding
 *      then disguised as a pass.
 *   2. IT IS BESIDE `fed_queue_line()`, which is the ONLY place a peer-bound line is
 *      built. One call site is one thing to check; a filter per verb is N things to
 *      keep in step, and this file has now shipped two divergences from exactly
 *      that cause: SMODES applying modes the client path refuses, and the log
 *      values bypassing `fed_obs()`.
 *   3. IT NAMES STRIP_RELAY AND STRIP_STORED IN THE TABLE rather than
 *      reimplementing either. Those two ARE the single implementations of "what
 *      a relayed message may contain" and "what a stored value may contain";
 *      the client relay path in core/msg_verbs.c passes the first for PRIVMSG text.
 *      This table is a statement about WHICH FIELD and WHICH POLICY, and nothing
 *      else -- the byte rules live in one place per policy and a change to either
 *      is a change to both surfaces.
 *
 * WHY TWO POLICIES IN ONE TABLE. Because the client path has two, and a peer relay
 * carries both kinds of field. A message's text is RELAYED, and `relay_byte_kept()`
 * keeps the mIRC formatting bytes a mIRC client renders and dropping them would
 * break. A topic, a kick reason and a mode string are STORED VALUES by the node
 * that receives them, and they go through the stricter stored-value policy -- which
 * is the same split core/msg_verbs.c makes, for the same reason.
 *
 * THE FIELD COUNT AND EVERY POSITION ARE PRESERVED. A stripped parameter becomes an
 * EMPTY parameter, never a missing one: `needs_colon()` puts the `:` marker on an
 * empty final parameter, so a positional parser on the far side finds the field
 * exactly where 4.3 says it is. A relay that dropped the parameter instead would
 * shift every field after it, which is a protocol divergence rather than a filter.
 *
 * COST: one extra pass over the parameters and, when a row matches, one copy of the
 * bytes that were kept. The arena is IRC_MAX_LINE, the same bound the render below
 * it works within, so a value that cannot fit is one `message_format()` would have
 * refused anyway -- and it is reported rather than truncated, because a truncated
 * parameter is a lie about what the peer sent.
 */
static const struct {
    const char *verb;
    int at;                          /* which parameter carries the text */
    conn_text_strip_policy_t policy; /* WHICH policy: message text or stored value */
} OUTBOUND_TEXT[] = {
    /* The two message verbs: index 1 is the text, and it is the same field and the
     * same policy as PRIVMSG's on the client relay path. */
    { "SPRIVMSG", 1, STRIP_RELAY },
    { "SNOTICE",  1, STRIP_RELAY },
    /* The state verbs' free-text fields, all of which the receiving node STORES or
     * renders to clients rather than relays. 4.3's frozen shapes put the channel in
     * the second slot for all three and the evaluating server in the first, which is
     * why these indices are what they are -- and why getting one wrong is a field
     * read from the wrong place rather than a visible error. */
    { "STOPIC",   2, STRIP_STORED },
    { "SKICK",    3, STRIP_STORED },
    { "SMODES",   2, STRIP_STORED },
    /* The 4.3 extension's free-text fields (#563): the realname SSETNAME carries
     * and the message SAWAY carries, both STORED -- a receiving node renders
     * them to its own clients, and the stored-value policy is what the client
     * path applies to the same values. SINVITE has no free text (channel and
     * nick are validated names), so it needs no row. */
    { "SSETNAME", 1, STRIP_STORED },
    { "SAWAY",    1, STRIP_STORED }
};
#define OUTBOUND_TEXT_COUNT \
    ((int)(sizeof OUTBOUND_TEXT / sizeof OUTBOUND_TEXT[0]))

/* Replace the one text parameter of `verb` with a filtered copy of itself.
 *
 * `cleaned` is an array of `IRC_MAX_PARAMS` pointers that the CALLER owns, and
 * only one slot of it ever changes: the field count and every position are
 * preserved, and that is what "the field count is preserved" means in code. A
 * relay that dropped the parameter instead would shift every field after it,
 * which is a protocol divergence rather than a filter.
 *
 * THREE ANSWERS, and the third is the interesting one:
 *
 *   0  NOTHING TO DO. No row for this verb, or the verb's shape has no such
 *      parameter. NOT a refusal: arity belongs to the verb's own table, and a
 *      second arity check here would be one more thing that can disagree with it.
 *   1  `cleaned` IS THE ARRAY TO BUILD FROM. Exactly one slot points into `arena`;
 *      every other slot is the caller's own pointer, copied across unchanged.
 *   -1 THE VALUE CANNOT BE REPRESENTED, and the caller refuses. That this is not a
 *      behaviour change is the point: `strlen(src) + 1 > cap` with cap ==
 *      IRC_MAX_LINE means the rendered line cannot fit either, so
 *      `message_format()` was going to refuse it anyway. Refusing here rather than
 *      truncating the value is the difference between a line that was never
 *      deliverable and a line that lies about what the peer sent.
 */
static int fed_relay_clean(const char *verb, const char *const *params,
                           int nparams, char *arena, size_t cap,
                           const char **cleaned, size_t *src_len,
                           size_t *kept_len)
{
    *src_len = 0u;
    *kept_len = 0u;
    for (int i = 0; i < OUTBOUND_TEXT_COUNT; i++) {
        const char *src;

        if (strcmp(verb, OUTBOUND_TEXT[i].verb) != 0) {
            continue;
        }
        if (OUTBOUND_TEXT[i].at >= nparams ||
            params[OUTBOUND_TEXT[i].at] == NULL) {
            return 0;
        }
        src = params[OUTBOUND_TEXT[i].at];
        *src_len = strlen(src);
        if (*src_len + 1u > cap) {
            *src_len = 0u;
            return -1;
        }
        for (int k = 0; k < nparams; k++) {
            cleaned[k] = params[k];
        }
        *kept_len = conn_text_strip(arena, cap, src, OUTBOUND_TEXT[i].policy);
        cleaned[OUTBOUND_TEXT[i].at] = arena;
        return 1;
    }
    return 0;
}

/* The stamp, the build, the render, the terminator and the queue, in that
 * order, once. The two callers of this used to be the whole of
 * fed_send_sverb()'s body and T3's keepalive in federation/link.c, and the
 * reasons below are the five ways that sequence can refuse.
 *
 * The buffers are two fixed locals rather than anything on server_t, and the
 * sizes are reply.c's arithmetic for the same reason it is there: IRC_MAX_LINE
 * counts a legal line INCLUDING its CRLF and message_format() reserves a byte
 * for its NUL, so a maximal line plus its terminator plus the NUL needs two
 * more than IRC_MAX_LINE. */
int fed_queue_line(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *prefix, const char *verb,
                   const char *const *params, int nparams,
                   fed_queue_why_t *why_out)
{
    char block[IRC_MAX_TAG_OVERHEAD];
    char line[IRC_MAX_LINE + 2];
    /* The arena `fed_relay_clean()` filters into. IRC_MAX_LINE rather than a
     * per-field bound because it is the bound that matters: a filtered value has
     * to fit inside a line the render below cannot exceed, so anything larger was
     * never deliverable. It is a third buffer and that is the cost -- named here
     * rather than left for a reader to notice. */
    char arena[IRC_MAX_LINE];
    const char *cleaned[IRC_MAX_PARAMS];
    const char *const *use = params;
    size_t src_len = 0u;
    size_t kept_len = 0u;
    int filter_rc;
    message_t m;
    size_t blen;
    size_t len;

    /* A NULL where a peer, a stamp or a verb belongs is a caller that has
     * already lost track of the line, and there is no word for it distinct from
     * the render refusal -- so it is reported as the render refusal rather than
     * as a reason of its own that an operator would have to learn. Every
     * caller checks its own arguments first and never reaches this. */
    if (s == NULL || peer == NULL || tags == NULL || prefix == NULL ||
        verb == NULL) {
        return fed_queue_refuse(why_out, FED_QUEUE_UNRENDERABLE);
    }
    /* 2.4's tag grammar is enforced on receipt as well, so an invalid stamp
     * here is a caller that built one wrongly rather than a hostile peer. */
    if (!irc_serve_tags_valid(tags)) {
        return fed_queue_refuse(why_out, FED_QUEUE_BAD_TAGS);
    }
    /* IRC_MAX_TAG_OVERHEAD rather than a block-specific bound, and the two
     * numbers are related in a way worth stating: 179 is the '@' plus the one
     * separating space plus the block, so the block alone is at most 177 and
     * the buffer is 179. It is the right constant to name here precisely
     * because it is the constant 3.2 derived, and a second, block-only bound
     * would be a number nobody re-derives when a value limit moves.
     *
     * irc_serve_tags_format() returns 0 for a block that does not fit, which
     * cannot happen for a stamp it just validated -- so a 0 here means the
     * buffer is not big enough, which is a bug in this file. It is still
     * reported rather than assumed away, because the alternative is the same
     * tagless line the arm above refuses. */
    blen = irc_serve_tags_format(tags, block, sizeof block);
    if (blen == 0u) {
        return fed_queue_refuse(why_out, FED_QUEUE_TAG_TOO_LONG);
    }
    /* THE FILTER, AND IT IS ABOVE THE BUILD so that what gets rendered is what
     * was filtered. Below the argument checks and below the stamp, and above
     * `message_build()` -- which is the whole of "one place a peer-bound line is
     * filtered": there is no path from a parameter to a peer socket in this file
     * that does not pass through these six lines.
     *
     * AND THE MEASUREMENT IS REPORTED. Stripping a value a peer sent is invisible
     * on the wire -- the far side sees a shorter field and cannot tell that
     * anything happened -- so a node that silently shortened relayed text would be
     * indistinguishable from one that mangled it. The line is the same shape as
     * every other measurement in this tree: what was kept, how many bytes came
     * off, and how many of those were in the strip set. */
    filter_rc = fed_relay_clean(verb, params, nparams, arena, sizeof arena,
                                cleaned, &src_len, &kept_len);
    if (filter_rc < 0) {
        return fed_queue_refuse(why_out, FED_QUEUE_UNRENDERABLE);
    }
    if (filter_rc > 0) {
        use = cleaned;
        /* REPORTED ONLY WHEN SOMETHING CAME OFF, because a line for every relayed
         * message would put this node's log rate under the mesh's message rate, and
         * a log that cannot be read is not a measurement. The count is what an
         * operator needs: a peer whose text is arriving shortened is either a peer
         * with a broken client or a peer doing this on purpose. */
        if (kept_len < src_len) {
            fed_obs("[observable] fed_relay_stripped: verb=%s kept=%zu "
                   "removed=%zu\n",
                   verb, kept_len, src_len - kept_len);
        }
    }
    if (message_build(&m, block, prefix, verb, use, nparams) != 0) {
        return fed_queue_refuse(why_out, FED_QUEUE_UNBUILDABLE);
    }
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        /* All or nothing, never a partial line: 3.2 forbids truncating a
         * parameter, and a half-written line on a peer link is not a shorter
         * message but a corrupted protocol stream the peer will misparse. */
        return fed_queue_refuse(why_out, FED_QUEUE_UNRENDERABLE);
    }
    /* RFC 1459 2.3: CRLF. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, peer, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated link is DROPPED, not buffered (3.4). Not counted twice
         * here, and nothing is closed here either. */
        return fed_queue_refuse(why_out, FED_QUEUE_SATURATED);
    }
    if (why_out != NULL) {
        *why_out = FED_QUEUE_OK;
    }
    return 0;
}

int fed_send_sverb(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *client_verb, const char *prefix,
                   const char *const *params, int nparams)
{
    const char *sverb;
    fed_queue_why_t why = FED_QUEUE_OK;
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";

    /* The refusals are reported, not returned quietly, for the reason every
     * other [observable] refusal in this node is: a federated node that dropped
     * a forwarded message for want of a verb name would otherwise look exactly
     * like a node whose peers were silent, and the two have opposite fixes. */
    if (s == NULL || peer == NULL || client_verb == NULL || prefix == NULL ||
        (params == NULL && nparams != 0)) {
        /* MEASURED FROM THE SAME TERNARY THAT IS PRINTED, so the number describes the
         * value ON THE LINE. Measuring the unguarded `client_verb` would be a NULL
         * dereference on exactly the branch this refusal exists to report, and the
         * fallback's length of 1 is the correct answer rather than a fudge: the line
         * says `verb=?`. */
        fed_obs("[observable] fed_sverb_refused: verb=%s reason=bad_args "
                "verb_len=%zu verb_bad_bytes=%zu\n",
               (client_verb != NULL) ? client_verb : "?",
               strlen((client_verb != NULL) ? client_verb : "?"),
               conn_text_bad_count((client_verb != NULL) ? client_verb : "?"));
        return -1;
    }
    /* An ALREADY-MAPPED verb is not mapped again. A caller that hands this an
     * S-verb by mistake would otherwise put `SSPRIVMSG` on the wire, and the
     * refusal below is the same one a client verb with no S-verb gets -- which
     * is the right answer for both, because both are "this node has no S-verb
     * for that". The one caller that legitimately has an S-verb in hand
     * (fanout_forward_sverb(), relaying) calls fed_queue_line() directly. */
    sverb = fed_sverb_for(client_verb);
    if (sverb == NULL) {
        fed_obs("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=NO_SVERB verb_len=%zu verb_bad_bytes=%zu target_len=%zu target_bad_bytes=%zu\n",
               client_verb, target, strlen(client_verb), conn_text_bad_count(client_verb), strlen(target), conn_text_bad_count(target));
        return -1;
    }

    /* The stamp and the wire are the shared half; the verb and the two refusal
     * words above and below are this function's own, because a keepalive is
     * not an S-verb and reports under a different [observable] line. See
     * fed_queue_line() in verbs.h. */
    if (fed_queue_line(s, peer, tags, prefix, sverb, params, nparams, &why) != 0) {
        fed_obs("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=%s verb_len=%zu verb_bad_bytes=%zu target_len=%zu target_bad_bytes=%zu\n",
               client_verb, target, fed_queue_why_name(why), strlen(client_verb), conn_text_bad_count(client_verb), strlen(target), conn_text_bad_count(target));
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * The DECODE side: the handlers G10 reaches
 * ---------------------------------------------------------------------------
 *
 * Every one of them does the same two things and nothing else: apply the fact to
 * this node's local state, and pass the line on. Neither is optional -- an
 * inbound state change that is applied but not relayed stops the mesh
 * converging, and one that is relayed but not applied leaves this node's cache
 * permanently behind the origin's.
 *
 * WHY THERE IS NO LOCAL CLIENT EMISSION, and it is a gap rather than a decision.
 * An inbound SJOIN names a member but carries only a SERVER prefix, because the
 * member's hostmask is not on the wire and 4.3's burst vocabulary is where it
 * belongs. A client cannot be shown ":bob!user@host JOIN #T" from a prefix that
 * says only "irc.b", and a JOIN with a server prefix is a line no client
 * understands. So a local member learns about a remote member through the
 * ROSTER -- 353, which 7/Phase 6's acceptance criterion is about -- and not yet
 * through a channel echo. The gap closes when SBURST carries the per-member host
 * and realname (4.3, driven in Phase 9). Writing a JOIN with an invented host
 * would be worse than the gap: 2.1's whole point is that a hostmask is OBSERVED
 * rather than asserted.
 */

/* Keep a channel's member-server set in step with the roster, where the set is
 * a refcount the ORIGIN keeps and the only count this node can take locally is
 * of its own cache.
 *
 * THE COST, stated because it is a real one: a member the origin has and this
 * node has not been told about is invisible here, so an SPART for the last
 * KNOWN member from a server that still has others behind it removes the
 * servers[] entry early -- and the channel is then no longer in that peer's
 * forward set, so a state change for it stops reaching them until the origin
 * re-reports a member. 2.2 says a non-owner's state is a cache and that caches
 * are allowed to be incomplete and self-healing; the alternative -- never
 * decrementing -- makes the set grow for the life of the channel and turns 3.1's
 * target set into "every server this node has ever heard of", which is the
 * global list the design explicitly rejects. */
void fed_touch_server(chan_t *ch, const char *server, int adding)
{
    if (adding != 0) {
        (void)chan_server_add(ch, server);
        return;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].server, server)) {
            return; /* somebody from that server is still known */
        }
    }
    (void)chan_server_remove(ch, server);
}

/* The actor an inbound state line renders with. An S-verb's raw prefix is a
 * peer-chosen string: a hostmask on a well-formed mesh, a server name on a
 * relayed line or the s->name fallback, arbitrary bytes from a malicious
 * peer. Rendering it raw puts `:irc.x JOIN #T` -- unparseable as an actor --
 * on clients, so the prefix is trusted only when it IS a hostmask (`!`
 * before `@`). Otherwise the burst-populated roster record speaks:
 * `nick!user@host` from stored fields. A known member with no record yet
 * renders as the bare nick -- the same rule 353 uses for empty-host entries
 * -- except for JOIN, which withholds entirely: gap 2's burst completion
 * emits the held JOIN, and `nick!*@*` is forbidden. A NULL nick (SMODES,
 * whose subject is the evaluating server) has no roster identity and no
 * bare form: NULL means withhold, and that caller falls back to the subject
 * server explicitly rather than through here. Returns a pointer valid for
 * the immediate fed_local_emit() call only when it returns `out`. */
const char *fed_actor_prefix(const chan_t *ch, const char *nick,
                                    const char *prefix, int withhold_bare,
                                    char *out, size_t cap)
{
    if (prefix != NULL) {
        const char *bang = strchr(prefix, '!');

        if (bang != NULL && strchr(bang + 1, '@') != NULL) {
            return prefix; /* observed hostmask: the only attribution on the wire */
        }
    }
    if (nick != NULL && ch != NULL) {
        for (size_t i = 0; i < ch->nremotes; i++) {
            const chan_remote_t *m = &ch->remotes[i];

            if (!chan_same_name(m->nick, nick)) {
                continue;
            }
            if (m->user[0] != '\0' && m->host[0] != '\0') {
                (void)snprintf(out, cap, "%s!%s@%s", m->nick, m->user,
                               m->host);
                return out;
            }
        }
    }
    if (withhold_bare || nick == NULL) {
        return NULL;
    }
    return nick;
}

/* The local half of an inbound state verb: resolve the channel and write the
 * client-shaped line to local members, with NO forward. The forward is the
 * handler's existing fanout_forward_channel_sverb() call, which is untouched:
 * this only adds the local emission fed_in_message() has always had. One
 * helper rather than inline code in seven handlers, so the resolve class
 * cannot drift between them: every state verb resolves FANOUT_STATE_CHANGE,
 * and deliver_local writes to members of either channel kind without
 * forwarding, which is exactly the half that was missing. */
void fed_local_emit(server_t *s, chan_t *ch, const char *prefix,
                     const char *verb, const char *const *params, int nparams)
{
    fanout_target_t t;

    if (ch == NULL || verb == NULL) {
        return;
    }
    if (fanout_resolve(s, NULL, ch->name, FANOUT_STATE_CHANGE, &t) == 0) {
        return;
    }
    (void)fanout_deliver_local(s, &t, prefix, verb, params, nparams, NULL);
}

/* Advertise family (ADVERTISE store + collision check): split out for #543 into
 * federation/advertise.c; the store readers stay declared in federation/link.h. */

/* fed_forward_all() -- verbs.h states why this exists and what the two shapes of
 * 4.3's verb set are. The body is SQUIT's broadcast loop with SQUIT's two
 * exclusions left at ITS call site, which is what keeps the general function free
 * of a verb it has no business naming. */
int fed_forward_all(server_t *s, const char *sverb, const char *prefix,
                    const char *const *params, int nparams)
{
    int carried = 0;

    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *lk = server_link_at(s, k);

        if (lk == NULL || lk->state != (int)ESTABLISHED) {
            continue;
        }
        /* == 0 IS SUCCESS, which is the shape fanout_forward_sverb() returns and
         * the shape every call site in this file tests. Inverting it here would
         * make the count mean the opposite of the one a reader expects. */
        if (fanout_forward_sverb(s, lk->name, sverb, prefix, params, nparams, NULL) ==
            0) {
            carried++;
        }
    }
    return carried;
}

