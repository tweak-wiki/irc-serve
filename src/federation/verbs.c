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

/* Parse the SJOIN flags token back into a flag word. The token is 4.3's frozen
 * single token (see fed_flag_token()), so this is a two-letter scan and not a
 * grammar: `+`, then `o` and/or `v`, or the literal `-`. A duplicate letter is
 * refused rather than collapsed, because a flags word this node does not
 * understand is a membership it would render wrongly in 353 and a line whose
 * author we could not describe. */
static int fed_parse_flags(const char *tok, unsigned *out)
{
    unsigned f = 0u;

    if (tok == NULL || tok[0] == '\0' || out == NULL) {
        return -1;
    }
    if (strcmp(tok, "-") == 0) {
        *out = 0u;
        return 0;
    }
    if (tok[0] != '+') {
        return -1;
    }
    for (size_t i = 1; tok[i] != '\0'; i++) {
        if (tok[i] == 'o' && (f & CHAN_MEMBER_OP) == 0u) {
            f |= CHAN_MEMBER_OP;
        } else if (tok[i] == 'v' && (f & CHAN_MEMBER_VOICE) == 0u) {
            f |= CHAN_MEMBER_VOICE;
        } else {
            return -1;
        }
    }
    if ((f & (CHAN_MEMBER_OP | CHAN_MEMBER_VOICE)) == 0u) {
        return -1; /* `+` with no letters names nothing */
    }
    *out = f;
    return 0;
}

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

/* The channel an inbound S-verb names, canonicalised, or NULL.
 *
 * A channel this node has never heard of is created HERE, from an SJOIN only,
 * and that is the one place a channel enters a federated node other than through
 * a local JOIN: an SJOIN proves the SENDER has a member, so by 2.2's "first
 * server to see a channel owns it" the origin is the sender. The other four state
 * verbs do not create -- they describe a change to a channel that already exists,
 * and a peer that could invent a channel here by parting from it could make this
 * node hold channels nobody joined. It is created with
 * the link's own epoch as its origin_epoch, which is the one field the wire
 * gives us about the creating boot and is what makes a later creation-race
 * comparison between two real values rather than between a value and a
 * placeholder.
 *
 * 2.2's full tie-break also needs the (epoch, name) of the FIRST creator, which
 * a bare SJOIN cannot distinguish from a relayed one -- that is 4.3's SBURST
 * vocabulary and 4.3 says the burst REPLACES rather than merges. So a
 * re-keying decision is NOT made here and a node that receives two SJOINs for
 * the same channel from two peers keeps the first origin it learned. That is a
 * known gap with a known owner (Phase 9's resync), and it is stated here rather
 * than left to be discovered as a split-brain. */
static chan_t *fed_in_channel(server_t *s, server_link_t *link, const char *name,
                              int create)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (s == NULL || link == NULL || name == NULL || !chan_name_valid(name)) {
        return NULL;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    ch = server_chan_get(s, canonical);
    if (ch == NULL && create == 0) {
        /* Only SJOIN creates. An SPART, STOPIC, SMODES or SKICK for a channel
         * this node has never heard of is REFUSED rather than creating it: those
         * verbs describe a change to a channel that already exists, and a peer
         * that could invent a channel here by parting from it would be able to
         * make this node hold channels nobody joined. */
        return NULL;
    }
    if (ch == NULL) {
        ch = chan_new(canonical, link->name, link->epoch);
        if (ch == NULL || server_chan_attach(s, ch) != 0) {
            chan_free(ch);
            return NULL;
        }
        fed_obs("[observable] chan_create: channel=%s origin=%s epoch=%llu "
               "creator=%s\n",
               ch->name, ch->origin, (unsigned long long)ch->origin_epoch,
               link->name);
    }
    return ch;
}

/* SPRIVMSG / SNOTICE: <target> <text>.
 *
 * A `message` class line, so 3.1 applies both channel rows at once: write to
 * local members AND forward -- to the owner if this node does not own the
 * channel, to servers[] UNION the ESTABLISHED links if it does. The local write
 * goes through fanout_deliver() with the CLIENT verb (a client is never sent an
 * S-verb) and the prefix is the one the line arrived with, which for a
 * peer-relayed SPRIVMSG is a real hostmask and is therefore the only thing this
 * node could put on the message for its own clients.
 *
 * AND THIS FUNCTION FORWARDS NOTHING ITSELF. It used to: it wrote locally
 * through fanout_deliver() and then called fanout_forward_channel_sverb() with
 * the received `tags`. That was a SECOND forward of the same emission, and it
 * was invisible until 3.1's owned/`message` row was amended, because until then
 * the only node that received a `message` was the owner and an owner had no
 * forward arm for the first of the two to double up on. With the amendment every
 * node that receives a `message` has a forward arm, and the two calls together
 * would have sent the owner TWO copies of one client message: one from
 * fanout_deliver()'s forward, which had no `carry` and therefore MINTED A FRESH
 * id, and one from here, which carried the real one. The fresh id is the worse
 * of the two -- 2.4 says a relay changes hops and nothing else, and a restamp is
 * how a message comes back.
 *
 * So the tags go INSTEAD, as fanout_deliver()'s `carry`, and the forward happens
 * once, in the one place 3.1's table is transcribed. What that argument buys is
 * not tidiness: it is that the local write and the forward cannot be given
 * different identities, which is the failure this whole function is shaped to
 * make unrepresentable. */
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams);
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams)
{
    int delivered = fanout_deliver(s, t, prefix, client_verb, params, nparams, NULL,
                                   tags);

    /* The LOCAL half, reported. The client-side path reports its own
     * deliveries in msg_verbs.c's `msg:` line, and a relayed message has no
     * such line anywhere -- it arrives on a peer link and is fanned out from
     * here -- so without this a node's log shows a message arriving from a
     * peer and nothing about what it did with it. The count is the number of
     * local members written to, which is 0 on a node that is purely a relay,
     * and that zero is the interesting value rather than a disappointing one.
     *
     * It is also the countable line a loop shows up in: a message that keeps
     * circulating prints this again, so "delivered exactly once" can be
     * asserted from the node as well as from the client. */
    /* `from_len=` is measured from the SAME ternary that is printed, not from the bare
     * `prefix`: on the fallback branch `prefix` is NULL and strlen(NULL) is the crash
     * this measurement sits next to a guard to avoid. The reported 1 is the length of
     * the `?` the reader can actually see. */
    fed_obs("[observable] fed_message: channel=%s from=%s delivered=%d "
           "origin=%s hops=%lu channel_len=%zu channel_bad_bytes=%zu "
           "origin_len=%zu origin_bad_bytes=%zu from_len=%zu from_bad_bytes=%zu\n",
           t->name, (prefix != NULL) ? prefix : "?", delivered, tags->origin,
           (unsigned long)tags->hops, strlen(t->name), conn_text_bad_count(t->name),
           strlen(tags->origin), conn_text_bad_count(tags->origin),
           strlen((prefix != NULL) ? prefix : "?"),
           conn_text_bad_count((prefix != NULL) ? prefix : "?"));
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

/* SJOIN: <channel> <member> <flags> <account> <user> <host>. */
static void fed_in_sjoin(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    unsigned flags = 0u;

    /* SIX PARAMETERS NOW, not four: `<channel> <member> <flags> <account> <user>
     * <host>`, and the arity is the FORMAT's and is enforced here rather than
     * guessed at, which is the reason the table in this file carries an SJOIN
     * row of 6,6. A peer running a build without the 4.3 extension sends four
     * and is refused, which is a loud incompatibility rather than a member
     * silently recorded with no host -- and the same direction 4.3.1 chose for
     * `<server>`, which was added before a second implementation existed rather
     * than after. The version bump is what keeps the two builds from linking at
     * all, so this refusal is a backstop rather than a case that happens. */
    if (nparams != 6 || fed_parse_flags(params[2], &flags) != 0 ||
        strlen(params[4]) > (size_t)CONN_USER_MAX ||
        strlen(params[5]) > (size_t)CHAN_MAX_REMOTE_HOST ||
        /* NULL for the HOLDER, and that absence is the whole of what an SJOIN can
         * say about one: 4.3's SJOIN carries no server field, so the holder is
         * unknown and is recorded as such ("not told", which chan_remote_add()
         * stores as empty). Writing the link's name here would file a guess as a
         * fact: exact on a two-node mesh, a relay's name on a larger one, and a
         * fact the next burst from whoever holds the member then has to
         * overwrite. The burst corrects it -- SBURSTM carries the holder, and
         * install overwrites the empty one -- and a repeat SJOIN must not clobber
         * what the burst established. It does not: chan_remote_add() only
         * overwrites the holder when the repeat carries one, and the send path's
         * fallback to the key stays a best effort that a burst replaces rather
         * than a stored answer. */
        chan_remote_add(ch, link->name, NULL, params[1], params[3], flags) != 0) {
        /* The `nparams > 1` guard is why the measurement comes from the SAME ternary
         * rather than from `params[1]`: on the branch where the guard failed,
         * params[1] does not exist. */
        if (chan_remote_count(ch) >= (size_t)CHAN_MAX_REMOTE_MEMBERS) {
            s->n_remote_roster_full++;
        }
        fed_obs("[observable] fed_sjoin_reject: channel=%s member=%s server=%s "
                "member_len=%zu member_bad_bytes=%zu\n",
               ch->name, (nparams > 1) ? params[1] : "?", link->name,
               strlen((nparams > 1) ? params[1] : "?"),
               conn_text_bad_count((nparams > 1) ? params[1] : "?"));
        return;
    }
    /* <user> and <host>, the 4.3 extension's fields: `-` is "not told" (the
     * sender's spelling of an empty ident or host), translated to "" on receipt
     * the way the account's `*` is. Set SEPARATELY from the add above, the way
     * burst.c installs them from its shadow records: the two have different
     * failure modes, and a refusal of one must not cost the other. The length
     * check above means the setters cannot fail on width here. */
    (void)chan_remote_set_user(ch, link->name, params[1],
                               (params[4][0] == '-' && params[4][1] == '\0')
                                   ? ""
                                   : params[4]);
    (void)chan_remote_set_host(ch, link->name, params[1],
                               (params[5][0] == '-' && params[5][1] == '\0')
                                   ? ""
                                   : params[5]);
    /* 2.1's REGISTRY, on the LIVE path and not only on the burst path, and the
     * reason is that a burst is per link ESTABLISHMENT: a member who joined this
     * node's mesh ten minutes after the last one would be unknown to a registry
     * fed only by SBURST, and 2.1's scoped `nick@server` would 401 a user who is
     * right there. SJOIN is the only verb that reports a user joining, so it is
     * the only place a live registry entry can come from. The registry's holder
     * is the LINK -- 4.3's SJOIN carries no server field, and a registry with no
     * answer cannot route, so the link is the best available -- while the roster
     * above records the absence and waits for a burst. The two disagree only for
     * a relaying peer's own best guess, which the next burst corrects. */
    fed_nickreg_learn_member(s, params[1], link->name, link->name, server_now_ms());
    /* 2.1's POLICY, ON THE LEARNING SIDE, and the reason it is a second call site
     * rather than a detail of the learn above: a user can register `zed` on a node
     * whose registry is empty and only later learn that a peer holds it, and a
     * node that checked only at claim time would leave that user holding the name
     * for ever. The far side of the same pair runs the same function against the
     * same two names, so between the two of them exactly one renames -- which is
     * the convergence fed_nickreg_local_loses() exists to make possible. */
    (void)fed_nickreg_resolve_local(s, params[1], server_now_ms());
    fed_touch_server(ch, link->name, 1);
    fed_obs("[observable] fed_sjoin: channel=%s member=%s server=%s flags=%u "
           "local=%zu remote=%zu origin=%s owned=%d member_len=%zu member_bad_bytes=%zu\n",
           ch->name, params[1], link->name, flags, ch->nmembers, ch->nremotes,
           ch->origin, chan_origin_is_self(s, ch), strlen(params[1]), conn_text_bad_count(params[1]));

    /* The JOIN this node's own clients see. The actor is the observed hostmask
     * when the line carries one; otherwise the burst-described roster record --
     * and when the member has no record yet, nothing at all: the next burst
     * that completes the record emits the held JOIN, and neither a guessed
     * `nick` nor a forbidden `nick!*@*` ever reaches a client. */
    {
    char actor[CONN_HOSTMASK_MAX];
    const char *who = fed_actor_prefix(ch, params[1], prefix, 1, actor,
                                       sizeof actor);

    if (who != NULL) {
        fed_local_emit(s, ch, who, "JOIN", NULL, 0);
    }
}
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SJOIN", prefix,
                                       params, nparams, tags);
}

/* SNICK: <old nick> <new nick>.
 *
 * IT NAMES NO CHANNEL, which is why it is NOT IN INBOUND: every row of that
 * table is dispatched with its channel read from a fixed parameter position, and
 * a two-parameter verb whose second parameter is a nickname has no position that
 * is a channel. See the dispatch in fed_handle_message() for how SQUIT solves the
 * same problem, and for why SNICK is asked in the same place rather than given a
 * position that lies.
 *
 * THE EFFECT IS IN THREE PLACES, and all three are needed or a rename is only
 * half-applied:
 *   - 2.1's registry: the entry that answered `<old>`@<this peer> must answer
 *     `<new>` instead, or every subsequent `old@peer` on this node still routes
 *     here and every `new@peer` is a 401.
 *   - the CHANNEL ROSTERS: the member is keyed (server, nick), so a rekeyed
 *     member whose roster row still says the old name is a member the roster
 *     cannot render and SPART cannot later remove.
 *   - the LOCAL CLIENTS: an SJOIN/SPART fanout is what teaches a client's view
 *     of the roster, and a rename that skips it leaves a client showing a name
 *     the server no longer holds.
 *
 * AND IT IS NOT A STATE-DESTROYING VERB, which is the reason it is not routed
 * through the same refusal chain a SQUIT is: nothing here ends, and a peer that
 * sends it for a name this node never held is a peer with a stale view rather
 * than one trying to remove a channel's member. It is still a 401-free silent
 * accept, because "I do not have that nick" is not an error worth breaking a
 * link over -- the next SBURST is the authority, and this node will correct
 * itself then.
 */
static void fed_in_snick(server_t *s, server_link_t *link, const char *prefix,
                         const irc_serve_tags_t *tags, const char *const *params,
                         int nparams)
{
    int renamed = 0;

    if (nparams != 2) {
        return;
    }
    /* THE PREFIX IS IGNORED, and that is load-bearing rather than lazy. SNICK is
     * forwarded to every established peer EXCEPT the one it came from, so on a
     * three-node mesh a rename the middle node performed is seen by the third
     * node as a rename the MIDDLE node performed. Attributing it to the prefix
     * instead would move the member to a different server's roster, which is the
     * misattribution 4.3.1 added `<server>` to SBURSTM to prevent. The member's
     * server is the LINK, because a rename does not move anybody between servers
     * -- it changes what this one calls them. */
    (void)prefix;

    fed_nickreg_rename(s, link->name, params[0], params[1], server_now_ms());
    fed_obs("[observable] fed_nickreg_rename: server=%s from=%s to=%s to_len=%zu to_bad_bytes=%zu\n", link->name,
           params[0], params[1], strlen(params[1]), conn_text_bad_count(params[1]));

    /* THE ROSTERS, one channel at a time. There is no index from nickname to
     * channel, and there must not be: a member's name is not a global key, so a
     * node-wide map would be a second registry whose only use is this walk and
     * whose staleness would then be a second thing to reconcile. The walk is
     * O(channels) and this node has a bounded number of them. */
    for (size_t ci = 0, nch = server_chan_count(s); ci < nch; ci++) {
        chan_t *ch = server_chan_at(s, ci);

        if (ch == NULL || ch->nremotes == 0) {
            continue;
        }
        if (chan_remote_rename(ch, link->name, params[0], params[1]) == 1) {
            renamed++;
            fed_touch_server(ch, link->name, 0);
            /* THE CHANNEL'S OWN CLIENTS, and the prefix is the LINK because the
             * line as it arrives names the link; fanout_forward_channel_sverb()
             * renders the prefix itself and this is the shape every other
             * state-change verb uses. A member's rename inside a channel is
             * something a client watching the channel must be told, and the
             * fanout is the only path to a client that exists. */
            (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SNICK",
                                               link->name, params, nparams, tags);
            /* The NICK the channel's own clients see: old nick as the prefix
             * with the new nick as the parameter, exactly the shape nickreg.c
             * renders for a local rename. */
            {
                const char *lp[1];

                lp[0] = params[1];
                fed_local_emit(s, ch, params[0], "NICK", lp, 1);
            }
        }
    }
    if (renamed == 0) {
        /* NO ROSTER HELD IT, which is the ordinary case for a user who is
         * connected but not in any channel this node knows about -- the common
         * case on a relay. The registry is still updated above, and a rename
         * that reaches nobody is not a failure: there was nothing to tell. */
        fed_obs("[observable] fed_snick: server=%s from=%s to=%s rosters=0 to_len=%zu to_bad_bytes=%zu\n",
               link->name, params[0], params[1], strlen(params[1]), conn_text_bad_count(params[1]));
    } else {
        fed_obs("[observable] fed_snick: server=%s from=%s to=%s rosters=%d to_len=%zu to_bad_bytes=%zu\n",
               link->name, params[0], params[1], renamed, strlen(params[1]), conn_text_bad_count(params[1]));
    }
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

/* ---------------------------------------------------------------------------
 * The inbound table, and the verbs it does not have
 * ---------------------------------------------------------------------------
 *
 * G8 asks this table for the VERB the peer sent, which is an S-verb -- the
 * encode direction's output is this table's input, which is what makes the two
 * halves of this file one format rather than two. A table rather than a switch
 * for the reason fed_sverb_for() gives: a switch duplicates every name in the
 * source, so a typo in one arm compiles cleanly and returns the wrong thing at
 * run time.
 *
 * `min`/`max` are the parameter bounds, and they are the FROZEN shapes' bounds
 * rather than a range: an SJOIN is always six parameters, an SPART is two or
 * three, and a verb arriving with a different count is a peer running a
 * different format and is REFUSED rather than guessed at. Refusing is the safe
 * direction because the alternative -- reading params[1] of a two-parameter
 * SPRIVMSG -- is a read of a field that does not exist.
 */
static const struct {
    const char *verb;
    int min;
    int max;
    void (*fn)(server_t *, server_link_t *, fanout_target_t *, const char *,
               const irc_serve_tags_t *, const char *const *, int);
    int vclass; /* what the target is resolved under, and the row it takes */
    const char *client_verb; /* what a RELAY of it is called */
} INBOUND[] = {
    { "SPRIVMSG", 2, 2, NULL, FANOUT_MESSAGE,  "PRIVMSG" },
    { "SNOTICE",  2, 2, NULL, FANOUT_MESSAGE,  "NOTICE"  },
    { "SJOIN",    6, 6, NULL, FANOUT_STATE_CHANGE, "JOIN"  },
    { "SPART",    2, 3, NULL, FANOUT_STATE_CHANGE, "PART"  },
    { "STOPIC",   3, 3, NULL, FANOUT_STATE_CHANGE, "TOPIC" },
    { "SMODES",   3, 4, NULL, FANOUT_STATE_CHANGE, "MODE"  },
    { "SKICK",    3, 4, NULL, FANOUT_STATE_CHANGE, "KICK"  }
};

static int inbound_index(const char *verb)
{
    if (verb == NULL) {
        return -1;
    }
    for (size_t i = 0; i < sizeof INBOUND / sizeof INBOUND[0]; i++) {
        if (strcmp(INBOUND[i].verb, verb) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* The 4.3 words this build does not speak yet, and WHY THAT IS NOT "unknown".
 *
 * SNAMES and SHASH are in 4.3's list and are not in INBOUND, because they are
 * later commits of this phase. They are listed here so that a peer sending one
 * is told this node has not implemented it rather than that it is not a verb -- a
 * distinction an operator needs, because the first means "a peer is running a
 * build I do not have" and the second means "a peer is talking nonsense".
 * Reporting them through n_fed_unknown_verb would make the counter mean two
 * incompatible things and stop being evidence of anything.
 *
 * SQUIT IS NOT HERE ANY MORE, and its removal is the change C5 made: the
 * departure announcement landed, so a peer sending one gets the purge rather than
 * a version fact. A verb that arrives and is handled must not leave its name in a
 * table that says it is not handled, or the table becomes a place where a reader
 * learns which half of the phase is finished -- which is what the list said about
 * SBURST before C4 removed it, and is why this paragraph exists.
 *
 * FEDERATE is NOT here: it never reaches G8, because G2 consumes it, and it is
 * the verb that ESTABLISHES the epoch every other tag rule is stated against. */
static const char *const DEFERRED[] = { "SNAMES", "SHASH" };

static int is_deferred(const char *verb)
{
    for (size_t i = 0; i < sizeof DEFERRED / sizeof DEFERRED[0]; i++) {
        if (strcmp(DEFERRED[i], verb) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * fed_dispatch -- the guard chain
 * ---------------------------------------------------------------------------
 */
void fed_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    irc_serve_tags_t tags;
    server_link_t *link;
    fanout_target_t t;
    char peer[IRC_MAX_SERVER_NAME + 1];
    const char *pserver;
    /* message_t::params is `char *[]` and every handler here takes
     * `const char *const *`, and C will not add that qualification silently to
     * an array of pointers. A local array is the copy that makes it legal, and
     * it does the arity bound as a side effect: G9 has already checked nparams
     * against the verb's frozen shape, so nothing past cap can be written and
     * the handlers cannot be handed a longer list than the wire shape allows. */
    const char *sp[IRC_MAX_PARAMS];
    int idx;

    /* --- G0: NULL args, no command -------------------------------------- */
    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* THE LINK IS LOOKED UP BY THE CONNECTION'S PEER NAME, and that is safe
     * here for a reason the connection's name being a display copy does not
     * obviously give. A connection only becomes CONN_SERVER in
     * fed_link_established(), which sets peer_name from the claim the handshake
     * accepted, and 2.3's uniqueness check guarantees at most one link holds
     * that name. So a CONN_SERVER conn names exactly one link, and
     * server_find_link() is that link. It is deliberately NOT a search by
     * descriptor: federation/link.c's fed_link_of_conn() documents the
     * recycled-descriptor trap a `link->fd == c->fd` lookup falls into, and this
     * path does not have it. */
    link = (c->peer_name != NULL) ? server_find_link(s, c->peer_name) : NULL;

    /* --- G1: pre-auth ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") != 0 &&
        (link == NULL || link->state != (int)ESTABLISHED)) {
        /* Dropped, and the link is NOT torn down. A line on a connection that is
         * not an established peer link is a stranger talking, and the answer to
         * a stranger is the handshake, not a closed socket: the same connection
         * is one second away from sending a FEDERATE. Tearing it down here would
         * make a peer that speaks before it says hello permanently
         * unconnectable, and the handshake FSM has no way to recover from that.
         *
         * Counted, because a node whose pre-auth drops climb is a node that is
         * being spoken to by something that is not a peer, and that is a finding
         * rather than a statistic. */
        s->n_fed_preauth_drop++;
        fed_obs("[observable] fed_preauth_drop: fd=%d command=%s state=%s command_len=%zu command_bad_bytes=%zu\n", c->fd,
               m->command,
               (link != NULL) ? ((link->state == (int)ESTABLISHED) ? "ESTABLISHED"
                                                                     : "PENDING")
                              : "NONE", strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G2: FEDERATE ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* The one verb that is exempt from every tag rule below, and it is
         * exempt BY CONSTRUCTION rather than by a special case: the epoch this
         * line is about to be judged against is the one it ESTABLISHES. A
         * FEDERATE carries no 2.4 block because 2.4's block is what a receiver
         * needs in order to deduplicate and loop-check a message, and a
         * handshake is neither relayed nor looped. */
        fed_on_federate(s, c, m);
        return;
    }

    /* --- G3: still not ESTABLISHED --------------------------------------- */
    if (link == NULL || link->state != (int)ESTABLISHED) {
        /* UNREACHABLE after G1, and kept as the assertion that the two cannot
         * disagree. A counted return rather than a silent one, so an edit that
         * reorders G1 and G3 leaves a number behind instead of a hole. */
        s->n_fed_preauth_drop++;
        fed_obs("[observable] fed_preauth_drop: fd=%d command=%s state=UNREACHABLE command_len=%zu command_bad_bytes=%zu\n",
               c->fd, m->command, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G4: the 2.4 tag block, and the trust boundary -------------------- */
    if (irc_serve_tags_parse(m, &tags) != 0) {
        pserver = fed_prefix_server(m->prefix, peer, sizeof peer);

        if (pserver == NULL) {
            /* CASE D. A prefix that is not a usable server name at all: absent,
             * empty, over-long, or a name the 2.4 tag grammar would refuse. There
             * is no identity to synthesise and no server to say it belongs to
             * someone else, so this is malformed rather than a relay -- and
             * counting it as a relay would tell an operator their peer is
             * misbehaving in a specific way when the line is simply not a line
             * this node can reason about. */
            s->n_fed_malformed++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "prefix=%s reason=BAD_PREFIX command_len=%zu command_bad_bytes=%zu "
                   "prefix_len=%zu prefix_bad_bytes=%zu\n",
                   c->fd, link->name, m->command,
                   (m->prefix != NULL) ? m->prefix : "(none)", strlen(m->command),
                   conn_text_bad_count(m->command),
                   strlen((m->prefix != NULL) ? m->prefix : "(none)"),
                   conn_text_bad_count((m->prefix != NULL) ? m->prefix : "(none)"));
            return;
        }

        if (is_deferred(m->command)) {
            /* CASE C. A 4.3 verb this build does not speak, arriving untagged.
             * Refused, but reported as what it is: a peer running a build with
             * the resync verbs is a version fact, and calling it an untagged
             * relay would send the operator looking for a loop. */
            s->n_fed_verb_deferred++;
            fed_obs("[observable] fed_verb_deferred: fd=%d peer=%s command=%s command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }

        if (fed_burst_verb(m->command) != 0) {
            /* CASE E, AND IT EXISTS BECAUSE A BURST IS NOT A MESSAGE. Every other
             * verb in this chain is happy to have its identity MINTED for it by
             * case A below, because a message's identity is per line and a
             * missing one costs that line. A burst is O(n) lines forming ONE
             * transaction, and case A mints a fresh id PER LINE -- which is
             * exactly right for dedup and exactly wrong for the thing the
             * transaction is for. A peer that could send an untagged burst would
             * therefore be able to make this node replace its entire view of
             * that origin, as often as it liked, with lines whose 2.4 identity
             * this node invented. So the one verb family that is state REPLACEMENT
             * is required to carry its identity on the wire, and the refusal is
             * counted as malformed rather than as a relay: a peer sending it is
             * not relaying somebody else's burst, it is sending a burst it did
             * not stamp. */
            s->n_fed_malformed++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "reason=BURST_UNTAGGED command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }

        if (!chan_same_name(pserver, link->name)) {
            /* CASE B. The peer is RELAYING and did not stamp the line. REFUSED,
             * and the link is NOT torn down.
             *
             * Every 2.4 guard is unavailable on this line: there is no origin to
             * check against our own name, no hop count to apply the ceiling to,
             * and no (origin, epoch, id) to record, so a store that "saw" it
             * would be recording a key it invented. A node that accepts untagged
             * relays therefore has NO loop prevention at all, and 2.4's three
             * rules are the whole of what stops two nodes bouncing a message for
             * ever. There is no partial acceptance available: either the
             * identity is on the wire or it is not.
             *
             * The discriminator is THE PREFIX and never the verb, and a peer
             * relaying a message it received FOR A CHANNEL IT HAS A MEMBER IN
             * sends `SPRIVMSG` with a REMOTE prefix -- so any rule keyed on the
             * verb would accept exactly the dangerous case and refuse the
             * harmless one. */
            s->n_fed_untagged_relay++;
            fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s prefix=%s "
                   "reason=RELAY_UNTAGGED command_len=%zu command_bad_bytes=%zu prefix_len=%zu prefix_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, pserver, strlen(m->command), conn_text_bad_count(m->command), strlen(pserver), conn_text_bad_count(pserver));
            return;
        }

        /* CASE A. The peer ORIGINATED the line: its prefix is its own server
         * name. Accepted, with the identity SUPPLIED rather than read.
         *
         * MINTING THE ID LOCALLY IS THE POINT. An untagged originated line has
         * no identity of its own, and a node that forwarded it with a
         * synthesised one has to invent an id; inventing it from the
         * per-SERVER counter is what makes the invented value unique to this
         * node and therefore safe to put in a key the far side will store.
         *
         * AND IT IS THE PEER'S EPOCH, not s->epoch, and the reason is subtle
         * enough to be worth the paragraph. The key is (origin, epoch, id) and
         * the origin here is the PEER, so the epoch has to be the boot the
         * peer's own id stream belongs to: a key whose epoch belongs to a
         * different boot than its id is a key that aliases. If this node stamped
         * s->epoch here, every relay node on a path would pair ITS counter with
         * an epoch that is not the counter's, and two of them relaying the same
         * untagged line would mint two DIFFERENT keys for one message -- so a
         * third node would accept both copies and deliver the message twice, with
         * dedup unable to collapse them because there is nothing shared to
         * collapse on. With the peer's epoch, both relayers mint into the SAME
         * (peer, peer-boot) id space, two relays of one untagged line collapse
         * onto one key, and the second copy is dropped as the duplicate it is.
         *
         * THE COST, because a bound that cannot be reached is not a bound: the
         * id is drawn from THIS node's counter while the epoch is the peer's, so
         * a synthetic id can in principle collide with the peer's own id of the
         * same number, and the peer would then have its genuine message dropped
         * as a duplicate. That is the recoverable direction: dedup.h states it,
         * that a dropped message is one lost message whereas a store that failed
         * to record is a loop, and it is reachable only by a peer that sent an
         * untagged line in the first place. A colliding key is the correct
         * answer to a line that claims to be from a boot we cannot see the
         * counter of. */
        memset(&tags, 0, sizeof tags);
        memcpy(tags.origin, link->name, strlen(link->name) + 1u);
        tags.epoch = link->epoch;
        tags.id = server_next_msg_id(s);
        tags.hops = 0u;
        fed_obs("[observable] fed_untagged: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu reason=ORIGINATED_UNTAGGED command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id, strlen(m->command), conn_text_bad_count(m->command));
    }

    /* --- G5: the hop ceiling --------------------------------------------- */
    if (tags.hops >= (uint32_t)IRC_MAX_HOPS) {
        /* 2.4: "irc-serve-hops increments per forward and the message is dropped
         * at 10." Checked on RECEIPT as well as at forward time, and the two are
         * not the same check: the forward-time one refuses to SPREAD a message
         * that is at the ceiling, and this one refuses to ACT on one that
         * arrived at it. A node that only checked at forward time would apply a
         * message that some other node had already decided to stop. */
        s->n_fed_hop_drop++;
        fed_obs("[observable] fed_hop_drop: fd=%d peer=%s command=%s hops=%lu "
               "ceiling=%d command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, (unsigned long)tags.hops, IRC_MAX_HOPS, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G6: never act on our own origin ---------------------------------- */
    if (chan_same_name(tags.origin, s->name)) {
        /* 2.4: "A node never forwards a message whose irc-serve-origin is
         * itself." The INBOUND half of it, and the half that makes "a two-node
         * ping-pong does not loop" true: a message this node originated came
         * back, and applying it would re-deliver to the local members it was
         * already delivered to and then forward it onward again. On a two-node
         * mesh that is the whole cycle; on a three-node mesh it is the short one
         * inside a longer one.
         *
         * The comparison is ASCII case-insensitive because server names are
         * (2.1, RFC 1459 2.3.2) and a peer that spells this node's name `IRC.A`
         * is naming THIS node. Treated as a different server, the hop ceiling
         * would be the only thing left and it is ten, so a two-node mesh would
         * bounce one message ten times before it stopped.
         *
         * IT IS REDUNDANT WITH G7, and it stays anyway. The dedup store is
         * bounded (IRC_DEDUP_MAX slots) and evictable (IRC_DEDUP_TTL_MS), so a
         * bound that CAN be reached is not a loop guard -- a node that has been
         * up for a while, or one on a busy mesh, can legitimately have evicted
         * the very entry that would have caught this. A rule that is a
         * belt-and-braces today is the only rule left when the braces are
         * dropped, and the hop ceiling is the second belt rather than the first:
         * it bounds the damage, it does not stop the loop. */
        s->n_fed_own_origin++;
        fed_obs("[observable] fed_own_origin_drop: fd=%d peer=%s command=%s "
               "origin=%s self=%s hops=%lu command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin, s->name,
               (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G7: the dedup store --------------------------------------------- */
    {
        int dedup = fed_dedup_seen(s, &tags, server_now_ms());

        if (dedup < 0) {
            /* THE STORE FAILED, and the message is dropped WITHOUT being
             * counted as a duplicate (#174). An allocation failure reported as
             * a duplicate would read on every dashboard as replay traffic,
             * and the memory pressure behind it would be invisible. */
            s->n_fed_dup_drop++;
            s->n_fed_dedup_error++;
            fed_obs("[observable] fed_dedup_error: fd=%d peer=%s command=%s origin=%s "
                   "epoch=%llu id=%llu hops=%lu command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, tags.origin,
                   (unsigned long long)tags.epoch, (unsigned long long)tags.id,
                   (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }
        if (dedup != 0) {
        /* RECORDED HERE, AT THE GUARD, AND NOT AFTER THE HANDLER.
         *
         * Dedup is a statement about the WIRE, not about whether this node
         * handled the message: a peer is not obliged to be correct, and nothing
         * stops a buggy or hostile one from sending the same id twice, once
         * well-formed and once not. A store that recorded only successfully
         * handled messages would take the second as new and act on it. So the
         * key is recorded on SIGHT, which is why this guard is above the verb
         * lookup and above the field validation: a message dropped by G8 or G9
         * is already recorded, and a peer cannot retry the same line under a new
         * id and get a different answer. A retry with a NEW id is a different
         * message, and 2.4's epoch exists so that a restarted peer is told to
         * use different ids.
         *
         * The two counters are incremented together because they are the same
         * event read at two levels -- the guard's drop and the store's duplicate
         * -- and a difference between them is either a store error
         * (n_fed_dedup_error, the <0 arm above) or a bug in the chain rather
         * than a number nobody looked at. */
        s->n_fed_dup_drop++;
        s->n_fed_dedup_dup++;
        fed_obs("[observable] fed_duplicate: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu hops=%lu command_len=%zu command_bad_bytes=%zu\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id,
               (unsigned long)tags.hops, strlen(m->command), conn_text_bad_count(m->command));
        return;
        } /* dedup != 0: a real duplicate */
    }

    /* --- G8: the verb ----------------------------------------------------- */
    /* THE BURST FAMILY IS ASKED BEFORE THE TABLE, and it is a separate branch
     * rather than five rows because it is not this kind of verb. INBOUND's rows
     * all describe a line about a CHANNEL, at a position the verb fixes, within
     * a two-or-three parameter arity; SBURSTC names the channel first and
     * carries six parameters, SBURSTM carries three, and SBURST carries two
     * numerics and names no channel at all. Rows for them would have arity ranges
     * that are individually correct and collectively a lie, and the handler
     * dispatch below reads the channel out of a position that means something
     * different for each verb.
     *
     * THEY ARE STILL GATED BY EVERYTHING ABOVE, which is the point of asking
     * here rather than earlier: a burst is state REPLACEMENT, so it is
     * hop-checked, own-origin-checked and deduplicated like anything else, and a
     * REPLAYED burst is the worst case this phase has. G9's arity check is not
     * applied to these five -- their shapes are five different shapes and the
     * format is where they are stated -- so each arm validates its own, and
     * federation/burst.c owns that because federation/burst.c is where the wire
     * format is. */
    if (fed_burst_verb(m->command) != 0) {
        (void)fed_burst_apply(s, link, m);
        return;
    }

    /* SQUIT, and the same placement argument one paragraph up: it names no
     * channel, so INBOUND's position-indexed read cannot reach it, and it is
     * asked HERE -- after the burst family and before the table -- so that
     * everything above still applies to it. That is the load-bearing part. A
     * SQUIT is the most state-destroying line in 4.3, and it is deduplicated
     * (G7), hop-checked (G5) and own-origin-checked (G6) by the same chain as an
     * SJOIN, which is why it is here and not in a second entry point. */
    if (strcmp(m->command, "SQUIT") == 0) {
        /* The same local array the table arms below use, and for the same reason
         * (message_t::params is `char *[]` and the handler takes a qualified
         * one). It is filled here rather than handed over as `m->params` because
         * the handler reads up to two entries and the wire can carry fifteen. */
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_squit(s, link, &tags, sp, m->nparams);
        return;
    }

    /* SNICK, in SQUIT's place in the chain, for SQUIT's reason: it names no
     * channel, so INBOUND's position-indexed read cannot reach it. It is asked
     * AFTER the SQUIT arm and BEFORE the table, so a SQUIT's own-origin
     * refusal and the burst family's ownership checks are all unaffected -- a
     * rename arriving on a link this node does not hold a member for is
     * unremarkable, and the two verbs must not be able to shadow each other. */
    if (strcmp(m->command, "SNICK") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_snick(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }

    /* SSETNAME, SAWAY and SINVITE, in SNICK's place in the chain, for SNICK's
     * reason: none of them fits INBOUND's position-indexed read. SSETNAME and
     * SAWAY name no channel at all, and SINVITE names a channel AND a user --
     * a row for it would resolve the wrong target and relay it as a channel
     * state change, which an invite is not. They are asked AFTER the SNICK arm
     * and BEFORE the table, so the guard chain above has already run: G1, G4,
     * G5, G6 and G7 all apply, and a peer replaying one line under a new id
     * is recorded rather than re-applied. */
    if (strcmp(m->command, "SSETNAME") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_ssetname(s, link, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SAWAY") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_saway(s, link, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SINVITE") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_sinvite(s, link, &tags, m->prefix, sp, m->nparams);
        return;
    }

    /* ADVERTISE AND SHUTDOWN, asked HERE for SQUIT's reason: neither names a
     * channel, so INBOUND's position-indexed read cannot reach either, and a row
     * for them would have to lie about what it reads. They are asked AFTER the
     * SNICK arm and BEFORE the table, so the whole of the guard chain above has
     * already run for them: G1 has refused a line from a link that is not
     * ESTABLISHED, G4 has resolved the 2.4 identity, G5 has checked the hop
     * ceiling, G6 has refused a line this node originated, and G7 has recorded the
     * key so a peer cannot retry the same line under a new id.
     *
     * IT MATTERS FOR ADVERTISE SPECIFICALLY, and that is why these two are here
     * rather than handled before the chain: an ADVERTISE carries a dial hint, and
     * a dial hint is the one thing on this node's wire that must never reach the
     * dial path. Handling it before the chain would mean accepting a hint from
     * anything that opened a TCP connection, which is a stranger, and the secret
     * in FEDERATE is the only thing that makes a peer a peer. */
    if (strcmp(m->command, "ADVERTISE") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_advertise(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }
    if (strcmp(m->command, "SHUTDOWN") == 0) {
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_shutdown(s, link, m->prefix, &tags, sp, m->nparams);
        return;
    }

    idx = inbound_index(m->command);
    if (idx < 0) {
        if (is_deferred(m->command) != 0) {
            s->n_fed_verb_deferred++;
            fed_obs("[observable] fed_verb_deferred: fd=%d peer=%s command=%s command_len=%zu command_bad_bytes=%zu\n",
                   c->fd, link->name, m->command, strlen(m->command), conn_text_bad_count(m->command));
            return;
        }
        s->n_fed_unknown_verb++;
        fed_obs("[observable] fed_unknown_verb: fd=%d command=%s peer=%s command_len=%zu command_bad_bytes=%zu\n", c->fd,
               m->command, link->name, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* --- G9: arity and fields -------------------------------------------- */
    /* Every field is validated with the SAME rule the local surface uses, and
     * that is the point rather than a detail: a nickname arrives here from a
     * network for the first time, and 2.1's charset exists because later phases
     * build on it. chan_remote_add() applies it to the nickname and the 2.4
     * grammar to the server name, so the roster cannot hold a name this node
     * could not qualify or render. */
    if (m->nparams < INBOUND[idx].min || m->nparams > INBOUND[idx].max) {
        s->n_fed_malformed++;
        fed_obs("[observable] fed_malformed: fd=%d command=%s field=arity "
               "nparams=%d want=%d..%d command_len=%zu command_bad_bytes=%zu\n",
               c->fd, m->command, m->nparams, INBOUND[idx].min, INBOUND[idx].max, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }
    /* --- G10: the handler -------------------------------------------------- */
    if (INBOUND[idx].vclass == FANOUT_MESSAGE) {
        /* The message verbs name the TARGET first, and there is nothing to
         * create: a SPRIVMSG does not prove a channel exists, it only says
         * somebody spoke in it. A channel this node does not hold is the
         * ordinary "not a member of my mesh" case, counted as malformed rather
         * than created, because creating a channel from a message would let any
         * peer invent channels on this node by talking in them.
         *
         * fanout_resolve() is asked with a NULL sender: the numerics it would
         * send have no client to go to, and asking for one would put a non-zero
         * on the counter server.h says should be zero forever. It is still the
         * one resolver, and `t.vclass` is still what it decides the row from. */
        if (fanout_resolve(s, NULL, m->params[0], FANOUT_MESSAGE, &t) == 0) {
            s->n_fed_malformed++;
            fed_obs("[observable] fed_malformed: fd=%d command=%s field=target "
                   "target=%s reason=NO_SUCH_TARGET command_len=%zu command_bad_bytes=%zu target_len=%zu target_bad_bytes=%zu\n",
                   c->fd, m->command, m->params[0], strlen(m->command), conn_text_bad_count(m->command), strlen(m->params[0]), conn_text_bad_count(m->params[0]));
            return;
        }
        /* The TEXT is the second parameter and it is the whole payload; the
         * target is the first and fanout_deliver() prepends t->name itself. */
        for (int i = 0; i < m->nparams - 1; i++) {
            sp[i] = m->params[i + 1];
        }
        /* ------------------------------------------------------------------
         * THE INBOUND HALF OF fed_relay_clean(), AND THE PEER SWEEP FOUND IT.
         * ------------------------------------------------------------------
         *
         * WHAT WAS MISSING, and it is a whole half of one line's journey. Three
         * filters already existed and none of them is on this path:
         *
         *   - `msg_verbs.c` filters a CLIENT's message text before fanning it out,
         *     with `conn_text_strip()` under STRIP_RELAY;
         *   - `fed_relay_clean()` below `fed_queue_line()` filters the same text
         *     again on the way to a PEER, with the same policy;
         *   - `write_to_members()` -> `send_line_tagged()` filters NOTHING, and it
         *     is what writes to a local client.
         *
         * So a message a PEER originated went peer -> this node -> a person's
         * terminal with its bytes untouched, while the identical message a client
         * on this same node originated was stripped. `test_peer_terminal_sweep`
         * found it on Linux as `:irc.b PRIVMSG #P549 :marker \x9f text` -- a bare
         * C1 control, which on an 8-bit terminal IS CSI -- and macOS reported the
         * same sweep clean, which turned out to be the sweep's own blind spot
         * rather than a platform difference (it drained the client buffer once per
         * marker and then swept only what arrived after the last drain).
         *
         * WHY HERE AND NOT IN `fed_in_message()`. Same reason `fed_relay_clean()`
         * sits below the verb table rather than in each verb: this is BELOW G9's
         * arity check, so a message verb added to INBOUND later cannot forget it,
         * and a table row that knows a verb's parameter layout is a site that can
         * be written wrong -- which the sweep has already caught once, with the
         * channel in the wrong slot of an SMODES row.
         *
         * WHICH POLICY, and it is the SAME one for the same reason the outbound
         * table uses it: this field is RELAYED MESSAGE TEXT, and the eight mIRC
         * formatting bytes in it are semantics a client renders rather than hazard.
         * The stored-value policy (`conn_text_strip()`, used for a topic or a kick
         * reason) would strip a colour code off every message on the network. So
         * the call below and the row above it name the same function, and a change
         * to the rules is a change to both halves.
         *
         * WHY THE STATE VERBS ARE NOT HERE. `STOPIC`, `SKICK` and `SMODES` reach a
         * local client only through `fanout_forward_channel_sverb()`, which writes
         * to PEERS and does not emit locally at all -- the gap `fed_dispatch`'s own
         * header names. So the peer->client exposure this fix closes is the message
         * path, and the state verbs' exposure is the forward path, which
         * `fed_relay_clean()` already covers. That is worth stating because the
         * difference is invisible from the table: the two halves of INBOUND look
         * identical and are filtered by different functions for that reason.
         *
         * THE MEASUREMENT IS REPORTED, for `fed_relay_clean()`'s reason: stripping
         * a peer's text is invisible on the wire -- the far side sees a shorter
         * field and cannot tell anything happened -- so a node that silently
         * shortened relayed text would be indistinguishable from one that mangled
         * it. `n_msg_stripped` is the same counter the client path increments,
         * because it is the same decision about the same field; the line below it
         * says which half of the node did it.
         *
         * COST: one extra pass over the text and one bounded copy, on the peer path
         * for the two message verbs, and only when the peer's line was accepted.
         * The 8 KiB arena is scoped to this block so it is not held for the state
         * verbs below, and it is `IRC_MAX_LINE` because the line is already bounded
         * by the framing layer -- stripping only removes bytes, so the filtered
         * value always fits in what the unfiltered one occupied.
         *
         * AND THE DELIVERY IS INSIDE THE BLOCK, which the first version of this was
         * NOT and which the sanitizer cell caught as a stack-use-after-scope. `sp[0]`
         * is a POINTER, and it was left pointing at `clean` while the closing brace
         * ended `clean`'s lifetime; `fed_in_message()` then read it back through
         * `message_build()` and got whatever the frame had become. It passed all
         * twelve build cells and every local test, because a dead stack read is only a
         * wrong answer when the reused bytes are not the right ones -- which is the
         * same reason this project's leak and use-after-free work keeps coming back to
         * Linux. The arena's scope and the pointer's scope are now the same scope, and
         * that is stated here because "the block ends after the call" is the kind of
         * thing a later edit tidies away. */
        {
            char clean[IRC_MAX_LINE];
            const size_t in_len = strlen(sp[0]);
            const size_t kept = conn_text_strip(clean, sizeof clean, sp[0], STRIP_RELAY);

            sp[0] = clean;
            if (kept != in_len) {
                s->n_msg_stripped++;
                fed_obs("[observable] fed_message_stripped: verb=%s kept=%zu "
                       "removed=%zu verb_len=%zu verb_bad_bytes=%zu\n",
                       m->command, kept, in_len - kept, strlen(m->command), conn_text_bad_count(m->command));
            }
            fed_in_message(s, &t, m->prefix, &tags, INBOUND[idx].client_verb, sp,
                           m->nparams - 1);
        }
        return;
    }
    {
        /* The state verbs name the channel in DIFFERENT PARAMETER POSITIONS --
         * first for SJOIN, second for the rest -- which is 4.3's frozen shape
         * and the reason this lookup is here rather than a single index. A
         * handler that read the wrong position would apply a state change to the
         * wrong channel, and "the wrong channel" is not a crash, it is a
         * divergence. */
        size_t at = (strcmp(m->command, "SJOIN") == 0) ? 0u : 1u;
        /* The node-wide cap (#542): refused HERE, before fed_in_channel() fails
         * it, because the NULL arm below reports that as fed_malformed and a
         * capacity refusal is not a peer protocol error. No client to numeric on
         * this path, so the observable IS the refusal, in handle_join's spelling. */
        if (strcmp(m->command, "SJOIN") == 0 &&
            chan_name_valid(m->params[at]) &&
            server_chan_get(s, m->params[at]) == NULL &&
            s->nchan_objs >= SERVER_MAX_CHANNELS) {
            fed_obs("[observable] chan_create_refused: channel=%s peer=%s "
                   "nchan=%zu cap=%d reason=TOO_MANY_CHANNELS "
                   "channel_len=%zu channel_bad_bytes=%zu\n",
                   m->params[at], link->name, s->nchan_objs, SERVER_MAX_CHANNELS,
                   strlen(m->params[at]), conn_text_bad_count(m->params[at]));
            return;
        }
        chan_t *ch = fed_in_channel(s, link, m->params[at],
                                    strcmp(m->command, "SJOIN") == 0);

        if (ch == NULL) {
            s->n_fed_malformed++;
            fed_obs("[observable] fed_malformed: fd=%d command=%s field=channel "
                   "channel=%s command_len=%zu command_bad_bytes=%zu channel_len=%zu channel_bad_bytes=%zu\n",
                   c->fd, m->command, m->params[at], strlen(m->command), conn_text_bad_count(m->command), strlen(m->params[at]), conn_text_bad_count(m->params[at]));
            return;
        }
        for (int i = 0; i < m->nparams; i++) {
            sp[i] = m->params[i];
        }
        if (strcmp(m->command, "SJOIN") == 0) {
            fed_in_sjoin(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SPART") == 0) {
            fed_in_spart(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "STOPIC") == 0) {
            fed_in_stopic(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SMODES") == 0) {
            fed_in_smodes(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SKICK") == 0) {
            fed_in_skick(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else {
            /* Unreachable: every enumerator of INBOUND is named above, and
             * G8 is the only way here. It is a BUG REPORT rather than a silent
             * return, because a table row with no arm is a verb this node
             * advertises by handling and does not do. */
            fed_obs("[observable] fed_unhandled_verb: command=%s command_len=%zu command_bad_bytes=%zu\n", m->command, strlen(m->command), conn_text_bad_count(m->command));
        }
    }
}
