/* verbs.c -- see verbs.h. The shared vocabulary both sides of 4.3's S-verbs
 * report through: fed_obs() and the inbound helpers. The encoder lives in
 * federation/encode.c, the guard chain in federation/dispatch.c. */
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

