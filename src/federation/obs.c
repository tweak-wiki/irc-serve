/* obs.c -- fed_obs(): the ONE printf for a peer-path log line.
 *
 * Split out of federation/verbs.c (#543): moved verbatim. Declared in
 * federation/obs.h and re-exported through federation/verbs.h.
 */
#include "federation/obs.h"

/* For fed_obs() below, which is printf for a log line whose %s arguments are peer
 * strings and has to walk a format string and a va_list to do it. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* For conn_text_logsafe() and conn_text_bad_count() -- a peer string this node
 * PRINTS is log-only and is therefore measured rather than filtered, for the same reason a
 * client string printed on this node's stdout is. A peer string this node STORES goes
 * through the field's own policy, and SMODES through chan_mode_implemented(). */
#include "core/connection.h"

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
 * out of five that logs peer data. It is declared in obs.h (re-exported through
 * verbs.h), and
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
