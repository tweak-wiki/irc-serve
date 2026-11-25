/* obs.h -- fed_obs(): the ONE printf for a peer-path log line.
 *
 * Split out of federation/verbs.c (#543): moved verbatim; re-exported through
 * federation/verbs.h so every existing consumer keeps working untouched.
 */
#ifndef IRC_FEDERATION_OBS_H
#define IRC_FEDERATION_OBS_H

/* ---------------------------------------------------------------------------
 * fed_obs -- the ONE printf for a peer-path log line, exported for burst.c
 * ---------------------------------------------------------------------------
 * WHAT THIS IS, in one sentence: `printf` with every `%s` argument rendered
 * through `conn_text_logsafe()` first, so a string the PEER chose cannot put a
 * control byte in an operator's terminal.
 *
 * WHY IT IS EXPORTED AND NOT STATIC, which is where it was until #135. The
 * policy argument for having it at all -- "a policy with thirty
 * enforcement points is a policy with twenty-nine chances to be forgotten" -- is
 * only true if there is ONE function. Leaving it static meant
 * `federation/burst.c` could not use it, and burst.c is the second-largest
 * peer-path logger in the node with 27 `[observable]` lines of its own, so the
 * choice was between a duplicated formatter (two policies, one of which nobody
 * would remember to update) and exporting the one. The export is the whole answer,
 * and the block in obs.c that says "SO IT IS ONE FUNCTION AND EVERY SITE
 * SAYS fed_obs" is now true across the peer path rather than true of one file.
 *
 * WHAT IT DOES NOT COVER, stated here because the export invites the assumption:
 *   - the STORED fields. A peer string this node STORES goes through that field's
 *     own policy (`valid_nick()`, `chan_set_topic()`, `irc_serve_server_name_valid()`,
 *     `chan_name_valid()`), which is a different question from what it PRINTS.
 *   - `link->name` and the other validated server names. A server name is made of
 *     printable bytes by construction, so routing it through the filter would cost
 *     a pass on every peer line to protect against nothing -- and every remaining
 *     raw `[observable] printf` in the peer path prints exactly these, this node's
 *     own counters, or fixed literals.
 *
 * COST: one pass per `%s` argument, on a path that runs once per peer line. It is a
 * format-string walker rather than the libc's formatter, so it does not inherit the
 * libc's behaviour: the closed conversion set is `%s`, `%d`, `%i`, `%u`, `%o`,
 * `%x`, `%X`, `%c` and `%%`, with `h`, `l`, `ll` and `z` honoured for width, and
 * anything else ends the line rather than guessing. See obs.c's block above the
 * definition for why that is a correctness requirement and not a style preference.
 *
 * scripts/check-peer-log-sites.py is what keeps the policy at every site, including
 * the ones this function's own header would let a reader believe are covered.
 */
void fed_obs(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#endif /* IRC_FEDERATION_OBS_H */
