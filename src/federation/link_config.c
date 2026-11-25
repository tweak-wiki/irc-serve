/* link_config.c -- see federation/link.h. The link open/close and the per-node
 * timer/retry overrides.
 *
 * Split verbatim out of link.c (issue #543 TU-30): fed_open()/fed_close(),
 * fed_set_timeouts()/fed_hs_due()/fed_set_retry(), and link_wipe() (whose
 * sole caller is fed_close()). All five functions stay declared in
 * federation/link.h (the tick.c precedent: no new header). The FEDERATE
 * exchange and the dispatch seam stay in link.c and are reached through
 * link.h.
 */
#include "federation/link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wipe `n` bytes at `p`. Written through a volatile pointer for the same reason
 * core/secret_util.c's secret_wipe() is: a
 * memset() to memory that stays live is a store the compiler may prove dead
 * and delete. */
static void link_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    size_t i;

    for (i = 0; i < n; i++) {
        v[i] = 0u;
    }
}

/* ---------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------------
 */
int fed_open(server_t *s, const char *secret)
{
    size_t len;

    if (s == NULL) {
        return -1;
    }
    if (s->fed_opened != 0) {
        /* A second open of the SAME node would wrap the wrapper and recurse.
         * A second node in the same process is no longer refused: its secret,
         * timers and counters are its own fields (issue #173). */
        printf("[observable] link_open_refused: reason=ALREADY_OPEN node=same\n");
        return -1;
    }
    if (secret != NULL) {
        len = strlen(secret);
        if (len >= (size_t)IRC_FED_MAX_SECRET) {
            /* Refused, not truncated: a truncated secret is weaker than the one
             * configured on the peer, and the failure would be a link that can
             * never authenticate, reported as a bad secret on both sides. */
            printf("[observable] link_open_refused: reason=SECRET_TOO_LONG "
                   "limit=%d\n",
                   IRC_FED_MAX_SECRET);
            return -1;
        }
        if (len != 0u && len < IRC_FED_MIN_SECRET) {
            /* A short shared secret is guessable online: the FEDERATE endpoint is
             * reachable by anyone who can open a socket, and there is no lockout.
             * Refused outright; the escape hatch exists only so tests with
             * legacy short secrets keep running (see tests/federation). */
            if (getenv("IRC_SERVE_ALLOW_SHORT_SECRET") == NULL) {
                printf("[observable] link_open_refused: reason=SECRET_SHORT "
                       "len=%zu min=%d\n",
                       len, IRC_FED_MIN_SECRET);
                return -1;
            }
            printf("[observable] link_open_warning: reason=SECRET_SHORT len=%zu "
                   "recommended_min=%d\n",
                   len, IRC_FED_MIN_SECRET);
        }
        memcpy(s->fed_secret, secret, len + 1u);
        s->fed_secret_len = len;
    } else {
        s->fed_secret[0] = '\0';
        s->fed_secret_len = 0;
    }
    s->fed_opened = 1;
    s->fed_inner = s->dispatch;
    s->dispatch = fed_dispatch_hook;
    /* NOT s->on_tick. The tick assignment is deliberately left to the caller
     * so that node_main.c shows the loop's time seam; see the header. */
    return 0;
}

/* Unwrap the dispatch fed_open() installed and forget this node's secret, so
 * a server_t that is shut down can be re-opened and so no credential outlives
 * the node that used it. Safe on a node that never called fed_open(), and on
 * NULL. Called from server_shutdown(); the goodbye (fed_send_shutdown) runs
 * before it, because the goodbye is queued through the node's own state and
 * the unwrap only touches the dispatch seam. */
void fed_close(server_t *s)
{
    if (s == NULL || s->fed_opened == 0) {
        return;
    }
    /* Unconditional: NULL restores NULL. A guarded restore leaves dispatch
     * hooked when opened pre-dispatch, and reopen then wraps the hook itself. */
    s->dispatch = s->fed_inner;
    s->fed_inner = NULL;
    s->fed_opened = 0;
    link_wipe(s->fed_secret, sizeof s->fed_secret);
    s->fed_secret_len = 0;
}

void fed_set_timeouts(server_t *s, uint64_t dial_ms, uint64_t hs_ms,
                       uint64_t keepalive_ms, uint64_t dead_ms)
{
    if (s == NULL) {
        return;
    }
    if (dial_ms != 0u) {
        s->fed_dial_ms = dial_ms;
    }
    if (hs_ms != 0u) {
        s->fed_hs_ms = hs_ms;
    }
    if (keepalive_ms != 0u) {
        s->fed_keepalive_ms = keepalive_ms;
    }
    if (dead_ms != 0u) {
        s->fed_dead_ms = dead_ms;
    }
}

/* T2's deadline. The reasoning, the failure it fixes and the measurement are in
 * link.h's fed_hs_due() -- the one-line rule is that a stamp not yet in the past
 * is not due, and it is reachable here without the clock going backwards because
 * this tick's now_ms was sampled before fed_link_promote() stamped created_ms from
 * a later reading on the same monotonic clock. */
int fed_hs_due(const server_t *s, uint64_t created_ms, uint64_t now_ms)
{
    if (s == NULL) {
        return 0;
    }
    if (created_ms == 0u) {
        return 0; /* no attempt stamped: a reset link, nothing to be late for */
    }
    if (now_ms < created_ms) {
        return 0; /* THE RULE. Unsigned, this would be 2^64-1 and always due. */
    }
    return (uint64_t)(now_ms - created_ms) >= s->fed_hs_ms;
}

void fed_set_retry(server_t *s, uint64_t base_ms, uint64_t max_ms, unsigned budget)
{
    if (s == NULL) {
        return;
    }
    if (base_ms != 0u) {
        s->fed_retry_base_ms = base_ms;
    }
    /* The ceiling is only ever LOWERED onto a base the caller also chose, and
     * never raised above a base that is smaller than it: a caller passing
     * max_ms < base_ms would otherwise get a ladder whose every step is above
     * its own ceiling, which is a policy with no first rung. Clamping here is
     * the difference between "the caller asked for a short scale" and "the
     * caller asked for something incoherent". */
    if (max_ms != 0u) {
        s->fed_retry_max_ms = (max_ms > s->fed_retry_base_ms) ? max_ms : s->fed_retry_base_ms;
    }
    if (budget != 0u) {
        s->fed_retry_budget = budget;
    }
}
