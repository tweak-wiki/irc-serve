/* test_burst_timeout.c -- issue #327: a BUSY is not forever.
 *
 * A peer that opens a burst and goes silent holds the shadow open and refuses
 * every other peer with BUSY. Past the 30s timeout (IRC_BURST_BUSY_TIMEOUT_MS)
 * the stale transaction is discarded (counted abandoned) and a second peer's
 * SBURST proceeds; within the window the refusal stands.
 *
 * UNIT test: two configured-but-never-dialled links on one node, lines parsed
 * from strings and applied directly. The timeout is driven through
 * fed_burst_sweep() with explicit stamps -- no sleeping -- and once through
 * fed_tick() to pin the wiring. Same isolation-test fixture as
 * test_fed_isolation.c.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "core/message.h"
#include "core/server.h"
#include "federation/burst.h"
#include "federation/link.h"

static server_link_t *configure_loopback(server_t *s, const char *name)
{
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(6668);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return fed_link_configure(s, name, (const struct sockaddr *)&sa,
                              (socklen_t)sizeof sa);
}

static void apply(server_t *s, server_link_t *link, const char *line)
{
    message_t m;

    assert(message_parse(line, &m) == 0);
    (void)fed_burst_apply(s, link, &m);
    message_free(&m);
}

int main(void)
{
    server_t s;
    server_link_t *lx;
    server_link_t *ly;
    uint64_t t0;

    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "secret-value-1") == 0);
    lx = configure_loopback(&s, "irc.x");
    ly = configure_loopback(&s, "irc.y");
    assert(lx != NULL && ly != NULL);

    /* Peer x opens a burst. */
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=1;"
          "irc-serve-hops=0 :irc.x SBURST 7 0");
    assert(s.burst != NULL);
    t0 = server_now_ms();

    /* Within the window, y's BEGIN is refused with BUSY: not opened, not
     * abandoned, still x's transaction. */
    apply(&s, ly,
          "@irc-serve-origin=irc.y;irc-serve-epoch=7;irc-serve-id=2;"
          "irc-serve-hops=0 :irc.y SBURST 7 0");
    assert(s.n_burst_abandoned == 0u);

    /* Past the timeout, the sweep discards the stale transaction. */
    fed_burst_sweep(&s, t0 + (uint64_t)IRC_BURST_BUSY_TIMEOUT_MS);
    assert(s.n_burst_abandoned == 1u);

    /* ... and y's BEGIN now proceeds. */
    apply(&s, ly,
          "@irc-serve-origin=irc.y;irc-serve-epoch=7;irc-serve-id=3;"
          "irc-serve-hops=0 :irc.y SBURST 7 0");
    assert(s.n_burst_abandoned == 1u);
    /* The tick path sweeps too: the tick past the timeout clears y's open
    * transaction, and y's next BEGIN then proceeds without a new abandon. */
    fed_tick(&s, t0 + 2u * (uint64_t)IRC_BURST_BUSY_TIMEOUT_MS + 1u);
    assert(s.n_burst_abandoned == 2u);
    apply(&s, ly,
          "@irc-serve-origin=irc.y;irc-serve-epoch=7;irc-serve-id=5;"
          "irc-serve-hops=0 :irc.y SBURST 7 0");
    assert(s.n_burst_abandoned == 2u);

    server_shutdown(&s);
    printf("ok: burst_timeout\n");
    return 0;
}
