/* test_burst_bad_nick.c -- issue #496: one bad SBURSTN must not kill the burst.
 *
 * A burst whose roster holds one illegal nick used to discard
 * the whole transaction at the record, and the commit's count assertion then
 * failed every resync from that peer forever. The fix isolates the record:
 * the bad SBURSTN is refused (n_fed_malformed + 1) and expect_nnicks shrinks by
 * one, so the commit's accepted-count check still balances and the good nicks
 * install.
 *
 * UNIT test: one node, one configured link, lines parsed from strings and
 * applied directly. Two nicks promised, one good and one illegal; the commit
 * restates the sent total. The good nick must be resolvable afterwards, with
 * exactly one malformed, zero abandons and zero truncations.
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
#include "federation/nickreg.h"

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
    char holder[64];

    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "secret-value-100") == 0);
    lx = configure_loopback(&s, "irc.x");
    assert(lx != NULL);

    /* Two nicks promised, one good ... */
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=1;"
          "irc-serve-hops=0 :irc.x SBURST 7 2");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=2;"
          "irc-serve-hops=0 :irc.x SBURSTN bob u h - 1 :hi");
    /* ... and one with an illegal character, which valid_nick() refuses. */
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=3;"
          "irc-serve-hops=0 :irc.x SBURSTN bad!nick u h - 1 :hi");
    /* The commit restates the SENT total: 2 nicks, 0 chans, 0 members. */
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=4;"
          "irc-serve-hops=0 :irc.x SBURSTE 7 2 0 0");

    /* The bad record was refused, not the burst: one malformed, nothing
     * abandoned, nothing truncated, and the good nick installed. */
    assert(s.n_fed_malformed == 1u);
    assert(s.n_burst_abandoned == 0u);
    assert(s.n_burst_truncated == 0u);
    assert(fed_nickreg_holder(&s, "bob", holder, sizeof holder, NULL) != NULL);

    server_shutdown(&s);
    printf("ok: burst_bad_nick\n");
    return 0;
}
