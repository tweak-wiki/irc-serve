/* test_burst_purge_skip.c -- issue #359: backwards burst origin-purge loop.
 *
 * A burst that orphans TWO same-origin channels must purge and dispose both.
 * The purge walk calls chan_dispose_if_empty(), which compacts the channel
 * array; a forward walk that advances past a disposal skips the channel
 * shifted into the freed slot, leaving a stale remote roster and a leaked
 * channel. The walk runs backwards, which is safe against swap-remove.
 *
 * UNIT test: one node, two origin-irc.x channels built directly, then an
 * empty burst from irc.x applied through fed_burst_apply(). Asserts both
 * channels are gone.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "core/channel.h"
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

static void make_origin_chan(server_t *s, const char *chan, const char *nick)
{
    chan_t *ch = chan_new(chan, "irc.x", 7u);

    assert(ch != NULL);
    assert(server_chan_attach(s, ch) == 0);
    assert(chan_remote_add(ch, "irc.x", "irc.x", nick, "*", 0) == 0);
    assert(chan_server_add(ch, "irc.x") == 0);
}

int main(void)
{
    server_t s;
    server_link_t *lx;

    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "secret-value-100") == 0);
    lx = configure_loopback(&s, "irc.x");
    assert(lx != NULL);

    make_origin_chan(&s, "#aaa", "alice");
    make_origin_chan(&s, "#bbb", "bob");
    assert(server_chan_count(&s) == 2u);

    /* An empty burst from irc.x: both channels orphaned. */
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=1;"
          "irc-serve-hops=0 :irc.x SBURST 7 0");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=2;"
          "irc-serve-hops=0 :irc.x SBURSTE 7 0 0 0");
    assert(server_chan_count(&s) == 0u);
    assert(server_chan_lookup(&s, "#aaa") == NULL);
    assert(server_chan_lookup(&s, "#bbb") == NULL);

    server_shutdown(&s);
    printf("ok: burst_purge_skip\n");
    return 0;
}
