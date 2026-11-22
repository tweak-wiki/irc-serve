/* test_burst_resync_keep.c -- issue #209: burst resync must not delete the
 * roster before a re-add that can fail.
 *
 * A peer burst purges this node's per-origin roster and re-adds members one
 * by one; a re-add past CHAN_MAX_REMOTE_MEMBERS is refused, so an over-full
 * burst silently shrank the channel until the next resync. The fix validates
 * the whole staged roster before purging and discards an un-installable
 * record, keeping the old roster.
 *
 * UNIT test: one node, two origin-irc.x channels built directly, then a burst
 * from irc.x applied through fed_burst_apply(). #full is at the 64-remote
 * cap (63 held via irc.y plus alice via irc.x) and the burst reports two new
 * members for it, which cannot fit: the record is discarded, so alice stays
 * and neither newcomer appears. #ok has room and proves the normal path still
 * installs: its burst record replaces alice with bob.
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

static void make_chan(server_t *s, const char *chan)
{
    chan_t *ch = chan_new(chan, "irc.x", 7u);

    assert(ch != NULL);
    assert(server_chan_attach(s, ch) == 0);
    assert(chan_server_add(ch, "irc.x") == 0);
    assert(chan_server_add(ch, "irc.y") == 0);
    assert(chan_remote_add(ch, "irc.x", "irc.x", "alice", "*", 0) == 0);
}

int main(void)
{
    server_t s;
    server_link_t *lx;
    chan_t *full;
    chan_t *ok;
    char nick[16];

    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "secret-value-100") == 0);
    lx = configure_loopback(&s, "irc.x");
    assert(lx != NULL);

    /* #full sits exactly at the remote cap: alice via the burst origin plus
     * 63 members held via a third server, which the purge must not touch. */
    make_chan(&s, "#full");
    full = server_chan_get(&s, "#full");
    assert(full != NULL);
    for (int i = 0; i < 63; i++) {
        (void)snprintf(nick, sizeof nick, "u%02d", i);
        assert(chan_remote_add(full, "irc.y", "irc.y", nick, "*", 0) == 0);
    }
    assert(chan_remote_count(full) == 64u);

    make_chan(&s, "#ok");
    ok = server_chan_get(&s, "#ok");
    assert(ok != NULL);

    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=1;"
          "irc-serve-hops=0 :irc.x SBURST 7 0");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=2;"
          "irc-serve-hops=0 :irc.x SBURSTC #full irc.x - 0 - :hello");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=3;"
          "irc-serve-hops=0 :irc.x SBURSTM #full irc.x bob - *");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=4;"
          "irc-serve-hops=0 :irc.x SBURSTM #full irc.x carol - *");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=5;"
          "irc-serve-hops=0 :irc.x SBURSTC #ok irc.x - 0 - :hello");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=6;"
          "irc-serve-hops=0 :irc.x SBURSTM #ok irc.x bob - *");
    apply(&s, lx,
          "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=7;"
          "irc-serve-hops=0 :irc.x SBURSTE 7 0 2 3");

    /* #full: the over-full record was discarded, so the old roster is whole. */
    full = server_chan_get(&s, "#full");
    assert(full != NULL);
    assert(chan_remote_count(full) == 64u);
    assert(chan_remote_find(full, "irc.x", "alice") != NULL);
    assert(chan_remote_find(full, "irc.x", "bob") == NULL);
    assert(chan_remote_find(full, "irc.x", "carol") == NULL);

    /* #ok: a fitting record still purges and installs as before. */
    ok = server_chan_get(&s, "#ok");
    assert(ok != NULL);
    assert(chan_remote_find(ok, "irc.x", "bob") != NULL);
    assert(chan_remote_find(ok, "irc.x", "alice") == NULL);

    server_shutdown(&s);
    printf("ok: burst_resync_keep\n");
    return 0;
}
