/* test_burst_overflow_discard.c -- issue #209: two-pass burst commit.
 *
 * A burst resync used to purge a channel's roster BEFORE re-adding its
 * members, so a record the re-add refused (here: 65 members for a 64-slot
 * roster) silently shrank the channel. The commit now pre-flights each
 * channel record and discards one that does not fit, leaving the existing
 * roster intact.
 *
 * UNIT test: one node, one origin-irc.x channel holding a full 64-member
 * remote roster, then a 65-member burst from irc.x applied through
 * fed_burst_apply(). Asserts the roster is unchanged and the 65th member
 * is absent.
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

#define TAG "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=9;" \
    "irc-serve-hops=0 :irc.x "

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
    chan_t *ch;
    char nick[32];
    char line[256];
    int i;

    assert(server_init(&s, "irc.a") == 0);
    assert(fed_open(&s, "secret-value-100") == 0);
    lx = configure_loopback(&s, "irc.x");
    assert(lx != NULL);

    /* A full roster of 64, all from the burst origin. */
    ch = chan_new("#full", "irc.x", 7u);
    assert(ch != NULL);
    assert(server_chan_attach(&s, ch) == 0);
    assert(chan_server_add(ch, "irc.x") == 0);
    for (i = 0; i < 64; i++) {
        (void)snprintf(nick, sizeof nick, "user%02d", i);
        assert(chan_remote_add(ch, "irc.x", "irc.x", nick, "*", 0) == 0);
    }
    assert(chan_remote_count(ch) == 64u);

    /* A 65-member restatement of the same channel, with the new member FIRST:
     * purge-then-re-add would install it and then have no slot left for the
     * last restated member, while the pre-flight discards the record whole. */
    apply(&s, lx, TAG "SBURST 7 0");
    apply(&s, lx, TAG "SBURSTC #full irc.x - 7 - :");
    apply(&s, lx, TAG "SBURSTM #full irc.x user64 - *");
    for (i = 0; i < 64; i++) {
        (void)snprintf(nick, sizeof nick, "user%02d", i);
        (void)snprintf(line, sizeof line, TAG "SBURSTM #full irc.x %s - *",
                       nick);
        apply(&s, lx, line);
    }
    apply(&s, lx, TAG "SBURSTE 7 0 1 65");

    /* The record did not fit, so nothing was purged: all 64 stay, the 65th
     * never arrived. */
    ch = server_chan_get(&s, "#FULL");
    if (ch == NULL) {
        ch = server_chan_get(&s, "#full");
    }
    assert(ch != NULL);
    assert(chan_remote_count(ch) == 64u);
    assert(chan_remote_find(ch, "irc.x", "user00") != NULL);
    assert(chan_remote_find(ch, "irc.x", "user63") != NULL);
    assert(chan_remote_find(ch, "irc.x", "user64") == NULL);

    server_shutdown(&s);
    printf("ok: burst_overflow_discard\n");
    return 0;
}
