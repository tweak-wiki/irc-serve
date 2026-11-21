/* test_remote_holder.c -- issue #277: an SJOIN repeat must not clobber the holder.
 *
 * 4.3's SJOIN carries no server field, so fed_in_sjoin() records the holder as
 * unknown (NULL, stored as ""). A burst from a node that DOES know carries the
 * holder in SBURSTM's <server>, and install writes it into the roster. The live
 * path and the burst path then race: every repeated SJOIN re-runs
 * chan_remote_add() for an entry the burst may since have corrected, and a
 * repeat that overwrote the holder with its own absence would flap the
 * attribution back to the relay on every rejoin -- which is the misattribution
 * #277's send path then re-emits as fact.
 *
 * UNIT test: no sockets, no children, no loop. chan_remote_add() is exercised
 * directly, because the claim is a property of the roster function both paths
 * share: a repeat carrying no holder keeps the one that is there, while a
 * repeat carrying one still overwrites.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/channel.h"

int main(void)
{
    chan_t *ch;
    const chan_remote_t *r;

    ch = chan_new("#T", "irc.c", 7u);
    assert(ch != NULL);

    /* A burst installs what it knows: bob is on irc.c, reported by irc.b. */
    assert(chan_remote_add(ch, "irc.b", "irc.c", "bob", "*", 0) == 0);
    r = chan_remote_find(ch, "irc.b", "bob");
    assert(r != NULL && strcmp(r->member_server, "irc.c") == 0);

    /* A live SJOIN repeat carries no holder (NULL): the burst's fact stands. */
    assert(chan_remote_add(ch, "irc.b", NULL, "bob", "*", 0) == 0);
    r = chan_remote_find(ch, "irc.b", "bob");
    assert(r != NULL && strcmp(r->member_server, "irc.c") == 0);

    /* An empty repeat is the same absence spelled differently. */
    assert(chan_remote_add(ch, "irc.b", "", "bob", "*", 0) == 0);
    r = chan_remote_find(ch, "irc.b", "bob");
    assert(r != NULL && strcmp(r->member_server, "irc.c") == 0);

    /* A repeat that DOES carry a holder still overwrites: a newer burst that
     * moved bob is believed, not kept stale. */
    assert(chan_remote_add(ch, "irc.b", "irc.d", "bob", "*", 0) == 0);
    r = chan_remote_find(ch, "irc.b", "bob");
    assert(r != NULL && strcmp(r->member_server, "irc.d") == 0);

    /* A fresh live-SJOIN entry records the absence rather than the link. */
    assert(chan_remote_add(ch, "irc.b", NULL, "cara", "*", 0) == 0);
    r = chan_remote_find(ch, "irc.b", "cara");
    assert(r != NULL && r->member_server[0] == '\0');

    chan_free(ch);
    printf("ok: remote_holder\n");
    return 0;
}
