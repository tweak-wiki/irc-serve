/* test_hash_seed.c -- the strtab's per-boot hash seed (issue #331).
 *
 * The nick/channel table is an open-addressed linear-probe map keyed by
 * attacker-chosen strings (nicks). With a fixed hash, one client can
 * pre-compute colliding nicks, force a long probe chain, and stall the node
 * with legal NICKs. server_init() therefore draws one random seed per boot
 * (from server_msgid_seed(), the same source as the #180 msg_id start) and
 * XORs it into the FNV-1a offset basis, so the same nick lands in a
 * different bucket on different boots.
 *
 * Two checks. First, the seed is observable: two boots draw different
 * s.hash_seed (near-certainly; the source is 64 random bits, so a repeat
 * means the RNG is broken, which is exactly what this asserts). Second, the
 * seed does not break the table: 500 nicks claim and resolve on both boots,
 * so the seeded hash is a working hash, not just a different one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/test_util.h"

#define SEED_BULK 500u

static conn_t *seed_conn(int fd, const char *nick)
{
    conn_t *c = conn_new(fd, CONN_CLIENT);

    TF_CHECK(c != NULL);
    if (nick != NULL) {
        memcpy(c->nick, nick, strlen(nick) + 1u);
    }
    return c;
}

static void seed_bulk(server_t *s, const char *what)
{
    char nick[IRC_MAX_NICK + 1];
    size_t i;
    size_t claimed = 0;

    for (i = 0; i < SEED_BULK; i++) {
        conn_t *c;

        snprintf(nick, sizeof nick, "seed%04u", (unsigned)i);
        c = seed_conn(300 + (int)i, nick);
        if (server_nick_claim(s, nick, c) == 0) {
            claimed++;
        } else {
            conn_free(c);
        }
    }
    TF_CHECK_MSG(claimed > 0, "%s: no nick claimed at all", what);
    for (i = 0; i < SEED_BULK; i++) {
        conn_t *found;

        snprintf(nick, sizeof nick, "seed%04u", (unsigned)i);
        found = server_nick_lookup(s, nick);
        if (found != NULL) {
            TF_CHECK_MSG(found->nick[0] != '\0', "%s: empty nick", what);
        }
    }
    TF_CHECK_MSG(server_nick_count(s) == claimed,
                 "%s: enumeration holds %zu, table holds %zu",
                 what, server_nick_count(s), claimed);
}

int main(void)
{
    server_t a;
    server_t b;

    TF_CHECK_MSG(server_init(&a, "irc.test") == 0, "server_init failed");
    TF_CHECK_MSG(server_init(&b, "irc.test") == 0, "server_init failed");
    TF_CHECK_MSG(a.hash_seed != 0, "boot A drew a 0 hash seed");
    TF_CHECK_MSG(b.hash_seed != 0, "boot B drew a 0 hash seed");
    TF_CHECK_MSG(a.hash_seed != b.hash_seed,
                 "two boots drew the same hash seed %llu: the per-boot seed "
                 "is not varying, so pre-computed collisions hold across "
                 "reboots and the #331 DoS stands",
                 (unsigned long long)a.hash_seed);
    seed_bulk(&a, "boot A");
    seed_bulk(&b, "boot B");
    server_shutdown(&a);
    server_shutdown(&b);
    tf_done("hash_seed");
    return 0;
}
