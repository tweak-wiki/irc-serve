/* strtab.c -- see strtab.h. The string -> pointer map, verbatim
 * out of server.c (issue #543); the registries that use it stay there.
 */
#include "core/strtab.h"

#include <stdlib.h>
#include <string.h>

#include "core/message.h"
/* ---------------------------------------------------------------------------
 * A small open-addressed string -> pointer map
 * ---------------------------------------------------------------------------
 * Two registries need it (nicks, channels) and both are keyed by a short ASCII
 * name, so one table type serves both rather than two bespoke structures. It
 * lives in this module behind strtab.h: nothing outside this file needs to
 * know how a nick is stored.
 *
 * Open addressing with linear probing and a FNV-1a hash. No growth: the table
 * is sized once from a generous bound, and a full table is reported rather than
 * rehashed, so a lookup in the send path cannot fail because of an allocation
 * that would have to block the loop.
 *
 * ---------------------------------------------------------------------------
 * WHY ONE TABLE IS FOLDED AND THE OTHER IS NOT
 * ---------------------------------------------------------------------------
 * The two registries disagree about case for a REASON, not by accident:
 *
 *   channels  2.2 says a channel name is stored uppercase-normalised and is
 *             displayed uppercase, so the canonical form IS the display form.
 *             The table is exact, and channel.c's accessor canonicalises the
 *             caller's spelling before it probes (see chan_name_upper and the
 *             reasoning at channel.c:48).
 *   nicks     2.1 and RFC 2812 2.3.1 say nicknames are case-INsensitive, so
 *             two spellings are one name -- but IRC convention and every client
 *             display the case the user chose. A user who registers as `Bob` must
 *             appear as `Bob` in 353, in a PRIVMSG prefix, in 352 and in 311.
 *
 * So a nick cannot be stored the way a channel is. `folded` is therefore a
 * property OF THE TABLE, set at construction, and every key that enters a folded
 * table is folded before it is hashed, compared or stored. It is not a
 * discipline every caller has to remember: the failure mode of getting it wrong
 * was issue #100, where `PRIVMSG BOB :hi` answered 401 to a user connected as
 * `bob` and -- worse -- `bob` and `BOB` were two claimable slots on a node whose
 * identity scheme is nick@server.
 *
 * The fold is ASCII and deliberately NOT tolower() in a locale, for
 * channel.c:48's reason: 005 advertises CASEMAPPING=ascii, so this node has
 * already told every client that []\~ and {}|^ are NOT equivalent, and folding
 * them here would break that promise in a way no test elsewhere would catch. A
 * registry key that depended on LC_CTYPE would additionally make two nodes on
 * differently-configured hosts disagree about whether a nickname is taken.
 */
#define STRTAB_BUCKETS 1024u

/* The longest key a FOLDED table can hold, and so the size of the scratch buffer
 * strtab_probe()/strtab_put() fold into. It is the nick bound rather than an
 * invented one: the only folded table is the nick registry, whose every key
 * arrives through server_nick_claim() -> valid_nick(), and valid_nick() caps a
 * nickname at IRC_MAX_NICK (message.h, from conn_t::nick's own width). A longer
 * string therefore cannot be a key of a folded table, and is refused rather than
 * truncated into one that could collide with a real name. */
#define STRTAB_FOLD_MAX (IRC_MAX_NICK + 1)

struct strtab_entry {
    char  *key;
    void  *val;
    int    used;
};

struct strtab {
    struct strtab_entry *buckets;
    size_t               nentries;
    int                  folded;  /* keys are ASCII-folded on the way in */
    /* Issue #331: per-boot random seed, XORed into the FNV-1a offset basis.
     * Without it an attacker pre-computes colliding nicks and forces a long
     * probe chain on the hot fanout path (single-client CPU DoS with legal
     * NICKs). Drawn once per server_init from server_msgid_seed() and shared
     * by both tables, so two boots hash the same nick to different buckets. */
    uint64_t             seed;
};

static uint64_t strtab_hash(const char *s, uint64_t seed)
{
    /* FNV-1a, 64-bit, with the per-boot seed XORed into the offset basis
     * (init-XOR, issue #331): the prime multiply avalanches the seed into
     * every byte, so pre-boot precomputation buys nothing. */
    uint64_t h = 1469598103934665603ull ^ seed;

    while (*s != '\0') {
        h ^= (uint64_t)(unsigned char)*s;
        h *= 1099511628211ull;
        s++;
    }
    return h;
}

/* THE ONE ASCII FOLD (issue #181): the single definition behind
 * message.h's irc_ascii_fold()/irc_ascii_same(). a-z -> A-Z only, no
 * locale/tolower, for the reasons the header gives. */
char irc_ascii_fold(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (char)(c - ('a' - 'A'));
    }
    return c;
}

int irc_ascii_same(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (irc_ascii_fold(*a) != irc_ascii_fold(*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Fold `key` into `out`, which holds `cap` bytes including the NUL. Returns 0 on
 * success, -1 if the result would not fit.
 *
 * The `char` parameter is passed and returned without an (unsigned char) cast
 * deliberately, and the reason is the same one channel.c:48 gives for not calling
 * toupper() at all: no libc function sees the value, and the range tests are
 * against ASCII literals, so a byte outside 'a'..'z' is returned unchanged
 * whatever the sign of char is. Casting would be noise here and a cast is
 * exactly what a future caller would have to remember not to drop. */
static int strtab_fold(char *out, size_t cap, const char *key)
{
    size_t i;

    for (i = 0; key[i] != '\0'; i++) {
        if (i + 1u >= cap) {
            return -1;
        }
        out[i] = irc_ascii_fold(key[i]);
    }
    out[i] = '\0';
    return 0;
}

struct strtab *strtab_new(int folded, uint64_t seed)
{
    struct strtab *t = (struct strtab *)calloc(1, sizeof *t);

    if (t == NULL) {
        return NULL;
    }
    t->buckets = (struct strtab_entry *)calloc(STRTAB_BUCKETS, sizeof *t->buckets);
    if (t->buckets == NULL) {
        free(t);
        return NULL;
    }
    t->folded = folded;
    t->seed = (seed != 0) ? seed : 1469598103934665603ull;
    return t;
}

void strtab_free(struct strtab *t)
{
    size_t i;

    if (t == NULL) {
        return;
    }
    for (i = 0; i < STRTAB_BUCKETS; i++) {
        free(t->buckets[i].key);
    }
    free(t->buckets);
    free(t);
}

/* Locate `key` in the table. Returns the bucket index, sets *found to 1 when the
 * key is present or 0 when the returned bucket is free, and returns
 * (size_t)-1 only when the table is completely full. One probe loop, so the
 * const-correct lookup and the mutating insert cannot drift apart.
 *
 * For a FOLDED table the key is folded first, here, rather than by each of the
 * four operations below. That is the whole point: strtab_get/contains/del/put
 * are the only doors to this table, they all come through this loop, and a caller
 * added later gets the case-insensitive rule whether or not it knows the rule
 * exists. */
static size_t strtab_probe(const struct strtab *t, const char *key, int *found)
{
    char        fold[STRTAB_FOLD_MAX];
    const char *k = key;
    size_t      idx;
    size_t      probe;

    *found = 0;
    if (t->folded && strtab_fold(fold, sizeof fold, key) != 0) {
        /* Too long to be a key of this table, so it can neither match an entry
         * nor become one. The same sentinel as a full table, and deliberately so:
         * every caller treats both as "give up" -- put() returns -1, get() and
         * contains() report absence, del() reports nothing to remove. Which of
         * the two it was is not a fact any caller can act on. */
        return (size_t)-1;
    }
    if (t->folded) {
        k = fold;
    }
    idx = (size_t)(strtab_hash(k, t->seed) % STRTAB_BUCKETS);
    for (probe = 0; probe < STRTAB_BUCKETS; probe++) {
        size_t at = (idx + probe) % STRTAB_BUCKETS;
        const struct strtab_entry *e = &t->buckets[at];

        if (!e->used) {
            *found = 0;
            return at;
        }
        if (strcmp(e->key, k) == 0) {
            *found = 1;
            return at;
        }
    }
    return (size_t)-1;
}

/* Is `key` present? Distinct from strtab_get(), which cannot answer this for a
 * table whose values are legitimately NULL -- and the channel registry is
 * exactly that, because struct chan does not exist until Phase 4. Reading
 * presence off the value would make every channel look absent. */
int strtab_contains(const struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return 0;
    }
    at = strtab_probe(t, key, &found);
    return (at != (size_t)-1 && found) ? 1 : 0;
}

int strtab_put(struct strtab *t, const char *key, void *val)
{
    struct strtab_entry *e;
    char   fold[STRTAB_FOLD_MAX];
    const char *stored = key;
    int    found = 0;
    size_t at;
    char  *copy;

    if (t == NULL || key == NULL || key[0] == '\0') {
        return -1;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1) {
        return -1;
    }
    e = &t->buckets[at];
    if (found) {
        e->val = val; /* overwrite: re-claim of the same key */
        return 0;
    }
    /* The key is STORED folded, so the table's own bytes are the canonical form
     * rather than whichever spelling the first claimer happened to type. Every
     * later probe folds its own key to match, and nothing has to remember that
     * the entry was inserted as "Bob" rather than "bob". */
    if (t->folded) {
        if (strtab_fold(fold, sizeof fold, key) != 0) {
            return -1;
        }
        stored = fold;
    }
    copy = (char *)malloc(strlen(stored) + 1u);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, stored, strlen(stored) + 1u);
    e->key = copy;
    e->val = val;
    e->used = 1;
    t->nentries++;
    return 0;
}

void *strtab_get(const struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return NULL;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1 || !found) {
        return NULL;
    }
    return t->buckets[at].val;
}

/* Empty the bucket at `at` and count it out of the table, then SHIFT the rest of
 * the probe chain back over the gap. The one place a slot is cleared, so
 * strtab_del() below and strtab_del_owner() further down cannot disagree about
 * what "removed" leaves behind.
 *
 * ---------------------------------------------------------------------------
 * WHY DELETION HAS TO SHIFT (issue #107)
 * ---------------------------------------------------------------------------
 * This used to stop at the assignment below, and that made every key that probed
 * PAST `at` unreachable. strtab_probe() walks forward from the key's home
 * bucket and stops at the first slot with used == 0, so an empty slot is not
 * merely an absence -- it is a WALL, and anything behind it is invisible.
 *
 * The consequence was user-visible rather than theoretical. `u4x` and `u79x` both
 * hash to bucket 14; claim both, release `u4x`, and lookup("u79x") returns NULL
 * while the name is still held. PRIVMSG and WHOIS then answer 401 for a
 * connected, registered user, and a second client can claim the same name while
 * the first is still listed in 353 -- because WHO walks the ENUMERATION and never
 * consults the table for the name. Roughly 1 in 1024 per colliding pair, and
 * every release adds another hole rather than closing one, so a node running for a
 * day accumulates a great many.
 *
 * ---------------------------------------------------------------------------
 * WHY SHIFTING IS CORRECT FOR THIS PROBE, AND NOT BY LUCK
 * ---------------------------------------------------------------------------
 * Backward-shift deletion is only sound if the probe sequence for a key does not
 * depend on the table's HISTORY. Here it does not, and the reason is structural:
 *
 *   strtab_probe() derives everything from the key and the table size alone --
 *   idx = hash(k) % STRTAB_BUCKETS, then at = (idx + probe) % STRTAB_BUCKETS for
 *   probe = 0, 1, 2, ... The one thing that varies with history is where the walk
 *   STOPS, and "stop at the first empty slot" is precisely the thing a deletion
 *   perturbs. So the obligation after a deletion is exactly one: put every entry
 *   back where its own probe sequence will find it again.
 *
 * An entry in slot p is findable iff every slot in the cyclic range [home, p) is
 * occupied. After this function returns, the ONLY slot that is newly empty is
 * the final gap, so re-establishing that invariant for every entry is the whole
 * requirement -- and the rule below is what re-establishes it.
 *
 * The FOLDED flag is irrelevant to this and the reasoning must not be read as
 * depending on it. strtab_put() STORES the folded key (see the note there), so
 * strtab_hash(e->key) on a stored key is the same value strtab_probe() computed
 * for it, folded or not, and the shift therefore computes the same home for a
 * stored entry that a later probe of that key will.
 *
 * ---------------------------------------------------------------------------
 * THE MOVE RULE
 * ---------------------------------------------------------------------------
 * Walking forward from the gap, an entry sitting at `from` gets moved into the
 * gap `hole` when its own probe distance from its home is AT LEAST its distance
 * from the gap:
 *
 *   k  = (from - home) % STRTAB_BUCKETS   -- how far the entry sits from home
 *   pd = (from - hole) % STRTAB_BUCKETS   -- how far the gap sits behind it
 *
 * That single comparison is both directions at once, because the entry's cluster
 * [home, from) is occupied and the gap is empty, so the gap CANNOT be inside that
 * cluster -- which is exactly what `k >= pd` says. Note it admits the equal case:
 * an entry homed exactly on the gap belongs in the gap, and since pd >= 1 always
 * the k == 0 case (the entry sitting in its own home slot, which must not move
 * anywhere) falls out as "stay" with no special case to get backwards.
 *
 *   k >= pd   the gap is at or behind the entry's home, so the entry moves into
 *             it and the gap advances to where the entry was.
 *   k <  pd   the gap is strictly inside the entry's own cluster, so the entry
 *             stays exactly where it is and the walk continues past it.
 *
 * Two things the loop must therefore do, and both are load-bearing:
 *
 *   - CONTINUE past an entry that does not move. Only the gap advances on a move,
 *     so an entry further along can still need the gap even though the one just
 *     examined could not take it.
 *   - STOP at the first EMPTY slot. Nothing beyond a second empty slot can be
 *     probing through this one, so the rest of the table cannot have been
 *     affected.
 *
 * The bound is STRTAB_BUCKETS-1 steps, which visits every other slot exactly once
 * and wraps without ever coming back to `at` -- so an entry can never be moved
 * into the slot the walk started from and read again. */
static void strtab_remove_at(struct strtab *t, size_t at)
{
    size_t hole = at;
    size_t from = (at + 1u) % STRTAB_BUCKETS;
    size_t probe;

    free(t->buckets[at].key);
    t->buckets[at].key = NULL;
    t->buckets[at].val = NULL;
    t->buckets[at].used = 0;
    t->nentries--;

    for (probe = 0; probe + 1u < STRTAB_BUCKETS; probe++) {
        struct strtab_entry *e = &t->buckets[from];
        size_t home;
        size_t k;
        size_t pd;

        if (!e->used) {
            break; /* the rest of the chain is not reachable through here */
        }
        home = (size_t)(strtab_hash(e->key, t->seed) % STRTAB_BUCKETS);
        k = (from + STRTAB_BUCKETS - home) % STRTAB_BUCKETS;
        pd = (from + STRTAB_BUCKETS - hole) % STRTAB_BUCKETS;
        if (k >= pd) {
            t->buckets[hole] = *e; /* the key pointer moves with the entry */
            e->key = NULL;
            e->val = NULL;
            e->used = 0;
            hole = from;
        }
        from = (from + 1u) % STRTAB_BUCKETS;
    }
}

int strtab_del(struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return -1;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1 || !found) {
        return -1;
    }
    strtab_remove_at(t, at);
    return 0;
}

/* ---------------------------------------------------------------------------
 * OWNER-SIDE TABLE OPERATIONS: "which keys point at this conn_t?"
 * ---------------------------------------------------------------------------
 * Every value in the nick table is a conn_t*, and the question "does this
 * connection still hold a name" is not answerable from conn_t::nick -- the
 * table is the only record, and conn_t::nick is a DISPLAY field that a rename
 * writes after the registry has already been updated. So it is asked of the
 * table, by scanning it.
 *
 * A linear scan of 1024 buckets on a table sized for a poll() set is the
 * right trade and not a compromise: these run when a connection is being torn
 * down or renamed, which is neither frequent nor latency-sensitive, and a
 * per-connection name counter would have to be kept correct by every write
 * path to the index -- which is the same class of "two places must agree"
 * hazard the index already has one of.
 *
 * The nick table is FOLDED, so these are spelling-agnostic by construction:
 * there is no comparison here to get wrong in the way a name-keyed scan of the
 * enumeration had to be (that was nick_same(), and it is gone -- see the
 * enumeration below). */
size_t strtab_count_owner(const struct strtab *t, const void *owner)
{
    size_t i;
    size_t n = 0;

    if (t == NULL) {
        return 0u;
    }
    for (i = 0; i < STRTAB_BUCKETS; i++) {
        if (t->buckets[i].used && t->buckets[i].val == owner) {
            n++;
        }
    }
    return n;
}

/* Remove EVERY key mapped to `owner`, and return how many went. Used by the
 * teardown, which must not leave any reference to a conn_t it is about to free
 * -- and cannot be written as a single strtab_del() because a connection is not
 * guaranteed to hold exactly one name (see server_nick_claim).
 *
 * A single pass is NOT enough now that deletion shifts, and this is the one place
 * the shift changes what a caller has to do rather than being invisible inside
 * the table. strtab_remove_at() can move an entry from the slot AFTER the one
 * being cleared back into that slot -- which is the first thing it examines, and
 * the overwhelmingly common case in a chain of names that share a home bucket. A
 * forward scan has already gone past that slot, so an entry shifted into it
 * belongs to `owner` and is missed: a connection holding two colliding names
 * would have one of them survive its own teardown, pointing at freed memory.
 *
 * So the pass repeats until a whole pass finds nothing left to remove. It is
 * bounded and cheap in the right way: every extra pass removes at least one
 * entry, and a connection holds a handful of names at most, so this is
 * O(STRTAB_BUCKETS) for the ordinary one-name teardown. That is the same linear
 * scan the operation already was. */
size_t strtab_del_owner(struct strtab *t, const void *owner)
{
    size_t n = 0;
    int again = 1;

    if (t == NULL) {
        return 0u;
    }
    while (again) {
        size_t i;

        again = 0;
        for (i = 0; i < STRTAB_BUCKETS; i++) {
            if (t->buckets[i].used && t->buckets[i].val == owner) {
                strtab_remove_at(t, i);
                n++;
                again = 1;
            }
        }
    }
    return n;
}
