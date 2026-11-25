/* server_registry.c -- see core/server.h. The nick and channel registries,
 * verbatim out of server.c (issue #543); the lifecycle, link/dial registries
 * and shutdown stay there. The registry functions were already declared in
 * core/server.h, and the two enumeration helpers stay static here, so there
 * is no new header (fanout_deliver.c precedent).
 */
#include "core/server.h"

#include <stdlib.h>
#include <string.h>
/* The nick/channel string -> pointer map (open-addressed strtab). */
#include "core/strtab.h"
#include "core/channel.h"
#include "core/message.h"
/* ---------------------------------------------------------------------------
 * Registries
 * ---------------------------------------------------------------------------
 */

/* ---------------------------------------------------------------------------
 * THE NICK INDEX, and the invariant that makes it one index
 * ---------------------------------------------------------------------------
 * A connection is in the enumeration if and only if it holds at least one name,
 * and it is in it AT MOST ONCE. The table holds one entry per name; the vector
 * holds one entry per USER. Those are different cardinalities on purpose, and
 * WHO is a question about users: 352 is one line per user, so a connection that
 * somehow held two names must still produce one line, or the same person appears
 * twice in a client's channel list and twice in every WHO they ask for.
 *
 * Every rule below exists to keep that one sentence true, and the two failures
 * it prevents are the two this registry has already had:
 *
 *   issue #102  a teardown removed the table entry and freed the conn_t, and
 *               the vector kept the pointer. A freed conn_t stayed reachable
 *               from server_nick_at() and WHO dereferenced it.
 *   issue #103  a claim appended unconditionally, so one connection holding two
 *               names was in the vector twice, the enumeration counted a
 *               connection that appears once, and a teardown that removed ONE
 *               copy left the other one dangling -- #102's bug reachable through
 *               #103's.
 *
 * The repair in both cases is the same shape: the vector is keyed by POINTER
 * and the table by NAME, and every operation is expressed on one side in terms
 * of the other so that neither half can be applied alone. There is no
 * name-keyed removal of the vector anywhere in this file, which is what
 * guarantee #102 rests on.
 */

/* Append `c` to the nick enumeration, unless it is already in it. Returns 0 on
 * success, -1 on allocation failure or a bad argument. The vector grows
 * geometrically like conn_t's own channel list does, and is not bounded: it
 * holds one entry per registered connection, so the loop's own FD_SETSIZE
 * ceiling is the bound.
 *
 * "Unless it is already in it" is issue #103. The append used to be
 * unconditional, which meant a connection holding two names appeared twice and
 * the enumeration counted connections and names at once. Making it conditional
 * makes the invariant hold whatever order the caller does things in, rather than
 * holding only because handle_nick() happens to claim before it releases: that
 * ordering is a property of one caller, and a mitigation by accident is not a
 * design. test_registries.c reaches the two-names state by calling this API
 * directly and asserts the count does not move.
 *
 * The cost is a linear scan per claim, over a vector bounded by FD_SETSIZE, on
 * a path that already hashed a key. */
static int nick_objs_add(server_t *s, conn_t *c)
{
    size_t i;

    if (s == NULL || c == NULL) {
        return -1;
    }
    for (i = 0; i < s->nnick_objs; i++) {
        if (s->nick_objs[i] == c) {
            return 0; /* already enumerated: one entry per connection */
        }
    }
    if (s->nnick_objs == s->nick_objs_cap) {
        size_t want = (s->nick_objs_cap == 0) ? 16u : s->nick_objs_cap * 2u;
        conn_t **grown = (conn_t **)realloc(s->nick_objs,
                                           want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        s->nick_objs = grown;
        s->nick_objs_cap = want;
    }
    s->nick_objs[s->nnick_objs] = c;
    s->nnick_objs++;
    return 0;
}

/* Remove `c` from the enumeration, preserving claim order. Idempotent.
 *
 * Keyed by POINTER, which is the whole point and replaces the name-keyed
 * nick_objs_del() this used to be. Comparing nick strings meant matching a
 * conn_t::nick -- a display field -- against a key, with the ASCII fold
 * re-implemented on the spot, and it could remove the entry of a connection
 * that did not hold the name at all: the case where a conn was DENIED a
 * nickname and had the same string in conn_t::nick anyway, which is exactly what
 * a client that asks for a name somebody else holds looks like from inside.
 *
 * Every copy is removed rather than the first: with the conditional append there
 * can only be one, but a teardown that is correct only because of what the
 * claim path does is the same fragile coupling in the other direction. */
static void nick_objs_drop(server_t *s, conn_t *c)
{
    size_t i = 0;

    while (i < s->nnick_objs) {
        if (s->nick_objs[i] == c) {
            size_t j;

            for (j = i + 1u; j < s->nnick_objs; j++) {
                s->nick_objs[j - 1u] = s->nick_objs[j];
            }
            s->nnick_objs--;
            s->nick_objs[s->nnick_objs] = NULL;
            continue; /* whatever shifted into slot i may also be c */
        }
        i++;
    }
}

int server_nick_claim(server_t *s, const char *nick, conn_t *c)
{
    if (s == NULL || nick == NULL || !valid_nick(nick)) {
        return -1;
    }
    if (server_nick_lookup(s, nick) != NULL) {
        return -1;
    }
    if (strtab_put(s->nicks, nick, c) != 0) {
        return -1;
    }
    /* The table is written FIRST and the vector second, and a failed append
     * rolls the table entry back. A half-applied claim would be worse than a
     * refused one: the two indexes disagreeing means a nickname this node
     * answers 433 for while WHO does not list it, or the reverse, and there is
     * no event that would ever reconcile them. Refusing the claim leaves the
     * state exactly as it was, which is the only outcome a caller can reason
     * about.
     *
     * The append is idempotent (see nick_objs_add), so a claim that only ADDS a
     * name to a connection already in the vector cannot fail here -- there is no
     * allocation on that path and nothing to roll back. That is deliberate: the
     * rename in handle_nick() claims the new name before releasing the old one,
     * and an idempotent append is what lets the two halves of a rename meet in
     * the middle without the enumeration briefly losing the connection. */
    if (nick_objs_add(s, c) != 0) {
        (void)strtab_del(s->nicks, nick);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * WHY THERE IS NO nick_same() ANY MORE
 * ---------------------------------------------------------------------------
 * There used to be a third copy of the node's ASCII fold here, comparing
 * conn_t::nick against a release key, and the reason it could be deleted is the
 * reason it existed: the enumeration was keyed by NAME, so removing an entry
 * meant finding it by name and meant re-implementing the table's own key rule in
 * a second place. The enumeration is keyed by pointer now, so no comparison is
 * needed and the fold exists in exactly one place -- inside the table's probe.
 *
 * The case it was protecting is still protected, and better: test_registries.c
 * releases "cAROL" for a nickname claimed as "carol" and asserts the ENUMERATION
 * shrank too, and that still works, because server_nick_release() below gets
 * the holder from the TABLE, and the table's probe folds. One implementation of
 * the rule instead of two, and the copy that could have drifted is the one that
 * is gone. irc_ascii_same() (message.h, issue #181) is the node's one fold. */

/* Give up ONE name, leaving the connection itself in the registry. This is the
 * release for a connection that is STAYING: handle_nick()'s rename is the only
 * caller in the tree. A caller that is destroying the connection must use
 * server_nick_unclaim() below instead, and the difference is not stylistic --
 * this function is handed a name and knows nothing about which conn_t will be
 * freed afterwards, so it cannot promise that no reference to it survives.
 *
 * Both halves come from the TABLE, in this order:
 *
 *   1. the holder is read out of the table, so a spelling the holder never typed
 *      still finds it: the table's probe folds, and this function does not have
 *      a fold of its own to get wrong. (A name nobody holds is a no-op, which is
 *      what makes the double call on the ordinary QUIT path -- handler, then
 *      reaper -- harmless rather than a corruption.)
 *   2. the name is removed, and the holder leaves the enumeration ONLY if it no
 *      longer holds a name. That second test is why a rename cannot drop the
 *      connection out of WHO's walk: handle_nick() claims the new name first,
 *      so the holder is in the table again by the time the old one is released,
 *      and the enumeration is a set of users rather than a count of names.
 *
 * A connection that holds two names keeps its entry until both are given up,
 * which is the invariant at the top of this section rather than a special case
 * here. */
void server_nick_release(server_t *s, const char *nick)
{
    conn_t *holder;

    if (s == NULL || nick == NULL) {
        return;
    }
    holder = (conn_t *)strtab_get(s->nicks, nick);
    if (holder == NULL) {
        return; /* nobody holds this name: already released */
    }
    (void)strtab_del(s->nicks, nick);
    if (strtab_count_owner(s->nicks, holder) == 0u) {
        nick_objs_drop(s, holder);
    }
}

/* Retire a connection from the nick index. THE teardown path, and the only one:
 * server_close_conn() and handle_quit() both come here, so a QUIT and a client
 * that vanished without one cannot do different things.
 *
 * It takes a conn_t and not a name, and that is the design rather than a
 * convenience. A name-keyed teardown has to ask "does this conn still hold the
 * name" and then remove the name -- the ownership guard that #102 got wrong by
 * applying to one half of the index and forgetting the other. Keyed on the
 * connection there is nothing to ask: the table loses exactly the entries whose
 * VALUE is this conn, and the vector loses exactly the entries that ARE this
 * conn. A connection that was denied a nickname cannot evict the holder's entry
 * (that entry's value is somebody else, and it is not this conn), and a
 * connection that somehow holds several names loses all of them rather than one,
 * which is what makes the subsequent conn_free() safe with no further argument.
 *
 * Idempotent, and a no-op for a connection that never claimed a name: the
 * teardown runs on every close, including every close of a connection that was
 * still in registration. Both halves are in this function with no early return
 * between them, so there is no longer a way to apply one of them alone. */
void server_nick_unclaim(server_t *s, conn_t *c)
{
    if (s == NULL || c == NULL) {
        return;
    }
    (void)strtab_del_owner(s->nicks, c);
    nick_objs_drop(s, c);
}

conn_t *server_nick_lookup(const server_t *s, const char *nick)
{
    if (s == NULL) {
        return NULL;
    }
    return (conn_t *)strtab_get(s->nicks, nick);
}

size_t server_nick_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nnick_objs;
}

conn_t *server_nick_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nnick_objs) {
        return NULL;
    }
    return s->nick_objs[i];
}

int server_chan_add(server_t *s, const char *name)
{
    if (s == NULL || name == NULL || name[0] == '\0') {
        return -1;
    }
    if (strtab_contains(s->chans, name)) {
        return -1; /* already known */
    }
    /* The key is registered here with a NULL value; server_chan_attach() below
     * installs the chan_t. Phase 2 stored NULL because struct chan did not exist,
     * and the two-step shape is what lets the Phase 2 probe keep its exact
     * contract -- see the comment on server_chan_lookup(). */
    return strtab_put(s->chans, name, NULL);
}

void server_chan_remove(server_t *s, const char *name)
{
    if (s != NULL) {
        (void)strtab_del(s->chans, name);
    }
}

const char *server_chan_lookup(const server_t *s, const char *name)
{
    if (s == NULL || !strtab_contains(s->chans, name)) {
        return NULL;
    }
    /* Phase 2's probe, unchanged: "is this EXACT key present". It is
     * deliberately case-SENSITIVE, because a case-insensitive fold is Phase 4's
     * business and belongs in the accessor that canonicalises rather than
     * appearing here as a silent side effect. The channel VALUE is reached
     * through server_chan_get() in core/channel.c. */
    return name;
}

/* ---------------------------------------------------------------------------
 * The channel set: values, and an ordered index
 * ---------------------------------------------------------------------------
 * The Phase 2 probes above answer "is this key present" and carry no value.
 * These are the value-carrying pair declared in core/channel.h, and they live
 * here because the strtab is file-private: a second accessor in another file
 * would mean either exporting the table type or duplicating the probe loop, and
 * the probe loop is the one thing in this file that must not exist twice.
 */
int server_chan_attach(server_t *s, chan_t *ch)
{
    if (s == NULL || ch == NULL || ch->name[0] == '\0') {
        return -1;
    }
    if (server_chan_get(s, ch->name) != NULL) {
        return -1; /* the name is taken */
    }
    /* THE NODE-WIDE CAP (issues #169 and #223), enforced on the SHARED path so
     * peer-driven creation (SJOIN, burst) cannot pass what the local JOIN path
     * refuses. Only creation is refused: attaching what the node holds does not
     * take this branch. Callers free the unattached channel, so a refusal here
     * leaves no ghost. */
    if (s->nchan_objs >= SERVER_MAX_CHANNELS) {
        return -1;
    }
    if (s->nchan_objs == s->chan_objs_cap) {
        size_t want = (s->chan_objs_cap == 0) ? 8u : s->chan_objs_cap * 2u;
        chan_t **grown = (chan_t **)realloc(s->chan_objs, want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        s->chan_objs = grown;
        s->chan_objs_cap = want;
    }
    if (strtab_put(s->chans, ch->name, ch) != 0) {
        return -1;
    }
    s->chan_objs[s->nchan_objs++] = ch;
    return 0;
}

chan_t *server_chan_get(const server_t *s, const char *name)
{
    char canonical[CHAN_MAX_NAME + 1];

    if (s == NULL || name == NULL) {
        return NULL;
    }
    /* Canonicalise first. A channel's name is stored uppercase (2.2), so a
     * lookup that did not fold would make "JOIN #T" and "JOIN #t" two
     * channels -- which is the one behaviour the Phase 2 probe deliberately
     * does not have. */
    (void)chan_name_upper(canonical, sizeof canonical, name);
    if (canonical[0] == '\0') {
        return NULL;
    }
    return (chan_t *)strtab_get(s->chans, canonical);
}

void server_chan_detach(server_t *s, const char *name)
{
    char canonical[CHAN_MAX_NAME + 1];

    if (s == NULL || name == NULL) {
        return;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    server_chan_remove(s, canonical);
    for (size_t i = 0; i < s->nchan_objs; i++) {
        if (s->chan_objs[i] != NULL &&
            strcmp(s->chan_objs[i]->name, canonical) == 0) {
            /* Order-preserving, like conn_t::chans and chan_t::members: LIST's
             * row order is creation order, and one channel leaving must not
             * reshuffle the rows behind it. */
            (void)memmove(&s->chan_objs[i], &s->chan_objs[i + 1u],
                          (s->nchan_objs - i - 1u) * sizeof s->chan_objs[0]);
            s->nchan_objs--;
            return;
        }
    }
}

size_t server_chan_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nchan_objs;
}

chan_t *server_chan_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nchan_objs) {
        return NULL;
    }
    return s->chan_objs[i];
}
