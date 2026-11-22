/* nickreg.c -- see nickreg.h. 2.1's remote-nick registry, and the rename-the-loser
 * decision that goes with it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE INDEX IS A VECTOR AND NOT A HASH TABLE
 * ---------------------------------------------------------------------------
 * Every other string-keyed index in this node is a strtab: server.c's nicks and
 * chans, and that is the right answer for a registry that can hold a connection
 * PER NAME and whose enumeration is a hot path (WHO walks it).
 *
 * This one is not that. The bound is IRC_FED_MAX_REMOTE_NICKS, which is 256, and
 * a linear scan of 256 POD entries on a path that runs at most once per inbound
 * burst record is a few hundred comparisons -- and a burst is a transaction that
 * is already O(nicks + members) with a staging buffer the size of four links'
 * write queues. A hash table here would be a second table, a probe function, a
 * growth policy and a second teardown arm, all to turn a comparison that happens
 * inside an O(n) transaction into a comparison that happens once.
 *
 * THE COST, since a costless scan is a claim: a lookup is O(n) in the number of
 * REMOTE users this node has been told about, and the resolution path
 * (fanout_resolve on a `nick@server` target) is O(n) per such message. At the
 * 256-entry bound that is one strcmp-fold over at most 256 entries, and a node
 * large enough for that to be visible would be a node whose mesh has more remote
 * users than its own -- which is a node whose registry is evicting anyway (see
 * n_rnick_evicted) and whose cost is better spent on a bigger bound.
 *
 * ---------------------------------------------------------------------------
 * EVICTION IS LEAST-RECENTLY-SEEN, AND WHY THE ORDER IS A LIST NOT AN INDEX
 * ---------------------------------------------------------------------------
 * Every learn, refresh and rename links its entry at the head of an intrusive
 * LRU list (dedup.c's arrangement: two pointers per entry, +16 B). That single
 * convention is what makes eviction the tail, what makes a refresh O(1), and
 * what makes "most recent" and "last" the same thing without a field saying so.
 * The vector itself is unordered storage: scans run over the allocation and
 * skip holes, and entries never move, which is what keeps the list's pointers
 * valid. A learn used to move its entry to the END of the vector -- a memmove
 * of up to 86 KiB per inbound nick record, ~21 MiB inside one 250-nick burst
 * tick -- and that is why the list is here rather than the index.
 */
#include "federation/nickreg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/fanout.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* The bound on the sweep throttle, DERIVED from the TTL rather than picked: a
 * sweep at most every TTL/16 means an entry is dropped within a sixteenth of its
 * real expiry of expiring, and the sweep itself costs one comparison per tick
 * that is not due. */
#define IRC_FED_RNICK_SWEEP_MS (IRC_FED_RNICK_TTL_MS / 16u)

/* One remote user, as some server last reported.
 *
 * THE LAYOUT IS WRITTEN OUT AS ARITHMETIC rather than left implicit, and it is
 * the same reason dedup.h gives for its entry size: a size that is quoted in a
 * cost argument and not written down is a cost argument whose input can drift
 * silently. The sum is asserted by a TEST rather than by a _Static_assert,
 * because -Wpre-c11-compat is in upstream clang's -Weverything and this project's
 * answer to a diagnostic it cannot satisfy without narrowing the warning set is
 * never to narrow it.
 *
 *   nick[IRC_MAX_NICK + 1]         64
 *   server[IRC_MAX_SERVER_NAME+1]  64
 *   user[64]                       64    (conn_t::user's width; RFC 1459 2.3 caps
 *                                          <username> at 9 characters and nothing
 *                                          in this tree stores more, but the
 *                                          width is the one a report could carry)
 *   host[CHAN_MAX_REMOTE_HOST+1]  128
 *   signon                         8
 *   seen_ms                        8
 *   lru_prev + lru_next            16
 *                                  ---
 *                                  352   == IRC_FED_RNICK_ENTRY_BYTES
 *
 * THE LRU PAIR IS WHAT MAKES LEARN O(1): the links live in the entry the way
 * dedup's do, so touching a record unlinks and re-links two pointers instead of
 * memmoving the 88 KiB tail behind it. Pointers and not indices because entries
 * never move -- nothing compacts the vector any more, so a pointer into the
 * calloc stays valid for the table's life. A freed slot is emptied AND unlinked,
 * and the empty-slot marker is still `nick[0] == '\0'`, which is unambiguous
 * because 2.1's valid_nick() rejects an empty nickname. */
#define IRC_FED_RNICK_ENTRY_BYTES 352u

struct fed_rnick {
    char     nick[IRC_MAX_NICK + 1];
    char     server[IRC_MAX_SERVER_NAME + 1];
    char     user[IRC_MAX_NICK + 1];
    char     host[CHAN_MAX_REMOTE_HOST + 1];
    uint64_t signon;
    uint64_t seen_ms;
    struct fed_rnick *lru_prev; /* LRU: less recently seen (NULL at the tail) */
    struct fed_rnick *lru_next; /* LRU: more recently seen (NULL at the head) */
};

/* Nickname and server-name comparison is message.h's irc_ascii_same()
 * (issue #181): 2.1 makes nicknames case-insensitive while the case the user
 * chose is what gets DISPLAYED, and 2.4's grammar makes server names
 * case-insensitive, so `IRC.A` and `irc.a` are one server and a registry that
 * stored them as two entries would let a node claim two servers hold a nick
 * when one does. */

/* Find the entry for (nick, server), or NULL. An EMPTY `server` is a wildcard
 * match rather than an equality test, which is what makes
 * fed_nickreg_forget(s, nick, NULL) able to forget a nick everywhere in one
 * call; the alternative is a second walk in the caller and a second thing to keep
 * in step with the first. */
static struct fed_rnick *nickreg_find(server_t *s, const char *nick,
                                      const char *server)
{
    size_t i;

    if (s == NULL || nick == NULL || s->rnicks == NULL) {
        return NULL;
    }
    /* OVER nrnicks, skipping holes: entries never move, so a freed slot stays a
     * hole and `nrnick_used` is a live count, not a bound. The zeroed tail and
     * the holes are skipped the same way. */
    for (i = 0; i < s->nrnicks; i++) {
        struct fed_rnick *e = &s->rnicks[i];

        if (e->nick[0] == '\0') {
            continue; /* free slot */
        }
        if (!irc_ascii_same(e->nick, nick)) {
            continue;
        }
        if (server != NULL && server[0] != '\0' && !irc_ascii_same(e->server, server)) {
            continue;
        }
        return e;
    }
    return NULL;
}

/* The LRU list, dedup's operations on server_t's head and tail: the head is the
 * most recently seen, the tail the eviction candidate. Push and unlink are
 * separate because eviction unlinks WITHOUT re-linking, and the sweep unlinks
 * the entries it drops the same way. */
static void nickreg_lru_push_head(server_t *s, struct fed_rnick *e)
{
    e->lru_prev = NULL;
    e->lru_next = s->nrnick_lru_head;
    if (s->nrnick_lru_head != NULL) {
        s->nrnick_lru_head->lru_prev = e;
    }
    s->nrnick_lru_head = e;
    if (s->nrnick_lru_tail == NULL) {
        s->nrnick_lru_tail = e;
    }
}

static void nickreg_lru_unlink(server_t *s, struct fed_rnick *e)
{
    if (e->lru_prev != NULL) {
        e->lru_prev->lru_next = e->lru_next;
    } else if (s->nrnick_lru_head == e) {
        s->nrnick_lru_head = e->lru_next;
    }
    if (e->lru_next != NULL) {
        e->lru_next->lru_prev = e->lru_prev;
    } else if (s->nrnick_lru_tail == e) {
        s->nrnick_lru_tail = e->lru_prev;
    }
    e->lru_prev = NULL;
    e->lru_next = NULL;
}

/* Mark `e` most recently seen. Pointer writes rather than the memmove this
 * replaced: a touch per burst record is what made a 250-nick burst copy
 * ~21 MiB inside one tick. */
static void nickreg_touch(server_t *s, struct fed_rnick *e)
{
    if (s->nrnick_lru_head == e) {
        return;
    }
    nickreg_lru_unlink(s, e);
    nickreg_lru_push_head(s, e);
}

/* Hand out a slot for a new entry, EVICTING the least recently seen when the
 * table is full.
 *
 * THE EVICTION IS NOT A REFUSAL, and the reason is 2.2's rule for the topic
 * cache: a cache that can refuse is a cache that can break a client command. A
 * node that has been told about more remote users than it will remember drops
 * the oldest and counts it, because the alternative -- refusing to learn a nick
 * at all -- would make a peer's resync silently incomplete, which is a far worse
 * failure than a forgotten entry that the next resync will supply again. */
static struct fed_rnick *nickreg_append(server_t *s)
{
    size_t i;
    struct fed_rnick *e = NULL;

    if (s->rnicks == NULL) {
        /* LAZILY, and the reason is the cost argument in the header: a node with
         * no peers never learns a remote nick, so allocating 88 KiB at
         * server_init() would be a cost paid by every single-node deployment for
         * a feature none of them can use. This is the same arrangement the dedup
         * table makes and for the same reason. */
        s->rnicks = (struct fed_rnick *)calloc(IRC_FED_MAX_REMOTE_NICKS,
                                               sizeof *s->rnicks);
        if (s->rnicks == NULL) {
            /* A node that cannot allocate the table cannot learn remote nicks,
             * and says so. Failing closed here is right for the same reason
             * fed_dedup_seen() fails closed: a lost nick record is one
             * unresolvable target, where a store that silently did not record is
             * a mesh whose rosters quietly disagree. */
            return NULL;
        }
        s->nrnicks = IRC_FED_MAX_REMOTE_NICKS;
    }
    /* A freed hole first: the scan reads first bytes only, not whole entries.
     * No hole means the table is full, so the LRU tail is evicted and its slot
     * reused in place -- no memmove on either path. */
    for (i = 0; i < s->nrnicks; i++) {
        if (s->rnicks[i].nick[0] == '\0') {
            e = &s->rnicks[i];
            break;
        }
    }
    if (e == NULL) {
        /* The dropped slot is CLEARED rather than merely unlinked so a reused
         * entry cannot inherit a prefix of the evicted one. */
        e = s->nrnick_lru_tail;
        nickreg_lru_unlink(s, e);
        memset(e, 0, sizeof *e);
        s->nrnick_used--;
        s->n_rnick_evicted++;
        printf("[observable] fed_nick_evicted: table=%zu bound=%zu\n",
               s->nrnick_used, (size_t)IRC_FED_MAX_REMOTE_NICKS);
    }
    memset(e, 0, sizeof *e);
    s->nrnick_used++;
    nickreg_lru_push_head(s, e);
    return e;
}

/* The shared body of the two learn functions. `server` may be "" and the
 * nick/user/host may be absent; see nickreg.h on which absences are ordinary. */
/* ---------------------------------------------------------------------------
 * nickreg_ident_ok(): THE RULE FOR A HOSTMASK COMPONENT, AND WHY IT IS A REFUSAL
 * ---------------------------------------------------------------------------
 * #142 asks whether `fed_rnick::user` and `fed_rnick::host` are STORED VALUES or
 * IDENTIFIERS, and the answer is IDENTIFIERS, and it follows from what consumes them.
 * They are what `fed_nickreg_render()` assembles into `nick!user@host`. Every other
 * name this tree holds a network-supplied value in is validated at ingest and REFUSED
 * rather than cleaned: `valid_nick()` for a nickname, `chan_name_valid()` for a channel,
 * `irc_serve_server_name_valid()` for a server, `account_name_wire_safe()` for an
 * account. None of them strips, because none of them can: a byte removed from a name
 * does not make it safer, it makes it a DIFFERENT name.
 *
 * THE CONTRAST IS A TOPIC, and it is the whole of the decision. A topic is free text:
 * it is stored, it is relayed, and it is rendered to every member of the channel, so
 * `conn_text_strip()` removes the bytes a terminal would execute and the words survive
 * -- and `chan_set_topic()` says why truncation is not available instead ("a topic cut
 * mid-word is a different topic, and a client would have no way to tell"). A `<host>` is
 * not free text. It is one of three NAMED slots, and a byte in it changes what the name
 * is rather than how it looks, so the only honest answers are "the peer sent a name this
 * node cannot render" and nothing else.
 *
 * THE RULE, and it is 3.2's rather than a new grammar. A MESSAGE PARAMETER can escape
 * NOTHING: it refuses SP, HTAB, CR and LF in every position and refuses a value needing
 * the ':' marker anywhere but the last. So a name a parameter cannot carry is a name
 * `nick!user@host` cannot carry, and the byte test is the one `account_name_wire_safe()`
 * already uses -- `ch <= 0x20 || ch == 0x7f` -- which is the whole of why that function
 * and this one agree about where the edge is rather than each having its own copy.
 *
 * BYTE ORDER IS DELIBERATE and it is not alphabetical: DEL (0x7F) is not a control
 * character, it is an ordinary glyph in most fonts and invisible in a log, and a name
 * carrying one is a name two renderers disagree about rather than one that escapes
 * anything. It is refused because it is ambiguous, not because it is dangerous, and the
 * comment says so because the alternative reading is that DEL was forgotten.
 *
 * WHAT IT DOES NOT CHECK, and the limit is named rather than left: this says the bytes
 * are renderable, not that the value is a legal host. 2.1's `<host>` is a hostname or
 * an IP literal and this does not parse either -- the tree has no hostname grammar and
 * inventing one here would be a larger decision than the exposure warrants. What IS
 * checked is everything that can move a cursor or break a field, and the residue is a
 * host that renders as the peer spelled it. That is the honest bound on a cache.
 *
 * COST: one pass over a value at most CONN_MAX_HOST bytes, once per burst nick record,
 * on a path that runs once per resync rather than once per message.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS NO LONGER `static`
 * ---------------------------------------------------------------------------
 * It was file-private, applied on the PEER side only. `conn_t::user` -- the same
 * `<user>` slot of the same `nick!user@host` hostmask -- had no predicate at all on the
 * CLIENT side, and that gap was an anonymous, pre-registration, cross-client terminal
 * injection: `USER <ESC>[2J... 0 * :x` stored the bytes in `c->user`, and
 * `conn_hostmask()` then put them in the PREFIX of every line that client sent to every
 * co-member of every channel it joined. See handle_user() in core/commands.c for the
 * full argument and for why the answer is refusing at ingest rather than filtering at
 * render.
 *
 * The blunt way to close it would have been a second predicate next to this one, and
 * that is the mistake this tree has already made three times: two functions answering
 * "which bytes may a hostmask component hold" is how they come to disagree, and the
 * disagreement is invisible until one of them is the one an attacker reaches. So this
 * one is exported and ASKED BY BOTH PATHS -- `nickreg_learn()` on a peer's SBURSTN
 * record, `handle_user()` on a client's `USER` -- and the same reasoning that settled
 * `SMODES` against client `MODE` applies: one predicate, asked twice, and a test that
 * the two agree.
 *
 * ---------------------------------------------------------------------------
 * THE SECOND HALF OF THE BYTE TEST, AND IT WAS MISSING
 * ---------------------------------------------------------------------------
 * The loop below is `ch <= 0x20 || ch == 0x7f`, which is a PARAMETER-shape rule and a
 * good one: a byte a message parameter cannot carry is a byte `nick!user@host` cannot
 * carry. It is also, on its own, blind to the exact byte class this project has now
 * spent two passes removing from the rest of the tree. `0x9B` is 0x9B: it is not <=
 * 0x20, it is not 0x7f, and on an 8-bit terminal it IS CSI. A raw `0x9B` in
 * `fed_rnick::user` was therefore accepted by this predicate, stored, and rendered
 * into a hostmask by every path that reads the registry -- and the same byte in
 * `conn_t::user` was accepted by NOTHING AT ALL and rendered into a hostmask by
 * `conn_hostmask()`, which is the reported vulnerability.
 *
 * SO IT ALSO ASKS `conn_text_display_check()`, which is the walk `valid_nick()` uses
 * for `conn_t::nick` and `conn_realname_check()` uses for `conn_t::realname`. That is
 * the same decision realname made for the same reason: a value STORED and re-rendered
 * into every line its owner sends must be about CODE POINTS and not bytes, or a
 * byte-range test refuses `ā` (`0xC4 0x81`, whose second byte is 0x81) and silently
 * eats every accented Latin, Greek and Cyrillic ident on the network. A filter that
 * mangles valid UTF-8 is worse than the injection it was meant to stop, because the
 * user cannot see it happen.
 *
 * WHAT THE SECOND HALF ADDS, exactly:
 *   CONN_DISPLAY_CONTROL  C0 and DEL -- already refused above, so this is redundant.
 *   CONN_DISPLAY_C1       U+0080-U+009F as a bare 0x80-0x9F byte or as 0xC2 0x80-0x9F.
 *                         THIS IS THE LIVE HOLE. U+009B is CSI whatever the encoding.
 *   CONN_DISPLAY_UTF8     invalid or truncated UTF-8 -- a bare continuation byte, an
 *                         overlong 0xC0/0xC1, a surrogate half, a sequence that stops
 *                         early. A stored value that is not a character has no honest
 *                         rendering and no way to be told apart from a typo.
 *
 * The two halves are an INTERSECTION, not a union, and that is deliberate: the loop
 * refuses SPACE and TAB which the display walk permits, and the display walk refuses
 * C1 and invalid UTF-8 which the loop permits. An ident is one of three NAMED slots in
 * a `nick!user@host`, so it is not free text and it gets the stricter of the two rules
 * on every axis.
 *
 * WHAT IT COSTS THE PEER PATH, stated because it is a behaviour change on a surface
 * that was already shipped: a peer whose SBURSTN carries a user or host holding a raw
 * C1 byte, an encoded C1 pair or a malformed UTF-8 sequence now has that FIELD REFUSED
 * where it used to be stored. The record is kept -- `nickreg_learn()` keeps it -- and
 * `nickreg_ident_refused()` reports the refusal as a length and a bad-byte count, so a
 * peer sending such a value was already generating a finding. A conforming peer
 * reports idents its own clients asserted through `USER`, and a client ident now goes
 * through this same predicate, so the two sides of a link agree by construction.
 */
int nickreg_ident_ok(const char *s, size_t cap)
{
    size_t i;

    /* An absent value is "not told", not "bad", and that is why the callers test
     * `s[0] != '\0'` themselves rather than this returning 0 for it: an empty host
     * is a normal state and reporting it as a refusal would be a false finding on
     * every record that omits one. */
    if (s == NULL || s[0] == '\0' || cap == 0u) {
        return 0;
    }
    /* AND THE WIDTH, which is the second half of the rule and was `bounded_copy()`'s
     * whole job until now. A value that does not FIT is one this node cannot hold,
     * whatever it is made of -- and `bounded_copy()` TRUNCATES, so without this a
     * 400-byte host would become a 63-byte host under a name the peer will never be
     * asked about again, which is 3.2's "never deliver a silently shortened
     * parameter" arriving by a different road. `account_name_wire_safe()` binds the
     * same way with ACCOUNT_MAX_NAME hard-wired, because its callers all share one
     * field width; here the caller supplies it, because `user` and `host` are two
     * different fields and a caller that passed the wrong one would get a value
     * truncated to a width nobody declared. */
    if (strlen(s) >= cap) {
        return 0;
    }
    for (i = 0; s[i] != '\0'; i++) {
        const unsigned char ch = (unsigned char)s[i];

        if (ch <= 0x20u || ch == 0x7fu) {
            return 0;
        }
        /* Hostmask delimiters, which RFC 1459 2.3 does not allow in <user>
         * and which would make the rendered `nick!user@host` prefix ambiguous:
         * a delimiter inside the ident would forge or split the prefix as seen
         * by a client that parses it, so the value is refused rather than
         * stored. `~`, `-`, `_`, `.` and alphanumerics remain allowed, along
         * with valid UTF-8. */
        if (ch == (unsigned char)'!' || ch == (unsigned char)'@' ||
            ch == (unsigned char)':' || ch == (unsigned char)';') {
            return 0;
        }
    }
    /* AND THE SECOND HALF, which is why this function is no longer sufficient on
     * its own. See the block at the definition for what it adds and why it is the
     * SAME walk `valid_nick()` and `conn_realname_check()` use rather than a
     * second spelling of "renderable". */
    if (conn_text_display_check(s) != CONN_DISPLAY_OK) {
        return 0;
    }
    return 1;
}

/* nickreg_ident_refused(): THE REPORT, AND WHY IT IS AN OBSERVABLE RATHER THAN A
 * COUNTER.
 *
 * #142 asked which counter. `n_fed_malformed` is for a line this node cannot PARSE and
 * this is a field this node will not STORE, so it would make that counter mean two
 * incompatible things. The alternative -- a new `server_t` counter -- is the gap #133
 * found and left open for a decision, and the reason it was left open is a real one: a
 * `server_t` counter is published in the single `[fixture] stats` line every integration
 * test parses, so adding one is a change to every test's ground truth rather than to
 * one file. So the answer is the mechanism `apply_chan()` already established for the
 * same class of event: refuse the field, keep the record, and SAY SO on a line an
 * operator reads.
 *
 * THE PEER IS TOLD BY THE EXISTING COUNT and not by anything new, which answers #142's
 * third sub-question. The burst terminator's `dropped=` already carries a record whose
 * fields this node could not hold, so a refusal here is visible to the peer through the
 * count it already reads -- the same answer `apply_chan()` gives for `<topic>`, and for
 * the same reason: the 4.3 burst format has no field-refusal report, and inventing one
 * would be a wire change this pass has no reason to make.
 *
 * THE VALUE IS MEASURED, NEVER PRINTED. `field=` names which of the two components was
 * refused -- a fixed literal at both call sites -- and the peer-chosen value appears
 * only as a length and a bad-byte count, which is `connection.h`'s Rule 1 and what
 * every other peer field on this node does. Printing it would put whatever the peer
 * sent into an operator's terminal, which is the very class this predicate exists to
 * keep out of the fields. */
static void nickreg_ident_refused(const server_t *s, const char *nick,
                                  const char *field, const char *value)
{
    if (value == NULL) {
        return;
    }
    (void)s;
    printf("[observable] fed_nickreg_field_refused: nick=%s field=%s len=%zu "
           "bad_bytes=%zu reason=NOT_A_PARAMETER_BYTE\n",
           nick, field, strlen(value), conn_text_bad_count(value));
}

static void nickreg_learn(server_t *s, const char *nick, const char *server,
                          const char *user, const char *host, uint64_t signon,
                          uint64_t now_ms)
{
    struct fed_rnick *e;
    int have;

    if (s == NULL || nick == NULL || nick[0] == '\0' || !valid_nick(nick)) {
        /* 2.1's charset rule is applied HERE rather than trusted, for the reason
         * federation/verbs.c's G9 gives: this is a nickname arriving from a
         * network, and an entry holding one this node could not qualify, compare
         * or render is an entry nothing can use. A malformed nick is counted by
         * the caller's own guard chain as malformed, so this is belt to that
         * braces. */
        return;
    }
    e = nickreg_find(s, nick, server);
    if (e != NULL) {
        /* A REPEAT REFRESHES rather than adding, which is what makes this a map
         * and not a log. `server` is deliberately not overwritten when it is
         * empty: an entry that came from a live SJOIN has no holder, and a later
         * report of the same nick with no holder must not erase a holder a burst
         * had already established. */
        if (server != NULL && server[0] != '\0') {
            (void)bounded_copy(e->server, sizeof e->server, server);
        }
        if (user != NULL && user[0] != '\0') {
            /* IDENTIFIERS, REFUSED NOT SANITISED (#142). See the predicate's own
             * comment for the policy and for why the answer here is "refuse the
             * field" rather than "strip it" or "store it and hope". */
            if (nickreg_ident_ok(user, sizeof e->user)) {
                (void)bounded_copy(e->user, sizeof e->user, user);
            } else {
                nickreg_ident_refused(s, nick, "user", user);
            }
        }
        if (host != NULL && host[0] != '\0') {
            if (nickreg_ident_ok(host, sizeof e->host)) {
                (void)bounded_copy(e->host, sizeof e->host, host);
            } else {
                nickreg_ident_refused(s, nick, "host", host);
            }
        }
        /* signon is only overwritten when the report carries one, for the same
         * reason: an absent field is "not told", not "zero", and 0 is a value 2.4
         * would have to be able to express. */
        if (signon != 0u) {
            e->signon = signon;
        }
        e->seen_ms = now_ms;
        nickreg_touch(s, e);
        return;
    }
    e = nickreg_append(s);
    if (e == NULL) {
        return;
    }
    /* Already zeroed by append(), which is what keeps a reused slot from keeping
     * a field the new report does not carry -- and why the zeroing lives there
     * rather than here, where it would also clear the links append() just set. */
    have = bounded_copy(e->nick, sizeof e->nick, nick);
    (void)bounded_copy(e->server, sizeof e->server, server);
    /* The two hostmask components go through the SAME predicate as the refresh arm
     * above, and the reason it is one function rather than two checks written at the
     * two call sites is the one this file has been bitten by twice: two answers to
     * "which bytes may this field carry" is how they come to disagree, and a slot
     * filled on the append path and refused on the refresh path is a registry whose
     * contents depend on the order the same nickname was reported in. */
    if (user != NULL && nickreg_ident_ok(user, sizeof e->user)) {
        (void)bounded_copy(e->user, sizeof e->user, user);
    } else if (user != NULL && user[0] != '\0') {
        nickreg_ident_refused(s, nick, "user", user);
    }
    if (host != NULL && nickreg_ident_ok(host, sizeof e->host)) {
        (void)bounded_copy(e->host, sizeof e->host, host);
    } else if (host != NULL && host[0] != '\0') {
        nickreg_ident_refused(s, nick, "host", host);
    }
    e->signon = signon;
    e->seen_ms = now_ms;
    if (have == 0) {
        /* Unreachable: valid_nick() bounds the nick and the buffer is that same
         * width. Handled rather than asserted because a table entry that was
         * partly written would be an entry nothing can read, and the only way to
         * find that out is a length check. */
        memset(e, 0, sizeof *e);
        s->n_rnick_evicted++;
    }
}

void fed_nickreg_learn(server_t *s, const char *nick, const char *server,
                        const char *user, const char *host, uint64_t signon,
                        uint64_t now_ms)
{
    nickreg_learn(s, nick, server, user, host, signon, now_ms);
}

void fed_nickreg_learn_member(server_t *s, const char *nick,
                              const char *burst_origin,
                              const char *member_server, uint64_t now_ms)
{
    const char *holder = member_server;

    /* THE FALLBACK, and it is the one channel.h's chan_remote_t already makes:
     * an empty member_server means "not told", and the burst origin is the best
     * available answer. On a two-node mesh and for a member the origin hosts
     * itself, the two strings are the same, so the fallback is exact there and an
     * approximation on a larger mesh -- which is the honest limit of a field that
     * 4.3.1 only required to be present. */
    if (holder == NULL || holder[0] == '\0') {
        holder = burst_origin;
    }
    /* The refinement passes the burst origin as the lookup server so a repeat for
     * the SAME origin updates in place rather than adding a second entry -- which
     * is what keeps a resync, which replaces per origin, from leaving a stale
     * entry behind under the old key. A holder that genuinely differs from the
     * origin is a DIFFERENT key and does get its own entry, which is correct: the
     * two names answer different questions (see channel.h on `server` versus
     * `member_server`). */
    nickreg_learn(s, nick, holder, NULL, NULL, 0u, now_ms);
}

void fed_nickreg_forget(server_t *s, const char *nick, const char *server)
{
    size_t i;

    if (s == NULL || s->rnicks == NULL || nick == NULL) {
        return;
    }
    /* Over the allocation, skipping holes: entries never move, so removal only
     * unlinks and zeroes, and a wildcard forget needs no re-examination of an
     * index the compaction used to shift into. A PART is not a hot path. */
    for (i = 0; i < s->nrnicks; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !irc_ascii_same(s->rnicks[i].nick, nick)) {
            continue;
        }
        if (server != NULL && server[0] != '\0' &&
            !irc_ascii_same(s->rnicks[i].server, server)) {
            continue;
        }
        nickreg_lru_unlink(s, &s->rnicks[i]);
        memset(&s->rnicks[i], 0, sizeof s->rnicks[0]);
        s->nrnick_used--;
    }
}

int fed_nickreg_rename(server_t *s, const char *server, const char *old_nick,
                       const char *new_nick, uint64_t now_ms)
{
    size_t i;
    size_t at = s != NULL ? s->nrnicks : 0u;

    if (s == NULL || s->rnicks == NULL || server == NULL || old_nick == NULL ||
        new_nick == NULL) {
        return 0;
    }
    /* THE NEW NAME IS CHECKED BEFORE THE OLD ONE IS FOUND, and the order is
     * cheap-versus-expensive: a name this node could not be given is refused
     * whether or not the old one is held, and a valid_nick() call per rename
     * costs nothing next to a rejected rename's later consequences. It is checked
     * against the SAME predicate 2.1 uses for a client's NICK, so a rename on the
     * wire cannot put a name on a mesh that a local client would have been
     * refused. */
    if (!valid_nick(new_nick)) {
        return -1;
    }
    if (irc_ascii_same(old_nick, new_nick)) {
        /* A rename TO THE SAME NAME is a no-op, and returning 0 for it rather
         * than 1 is what stops a caller from reporting a roster change it did not
         * make. Both names folding equal is the case worth handling, not the byte
         * -equal one: `Bob` and `bob` are the same nickname to 2.1 and a peer
         * that sends both is not asking for a rename. */
        return 0;
    }
    for (i = 0; i < s->nrnicks; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !irc_ascii_same(s->rnicks[i].nick, new_nick)) {
            continue;
        }
        if (!irc_ascii_same(s->rnicks[i].server, server)) {
            /* HELD BY A DIFFERENT SERVER, and that is NOT a collision: 2.1's
             * duplicate is legal and is resolved by the rename policy, not by
             * refusing the rename. Refusing here would leave the two users
             * holding one name for ever, which is the state the policy exists to
             * end. */
            continue;
        }
        /* HELD BY THE SAME SERVER, which means the server has two of its own
         * users answering to the new name -- impossible in reality and a wire
         * fault if reported, and refused rather than merged because merging would
         * make one of two live users unreachable. */
        return -1;
    }
    for (i = 0; i < s->nrnicks; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !irc_ascii_same(s->rnicks[i].nick, old_nick)) {
            continue;
        }
        if (!irc_ascii_same(s->rnicks[i].server, server)) {
            continue;
        }
        at = i;
        break;
    }
    if (at == s->nrnicks) {
        return 0;
    }

    /* THE BOUNDED COPY, through the same helper learn() uses, so a rename cannot
     * produce an entry learn() would have refused -- two entry-creation paths with
     * different bounds is how a table ends up holding a truncated name that no
     * lookup can match. */
    if (!bounded_copy(s->rnicks[at].nick, sizeof s->rnicks[at].nick, new_nick)) {
        return -1;
    }
    /* THE STAMP MOVES, and the reason is that the most recent fact about this
     * user is now their new name. What does NOT move is `signon`, and the reason
     * is the opposite: a rename is not a reconnection, and a node that gave a
     * renamed user a fresh signon time would make every channel the user is in
     * believe the channel's age restarted, which is what SBURSTM's flags and
     * 2.2's mode timestamps are derived from. */
    s->rnicks[at].seen_ms = now_ms;

    /* TO THE LRU HEAD, because eviction is tail-driven and an entry left where
     * it was would be evicted next despite having just been confirmed. The
     * fields are not rebuilt -- in particular `user` and `host` are carried
     * through unchanged, which is the point of a rename over a re-learn. */
    nickreg_touch(s, &s->rnicks[at]);
    return 1;
}

/* fed_nickreg_resolve_local() -- nickreg.h states the five effects and the three
 * call sites, and what follows is the order they have to happen in. The order is
 * the whole of the correctness argument, so each step says what it is for. */
int fed_nickreg_resolve_local(server_t *s, const char *nick, uint64_t now_ms)
{
    char holder[IRC_MAX_SERVER_NAME + 1];
    char fresh[IRC_MAX_NICK + 1];
    char oldnick[IRC_MAX_NICK + 1];
    conn_t *c;

    if (s == NULL || nick == NULL || nick[0] == '\0' || !valid_nick(nick)) {
        return 0;
    }
    /* THE WINNING REMOTE HOLDER, and it is a SCAN rather than
     * fed_nickreg_holder(). The two ask different questions: holder() is the
     * FORWARDING answer -- "some server that has this nick", where either of two
     * holders is correct and the first one found is as good as the other -- while
     * the policy needs the BEST of the remote holders, because a total order
     * applied to an arbitrary competitor is not the order. With two remote
     * claimants, deciding against whichever the table happened to list first
     * would rename a user on the strength of a competitor that lost, and would
     * decide differently on a node whose table was built in a different order.
     *
     * THE SCAN IS OVER s->rnicks AND NOT fed_nickreg_holder()'s helper, and it is
     * a handful of comparisons against a 256-entry bound: the alternative is an
     * index from nickname to holders, which is a second map to keep in step with
     * this one. */
    {
        int have = 0;

        for (size_t i = 0; i < s->nrnicks; i++) {
            const struct fed_rnick *e = &s->rnicks[i];

            if (e->nick[0] == '\0' || !irc_ascii_same(e->nick, nick)) {
                continue;
            }
            if (e->server[0] == '\0' || chan_same_name(e->server, s->name)) {
                /* This node's own claim, or an entry whose holder was never told
                 * (4.3's SJOIN carries no server field). Neither is a competitor:
                 * an entry with no holder cannot outrank a name, because there is
                 * no name to compare. */
                continue;
            }
            if (!have || fed_nickreg_local_loses(holder, e->server) != 0) {
                /* e->server is the smaller of the two, so it is the new winner. */
                (void)bounded_copy(holder, sizeof holder, e->server);
                have = 1;
            }
        }
        if (!have) {
            return 0;
        }
    }
    /* THE LOCAL HOLDER IS FOUND BEFORE THE VERDICT IS REACHED, and the order is
     * what keeps the report below meaningful. server_nick_lookup() is the
     * authority for a name this node holds, because server_t::nicks is
     * per-SERVER and this table holds only REMOTE nicks -- so a name this node has
     * no user for is not a duplicate here, it is a user on somebody else's mesh
     * that this function has nothing to decide about.
     *
     * Asking first means the LOCAL_WINS report below fires only for a name a local
     * user actually holds, and a node on a healthy mesh never prints it. The
     * alternative -- deciding first and reporting, then discovering there is no
     * local user -- prints a line for every remote nickname the node has ever
     * heard of, which is a log nobody reads and a report that means nothing. */
    c = server_nick_lookup(s, nick);
    if (c == NULL) {
        /* A REMOTE duplicate this node has no local user for, which is the HALF
         * of the pair that does nothing here: the other node runs this same
         * function against the same two names and renames its own user if it is
         * the loser there. That is the convergence fed_nickreg_local_loses()
         * exists to make possible, and it is why this branch reports nothing --
         * there is no finding, and a line printed on every remote-only duplicate
         * would make the report above unreadable. */
        return 0;
    }
    if (fed_nickreg_local_loses(s->name, holder) == 0) {
        /* THIS NODE WINS, and the fact is REPORTED rather than silently kept, so an
         * operator reading one side's log can see that a duplicate existed and that
         * THIS side was the one told to keep it. Without it "nobody was renamed
         * here" and "every node agreed nobody should be" are the same observation,
         * and a mesh that had resolved the duplicate by BOTH sides renaming would
         * look identical from the renamed side alone.
         *
         * IT IS A LINE AND NOT A COUNTER, and the reason is frequency: this fires
         * only when a local user holds a name a peer also holds, which is a rare
         * and fully-resolved event. A counter an operator has to look up the
         * meaning of is worse than a line nobody has to look for. */
        printf("[observable] nick_duplicate: nick=%s local=%s remote=%s "
               "verdict=LOCAL_WINS\n",
               nick, s->name, holder);
        return 0;
    }
    if (fed_nickreg_next_name(s, nick, fresh, sizeof fresh) != 0) {
        /* EVERY CANDIDATE WAS TAKEN, which is no longer a duplicate-nick problem
         * but an exhausted suffix space. The name is RELEASED rather than kept,
         * because keeping it is exactly the divergence the policy exists to
         * prevent: two servers, one name, no agreement. The user is not
         * disconnected: 2.1 is about which of two users gives way, and dropping
         * the connection would invent a policy about session lifetime that
         * nothing here decided. A released name is what lets the client's next
         * NICK succeed, which is the only recovery a client has. */
        server_nick_release(s, nick);
        (void)reply(s, c, "433", (const char *const[]){ nick }, 1,
                    "Nickname is already in use");
        printf("[observable] nick_reject: fd=%d nick=%s reason=remote_holder "
               "holder=%s detail=NO_FREE_CANDIDATE\n",
               c->fd, nick, holder);
        return 0;
    }

    /* CLAIM BEFORE RELEASE, and this is the order issue #100 established for the
     * local claim path: releasing first leaves a window in which the old name is
     * unowned, and a second client on this node could take it and become a third
     * holder of a name two servers already disagree about. */
    (void)server_nick_claim(s, fresh, c);
    server_nick_release(s, nick);
    /* THE OLD NAME IS COPIED BEFORE c->nick IS OVERWRITTEN, and all four later
     * steps need it: the NICK the client reads, the NICK each channel member
     * reads, the SNICK's two parameters, and the hostmask the peers log. It is
     * copied rather than read from c->nick for the same reason the registry is
     * asked rather than trusted -- `nick` and `c->nick` are the same string
     * folded, and a caller that passed `Bob` must not produce a line that names
     * the client's own spelling. */
    (void)bounded_copy(oldnick, sizeof oldnick, nick);
    memcpy(c->nick, fresh, strlen(fresh) + 1u);

    /* 1. THE CLIENT, through send_line() and not a fanout: there is exactly one
     * addressee, and 3 makes the reply path the single place that decides where
     * an outbound client message may be written. The prefix is this node's own
     * name rather than the user's old hostmask -- 3.3.1's prefix exists so a
     * receiver can ATTRIBUTE the line, and the receiver here is a connection this
     * node already attributes -- and the observable is the same shape a
     * client-issued rename produces, which is worth more to a reader than the
     * extra bytes. */
    (void)send_line(s, c, NULL, "NICK", (const char *const[]){ fresh }, 1);

    /* 2. THE CHANNELS, through the resolve-then-deliver pair every channel state
     * change already uses, so a rename reaches a channel's clients by the one path
     * that knows how to address them and which of them to skip.
     *
     * IT IS THE LOCAL-ONLY DELIVER and not fanout_deliver(), and the reason is the
     * one fanout.h gives: the mesh is told ONCE, by the single SNICK below, and a
     * per-channel forward would make the number of lines a peer receives a function
     * of how many channels the user happens to be in. */
    if (c->nchans > 0u) {
        for (size_t ci = 0, nch = server_chan_count(s); ci < nch; ci++) {
            chan_t *ch = server_chan_at(s, ci);
            fanout_target_t ct;

            if (ch == NULL || chan_find_member(ch, c) == NULL) {
                continue;
            }
            if (fanout_resolve(s, c, ch->name, FANOUT_STATE_CHANGE, &ct) != 0) {
                (void)fanout_deliver_local(s, &ct, oldnick, "NICK",
                                           (const char *const[]){ fresh }, 1, NULL);
            }
        }
    }

    /* 3. THE MESH, ONCE for the whole node rather than once per channel. A rename
     * is one fact about one user, and a peer receiving it once per shared channel
     * would apply it once per line and count N renames for one user.
     *
     * THE PREFIX IS A HOSTMASK and that is the one thing SNICK needs which the
     * local lines above do not: fed_in_snick() ignores the prefix on receipt -- so
     * a relaying node cannot misattribute the member, which is what 4.3.1's
     * SBURSTM <server> field exists to prevent -- and a hostmask is what a human
     * reading the far side's log has to work with. It is built HERE rather than by
     * conn_hostmask() because that function's only subject is a conn_t and
     * c->nick has already been overwritten; asking it would render the NEW name
     * and produce a line that renames a user from a name its own prefix does not
     * have. The "-" and "*" fallbacks are burst.c's, for the same reason: an
     * unregistered connection has no user and a client may have no host, and
     * 3.2's dash placeholder is what keeps a hostmask with an empty field
     * representable. */
    {
        char mask[CONN_HOSTMASK_MAX];
        const char *nickparams[2];
        const char *user = (c->user[0] != '\0') ? c->user : "-";
        const char *host = (c->host[0] != '\0') ? c->host : "*";

        (void)snprintf(mask, sizeof mask, "%s!%s@%s", oldnick, user, host);
        nickparams[0] = oldnick;
        nickparams[1] = fresh;
        fed_forward_all(s, "SNICK", mask, nickparams, 2);
    }

    (void)now_ms;
    printf("[observable] nick_renamed: fd=%d from=%s to=%s reason=REMOTE_HOLDER "
           "holder=%s\n",
           c->fd, oldnick, fresh, holder);
    return 1;
}

void fed_nickreg_purge_server(server_t *s, const char *server)
{
    size_t i;

    if (s == NULL || s->rnicks == NULL || server == NULL) {
        return;
    }
    /* No compaction and no index repair: entries never move, so removal only
     * unlinks and zeroes -- which also retires purge's wraparound `i--`, whose
     * correctness depended on the shift it compensated for. */
    for (i = 0; i < s->nrnicks; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !irc_ascii_same(s->rnicks[i].server, server)) {
            continue;
        }
        nickreg_lru_unlink(s, &s->rnicks[i]);
        memset(&s->rnicks[i], 0, sizeof s->rnicks[0]);
        s->nrnick_used--;
    }
}

size_t fed_nickreg_sweep(server_t *s, uint64_t now_ms)
{
    size_t i;
    size_t dropped = 0;
    uint64_t last = 0;

    if (s == NULL || s->rnicks == NULL) {
        return 0;
    }
    /* The throttle, and it is a comparison on a path that runs EVERY TICK: a node
     * with peers pays one subtraction per 50 ms for a store whose entries live
     * for minutes. 0 means "never swept", which is also the state of a node that
     * has just learned its first nick, so the first sweep is immediate. */
    if (s->nrnick_swept_ms != 0u &&
        (now_ms - s->nrnick_swept_ms) < IRC_FED_RNICK_SWEEP_MS) {
        return 0;
    }
    s->nrnick_swept_ms = now_ms;
    /* A FULL SCAN, unlinking the expired: the vector is no longer ordered by
     * recency, so the suffix walk's early break would be wrong. A sweep runs at
     * most every TTL/16 and unlinks rather than shifting, so examining all of
     * the table costs a walk, not a copy. */
    for (i = 0; i < s->nrnicks; i++) {
        struct fed_rnick *e = &s->rnicks[i];

        if (e->nick[0] == '\0') {
            continue;
        }
        if ((now_ms - e->seen_ms) < IRC_FED_RNICK_TTL_MS) {
            continue;
        }
        if (dropped == 0u || e->seen_ms < last) {
            last = e->seen_ms;
        }
        nickreg_lru_unlink(s, e);
        memset(e, 0, sizeof *e);
        dropped++;
    }
    if (dropped == 0u) {
        return 0;
    }
    s->nrnick_used -= dropped;
    printf("[observable] fed_nick_swept: dropped=%zu ttl_ms=%llu oldest_ms=%llu "
           "left=%zu\n",
           dropped, (unsigned long long)IRC_FED_RNICK_TTL_MS,
           (unsigned long long)last, s->nrnick_used);
    return dropped;
}

size_t fed_nickreg_count(const server_t *s)
{
    if (s == NULL) {
        return 0;
    }
    return s->nrnick_used;
}

void fed_nickreg_close(server_t *s)
{
    size_t held;

    if (s == NULL) {
        return;
    }
    held = s->nrnick_used;
    free(s->rnicks);
    s->rnicks = NULL;
    s->nrnick_lru_head = NULL;
    s->nrnick_lru_tail = NULL;
    s->nrnick_used = 0;
    s->nrnick_swept_ms = 0;
    /* WHETHER IT HELD ANYTHING, which is the fact a reader of a node's last line
     * wants and the fact a test can assert on a platform whose LSan cannot check
     * it. Same contract as fed_burst_close(). */
    printf("[observable] fed_nick_close: entries=%s held=%zu\n",
           (held > 0u) ? "OPEN" : "NONE", held);
}

const char *fed_nickreg_holder(const server_t *s, const char *nick, char *out,
                               size_t cap, int *ambiguous_out)
{
    const struct fed_rnick *e;
    int found = 0;

    if (ambiguous_out != NULL) {
        *ambiguous_out = 0;
    }
    if (out != NULL && cap > 0u) {
        out[0] = '\0';
    }
    if (s == NULL || s->rnicks == NULL || nick == NULL || out == NULL || cap == 0u) {
        return NULL;
    }
    /* From the LRU TAIL, which is what keeps "the first holder is the answer"
     * meaning what it meant when the vector itself was LRU-ordered: the least
     * recently seen holder answers, and the flag names the rest. Still O(256). */
    for (e = s->nrnick_lru_tail; e != NULL; e = e->lru_prev) {
        if (e->nick[0] == '\0' || !irc_ascii_same(e->nick, nick)) {
            continue;
        }
        if (found == 0) {
            /* THE FIRST HOLDER IS THE ANSWER and the ambiguity flag is the rest
             * of it. Both are set in ONE pass because a second pass to count the
             * holders would double the cost of a call on the resolution path for
             * an answer most callers do not need -- and the flag is what the
             * rename policy asks for, so it is cheaper to compute it than to
             * leave it out and have a caller walk the table itself. */
            if (bounded_copy(out, cap, e->server) == 0) {
                return NULL;
            }
            found = 1;
        } else if (!irc_ascii_same(out, e->server)) {
            if (ambiguous_out != NULL) {
                *ambiguous_out = 1;
            }
            /* Deliberately NOT replacing `out`: the first holder stays the
             * answer for a FORWARDER, and the ambiguity flag is what a caller that
             * needs to resolve the duplicate asks about. Choosing the lexicographic
             * winner here instead would mean a router silently preferring one of
             * two users by an accident of table order. */
        }
    }
    return (found != 0) ? out : NULL;
}

const char *fed_nickreg_render(const server_t *s, const char *nick,
                               const char *server, char *out, size_t cap)
{
    const struct fed_rnick *e;
    size_t n = 0;
    int wrote;

    if (out == NULL || cap == 0u) {
        return NULL;
    }
    out[0] = '\0';
    if (s == NULL || nick == NULL) {
        return NULL;
    }
    e = nickreg_find((server_t *)(uintptr_t)(const void *)s, nick, server);
    if (e == NULL) {
        return NULL;
    }
    /* THE SHAPE IS 2.1's: nick!user@host. It is the only rendering a remote user
     * can be given, and it is assembled by hand rather than through
     * conn_hostmask() because that function takes a conn_t and a remote user has
     * none -- which is the whole reason this function exists. A missing user or
     * host renders as the empty component rather than being refused, because 2.2
     * says an empty host is the NORMAL state for a member learned from a live
     * SJOIN and a renderer that refused would leave the most common entry in the
     * table unrenderable. */
    wrote = snprintf(out, cap, "%s!%s@%s", e->nick, e->user, e->host);
    if (wrote < 0 || (size_t)wrote >= cap) {
        out[0] = '\0';
        return NULL;
    }
    n = (size_t)wrote;
    return (n > 0u) ? out : NULL;
}

int fed_nickreg_local_loses(const char *local, const char *remote)
{
    size_t i;

    if (local == NULL || remote == NULL) {
        return 0;
    }
    /* A REMOTE HOLDER WITH NO NAME cannot win, and the answer is that the local
     * holder keeps the nick. 4.3's SJOIN carries no server field, so an entry
     * learned from one has an empty holder; treating that as a competing claim
     * would let a peer rename a user by sending an SJOIN with no server at all,
     * which is a capability no message in 4.3 is supposed to carry. */
    if (remote[0] == '\0') {
        return 0;
    }
    for (i = 0;; i++) {
        char a = irc_ascii_fold((local[i] != '\0') ? local[i] : ' ');

        if (local[i] == '\0') {
            /* LOCAL IS A STRICT PREFIX OF REMOTE, so local is the SMALLER name and
             * the rule this function states -- the greater name is renamed -- says
             * the local holder KEEPS it. Returning 1 here would be the opposite of
             * what the one-character-lower loop does for the same pair: for
             * `local = "irc.b"`, `remote = "irc.b1"` the first differing byte says
             * local is smaller and keeps it, so a shorter local name has to keep it
             * too or the order is not a total order and two nodes can disagree
             * about a pair whose names differ only in length.
             *
             * The space is a sentinel that folds above every legal name byte and
             * cannot be confused with a shorter string, which is what makes this
             * loop safe at the terminator. */
            return 0;
        }
        if (remote[i] == '\0') {
            /* Remote is a strict prefix of local, so local is the GREATER name and
             * is renamed -- the mirror of the arm above, and for the same reason:
             * without it `irc.b1` and `irc.b` would resolve the opposite way
             * depending on which is longer, which is precisely the non-convergence
             * this function's whole existence is meant to prevent. */
            return 1;
        }
        if (a != irc_ascii_fold(remote[i])) {
            return (a > irc_ascii_fold(remote[i])) ? 1 : 0;
        }
    }
}

int fed_nickreg_next_name(const server_t *s, const char *nick, char *out,
                          size_t cap)
{
    unsigned n;

    if (s == NULL || nick == NULL || out == NULL || cap == 0u) {
        return -1;
    }
    for (n = 1u; n <= (unsigned)IRC_FED_RNICK_SUFFIX_MAX; n++) {
        char candidate[IRC_MAX_NICK + 1];
        int wrote;
        size_t i;

        /* The candidate is built into a buffer of the nick's OWN width and the
         * LENGTH is checked rather than the suffix being dropped, because 2.1
         * says a nickname is IRC_MAX_NICK bytes and a node that stored a longer
         * one could not render it in a hostmask -- the same reason
         * conn_hostmask() sizes its buffer from the struct widths. */
        wrote = snprintf(candidate, sizeof candidate, "%s%.*s", nick, (int)n,
                         "________________");
        if (wrote < 0 || (size_t)wrote >= sizeof candidate) {
            return -1; /* no room even for one suffix: the nick is at the bound */
        }
        /* AND EVERY CANDIDATE IS CHECKED AGAINST THE LOCAL REGISTRY, because a
         * rename that lands on a name somebody else already holds is not a
         * rename, it is a third collision. The caller re-runs
         * fed_nickreg_local_loses() on whatever this returns, which is the
         * check against a REMOTE holder -- this one is against a local one and
         * the two are different tables. */
        for (i = 0; i < s->nrnicks; i++) {
            if (s->rnicks[i].nick[0] != '\0' && irc_ascii_same(s->rnicks[i].nick, candidate)) {
                break;
            }
        }
        if (i < s->nrnicks) {
            continue;
        }
        /* The LOCAL nick registry is the other thing a candidate can collide
         * with, and it is server_nick_lookup() rather than a walk of this table:
         * a local nickname is held by a conn_t and lives in server_t::nicks, which
         * is the authority for it. A candidate that a local user already holds is
         * not available, and finding that out by asking the registry this file
         * owns would be asking the wrong question. */
        if (server_nick_lookup(s, candidate) != NULL) {
            continue;
        }
        if (bounded_copy(out, cap, candidate) == 0) {
            return -1;
        }
        return 0;
    }
    return -1;
}
