/* advertise.c -- what a peer ADVERTISEs about itself, and the store it lands in,
 * split out of federation/verbs.c (issue #543). Verbatim move; the store
 * readers are declared in federation/link.h. */
#include "federation/verbs.h"
#include "federation/link.h"

#include <stdlib.h>
#include <string.h>

/* Does this node ALREADY hold a link to the server called `name`? The
 * collision check needs exactly this question and nothing more, so it walks the
 * link vector here rather than going through a lookup nobody else wants: a
 * by-name accessor on server_t::links would be a general-purpose API whose only
 * caller is one collision check, and the lesson 2.1 teaches about the nickname
 * registry is that a second place to ask "do we already know this name" is a
 * second place for the answer to be wrong.
 *
 * CONFIGURED OR ESTABLISHED, BOTH, and the reason is what a collision IS: a link
 * this node has been told about and a link this node has finished handshaking
 * with are both a claim on the name, and a name is unique per MESH (2.3) rather
 * than per socket. So the check is against the link vector and not against the
 * FSM state, and a peer that advertises a name this node is still dialling is
 * reported as a collision -- which is exactly when an operator wants to hear
 * about it, because that is the moment the refusal is coming. */
static int advert_name_is_held(const server_t *s, const char *name)
{
    if (s == NULL || name == NULL) {
        return 0;
    }
    for (size_t i = 0; i < server_link_count(s); i++) {
        if (chan_same_name(server_link_at(s, i)->name, name)) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * What a peer ADVERTISES about itself, and the store it lands in
 * ---------------------------------------------------------------------------
 *
 * ONE ENTRY PER ADVERTISING PEER, refreshed in place, bounded by
 * IRC_FED_MAX_ADVERTISED. The bound is the number of peers a node can be
 * configured with (IRC_FED_MAX_PEERS), which is what makes it the RIGHT bound
 * rather than an arbitrary one: this node cannot be advertised to by more servers
 * than it has links, so the table cannot grow past its own peer set and an
 * advertisement from a stranger has nowhere to go. The store is allocated at its
 * FULL bound on first use rather than grown, for the reason every other flat
 * table in this node is (see fed_nickreg.c), and freed by fed_advert_close().
 *
 * EVERY FIELD IS COPIED THROUGH A BOUNDED COPY, and the host is a name and not an
 * address struct, which is deliberate: the wire carries a hostname and a port
 * because that is what an operator can configure and what a human can read in a
 * log. Storing an address here would be storing something the dial path could
 * be tempted by, and the whole argument in server.h is that the temptation
 * should not exist. */
struct fed_advert {
    char     peer[IRC_MAX_SERVER_NAME + 1];  /* the LINK this came over */
    char     name[IRC_MAX_SERVER_NAME + 1];  /* the name it advertises */
    char     host[CONN_HOST_MAX + 1];        /* the dial hint it advertises */
    unsigned port;
    unsigned load_pct;
    uint64_t seen_ms;
};

static struct fed_advert *advert_table(server_t *s)
{
    if (s->advs == NULL) {
        s->advs = (struct fed_advert *)calloc(IRC_FED_MAX_ADVERTISED,
                                              sizeof *s->advs);
        if (s->advs == NULL) {
            /* A node that cannot record cannot report, and saying so is better
             * than a store that silently did not record: an operator looking at
             * `advert_known=0` on a mesh that is advertising would otherwise have
             * no way to tell a quiet node from a broken one. */
            fed_obs("[observable] fed_advert_alloc_failed\n");
            return NULL;
        }
    }
    return s->advs;
}


/* ADVERTISE <load%> [<name> <host> <port>].
 *
 * A PAYLOAD, AND NOT A BARE LIVENESS PING, and the reason is that a bare one
 * would be a second liveness signal that can disagree with the first.
 * federation/link.c's T4 already decides a link is dead from the link's own
 * silence, and it is the only thing that should: it is on a timer, it has a
 * threshold, and its counter is one an operator watches. A peer that sent a bare
 * ADVERTISE as a heartbeat would be asserting liveness on a schedule neither
 * side agreed, and a node receiving one would have to decide whether to believe
 * it -- and the answer would be "no, because T4 exists", which makes the verb
 * pointless.
 *
 * SO ADVERTISE IS FOR PROPAGATION OF STATE THE LINK DOES NOT OTHERWISE CARRY,
 * and the state a single node has is how loaded it is. The load percentage is
 * therefore REQUIRED rather than optional: an ADVERTISE with no payload would be
 * a heartbeat, and this is not a heartbeat. It is also the only number this node
 * puts on the wire about itself, and it comes from fed_set_load() -- an operator's
 * value, not a measurement, because this node has no load metric and a fabricated
 * 0% would be a number it does not believe.
 *
 * THE SECOND HALF IS THE DIAL HINT, and it is OPTIONAL because a peer may not
 * want to publish where it is. It is recorded, reported and NEVER DIalled, and
 * server.h says at length why that is a security property and what a future
 * reader would have to write down before changing it. The one thing this node
 * DOES do with it is the collision check below, which is a use that cannot
 * connect to anything.
 *
 * VALIDATION, and each refusal is a distinct one because they have distinct
 * fixes: the load must parse as a number in 0..100; a hint is either absent or
 * exactly three parameters; the name must satisfy 2.4's server-name grammar (the
 * same rule fed_on_federate() applies, so an advertisement cannot claim a name
 * this node would refuse to link to); the host must be non-empty and printable
 * (a hostname, not a URL, not a sockaddr -- 3.4 resolves names to addresses ONCE
 * at startup and never inside the event loop, and this store is not a resolver);
 * and the port must be 1..65535. A refused ADVERTISE does NOT tear the link down:
 * a peer running a build with a different shape for this verb is a version fact,
 * and the same reasoning fed_in_smodes() applies when a line it cannot use
 * arrives. */
void fed_in_advertise(server_t *s, server_link_t *link, const char *prefix,
                     const irc_serve_tags_t *tags,
                     const char *const *params, int nparams)
{
    struct fed_advert *table;
    struct fed_advert *slot = NULL;
    char loadbuf[16];
    unsigned long load = 0u;
    int hinted = 0;

    (void)prefix;
    (void)tags;

    /* ARITY: one parameter, or four. Not two and not three, because a partial
     * hint is not a hint -- a name with no address, or an address with no port,
     * is a fragment that would have to be interpreted, and this node's rule is
     * that it does not interpret fragments of a wire format it invented. */
    if (nparams != 1 && nparams != 4) {
        s->n_fed_advertise_bad++;
        fed_obs("[observable] fed_advertise_refused: peer=%s reason=ARITY "
               "nparams=%d\n",
               link->name, nparams);
        return;
    }
    if (strlen(params[0]) >= sizeof loadbuf) {
        s->n_fed_advertise_bad++;
        fed_obs("[observable] fed_advertise_refused: peer=%s reason=LOAD_LONG\n",
               link->name);
        return;
    }
    (void)bounded_copy(loadbuf, sizeof loadbuf, params[0]);
    /* A STRICT PARSE, and the reason is the same one 4.3's terminator counts
     * have: a field that "looks like" a number and is not would be stored as
     * whatever the parser salvaged, and a load of 50 from "50abc" is a number
     * this node reported that the peer never sent. */
    for (const char *c = loadbuf; *c != '\0'; c++) {
        if (*c < '0' || *c > '9') {
            s->n_fed_advertise_bad++;
            /* MEASURED FROM params[0], NOT FROM loadbuf, and the difference is the
             * point: `loadbuf` is a 16-byte COPY of the peer's field, so a peer that
             * sent 200 characters has 15 of them in loadbuf and 200 in params[0].
             * Reporting `value_len=` from loadbuf would say 15 for an input of 200 --
             * a measurement that is wrong precisely when the input is interesting.
             * The value PRINTED is loadbuf, which is the copy, and the value
             * MEASURED is what the peer sent. */
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=LOAD_NOT_NUML "
                   "value=%s value_len=%zu value_bad_bytes=%zu\n",
                   link->name, loadbuf, strlen(params[0]),
                   conn_text_bad_count(params[0]));
            return;
        }
        load = (load * 10u) + (unsigned long)(*c - '0');
        if (load > 100u) {
            s->n_fed_advertise_bad++;
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=LOAD_RANGE "
                   "value=%s value_len=%zu value_bad_bytes=%zu\n",
                   link->name, loadbuf, strlen(params[0]),
                   conn_text_bad_count(params[0]));
            return;
        }
    }
    if (loadbuf[0] == '\0') {
        s->n_fed_advertise_bad++;
        fed_obs("[observable] fed_advertise_refused: peer=%s reason=LOAD_EMPTY\n",
               link->name);
        return;
    }
    if (nparams == 4) {
        unsigned long port = 0u;
        int digits = 0;

        hinted = 1;
        if (!irc_serve_server_name_valid(params[1])) {
            s->n_fed_advertise_bad++;
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=NAME_INVALID "
                   "name=%s name_len=%zu name_bad_bytes=%zu\n",
                   link->name, params[1], strlen(params[1]), conn_text_bad_count(params[1]));
            return;
        }
        if (params[2][0] == '\0' || strlen(params[2]) >= CONN_HOST_MAX + 1u) {
            s->n_fed_advertise_bad++;
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=HOST_INVALID\n",
                   link->name);
            return;
        }
        for (const char *c = params[2]; *c != '\0'; c++) {
            if (*c <= 0x20 || (unsigned char)*c >= 0x7fu) {
                /* PRINTABLE AND NOT A SEPARATOR, and the reason is that this
                 * field is a HOSTNAME in a log: a value containing a space, a
                 * colon or a control byte would render a line a reader
                 * misparses, and 3.2's rule about parameters that cannot be
                 * represented is the same rule about text that cannot be read
                 * safely. It is NOT a hostname syntax check: 3.4 resolves names
                 * once at startup, and this store never resolves anything. */
                s->n_fed_advertise_bad++;
                fed_obs("[observable] fed_advertise_refused: peer=%s "
                       "reason=HOST_UNPRINTABLE\n",
                       link->name);
                return;
            }
        }
        for (const char *c = params[3]; *c != '\0'; c++) {
            if (*c < '0' || *c > '9') {
                s->n_fed_advertise_bad++;
                fed_obs("[observable] fed_advertise_refused: peer=%s reason=PORT_NOT_NUML "
                       "value=%s value_len=%zu value_bad_bytes=%zu\n",
                       link->name, params[3], strlen(params[3]), conn_text_bad_count(params[3]));
                return;
            }
            port = (port * 10u) + (unsigned long)(*c - '0');
            digits++;
        }
        if (digits == 0 || port == 0u || port > 65535u) {
            s->n_fed_advertise_bad++;
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=PORT_RANGE "
                   "value=%s value_len=%zu value_bad_bytes=%zu\n",
                   link->name, params[3], strlen(params[3]), conn_text_bad_count(params[3]));
            return;
        }
    }
    table = advert_table(s);
    if (table == NULL) {
        return;
    }
    /* REFRESH IN PLACE, keyed on the LINK and not on the advertised name, and the
     * reason is that the link is the only thing this node can vouch for. A store
     * keyed on the advertised name would let a peer overwrite another peer's
     * entry, and the two are exactly the entries an operator would be comparing.
     * A peer that advertises a DIFFERENT name than its link is not an error --
     * a relay is a legitimate thing to be -- so the record is allowed to disagree
     * with its own key and the line below says so. */
    for (size_t i = 0; i < s->nadv; i++) {
        if (chan_same_name(table[i].peer, link->name)) {
            slot = &table[i];
            break;
        }
    }
    if (slot == NULL) {
        if (s->nadv >= IRC_FED_MAX_ADVERTISED) {
            /* Unreachable given the bound is IRC_FED_MAX_PEERS and the link came
             * from one of this node's peers, and it is handled rather than
             * asserted because a table that dropped an advertisement because it
             * was full would be a store that reports a smaller mesh than it has. */
            s->n_fed_advertise_bad++;
            fed_obs("[observable] fed_advertise_refused: peer=%s reason=STORE_FULL "
                   "bound=%zu\n",
                   link->name, IRC_FED_MAX_ADVERTISED);
            return;
        }
        slot = &table[s->nadv];
        memset(slot, 0, sizeof *slot);
        s->nadv++;
    } else {
        memset(slot, 0, sizeof *slot);
    }
    (void)bounded_copy(slot->peer, sizeof slot->peer, link->name);
    (void)bounded_copy(slot->name, sizeof slot->name, hinted ? params[1] : "");
    (void)bounded_copy(slot->host, sizeof slot->host, hinted ? params[2] : "");
    if (hinted != 0) {
        unsigned long port = 0u;

        for (const char *c = params[3]; *c != '\0'; c++) {
            port = (port * 10u) + (unsigned long)(*c - '0');
        }
        slot->port = (unsigned)port;
    }
    slot->load_pct = (unsigned)load;
    slot->seen_ms = server_now_ms();
    s->n_fed_advertise++;
    /* AND THE ROUTING COPY, which is the propagation half's whole payload. This is
     * the second writer of server_link_t::load_seen and the only one -- server.h
     * says why the figure is held in two places (the store is observational, the
     * field is what T8's policy reads), and it is written HERE rather than in the
     * tick so that the store and the field cannot disagree: they are two halves of
     * one statement sequence.
     *
     * THE EDGE LATCH IS CLEARED HERE AND ONLY HERE, when the figure arrives BELOW
     * the threshold, so a peer that sheds, recovers and sheds again is reported
     * twice. It is deliberately NOT cleared when the figure merely refreshes at the
     * same level: that is what makes the tick report a crossing rather than a
     * state, and without it a busy peer would print one line per POLL_TICK_MS for
     * the life of the link. The threshold of 0 means "no opinion" and the
     * comparison below it is false for every figure, so an unset shed_pct neither
     * reports nor latches -- a node with no threshold is not a node silently
     * suppressing reports it would otherwise make. */
    if (s->shed_pct == 0u || (unsigned)load < s->shed_pct) {
        link->shed_reported = 0;
    }
    link->load_seen = (unsigned)load;
    link->load_seen_ok = 1;

    /* THE COLLISION CHECK, and it is one of the three things this store is allowed
     * to be used for (server.h lists them). 2.3 makes two nodes with one name
     * "catastrophic and undetectable later", and the handshake refuses the second
     * -- so an advertisement is the CHEAPEST place to notice, because the node
     * that advertises a name this node already holds is a node about to be
     * refused, and an operator who learns that from this counter learns it before
     * the refusal rather than after.
     *
     * IT COMPARES BOTH WAYS AND DOES NOT CALL IT A COLLISION WHEN THE NAME IS
     * THIS NODE'S OWN, because that is not a collision -- it is a peer telling
     * this node its own name, which is what a peer does. It is reported anyway,
     * on its own line, because a peer whose link name and advertised name differ
     * is a relay and an operator may want to know. */
    if (hinted != 0) {
        if (chan_same_name(slot->name, s->name)) {
            fed_obs("[observable] fed_advertise: peer=%s name=%s host=%s port=%u "
                   "load=%u%% detail=SELF_NAME name_len=%zu name_bad_bytes=%zu host_len=%zu host_bad_bytes=%zu\n",
                   link->name, slot->name, slot->host, slot->port, slot->load_pct, strlen(slot->name), conn_text_bad_count(slot->name), strlen(slot->host), conn_text_bad_count(slot->host));
        } else if (advert_name_is_held(s, slot->name)) {
            s->n_fed_advertise_collision++;
            fed_obs("[observable] fed_advertise_collision: peer=%s advertised=%s "
                   "held_by=this_node advertised_len=%zu advertised_bad_bytes=%zu\n",
                   link->name, slot->name, strlen(slot->name), conn_text_bad_count(slot->name));
        } else {
            fed_obs("[observable] fed_advertise: peer=%s name=%s host=%s port=%u "
                   "load=%u%% dialed=NO name_len=%zu name_bad_bytes=%zu host_len=%zu host_bad_bytes=%zu\n",
                   link->name, slot->name, slot->host, slot->port, slot->load_pct, strlen(slot->name), conn_text_bad_count(slot->name), strlen(slot->host), conn_text_bad_count(slot->host));
        }
    } else {
        fed_obs("[observable] fed_advertise: peer=%s load=%u%% dialed=NO\n",
               link->name, slot->load_pct);
    }
}

size_t fed_advertised_count(const server_t *s)
{
    return (s != NULL) ? s->nadv : 0u;
}

void fed_advert_close(server_t *s)
{
    if (s == NULL) {
        return;
    }
    /* THE ARM, printing whether the table was OPEN for the reason
     * server_shutdown() makes about the burst shadow: LeakSanitizer does not run
     * on Darwin, so the only local evidence that a store was released is a line a
     * test can assert on, and the Linux CI job reads the same line beside its own
     * LSan run. */
    fed_obs("[observable] fed_advert_close: table=%s known=%zu\n",
           (s->advs != NULL) ? "OPEN" : "NONE", s->nadv);
    free(s->advs);
    s->advs = NULL;
    s->nadv = 0u;
}
