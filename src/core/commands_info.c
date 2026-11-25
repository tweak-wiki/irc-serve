/* commands_info.c -- see commands_info.h. The server-info family, verbatim out
 * of commands.c; the table that calls these still lives there.
 */
#include "core/commands_info.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * 4.2's LUSERS, ADMIN and INFO -- the server-info family
 * ---------------------------------------------------------------------------
 * All three answer questions about the NODE rather than about a channel or a
 * person, and all three are RFC 2812 3.4.2/3.4.4 commands that a client sends
 * unprompted when it connects. That is why they live next to the MOTD and not in
 * chan_verbs.c or msg_verbs.c: the family a verb belongs to is decided by what
 * it asks about, and these three ask about this server.
 *
 * The three handlers are EXPOSED via commands_info.h rather than static,
 * because their only caller is the dispatch table in commands.c, which lives
 * in another TU. The helpers above them stay static: nothing outside this
 * file calls them.
 *
 * ---------------------------------------------------------------------------
 * EVERY NUMBER IN HERE IS MEASURED, AND THE ONE THAT IS NOT IS SAID SO
 * ---------------------------------------------------------------------------
 * A node that answered LUSERS with a plausible constant would be the same defect
 * as a 324 that disagrees with the node's actual modes, which Phase 4 refused to
 * ship: "a numeric that lies about what it is". So:
 *
 *   <clients>       server_nick_count(): the connections on this node holding a
 *                   nickname. A connection that has not chosen a name is not a
 *                   user of this network and is not counted, and a connection
 *                   that has sent NICK but not USER IS counted -- it is a client,
 *                   which is what the word means. The distinction is in the
 *                   comment rather than in a different counter because there is
 *                   only one counter and 3.4's single event loop has no other
 *                   place to keep a second one.
 *   <servers>       the peers this node has an ESTABLISHED link to. NOT
 *                   server_link_count(), which counts a link that exists and has
 *                   no socket -- a name and a destination, or a peer that is
 *                   still handshaking. 2.3 is explicit that a link is not
 *                   ESTABLISHED until the handshake finished, and a server count
 *                   that included a half-linked peer would overstate the mesh.
 *   <hops>          0, and 0 is TRUE: the value counts forwards, and this node
 *                   originated every count it is reporting. A node answering 1
 *                   here would be claiming a relay that did not happen -- the
 *                   same argument msg_verbs.c makes for 352's <hopcount>.
 *   <max clients>   NO CONFIGURED MAXIMUM EXISTS on this node, and the numeral
 *                   carries the next honest thing, which is the hard bound:
 *                   server.h's SERVER_FD_TABLE, which is FD_SETSIZE, because
 *                   server_t::by_fd is a flat array indexed by descriptor and the
 *                   accept site refuses an fd at or above it (3.4). A node with
 *                   more clients than that cannot exist, so it is a real ceiling
 *                   rather than a configured wish. It is deliberately a CEILING
 *                   and not a promise: the listener and every peer link occupy
 *                   slots in the same table, so the figure a client could
 *                   actually reach is lower, and nothing here claims otherwise.
 *                   No client compares against it -- 004 advertises no
 *                   MAXCLIENTS and 005 does not either, so there is nothing to
 *                   disagree with.
 *   252, 253, 254   NOT SENT, and that is a decision rather than an omission.
 *                   RFC 2812 3.4.4 lists them among LUSERS's replies because a
 *                   server MAY keep separate counters for total connections, NEW
 *                   clients, and channel-visibility groups. This node keeps
 *                   exactly one user counter and has no connection-class
 *                   configuration, so producing those three would mean splitting
 *                   one real number into three invented ones. 4.4's range is
 *                   covered by 251, 255, 265 and 266, all of which are real.
 *
 * ---------------------------------------------------------------------------
 * 402 ERR_NOSUMSERVER, AND IT IS A FIFTH HOLE IN 4.4's LIST
 * ---------------------------------------------------------------------------
 * LUSERS and ADMIN both take an optional <server> mask (3.4.2, 3.4.4). On a mesh
 * a server that is asked about another one FORWARDS the question, and 402 is the
 * numeric that says there is nowhere to forward it to. On a single node there is
 * no route, so 402 is exactly the answer -- and it is not in 4.4's error list,
 * which is a gap in the list rather than in the protocol, for the same reason
 * 301, 303, 417 and 302 are (see the note above 4.4's list and
 * msg_verbs.c's handle_userhost()). The RFC numeric is used because it is the
 * one a client understands, and the trailing text names what was actually
 * wrong. Proposed for 4.4's list; recorded in the report.
 */

/* <max clients> -- see the file-header comment for why this is the connection
 * table's bound rather than a configured maximum. SERVER_FD_TABLE rather than
 * FD_SETSIZE written out, so the numeral cannot disagree with the table it
 * describes if that table is ever resized. */
#define NODE_MAX_CLIENTS SERVER_FD_TABLE

/* Is this <server> mask naming THIS node? Case-insensitive, and the fold is
 * channel.h's rather than a strcmp(): 2.4 requires a server-name comparison to
 * be case-insensitive, and chan_same_name() is the one fold the tree exports for
 * exactly that reason -- "is this the same name" must have ONE answer, or a
 * second copy of it is a second rule to fall out of step. */
static int server_mask_is_self(const server_t *s, const char *arg)
{
    return chan_same_name(s->name, arg);
}

/* Peers with an ESTABLISHED link. The state is compared as an int, which
 * is what federation/link.c does at its other call sites, because
 * server_link_t::state holds a handshake_state_t and is only
 * ever written by fed_link_set_state(). */
static size_t established_peers(const server_t *s)
{
    size_t n = 0;

    for (size_t i = 0; i < server_link_count(s); i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->state == (int)ESTABLISHED) {
            n++;
        }
    }
    return n;
}

/* A <server> mask that is not this node. 402, naming the mask, and NO other
 * numeric: a client that asked about a server this node cannot reach has exactly
 * one thing to do about it, and answering with a 403 (the channel family's
 * "no such channel") would send it looking for a channel. */
static int refuse_foreign_server(server_t *s, conn_t *c, const char *verb,
                                 const char *arg)
{
    (void)reply(s, c, "402", (const char *const[]){ arg }, 1,
                "No such server: %s cannot reach %s", s->name, arg);
    /* `arg` is `m->params[i]` from whichever verb asked -- LUSERS, VERSION, TIME,
     * STATS, LINKS, MOTD -- so it is whatever the client put there, and this line
     * named it. Measured, like every other log-only value in this file: the 402
     * above still echoes the same string back to the client that sent it, which is
     * the right thing for a refusal and is not a hazard, because there is no second
     * reader. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, arg);
        printf("[observable] srv_query: verb=%s nick=%s server=%s server_len=%zu "
               "server_bad_bytes=%zu reason=NO_SUMSERVER\n",
               verb, c->nick, shown, strlen(arg), conn_text_bad_count(arg));
    }
    return 1;
}

/* 251, 254, 255, 265, 266. Order is the RFC's and it matters only to a human
 * reading a log; a client reads all five. */
static void send_lusers(server_t *s, conn_t *c)
{
    size_t clients = server_nick_count(s);
    size_t servers = established_peers(s);
    size_t channels = server_chan_count(s);
    /* The two numbers 265 and 266 need are carried as STRINGS because they are
     * MIDDLE parameters, and 3.2's formatter will not format a number into a
     * non-final parameter position -- it reports the message as unrepresentable
     * instead, which is a refusal on n_reply_refused, the counter reply.c calls
     * a bug report. The same dance send_topic() does for 333's timestamp. */
    char now_clients[24];
    char now_max[24];

    (void)snprintf(now_clients, sizeof now_clients, "%zu", clients);
    (void)snprintf(now_max, sizeof now_max, "%d", NODE_MAX_CLIENTS);

    (void)reply(s, c, "251", NULL, 0, "%s %d %zu %zu %d", s->name, 0, clients,
                servers, NODE_MAX_CLIENTS);
    /* ------------------------------------------------------------------------
     * 254 RPL_LUSERCHANNELS, AND IT IS THE ONE OF THE THREE OPTIONAL REFINEMENT
     * NUMERICS THAT IS NOT OPTIONAL HERE.
     * ------------------------------------------------------------------------
     * RFC 2812 5.1 defines it as "<integer> :channels formed", and 3.4.2 draws
     * the line that matters: "When replying, a server MUST send back
     * RPL_LUSERCLIENT and RPL_LUSERME. The other replies are only sent back if a
     * non-zero count is found for them." So the test is not "is this server's
     * feature set rich" -- it is "is the count zero".
     *
     *   252 RPL_LUSEROP     operators online.   This node has none: 258 says so
     *                      on the wire and CHOPER is unconditionally refused,
     *                      so the count is zero and its absence is CONFORMANT.
     *   253 RPL_LUSERUNKNOWN unknown connections. This node has none: every
     *                      accepted connection becomes either a registered
     *                      client or a peer link, and an unregistered socket is
     *                      not a category the node keeps a count of. Zero, and
     *                      so correctly absent.
     *   254 RPL_LUSERCHANNELS channels formed. NOT zero. This node creates
     *                      channels on the first JOIN and keeps them in the
     *                      registry 2.2 requires, so once anybody has joined
     *                      anything the count is positive and RFC 2812 3.4.2
     *                      requires the numeric.
     *
     * THE NUMBER IS `server_chan_count()`, WHICH IS THE SAME COUNT `LIST` WALKS,
     * and that is worth stating rather than leaving implied: a client can ask
     * LUSERS for the figure and LIST for the items and compare them, and on this
     * node the two agree because they are one counter read twice.
     *
     * SENT ONLY WHEN NON-ZERO, which is the condition RFC 2812 states rather
     * than a preference. A node with no channels emits no 254, and a client
     * reading /LUSERS output sees the same three lines it saw before this phase.
     *
     * THE COST, stated: one more line in every LUSERS answer once a channel
     * exists, which is a line-count change for any test that counts them -- and
     * test_away_notify.c's and test_batch.c's WHOIS counts are the precedent for
     * how this tree handles that. The benefit is that /LUSERS on a node with
     * channels stops omitting a figure a client displays, which is the same
     * "an away state no client can see is not an away state" argument Phase 5
     * made about 301.
     */
    if (channels > 0u) {
        char formed[24];

        (void)snprintf(formed, sizeof formed, "%zu", channels);
        (void)reply(s, c, "254", (const char *const[]){ formed }, 1, "channels formed");
    }
    (void)reply(s, c, "255", NULL, 0, "I have %zu clients and %zu servers", clients,
                servers);
    (void)reply(s, c, "265", (const char *const[]){ now_clients, now_max }, 2,
                "Current local users %s, max %s", now_clients, now_max);
    /* 266's <global> is the same number as 265's <local> on this node, and that
     * is a fact rather than a shortcut: a single node IS the whole of the
     * network it serves, so the two counts coincide until there is a second
     * node. A node that reported a larger global figure would be inventing one. */
    (void)reply(s, c, "266", (const char *const[]){ now_clients, now_max }, 2,
                "Current global users %s, max %s", now_clients, now_max);
    printf("[observable] lusers: nick=%s clients=%zu servers=%zu channels=%zu "
           "max=%d hops=0\n",
           c->nick, clients, servers, channels, NODE_MAX_CLIENTS);
}

void handle_lusers(server_t *s, conn_t *c, const message_t *m)
{
    /* Every mask must name this node. A mask that named another would be a
     * forwarding question, and refuse_foreign_server() is the honest answer on
     * a node with no route -- the alternative is answering with this node's
     * numbers for a server the client did not ask about. */
    for (int i = 0; i < m->nparams; i++) {
        if (server_mask_is_self(s, m->params[i]) == 0) {
            (void)refuse_foreign_server(s, c, "LUSERS", m->params[i]);
            return;
        }
    }
    send_lusers(s, c);
}

/* 256-259. The two RPL_ADMINLOC slots and the RPL_ADMINEMAIL slot carry FACTS
 * about this node rather than a stand-in for a person, and the honest ones are
 * the two that say there is nothing to report:
 *
 *   257  the node's own identity, which 2.1's fields really hold: its server
 *        name, the network it serves, and the version it reports in 002 and 004.
 *   258  that there is no services and no operator, which is what makes
 *        CHOPER a refusal rather than a grant. A node whose 258 said nothing
 *        about operators would be leaving a client to discover the answer by
 *        trying.
 *   259  that no administrative contact address is configured. RFC 2812 3.4.2
 *        makes 259 a contact address and there is none; putting a string that
 *        reads as an address here would be inventing a mailbox, and a client
 *        that rendered it would offer it to a human.
 */
void handle_admin(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams > 1) {
        (void)reply_refused(s, c, "ADMIN", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams == 1 && server_mask_is_self(s, m->params[0]) == 0) {
        (void)refuse_foreign_server(s, c, "ADMIN", m->params[0]);
        return;
    }
    (void)reply(s, c, "256", NULL, 0, "Administrative info");
    (void)reply(s, c, "257", NULL, 0, "Server %s on the %s network, version %s",
                s->name, NODE_NETWORK, IRC_SERVE_VERSION);
    (void)reply(s, c, "258", NULL, 0,
                "No services and no operator flags on this node: CHOPER cannot "
                "succeed.");
    (void)reply(s, c, "259", NULL, 0,
                "No administrative contact address is configured for this node.");
    printf("[observable] admin: nick=%s server=%s services=0 oper=0\n", c->nick,
           s->name);
}

/* 371 RPL_INFO, one per line, terminated by 374 RPL_ENDOFINFO.
 *
 * 371 and 374 are a SIXTH hole in 4.4's numeric list -- it has 372-376 for the
 * MOTD and 251-266 for LUSERS and ADMIN, and INFO sits in the gap between the
 * two ranges. Same class of gap as 301, 303, 417, 302 and 402: the RFC defines
 * them, 4.4 does not list them, and the RFC's is the one a client understands.
 * 375 and 376 are NOT used instead, because they are RPL_MOTDSTARTING and
 * RPL_MOTDEND and reusing them for INFO would make the MOTD's terminator lie.
 *
 * The body describes what this node IS and does NOT, and every line is a claim
 * a reader could check against the tree. A description that promised services,
 * authentication or operator support would be a lie with a numeric attached --
 * which is the standard the 324, the 432 and the 301 in this node were all held
 * to. */
static const char *const k_info[] = {
    "- " NODE_NETWORK ": a federation-native IRC node, running " IRC_SERVE_VERSION ".",
    "- client commands: the 4.1 MUST set, plus WHO WHOIS ISON LIST AWAY INVITE",
    "  MOTD LUSERS ADMIN INFO USERHOST KNOCK from 4.2. Unknown verbs are 421.",
    "- channels: JOIN PART TOPIC NAMES LIST KICK MODE, on origin-owned channels",
    "  with the single-writer rule; a state change on a channel this node cannot",
    "  route to is 437.",
    "- channel modes evaluated here: +b. 004 advertises b,k,l,imnpst and every",
    "  other letter is refused with 472 rather than silently ignored.",
    "- user modes: +i only. 004 advertises i and MODE <self> +i/-i sets it and",
    "  221 reports it; any other flag is 501, another user's modes 502.",
    "- federation: FEDERATE link handshake, the S-verb set, SBURST resync,",
    "  per-node (origin,epoch,id) dedup, hop ceiling 10.",
    "- notify locality: SETNAME/AWAY/INVITE notify local channel members only;",
    "  cross-node delivery waits on a 4.3 wire bump. 005 NOTIFYLOCAL says so too.",
    "- no authentication, no services, no operator flags: PASS is recorded and not",
    "  checked, and CHOPER is refused with 464 because there is nothing to grant.",
    "- free software under the GNU AGPL v3.0 or later; see LICENSE and NOTICE."
};

void handle_info(server_t *s, conn_t *c, const message_t *m)
{
    (void)m; /* INFO takes no parameters; RFC 2812 3.4.2 defines none */

    for (size_t i = 0; i < sizeof k_info / sizeof k_info[0]; i++) {
        (void)reply(s, c, "371", NULL, 0, "%s", k_info[i]);
    }
    (void)reply(s, c, "374", NULL, 0, "End of /INFO list");
    printf("[observable] info: nick=%s lines=%zu\n", c->nick,
           sizeof k_info / sizeof k_info[0]);
}

