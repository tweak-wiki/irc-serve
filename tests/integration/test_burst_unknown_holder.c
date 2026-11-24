/* test_burst_unknown_holder.c -- issue #277: a burst-corrected holder survives SJOIN.
 *
 * A remote learned via a live SJOIN has an unknown holder (4.3's SJOIN carries
 * no server field, so fed_in_sjoin() records the absence). A burst from a node
 * that DOES know carries the holder in SBURSTM's <server>, and install writes
 * it into the roster. The defect was the other direction: the NEXT live SJOIN
 * for the same nick re-ran chan_remote_add() with the link's name, and the
 * repeat overwrote the burst-established holder with the relay -- so every
 * burst after that re-emitted the relay as fact, nick@server resolved wrong,
 * and no later burst could repair it, because each one was clobbered again on
 * arrival.
 *
 * WHAT IS ASSERTED, ON THE WIRE: node A bursts a member record for bob whose
 * <server> is irc.c -- the holder irc.b's burst reported -- even though the
 * last thing A heard about bob was a live SJOIN over its link to irc.b. Before
 * the fix the same burst names irc.b: the SJOIN repeat clobbered the
 * correction. SBURSTE's counts are asserted against the staged records, which
 * is the agreement a sender that miscounted would break.
 *
 * WHY ONE NODE AND TWO SCRIPTED PEERS, rather than the three-node mesh the
 * issue names: the claim is about what A EMITS after a burst-install followed
 * by an SJOIN repeat, and both halves are fully determined by bytes this test
 * sends. A scripted peer playing irc.b sends a well-formed burst (naming
 * irc.c as bob's holder, as B would after learning bob directly from C) and
 * then the SJOIN repeat; a second scripted peer completes a handshake later
 * and reads A's own burst off the wire. No scheduling, no redial races, no
 * relay timing -- an establishment burst goes out once, at establishment, and
 * the second peer is only accepted once both of A's inputs have landed.
 *
 * WHAT THIS DOES NOT PROVE, stated rather than left for a reader: that a live
 * three-node mesh delivers the SJOIN repeat in the first place. That is the
 * relay's job (fanout_forward_channel_sverb, covered by the relay-shape
 * suite), and this file starts where the relay's delivery ends.
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline: nf_expect() and
 * nf_expect_nth() over the child's output, and a select() loop in
 * read_until(), the one place that owns a raw socket.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/burst.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/peer_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define NAME_P2 "irc.p2"
#define CHAN_T "#T"
#define NICK_BOB "bob"

#define BURST_EPOCH "1700000000"

/* PRE-FORK STATE. The parent fills the peer list between spawns and the child
 * that comes next reads it; see test_fed_burst.c for why a child cannot see
 * anything the parent writes after the fork. */
typedef struct {
    const char *name;
    int         port;
} peer_cfg_t;

static peer_cfg_t g_peers[4];
static size_t     g_npeers;
static int        g_trace;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

/* Runs in the CHILD, before anything may connect. */
static void child_setup(server_t *s)
{
    struct sockaddr_in addr;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    /* The shipped handshake/dial budgets (5000/5000 in the product's own
     * terms): a loaded runner slips ticks, and the product's correct answer to
     * a missed budget is a retry while this test's 15s deadline expires. */
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);
    /* p2 is accepted late, so its first dials die unanswered: redial sooner
     * than the shipped ladder, or the live attempt lands after this test's
     * deadline. Test-only seam, same as fed_set_timeouts. */
    fed_set_retry(s, 4000, 8000, 10);

    for (size_t i = 0; i < g_npeers; i++) {
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_peers[i].name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_peers[i].name, g_peers[i].port);
    }
}

static void set_peers(const peer_cfg_t *peers, size_t n)
{
    memset(g_peers, 0, sizeof g_peers);
    g_npeers = n;
    for (size_t i = 0; i < n && i < sizeof g_peers / sizeof g_peers[0]; i++) {
        g_peers[i] = peers[i];
    }
}

/* The 2.4 stamp for a line this TEST originates, rendered here rather than
 * read from the node: the point is what the node does with a stamp the node
 * did not mint. `id` differs per line so two lines are two distinct messages
 * to the dedup store rather than one being dropped as a duplicate of the
 * other. */
static void stamp(char *out, size_t cap, unsigned long id)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=" NAME_B ";irc-serve-epoch=" BURST_EPOCH
                   ";irc-serve-id=%lu;irc-serve-hops=0",
                   id);
}

/* Read from `fd` until a line containing `needle` has arrived or the deadline
 * passes. Bytes accumulate in `dst`; the match is by substring because the
 * sender's prefix and tag block are the node's, not this test's. */
static int read_until(int fd, const char *needle, char *dst, size_t cap,
                      int timeout_ms)
{
    size_t used = 0;
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;

    dst[0] = '\0';
    for (;;) {
        struct timeval tv;
        unsigned long long now = pf_now_ms();
        unsigned long long left = (deadline > now) ? deadline - now : 0ull;
        fd_set rfds;
        int rc;

        if (strstr(dst, needle) != NULL) {
            return 0;
        }
        if (left == 0ull) {
            return -1;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000ull);
        tv.tv_usec = (suseconds_t)((left % 1000ull) * 1000ull);
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            return -1;
        }
        {
            long got = pf_drain(fd, dst + used, cap - used);

            if (got <= 0) {
                return -1;
            }
            used += (size_t)got;
        }
    }
}

/* Complete the handshake AS `peer`, then read the burst node A sends at
 * establishment. Retried across accepts: dial attempts the node abandons while
 * this test was busy stay queued behind the live one, and reading EOF off one
 * of those is a stale connection, not a failure. */
static int accept_burst_peer(int listen_fd, const char *peer, char *burst,
                             size_t cap, int timeout_ms)
{
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;

    for (;;) {
        unsigned long long now = pf_now_ms();
        char reply[256];
        const char *claim[2];
        int fd;
        int left;

        if (now >= deadline) {
            return -1;
        }
        left = (int)(deadline - now);
        fd = pf_accept_deadline(listen_fd, (left < T_IO_MS) ? left : T_IO_MS);
        if (fd < 0) {
            return -1;
        }
        claim[0] = ":" NAME_A " FEDERATE " NAME_A " ";
        claim[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
        if (pf_read_until(fd, claim, 2, T_IO_MS) != 0) {
            close(fd);
            continue;
        }
        (void)snprintf(reply, sizeof reply,
                       ":%s FEDERATE %s " BURST_EPOCH " %s %s\r\n", peer, peer,
                       SECRET, IRC_SERVE_VERSION);
        if (pf_send_line(fd, reply) != 0) {
            close(fd);
            continue;
        }
        if (read_until(fd, "SBURSTE ", burst, cap, T_IO_MS) == 0) {
            close(fd);
            return 0;
        }
        close(fd);
    }
}

static size_t count_lines_with(const char *burst, const char *verb,
                               const char *nick)
{
    size_t n = 0;
    const char *p = burst;

    while ((p = strstr(p, verb)) != NULL) {
        const char *eol = strchr(p, '\n');

        if (eol == NULL) {
            eol = p + strlen(p);
        }
        if (nick == NULL || (strstr(p, nick) != NULL && strstr(p, nick) < eol)) {
            n++;
        }
        p = eol;
    }
    return n;
}

int main(void)
{
    nf_node_t a;
    peer_cfg_t a_peers[2] = { { NAME_B, 0 }, { NAME_P2, 0 } };
    int p1_listen = -1;
    int p1_fd = -1;
    int p2_listen = -1;
    int p1_port = 0;
    int p2_port = 0;
    char line[1024];
    char block[256];
    char burst[65536];
    const char *claim[2];
    const char *sb = NULL;
    const char *term = NULL;
    unsigned long long epoch = 0ull;
    unsigned long long nn = 0ull;
    unsigned long long nc = 0ull;
    unsigned long long nm = 0ull;
    size_t bob_lines = 0u;
    size_t sburst_m = 0u;

    p1_listen = pf_listen_loopback(&p1_port);
    TF_CHECK_MSG(p1_listen >= 0, "the test could not open a listening socket");
    p2_listen = pf_listen_loopback(&p2_port);
    TF_CHECK_MSG(p2_listen >= 0, "the test could not open a listening socket");

    /* A dials both. p2 is only ACCEPTED later: its establishment burst must
     * reflect everything below, and a burst goes out once, at establishment. */
    a_peers[0].port = p1_port;
    a_peers[1].port = p2_port;
    set_peers(a_peers, 2);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    /* --- peer one, playing irc.b ---------------------------------------- */
    p1_fd = pf_accept_deadline(p1_listen, T_IO_MS);
    close(p1_listen);
    TF_CHECK_MSG(p1_fd >= 0, "node A never dialled peer one: %s", a.out);

    claim[0] = ":" NAME_A " FEDERATE " NAME_A " ";
    claim[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
    TF_CHECK_MSG(pf_read_until(p1_fd, claim, 2, T_IO_MS) == 0,
                 "node A never sent a FEDERATE: %s", a.out);
    (void)snprintf(line, sizeof line,
                   ":" NAME_B " FEDERATE " NAME_B " " BURST_EPOCH " %s %s\r\n",
                   SECRET, IRC_SERVE_VERSION);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the FEDERATE reply failed");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link: %s", a.out);
    /* A's establishment burst goes out here, before it knows anything: drain
     * it so no stale byte is mistaken for the burst under test later. */
    TF_CHECK_MSG(read_until(p1_fd, "SBURSTE ", burst, sizeof burst, T_IO_MS)
                 == 0,
                 "node A never sent its establishment burst: %s", a.out);

    /* --- a live SJOIN: bob's holder is unknown --------------------------- */
    stamp(block, sizeof block, 101UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SJOIN " CHAN_T " " NICK_BOB " - * - -\r\n", block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SJOIN send failed");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_T " member=" NICK_BOB
                               " server=" NAME_B,
                           T_IO_MS) == 0,
                 "node A never recorded the live SJOIN: %s", a.out);

    /* --- irc.b's burst: bob is on irc.c ---------------------------------- */
    stamp(block, sizeof block, 102UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SBURST " BURST_EPOCH " 1\r\n", block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SBURST send failed");
    stamp(block, sizeof block, 103UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SBURSTN " NICK_BOB " " NICK_BOB
                   " 127.0.0.1 - " BURST_EPOCH " :\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SBURSTN send failed");
    stamp(block, sizeof block, 104UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SBURSTC " CHAN_T " " NAME_B " - 0 - :\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SBURSTC send failed");
    stamp(block, sizeof block, 105UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SBURSTM " CHAN_T " irc.c " NICK_BOB " - *\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SBURSTM send failed");
    stamp(block, sizeof block, 106UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SBURSTE " BURST_EPOCH " 1 1 1\r\n", block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the SBURSTE send failed");
    TF_CHECK_MSG(nf_expect(&a, "members=1 installed=1", T_IO_MS) == 0,
                 "node A never applied irc.b's burst: %s", a.out);

    /* --- the repeat: the same live SJOIN, after the correction ------------ */
    stamp(block, sizeof block, 107UL);
    (void)snprintf(line, sizeof line,
                   "%s :" NAME_B " SJOIN " CHAN_T " " NICK_BOB " - * - -\r\n", block);
    TF_CHECK_MSG(pf_send_line(p1_fd, line) == 0, "the repeat SJOIN failed");
    TF_CHECK_MSG(nf_expect_nth(&a, "fed_sjoin: channel=" CHAN_T " member="
                                  NICK_BOB,
                               2, T_IO_MS) == 0,
                 "node A never applied the repeated SJOIN: %s", a.out);

    /* --- peer two: read what A now bursts -------------------------------- */
    TF_CHECK_MSG(accept_burst_peer(p2_listen, NAME_P2, burst, sizeof burst,
                                   3 * T_IO_MS) == 0,
                 "no live peer-two attempt carried a burst: %s", a.out);
    close(p2_listen);

    /* The channel the burst is about. */
    TF_CHECK_MSG(count_lines_with(burst, " SBURSTC ", CHAN_T) == 1u,
                 "node A's burst does not carry " CHAN_T " exactly once: %s",
                 burst);
    /* The member, attributed to its holder -- not to the relay that told A. */
    bob_lines = count_lines_with(burst, " SBURSTM ", NICK_BOB);
    TF_CHECK_MSG(bob_lines == 1u,
                 "node A's burst does not carry bob exactly once: %s", burst);
    TF_CHECK_MSG(strstr(burst, " " CHAN_T " irc.c " NICK_BOB " ") != NULL,
                 "node A's burst misattributes bob: %s", burst);
    /* The terminator agrees with the staging, or every receiver discards. */
    sburst_m = count_lines_with(burst, " SBURSTM ", NULL);
    sb = strstr(burst, " SBURSTE ");
    TF_CHECK_MSG(sb != NULL, "node A's burst has no terminator: %s", burst);
    term = sb + strlen(" SBURSTE ");
    TF_CHECK_MSG(sscanf(term, "%llu %llu %llu %llu", &epoch, &nn, &nc, &nm)
                 == 4,
                 "node A's terminator does not parse: %s", burst);
    TF_CHECK_MSG(nn == 0ull, "node A's burst claims nicks it has none of: %s",
                 burst);
    TF_CHECK_MSG(nc == 1ull, "node A's burst claims %llu channels: %s", nc,
                 burst);
    TF_CHECK_MSG(nm == (unsigned long long)sburst_m,
                 "node A's burst counts %llu members but stages %lu: %s", nm,
                 (unsigned long)sburst_m, burst);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    if (p1_fd >= 0) {
        close(p1_fd);
    }
    nf_free(&a);

    tf_done("burst_unknown_holder");
    return 0;
}
