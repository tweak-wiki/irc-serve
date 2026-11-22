/* test_channel_cap.c -- the per-connection channel cap, and the away-notification
 * walk it bounds.
 *
 * ===========================================================================
 * WHAT THIS FILE ASSERTS, AND WHAT IT IS NOT
 * ===========================================================================
 * `conn_t::chans` grew by doubling with no ceiling. The only limit on how many
 * channels one connection could hold was the node's global registry (1024 slots),
 * which is a SHARED resource -- so one client could create every channel the node
 * can hold and deny channel creation to everybody else on it. Measured, that cost
 * 12,202 bytes of input and returned 872 KiB of RSS, and the same 1024 entries
 * made a ten-byte `AWAY` cost 9.6 ms of event-loop time, because the
 * away-notification walks the connection's own list.
 *
 * So this file asserts three things and nothing else:
 *
 *   1. A client may hold up to CONN_MAX_CHANNELS channels, and the JOIN that
 *      would exceed it is refused with 405 -- RFC 1459's ERR_TOOMANYCHANNELS,
 *      which no other site on this node emits -- and counted on an
 *      `[observable]` line, because a JOIN that silently does nothing is
 *      indistinguishable from one the client never sent.
 *   2. The cap is on MEMBERSHIP and not on the command: a client at the cap may
 *      PART and then JOIN again, so a client is never locked out of its own
 *      channels by having held a lot of them once.
 *   3. The away-notification walk is bounded by a CONSTANT and reports how much
 *      it walked, so the cost of one `AWAY` is no longer a function of how many
 *      channels an attacker put the client in.
 *
 * WHAT IT IS NOT, and this matters for reading a red: this file does NOT assert
 * that the walk truncates. It cannot, and that is the point. The bound is
 * `AWAY_NOTIFY_MAX_CHANNELS`, whose value is `CONN_MAX_CHANNELS`, because
 * `chan_admit()` refuses a JOIN that would take a connection past the cap -- so a
 * connection the cap admits can never be truncated by the walk bound. What this
 * file asserts instead is that the two constants are the SAME number, which is
 * the invariant that makes the bound a safety net for a second writer of
 * `conn_t::chans` rather than a behaviour change for a legitimate client. If
 * somebody lowers the walk bound below the membership cap, this file goes red and
 * says so, because at that point a legitimate operator's away notifications start
 * disappearing.
 *
 * ===========================================================================
 * THE WIRE IS THE SURFACE, AND THERE IS NO sleep()
 * ===========================================================================
 * Every wait is a deadline loop in the harness (`tc_expect()`), and each JOIN is
 * confirmed by its own channel's echo rather than by a shared ` 366 ` -- a needle
 * that does not name the channel is satisfied by the previous channel's answer,
 * which is how a join-based test ends up asserting about a channel the client
 * never entered. No `fd=` is pinned anywhere: the node's descriptor for a
 * connection depends on how many descriptors it holds open, which differs between
 * Linux and macOS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/msg_verbs.h"
#include "core/server.h"
#include "core/chan_verbs.h"

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* The cap is exercised to its exact edge rather than "a lot of channels", because
 * a cap test that does not reach the edge passes against a cap of any size. The
 * count is derived from the constant the product compiles with, so moving the
 * number does not silently turn this into a cap-of-3 test. */
#define SW_MAX_JOIN CONN_MAX_CHANNELS

/* One channel name per probe, and the width is 63 (CHAN_MAX_NAME) so the index
 * has room at any cap this node could plausibly hold. */
static void chan_name(char *out, size_t cap, unsigned idx)
{
    (void)snprintf(out, cap, "#CC%04u", idx);
}

/* ---------------------------------------------------------------------------
 * CASE 1 -- THE CAP IS REACHED, AND THE NEXT JOIN IS REFUSED
 * ---------------------------------------------------------------------------
 * 128 JOINs is a lot of round trips, and they are done one at a time rather than
 * in one batch for the reason every join test has to: the wait for channel N's
 * echo is what proves channel N exists, and a batch of 128 JOINs proves nothing
 * about which of them the node acted on. The cost is real -- 128 round trips on a
 * loopback socket is well under a second -- and it buys an assertion that reaches
 * the edge exactly. */
static void case_cap_refuses_the_next_join(void)
{
    nf_node_t node;
    test_client_t c;
    char line[128];
    char echo[96];
    char chan[32];
    unsigned i;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "could not connect");
    TF_CHECK_MSG(tc_send(&c, "NICK cap") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&c, "USER cap 0 * :Cap") == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "the cap client never registered");

    for (i = 0; i < SW_MAX_JOIN; i++) {
        chan_name(chan, sizeof chan, i);
        (void)snprintf(line, sizeof line, "JOIN %s", chan);
        TF_CHECK_MSG(tc_send(&c, line) == 0,
                     "JOIN %u of %d could not be sent", i, SW_MAX_JOIN);
        (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
        TF_CHECK_MSG(tc_expect(&c, echo, T_IO_MS) == 0,
                     "JOIN %u of %d never echoed. Either the node refused a JOIN "
                     "the cap allows, or the needle matched an earlier channel "
                     "and the client is not in this one -- both are a cap that "
                     "behaves like something other than the documented bound.\n"
                     "  saw: %s", i, SW_MAX_JOIN, tc_buffer(&c));
    }

    /* AND THE ONE PAST THE EDGE. 405 is RFC 1459's ERR_TOOMANYCHANNELS: the
     * number the specification defines for exactly this, and one no other site
     * on this node emits, so it cannot be confused with 437's "cannot join
     * channel" or 474's "banned". */
    chan_name(chan, sizeof chan, SW_MAX_JOIN);
    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the JOIN past the cap could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " 405 ", T_IO_MS) == 0,
                 "the JOIN that would take this connection past CONN_MAX_CHANNELS "
                 "(%d) was not refused with 405. A cap that does not refuse at the "
                 "edge is a cap that has moved, and the only way this node can say "
                 " why a JOIN did nothing is a numeric and an `[observable]` line.\n"
                 "  saw: %s", SW_MAX_JOIN, tc_buffer(&c));
    /* The channel name is in the refusal, because 405's parameter is the channel
     * the client asked for and a refusal that names no channel leaves a client
     * unable to tell which of its JOINs was dropped. */
    TF_CHECK_MSG(nf_expect(&node, "chan_join_refused: channel=", T_IO_MS) == 0,
                 "the refusal was not counted. A JOIN that quietly does nothing "
                 "is indistinguishable from one the client never sent, which is "
                 "the discrepancy the observable output exists to make "
                 "findable.\n  node said: %s", node.out);
    TF_CHECK_MSG(nf_expect(&node, "reason=TOO_MANY_CHANNELS", T_IO_MS) == 0,
                 "the refusal does not name the reason.\n  node said: %s",
                 node.out);
    /* AND IT IS MEASURED: the held count is what the client actually had, so an
     * operator can see the cap being hit rather than inferring it. */
    (void)snprintf(line, sizeof line, "held=%d cap=%d", SW_MAX_JOIN,
                   SW_MAX_JOIN);
    TF_CHECK_MSG(nf_expect(&node, line, T_IO_MS) == 0,
                 "the refusal does not report the held count against the cap. "
                 "`held=%d cap=%d` is what says this was the edge rather than "
                 "some earlier number.\n  node said: %s", SW_MAX_JOIN,
                 SW_MAX_JOIN, node.out);
    /* AND NOTHING WAS CREATED (issue #274): the refused JOIN must not leave a
     * zero-member ghost behind. The create-print precedes any reply, and the
     * 405 above is already in hand, so the node's output is settled: a
     * `chan_create` line for the refused name here means the refusal created
     * the channel it refused, and repeated hits would fill the registry with
     * ghosts until later JOINs fail with 437 on channels nobody is in. */
    {
        char nocreate[64];
        test_client_t g;
        char roster[128];

        (void)snprintf(nocreate, sizeof nocreate, "chan_create: channel=%s",
                       chan);
        TF_CHECK_MSG(strstr(node.out, nocreate) == NULL,
                     "a JOIN refused at the per-connection cap left a channel "
                     "behind: there is a chan_create line for %s, so the "
                     "registry now holds a zero-member ghost.\n  node said: %s",
                     chan, node.out);
        /* AND THE NAMES PROVE IT: a second client JOINing the refused name is
         * its creator -- the 353 names it with @ -- which is only true if the
         * refused JOIN created nothing. A ghost would admit this client as a
         * plain member instead, with no @. */
        tc_init(&g);
        TF_CHECK_MSG(tc_connect(&g, node.port) == 0,
                     "the prover client could not connect");
        TF_CHECK_MSG(tc_send(&g, "NICK ghost2") == 0, "NICK send failed");
        TF_CHECK_MSG(tc_send(&g, "USER ghost2 0 * :Ghost") == 0,
                     "USER send failed");
        TF_CHECK_MSG(tc_expect(&g, " 001 ", T_IO_MS) == 0,
                     "the prover client never registered");
        (void)snprintf(line, sizeof line, "JOIN %s", chan);
        TF_CHECK_MSG(tc_send(&g, line) == 0,
                     "the prover JOIN could not be sent");
        (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
        TF_CHECK_MSG(tc_expect(&g, echo, T_IO_MS) == 0,
                     "the prover JOIN never echoed.\n  saw: %s",
                     tc_buffer(&g));
        (void)snprintf(roster, sizeof roster, "353 ghost2 = %s @ghost2", chan);
        TF_CHECK_MSG(tc_expect(&g, roster, T_IO_MS) == 0,
                     "the prover client is not the creator of %s: the refused "
                     "JOIN left a ghost channel behind and this client joined "
                     "it as a plain member.\n  saw: %s", chan,
                     tc_buffer(&g));
        tc_close(&g);
    }
    /* AND THE CLIENT IS STILL SERVED, which is the difference between a cap and
     * a disconnect: 1024 channels is a fact about the client, not an attack on
     * anybody else, and a node that closed the connection would be refusing to
     * serve a client it has already admitted. A PING whose PONG this node renders
     * as `:irc.test PONG irc.test <token>`, and the needle names the token so an
     * earlier line cannot satisfy it. */
    {
        char token[32];
        char ping[64];
        char pong[96];

        (void)snprintf(token, sizeof token, "cap%u", (unsigned)SW_MAX_JOIN);
        (void)snprintf(ping, sizeof ping, "PING :%s", token);
        (void)snprintf(pong, sizeof pong, "PONG irc.test %s", token);
        TF_CHECK_MSG(tc_send(&c, ping) == 0, "the post-refusal PING could not be sent");
        TF_CHECK_MSG(tc_expect(&c, pong, T_IO_MS) == 0,
                     "a client that hit the channel cap stopped being served. The "
                     "cap bounds a resource; it is not a reason to hang up on a "
                     "client that has done nothing else wrong.\n"
                     "  saw: %s", tc_buffer(&c));
    }

    /* AND THE REFUSED JOIN LEFT NO GHOST (#274). A JOIN refused at the cap
     * must not create the channel object: this client is at the cap, so a
     * second client joins the refused name, and the node must report
     * `chan_create` for it -- the line it prints when a channel object is
     * born. A zero-member ghost left behind by the refused JOIN would make
     * this a join of an existing channel, and no `chan_create` would appear.
     * The echo alone cannot say this: joining a ghost echoes exactly like
     * joining a fresh channel, which is why the observable is the assertion
     * rather than the wire. */
    {
        test_client_t d;
        char ghost[32];

        chan_name(ghost, sizeof ghost, SW_MAX_JOIN);
        tc_init(&d);
        TF_CHECK_MSG(tc_connect(&d, node.port) == 0,
                     "the ghost-probe client could not connect");
        TF_CHECK_MSG(tc_send(&d, "NICK ghostprobe") == 0,
                     "ghost-probe NICK send failed");
        TF_CHECK_MSG(tc_send(&d, "USER ghostprobe 0 * :Ghost") == 0,
                     "ghost-probe USER send failed");
        TF_CHECK_MSG(tc_expect(&d, " 001 ", T_IO_MS) == 0,
                     "the ghost-probe client never registered");
        (void)snprintf(line, sizeof line, "JOIN %s", ghost);
        TF_CHECK_MSG(tc_send(&d, line) == 0,
                     "the ghost-probe JOIN could not be sent");
        (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", ghost);
        TF_CHECK_MSG(tc_expect(&d, echo, T_IO_MS) == 0,
                     "a second client could not JOIN the refused channel "
                     "name.\n  saw: %s", tc_buffer(&d));
        (void)snprintf(line, sizeof line, "chan_create: channel=%s", ghost);
        TF_CHECK_MSG(nf_expect(&node, line, T_IO_MS) == 0,
                     "no `chan_create` for the refused name when a second client "
                     "joined it, so the refused JOIN left a zero-member ghost "
                     "behind (#274).\n  node said: %s", node.out);
        tc_close(&d);
    }

    /* CASE 2 -- THE CAP IS ON MEMBERSHIP, NOT ON THE COMMAND. PART one channel
     * and the same JOIN that was refused works, which is what keeps a client
     * from being locked out of its own channels by having held a lot of them
     * once. It is also the shape a legitimate client produces: a bouncer rotating
     * through channels would otherwise be stuck at the cap permanently. */
    chan_name(chan, sizeof chan, 0u);
    (void)snprintf(line, sizeof line, "PART %s", chan);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the PART could not be sent");
    (void)snprintf(echo, sizeof echo, " PART %s\r\n", chan);
    TF_CHECK_MSG(tc_expect(&c, echo, T_IO_MS) == 0,
                 "the PART never echoed, so the membership this test needs to free "
                 "was never given up and the re-JOIN below would be refused for "
                 "the wrong reason.\n  saw: %s", tc_buffer(&c));
    chan_name(chan, sizeof chan, SW_MAX_JOIN);
    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the re-JOIN could not be sent");
    (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
    TF_CHECK_MSG(tc_expect(&c, echo, T_IO_MS) == 0,
                 "a JOIN that was refused at the cap was refused AGAIN after a PART "
                 "freed a slot. The cap is on how many channels a connection holds, "
                 "not on how many it has ever held, and a client that cannot "
                 "re-enter a channel it left is a client the cap has locked out.\n"
                 "  saw: %s", tc_buffer(&c));

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 3 -- THE AWAY WALK IS BOUNDED, AND REPORTS HOW FAR IT WALKED
 * ---------------------------------------------------------------------------
 * The bound is the same number as the membership cap, which is the invariant this
 * case's real assertion is about: a client the cap admits can never be truncated
 * by the walk bound, so the walk bound is a safety net for a second writer of
 * `conn_t::chans` rather than a behaviour change for a legitimate operator. If
 * the two constants come apart, a client between them starts losing
 * notifications, and nothing on the wire says so. */
static void case_away_walk_is_bounded(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK_MSG(AWAY_NOTIFY_MAX_CHANNELS == CONN_MAX_CHANNELS,
                 "AWAY_NOTIFY_MAX_CHANNELS (%d) is not CONN_MAX_CHANNELS (%d). "
                 "The walk bound must be at least the membership cap, or a client "
                 "the cap admits can be truncated by the walk and lose away "
                 "notifications silently -- which is exactly the availability "
                 "failure the bound is supposed to prevent, arrived at from the "
                 "other direction.",
                 AWAY_NOTIFY_MAX_CHANNELS, CONN_MAX_CHANNELS);

    /* Two channels is enough to see the walk's own reporting, and it keeps this
     * case's runtime to a handful of round trips rather than 128: what is under
     * test is the BOUND and the REPORT, not the walk's performance. */
    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "could not connect");
    TF_CHECK_MSG(tc_send(&c, "NICK away") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&c, "USER away 0 * :Away") == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "the away client never registered");
    TF_CHECK_MSG(tc_send(&c, "JOIN #CA01") == 0, "the first JOIN failed");
    TF_CHECK_MSG(tc_expect(&c, " JOIN #CA01\r\n", T_IO_MS) == 0,
                 "the first JOIN never echoed");
    TF_CHECK_MSG(tc_send(&c, "JOIN #CA02") == 0, "the second JOIN failed");
    TF_CHECK_MSG(tc_expect(&c, " JOIN #CA02\r\n", T_IO_MS) == 0,
                 "the second JOIN never echoed");

    /* THE TEN-BYTE LINE, and what comes back is the measurement: `channels=`
     * (what the connection holds), `walked=` (how far the bound let it go) and
     * `recipients=` (what it delivered). `channels` and `walked` being EQUAL is
     * the whole claim for a client below the cap, and their differing on a node
     * that has admitted this client would be a truncation nobody asked for. */
    TF_CHECK_MSG(tc_send(&c, "AWAY :out to lunch") == 0, "the AWAY could not be sent");
    TF_CHECK_MSG(nf_expect(&node, "away_notify: nick=away channels=2 walked=2 "
                               "bound=128 recipients=0 state=set", T_IO_MS) == 0,
                 "the away notification did not report walking exactly the channels "
                 "the connection holds. `channels=2 walked=2` is what says the walk "
                 "was not truncated for a client the cap admits; `recipients=0` is "
                 "what says nobody in those two channels negotiated away-notify, "
                 "which is the correct answer for a sweep that joins alone.\n"
                 "  node said: %s", node.out);
    /* AND NO TRUNCATION FLAG, which is the negative half: `truncated=1` on a
     * client under the cap would mean the walk bound is below the membership
     * bound, which is the invariant this case's first assertion is about. */
    TF_CHECK_MSG(strstr(node.out, "truncated=1") == NULL,
                 "the away walk reported truncating for a client that holds two "
                 "channels against a bound of %d. A walk that stops early on a "
                 "client below the cap is dropping away notifications nobody asked "
                 "it to drop.\n  node said: %s", AWAY_NOTIFY_MAX_CHANNELS,
                 node.out);
    /* AND THE OTHER EDGE, because a bare `AWAY` is a different branch and a bound
     * that only held on one edge would be a bound that half worked. */
    TF_CHECK_MSG(tc_send(&c, "AWAY") == 0, "the clearing AWAY could not be sent");
    TF_CHECK_MSG(nf_expect(&node, "away_notify: nick=away channels=2 walked=2 "
                               "bound=128 recipients=0 state=cleared", T_IO_MS) == 0,
                 "the away-CLEAR walk did not report the same shape. Both edges "
                 "notify, because the cleared edge is the one that tells a member "
                 "the user is back, and a bound that only held on the way out "
                 "would be a bound that half worked.\n  node said: %s", node.out);

    /* AND THE CLIENT HEARD BOTH EDGES: 305 for "away" and 306 for "back", which
     * are the two numerics that make a state change answerable. */
    TF_CHECK_MSG(tc_expect(&c, " 306 ", T_IO_MS) == 0,
                 "the client was never told it was marked away.\n  saw: %s",
                 tc_buffer(&c));
    TF_CHECK_MSG(tc_expect(&c, " 305 ", T_IO_MS) == 0,
                 "the client was never told it was back.\n  saw: %s", tc_buffer(&c));

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 4 -- THE NODE-WIDE CAP REFUSES CREATION, AND A PART FREES A SLOT
 * ---------------------------------------------------------------------------
 * Issue #169: membership is capped per connection (128) but nothing capped the
 * node, so distinct JOINs from many connections grew the registry without
 * bound. Filling to SERVER_MAX_CHANNELS takes 8 connections at 128 channels
 * each (one client cannot hold the whole cap, which is the point of the
 * per-connection bound); the JOINs go out 16 to a command (CHAN_MAX_LIST_ARGS)
 * so the fill is tens of round trips rather than a thousand, and each channel
 * is still confirmed by its own echo. A fresh client past the cap gets 437 --
 * the attach-failure numeric, not 405's per-connection one -- plus an
 * `[observable] chan_create_refused ... reason=TOO_MANY_CHANNELS` line and no
 * `chan_create` line for the refused name; joining a channel the node already
 * holds still works (only CREATION is refused); and after one PART the same
 * JOIN creates again. */
static void case_node_cap_refuses_creation(void)
{
    /* One client holds CONN_MAX_CHANNELS, so the fill needs this many of them.
     * Derived from the two constants so moving either number keeps the fill at
     * exactly the edge rather than silently short of it. */
    enum { NFILL = SERVER_MAX_CHANNELS / CONN_MAX_CHANNELS };
    enum { NBATCH = CONN_MAX_CHANNELS / CHAN_MAX_LIST_ARGS };
    nf_node_t node;
    test_client_t f[NFILL];
    test_client_t c;
    char line[512];
    char echo[96];
    char chan[32];
    unsigned fi;
    unsigned b;
    unsigned k;

    TF_CHECK_MSG(SERVER_MAX_CHANNELS % CONN_MAX_CHANNELS == 0,
                 "SERVER_MAX_CHANNELS (%d) is not a multiple of "
                 "CONN_MAX_CHANNELS (%d), so an exact fill needs a ragged "
                 "last client this case does not have.",
                 SERVER_MAX_CHANNELS, CONN_MAX_CHANNELS);
    TF_CHECK_MSG(CONN_MAX_CHANNELS % CHAN_MAX_LIST_ARGS == 0,
                 "CONN_MAX_CHANNELS (%d) is not a multiple of "
                 "CHAN_MAX_LIST_ARGS (%d), so batched JOINs cannot land "
                 "exactly on the per-connection edge.",
                 CONN_MAX_CHANNELS, CHAN_MAX_LIST_ARGS);
    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    for (fi = 0; fi < NFILL; fi++) {
        char nick[32];

        tc_init(&f[fi]);
        TF_CHECK_MSG(tc_connect(&f[fi], node.port) == 0,
                     "filler %u could not connect", fi);
        (void)snprintf(nick, sizeof nick, "fill%u", fi);
        (void)snprintf(line, sizeof line, "NICK %s", nick);
        TF_CHECK_MSG(tc_send(&f[fi], line) == 0, "filler %u NICK failed", fi);
        (void)snprintf(line, sizeof line, "USER %s 0 * :Fill", nick);
        TF_CHECK_MSG(tc_send(&f[fi], line) == 0, "filler %u USER failed", fi);
        TF_CHECK_MSG(tc_expect(&f[fi], " 001 ", T_IO_MS) == 0,
                     "filler %u never registered", fi);
    }
    for (fi = 0; fi < NFILL; fi++) {
        for (b = 0; b < NBATCH; b++) {
            size_t used = 5; /* "JOIN " */

            memcpy(line, "JOIN ", 5);
            for (k = 0; k < CHAN_MAX_LIST_ARGS; k++) {
                unsigned idx = fi * (unsigned)CONN_MAX_CHANNELS +
                               b * (unsigned)CHAN_MAX_LIST_ARGS + k;

                (void)snprintf(chan, sizeof chan, "#CN%04u", idx);
                if (k != 0) {
                    line[used++] = ',';
                }
                memcpy(line + used, chan, strlen(chan) + 1u);
                used += strlen(chan);
            }
            TF_CHECK_MSG(tc_send(&f[fi], line) == 0,
                         "filler %u batch %u could not be sent", fi, b);
            for (k = 0; k < CHAN_MAX_LIST_ARGS; k++) {
                unsigned idx = fi * (unsigned)CONN_MAX_CHANNELS +
                               b * (unsigned)CHAN_MAX_LIST_ARGS + k;

                (void)snprintf(chan, sizeof chan, "#CN%04u", idx);
                (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
                TF_CHECK_MSG(tc_expect(&f[fi], echo, T_IO_MS) == 0,
                             "filler %u channel %s never echoed -- the fill "
                             "stopped short of the cap, so the refusal below "
                             "would be for the wrong reason.\n  saw: %s",
                             fi, chan, tc_buffer(&f[fi]));
            }
        }
    }

    /* AND THE ONE PAST THE EDGE, from a client that holds nothing: 437, not
     * 405, because the per-connection cap is not what fired. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "could not connect");
    TF_CHECK_MSG(tc_send(&c, "NICK capnode") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&c, "USER capnode 0 * :CapNode") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "the overflow client never registered");
    TF_CHECK_MSG(tc_send(&c, "JOIN #CNOVERFLOW") == 0,
                 "the JOIN past the node cap could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " 437 ", T_IO_MS) == 0,
                 "the JOIN that would take this node past SERVER_MAX_CHANNELS "
                 "(%d) was not refused with 437.\n  saw: %s",
                 SERVER_MAX_CHANNELS, tc_buffer(&c));
    TF_CHECK_MSG(nf_expect(&node, "chan_create_refused: channel=", T_IO_MS) == 0,
                 "the creation refusal was not counted.\n  node said: %s",
                 node.out);
    TF_CHECK_MSG(nf_expect(&node, "reason=TOO_MANY_CHANNELS", T_IO_MS) == 0,
                 "the creation refusal does not name the reason.\n"
                 "  node said: %s", node.out);
    /* AND NOTHING WAS CREATED: no chan_create line for the refused name, so
     * the count the refusal reported is the count the node still holds. */
    TF_CHECK_MSG(strstr(node.out, "chan_create: channel=#CNOVERFLOW") == NULL,
                 "a refused JOIN left a chan_create line for #CNOVERFLOW: the "
                 "refusal created the channel it refused.\n  node said: %s",
                 node.out);
    /* AND ONLY CREATION IS REFUSED: an existing channel still admits members,
     * and a second new name is refused again, so the count did not move. */
    TF_CHECK_MSG(tc_send(&c, "JOIN #CN0000") == 0,
                 "the JOIN of an existing channel could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " JOIN #CN0000\r\n", T_IO_MS) == 0,
                 "a JOIN of a channel the node already holds was refused at "
                 "the node cap. Only creation is capped; membership of what "
                 "exists must keep working.\n  saw: %s", tc_buffer(&c));
    TF_CHECK_MSG(tc_send(&c, "JOIN #CNOVERFLOW2") == 0,
                 "the second overflow JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " 437 ", T_IO_MS) == 0,
                 "a second new channel past the cap was not refused: the "
                 "first refusal must have created something.\n  saw: %s",
                 tc_buffer(&c));

    /* PART FREES A SLOT: the filler held #CN0000 alone, so parting destroys it
     * and the refused JOIN creates again -- the cap is on what the node holds,
     * not on what it has ever held. */
    TF_CHECK_MSG(tc_send(&f[0], "PART #CN0000") == 0,
                 "the freeing PART could not be sent");
    TF_CHECK_MSG(tc_expect(&f[0], " PART #CN0000\r\n", T_IO_MS) == 0,
                 "the freeing PART never echoed.\n  saw: %s",
                 tc_buffer(&f[0]));
    TF_CHECK_MSG(tc_send(&c, "PART #CN0000") == 0,
                 "the overflow client's PART could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " PART #CN0000\r\n", T_IO_MS) == 0,
                 "the overflow client's PART never echoed.\n  saw: %s",
                 tc_buffer(&c));
    /* The fill already printed one `chan_create: channel=#CN0000`, so the
     * SECOND occurrence is the proof the PART freed the slot and the re-JOIN
     * created again -- a plain nf_expect would match the fill's own line and
     * prove nothing. */
    TF_CHECK_MSG(tc_send(&c, "JOIN #CN0000") == 0,
                 "the re-JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " JOIN #CN0000\r\n", T_IO_MS) == 0,
                 "a JOIN refused at the node cap was refused AGAIN after a "
                 "PART freed a slot.\n  saw: %s", tc_buffer(&c));
    TF_CHECK_MSG(nf_expect_nth(&node, "chan_create: channel=#CN0000", 2,
                               T_IO_MS) == 0,
                 "the re-JOIN after a PART created nothing: there is no "
                 "second chan_create line for #CN0000.\n  node said: %s",
                 node.out);

    tc_close(&c);
    for (fi = 0; fi < NFILL; fi++) {
        tc_close(&f[fi]);
    }
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 5 -- A PEER CANNOT CREATE PAST THE CAP (issue #223)
 * ---------------------------------------------------------------------------
 * Case 4 pins the cap on the local JOIN path; this pins it on the peer-driven
 * ones. Node A is filled to SERVER_MAX_CHANNELS exactly the way case 4 fills
 * its node, then node B links to A and a client of B joins #PEERNEW -- which B
 * creates locally (B is empty) and forwards as SJOIN. A must refuse the
 * creation: the fix enforces the cap in server_chan_attach(), the path both
 * SJOIN and the burst commit share, so the refusal is the attach failing the
 * way an allocation failure would. The arrival marker is A's `fed_malformed`
 * line for the SJOIN -- the attach failure surfaces there, which is the
 * pre-existing shape of a creation that could not happen -- and the assertion
 * is the absence of a `chan_create` line for #PEERNEW after it. A still serves
 * its own channels, so the refusal is creation-only. */
static void case_peer_creation_refused_at_cap(void)
{
    enum { NFILL = SERVER_MAX_CHANNELS / CONN_MAX_CHANNELS };
    enum { NBATCH = CONN_MAX_CHANNELS / CHAN_MAX_LIST_ARGS };
    static char secret[] = "cap-peer-secret-0123456789";
    nf_node_t a;
    nf_node_t b;
    test_client_t f[NFILL];
    test_client_t c;
    test_client_t d;
    char peer_arg[96];
    char line[512];
    char echo[96];
    char chan[32];
    unsigned fi;
    unsigned bb;
    unsigned k;

    {
        char *const argv[] = { (char *)"irc-serve", (char *)"--name",
                               (char *)"irc.a",   (char *)"--secret",
                               (char *)secret,    (char *)"0",
                               NULL };

        TF_CHECK_MSG(nf_spawn_binary_argv(&a, argv) == 0,
                     "could not start node A from the shipped binary");
    }
    for (fi = 0; fi < NFILL; fi++) {
        char nick[32];

        tc_init(&f[fi]);
        TF_CHECK_MSG(tc_connect(&f[fi], a.port) == 0,
                     "filler %u could not connect", fi);
        (void)snprintf(nick, sizeof nick, "fill%u", fi);
        (void)snprintf(line, sizeof line, "NICK %s", nick);
        TF_CHECK_MSG(tc_send(&f[fi], line) == 0, "filler %u NICK failed", fi);
        (void)snprintf(line, sizeof line, "USER %s 0 * :Fill", nick);
        TF_CHECK_MSG(tc_send(&f[fi], line) == 0, "filler %u USER failed", fi);
        TF_CHECK_MSG(tc_expect(&f[fi], " 001 ", T_IO_MS) == 0,
                     "filler %u never registered", fi);
    }
    /* The fill goes out batched like case 4's: 16 channels to a JOIN, and each
     * batch's echoes are read before the next batch is sent, so the node's
     * per-client output never grows past one batch. */
    for (fi = 0; fi < NFILL; fi++) {
        for (bb = 0; bb < NBATCH; bb++) {
            size_t used = 5; /* "JOIN " */

            memcpy(line, "JOIN ", 5);
            for (k = 0; k < (unsigned)CHAN_MAX_LIST_ARGS; k++) {
                unsigned idx = fi * (unsigned)CONN_MAX_CHANNELS +
                               bb * (unsigned)CHAN_MAX_LIST_ARGS + k;

                (void)snprintf(chan, sizeof chan, "#CP%04u", idx);
                if (k != 0) {
                    line[used++] = ',';
                }
                memcpy(line + used, chan, strlen(chan) + 1u);
                used += strlen(chan);
            }
            TF_CHECK_MSG(tc_send(&f[fi], line) == 0,
                         "filler %u batch %u could not be sent", fi, bb);
            for (k = 0; k < (unsigned)CHAN_MAX_LIST_ARGS; k++) {
                unsigned idx = fi * (unsigned)CONN_MAX_CHANNELS +
                               bb * (unsigned)CHAN_MAX_LIST_ARGS + k;

                (void)snprintf(chan, sizeof chan, "#CP%04u", idx);
                (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
                TF_CHECK_MSG(tc_expect(&f[fi], echo, T_IO_MS) == 0,
                             "filler %u channel %s never echoed -- the fill "
                             "stopped short of the cap.\n  saw: %s",
                             fi, chan, tc_buffer(&f[fi]));
            }
        }
    }

    /* Node B links to the full node A. B is empty, so the establishment burst
     * carries nothing A would have to refuse; the refused creation comes next,
     * over a live SJOIN. */
    (void)snprintf(peer_arg, sizeof peer_arg, "irc.a,127.0.0.1,%d", a.port);
    {
        char *const argv[] = { (char *)"irc-serve", (char *)"--name",
                               (char *)"irc.b",   (char *)"--secret",
                               (char *)secret,    (char *)"--peer",
                               peer_arg,          (char *)"0",
                               NULL };

        TF_CHECK_MSG(nf_spawn_binary_argv(&b, argv) == 0,
                     "could not start node B with a --peer of %s", peer_arg);
    }
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_IO_MS) == 0,
                 "node A never accepted the link from node B: %s", a.out);
    tc_init(&d);
    TF_CHECK_MSG(tc_connect(&d, b.port) == 0, "could not connect to node B");
    TF_CHECK_MSG(tc_send(&d, "NICK peeruser") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&d, "USER peeruser 0 * :Peer") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&d, " 001 ", T_IO_MS) == 0,
                 "the peer-side client never registered");
    TF_CHECK_MSG(tc_send(&d, "JOIN #PEERNEW") == 0,
                 "the peer-side JOIN could not be sent");
    TF_CHECK_MSG(tc_expect(&d, " JOIN #PEERNEW\r\n", T_IO_MS) == 0,
                 "node B refused a creation it has room for: B is empty, so "
                 "this JOIN must succeed locally and only fail on A.\n  saw: %s",
                 tc_buffer(&d));
    /* THE SJOIN ARRIVED AND DIED AT THE CAP: the attach failure surfaces as a
     * refused SJOIN line, which is the marker the absence below is read
     * after -- without it the absence could mean the SJOIN never arrived. */
    TF_CHECK_MSG(nf_expect(&a, "command=SJOIN", T_IO_MS) == 0,
                 "node A never reported the SJOIN for #PEERNEW: the refusal "
                 "below would be vacuous.\n  node said: %s", a.out);
    TF_CHECK_MSG(strstr(a.out, "chan_create: channel=#PEERNEW") == NULL,
                 "node A created #PEERNEW past SERVER_MAX_CHANNELS: a peer can "
                 "push this node past the cap the local JOIN path refuses.\n"
                 "  node said: %s", a.out);
    /* AND A STILL SERVES WHAT IT HOLDS: joining an existing channel works, so
     * the refusal is creation-only and the link is alive. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, a.port) == 0, "could not connect to node A");
    TF_CHECK_MSG(tc_send(&c, "NICK capnode") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&c, "USER capnode 0 * :CapNode") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "the overflow client never registered");
    TF_CHECK_MSG(tc_send(&c, "JOIN #CP0000") == 0,
                 "the JOIN of an existing channel could not be sent");
    TF_CHECK_MSG(tc_expect(&c, " JOIN #CP0000\r\n", T_IO_MS) == 0,
                 "a JOIN of a channel node A already holds was refused at the "
                 "node cap.\n  saw: %s", tc_buffer(&c));

    tc_close(&d);
    tc_close(&c);
    for (fi = 0; fi < NFILL; fi++) {
        tc_close(&f[fi]);
    }
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * CASE 6 -- THE SHARED PATH REFUSES AT THE CAP (unit level, issue #223)
 * ---------------------------------------------------------------------------
 * Case 5 proves a full node refuses a peer's creation end to end; this pins
 * the mechanism to the attach call itself, through the same public entry
 * points the SJOIN and burst paths use. A server is filled to exactly
 * SERVER_MAX_CHANNELS with chan_new()/server_chan_attach(), the next attach
 * fails, the count does not move, and after one detach the same name attaches
 * again -- so the bound is on what the node holds, enforced where every
 * creation path converges, and not on what it has ever held. No sockets, no
 * children: the claim is about the registry, and the registry is observable
 * without a wire. */
static void case_attach_refuses_at_cap(void)
{
    server_t s;
    char name[32];
    unsigned i;

    TF_CHECK_MSG(server_init(&s, "irc.a") == 0, "server_init failed");
    for (i = 0; i < (unsigned)SERVER_MAX_CHANNELS; i++) {
        chan_t *ch;

        (void)snprintf(name, sizeof name, "#CU%04u", i);
        ch = chan_new(name, "irc.a", s.epoch);
        TF_CHECK_MSG(ch != NULL, "chan_new failed for %s", name);
        TF_CHECK_MSG(server_chan_attach(&s, ch) == 0,
                     "attach %u of %d failed before the cap", i,
                     SERVER_MAX_CHANNELS);
    }
    TF_CHECK_MSG(server_chan_count(&s) == (size_t)SERVER_MAX_CHANNELS,
                 "a filled node does not hold the cap");
    {
        chan_t *extra = chan_new("#CUOVER", "irc.a", s.epoch);

        TF_CHECK_MSG(extra != NULL, "chan_new failed for the overflow channel");
        TF_CHECK_MSG(server_chan_attach(&s, extra) != 0,
                     "attach past SERVER_MAX_CHANNELS succeeded: the shared "
                     "path does not enforce the node-wide cap");
        chan_free(extra);
    }
    TF_CHECK_MSG(server_chan_count(&s) == (size_t)SERVER_MAX_CHANNELS,
                 "a refused attach moved the count");
    /* AND NOTHING WAS GROWN FOR IT: the index stays at exactly the cap. A
     * refusal that doubled the vector first would be the old shape -- growth
     * below the put that a full hash table then threw away -- and this is the
     * assertion that tells the two apart. */
    TF_CHECK_MSG(s.chan_objs_cap == (size_t)SERVER_MAX_CHANNELS,
                 "a refused attach grew the channel index to %zu: the cap "
                 "must fire before any allocation, not after it",
                 s.chan_objs_cap);
    /* AND A FREED SLOT TAKES THE SAME NAME AGAIN: detach drops the count, and
     * the re-attach of the refused name succeeds -- the cap is on what the
     * node holds, not on what it has ever held. */
    server_chan_detach(&s, "#CU0000");
    TF_CHECK_MSG(server_chan_count(&s) == (size_t)SERVER_MAX_CHANNELS - 1u,
                 "a detach did not free a slot");
    {
        chan_t *retry = chan_new("#CUOVER", "irc.a", s.epoch);

        TF_CHECK_MSG(retry != NULL, "chan_new failed for the retry");
        TF_CHECK_MSG(server_chan_attach(&s, retry) == 0,
                     "the retry past a freed slot was refused: the cap is "
                     "supposed to count what the node holds");
    }
    TF_CHECK_MSG(server_chan_count(&s) == (size_t)SERVER_MAX_CHANNELS,
                 "the retried attach did not restore the cap");
    server_shutdown(&s);
}

int main(void)
{
    case_cap_refuses_the_next_join();
    case_away_walk_is_bounded();
    case_node_cap_refuses_creation();
    case_peer_creation_refused_at_cap();
    case_attach_refuses_at_cap();
    tf_done("test_channel_cap");
    return 0;
}
