/* test_tagmsg.c -- IRCv3 TAGMSG relay on the wire, against the real binary.
 *
 * #672: the node advertised `message-tags` but answered TAGMSG with 421, so
 * typing indicators went into a black hole. The fix relays TAGMSG to the
 * channel's capped members with the client's tag block verbatim.
 *
 * Windows are closed by a PING/PONG drain on the asserting client (6.3: no
 * fixed sleeps), and every assertion runs over the span its command could have
 * answered in, so a stale needle cannot satisfy it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define CHAN "#T"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "tag%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s", token);
}

static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\"", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    TF_CHECK_MSG(tc_send(c, "JOIN " CHAN) == 0, "%s JOIN failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN", nick);
    drain(c);
}

static size_t copies_since(const test_client_t *c, size_t mark,
                           const char *needle)
{
    const char *hay = tc_buffer(c) + mark;
    size_t n = 0;
    size_t nlen = strlen(needle);

    if (nlen == 0u) {
        return 0u;
    }
    while (*hay != '\0') {
        if (strncmp(hay, needle, nlen) == 0) {
            n++;
            hay += nlen;
            continue;
        }
        hay++;
    }
    return n;
}

static void case_tagmsg(void)
{
    nf_node_t node;
    test_client_t alice; /* sender, message-tags */
    test_client_t bob;   /* capped member: must receive */
    test_client_t carol; /* uncapped member: must not */
    test_client_t dave;  /* registered, not on #T: 404 */
    test_client_t pre;   /* unregistered: 451 */
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&alice);
    tc_init(&bob);
    tc_init(&carol);
    tc_init(&dave);
    tc_init(&pre);
    register_caps(&alice, node.port, "alice", CAP_MESSAGE_TAGS);
    register_caps(&bob, node.port, "bob", CAP_MESSAGE_TAGS);
    register_caps(&carol, node.port, "carol", NULL);

    /* ---- 1. RELAY: the capped member gets the tags verbatim ---- */
    {
        char want[256];

        mark = tc_received(&bob);
        TF_CHECK_MSG(tc_send(&alice, "@+typing=active TAGMSG " CHAN) == 0,
                     "alice TAGMSG send failed");
        drain(&bob);
        (void)snprintf(want, sizeof want,
                       "@+typing=active :alice!alice@127.0.0.1 TAGMSG " CHAN "\r\n");
        TF_CHECK_MSG(strstr(tc_buffer(&bob) + mark, want) != NULL,
                     "bob never got the relayed TAGMSG with its tags intact.\n"
                     "  bob saw: %s", tc_buffer(&bob) + mark);
    }

    /* ---- 2. NO LEAK: the uncapped member gets nothing ---- */
    {
        size_t m = tc_received(&carol);
        size_t got;

        TF_CHECK_MSG(tc_send(&alice, "@+typing=active TAGMSG " CHAN) == 0,
                     "alice TAGMSG send failed");
        drain(&carol);
        got = copies_since(&carol, m, "TAGMSG " CHAN);
        TF_CHECK_MSG(got == 0u,
                     "carol (no message-tags) received %zu TAGMSG lines; "
                     "a tagless TAGMSG is meaningless.\n  carol saw: %s",
                     got, tc_buffer(&carol) + m);
    }

    /* ---- 3. NO ECHO: the sender is not in its own audience ---- */
    {
        size_t m = tc_received(&alice);
        size_t got;

        TF_CHECK_MSG(tc_send(&alice, "@+typing=active TAGMSG " CHAN) == 0,
                     "alice TAGMSG send failed");
        drain(&alice);
        got = copies_since(&alice, m, "TAGMSG " CHAN);
        TF_CHECK_MSG(got == 0u,
                     "alice got %zu echoes of her own TAGMSG; she already "
                     "knows her typing state.\n  alice saw: %s",
                     got, tc_buffer(&alice) + m);
    }

    /* ---- 4. NON-MEMBER: 404, mirroring PRIVMSG ---- */
    {
        char line[256];

        (void)snprintf(line, sizeof line, "NICK %s", "dave");
        TF_CHECK_MSG(tc_connect(&dave, node.port) == 0, "dave connect failed");
        TF_CHECK_MSG(tc_send(&dave, line) == 0, "dave NICK failed");
        TF_CHECK_MSG(tc_send(&dave, "USER dave 0 * :Real dave") == 0,
                     "dave USER failed");
        TF_CHECK_MSG(tc_expect(&dave, " 001 ", T_IO_MS) == 0,
                     "dave never registered");
        drain(&dave);
        mark = tc_received(&dave);
        TF_CHECK_MSG(tc_send(&dave, "@+typing=active TAGMSG " CHAN) == 0,
                     "dave TAGMSG send failed");
        TF_CHECK_MSG(tc_expect(&dave, " 404 ", T_IO_MS) == 0,
                     "TAGMSG from off-channel got no 404.\n  dave saw: %s",
                     tc_buffer(&dave) + mark);
    }

    /* ---- 5. PRE-REGISTRATION: 451, the registration gate holds ---- */
    {
        TF_CHECK_MSG(tc_connect(&pre, node.port) == 0, "pre connect failed");
        mark = tc_received(&pre);
        TF_CHECK_MSG(tc_send(&pre, "@+typing=active TAGMSG " CHAN) == 0,
                     "pre TAGMSG send failed");
        TF_CHECK_MSG(tc_expect(&pre, " 451 ", T_IO_MS) == 0,
                     "pre-registration TAGMSG got no 451.\n  pre saw: %s",
                     tc_buffer(&pre) + mark);
    }

    /* ---- 6. NON-CHANNEL TARGET: 403, a nick is no channel for this verb ---- */
    {
        mark = tc_received(&alice);
        TF_CHECK_MSG(tc_send(&alice, "@+typing=active TAGMSG bob") == 0,
                     "alice TAGMSG-to-nick send failed");
        TF_CHECK_MSG(tc_expect(&alice, " 403 ", T_IO_MS) == 0,
                     "TAGMSG to a nick got no 403.\n  alice saw: %s",
                     tc_buffer(&alice) + mark);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&alice);
    tc_close(&bob);
    tc_close(&carol);
    tc_close(&dave);
    tc_close(&pre);
}

int main(void)
{
    case_tagmsg();
    tf_done("tagmsg");
    return 0;
}
