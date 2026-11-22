/* test_shutdown_goodbye_before_close.c -- issue #288: the shutdown split.
 *
 * server_shutdown() is phase 1 (say goodbye) then phase 2 (close everything),
 * and the ordering -- SHUTDOWN queued before any close() count moves -- is a
 * property of the split rather than of a two-node wire exchange, so this is a
 * unit test: one server_t in this process, one ESTABLISHED link over a
 * socketpair, and a transport double that captures what would have travelled
 * and counts closes without closing anything.
 *
 * Phase 1 must leave a SHUTDOWN in the capture with both close counts still at
 * zero and the conn still registered; phase 2 must then close it through the
 * normal path (transport_close runs, n_closed moves). A regression that closed
 * first -- or a goodbye that never got queued -- fails here, not in a
 * 15-second integration drain.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/server.h"
#include "core/transport.h"
#include "federation_handshake.h"

static char g_sent[4096];
static size_t g_sent_len = 0u;
static int g_close_count = 0;

static ssize_t mock_send(conn_t *c, const void *buf, size_t len)
{
    (void)c;
    if (len == 0u || buf == NULL) {
        return 0;
    }
    /* One SHUTDOWN line is a few hundred bytes; the bound only says so. */
    assert(g_sent_len + len + 1u < sizeof g_sent);
    memcpy(g_sent + g_sent_len, buf, len);
    g_sent_len += len;
    g_sent[g_sent_len] = '\0';
    return (ssize_t)len;
}

static ssize_t mock_recv(conn_t *c, void *buf, size_t len)
{
    (void)c;
    (void)buf;
    (void)len;
    /* The receive queue is empty, so the shutdown drain stops at once. */
    return TRANSPORT_RETRY;
}

static void mock_close(conn_t *c)
{
    (void)c;
    g_close_count++;
}

static const transport_ops_t k_mock_ops = { mock_recv, mock_send, mock_close };

int main(void)
{
    server_t s;
    int sv[2];
    conn_t *c;
    uint64_t closed_before;

    assert(server_init(&s, "irc.a") == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    c = conn_new(sv[0], CONN_SERVER);
    assert(c != NULL);
    c->t_ops = &k_mock_ops;
    assert(server_add_conn(&s, c) == 0);
    s.links = (server_link_t *)calloc(1u, sizeof *s.links);
    assert(s.links != NULL);
    memcpy(s.links[0].name, "irc.b", sizeof "irc.b");
    s.links[0].fd = sv[0];
    s.links[0].state = ESTABLISHED;
    s.nlinks = 1u;

    closed_before = s.n_closed;

    /* Phase 1 says goodbye and closes nothing. */
    server_shutdown_phase1_say_goodbye(&s);
    assert(strstr(g_sent, "SHUTDOWN") != NULL);
    assert(g_close_count == 0);
    assert(s.n_closed == closed_before);
    assert(server_conn(&s, sv[0]) == c);

    /* Phase 2 closes everything phase 1 left open, through the normal path. */
    server_shutdown_phase2_close(&s);
    assert(g_close_count == 1);
    assert(s.n_closed == closed_before + 1u);
    assert(server_conn(&s, sv[0]) == NULL);

    /* The far half was never registered; phase 2 closed sv[0] itself. */
    assert(close(sv[1]) == 0);

    printf("ok: shutdown_goodbye_before_close\n");
    return 0;
}
