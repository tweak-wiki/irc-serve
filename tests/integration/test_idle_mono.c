/* test_idle_mono.c -- 317 idle is measured on the monotonic clock (#175).
 *
 * conn_t::last_active_ms is server_now_ms() milliseconds, and 317's
 * <idle> is the saturating (now_ms - last_active_ms) / 1000 at format
 * time. A wall-clock step must therefore not move the idle number. 317
 * carries the idle alone (#671: one middle parameter per RFC 2812 5.1).
 *
 * In-process against server_t, like test_fanout_gate.c: the idle under test is
 * a fabricated stamp 60 s in the monotonic past, which no wire fixture could
 * produce without sleeping for a minute. The queued reply bytes are read out of
 * the asker's write queue and the 317 line is parsed positionally.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/msg_verbs.h"
#include "core/server.h"
#include "harness/test_util.h"

static server_t g_server;

typedef struct {
    conn_t *c;
    int     pair[2];
} member_t;

static void member_open(member_t *m, const char *nick)
{
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, m->pair) == 0,
                 "socketpair failed for %s", nick);
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(m->pair[i], F_GETFL, 0);

        TF_CHECK(flags >= 0);
        TF_CHECK_MSG(fcntl(m->pair[i], F_SETFL, flags | O_NONBLOCK) == 0,
                     "could not make %s's descriptor nonblocking", nick);
    }
    m->c = conn_new(m->pair[0], CONN_CLIENT);
    TF_CHECK(m->c != NULL);
    if (m->c == NULL) {
        return;
    }
    /* Owned by the node from here on, so server_shutdown() at the foot of
     * main() closes and frees it; see test_fanout_gate.c. */
    TF_CHECK_MSG(server_add_conn(&g_server, m->c) == 0,
                 "could not register %s", nick);
    TF_CHECK_MSG(server_nick_claim(&g_server, nick, m->c) == 0,
                 "could not claim the nickname %s", nick);
    memcpy(m->c->nick, nick, strlen(nick) + 1u);
    memcpy(m->c->user, nick, strlen(nick) + 1u);
    memcpy(m->c->host, "10.0.0.9", sizeof "10.0.0.9");
}

static void member_close_peer(member_t *m)
{
    if (m->pair[1] >= 0) {
        (void)close(m->pair[1]);
        m->pair[1] = -1;
    }
}

/* The asker's queued bytes from `from` onwards, NUL-terminated. */
static void queued(const member_t *m, size_t from, char *out, size_t cap)
{
    const size_t have = conn_write_pending(m->c);
    size_t n = 0;

    TF_CHECK_MSG(out != NULL && cap > 0u, "queued() called with nowhere to write");
    if (out == NULL || cap == 0u) {
        return;
    }
    out[0] = '\0';
    for (size_t i = from; i < have && n + 1u < cap; i++) {
        out[n++] = m->c->wbuf[atomic_load_explicit(&m->c->woff, memory_order_acquire) + i];
    }
    out[n] = '\0';
}

/* WHOIS `target` from `asker`, then parse the 317 <idle> :text line out of
 * the queued bytes. */
static void whois_idle(const member_t *asker, const char *target,
                       unsigned long long *idle)
{
    char line[128];
    char buf[4096];
    message_t msg;
    size_t from = conn_write_pending(asker->c);
    const char *at;
    const char *body;
    char trailing[64];

    (void)snprintf(line, sizeof line, "WHOIS %s", target);
    TF_CHECK_MSG(message_parse(line, &msg) == 0, "could not parse %s", line);
    handle_whois(&g_server, asker->c, &msg);
    message_free(&msg);

    queued(asker, from, buf, sizeof buf);
    at = strstr(buf, " 317 ");
    TF_CHECK_MSG(at != NULL, "no 317 in the WHOIS reply:\n%s", buf);
    if (at == NULL) {
        return;
    }
    body = strstr(at, " 317 ");
    TF_CHECK_MSG(body != NULL, "no 317 in the WHOIS reply:\n%s", buf);
    if (body == NULL) {
        return;
    }
    /* Skip " 317 <asker> <target> ". */
    body += strlen(" 317 ");
    body = strchr(body, ' ');
    TF_CHECK_MSG(body != NULL, "malformed 317 line:\n%s", buf);
    if (body == NULL) {
        return;
    }
    body = strchr(body + 1, ' ');
    TF_CHECK_MSG(body != NULL, "malformed 317 line:\n%s", buf);
    if (body == NULL) {
        return;
    }
    TF_CHECK_MSG(sscanf(body, "%llu :%63[^\r\n]", idle, trailing) == 2,
                 "317's parameters are not <idle> :text; got:\n%s", buf);
}

int main(void)
{
    member_t asker;
    member_t target;
    unsigned long long idle = 0;

    TF_CHECK_MSG(server_init(&g_server, "irc.test") == 0, "server_init failed");
    member_open(&asker, "alice");
    member_open(&target, "bob");

    /* A fresh connection is idle for 0 s: last_active_ms starts at the
     * accept instant, so the difference at format time is sub-second. */
    whois_idle(&asker, "bob", &idle);
    TF_CHECK_MSG(idle == 0ull, "a fresh connection reports idle %llu, not 0", idle);

    /* Advance the idle 60 s into the monotonic past. This is the whole of the
     * "advance tick 60 s" case: the formatter subtracts stamps on the same
     * clock, so it must read exactly 60 whatever the wall clock says.
     * Unsigned backdate: on a machine booted <60 s ago server_now_ms() is
     * smaller than the offset and the subtraction wraps (idle reports 0, not
     * 60). Guard the precondition instead of asserting through it. */
    {
        uint64_t now_ms = server_now_ms();
        TF_CHECK_MSG(now_ms > 0u, "monotonic clock returned 0");
        if (now_ms < 61000u) {
            printf("note: runner uptime %llus < 61 s, backdate would underflow; skipping 60 s case\n",
                   (unsigned long long)(now_ms / 1000u));
        } else {
            target.c->last_active_ms = now_ms - 60000u;
            whois_idle(&asker, "bob", &idle);
            TF_CHECK_MSG(idle == 60ull, "60 s of monotonic idle reports %llu, not 60", idle);
        }
    }

    /* No wall-clock field remains on the 317 line: signon_at is still stamped
     * at accept (connection.c owns that), but it is no longer rendered, so
     * there is nothing here to check against the clock. */

    member_close_peer(&asker);
    member_close_peer(&target);
    server_shutdown(&g_server);
    return 0;
}
