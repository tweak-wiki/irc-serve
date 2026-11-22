/* test_shutdown_goodbye.c -- issue #272: the shutdown goodbye reaches the wire.
 *
 * Graceful shutdown queues a SHUTDOWN to every ESTABLISHED peer and pumps it
 * before any socket closes, so the mesh treats a restart as a leave rather
 * than a crash. The regression shape is the original bug exactly: the goodbye
 * queued but never sent, freed with the write buffer, so every planned
 * restart looked like a crash (peers retry with backoff and hold roster
 * ghosts until timeout).
 *
 * The assertion is on the RECEIVING node's log, not the sender's: the sender
 * prints fed_shutdown_sent: when the line is QUEUED, so a sender-side wait
 * stays green even if the pump is removed and the bytes die in the freed
 * buffer. Only the peer seeing `fed_shutdown:` proves the bytes crossed the
 * socket, were framed, and were applied as a clean leave (clean_leave=1,
 * retried=0 -- no retry ladder, no crash handling).
 *
 * No fixed sleep(): the link precondition and both goodbye waits are
 * nf_expect() deadline loops.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define SECRET "irc-serve-shutdown-goodbye-secret"
#define NAME_A "irc.a"
#define NAME_B "irc.b"

static int g_peer_port;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0, "fed_open() failed in the child");
    s->on_tick = child_tick;
    fed_set_timeouts(s, 5000, 5000, 30000, 90000);
    if (g_peer_port <= 0) {
        return; /* the accepting side; the inbound claim configures its link */
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", NAME_A,
                 g_peer_port);
}

int main(void)
{
    nf_node_t a;
    nf_node_t b;

    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);

    /* Graceful shutdown of A: SIGTERM breaks the loop, server_shutdown()
     * queues the SHUTDOWN and pumps it before any close() runs. */
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_expect(&a, "fed_shutdown_sent:", T_IO_MS) == 0,
                 "node A sent no SHUTDOWN goodbye on the way out: %s", a.out);

    /* THE ON-WIRE PROOF: B received the goodbye, applied it, and marked the
     * leave clean -- retried=0 means no crash path, no retry ladder. If the
     * goodbye died in A's freed write buffer, B sees EOF/read_error instead
     * and this wait expires. */
    TF_CHECK_MSG(nf_expect(&b, "link_clean_leave: peer=" NAME_A
                               " reason=PEER_SHUTDOWN",
                           T_IO_MS) == 0,
                 "node B never marked node A's departure clean: %s", b.out);
    TF_CHECK_MSG(nf_expect(&b, "[observable] fed_shutdown: peer=" NAME_A,
                           T_IO_MS) == 0,
                 "node B never received node A's SHUTDOWN goodbye: %s", b.out);

    (void)nf_stop(&b);
    nf_free(&a);
    nf_free(&b);
    tf_done("shutdown_goodbye");
    return 0;
}
