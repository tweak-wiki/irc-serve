/* test_mode_forward_mask.c -- #273: a forwarded +b with an over-long mask
 * answers the client.
 *
 * `handle_mode()`'s forward arm refused a mask longer than CHAN_MAX_BAN with a
 * log line and a bare return -- no numeric to the client. The owned path
 * answers 417 for the same condition, so a client on a non-owning node waited
 * for a change the origin would refuse, with nothing on the wire saying so.
 *
 * In-process, because reaching the forward arm from the wire is not possible
 * with two of this node's own nodes: op status comes only from `chan_join()`
 * (first member) or `handle_mode()`'s own +o arm (which needs op already), so
 * no client on a non-owning node can ever be op and the wire path is
 * unreachable. The arm is therefore driven directly: a server whose channel
 * origin names a linked peer (ESTABLISHED link rig, as in test_dedup_error.c),
 * with a local member granted op by hand, fed a parsed MODE line with a
 * 400-byte mask.
 *
 * Two assertions: the client receives the 417, and nothing went to the peer
 * (forwarded=0 -- the peer conn's queue stays empty). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "federation/link.h"
#include "federation_handshake.h"
#include "harness/test_util.h"

#define NODE_NAME "irc.test"
#define PEER_NAME "irc.b"
#define CHAN "#t"

/* A route to PEER_NAME: an ESTABLISHED link whose fd names a registered
 * CONN_SERVER conn. server_find_peer() resolves link -> state -> by_fd, so a
 * link with fd -1 (as in test_dedup_error.c, which only needs the link NAME)
 * is ORPHANED here -- its whole point there is not needing the route. The
 * socketpair's peer end is never read; nothing here pumps. */
static void link_rig(server_t *s, conn_t **peer_out, int *peer_fd_out)
{
    server_link_t *l;
    conn_t *peer;
    int pair[2];

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                 "socketpair failed for the peer link");
    peer = conn_new(pair[0], CONN_SERVER);
    TF_CHECK_MSG(peer != NULL, "conn_new() failed for the peer connection");
    TF_CHECK_MSG(server_add_conn(s, peer) == 0, "peer conn not registered");
    peer->peer_name = (char *)malloc(strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(peer->peer_name != NULL, "could not set the peer's name");
    memcpy(peer->peer_name, PEER_NAME, strlen(PEER_NAME) + 1u);

    s->links = (server_link_t *)calloc(IRC_FED_MAX_PEERS, sizeof *s->links);
    TF_CHECK_MSG(s->links != NULL, "could not allocate the link vector");
    s->links_cap = (size_t)IRC_FED_MAX_PEERS;
    s->nlinks = 1;
    l = &s->links[0];
    memcpy(l->name, PEER_NAME, strlen(PEER_NAME) + 1u);
    l->fd = pair[0];
    handshake_init(&l->hs);
    l->hs.state = ESTABLISHED;
    l->state = (int)l->hs.state;
    *peer_out = peer;
    *peer_fd_out = pair[1];
}

int main(void)
{
    server_t s;
    chan_t *ch;
    conn_t *c = NULL;
    conn_t *peer = NULL;
    int peer_fd = -1;
    int cpair[2];
    message_t m;
    char mask[400 + 1u];
    char line[512];
    size_t from;

    TF_CHECK_MSG(server_init(&s, NODE_NAME) == 0, "server_init failed");
    link_rig(&s, &peer, &peer_fd);

    /* The client: a registered conn with a real fd, nick/user/host filled as
     * accept() would fill them, claimed so queued numerics have a target. */
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, cpair) == 0,
                 "socketpair failed for the client");
    c = conn_new(cpair[0], CONN_CLIENT);
    TF_CHECK_MSG(c != NULL, "conn_new() failed for the client");
    TF_CHECK_MSG(server_add_conn(&s, c) == 0, "client conn not registered");
    memcpy(c->nick, "bob", sizeof "bob");
    memcpy(c->user, "bob", sizeof "bob");
    memcpy(c->host, "10.0.0.9", sizeof "10.0.0.9");
    TF_CHECK_MSG(server_nick_claim(&s, "bob", c) == 0, "nick claim failed");

    /* The channel: origin names the linked peer (forward verdict), with bob
     * a member granted op by hand -- op has no other writer reachable here. */
    ch = chan_new(CHAN, PEER_NAME, s.epoch);
    TF_CHECK_MSG(ch != NULL, "chan_new failed");
    TF_CHECK_MSG(server_chan_attach(&s, ch) == 0, "chan attach failed");
    TF_CHECK_MSG(chan_add_member(ch, c, CHAN_MEMBER_OP) == 0, "join failed");

    /* A 400-byte mask, shaped as a plausible mask rather than bare filler. */
    memset(mask, 'a', sizeof mask - 1u);
    mask[0] = '*';
    mask[1] = '!';
    mask[2] = '@';
    mask[sizeof mask - 1u] = '\0';
    (void)snprintf(line, sizeof line, "MODE %s +b %s", CHAN, mask);
    TF_CHECK_MSG(message_parse(line, &m) == 0, "the MODE line does not parse");

    from = conn_write_pending(c);
    handle_mode(&s, c, &m);

    /* THE NUMERIC: 417, the same answer the owned path gives, byte-identical
     * to the owned-path line test_banlist.c asserts. */
    {
        size_t have;
        char got[512];
        size_t n = 0;

        have = conn_write_pending(c);
        TF_CHECK_MSG(have > from, "the client received nothing: no numeric "
                     "was sent for the refused forward");
        for (size_t i = from; i < have && n + 1u < sizeof got; i++) {
            got[n++] = c->wbuf[atomic_load_explicit(&c->woff, memory_order_acquire) + i];
        }
        got[n] = '\0';
        TF_CHECK_MSG(strstr(got, " 417 bob :Input line was too long\r\n") != NULL,
                     "no 417 in the client's queue.\n  got: %s", got);
    }

    /* THE ORIGIN SAW NOTHING: nothing was forwarded. */
    TF_CHECK_MSG(conn_write_pending(peer) == 0u,
                 "the refused mask was forwarded: peer queue holds %zu bytes",
                 conn_write_pending(peer));

    message_free(&m);
    close(cpair[1]);
    close(peer_fd);
    /* Owned by the node now: freed through its own exit path. */
    server_shutdown(&s);
    tf_done("mode_forward_mask");
    return 0;
}
