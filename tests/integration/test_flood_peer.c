/* test_flood_peer.c -- peer links get a flood bucket, not an exemption (#540).
 *
 * poll_loop.c used to charge the token bucket only for non-CONN_SERVER lines,
 * so one compromised peer could aim unlimited parse work at the loop thread.
 * Now every framed line spends one token; peers just get the larger bucket
 * (16384 vs 256) because they carry aggregate traffic.
 *
 * Two halves, both on a real CONN_SERVER link whose far end this test owns:
 * a 300-line burst -- a legit netburst, well under 16384 -- must all be
 * dispatched with the link still up; a 40000-line back-to-back flood -- over
 * the 16384 burst, with only ~50/sec refill beside it -- must get the link
 * closed (the far end sees EOF). No 417 is expected on the peer: numerics
 * never go to peers, so the close is the whole response.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a stepped poll or select.
 */
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/connection.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "harness/test_util.h"

#define NODE_NAME "irc.a"

#define LEGIT_LINES 300u
#define FLOOD_LINES 40000u

static int g_listen_fd = -1;

static int test_listen(int *port_out)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof addr;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

/* One peer link: the far end stays with the caller, the near end is a
 * CONN_SERVER conn registered in the node. No handshake runs -- the bucket
 * sits below dispatch, so framing and charging are all this test needs. */
static int peer_link_up(server_t *s, int port, int *far_out, int *node_fd_out)
{
    struct sockaddr_storage peer_addr;
    socklen_t peer_alen = (socklen_t)sizeof peer_addr;
    struct sockaddr_in addr;
    conn_t *pc;
    int far;
    int node_fd;

    far = socket(AF_INET, SOCK_STREAM, 0);
    if (far < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (connect(far, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(far);
        return -1;
    }
    node_fd = accept(g_listen_fd, (struct sockaddr *)&peer_addr, &peer_alen);
    if (node_fd < 0) {
        close(far);
        return -1;
    }
    pc = conn_new(node_fd, CONN_SERVER);
    if (pc == NULL || server_add_conn(s, pc) != 0) {
        close(node_fd);
        close(far);
        return -1;
    }
    *far_out = far;
    *node_fd_out = node_fd;
    return 0;
}

/* Send `n` PING lines in one write; the kernel buffers kilobytes, so a
 * back-to-back burst arrives as a burst rather than a trickle. */
static int send_lines(int fd, unsigned n)
{
    static char buf[8192];
    size_t off = 0;
    size_t total;
    unsigned i;

    for (i = 0; i < n; i++) {
        memcpy(buf + off, "PING x\r\n", 8u);
        off += 8u;
        if (off + 8u > sizeof buf) {
            ssize_t w = send(fd, buf, off, 0);
            if (w != (ssize_t)off) {
                return -1;
            }
            off = 0;
        }
    }
    total = off;
    off = 0;
    while (off < total) {
        ssize_t w = send(fd, buf + off, total - off, 0);
        if (w <= 0) {
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/* Step until the node has dispatched `want` lines or the deadline passes. */
static int drive_until_lines(server_t *s, uint64_t want, int ms)
{
    uint64_t deadline = server_now_ms() + (uint64_t)ms;

    for (;;) {
        (void)poll_loop_step(s, POLL_TICK_MS);
        if (s->n_lines >= want) {
            return 0;
        }
        if (server_now_ms() >= deadline) {
            return -1;
        }
    }
}

/* Step until the conn is reaped or the deadline passes. */
static int drive_until_gone(server_t *s, int fd, int ms)
{
    uint64_t deadline = server_now_ms() + (uint64_t)ms;

    for (;;) {
        (void)poll_loop_step(s, POLL_TICK_MS);
        if (server_conn(s, fd) == NULL) {
            return 0;
        }
        if (server_now_ms() >= deadline) {
            return -1;
        }
    }
}

/* True once the far end sees EOF (the node closed), deadline-bounded. */
static int far_sees_eof(int far, int ms)
{
    uint64_t deadline = server_now_ms() + (uint64_t)ms;

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        char b;
        ssize_t got;

        FD_ZERO(&rfds);
        FD_SET(far, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 20000;
        if (select(far + 1, &rfds, NULL, NULL, &tv) > 0) {
            got = recv(far, &b, 1u, 0);
            if (got == 0) {
                return 1;
            }
        }
        if (server_now_ms() >= deadline) {
            return 0;
        }
    }
}

int main(void)
{
    server_t s;
    int port = 0;
    int far = -1;
    int node_fd = 0;
    uint64_t base;

    g_listen_fd = test_listen(&port);
    TF_CHECK_MSG(g_listen_fd >= 0, "the test could not open its own listener");
    TF_CHECK_MSG(server_init(&s, NODE_NAME) == 0, "server_init failed");
    s.dispatch = NULL; /* the bucket sits below dispatch; none needed */
    TF_CHECK_MSG(server_listen(&s, 0) == 0, "server_listen failed");
    TF_CHECK_MSG(peer_link_up(&s, port, &far, &node_fd) == 0,
                 "the test could not bring up its peer link");

    /* A legit netburst fits the peer bucket and leaves the link up. */
    TF_CHECK_MSG(send_lines(far, LEGIT_LINES) == 0, "burst send failed");
    base = s.n_lines;
    TF_CHECK_MSG(drive_until_lines(&s, base + LEGIT_LINES, 10000) == 0,
                 "the node did not dispatch the peer's %u-line burst "
                 "(got %llu of them); a legit netburst must fit the peer "
                 "bucket",
                 LEGIT_LINES,
                 (unsigned long long)(s.n_lines - base));
    TF_CHECK_MSG(server_conn(&s, node_fd) != NULL,
                 "the peer link is gone after a %u-line burst it should "
                 "have absorbed",
                 LEGIT_LINES);
    TF_CHECK_MSG(far_sees_eof(far, 300) == 0,
                 "the peer saw EOF after a legit burst: the node closed a "
                 "link it should have kept");

    /* Past the 16384 burst, back-to-back, the link is capped. */
    TF_CHECK_MSG(send_lines(far, FLOOD_LINES) == 0, "flood send failed");
    TF_CHECK_MSG(drive_until_gone(&s, node_fd, 60000) == 0,
                 "a peer that sent %u lines back-to-back is still connected; "
                 "the peer bucket must cap it",
                 FLOOD_LINES);
    TF_CHECK_MSG(far_sees_eof(far, 10000) != 0,
                 "the capped peer link never EOF'd at the far end");

    close(far);
    close(g_listen_fd);
    server_shutdown(&s);
    tf_done("flood_peer");
    return 0;
}
