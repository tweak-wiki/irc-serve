/* server_listen.c -- see core/server.h. The listener arms
 * (server_listen/server_port/server_tls_port/server_listen_tls/
 * server_accept_tls_one), verbatim out of server.c (issue #543); the lifecycle,
 * clock, tick and shutdown stay there. The listen functions were already
 * declared in core/server.h and the block has no static helpers, so there is
 * no new header (server_dial.c precedent).
 */
#include "core/server.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Accept-time nonblocking helper, peer describer and registry add, defined in
 * server_conns.c. */
#include "core/server_conns.h"
/* Phase 12: the implicit-TLS accept hands the socket to the TLS transport. */
#include "core/transport.h"

int server_listen(server_t *s, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    if (s == NULL || port < 0 || port > 65535) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    /* Nonblocking BEFORE the fd is reachable by the loop. 3.4: the loop never
     * blocks, and an fd that is briefly blocking is a stall for every other
     * client on the node. */
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    s->listen_fd = fd;
    return 0;
}

int server_port(const server_t *s)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    if (s == NULL || s->listen_fd < 0) {
        return -1;
    }
    if (getsockname(s->listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

int server_tls_port(const server_t *s)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    if (s == NULL || s->tls_listen_fd < 0) {
        return -1;
    }
    if (getsockname(s->tls_listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

/* ---------------------------------------------------------------------------
 * THE IMPLICIT-TLS LISTENER (Phase 12), and why it is a SECOND LISTENER
 * ---------------------------------------------------------------------------
 * server_listen_tls() is server_listen() again with two differences, and both of
 * them are load-bearing rather than incidental.
 *
 * THE SECOND LISTENER. IRCv3's `sts` specification is explicit that it does not
 * work over a STARTTLS-only port: "STS expects that servers instead offer a port
 * that directly services secure connections and it is incompatible with servers
 * that offer secure connections only via STARTTLS on an insecure port." So a node
 * that wants to advertise `sts` -- which is the mechanism that stops a client
 * being downgraded after the first connection, and therefore the only part of this
 * phase that protects a return visit -- needs a port a client can connect to and be
 * encrypted from the first byte. That is this listener, on RFC 7194's 6697.
 *
 * THE REFUSAL WHEN THERE IS NO TLS. Refused rather than started, because a node
 * whose --tls-port is bound and which then serves PLAINTEXT on it is the worst
 * possible outcome: the operator typed a TLS port, a client sees 6697 and expects
 * a handshake, and gets IRC in the clear instead. There is no configuration in
 * which this function binds a port it cannot encrypt, and that is the whole of
 * the safety property here.
 *
 * THE CODE IS server_listen()'S AND NOT A REFACTOR OF IT. Duplicating twenty lines
 * of bind/listen/nonblocking is cheaper than a `int is_tls` parameter on
 * server_listen(), because a parameter would make every existing caller think about
 * a mode it does not have, and this codebase's own convention
 * (server_conns_set_nonblocking()'s comment) is that a descriptor must be
 * nonblocking BEFORE it is reachable from the loop -- which is a sequence
 * worth reading in one piece at each site rather than branching inside. */
int server_listen_tls(server_t *s, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    if (s == NULL || port < 0 || port > 65535) {
        return -1;
    }
    /* THE REFUSAL, and it is checked BEFORE socket(). There is no point creating a
     * descriptor this node is not going to be able to use, and on a build without
     * TLS there is no point at all.
     *
     * IT IS DEFENCE IN DEPTH AND NO TEST COVERS IT, and both halves of that are
     * deliberate. main() already refuses `--tls-port` when no certificate was
     * supplied, so this branch is UNREACHABLE through the shipped binary --
     * tests/integration/test_tls.c deletes it and stays green, which is how it was
     * found. It is kept because this function is public and a future caller that
     * does not go through main() would otherwise bind a port it cannot encrypt.
     * See test_tls.c's case_one_named_gap() for why there is no inspection
     * assertion on it either. */
    if (s->tls == NULL) {
        printf("[observable] tls_listen: state=REFUSED port=%d "
               "reason=NO_TLS_CONFIGURED\n", port);
        return -1;
    }
    if (s->tls_listen_fd >= 0) {
        /* One implicit-TLS listener. A second one would be a second place an
         * operator's intent about this node's TLS surface is recorded, and this
         * struct already has one (`tls_listen_port`). */
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    s->tls_listen_fd = fd;
    s->tls_listen_port = port;
    return 0;
}

/* Accept ONE connection on the implicit-TLS listener and hand the socket straight
 * to the TLS transport. Returns 1 on success, 0 when nothing is pending, -1 on a
 * fatal accept error, or SERVER_ACCEPT_REJECTED for the FD_SETSIZE rejection --
 * the same vocabulary server_accept_one() uses, so the loop's drain loop over the
 * TLS listener is character-for-character the drain loop over the plain one.
 *
 * THE HANDSHAKE IS NOT DONE HERE, and the difference matters: this is a nonblocking
 * node and a TLS handshake is several round trips. So the connection is registered
 * with a TLS transport whose handshake has only been STARTED, and the loop carries
 * it to completion on its own schedule -- which is exactly the case conn_t::want_read
 * and the empty pass in conn_pump() exist for, and which could not be expressed at
 * all in a loop that derived its poll mask from data.
 *
 * THE ORDER IS: accept, nonblocking, conn_new, ADD THE CONNECTION, and only then
 * start TLS. server_add_conn() sets conn_t::owner, which the backend needs to find
 * the node's SSL_CTX, so starting TLS first would find a conn with no node. That is
 * why the two steps are not swapped, and why transport_starttls() reports
 * NOT_CONFIGURED rather than dereferencing NULL. */
int server_accept_tls_one(server_t *s)
{
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof peer;
    conn_t *c;
    int fd;

    if (s == NULL || s->tls_listen_fd < 0) {
        return -1;
    }
    for (;;) {
        fd = accept(s->tls_listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
#if defined(EMFILE) || defined(ENFILE)
            if (errno == EMFILE || errno == ENFILE) {
                return 0;
            }
#endif
            return -1;
        }
        break;
    }
    /* 3.4's explicit FD_SETSIZE check, for the same reason and with the same
     * consequence as at the plaintext accept site: poll() would silently drop it. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        printf("[observable] accept_rejected: fd=%d reason=fd_ge_fdsize limit=%d "
               "transport=tls\n", fd, FD_SETSIZE);
        return SERVER_ACCEPT_REJECTED;
    }
    if (server_conns_set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    c = conn_new(fd, CONN_CLIENT);
    if (c == NULL) {
        close(fd);
        return -1;
    }
    server_conns_describe_peer(c, (const struct sockaddr *)&peer);
    if (server_add_conn(s, c) != 0) {
        conn_free(c);
        close(fd);
        return -1;
    }
    if (transport_starttls(c, 1) != 0) {
        /* The handshake could not even be STARTED, which on this build means the
         * node's TLS state went away between the listener being bound and this
         * accept. The connection is closed rather than left in the clear, and the
         * reason is counted and printed: a node that silently served a plaintext
         * connection on its TLS port is exactly the failure this whole phase
         * exists to prevent. */
        s->n_tls_handshake_failed++;
        printf("[observable] tls_handshake_failed: fd=%d reason=START_FAILED "
               "transport=implicit action=CLOSE\n", fd);
        conn_mark_closing(c);
        return 1;
    }
    printf("[observable] client_connect: fd=%d host=%s state=REG_PASS "
           "transport=tls\n", fd, c->host);
    return 1;
}
