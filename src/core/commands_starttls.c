/* commands_starttls.c -- see commands_starttls.h. The STARTTLS upgrade and
 * its refusal policy, plus the one-line CAP pass-through, verbatim out of
 * commands.c; the dispatch table that names both handlers still lives there.
 */
#include "core/commands_starttls.h"

#include <stdatomic.h>
#include <stdio.h>

#include "core/cap.h"
#include "core/reply.h"
#include "tls_backend.h"

/* CAP. A one-line pass-through to cap.c, and it is here rather than a function
 * pointer straight into cap_handle() so that the dispatch table's entry has the
 * same shape as every other entry in it. The logic is cap.c's; this says only
 * that `CAP` reaches it. */
/* ---------------------------------------------------------------------------
 * STARTTLS, and THE FOUR REFUSALS ARE THE FEATURE
 * ---------------------------------------------------------------------------
 * The upgrade itself is three lines: queue 670, flush it, let the transport take
 * over the socket. Everything that matters is in what this refuses, and each
 * refusal is a rule from a specification rather than a judgement call.
 *
 * ---------------------------------------------------------------------------
 * FIRST: THERE IS NO STARTTLS IN RFC 2812
 * ---------------------------------------------------------------------------
 * This project's Phase 11 pass built an RFC 2812 conformance table by reading the
 * RFC. RFC 2812 defines NO STARTTLS: the string does not appear in it, nor do the
 * numerics 670 and 691, and neither does the word TLS. STARTTLS is an IRCv3
 * extension -- the `tls` capability specification, which is DEPRECATED in favour
 * of `sts` -- and it is the normative source for everything below. Saying so here
 * rather than leaving a future reader to assume the RFC says it is the difference
 * between a documented citation and a plausible one, and the `sts` specification's
 * own relationship section is what makes the point: STS "is incompatible with
 * servers that offer secure connections only via STARTTLS on an insecure port."
 * STARTTLS is implemented because the command is real and clients use it; `sts` is
 * advertised because it is the mechanism that actually protects anything.
 *
 * ---------------------------------------------------------------------------
 * THE REFUSALS, in the order they are checked, and why that order
 * ---------------------------------------------------------------------------
 *   1. NOT CONFIGURED     this build has no TLS, or this node has no certificate.
 *                         691. Checked FIRST because it is the only one that is a
 *                         permanent property of the node: everything below is a
 *                         statement about this connection.
 *
 *   2. ALREADY TLS        691. Refusing is not politeness -- it is arithmetic. A
 *                         second STARTTLS would mean a second handshake layered
 *                         inside the first one's session, and a client that
 *                         expected one would read the ServerHello as IRC and hang.
 *
 *   3. AFTER A CREDENTIAL 691, AND THIS IS THE ONE THAT IS EASY TO GET WRONG. The
 *                         whole point of upgrading is that what follows is private.
 *                         If a client has already sent a password, upgrading does
 *                         not un-send it: an attacker who has been reading the
 *                         plaintext prefix has the credential, and everything after
 *                         the upgrade being encrypted is a very comfortable
 *                         theatre. So a connection that has carried a PASS value or
 *                         an AUTHENTICATE payload is REFUSED -- including when the
 *                         credential was refused, which is what
 *                         conn_t::credential_seen's comment is about.
 *
 *                         IT IS CHECKED BEFORE THE REGISTRATION RULE BELOW, and
 *                         that is a decision rather than an ordering accident: see
 *                         the comment at the check.
 *
 *   4. AFTER REGISTRATION 691. The `tls` specification: "To use STARTTLS a client
 *                         simply sends the STARTTLS command to the server BEFORE
 *                         THE CLIENT REGISTERS WITH THE SERVER USING THE NICK AND
 *                         USER COMMANDS". After registration this node has already
 *                         emitted 001-005, MOTD and possibly a JOIN; a client that
 *                         re-handshakes mid-registration has a burst half-sent in
 *                         the clear and the rest encrypted, and a peer relaying
 *                         those lines sees two different transports on one
 *                         connection. There is no version of this that is safe to
 *                         allow, and the specification's position is that it is not
 *                         a thing to allow.
 *
 * A legitimate client costs nothing by this: every current client that wants TLS
 * either connects to the implicit-TLS port (RFC 7194) or sends STARTTLS first
 * thing, before NICK and USER. The order is not an inconvenience; it is the
 * specification's.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DISCARDED ON SUCCESS, and it is a security step rather than a tidy-up
 * ---------------------------------------------------------------------------
 * `c->rlen = 0` below. The read buffer may hold lines the client PIPELINED behind
 * its STARTTLS -- `STARTTLS\r\nJOIN #x\r\n` in one segment, which every capable
 * client library will do -- and those lines arrived IN THE CLEAR, before the peer
 * proved anything. Leaving them in the buffer would mean dispatching them after the
 * handshake, as though they had arrived over the encrypted connection: an attacker
 * who could inject into the plaintext prefix could have them executed on a
 * connection the operator believes is authenticated and encrypted.
 *
 * The write queue is NOT cleared, and the asymmetry is deliberate: everything in it
 * was queued before the upgrade and is being sent in the clear legitimately (the
 * 670 itself is in there), and the node has nothing it would be ashamed to send
 * before a handshake.
 *
 * ---------------------------------------------------------------------------
 * 670 AND 691 ARE NOT IN RFC 2812 EITHER
 * ---------------------------------------------------------------------------
 * They come from the same deprecated `tls` extension, which gives them verbatim:
 * "the server then sends numeric 670 (RPL_STARTTLS)" and "If there is an error
 * with setting up TLS on the server side, the server must send numeric 691
 * (ERR_STARTTLS) containing a human-readable description of the error as its
 * parameter." RFC 2812 4.5 assigns 6xx to ERR_* and 670/691 fall in that range, so
 * the shape is the RFC's even though the two numbers are not. Every 691 below
 * carries a distinct text, because the specification says the text is for a human
 * and a client cannot machine-parse it: an operator reading the log needs to know
 * WHICH rule fired, and one shared "STARTTLS failed" would be the least useful
 * thing in the file. */
void handle_starttls(server_t *s, conn_t *c, const message_t *m)
{
    /* ARITY FIRST, and it is 461 rather than 691. A STARTTLS with a parameter is a
     * malformed command, and 461 is this node's answer for that everywhere else; a
     * 691 here would claim the server tried and failed at TLS on a line that never
     * named TLS. */
    if (m->nparams > 0) {
        (void)reply_refused(s, c, "STARTTLS", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (tls_backend_available() == 0 || s->tls == NULL) {
        (void)reply(s, c, "691", NULL, 0, "STARTTLS failed: TLS is not available "
                                            "on this server");
        printf("[observable] starttls_refused: fd=%d reason=TLS_NOT_CONFIGURED\n",
               c->fd);
        return;
    }
    if (c->tls_active != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: this connection is already using TLS");
        printf("[observable] starttls_refused: fd=%d reason=ALREADY_TLS\n", c->fd);
        return;
    }
    /* THE CREDENTIAL CHECK COMES BEFORE THE REGISTRATION CHECK, and the order is
     * the point.
     *
     * Both are refusals and both are correct, so the only question is which reason
     * an operator and a client are told -- and a client that has sent a password
     * AND then registered has done both things, and the one it needs to hear about
     * is that its password went out in the clear. "it is only available before
     * registration" would be true and would hide the finding that matters: that this
     * node is being asked to make an encrypted connection out of a socket that has
     * already leaked a credential, and that somebody needs to go and change it.
     *
     * Checking registration first was the first version, and it produced exactly
     * that: a client which sent PASS, NICK, USER, STARTTLS -- which is what a
     * client that has decided to authenticate does -- was told it was too late,
     * with no mention of the password. A refusal that is true and incomplete is
     * worse than one that is verbose. */
    if (c->credential_seen != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: a credential has already been sent on this "
                    "connection in the clear");
        printf("[observable] starttls_refused: fd=%d "
               "reason=AFTER_CREDENTIAL\n", c->fd);
        return;
    }
    if (atomic_load_explicit(&c->state, memory_order_acquire) != CONN_REG_PASS) {
        int st = atomic_load_explicit(&c->state, memory_order_acquire);
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: it is only available before registration");
        printf("[observable] starttls_refused: fd=%d reason=AFTER_REGISTRATION "
               "state=%d\n", c->fd, st);
        return;
    }
    /* THE DISCARD, before the confirmation and not after it: a line that arrived
     * in the clear must never be dispatched after the handshake. */
    c->rlen = 0;
    /* The 670, in the clear, with the specification's own wording. It is QUEUED
     * and not sent, and this handler never touches the socket -- which is not a
     * style preference but reply.c's whole rule, the one
     * tests/integration/test_reply_guard.c asserts by inspection: a handler that
     * reaches past reply() into the transport is a second place that decides what
     * reaches a connection.
     *
     * THE ORDERING IS NONE THE WORSE FOR IT, and that is the part worth checking.
     * conn_queue() raises want_write, so the loop's very next poll set asks for
     * POLLOUT; conn_on_writable() drains the queue through conn_pump(); and
     * conn_pump() starts the handshake only once the queue is EMPTY. So the 670 is
     * on the wire before the first byte of the handshake by construction, and it is
     * on the wire because the LOOP put it there.
     *
     * An earlier version of this handler called conn_pump() directly, to make the
     * 670 prompt. That cost test_reply_guard's invariant for no benefit: the loop
     * flushes within one tick either way, because the socket is writable. That is
     * what a suite is for -- the rule was written before this handler existed and
     * it was right. */
    c->starttls_pending = 1;
    (void)reply(s, c, "670", NULL, 0, "STARTTLS successful, proceed with TLS "
                                      "handshake");
    printf("[observable] starttls_agreed: fd=%d\n", c->fd);
}

void handle_cap_wrapper(server_t *s, conn_t *c, const message_t *m)
{
    cap_handle(s, c, m);
}
