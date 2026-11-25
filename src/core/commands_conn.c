/* commands_conn.c -- see commands_conn.h. The connection-lifecycle family
 * (PING/PONG/QUIT), verbatim out of commands.c; the table that calls the
 * handlers still lives there.
 */
#include "core/commands_conn.h"

#include <stdio.h>
#include <string.h>

#include "core/fanout.h"
#include "core/reply.h"

/* PING. Legal before registration, like every liveness probe: a client that
 * sent NICK and USER in one segment and then PINGs must get its answer, and a
 * client stuck mid-registration must be able to tell the node is alive. */
void handle_ping(server_t *s, conn_t *c, const message_t *m)
{
    const char *token = (m->nparams > 0) ? m->params[0] : NULL;

    /* A PING with no argument is answered with the server name (RFC 1459 2.4);
     * send_pong() applies that to an absent or empty token. */
    (void)send_pong(s, c, token);
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        /* The token is an OPAQUE STRING THE CLIENT MADE UP, and this is the only
         * place it is ever rendered. It reaches the wire too -- inside the PONG --
         * but that goes back to the client that sent it, so the log is where the
         * hazard is: `PING <ESC>[2J` put a control byte in an operator's terminal
         * from one line, before registration. */
        (void)conn_text_logsafe(shown, sizeof shown, token);
        printf("[observable] ping: fd=%d token=%s token_len=%zu token_bad_bytes=%zu\n",
               c->fd, shown, (token != NULL) ? strlen(token) : 0u,
               conn_text_bad_count(token));
    }
}

/* PONG. Accepted and answered with nothing: a PONG is a reply to something the
 * client believes is outstanding, so the protocol is satisfied by the client
 * having received it. Answering a PONG with a PONG is how a naive
 * implementation starts a storm. */
void handle_pong(server_t *s, conn_t *c, const message_t *m)
{
    (void)s; /* the accepted PONG answers nothing, so it needs no node state */
    {
        const char *tok = (m->nparams > 0) ? m->params[0] : NULL;
        char shown[CONN_LOG_FIELD_MAX + 1u];

        /* The same rule as PING, and the same reason: this token is echoed to the
         * log and to nobody else. A PONG is the one line a client can send whose
         * entire content is attacker-chosen and unexamined, so it is the cheapest
         * injection on this node and it is closed by the same shared predicate. */
        (void)conn_text_logsafe(shown, sizeof shown, tok);
        printf("[observable] pong: fd=%d token=%s token_len=%zu token_bad_bytes=%zu\n",
               c->fd, shown, (tok != NULL) ? strlen(tok) : 0u,
               conn_text_bad_count(tok));
    }
}

/* QUIT. Release the nickname, then mark the connection CLOSING.
 *
 * It does NOT close the descriptor. 3.4: the send path never closes a
 * connection, and a reaper at a fixed point in the loop is the single place an
 * fd is closed. Closing here would break that invariant in the most
 * load-bearing way available -- the close count is what the reaper's
 * idempotence is checked against, and a second close path makes every one of
 * those tests weaker.
 *
 * c->nick is deliberately left set. The reaper retires the connection again, and
 * because the table no longer maps any name to this conn by then, that call is a
 * no-op -- unless some other client has already taken the name, in which case
 * retiring the connection removes the new holder's entry only if the table still
 * points at THIS conn, which is exactly what stops a closing conn from evicting
 * its successor on the way out.
 *
 * The release here is therefore belt to those braces rather than the only thing
 * holding them up: server_close_conn() retires the nickname for every close
 * whatever caused it, so the name is safe even if this line were forgotten. It
 * is kept because this is the semantically right place for it, and because "safe
 * if you forget" is a property of the design worth being able to rely on rather
 * than a reason to stop being explicit.
 *
 * It is the same function the reaper calls, and that is not tidiness. QUIT and a
 * client that vanishes without one are the two ways a connection ends, and they
 * used to release the name by different routes -- the handler through the
 * name-keyed release, the reaper by hand. That difference is issue #102: the
 * reaper's hand-written half removed the table entry and left the enumeration
 * entry, so a freed conn_t stayed in WHO's walk. A QUIT hid it, because the
 * handler had already done the vector's half correctly. */
void handle_quit(server_t *s, conn_t *c, const message_t *m)
{
    const char *reason = (m->nparams > 0) ? m->params[0] : NULL;

    server_nick_unclaim(s, c);
    /* The reason is logged, never stored: there is no NickServ, no quit cache,
     * and no reason for one to exist until Phase 9.
     *
     * WHICH MAKES IT A LOG-ONLY FIELD, and that is the whole policy: measured, not
     * filtered. A `QUIT :<ESC>[2J` reached an operator's terminal raw, and unlike
     * the away message this value is never relayed to another client, so there is
     * no reader downstream to protect and a stripped copy would only be a shorter
     * lie about what the client sent. The length is reported beside the value
     * because a reason is free text of unbounded length -- up to the line cap --
     * and a withheld one has to be diagnosable.
     *
     * NOT TRUNCATED, which is why the field is withheld rather than shortened when
     * it exceeds the print width. A log line that cut a sentence in half would be
     * a different sentence from the one the client sent, and 3.2's rule against
     * silently shortening a parameter is about exactly that even here. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, reason);
        printf("[observable] quit: fd=%d nick=%s reason=%s reason_len=%zu "
               "reason_bad_bytes=%zu\n",
               c->fd, c->nick, shown, (reason != NULL) ? strlen(reason) : 0u,
               conn_text_bad_count(reason));
    }
    /* Issue #609: the QUIT line itself, to the union of this connection's
    * channels, excluding the quitter. Without it chan_conn_gone() renders
    * the departure as one PART per channel, and a QUIT is not a PART --
    * every client keys away-tracking and bouncer replay on the difference.
    * The reason is stripped once here (STRIP_STORED, like the fed departure
    * path); it is never refused, because a QUIT must quit. */
    if (c->nchans > 0u) {
        char qprefix[CONN_HOSTMASK_MAX];
        char qreason[IRC_MAX_LINE + 1u];
        const char *qp[1];
        fanout_form_t qplain;
        int qdelivered = 0;

        if (conn_hostmask(c, qprefix, sizeof qprefix) != 0) {
            qplain.params = NULL;
            qplain.nparams = 0;
            if (reason != NULL && reason[0] != '\0') {
                (void)conn_text_strip(qreason, sizeof qreason, reason,
                                      STRIP_STORED);
                qp[0] = qreason;
                qplain.params = qp;
                qplain.nparams = 1;
            }
            qdelivered = fanout_deliver_union_local_gated(
                s, c->chans, c->nchans, qprefix, "QUIT", &qplain, NULL, NULL,
                NULL, c);
            c->quit_announced = 1;
        } else {
            printf("[observable] quit_notify: nick=%s reason=UNRENDERABLE\n",
                   c->nick);
        }
        printf("[observable] quit_notify: nick=%s channels=%zu recipients=%d\n",
               c->nick, c->nchans, qdelivered);
    } else {
        c->quit_announced = 1;
    }
    conn_mark_closing(c);
}
