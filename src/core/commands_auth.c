/* commands_auth.c -- see commands_auth.h. The AUTHENTICATE family, verbatim out
 * of commands.c; the table that calls handle_authenticate() still lives there.
 */
#include "core/commands_auth.h"

#include <stdio.h>
#include <string.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/reply.h"
#include "core/secret_util.h"
#include "core/transport.h"
#include "account_store.h"
#include "sasl_framework.h"
#include "tls_backend.h"
/* AUTHENTICATE, RFC 4422 3.1 / IRCv3 sasl.
 *
 *   AUTHENTICATE PLAIN                 -> server: AUTHENTICATE +
 *   AUTHENTICATE PLAIN <base64>        -> one-shot, verified
 *   AUTHENTICATE <base64>              -> the response to the '+'
 *   AUTHENTICATE *                     -> the client abandons the exchange
 *
 * The '+' is the initial-response request: it asks the client to send a
 * PLAIN payload without naming the mechanism again, which is the form every
 * client actually uses and the form that would be impossible to answer if this
 * node only understood a mechanism on the first line.
 *
 * ---------------------------------------------------------------------------
 * WHAT A BAD CREDENTIAL DOES
 * ---------------------------------------------------------------------------
 * It fails REGISTRATION, and that is the requirement this design is explicit
 * about rather than incidental. The three responses are, in order:
 *
 *   1. `AUTHENTICATE *` -- RFC 4422's server-chosen abort. It tells the client the
 *      exchange is over, so a client that is waiting for a verdict gets one and
 *      does not wait for a deadline.
 *   2. `904 ERR_SASLFAIL` -- SASL's own numeric for credentials that did not
 *      take. NOT 908 (RPL_SASLMECHS, which would offer the client a second try at
 *      a credential it just got wrong, turning one failure into an unlimited
 *      guessing loop) and NOT 451.
 * The connection is NOT closed here, and the reason is a property of the loop
 * rather than a judgement about the client: poll_loop.c refuses to pump the write
 * queue of a CONN_CLOSING connection, and the reaper frees that queue with the
 * conn_t. Marking CLOSING in the same dispatch that queues the abort and the 904
 * would DISCARD BOTH, so a client whose credential failed would see a bare FIN
 * with no explanation -- strictly worse than telling it. So the connection is
 * left open and unusable: commands_state_update() refuses the transition while
 * c->sasl is SASL_FAILED, so every non-registration command is 451 and 001 can
 * never arrive.
 *
 * THE COST, stated rather than hidden: a client that neither disconnects nor
 * gives up holds one slot in by_fd and one write queue until it goes away, and
 * nothing here closes it for it. The slot is bounded by SERVER_FD_TABLE, so this
 * is a cap on how many such connections can exist rather than an unbounded leak,
 * and the alternative -- an immediate close that throws away the explanation --
 * is worse. Closing them on the next poll iteration would need a second state
 * that distinguishes "closing after the reason was queued" from every other
 * CLOSING, which is a loop change and not an authentication one.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS AND IS NOT IN THE [observable] LINE
 * ---------------------------------------------------------------------------
 * The authcid and the outcome. NEVER the password, the base64 payload, or the
 * authzid -- and the authzid is excluded for a reason beyond tidiness: it is a
 * third field of the payload and a caller-supplied string that a client can put
 * anything in, so logging it adds an injection vector to the log for no
 * diagnostic gain. The authcid is a login name and the operator needs it; the
 * other two are the credential.
 *
 * The payload is also not rendered into a buffer anywhere on this path: it is
 * decoded into a stack array, split, verified, and scrubbed -- every return
 * below runs auth_wipe_credential() over all four locals, so the bytes do not
 * survive in the dead frame for the next call to reuse. There is no place in
 * this function where a credential could be printed by accident later, because
 * no variable holds one afterwards. */
/* Overwrite `n` bytes at `p`, through a volatile pointer: a memset() to a stack
 * buffer whose frame is about to be reused is a store the compiler may prove
 * dead and delete, which is why secret_util.h's secret_wipe() does the same. */
static void auth_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    for (size_t i = 0; i < n; i++) {
        v[i] = 0u;
    }
}

/* Scrub the four locals handle_authenticate() decodes the credential into. One
 * call site per buffer rather than four wipes inline, so the ten returns below
 * cannot scrub three and forget one. */
static void auth_wipe_credential(unsigned char *payload, char *authzid,
                                 char *authcid, char *passwd)
{
    auth_wipe(payload, SASL_MAX_PAYLOAD);
    auth_wipe(authzid, SASL_MAX_AUTHCID + 1u);
    auth_wipe(authcid, SASL_MAX_AUTHCID + 1u);
    auth_wipe(passwd, SASL_MAX_PASSWORD + 1u);
}

/* #539: process-wide credential-verification budget, the flood bucket's shape
 * (#168) applied to the KDF instead of to lines. Burst 64 absorbs a restart
 * storm and the terminal sweep's 61-probe SASL pass; 2/sec sustained is orders
 * of magnitude above legitimate login rate and bounds loop time stolen by a
 * reconnect+login loop to ~2 KDFs/sec. */
#define AUTH_BURST 64.0
#define AUTH_REFILL_PER_SEC 2.0

/* Spend one verification token. 1 when the caller may hash, 0 when the bucket
 * is empty and the caller must refuse WITHOUT verifying. A refusal here sets
 * no state and counts no failure, so a legitimate client simply retries. */
static int auth_try_spend(server_t *s)
{
    uint64_t now = server_now_ms();

    if (s->auth_last_ms == 0u) {
        s->auth_tokens = AUTH_BURST;
        s->auth_last_ms = now;
    } else if (now > s->auth_last_ms) {
        s->auth_tokens += (double)(now - s->auth_last_ms) *
                          (AUTH_REFILL_PER_SEC / 1000.0);
        if (s->auth_tokens > AUTH_BURST) {
            s->auth_tokens = AUTH_BURST;
        }
        s->auth_last_ms = now;
    }
    if (s->auth_tokens < 1.0) {
        return 0;
    }
    s->auth_tokens -= 1.0;
    return 1;
}

void handle_authenticate(server_t *s, conn_t *c, const message_t *m)
{
    const char *mech = NULL;
    const char *arg = NULL;
    unsigned char payload[SASL_MAX_PAYLOAD];
    char authzid[SASL_MAX_AUTHCID + 1];
    char authcid[SASL_MAX_AUTHCID + 1];
    char passwd[SASL_MAX_PASSWORD + 1];
    long decoded;
    const char *params[2];

    /* BEFORE EVERYTHING, INCLUDING THE ABORT. See conn_t::credential_seen: what
     * this records is that a credential was OFFERED, and an offer that was then
     * refused is the interesting case rather than an edge one. `AUTHENTICATE *`
     * carries no payload at all and so arguably offers nothing -- but it is set
     * anyway, deliberately, because "the client got as far as starting SASL and
     * then asked to upgrade the socket" is a shape an attacker produces, and
     * refusing it costs a legitimate client nothing: a client that wants to
     * STARTTLS sends STARTTLS. */
    c->credential_seen = 1;

    /* PER-CONNECTION THROTTLE. After three failed credential verifications this
     * connection stops verifying and refuses every further AUTHENTICATE with
     * 904, so a single connection cannot run an unbounded online dictionary
     * attack. The connection is deliberately NOT closed: poll_loop.c does not
     * pump the write queue of a CLOSING connection, so closing here would
     * discard the 904 queued above and leave the client with a bare FIN. The
     * client is already unable to register (SASL_FAILED is terminal), so the
     * connection is effectively dead and will be reaped on disconnect/timeout. */
    if (c->sasl_failures >= 3) {
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED", ERR_SASLFAIL,
                            NULL, 0, "SASL authentication failed: too many attempts");
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=TOO_MANY_ATTEMPTS\n",
               c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* SASL_FAILED is terminal: a bad credential stays failed. Without this,
     * AUTHENTICATE * (below) or a fresh AUTHENTICATE PLAIN would clear the
     * failure and let NICK+USER register anonymously. */
    if (c->sasl == (int)SASL_FAILED) {
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED", ERR_SASLFAIL,
                            NULL, 0, "SASL authentication failed");
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=ALREADY_FAILED\n",
               c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* AUTHENTICATE * is the ABORT (RFC 4422 3.1), and it is answered before any
     * parsing: a client abandoning an exchange must not have to supply a
     * well-formed one to be allowed to stop. It leaves the connection
     * registerable, because declining to authenticate is not failing to. */
    if (m->nparams >= 1 && strcmp(m->params[0], "*") == 0) {
        c->sasl = (int)SASL_ABORTED;
        (void)reply(s, c, RPL_SASLABORTED, NULL, 0, "SASL authentication aborted");
        printf("[observable] sasl: fd=%d outcome=ABORTED\n", c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* WHICH PARAMETER IS THE MECHANISM, AND WHICH IS THE RESPONSE.
     *
     * RFC 4422's first form is `AUTHENTICATE <mechanism> [<initial-response>]`,
     * so two parameters is unambiguous. The SECOND form -- the client answering
     * the '+' this node sent -- is a single parameter that is NOT a mechanism
     * name, and there is no syntactic way to tell the two apart: a base64 blob
     * may have no '=' padding and may begin with any of the 64 alphabet
     * characters, so "does it contain '='" and "does it start with a plausible
     * name" are both guesses that break on a real client.
     *
     * The answer is the STATE, and that is why c->sasl is a field on the
     * connection at all. A single parameter while an exchange is in progress is
     * the response; a single parameter with no exchange in progress is a
     * mechanism name. The alternative -- guessing from the bytes -- is how a
     * server accepts a credential it never asked for. */
    if (m->nparams >= 2) {
        mech = m->params[0];
        arg = m->params[1];
    } else if (m->nparams == 1) {
        if (c->sasl == (int)SASL_IN_PROGRESS) {
            mech = "PLAIN";
            arg = m->params[0];
        } else {
            mech = m->params[0];
        }
    }
    if (mech == NULL) {
        /* Either a bare `AUTHENTICATE` or a first line that is neither a known
         * mechanism nor a payload. 908 offers the one mechanism this node has,
         * which is the answer a client needs and the only honest one: a node with
         * no credential store has NO mechanism, and saying so is what 908's list
         * being empty means. */
        params[0] = (account_store_count(s->sasl_store) > 0u) ? "PLAIN" : "";
        (void)reply(s, c, RPL_SASLMECHS, params, 1,
                    "are available SASL mechanisms");
        printf("[observable] sasl: fd=%d outcome=NO_MECHANISM store=%zu\n", c->fd,
               account_store_count(s->sasl_store));
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }
    if (strcasecmp(mech, "PLAIN") != 0) {
        /* A mechanism this node names but does not implement, or one it does not
         * know at all. 908 rather than a refusal: the client asked what it can
         * use, and the answer is what it can use. */
        params[0] = (account_store_count(s->sasl_store) > 0u) ? "PLAIN" : "";
        (void)reply(s, c, RPL_SASLMECHS, params, 1,
                    "are available SASL mechanisms");
        /* THE MECHANISM IS MEASURED, NOT ASSUMED SAFE. It is worth saying
         * explicitly because an earlier reading of this pass claimed `mech` was
         * "already bounded and named by 908" -- it is NEITHER. Nothing bounds it
         * before this line: it is `m->params[0]`, so it may be as long as the line
         * cap, and 908 names the mechanism in a REPLY to the client rather than
         * constraining what the log may print. Measured on the pre-fix binary, a
         * single `AUTHENTICATE <ESC>[2J` put both bytes in the log.
         *
         * `authzid` is excluded from this line and from every other line on this
         * path deliberately, and the header at handle_authenticate() gives the
         * reason: it is the other half of a credential and adding it to a log buys
         * nothing. That exclusion is unchanged. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, mech);
            printf("[observable] sasl: fd=%d outcome=MECH_REFUSED mech=%s "
                   "mech_len=%zu mech_bad_bytes=%zu\n",
                   c->fd, shown, strlen(mech), conn_text_bad_count(mech));
        }
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* Gate, don't encrypt (#167): PLAIN on a plaintext connection to a node
     * with TLS configured is refused BEFORE any credential is read, so the
     * password never crosses the wire in the clear. The client is told to
     * upgrade with STARTTLS or reconnect on the TLS port first; cap.c has
     * already withheld `sasl` from CAP LS here, so a client that reached this
     * far ignored the advertisement. A node with no TLS keeps the old
     * behaviour. The refusal marks the connection failed, so registration can
     * never follow it. */
    if (tls_backend_available() != 0 && s->tls != NULL &&
        transport_is_tls(c) == 0) {
        c->sasl = (int)SASL_FAILED;
        c->sasl_failures++;
        s->n_sasl_fail++;
        params[0] = "*";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 1);
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED",
                            ERR_SASLFAIL, NULL, 0,
                            "SASL authentication failed: TLS is required on "
                            "this node for SASL PLAIN");
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=TLS_REQUIRED\n",
               c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    if (arg == NULL) {
        /* Start the exchange. The '+' is a trailing parameter with no space in
         * it, and RFC 4422 requires it to be exactly that. */
        c->sasl = (int)SASL_IN_PROGRESS;
        params[0] = c->nick[0] != '\0' ? c->nick : "*";
        params[1] = "+";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 2);
        printf("[observable] sasl: fd=%d outcome=STARTED mech=PLAIN\n", c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    decoded = sasl_b64_decode(arg, strlen(arg), payload, sizeof payload);
    if (decoded < 0 ||
        sasl_plain_parse((const char *)payload, (size_t)decoded, authzid,
                         sizeof authzid, authcid, sizeof authcid, passwd,
                         sizeof passwd) != 0) {
        c->sasl = (int)SASL_FAILED;
        s->n_sasl_fail++;
        /* ONE parameter, so the line is exactly `AUTHENTICATE *`. With two the
         * formatter would colonned the '*' (a value beginning with ':' or
         * holding a space needs the marker, and this one needs neither) and the
         * client would see a trailing parameter where RFC 4422 3.1 specifies a
         * single one. The abort is the one line in this exchange a client reads
         * with a byte comparison, so it is written as the RFC writes it. */
        params[0] = "*";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 1);
        /* 905 is the payload that does not FIT, 904 the one that does not READ.
         * sasl_b64_decode() answers -1 for both, so the length decides:
         * anything past SASL_MAX_RESPONSE -- the base64 text a client may send --
         * never fit the decode buffer and is too long; anything shorter is
         * malformed. (shortcut: a short blob whose FIELDS overflow is answered
         * 904 rather than 905; upgrade by threading a reason out of
         * sasl_plain_parse() if a client ever needs the distinction.) */
        if (strlen(arg) > (size_t)SASL_MAX_RESPONSE) {
            (void)reply(s, c, ERR_SASLTOOLONG, NULL, 0,
                        "SASL authentication failed: response too long");
        } else {
            /* `INVALID_AUTHENTICATE` is the code the SASL specification defines for
             * exactly this -- an AUTHENTICATE whose payload this node cannot read --
             * and standard-replies says an existing code MUST be used where one is
             * defined. */
            (void)reply_refused(s, c, "AUTHENTICATE", "INVALID_AUTHENTICATE", ERR_SASLFAIL,
                                NULL, 0,
                                "SASL PLAIN payload was not base64 or not three "
                                "NUL-separated fields");
        }
        conn_mark_closing(c);
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=%s\n", c->fd,
               strlen(arg) > (size_t)SASL_MAX_RESPONSE ? "RESPONSE_TOO_LONG"
                                                       : "BAD_PAYLOAD");
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* The verification itself. No store means no authentication, and the node
     * does not pretend otherwise: cap.c has already withheld `sasl` from CAP LS,
     * so a client that reached here has either ignored the advertisement or
     * arrived with a hard-coded configuration. */
    /* #539: spend a verification token BEFORE hashing, so a reconnect+login
     * loop cannot burn loop-thread KDF time faster than 2/sec no matter how
     * many connections it opens. No state is set and no failure counted: the
     * client did nothing wrong and retries. */
    if (!auth_try_spend(s)) {
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED",
                            ERR_SASLFAIL, NULL, 0,
                            "SASL authentication failed: too many attempts, "
                            "try again later");
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=RATE_LIMITED\n",
               c->fd);
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    if (!sasl_plain_verify(s->sasl_store, authzid, authcid, passwd)) {
        const int no_store = (account_store_count(s->sasl_store) == 0u);

        c->sasl = (int)SASL_FAILED;
        c->sasl_failures++;
        s->n_sasl_fail++;
        params[0] = "*";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 1);
        /* The text says WHICH failure, because the operator needs to know
         * whether to fix the store or to look for an attack, and the client
         * needs to know not to retry the same password. It never says anything
         * about the credential itself. */
        /* NOT `SAASL_FAIL`, which the registry defines as an account that is
         * TEMPORARILY locked: neither of this node's two failures is that, and a
         * client reading `SAASL_FAIL` would offer the user to wait and retry a
         * password that will never verify. The registry has no code for "the
         * credentials did not verify", so this one is `ERR_`-prefixed as ours. */
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED", ERR_SASLFAIL,
                            NULL, 0, "SASL authentication failed: %s",
                            no_store ? "this node holds no client credential store"
                            : "the credentials did not verify");
        /* ------------------------------------------------------------------------
         * `authcid=` IS MEASURED, NOT PRINTED, AND IT WAS THE ONE SITE OF SIX
         * WITHOUT `conn_text_logsafe()`
         * ------------------------------------------------------------------------
         * `sasl_plain_parse()` validates LENGTH and nothing else, so `authcid` is
         * whatever the client base64-encoded: a pre-registration, unauthenticated
         * line could put ESC and CSI into the operator's terminal. Three sibling
         * sites in this same function already call `conn_text_logsafe()` -- the
         * `mech=` refusal above, the `account_set()` refusal below and the
         * COMPLETED line -- and this one did not, which is why it survived the
         * sweep: the sweep drives each verb with a single line, and `authcid` only
         * exists across TWO messages of state (`AUTHENTICATE PLAIN` then
         * `AUTHENTICATE <payload>`), because the payload of a one-line exchange is
         * parsed as a MECHANISM NAME and refused at 908 before anything is stored.
         *
         * The fix is the same call the other five make, which is the whole of why
         * it is one line: the pattern is already established in this file and a
         * site that departs from it is the one that leaks. `conn_text_logsafe()`
         * writes the value verbatim when every byte is printable ASCII and `-`
         * otherwise, so the reading below pairs it with the two counts that say
         * what was withheld and how long it really was. A UTF-8 authcid prints as
         * `-` here; it is still stored, still used to look the account up, and
         * still legible to the client, and this line is the operator's diagnostic
         * rather than the account.
         *
         * The credential itself -- `passwd` -- is never printed anywhere on this
         * path, and adding `authzid` would have been adding the other half of a
         * credential to a log for no diagnostic gain. Neither changes. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, authcid);
            printf("[observable] sasl: fd=%d authcid=%s authcid_len=%zu "
                   "authcid_bad_bytes=%zu outcome=REJECTED reason=%s\n",
                   c->fd, shown, strlen(authcid), conn_text_bad_count(authcid),
                   no_store ? "NO_STORE" : "BAD_CREDENTIAL");
        }
        auth_wipe_credential(payload, authzid, authcid, passwd);
        return;
    }

    /* Verified. What is recorded is the fact and the identity, so a later numeric
     * could report it; the counter is the node's own claim and it is incremented
     * here because this is the only place a credential is ever accepted.
     *
     * AND THE ACCOUNT IS ESTABLISHED HERE, which is the whole of what Phase 10.1
     * added to this function. Until now `c->sasl = SASL_COMPLETED` granted
     * nothing and recorded an authcid nothing could read, which is why seven
     * IRCv3 specs were blocked on an account concept that did not exist: SASL
     * authenticates a CONNECTION and an account is what you are ACROSS
     * connections.
     *
     * THE PASSWORD IS HANDED TO account_set() AND NOT STORED, and it is the same
     * `passwd` local that sasl_plain_verify() just read. account_set() re-checks
     * it against the OPERATOR'S ACCOUNT REGISTRY -- a different table from the
     * credential store this function verified against -- so a node whose two
     * files disagree about `alice` logs her in as nobody rather than logging her
     * in as an account that does not exist. That is the fail-closed direction and
     * it costs one bounded constant-time walk on a path that runs once per login.
     *
     * A REFUSAL HERE IS NOT AN AUTHENTICATION FAILURE. The credential verified;
     * the client is authenticated and is simply not identified to an account,
     * which is the same state as a client that declined to authenticate. So
     * `c->sasl` stays COMPLETED, registration proceeds, and the node says why on
     * its own output -- because the alternative (refusing the whole exchange
     * because an account was not configured) would make adding an account
     * registry a change to who can log in, and it must not be.
     */
    c->sasl = (int)SASL_COMPLETED;
    s->n_sasl_ok++;
    if (account_set(s, c, authcid, passwd) != 0) {
        s->n_account_refused++;
        /* The same measurement as the rejection line above, for the same reason:
         * `account_set()` refused, which is the path where its
         * `account_name_wire_safe()` check is what said no, so nothing upstream
         * validated this name. The credential DID verify -- so this is an
         * identification failure and not an authentication one -- which is exactly
         * why the login name matters to whoever reads the log. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, authcid);
            printf("[observable] account: fd=%d authcid=%s authcid_len=%zu "
                   "authcid_bad_bytes=%zu outcome=REFUSED reason=%s registry=%s\n",
                   c->fd, shown, strlen(authcid), conn_text_bad_count(authcid),
                   (s->account_store == NULL) ? "NO_REGISTRY" : "NOT_IN_REGISTRY",
                   (s->account_store != NULL) ? "loaded" : "none");
        }
    }
    /* TWO KEYS AND NOT ONE, and the split is deliberate: `logged_in` is the
     * BOOLEAN and `account=` on account_set()'s line is a NAME. Rendering both
     * as `account=` would put a name and a 0/1 behind one key on two different
     * lines, and a reader (or a grep, or a test) asking "what is this user's
     * account" would have to know which of the two it had found. */
    /* Measured, and here `account_name_wire_safe()` DID run -- inside
     * `account_set()` -- so this value is one of the few client strings on the node
     * that is already known safe. It is measured anyway rather than trusted,
     * because the two facts are different: the CHECK runs on the success path, and
     * this line prints on both. One `conn_text_logsafe()` costs a pass over 63 bytes
     * once per login, and it removes the need to know which path this was. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, authcid);
        printf("[observable] sasl: fd=%d authcid=%s authcid_len=%zu "
               "authcid_bad_bytes=%zu outcome=COMPLETED granted=0 logged_in=%d\n",
               c->fd, shown, strlen(authcid), conn_text_bad_count(authcid),
               account_logged_in(c));
    }
    /* Registration is not forced here. A client that sent NICK and USER before
     * its AUTHENTICATE has already satisfied the state machine, and if it was
     * held for CAP it is still held -- so the gate is re-evaluated rather than
     * bypassed. */
    /* 903 is SASL's own success verdict, and it goes out unconditionally: a
     * client that authenticates before registering watches for exactly this. */
    (void)reply(s, c, RPL_SASLSUCCESS, NULL, 0, "SASL authentication successful");
    auth_wipe_credential(payload, authzid, authcid, passwd);
    commands_state_update(s, c);
}
