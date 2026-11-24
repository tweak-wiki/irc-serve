/* sasl_framework.h -- REAL SASL PLAIN, verified against a credential store.
 *
 * Authority: docs/SERVER_DESIGN.md 5 ("implement real SASL PLAIN (base64 ->
 * authzid\0authcid\0passwd -> credential store)"), 7/Phase 8, and RFC 4616.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS HERE, AND WHY IT IS GONE
 * ---------------------------------------------------------------------------
 * This file used to be a state machine whose `sasl_step()` DISCARDED its input,
 * called `printf("[observable] ...")` four times a call, and marked the exchange
 * COMPLETED on the second step regardless of what -- if anything -- the client
 * sent. A `sasl_framework.c` that answers PLAIN by returning success is the exact
 * defect Phase 6's README described as "a node that is not allowed to be here",
 * and shipping that as authentication would be worse than shipping nothing: a
 * client would be told it authenticated and would act on it.
 *
 * So the state machine is GONE as a concept rather than fixed. What remains is
 * the part that has to be real:
 *
 *   - a CREDENTIAL STORE, loaded from a file the operator supplies, so there is
 *     something for a password to be WRONG against;
 *   - base64 decode of what the client sent;
 *   - RFC 4616's three-NUL-separated field split;
 *   - a COMPARISON that does not leak the password's prefix by timing;
 *   - and a refusal that fails CLOSED when the store is missing, unreadable, or
 *     too permissive.
 *
 * The observable state names (`sasl_state_t`) survive because
 * tests/compliance/test_sasl_handshake.c calls sasl_state_machine(), and a
 * module with no callers is not a place to change a test's API. The entry points
 * now do the real thing; sasl_state_machine() drives them over a store it builds
 * in memory.
 *
 * ---------------------------------------------------------------------------
 * WHAT SASL AUTHENTICATES AGAINST, STATED PLAINLY
 * ---------------------------------------------------------------------------
 * There is no operator credential store in this tree, and there is no
 * NickServ. So this states its own scope rather than implying a larger one:
 *
 *   SASL PLAIN authenticates a CLIENT against THIS NODE'S credential store --
 *   the file named by `--sasl-store` -- and the ONLY thing it establishes is
 *   "this connection proved it holds the password recorded for <authcid>". It
 *   grants NOTHING: no operator flag, no channel privilege, no service, no
 *   exemption from a mode change. `conn_t` has no field a successful SASL would
 *   write, because there is nothing here it could legitimately grant.
 *
 *   Credentials are PER NODE, which is a real limitation and not a design
 *   choice: a federated deployment shares authentication by link auth (2.3),
 *   and this store is not that mechanism. Two nodes in a mesh with two different
 *   `--sasl-store` files will disagree about who a user is, and neither can
 *   detect it. That is stated rather than solved, because solving it means a
 *   credential-propagation protocol and 9's risk table is the right place for
 *   that argument.
 *
 * The alternative designs were considered and rejected rather than overlooked:
 *
 *   NO CHECK AT ALL, or "any password is accepted". This is the failure mode
 *   above and it is worse than having no SASL, because a client believes it
 *   authenticated.
 *   AGAINST THE HOST'S getpwnam(). Real, but it makes a federated node's user
 *   namespace the host's, so a container image's `root` becomes an IRC identity
 *   nobody chose, and the node's `--name` gives no hint of it.
 *   A HASH. Right in the abstract and -- for the FILE -- wrong here: this
 *   tree contains no cryptographic code and hand-rolling a primitive into an
 *   authentication path is a worse outcome than being explicit about what the
 *   file is. The file is a secret store, so it is required to be a SECRET
 *   FILE -- see sasl_store_load() -- and that requirement, not a hash, is the
 *   control on what is on disk. What is hashed is the HEAP copy: each record
 *   holds iterated SHA-256(salt || password) under a per-record salt, so a core dump or
 *   an allocator reuse reads back digests rather than passwords.
 */
#ifndef IRC_SASL_FRAMEWORK_H
#define IRC_SASL_FRAMEWORK_H

#include <stddef.h>

#include "account_store.h"

/* Bounds on the PLAIN exchange. All of them are constants rather than
 * configuration, and the reason is the one that applies to every one: the
 * bounds that matter here are the client's, read off the wire, and a bound
 * that depended on a number in the credential file would be a bound the
 * file sets. The TABLE's bounds (record count, name and password length,
 * line length) are account_store.h's: there is one table now, so there is
 * one place that bounds it. */
#define SASL_MAX_AUTHCID    63   /* conn_t::nick's bound minus one; an authcid
                                  * IS a nickname in every client that offers it */
#define SASL_MAX_PASSWORD  128   /* RFC 4013's PLAIN has no length limit, so this
                                  * is ours and is stated, not inherited.
                                  * ACCOUNT_MAX_PASSWORD is deliberately the
                                  * same value, so one file serves both uses */
#define SASL_MAX_PAYLOAD   1024  /* the DECODED PLAIN payload */
#define SASL_MAX_RESPONSE  1024  /* the base64 text a client may send */

/* Observable SASL state. The names are the ones this module has always had;
 * `FAILED` is terminal and `ABORTED` means "not started or abandoned". */
typedef enum {
    SASL_ABORTED = 0,
    SASL_IN_PROGRESS = 1,
    SASL_COMPLETED = 2,
    SASL_FAILED = 3
} sasl_state_t;

/* THE TABLE IS account_store_t. There used to be a second user table here --
 * its own record, salt, hash and compare beside account_store.c's -- so one
 * user add was two writes in two formats and a user in one store only could
 * SASL-auth but not log in, or the reverse, with no error logged (#538). Now
 * the store comes from account_store_load()/account_store_new() (or from
 * sasl_store_load() below for the legacy two-field file, which loads the
 * same table with created=0), and sasl_plain_verify() is the one caller of
 * account_store_verify() on the SASL path. A caller cannot build a table by
 * laying out fields, so the bounds above -- and account_store.h's -- are
 * the bounds rather than a suggestion. */

typedef struct {
    sasl_state_t state;
    char         mechanism[32];
    char         authzid[64];
    char         authcid[64];
    int          step_count;
    int          last_error;

    /* The table this context verifies against. NULL MEANS NO TABLE, and the
     * verify path treats NULL as "every credential fails" -- fail closed. It
     * is a pointer rather than an owned copy so a node loads the file once
     * and every connection borrows it, which is also why it must outlive
     * every context pointing at it; server_shutdown() frees the table and
     * the loop has stopped by then. */
    const account_store_t *store;
} sasl_ctx_t;

/* ---------------------------------------------------------------------------
 * The legacy credential file
 * --------------------------------------------------------------------------- */

/* Load `path` in the legacy two-field form (`authcid<TAB>password`, no
 * `created` column) into the ONE table, with created=0 ("the epoch", which
 * account_store.h documents as honestly unknown rather than false). Returns
 * NULL on ANY failure -- unreadable, not a regular file, group- or
 * world-accessible, malformed, or with no usable record -- and prints one
 * [observable] `sasl_store: state=...` line naming the reason, which is the
 * same contract the loader always had and the same lines the tests watch.
 * There is no partial success: a store that loaded half its file would
 * authenticate half the passwords an operator believes are configured.
 *
 * New files should use the three-field account format and
 * account_store_load(): one file named by both --sasl-store and
 * --account-store is one user population for both SASL and login, which is
 * the shape that cannot disagree with itself. */
account_store_t *sasl_store_load(const char *path);

/* ---------------------------------------------------------------------------
 * Verification
 * --------------------------------------------------------------------------- */

/* RFC 4616 PLAIN: `authzid NUL authcid NUL passwd`, from `len` bytes of decoded
 * payload. Returns 0 when all three fields were present and within their bounds,
 * -1 otherwise, and zeroes every output on any failure -- a caller that ignores
 * the return value gets empty strings rather than the previous call's bytes.
 *
 * `pass_cap` is the bound on the PASSWORD field, not on the whole payload, and
 * the caller chooses it; it is a parameter rather than a constant because
 * SASL_MAX_PASSWORD is the store's bound and a caller with a smaller buffer must
 * be refused rather than overflow. */
int sasl_plain_parse(const char *payload, size_t len,
                     char *authzid, size_t authzid_cap,
                     char *authcid, size_t authcid_cap,
                     char *passwd, size_t passwd_cap);

/* Verify `authcid`/`passwd` against `store`, which is the ONE table.
 *
 * The SASL-specific policy lives here and nowhere else: an authzid that names
 * somebody ELSE than the authcid is refused (an empty authzid is RFC 4013's
 * "the same as the authentication identity" and is not a difference), and a
 * NULL or empty store refuses every credential -- fail closed. The password
 * comparison itself is account_store_verify()'s: one table, one verify
 * function, and this is the call. The walk, the dummy compare and the
 * hash-against-hash argument are documented there and not repeated here, so
 * the two cannot drift apart again. */
int sasl_plain_verify(const account_store_t *store,
                      const char *authzid, const char *authcid, const char *passwd);

/* base64 decode `inlen` bytes of `in` into `out`. Returns the decoded byte count,
 * or -1 on malformed input or insufficient capacity. Whitespace anywhere is
 * skipped, because clients wrap long AUTHENTICATE payloads and a server that
 * refuses a wrapped one refuses irssi. The output is NOT NUL-terminated; the
 * caller bounds it with the returned count, which is what makes a payload
 * containing a NUL -- which RFC 4616's format REQUIRES three of -- usable. */
long sasl_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap);

/* ---------------------------------------------------------------------------
 * The observable state machine this module has always exposed
 * --------------------------------------------------------------------------- */

/* Zero `ctx`, set state to SASL_ABORTED and copy `mechanism` (truncating).
 * `ctx->store` is left NULL, which means "no store" and therefore "every
 * credential fails"; use sasl_set_store() to attach one. */
void sasl_init(sasl_ctx_t *ctx, const char *mechanism);

/* Attach the table a later step verifies against. NULL detaches it, which is
 * the same as never having had one. */
void sasl_set_store(sasl_ctx_t *ctx, const account_store_t *store);

/* Start the mechanism. Only valid from SASL_ABORTED, which it consumes; from any
 * other state it returns that state unchanged. */
sasl_state_t sasl_start(sasl_ctx_t *ctx);

/* Advance the exchange one step. Only valid from SASL_IN_PROGRESS.
 *
 * `server_data`/`len` are the RAW bytes the client sent: for AUTHENTICATE PLAIN
 * that is the base64 TEXT, and this function decodes it. On success the context
 * holds the decoded authzid/authcid, the state is COMPLETED, and nothing is
 * written to `client_out`/`out_len` (which are set to 0 when both are non-NULL).
 * On a malformed payload or a credential that does not verify, the state is
 * FAILED and `last_error` names which: SASL_ERR_* below.
 *
 * Returns the new state. A step in any other state returns that state unchanged,
 * so a caller that steps twice cannot be promoted to COMPLETED by the second
 * call -- which is exactly what the previous implementation did. */
sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len,
                       char *client_out, size_t *out_len);

/* `last_error` values. Named so a refusal can say WHICH, since "authentication
 * failed" and "the payload was not base64" have different fixes for the client
 * and different ones for the operator. */
#define SASL_OK              0
#define SASL_ERR_NO_STORE   (-1)  /* no credential store: nobody can pass */
#define SASL_ERR_MECH      (-2)  /* a mechanism this node does not implement */
#define SASL_ERR_PAYLOAD   (-3)  /* not base64, or not three NUL-separated fields */
#define SASL_ERR_CREDENTIAL (-4) /* a well-formed credential that does not verify */

/* Force the context to SASL_ABORTED (a client sent AUTHENTICATE *, which is how
 * a client abandons the exchange) or SASL_FAILED, recording `error_code`. */
sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code);
sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code);

/* Read-only current state. */
sasl_state_t sasl_get_state(const sasl_ctx_t *ctx);

/* Drive the whole observable lifecycle over an in-memory store: a correct PLAIN
 * credential reaches COMPLETED, a wrong password reaches FAILED, an unknown
 * authcid reaches FAILED, a malformed payload reaches FAILED, and a context with
 * no store at all reaches FAILED. Returns 1 only when every path behaved as
 * documented, 0 otherwise.
 *
 * It prints nothing. The previous version printed "[observable]" lines on every
 * call, which meant a credential store's contents were being formatted into a
 * string on the authentication path -- the first thing anyone looks at when
 * asking where a password went. */
int sasl_state_machine(void);

#endif /* IRC_SASL_FRAMEWORK_H */
