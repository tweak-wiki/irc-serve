/* commands_register.c -- see commands_register.h. The registration family,
 * verbatim out of commands.c; the table that calls the handlers still
 * lives there.
 */
#include "core/commands_register.h"

#include <stdio.h>
#include <string.h>

#include "core/fanout.h"
#include "core/reply.h"
#include "federation/nickreg.h"
#include "federation/verbs.h"
/* ---------------------------------------------------------------------------
 * Field copies
 * ------------------------------------------------------------------------ */

/* Copy an asserted identity field into a fixed 2.1 field, truncating at the
 * struct width rather than refusing the registration.
 *
 * Truncation is a choice and it is a compromise: a realname longer than 255
 * bytes is legal on the wire and refusing it would lock out a client with a
 * long name, while storing it would need a field 2.1 does not have. So the
 * stored value is a prefix of what was asserted, and the caller is told, so it
 * can say so rather than quietly disagreeing with the client about what it
 * sent. (The nick has no such problem: valid_nick() caps it at IRC_MAX_NICK,
 * which is sizeof(conn_t::nick) - 1 by construction.) */
static void copy_field(char *dst, size_t cap, const char *src, int *trunc)
{
    size_t n = strlen(src);

    if (n >= cap) {
        n = cap - 1u;
        if (trunc != NULL) {
            *trunc = 1;
        }
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ---------------------------------------------------------------------------
 * Handlers
 * ------------------------------------------------------------------------ */

/* PASS: RECORDED, NOT AUTHENTICATED.
 *
 * There is no password mechanism in this phase and no credential store to check
 * one against, so the line is acknowledged by counting it and refused by
 * nothing. A client that sends PASS with any value, including a wrong one, is
 * treated exactly like a client that sent none. That is the whole of the
 * feature and it is deliberately not dressed up as anything more: real
 * authentication is SASL, and SASL is Phase 8.
 *
 * The password is NOT logged. The count is the record -- s->n_pass_seen -- and a
 * node that printed a secret to its own stdout would leak it into every log
 * collector downstream. */
void handle_pass(server_t *s, conn_t *c, const message_t *m)
{
    /* BEFORE THE ARITY CHECK, and that is the whole point of the placement. A PASS
     * with no parameter carries no credential, but a PASS with a parameter that is
     * refused a few lines below has still put one on the wire in the clear, and a
     * client that STARTTLSes afterwards must be refused: see
     * conn_t::credential_seen and handle_starttls(). */
    c->credential_seen = 1;
    if (m->nparams < 1) {
        (void)reply_refused(s, c, "PASS", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    s->n_pass_seen++;
    printf("[observable] pass: fd=%d recorded=1 authenticated=0\n", c->fd);
}

/* NICK: the one place a nickname is chosen, and the first production caller of
 * valid_nick().
 *
 * Three rejections, and they are different rejections:
 *   431  no nickname at all -- zero parameters, or one empty parameter
 *   432  a nickname that is not a legal nickname
 *   433  a legal nickname this node already holds for somebody else
 *
 * 432 is NOT in 4.4's list of error numerics, and that is a gap in the list
 * rather than a gap in the protocol: 4.4 names 431 and 433 but no numeric for
 * "the nickname you sent is malformed", and 432 ERR_ERRONEUSNICKNAME is the one
 * every client understands. Sending 433 instead would be a lie about the
 * reason -- the name is not in use, it is illegal -- and a client that retried
 * with a "different name" on a 433 would be acting on a false premise. So the
 * RFC numeric is used and the discrepancy is flagged for the design.
 *
 * 432 carries the offending nickname in the TRAILING TEXT rather than in a
 * middle parameter, which departs from the RFC's parameter order and is forced:
 * a nickname illegal enough to be refused may be empty, may start with ':', or
 * may contain a space, and a value that cannot be represented in a non-final
 * parameter position is REFUSED by the formatter rather than reshaped. Naming
 * the bad nickname in the text cannot fail, because the trailing parameter is
 * always representable.
 *
 * 433 does use the middle parameter, and safely so: the nickname got that far
 * by passing valid_nick(), so it is non-empty and cannot start with ':'. */
void handle_nick(server_t *s, conn_t *c, const message_t *m)
{
    const char *want;
    const char *mid[1];

    if (m->nparams < 1 || m->params[0][0] == '\0') {
        (void)reply(s, c, "431", NULL, 0, "No nickname given");
        return;
    }
    if (m->nparams > 1) {
        /* Also how a nickname containing a space is refused: the wire cannot
         * express a space inside one parameter, so a client that sends
         * "NICK a b" has sent two parameters, and this is the answer it gets --
         * which is a TOO MANY case that the legacy text calls "not enough". The
         * text is left exactly as it is, because changing it would change the wire
         * for every client that negotiated nothing; for one that negotiated
         * `standard-replies` the code above says which of the two it was. */
        (void)reply_refused(s, c, "NICK", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");        return;
    }
    want = m->params[0];
    if (!valid_nick(want)) {
        (void)reply(s, c, "432", NULL, 0, "Erroneous nickname: %s", want);
        printf("[observable] nick_reject: fd=%d reason=erroneous\n", c->fd);
        return;
    }

    /* Re-asserting the nickname you already hold is silent: RFC 2812 3.2 says a
    * NICK to the name you already have changes nothing and generates no error.
    *
    * Asked as a REGISTRY question rather than as `strcmp(want, c->nick) == 0`,
    * and the difference is the whole of issue #100. The registry folds case, so
    * `NICK BOB` from the client registered as `bob` is the same name -- and a
    * string comparison here would miss that, fall through to the claim, find
    * the name already held by this very connection, and answer 433 to a client
    * for the nickname it already holds. Asking the registry also keeps this
    * correct for the same reason the fix lives there: the definition of "the
    * same nickname" is a property of the table, so there is no second copy of
    * the rule here to fall out of step with it.
    *
    * A case-only change adopts the new spelling (issue #215): the registry key
    * already folds, so no release/re-claim is needed -- and a re-claim would
    * fail, because server_nick_claim() refuses any name the table already
    * holds, including one held by this very connection. Only the display
    * bytes in conn_t::nick move. */
    if (server_nick_lookup(s, want) == c) {
        memcpy(c->nick, want, strlen(want) + 1u);
        return;
    }
    if (server_nick_claim(s, want, c) != 0) {
        /* The incumbent keeps it: server_nick_claim() is a lookup-and-insert,
         * so the loser never displaces the holder, and nothing here writes to
         * the holder's conn. */
        mid[0] = want;
        (void)reply(s, c, "433", mid, 1, "Nickname is already in use");
        printf("[observable] nick_reject: fd=%d reason=in_use\n", c->fd);
        return;
    }

    /* 2.1's RENAME-THE-LOSER, and the whole policy is
     * fed_nickreg_resolve_local() rather than anything here. That is the point of
     * it being a function: a rule written at the claim site and a rule written at
     * the report site would be TWO rules, and a rename needs FIVE effects -- the
     * decision, a new name, the local registry, the client and its channels, and
     * the mesh -- of which a call site implementing four would produce a mesh
     * that LOOKS renamed and is not.
     *
     * IT IS CALLED HERE AND ALSO AFTER A REMOTE CLAIM IS LEARNED (on an SJOIN and
     * on a burst), because a user can register a name on a node whose registry is
     * empty and have the competing claim arrive afterwards. Checking only at claim
     * time would leave that user holding a name for ever, which is the
     * "user-visible and undefined" state 2.1 names. The other half of the
     * convergence argument is that the OTHER node runs this same function against
     * the same two names and renames its own user if it is the loser there -- so
     * nothing has to tell a node to rename anybody.
     *
     * NOTHING BELOW THIS CALL TOUCHES THE NAME, because the function owns all of
     * it -- including the case where it declines to act, which is most calls. */
    /* A CLIENT-INITIATED CHANGE, for a connection that already held a name, and
     * this is the block the rename-the-loser policy does NOT replace: a user
     * choosing a new name is a different event from a user being told their name
     * is taken, and the two observables are kept apart so a reader of a log can
     * tell them. The release happens BEFORE the claim, which is the opposite
     * order from fed_nickreg_resolve_local()'s and for the same reason stated
     * there -- except that here the name being released is THIS connection's own
     * and is being given up deliberately, so there is no third user who could
     * take it in the window.
     *
    * IT IS REPORTED AND FANNED OUT (issue #609): a client-issued rename is
    * echoed to the renamer as `:old!u@h NICK new`, which RFC 2812 mandates
    * the client receive, delivered once to the union of its channels, and
    * forwarded to the mesh as SNICK -- the same three steps
    * fed_nickreg_resolve_local() performs for a policy rename, minus the
    * registry work already done above. */
    char previous[sizeof c->nick];
    char oldmask[CONN_HOSTMASK_MAX];
    int renamed = (c->nick[0] != '\0');

    if (renamed != 0) {
        /* Built BEFORE the release below from the fields §2.1 owns -- the
        * same fallbacks nickreg.c uses, for the same reason: an
        * unregistered connection has no user and a client may have no
        * host. */
        (void)snprintf(oldmask, sizeof oldmask, "%s!%s@%s", c->nick,
                        (c->user[0] != '\0') ? c->user : "-",
                        (c->host[0] != '\0') ? c->host : "*");
        memcpy(previous, c->nick, sizeof previous);
    }
    if (renamed != 0) {
        server_nick_release(s, previous);
        printf("[observable] nick_change: fd=%d from=%s to=%s\n", c->fd, previous,
               want);
    }
    /* c->nick IS SET BEFORE THE POLICY RUNS and not after, and the order is
     * load-bearing in both directions. Before: fed_nickreg_resolve_local() finds
     * the local holder with server_nick_lookup() and then writes c->nick itself,
     * so a connection still carrying an empty nick would be renamed to nothing and
     * a connection carrying its PREVIOUS nick would be renamed from the wrong
     * name. After: the rename the policy performs would be undone by the memcpy,
     * leaving the registry claiming `fresh` and the connection answering to
     * `want` -- the divergence 2.1's policy exists to end. */
    memcpy(c->nick, want, strlen(want) + 1u);
    (void)fed_nickreg_resolve_local(s, want, server_now_ms());
    commands_state_update(s, c);
    if (renamed != 0) {
        const char *newp[1];
        const char *snickp[2];
        fanout_form_t nplain;
        int ndelivered = 0;

        /* Read back AFTER the policy ran: a rename that collided with a
        * remote holder may have landed on a fresh name, and every line
        * below must carry where the user actually is. */
        newp[0] = c->nick;
        (void)send_line(s, c, oldmask, "NICK", newp, 1);
        if (c->nchans > 0u) {
            nplain.params = newp;
            nplain.nparams = 1;
            ndelivered = fanout_deliver_union_local_gated(
                s, c->chans, c->nchans, oldmask, "NICK", &nplain, NULL, NULL,
                NULL, c);
        }
        snickp[0] = previous;
        snickp[1] = c->nick;
        (void)fed_forward_all(s, "SNICK", oldmask, snickp, 2);
        printf("[observable] nick_notify: nick=%s channels=%zu recipients=%d\n",
               c->nick, c->nchans, ndelivered);
    }
}

/* USER: USER <user> <mode> <unused> :<realname> (RFC 1459 2.4 / RFC 2812 3.1).
 *
 * ---------------------------------------------------------------------------
 * THE HOSTNAME IS NOT STORED. THE OBSERVED ADDRESS IS.
 * ---------------------------------------------------------------------------
 * Worth being precise, because the natural assumption is backwards here: USER
 * has NO hostname parameter. RFC 2812 3.1 defines four of them -- user, mode,
 * unused, realname -- and the third is literally named <unused>. What older
 * clients and some current ones put in that slot is a hostname, which is where
 * the idea that USER carries a claimed host comes from, and it is a WEAKER
 * claim than that: the slot is specified as ignored, so a value there is a
 * client filling in a field the protocol says means nothing.
 *
 * Either way the answer is the same. c->host keeps what accept() put there, the
 * observed peer address, and USER does not touch it. A node that stored the
 * assertion has its identity model controlled by the party being identified:
 * anyone can claim to be `host.example.com`, and everything downstream -- 001,
 * WHOIS, and every access control rule a later phase writes against c->host --
 * would then be a decision the client made about itself.
 *
 * The cost is that a legitimately different hostname (a client behind NAT with
 * a real one) is unavailable to this node, and that c->host holds an address
 * rather than a name. Both are the right trade at a point where the alternative
 * is a spoofable identity field, and it is CHEAP NOW: a one-line omission here,
 * against un-spoofing every c->host consumer in Phase 5 and Phase 6 later.
 *
 * The assertion is not thrown away silently -- it goes to the observable
 * output, so a mismatch between what a client claims and where it connected from
 * is visible when diagnosing something -- but it is not identity.
 *
 * ---------------------------------------------------------------------------
 * A SECOND `USER` IS REFUSED: 462, AND THE IDENT IS NOT WRITTEN
 * ---------------------------------------------------------------------------
 * `USER` is `pre_reg` in k_commands[] because CAP, SASL, NICK, USER, PING, PONG
 * and QUIT are the seven verbs a client may send BEFORE it has registered. That
 * is a statement about what may arrive FIRST, and it is not a statement about
 * what may arrive again: the dispatch table's registration gate is
 *
 *     if (!commands_registered(c) && (cmd == NULL || cmd->pre_reg == 0))
 *
 * which a REGISTERED connection passes for every row including `pre_reg`, so
 * this handler used to run for a second `USER` on a live connection and wrote
 * `conn_t::user` unconditionally. A client could therefore move its own ident
 * with no line to itself and no line to anybody sharing a channel.
 *
 * THE THREAT MODEL, and the part of it that is not the obvious one. Three
 * candidate harms, and only two are real:
 *
 *   NOT IMIMPERSONATION, and the reason is worth stating because it is the
 *   answer that makes "just refuse it" feel arbitrary otherwise. Nothing on
 *   this node is GRANTED to an ident. No privilege, no account and no access
 *   decision reads `c->user` alone -- `account-logged-in` and every operator
 *   check are keyed on other things, and the ident is client-asserted and
 *   UNVERIFIED at registration, so two users may already hold the same one and
 *   a client could equally have REGISTERED with the ident it now moves to. There
 *   is no identity here to impersonate.
 *
 *   YES, A CHANNEL BAN MASK. This is the part that makes the write a defect
 *   rather than a shrug. `chan_banned()` is called on every JOIN and matches a
 *   stored mask against the NICK, against the HOST, and against the COMPOSITE
 *   `nick!user@host` -- and the suite exercises exactly that composite form
 *   (`MODE #mo +b *!*@127.0.0.1`, refused with 474). A mask of the shape
 *   `mallory!*@*` or `mallory!badident@*` can only match through the composite,
 *   so on this node a client that changes its ident, PARTs and re-JOINs is
 *   ADMITTED to a channel it is banned from. That is an access-control bypass
 *   reachable from a single client command, and it is why the answer is not (b)
 *   "accept but notify": a notification does not stop the rejoin.
 *
 *   YES, THE SILENCE ITSELF, to two audiences. Every roster this node draws --
 *   311, 352, 353, the message prefix, 302 -- then reports an ident nobody was
 *   told about, so a `userhost-in-names` client (Phase 10.5) is shown a hostmask
 *   that changed without a word. And `resume.c` REQUIRES (nick, ident, host) to
 *   all match to resume, so the write silently invalidates the client's own
 *   session record. On a mesh the peer's roster keeps the old ident until the
 *   next SBURST, because nothing tells it.
 *
 * WHY 462, AND IT IS NOT A CHOICE. RFC 2812 3.1.3 lists the numeric replies to
 * `USER` as exactly two -- `ERR_NEEDMOREPARAMS` and `ERR_ALREADYREGISTRED` -- and
 * the numeric's own entry in RFC 2812 9 names the case: "user details from second
 * USER message". So a second `USER` is 462 because the RFC says so, not because
 * 462 is the nearest available complaint. (Design 9's risk row previously recorded
 * the opposite -- that refusing "is a behaviour change to an RFC 1459 MUST command
 * with nothing in the RFC requiring it" -- and that was wrong: it had read RFC
 * 1459, whose `USER` section says nothing about a second one, and not RFC 2812
 * 3.1.3. The finding the row was built on is correct; the reason it did not act
 * on it was not.)
 *
 * WHY 462 IS NOT MIGRATED, which looks inconsistent beside the four numerics
 * 4.4.3 does migrate: those four answer MORE THAN ONE QUESTION on this node, so
 * the number alone cannot say which refusal happened. `462` answers exactly one
 * -- "you are already registered" -- so by the rule it stays legacy, and
 * reply_refused()'s NULL code is what selects that branch. A client that
 * negotiated `standard-replies` gets the 462; it is unambiguous.
 *
 * THE GATE IS `commands_registered()`, NOT "HAS SEEN A `USER` BEFORE", and the
 * difference is the whole of the compatibility cost. A client that sends `USER`
 * twice BEFORE completing registration still works, last-one-wins, because it is
 * pre-registration in the sense every other gate in this file means. What is
 * refused is the write to a connection that has already been told `001`, which
 * is where the hole was.
 *
 * THE GATE IS BEFORE THE ARITY TEST, and this is the one place it differs from
 * handle_setname()'s order, deliberately: the arity complaint is a fact about the
 * MESSAGE and the registration state is a fact about the CONNECTION, and for a
 * registered connection the message cannot be processed at all. Answering `461
 * Not enough parameters` to a client that sent the very same four parameters a
 * moment ago and was answered `001` would be a numeric describing a problem the
 * client does not have.
 *
 * WHAT IT COSTS, honestly. A client that re-sends `USER` after registration gets
 * one numeric it did not ask for and keeps its connection, its nickname, its
 * channels and its realname -- the refusal does not close anything. The only
 * thing taken away is the ability to move its own ident, which is the defect. The
 * ident a client wants is the one it should have sent at registration, where it
 * can still be refused (417/empty) rather than silently truncated. */
void handle_user(server_t *s, conn_t *c, const message_t *m)
{
    int trunc_real = 0;
    conn_realname_verdict_t v;
    size_t asserted_len;
    int asserted_ok;
    size_t asserted_bad;

    if (commands_registered(c)) {
        (void)reply_refused(s, c, "USER", NULL, "462", NULL, 0,
                            "Unauthorized command (already registered)");
        printf("[observable] user_refused: fd=%d nick=%s reason=ALREADY_REGISTERED "
               "nparams=%d\n",
               c->fd, c->nick, m->nparams);
        return;
    }

    if (m->nparams < 4) {
        (void)reply_refused(s, c, "USER", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    /* THE REALNAME LENGTH IS REFUSED HERE, mirroring SETNAME (gate 3): an
     * over-long realname is 417 and registration does NOT complete -- no
     * `user_seen`, no stored ident, no 001 -- so a retry with a valid USER
     * still registers. 3.2 forbids delivering a silently shortened parameter,
     * and at registration the shortened value would federate via extended-join
     * as if the client wrote it. Checked BEFORE any field is written, so the
     * refusal stores nothing. The BAD_BYTE arm below still empties the field
     * and registers, because refusing that would strand a half-registered
     * client over a rendering accident (see below). */
    if (conn_realname_check(m->params[3]) == CONN_REALNAME_TOO_LONG) {
        (void)reply_refused(s, c, "USER", "ERR_INPUTTOOLONG", "417", NULL, 0,
                            "Realname is not acceptable");
        printf("[observable] realname_refused: fd=%d nick=%s verb=USER "
               "reason=TOO_LONG len=%zu\n",
               c->fd, c->nick, strlen(m->params[3]));
        return;
    }

    /* ------------------------------------------------------------------------
     * THE IDENT, AND WHY IT IS VALIDATED AT INGEST RATHER THAN FILTERED AT RENDER
     * ------------------------------------------------------------------------
     * `c->user` was the one field of this node's five identity fields with no
     * predicate at all. `copy_field()` bounds LENGTH and nothing else, and
     * `CHGHOST` is deliberately unimplemented, so `handle_user()` was the single
     * writer -- and `conn_hostmask()` was the reader that put the bytes in the
     * PREFIX of every line the client sent, to every co-member of every channel it
     * joined. One pre-registration line, no credential, no second client needed to
     * ring or rewrite somebody else's terminal:
     *
     *     USER \033[2J\033[31m...\033[0m 0 * :x     then JOIN and speak
     *
     * A raw `0x9B` survived it too, which is the exact byte class an earlier pass
     * removed from the peer->client path. The other four identity fields --
     * `nick` (`valid_nick()`), `realname` (`conn_realname_check()`), `account`
     * (`account_name_wire_safe()`) and `host` (OBSERVED, never client-asserted) --
     * are all validated at ingest. This one was the hole.
     *
     * THE DECISION IS INGEST, AND THERE ARE THREE REASONS. They are recorded here
     * rather than in a commit message because the obvious "simplification" a future
     * reader will reach for is to move this into `conn_hostmask()`, and that would
     * be a regression:
     *
     *   1. RENDER-TIME FILTERING PUTS THE SAFETY IN ONE PLACE USED BY ~20 CALL
     *      SITES. Every one of them then depends on it being correct, and any new
     *      call site silently inherits the hazard. That fragile shape has bitten
     *      this project repeatedly -- `handle_topic()` broadcast and stored two
     *      different copies of one field, and `handle_mode()` had three.
     *
     *   2. INGEST MEANS THE VALUE IS SAFE EVERYWHERE IT GOES, including paths
     *      nobody has enumerated. `c->user` reaches `resume.c`'s ident, the
     *      operator log, and every hostmask -- three surfaces an audit found by
     *      READING, and there may be more.
     *
     *   3. `conn_realname_check()` IS THE DIRECT PRECEDENT: the same field-list
     *      argument, refusing so registration completes with an empty field. A
     *      client that sends a control byte registers with no ident -- same
     *      consequence as an over-long realname, which this function already
     *      accepts.
     *
     * THE RULE IS `nickreg_ident_ok()`, which is THE PROJECT'S OWN RULE FOR A
     * HOSTMASK COMPONENT -- nickreg.c's header calls it exactly that -- and which
     * was applied on the peer side only. It is now asked here too, so the two
     * paths agree rather than the project owning two hostmask rules. Its second
     * half is `conn_text_display_check()`, the same walk `valid_nick()` and
     * `conn_realname_check()` use, which is what makes a UTF-8 ident (`ā`,
     * Cyrillic) acceptable while a raw `0x9B` is not: it is about CODE POINTS, not
     * bytes, and a byte-range refusal here would silently eat every non-ASCII
     * ident on the network. That is the direction that matters -- a filter that
     * mangles valid UTF-8 is worse than the original bug, because it is silent.
     *
     * WHAT THE CLIENT SEES: nothing. The registration completes, 001 arrives, and
     * the ident is empty. There is no numeric for "your ident was refused", and
     * inventing one would be a wire change for a value no real client sends a
     * control byte in. What a CO-MEMBER sees is a hostmask with an empty `<user>`
     * slot -- `nick!@host` -- which is the same thing they see for a client that
     * sent `USER  0 * :x` and nothing this node would call an ident.
     *
     * IT IS REPORTED, because the failure is otherwise invisible: the only
     * observable difference between "the client sent no ident" and "the client
     * sent something this node threw away" would be a missing ident in every later
     * roster, which is exactly the discrepancy the observable output exists to make
     * findable. And it is reported as a MEASUREMENT -- a length and a bad-byte
     * count -- never as the bytes, which is the same contract
     * `nickreg_ident_refused()` keeps on the peer side and the same rule the
     * `<servername>` refusal below follows.
     *
     * LENGTH IS REFUSED, not truncated. An ident that is too long for the field
     * is refused (the field is emptied) rather than silently shortened, because a
     * truncated ident would be a value the client never sent -- which is the same
     * reason the control-byte case is refused. `USERLEN` therefore stays out of
     * the 005 token list: this node refuses over-long idents instead of applying
     * a bound, so advertising a number would promise a limit it does not apply.
     *
     * `user_seen` IS SET ON EVERY PATH BELOW, including the refusal, because the
     * state projection asks "did a USER arrive" and not "is the ident non-empty":
     * see the top of this file for why the two came apart and what
     * a client whose ident was refused would otherwise have lost. */
    c->user_seen = 1;
    if (m->params[0][0] != '\0' &&
        nickreg_ident_ok(m->params[0], sizeof c->user) == 0) {
        /* `bad_bytes=` IS A FLOOR AND NOT A CENSUS, and naming that matters
         * because a reader will otherwise treat 0 as "nothing was wrong".
         * `conn_text_bad_count()`'s set is C0 and DEL and connection.h argues at
         * length why it excludes every byte >= 0x80 -- those are UTF-8
         * continuation bytes, and a count that included them would eat every
         * non-ASCII value on the node. The predicate that refused this ident is
         * STRICTER: `nickreg_ident_ok()`'s second half asks
         * `conn_text_display_check()`, which also refuses a raw C1 byte and
         * invalid UTF-8. So the byte that makes a payload dangerous on an 8-bit
         * terminal (0x9B) is refused and NOT counted, and an ident refused with
         * `bad_bytes=0` is one whose problem was a code point rather than a
         * control byte. The reason token beside it is what names the rule.
         * WidenING the count instead would break the documented UTF-8 decision
         * for every other caller of the same function, so the honest answer is
         * to say what the number covers rather than to change it. */
        if (strlen(m->params[0]) >= sizeof c->user) {
            printf("[observable] user_refused: fd=%d nick=%s verb=USER field=user "
                   "reason=FIELD_TOO_LONG len=%zu bad_bytes=%zu\n",
                   c->fd, c->nick, strlen(m->params[0]),
                   conn_text_bad_count(m->params[0]));
        } else {
            printf("[observable] user_refused: fd=%d nick=%s verb=USER field=user "
                   "reason=NOT_A_PARAMETER_BYTE len=%zu bad_bytes=%zu\n",
                   c->fd, c->nick, strlen(m->params[0]),
                   conn_text_bad_count(m->params[0]));
        }
        c->user[0] = '\0';
    } else {
        copy_field(c->user, sizeof c->user, m->params[0], NULL);
    }
    /* THE REALNAME IS CHECKED BY THE SAME PREDICATE `SETNAME` USES, and it is
     * checked BEFORE the field is written rather than after, so a refused value is
     * never briefly stored. conn_realname_check()'s argument is at its definition;
     * what is decided here is what happens when it says no, and the decision is not
     * "truncate".
     *
     * A realname carrying a C0 control is LEFT EMPTY rather than refused, and the
     * asymmetry with SETNAME is deliberate rather than an inconsistency:
     *
     *   - SETNAME arrives on an already-REGISTERED connection, where refusing leaves
     *     the connection usable and the previous value in place -- 417 and nothing
     *     changes.
     *   - USER arrives BEFORE registration completes. Refusing it would leave the
     *     client half-registered with no way to recover except reconnecting, for a
     *     value no current client sends (a realname containing ESC or BEL is a
     *     rendering accident, and CR/LF/NUL cannot reach here at all because the
     *     parser refuses them first). So the registration is allowed to complete
     *     with an EMPTY realname, which is already a legal state in this node --
     *     `extended-join` renders it as a bare `:`, and the comment there says a
     *     client that sent none has an empty realname "which is a fact about the
     *     client rather than a limit this node imposes".
     *
     * IT IS REPORTED, because the failure is otherwise invisible: the only
     * observable difference between "the client sent nothing" and "the client sent
     * something this node threw away" would be a realname that is missing from
     * every later roster, which is exactly the kind of discrepancy 3.4's observable
     * output exists to make findable.
     *
     * LENGTH IS REFUSED ABOVE with 417, exactly like SETNAME: an over-long
     * realname never reaches this copy, so copy_field() cannot truncate it
     * (the length was already proven within bounds) and no shortened value is
     * ever reported as the user's. */
    v = conn_realname_check(m->params[3]);
    if (v == CONN_REALNAME_BAD_BYTE) {
        printf("[observable] realname_refused: fd=%d nick=%s verb=USER "
               "reason=BAD_BYTE len=%zu\n",
               c->fd, c->nick, strlen(m->params[3]));
        c->realname[0] = '\0';
    } else {
        copy_field(c->realname, sizeof c->realname, m->params[3], &trunc_real);
    }
    /* ------------------------------------------------------------------------
     * `<servername>` IS NOT PRINTED, AND THAT IS THE FIX (#121)
     * ------------------------------------------------------------------------
     * `m->params[2]` used to be rendered raw on the line below. One pre-
     * registration command from the wire put arbitrary bytes into an operator's
     * terminal: `USER vic 0 <ESC>[2J<BEL> :x` produced
     *
     *     [observable] user: ... asserted_host=<ESC>[2J<BEL> host=127.0.0.1
     *
     * with the ESC and the BEL surviving, and 0x07 rings a terminal's bell while
     * ESC `[` is a CSI sequence any terminal executes. No credential, no channel,
     * no second client -- one line on a socket, before registration completes.
     *
     * THE FIX IS NOT A BYTE FILTER, and the reason is the only thing that decides
     * it: **this node has no consumer for this field.** `host_source=observed` --
     * the host on that same line is `c->host`, what accept() saw, and nothing a
     * client asserts in `USER` moves it. So a filter would buy nothing for the
     * bytes that pass it while still logging a value no reader can act on, and the
     * hazard would remain for every byte the filter's author did not think of.
     * A field with no consumer is not logged raw; it is summarised.
     *
     * WHAT IS REPORTED INSTEAD, and why each of the three is worth a column:
     *
     *   asserted_host_len          Is the client sending something at all? A
     *                              client with no servername (or one sending an
     *                              empty one) is a fact about the client, and
     *                              `USER`'s parameters are all required, so it
     *                              is a fact worth having.
     *   asserted_host_wellformed   Did it send a name this node's OWN server-name
     *                              grammar would accept?
     *                              irc_serve_server_name_valid() is that grammar,
     *                              and it is the predicate `server_init()` and the
     *                              federation handshake already apply to a server
     *                              name -- so this column answers "is this the
     *                              shape of thing this node would call a server",
     *                              using a rule that already exists rather than a
     *                              third spelling of it. Its grammar is alnum, '-'
     *                              and '.', so a value that passes it cannot carry
     *                              a control byte, and this column is safe by
     *                              construction rather than by luck.
     *   asserted_host_bad_bytes    How many bytes were in the injection set. The
     *                              count is measured, never the bytes, and it is
     *                              what turns "something odd happened" into a
     *                              number an operator can watch.
     *
     * WHY `417` IS NOT USED HERE, which is the third of §9's options and the one
     * that would have been simplest. Every real client sends a servername --
     * usually its own FQDN -- so refusing `USER` over it strands a half-registered
     * client for a field nothing reads. That is the same argument handle_user()'s
     * realname makes at length above, and it is why the policy for THIS field is
     * "print less" rather than "print differently".
     *
     * THE COST, named: an operator can no longer read back what a client claimed
     * it was talking to. The length, the well-formedness verdict and the bad-byte
     * count survive; the string does not. That is the intended trade -- a
     * diagnostic that cannot be acted on is not worth an injection vector -- and
     * if an operator ever needs the value, the place to get it is a log line this
     * node writes from a source it controls, not one a client dictates. */
    asserted_len = strlen(m->params[2]);
    asserted_ok = irc_serve_server_name_valid(m->params[2]);
    asserted_bad = conn_text_bad_count(m->params[2]);
    /* ------------------------------------------------------------------------
     * `user=` IS RENDERED THROUGH `conn_text_logsafe()`, AND THAT IS NOT REDUNDANT
     * WITH THE INGEST CHECK ABOVE
     * ------------------------------------------------------------------------
     * It is the same argument the `mech=`/`authcid=` sites in handle_authenticate()
     * give, and it applies here with a difference worth naming. The ingest check
     * has already refused every byte a terminal executes, so the value that
     * reaches this line is not an injection. It is not, however, necessarily
     * PRINTABLE ASCII -- a UTF-8 ident is `ā` as `0xC4 0x81`, and `0x81` is inside
     * the C1 range this node's own sweep treats as a marker. So a raw `%s` here
     * would print a byte class this project has spent two passes removing from
     * every other surface, on a line an operator reads.
     *
     * The alternative -- printing it because the ingest check ran -- would mean
     * the safety of this line depends on the reader knowing that it ran. That is
     * the shape the render-time-filtering decision is written against, one level
     * down: a site that is safe only because of an invariant established a
     * hundred lines earlier is a site that stops being safe when that invariant
     * moves. So the line is MEASURED rather than trusted, which is
     * `conn_text_logsafe()`'s contract: verbatim when every byte is printable
     * ASCII, and `-` with the true `len=` beside it otherwise.
     *
     * THE COST, named: a UTF-8 ident prints as `-` on this line. The value is
     * still stored, still rendered into every hostmask, and still legible to
     * every client -- the withholding is on the OPERATOR'S diagnostic and nowhere
     * else, and `user_len=` is what says how long the real value was. Every other
     * verbatim-or-`-` site on this node pays the same price for the same reason.
     *
     * `trunc_user` is refused in the same breath: an ident truncated to fit the
     * field is a field the client did not send, and the line below says so by
     * name. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, c->user);
        printf("[observable] user: fd=%d user=%s user_len=%zu "
               "realname_trunc=%d "
               "asserted_host_len=%zu asserted_host_wellformed=%d "
               "asserted_host_bad_bytes=%zu host=%s host_source=observed\n",
               c->fd, shown, strlen(c->user), trunc_real, asserted_len,
               asserted_ok, asserted_bad, c->host);
    }
    if (asserted_bad != 0u) {
        printf("[observable] asserted_host: fd=%d reason=BAD_BYTES dropped=%zu "
               "detail=SUMMARISED_ONLY\n",
               c->fd, asserted_bad);
    }
    commands_state_update(s, c);
}
