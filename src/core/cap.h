/* cap.h -- IRCv3 capability negotiation, and the connection state it owns.
 *
 * Authority: docs/SERVER_DESIGN.md 7/Phase 8 ("CAP negotiation (LS/REQ/ACK/NAK)")
 * and the IRCv3 capability-negotiation specification.
 *
 * ---------------------------------------------------------------------------
 * WHAT "CAP" IS FOR, IN ONE PARAGRAPH, BECAUSE IT IS NOT OPTIONAL DECORATION
 * ---------------------------------------------------------------------------
 * A modern client connects and sends `CAP LS` before it says NICK or USER,
 * because it has extensions to find out about and it must not be told 451 in the
 * middle of asking. The server answers with the capabilities it has, the client
 * picks the ones it wants with `CAP REQ`, and then it sends `CAP END` to say
 * "I am done negotiating" -- and THE REGISTRATION MUST NOT COMPLETE UNTIL THAT
 * ARRIVES. That last clause is the whole point of the subcommand: a server that
 * completes registration as soon as it has NICK and USER sends 001-005 in the
 * middle of the client's CAP exchange, the client treats the burst as the answer
 * to something else, and the connection hangs with no error on either side. Every
 * modern client hangs against such a server. Getting it wrong is not a
 * compatibility detail.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THIS MODULE EXISTS TO ENFORCE: ADVERTISE ONLY WHAT IS REAL
 * ---------------------------------------------------------------------------
 * `CAP LS` lists capabilities THIS NODE IMPLEMENTS. A listed capability that is
 * not implemented is worse than a missing one, and it is worse in a specific way:
 * a missing one is a client that carries on without the feature, which works,
 * while a listed one is a client that switches the feature on and then behaves
 * as though this node honoured it. That is the same rule this project has held
 * numerics to since Phase 3 -- a 324 that disagrees with the node's modes, a 433
 * that claims a malformed nick is taken, an INFO that lists features nothing
 * implements. CAP LS is that rule applied to a list rather than a numeric.
 *
 * So the table below is a list of implementations, not a list of intentions, and
 * `sasl` is in it CONDITIONALLY: a node started without `--sasl-store` holds no
 * credential store and therefore cannot authenticate anybody, so it does not
 * advertise `sasl`. A client that saw `sasl` and then got 908 would have been
 * told a capability existed and does not.
 *
 * ---------------------------------------------------------------------------
 * RELATIONSHIP TO 005's PREFIX=, STATED RATHER THAN LEFT IMPLICIT
 * ---------------------------------------------------------------------------
 * `005 PREFIX=(ov)@+` names the SIGILS this node uses for prefix modes: '@' is
 * op, '+' is voice. It says which sigils exist and what they mean, and it is
 * true regardless of whether `multi-prefix` is enabled. `multi-prefix` is a
 * separate thing and says only whether a `353` may render MORE THAN ONE sigil
 * per member -- it changes how much is drawn, not what the sigils mean. The two
 * therefore do not contradict each other, and a node that renders one sigil per
 * member is still a node whose sigils are '@' and '+'.
 *
 * What multi-prefix DOES commit this node to, and the part that is easy to get
 * half right, is the ORDER of the drawn run. `chan_verbs.c`'s names_signs()
 * draws in PREFIX order -- '@' before '+' -- because a client reads the run left
 * to right and looks it up in PREFIX, and a run in any other order gives it an
 * answer the node does not hold. The same capability also governs `352`
 * RPL_WHOREPLY (`msg_verbs.c`'s who_flags()), because IRCv3's multi-prefix names
 * both numerics and a node that honoured it in 353 alone would be a node whose
 * 353 is authoritative and whose 352 is a summary.
 *
 * The consistency that DOES have to hold is between `CAP LS` and the code: every
 * name in cap_available() must be a name something here implements. That is why
 * there is no `cap-notify` (this node never sends an unsolicited CAP NEW).
 *
 * **`chghost` is absent for a reason that is NOT the tidy one, and it is worth the
 * space.** The specification's trigger is "when a client username or host is
 * changed". This node cannot change a HOST after accept() -- `describe_peer()` is
 * its only writer, and `resume.c` *requires* (nick, ident, host) to match to resume,
 * so a resume refuses rather than applying a new identity -- and there is no
 * `CHGHOST` verb in `k_commands[]` and no emitter anywhere in `src/`. So there is
 * nothing to send.
 *
 * **But an IDENT *CAN* change, and that is the finding.** `handle_user()` writes
 * `conn_t::user` unconditionally, and `USER` is a `pre_reg` verb that the dispatch
 * table still routes for a REGISTERED connection -- so a client may re-send `USER`
 * and change its own ident at any time, silently, with nothing told to anybody.
 * `tests/integration/test_chghost.c` makes the whole of that provable: the change
 * on the wire through a third party's `311`, the absence of any notification on an
 * idle second connection, and the `421` for a client-sent `CHGHOST`.
 *
 * So the capability is absent because **the one thing that changes is not supposed
 * to be able to** -- which is a defect in `handle_user()`, reported in §9 and not
 * fixed here, rather than a feature waiting to be notified. No way to move a host
 * was invented to make the notification implementable: `WEBIRC`/`spoofing` is the
 * territory that belongs to, and adding a verb that sets `conn_t::host` would be
 * inventing a spoofing surface to satisfy a specification.
 *
 * **Phase 10.5 onward retired several names from that sentence.** It used to read
 * "and no `server-time` or `userhost-in-names` (it stamps neither)" — true when
 * written, and no longer true of `userhost-in-names` (Phase 10.5), `setname`
 * (Phase 10.6), `echo-message` (Phase 10.7), `standard-replies` (Phase 10.9) or
 * `away-notify` (Phase 10.8b), all of which are in the table above and implemented
 * behind it. `server-time` is still absent, and `chghost` is still absent for the
 * reason its own paragraph below gives, which is not the tidy one.
 * The line is corrected rather than deleted because an out-of-date "and no X" in a
 * header is the exact shape of the incoherence this file exists to prevent, and the
 * build cannot see it.
 *
 * ---------------------------------------------------------------------------
 * `account-tag` IS IN THE TABLE, AND BOTH HALVES OF IT LANDED TOGETHER
 * ---------------------------------------------------------------------------
 * Phase 10.1 built the account identity -- a `conn_t` carries an account name and
 * a `logged_in` flag, set from the SASL `authcid` when -- and only when -- both
 * an operator's credential store and their account registry verify the
 * credential -- and DELIBERATELY left the capability out of k_caps[].
 *
 * The reason it left it out was the specification's own sentence, quoted because
 * paraphrasing it loses the part that matters: **"If the user is not identified
 * to any services account, the tag MUST NOT be sent."** The tag's ABSENCE is an
 * assertion -- a client reads "no `account` tag" as "this user is anonymous" --
 * so advertising the capability and then never emitting the tag would not merely
 * fail to help: it would tell every client that every logged-in user on this node
 * is anonymous.
 *
 * THAT REASONING WAS CORRECT AND IT IS NOW RESOLVED RATHER THAN OVERTURNED. The
 * name went in at the same moment as the emission -- fanout.c's
 * `fanout_tag_block()` writes the tag, and this table lists the name -- and with
 * both halves present the incoherence does not arise: a client that negotiates
 * `account-tag` gets the tag on every line a logged-in sender emits to it, and a
 * client that does not negotiate it is written to exactly as before. The
 * advertisement is no longer a claim about an absence, and the paragraph above is
 * KEPT rather than deleted because the incoherent version is one table line away
 * and nobody should have to rediscover the argument.
 *
 * THE AVAILABILITY CHECK IS ACCOUNT_POSSIBLE(), beside sasl_possible() below, and
 * it is 0 on a node with no registry for exactly the reason `sasl` is withheld
 * there: with nothing behind the name there is nothing the tag could say, and a
 * node that listed it would be a node whose every logged-in user -- which cannot
 * exist -- is anonymous. The check asks whether there is anything to SAY, which is
 * what makes it the right question now that there is something to say.
 *
 * THE TAG IS NOT SENT TO A CLIENT THAT DID NOT NEGOTIATE IT, and that is a
 * second, independent gate in cap_account_tag_enabled() below. Absence is an
 * assertion, so an UNSOLICITED `account` tag is as wrong as a missing one: it
 * tells a client that opted out of tags that this user is identified. The emission
 * is therefore per DESTINATION, exactly like the `msgid` tag, and the ACCOUNT NAME
 * ITSELF is resolved once per emission in fanout.c rather than once per
 * destination -- the comment on fanout_emitter_account() gives the argument, and
 * getting it wrong is the same class of bug as the one an emission's id had.
 */

#ifndef IRC_CORE_CAP_H
#define IRC_CORE_CAP_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* Capability names, as one constant each.
 *
 * Named rather than written as literals at the call sites because a capability
 * that is spelled two ways is a capability that is ACKed once and NAKed once, and
 * that looks like a bug in the negotiation rather than a typo. */
#define CAP_MULTIPREFIX "multi-prefix"
#define CAP_MESSAGE_TAGS "message-tags"
#define CAP_MESSAGE_IDS "draft/message-ids"
#define CAP_SASL "sasl"
#define CAP_ACCOUNT_TAG "account-tag"
#define CAP_ACCOUNT_NOTIFY "account-notify"
#define CAP_EXTENDED_JOIN "extended-join"
#define CAP_USERHOST_IN_NAMES "userhost-in-names"
#define CAP_SETNAME "setname"
#define CAP_ECHO_MESSAGE "echo-message"
#define CAP_STANDARD_REPLIES "standard-replies"
#define CAP_AWAY_NOTIFY "away-notify"
#define CAP_BATCH "batch"
#define CAP_LABELED_RESPONSE "labeled-response"
#define CAP_INVITE_NOTIFY "invite-notify"
/* PHASE 12. Two names, and they are NOT interchangeable -- the `tls`
 * specification is deprecated in favour of `sts`, and this codebase implements
 * both because they answer different questions about the same node.
 *
 *   tls   "the server supports the STARTTLS command". A hint. Deprecated by the
 *         IRCv3 working group in favour of `sts`, but implemented here because the
 *         STARTTLS command is implemented here and a client that wants to upgrade
 *         has to be able to find out that it can. Its specification is also the
 *         only one that says when STARTTLS may be used, which is load-bearing for
 *         commands.c's handler.
 *
 *   sts   Strict Transport Security. NOT a hint: it carries a policy value
 *         (`sts=duration=...,port=...`) that a conforming client acts on by
 *         refusing to make insecure connections at all. It is the only part of
 *         this phase that protects a RETURN visit, which is why it is the one that
 *         matters, and why the implicit-TLS listener exists at all.
 *
 * BOTH ARE WITHHELD ON A NODE WITH NO CERTIFICATE, which is cap.h's rule rather
 * than a decision of this phase: a node that advertised either could not honour
 * it. AND BOTH ARE WITHHELD ON A CONNECTION THAT IS ALREADY ENCRYPTED, which is
 * the specification's rule rather than this file's: `tls` says the server supports
 * the STARTTLS command and there is nothing left to upgrade, and `sts` is a policy
 * about upgrading a connection that has already been upgraded. That is why
 * cap_available() takes a `conn_t *` -- the implicit-TLS listener and a STARTTLS
 * upgrade both put an encrypted conn_t on a node whose certificate is perfectly
 * well configured, and a node-wide answer would be a lie on exactly those two
 * connections. */
#define CAP_TLS "tls"
#define CAP_STS "sts"

/* The `sts` capability's VALUE, rendered for CAP LS.
 *
 * IT IS RENDERED AND NOT REQUESTED, which is the part of the specification that
 * is easy to get backwards. From the `sts` specification:
 *
 *   - "When enabled, the capability has a REQUIRED value: a comma (,) separated
 *     list of tokens."
 *   - "Clients MUST NOT request this capability with `CAP REQ`. Servers MAY reply
 *     with a `CAP NAK` message if a client requests this capability."
 *
 * So `CAP LS` carries `sts=...`, a `CAP REQ :sts` is NAKed, and a client never
 * negotiates it. That is why `sts` is the ONE name in this file whose REQ is
 * refused, and why it is refused in cap.c's REQ handler rather than by leaving it
 * out of the table: a client that asked and got an ACK would believe it had
 * negotiated a policy that governs what it may connect to.
 *
 * The two keys, and WHICH IS REQUIRED when:
 *
 *   port=       REQUIRED on an INSECURE connection -- which is where `CAP LS`
 *               travels, so in practice it is always required here. It is the port
 *               the client must reconnect to. **A `sts` WITH NO `port` IS NOT
 *               RENDERED AT ALL**, and that is a change: this comment used to say
 *               the key was "omitted when this node has no --tls-port" and called
 *               that absence CORRECT, on the grounds that "the specification says a
 *               client that receives a persistence policy with no port over an
 *               insecure connection ignores it". The specification says the
 *               opposite, and the difference is the whole of the fix:
 *
 *                 "If any required part is missing, clients MUST continue as if no
 *                  STS policy was advertised."
 *
 *               So the absence was not a client ignoring a malformed policy -- it
 *               was a client doing exactly what it was told, which is to behave as
 *               though this node had no policy, indistinguishable from a node that
 *               has no downgrade protection at all. Meanwhile an operator reading
 *               `CAP LS` concluded protection that did not exist, which is the
 *               "advertise before the feature exists" failure this file exists to
 *               prevent, and a client that honoured only `duration` cached a
 *               persistence policy for a hostname with no secure port and then
 *               refused to connect.
 *
 *               The rule is also that `sts` is "incompatible with servers that offer
 *               secure connections only via STARTTLS on an insecure port", and a
 *               node with a certificate and no --tls-port is exactly that node. So
 *               there is no configuration in which omitting `port` was the honest
 *               rendering: cap.c's sts_possible() withholds the NAME instead, and
 *               plain `tls` -- which is merely true -- is still advertised.
 *   duration=   REQUIRED on a SECURE connection -- how long the client must keep
 *               using TLS. **A `duration=0` IS NOT RENDERED AT ALL**, and that is
 *               the second change this pass made to this paragraph: it used to say
 *               that `duration=0` with a `port` "is correct and is deliberately not
 *               changed -- it names where TLS is available and asserts no
 *               persistence, which is the default the specification recommends", and
 *               that was a true statement about the specification's EXAMPLE
 *               CONFIGURATION applied to a CAPABILITY LINE.
 *
 *               Those are two different places. An example configuration is a file
 *               an administrator edits, and `duration=0` in one is a decision. A
 *               capability line is a sentence this node composes from whatever the
 *               operator's flags happened to say -- and `--tls-sts-duration` DEFAULTS
 *               TO ZERO, so a node that was given a certificate and a secure port
 *               and nothing else advertised `sts=duration=0,port=NNNN` as though
 *               somebody had chosen it. A client cannot tell the two apart, and the
 *               specification's own sentence says why the default belongs in an
 *               example and not on the wire: using it in an example configuration
 *               "will require server administrators to deliberately choose an expiry
 *               according to their specific needs rather than (perhaps unknowingly)
 *               rely on an arbitrary generic value". Withholding the name is what
 *               makes the choice deliberate; `tls` still answers the question the
 *               capability was partly answering, and is true.
 *
 *               THE COST, because the previous paragraph is not an argument against
 *               this one: an operator who wants "TLS here, persist nothing" can no
 *               longer say so in `CAP LS`, because the only rendering of that wish is
 *               a capability indistinguishable from the one where nobody thought
 *               about it. They get `tls` -- STARTTLS is available -- which is the
 *               part that is a fact about this node rather than a policy about a
 *               future visit.
 *
 * The buffer is a constant rather than a caller-chosen size for the same reason
 * CAP_LS_MAX is: `sts=duration=4294967295,port=65535` is 34 bytes, and a capability
 * that could be truncated is a capability that silently hides its own policy. */
#define CAP_STS_VALUE_MAX 48

/* 410 ERR_INVALIDCAPSUBCOMMAND. Not in design 4.4's numeric list, which is a gap
 * in the list rather than in the protocol, for the same reason 301, 303, 417,
 * 302, 371/374 and 402 are: the RFC defines it and it is the one a client
 * understands. The alternative -- 421, which the wire DOES have for an unknown
 * command -- would be a lie about what happened, because CAP is a known command
 * with an unknown SUBcommand, and a client that retried `CAP` on a 421 would get
 * the same answer for ever. */
#define RPL_INVALIDCAPSUBCOMMAND "410"

/* 908 RPL_SASLMECHS: the mechanisms this node offers. It is sent in answer to
 * `AUTHENTICATE` with a mechanism this node does not implement, which is the only
 * place a client learns what to try instead. */
#define RPL_SASLMECHS "908"

/* Initialise `c`'s capability state. conn_new() gets this right for free because
 * it callocs, and it is here so that a caller which already has a conn_t can say
 * so explicitly. Idempotent. */
void cap_init(conn_t *c);

/* Is `name` a capability THIS BUILD knows about at all? Distinct from
 * cap_available(), which also asks whether this NODE can do it right now: a
 * capability this build has never heard of is answered 410, and one this build
 * knows but this node cannot currently do is answered NAK. */
int cap_known(const char *name);

/* Can this node offer `name` TO THIS CONNECTION RIGHT NOW? 1 offered, 0 not.
 *
 * `c` IS PART OF THE QUESTION, and it is not a convenience parameter. `tls` and `sts`
 * describe a way to get from PLAINTEXT to encrypted, so on a connection that is
 * already encrypted neither can be true: the `tls` specification forbids advertising
 * `tls` on a secure connection, and `sts` is a policy about upgrading a connection
 * that is already upgraded. Every other name in the table is a property of the NODE
 * (or of the connection's own negotiation state, which its own predicate reads), so
 * `c` is NULL for them and only these two read it.
 *
 * A NULL `c` means "ask about the node, not about a connection" and is answered as
 * a PLAINTEXT connection -- the widest list. cap.c's conn_plaintext() gives the
 * reasoning; the one caller with no connection is tests/protocol/test_cap_bounds.c,
 * which sweeps the buffer bound and wants the longest list it can render.
 *
 * Cost: one pointer test and, for the two TLS names, one transport-pointer test --
 * per CAP LS, not per packet. */
int cap_available(const server_t *s, const conn_t *c, const char *name);

/* Render the available set into `out` as the space-separated list a `CAP LS`
 * trailing parameter carries. Returns the byte count written, or 0 if it does not
 * fit -- which cannot happen for a buffer sized CAP_LS_MAX, and is reported
 * rather than truncated if it somehow does.
 *
 * `c` is threaded through for the reason cap_available() above gives: the rendered
 * list depends on whether the connection being answered is already encrypted, so a
 * `CAP LS` over TLS is a SHORTER list than the same command on the plaintext port of
 * the same node. That difference is the point of the parameter and is asserted on
 * the wire in tests/integration/test_tls.c. */
size_t cap_available_list(const server_t *s, const conn_t *c, char *out, size_t cap);

/* A buffer that holds every capability this node can advertise plus their
 * separators and a NUL. It is a constant rather than a caller-chosen size so a
 * new capability cannot be added without the buffer growing with it -- which is
 * the failure where a truncated LS silently hides a capability from every client
 * that asks. */
/* The worst case a CAP LS/REQ/NAK reply can occupy, DERIVED rather than picked.
 *
 * This was 256, and CodeQL was right that three snprintf calls could overflow it:
 * cap_split() accepts up to CAP_MAX_REQ names of up to CAP_NAME_MAX bytes each, so
 * the reply can need CAP_MAX_REQ * (CAP_NAME_MAX + 1) bytes of names PLUS one
 * separator between each pair -- 1040 + 15 = 1055 into a 256-byte stack buffer.
 * Reachable from the wire by any client sending sixteen long capability names.
 *
 * The arithmetic is spelled out here so the number cannot drift from the inputs
 * again, which is what made 256 wrong in the first place: it was a guess about how
 * much text a reply needs rather than a function of how much text can arrive. */
/* How many capability names one CAP REQ may carry, and the longest name accepted.
 * cap_split() rejects anything longer than CAP_NAME_MAX as "not a capability", and
 * more than CAP_MAX_REQ names as "more than we will consider" -- both refusals,
 * not silent truncation. They live here rather than in cap.c because CAP_LS_MAX is
 * derived from them and a derived constant in one file reading inputs in another is
 * how the two drift apart. */
#define CAP_MAX_REQ 16
#define CAP_NAME_MAX 64

/* The worst case a CAP LS/REQ/DEL/NAK/LIST reply can occupy, DERIVED from its
 * inputs.
 *
 * This was 256, and CodeQL was right that the accumulating snprintf calls in cap.c
 * could overflow it. cap_split() accepts up to CAP_MAX_REQ names of up to
 * CAP_NAME_MAX bytes each, so a refused list can need
 * CAP_MAX_REQ * (CAP_NAME_MAX + 1) + CAP_MAX_REQ bytes -- 1040 + 16 = 1056 --
 * into what was a 256-byte STACK buffer. Measured: sixteen 64-character capability
 * names, which any client may send, need 1040 bytes, so the overflow is 784 bytes
 * and it is reachable from the wire.
 *
 * The accumulation is what makes it an overflow rather than a truncation:
 * snprintf returns the length it WOULD have written, so `rn` grows past the end of
 * the buffer, `refused + rn` is already out of bounds, and `sizeof refused - rn`
 * underflows as a size_t. Three bugs in one expression.
 *
 * 256 was a guess about how much text a reply needs rather than a function of how
 * much text can arrive, and CAP_MAX_REQ and CAP_NAME_MAX live here rather than in
 * cap.c so the derivation can see them -- a derived constant in one file reading
 * inputs in another is exactly how the two drifted apart.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS NUMBER DOES NOT COVER, WHICH #123 FOUND (#123)
 * ---------------------------------------------------------------------------
 * The derivation above bounds a REPLY to a client's request: at most CAP_MAX_REQ
 * names, each at most CAP_NAME_MAX. It does NOT bound what this node puts in a
 * reply of its own accord, and there are two of those:
 *
 *   CAP LS      the whole available set, plus `sts`'s value. Bounded on every
 *               write by cap_available_list(), which accounts for the value's
 *               length separately and fails to empty rather than truncating.
 *               tests/protocol/test_cap_bounds.c sweeps every capacity from 1 to
 *               CAP_LS_MAX + 64 with a canary behind the buffer and asserts no
 *               write escapes at any of them.
 *
 *   CAP LIST    the names this client enabled. Those names come from the node's own
 *               `k_caps` table, not from the wire -- cap_enabled() matches a name
 *               against the table -- so a client cannot make this arm long by
 *               asking. It was, however, accumulated BY HAND with no bound on any of
 *               its four writes, and it is now routed through the same bounded
 *               helper the ACK/NAK arms use.
 *
 * AND THE TABLE IS ALREADY LARGER THAN THE DERIVATION. `k_caps` holds SEVENTEEN
 * names and CAP_MAX_REQ is sixteen, so a reply this node composes from its own
 * table is not covered by this derivation even in principle; what bounds it in
 * practice is that the seventeen names total 186 bytes against 1056. A client can
 * reach all seventeen by REQing sixteen and then one more (c->caps accumulates
 * across REQs during a negotiation), so seventeen IS reachable from the wire --
 * 203 bytes with separators and the NUL, 19.2% of this buffer.
 *
 * So this constant is not what holds either arm up, and the arithmetic above
 * should not be read as saying it is. It is the size of the buffer; the two arms
 * that fill it are what enforce the bound, and each is asserted separately. */
#define CAP_LS_MAX (CAP_MAX_REQ * (CAP_NAME_MAX + 1) + CAP_MAX_REQ)

/* Is the client still mid-negotiation, and therefore is registration held?
 * TRUE from the first `CAP LS` or `CAP REQ` until `CAP END`. This is the one
 * boolean the registration gate in commands.c asks, and it lives here so that the
 * thing that STARTS the negotiation and the thing that RELEASES it are in one
 * file. */
int cap_negotiating(const conn_t *c);

/* Has the client enabled `name`? 1 enabled, 0 not. Case-insensitive on the name,
 * because IRCv3 capability names are. */
int cap_enabled(const conn_t *c, const char *name);

/* draft/message-ids: whether this node writes a `msgid` on a delivered message
 * to this client. REQUIRES message-tags as well, and the two are not
 * interchangeable -- see cap.c for why a msgid without tag support is not a
 * best-effort thing to do. */
int cap_message_ids_enabled(const conn_t *c);

/* account-tag: whether this node writes an `account` tag naming the SENDER's
 * account on a line it delivers to this client. REQUIRES message-tags for
 * exactly the reason cap_message_ids_enabled() does, and the second half of the
 * emission is the account NAME -- which this node resolves from its own registry,
 * once per emission, and renders per destination.
 *
 * BOTH GATES ARE PER DESTINATION. That is the shape of the whole feature and it
 * is not a detail: two members of one channel are free to disagree about whether
 * they want to be told who sent a message, and a tag block written once for an
 * emission would put it on the line of the one who asked for none. */
int cap_account_tag_enabled(const conn_t *c);

/* `away-notify` in the shape `fanout.h`'s `fanout_gate_fn` wants --
 * `int (*)(const conn_t *, void *)` -- so the away notification can be handed to
 * `fanout_deliver_local_gated()` with no glue at the call site. Asked about the
 * DESTINATION: a member who asked for the capability is still not told their
 * own state (the setter is excluded), and a member who did not ask is told
 * nothing at all. */

int cap_gate_away_notify(const conn_t *dst, void *ctx);

/* `setname` in the shape `fanout.h`'s `fanout_gate_fn` wants, for the
 * COMMON-CHANNEL FAN-OUT rather than for the confirmation.
 *
 * THE GATE IS ASKED ABOUT THE DESTINATION, and this is the specification's own
 * condition rather than a choice: "The SETNAME message MUST NOT be sent to clients
 * which do not have the `setname` capability negotiated." A realname is personal
 * data, so who hears about a change is decided by the person hearing it;
 * gating the fan-out on the SENDER would make the two halves of one specification
 * answer opposite questions about the same field. */

int cap_gate_setname(const conn_t *dst, void *ctx);

/* `invite-notify` in `fanout.h`'s `fanout_gate_fn` shape: the audience is the
 * channel members that negotiated it, not the invitee. */
int cap_gate_invite_notify(const conn_t *dst, void *ctx);

/* Handle one `CAP` line. Returns 1 if it was handled, 0 if it was not a CAP at
 * all (which cannot happen: the caller has already dispatched on the verb). */
void cap_handle(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_CAP_H */
