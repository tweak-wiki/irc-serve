/* link_guard.c -- see federation/link.h. The FEDERATE admission guard.
 *
 * Split verbatim out of link.c (issue #543 TU-35): the constant-time secret
 * comparison and fed_check_federate() itself (shape/secret/identity checks).
 * The verdict spellings (FED_REASON_NAME/FED_REASON_KEY), fed_federate_reason(),
 * the per-reason counter and the observable dump stay in link.c; the refusal
 * and claim-accepted arms that consume verdicts stay there too and are reached
 * through link.h.
 */
#include "federation/link.h"

#include <string.h>

/* Constant-time secret comparison.
 *
 * The threat is specific and it is the reason this is not strcmp(): a
 * rejection closes the connection, so the TIME at which the close arrives is
 * observable to whoever opened it, and strcmp returns at the first differing
 * byte. That is a prefix oracle -- try a secret a byte at a time and the
 * close latency tells you when you are right -- and it needs no access to this
 * node beyond the ability to open a socket to it.
 *
 * So the diff is accumulated in an unsigned char and the loop runs to the end
 * with no early exit, and the accumulator is what is tested at the end. The
 * casts are explicit because an implicit char-to-unsigned-char conversion is
 * exactly the kind of thing -Wsign-conversion reports, and a diagnostic about
 * a secret comparison is a diagnostic worth having.
 *
 * The LENGTH is compared by the same walk rather than separately: the loop
 * runs to max(la, lb) and reads 0 for the side that has already ended. A C
 * string has no embedded NUL, so the byte past the end of the shorter one is
 * always non-zero on the longer side, and a length difference therefore shows
 * up as a differing byte like any other -- which is why there is no branch on
 * the lengths and no separate length term to fold in. */
static int secret_matches(const char *configured, const char *offered)
{
    size_t la;
    size_t lb;
    size_t n;
    size_t i;
    unsigned char diff = 0;

    if (configured == NULL || offered == NULL) {
        return 0;
    }
    la = strlen(configured);
    lb = strlen(offered);
    n = (la > lb) ? la : lb;
    for (i = 0; i < n; i++) {
        unsigned char a = (i < la) ? (unsigned char)configured[i] : (unsigned char)0;
        unsigned char b = (i < lb) ? (unsigned char)offered[i] : (unsigned char)0;

        diff |= (unsigned char)(a ^ b);
    }
    return (diff == 0u) ? 1 : 0;
}

fed_federate_result_t fed_check_federate(const server_t *s,
                                         const server_link_t *self,
                                         const message_t *m, const char *secret,
                                         uint64_t *peer_epoch_out)
{
    const char *claim;
    uint64_t peer_epoch = 0;
    size_t i;

    if (s == NULL || m == NULL) {
        return FED_BAD_ARITY;
    }

    /* --- 1. shape ------------------------------------------------------- */
    /* A FEDERATE names the sender twice: once as the prefix and once as the
     * first parameter. The PARAMETER is the authority, and the prefix is
     * required to be present because a line that does not say who sent it is
     * not a handshake. They are deliberately not cross-checked against each
     * other here: the inbound prefix rules are fed_dispatch()'s, and a second
     * opinion about them in the link module is a second opinion somebody can
     * have. Until C3 exists, a peer whose prefix disagrees with its claim is
     * one the shape check accepts and the claim check then applies -- which is
     * the right way round, because the claim is the name that would have to be
     * unique. */
    if (m->nparams != 4 || m->prefix == NULL) {
        return FED_BAD_ARITY;
    }
    claim = m->params[0];
    if (claim == NULL || strlen(claim) > (size_t)IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(claim)) {
        return FED_BAD_NAME;
    }
    /* 2.4's epoch grammar, enforced by the shared overflow-safe
     * parse_decimal: 1..20 digits, no leading zero, <= UINT64_MAX. */
    if (m->params[1] == NULL ||
        parse_decimal(m->params[1], strlen(m->params[1]), UINT64_MAX,
                      &peer_epoch) != 0) {
        return FED_BAD_EPOCH;
    }
    if (strcmp(m->params[3], IRC_SERVE_VERSION) != 0) {
        return FED_BAD_VERSION;
    }

    /* --- 2. the secret -------------------------------------------------- */
    /* Before the identity checks, so that a node which is not allowed to be
     * here learns nothing about this node's name space. */
    /* AN EMPTY CONFIGURED SECRET REFUSES, AND THAT IS THE POLICY.
     *
     * `irc-serve 6667` has no --secret, so the secret is "", and the constant-
     * time compare below answers ACCEPT for an offered "" because two empty
     * strings are equal. On a default-configured node that made the secret step
     * a step nobody could fail: the ONLY thing standing between anyone who can
     * reach the TCP port and a peer link under a name of their choosing was an
     * equality between two empty strings.
     *
     * AN HONEST WORD ON HOW REACHABLE THAT WAS, because the difference matters
     * to whoever reads this later. An empty parameter cannot be put on the wire
     * in a non-final position by this node's parser: core/message.c skips an
     * empty token rather than counting it, and a `:` parameter swallows the rest
     * of the line. So `:x FEDERATE n 1 "" irc-serve-0.1.0` arrives with the
     * secret parameter set to the two characters quote-quote, and the line
     * `:x FEDERATE n 1 : irc-serve-0.1.0` arrives as three parameters and is
     * refused as BAD_ARITY. Checked against the shipped binary, not inferred.
     * The empty-vs-empty accept was therefore LATENT rather than open: what
     * stood between a default-configured node and a stranger was a parser rule
     * in a module that knows nothing about peers, not a check in this path.
     * A change to a parameter rule in core/message.c -- which is a
     * one-line-shaped change and is the kind this tree makes -- would have opened
     * it, and nothing in the link path would have said so. This check is the
     * link path's own answer, and it holds whatever a parser does with an empty
     * parameter.
     *
     * The alternative -- treating "no secret" as "no authentication" -- was
     * what the default used to mean, and it is not what an operator who reads
     * `secret=none` on the startup line is being told. Federation here is
     * OPT-IN: a node federates because it was given a secret, so a node with no
     * secret is a node that federates with nobody, and it says so on the wire
     * with a verdict of its own rather than folding the case into BAD_SECRET.
     * An operator reading `reason=` has to be able to tell "somebody guessed
     * wrong" from "this node is not configured to federate", because the fixes
     * are opposites: the first is a credential under attack, the second is a
     * missing --secret. BAD_SECRET on a node whose secret is empty would also be
     * a lie in the other direction -- it would say the offered value was wrong
     * when the truth is that no value is right.
     *
     * BEFORE secret_matches(), and deliberately so. secret_matches() is a
     * correct constant-time compare and stays one, unchanged; what it cannot do
     * is express a policy, and "is authentication switched on at all" is a
     * policy rather than an equality.
     *
     * It does not break backward compatibility, which is the thing that made it
     * look hard. `irc-serve 6667` still starts, binds, serves clients and
     * prints the same lines: the CLIENT surface is untouched, and this check is
     * reached only by a FEDERATE, a peer handshake that did not exist before
     * Phase 6 and therefore cannot be something a working deployment depended
     * on.
     *
     * The cost, stated exactly, and it is SMALLER than the argument above first
     * suggests: a node with no secret could not federate anyway, in either
     * direction. Its own claim never left the node -- fed_queue_federate()
     * renders a FEDERATE whose third parameter is the secret, and
     * message_format() refuses a parameter the wire cannot represent in a
     * non-final position, which an empty one is -- so a default-configured node
     * dialling a peer reports `link_send_failed: reason=UNRENDERABLE` and sends
     * nothing at all. Both of those were checked against the shipped binary,
     * not inferred. So there is no working all-`--secret`-less mesh for this to
     * break; what changes is that the INBOUND refusal now exists, is named, and
     * is counted, instead of depending on a parser in core/message.c to keep
     * an empty parameter off the wire.
     *
     * The one behaviour a deployment could notice is the one the policy is
     * ABOUT: a node with a --secret and a node without one can no longer link
     * to each other, which is correct, because one of them is not authenticating
     * anybody. The remaining cost is a diagnostic that used to say
     * UNRENDERABLE where it means "you gave me no secret", and that is a
     * follow-up on the OUTBOUND side of fed_queue_federate() rather than
     * something this check can fix. */
    if (secret == NULL || secret[0] == '\0') {
        return FED_NO_SECRET;
    }
    if (!secret_matches(secret, m->params[2])) {
        return FED_BAD_SECRET;
    }

    /* --- 3. not our own name -------------------------------------------- */
    if (irc_ascii_same(claim, s->name)) {
        return FED_SELF_NAME;
    }

    /* --- 4. uniqueness -------------------------------------------------- */
    /* The link this exchange is ON is skipped: it is not a rival claim on the
     * name it is handshaking about, and a dialling node has held one since the
     * moment the peer was configured. Every OTHER link with this name is a
     * rival, and the difference between the two verdicts is the whole of 2.3's
     * rule: a link that is ESTABLISHED is a live route to that name, and
     * admitting a second one is the split brain; a link that HOLDS A DESCRIPTOR
     * but is not established is a half-open exchange for the same name, and
     * admitting a second one would put two descriptors on one identity.
     *
     * AND A LINK WITH NO DESCRIPTOR IS NEITHER. That clause is the correction,
     * and it was missing until a re-link was tested: a link in INIT with fd == -1
     * is a NAME and a DESTINATION, not a claim on the name. It is what fed_dead()
     * leaves behind -- the peer went away, the descriptor is closed, the name is
     * kept so that T7 can dial it again and so that 2.2's fail-closed rule has an
     * origin to be unreachable FROM. Refusing a peer's re-claim because such a
     * link exists made 2.2's "re-linking a server of the same name resurrects the
     * channel" UNREACHABLE: the peer re-dialled, was told the name was in use by
     * a link that had no socket on it, and the mesh could never recover from a
     * partition without an operator deleting configuration.
     *
     * THE COST, and it is the reason this is about the DESCRIPTOR and not about
     * the state: a node can now hold at most one link per name whose fd is >= 0
     * and any number whose fd is -1, and only the first kind is a claim. A link
     * that is FAILED or TIMED_OUT WITH A DESCRIPTOR still holds one -- T2 leaves
     * the descriptor alone on purpose -- so a peer re-dialling into that state is
     * still refused with NAME_IN_USE, and clearing it is fed_link_reset()'s job.
     * That asymmetry is left as it is rather than papered over: it is the same
     * asymmetry link.h draws between a link that was established and went away
     * (resettable, because there is something to stop believing in) and one that
     * never completed (terminal, because there was never anything to believe). */
    for (i = 0; i < server_link_count(s); i++) {
        const server_link_t *other = server_link_at(s, i);

        if (other == NULL || other == self || !irc_ascii_same(other->name, claim)) {
            continue;
        }
        if (other->state == (int)ESTABLISHED) {
            return FED_DUPLICATE_LINK;
        }
        if (other->fd >= 0) {
            return FED_NAME_IN_USE;
        }
    }
    /* And the same answer reached through the function every router uses. It
     * is redundant with the scan above by construction, and it is here anyway:
     * server_find_peer() is the ESTABLISHED-narrowed predicate, so if the two
     * ever disagreed about what counts as established this would reject rather
     * than admit a second route to a name the node can already reach. */
    if (server_find_peer(s, claim) != NULL) {
        return FED_DUPLICATE_LINK;
    }
    /* A connection already on a link, presenting a DIFFERENT name.
     *
     * This had no verdict of its own and answered FED_DUPLICATE_LINK, which was
     * wrong and is retracted here: a node dialled a peer under one name and the
     * peer announced another is a MISCONFIGURATION -- one side's --peer or
     * --name disagrees with the other side's --name -- and not a split brain.
     * The two have opposite fixes and different shapes of aftermath, and
     * reporting a name disagreement as a duplicate route is exactly the
     * overloading this verdict was supposed to prevent. Split brain has its own
     * verdict above, and it is the one that increments n_link_duplicate.
     *
     * The rejection itself is unchanged and for the same reason as every other
     * rejection: a link has exactly one name (the table is keyed on it), so a
     * second identity presented on one socket cannot be adopted, and accepting
     * it would leave this node with a route whose name is not the one the
     * handshake was checked against. The line is closed, counted and dumped
     * like any other, under a name that says what happened. */
    if (self != NULL && !irc_ascii_same(self->name, claim)) {
        return FED_NAME_MISMATCH;
    }
    /* Only on the accepted path, and the out-parameter is why: the epoch is
     * parsed in the shape check because that is where the grammar belongs, and
     * the caller needs it to stamp the link. Returning it only on FED_OK means
     * a caller that ignores a verdict never has a half-validated epoch to
     * write onto a link, which is the one way this out-parameter could be
     * misused. A NULL out-parameter is fine -- it is optional. */
    if (peer_epoch_out != NULL) {
        *peer_epoch_out = peer_epoch;
    }
    return FED_OK;
}

