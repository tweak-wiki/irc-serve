/* shapes.c -- the frozen S-verb parameter shapes, split out of federation/verbs.c
 * (issue #543). Verbatim move; the encoders are declared in federation/verbs.h. */
#include "federation/verbs.h"

#include "core/account.h"

#include <string.h>

/* ---------------------------------------------------------------------------
 * The frozen shapes
 * ------------------------------------------------------------------------- */

/* The nick of a `nick!user@host` prefix, or `prefix` itself when it has no '!'.
 * Writes at most `cap` bytes. 2.1 defines the hostmask with exactly one '!' and
 * the nick before it, so this is a cut and not a parse: nothing a client can
 * send makes a second '!' part of the nick, because '!' is not a legal nick
 * character (2.1's own charset rule). */
static const char *fed_prefix_nick(const char *prefix, char *out, size_t cap)
{
    const char *bang = strchr(prefix, '!');
    size_t n = (bang != NULL) ? (size_t)(bang - prefix) : strlen(prefix);

    if (n >= cap) {
        return NULL;
    }
    memcpy(out, prefix, n);
    out[n] = '\0';
    return out;
}

/* The member's prefix flags as the single token 4.3's SJOIN carries, and the
 * `-` that means "none".
 *
 * THE EMPTY CASE IS A LITERAL, and the reason is the wire rather than taste: an
 * empty middle parameter is not representable here at all. 3.2 says a value that
 * needs the ':' marker is only representable in the FINAL position, and
 * message_parse() drops an uncolonned empty token, so a shape that said "omit
 * the flags when there are none" would arrive as a TWO-parameter SJOIN on one
 * node and the receiver would have to guess whether the third field was missing
 * or empty. `-` is one byte, never needs a colon, and cannot be confused with a
 * flag run. */
static const char *fed_flag_token(unsigned flags, char *out, size_t cap)
{
    size_t used = 0;

    if (cap < 2u) {
        return NULL;
    }
    if (flags == 0u) {
        out[0] = '-';
        out[1] = '\0';
        return out;
    }
    out[used++] = '+';
    if ((flags & CHAN_MEMBER_OP) != 0u && used + 1u < cap) {
        out[used++] = 'o';
    }
    if ((flags & CHAN_MEMBER_VOICE) != 0u && used + 1u < cap) {
        out[used++] = 'v';
    }
    out[used] = '\0';
    return out;
}

/* The member's flags, looked up on the channel the emission is about.
 *
 * READ OUT OF THE CHANNEL RATHER THAN PASSED IN, and the reason is authority:
 * the flags are a property of the MEMBERSHIP, and the node forwarding the join
 * is the node that just made it, so its own record is the authority for what it
 * granted. A parameter would have to be threaded through fanout_deliver() and
 * fanout_forward_link() for one value that one caller (handle_join) knows and
 * every other caller does not -- and a default of 0 on the other five would be a
 * way for an SJOIN to lose +o without anybody noticing. */
/* An account name, or `*`, into `out`. The ONE place the protocol's
 * "no account" spelling is produced for the S-verb side, for the same reason
 * fanout.c's fanout_emitter_account() is the one place it is produced on the
 * client side: a token written in two places is a token that comes to disagree
 * with itself about what an absent account looks like. */
static int fed_account_token(const char *name, char *out, size_t cap)
{
    size_t n;

    if (out == NULL || cap < 2u) {
        return 0;
    }
    if (name == NULL || name[0] == '\0') {
        out[0] = '*';
        out[1] = '\0';
        return 1;
    }
    n = strlen(name);
    if (n >= cap) {
        return 0;
    }
    memcpy(out, name, n + 1u);
    return 1;
}

/* The member's account as 4.3's SJOIN carries it: the account name, or `*`.
 *
 * READ OUT OF THE MEMBERSHIP for the same reason fed_member_flags() reads the
 * flags out of it, and with the same asymmetry handled the same way: a LOCAL
 * member is a conn_t and its account is account_name() -- "" for a connection that
 * is not identified, which renders as `*` -- while a REMOTE member's account is
 * the field its SJOIN or SBURSTM filled in, and an entry this node has not been
 * told about renders as `*` too.
 *
 * `*` IS NEVER STORED, so a member with an empty `account` field and a member who
 * has no account at all are the same value here, which is the roster-level version
 * of 2.1.1's invariant: there is no such thing as an account named "*". The buffer
 * is ACCOUNT_SJOIN_ACCOUNT_MAX because the value is either a name or that one
 * byte, and a name is bounded by CONN_MAX_ACCOUNT. */
#define ACCOUNT_SJOIN_ACCOUNT_MAX (CONN_MAX_ACCOUNT + 2u)

static int fed_member_account(const chan_t *ch, const char *nick, char *out,
                              size_t cap)
{
    const struct member *local;

    /* A NULL CHANNEL IS NOT A REFUSAL, and that is fed_member_flags()'s rule
     * applied to a second property: a caller shaping a JOIN for a channel this
     * node does not hold -- which a peer-only fixture and a forward of a channel
     * whose record has already been dropped both are -- still has to produce a
     * legal SJOIN, and "no membership here" is truthfully `*`. Refusing would make
     * the whole forward of that line fail with BAD_SHAPE, which says nothing true
     * about anything. */
    if (nick == NULL || out == NULL || cap < 2u) {
        return 0;
    }
    if (ch == NULL) {
        return fed_account_token("", out, cap);
    }
    local = chan_find_nick(ch, nick);
    if (local != NULL && local->c != NULL) {
        return fed_account_token(account_name(local->c), out, cap);
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].nick, nick)) {
            return fed_account_token(ch->remotes[i].account, out, cap);
        }
    }
    return fed_account_token("", out, cap);
}

/* The member's ident and visible host as 4.3's extended SJOIN carries them.
 *
 * READ OUT OF THE MEMBERSHIP, like the flags and the account above, and only
 * ever asked at the ORIGIN: fed_sverb_params() runs where the membership was
 * just made, so the member is local and the connection is its authority. A
 * relay never re-shapes, so this never sees a remote member in practice -- but
 * the fallback is `*`/`-`-shaped anyway rather than a refusal, for the same
 * reason fed_member_account() falls back to `*`: shaping a JOIN must not fail
 * for a record that is already gone.
 *
 * `-` IS THE EMPTY SPELLING for both fields (burst.c's burst_mid_or_dash()
 * contract), and it is translated back to "" on receipt. The copies cannot
 * truncate -- the scratch is sized for the widest value each conn_t field can
 * hold -- so a short buffer is a caller bug and refused rather than cut. */
static int fed_member_hostmask(const chan_t *ch, const char *nick, char *user,
                               size_t user_cap, char *host, size_t host_cap)
{
    const struct member *local;

    if (nick == NULL || user == NULL || host == NULL || user_cap < 2u ||
        host_cap < 2u) {
        return 0;
    }
    if (ch != NULL) {
        local = chan_find_nick(ch, nick);
        if (local != NULL && local->c != NULL) {
            const char *u = (local->c->user[0] != '\0') ? local->c->user : "-";
            const char *h = (local->c->host[0] != '\0') ? local->c->host : "-";

            if (strlen(u) + 1u > user_cap || strlen(h) + 1u > host_cap) {
                return 0;
            }
            memcpy(user, u, strlen(u) + 1u);
            memcpy(host, h, strlen(h) + 1u);
            return 1;
        }
    }
    user[0] = '-';
    user[1] = '\0';
    host[0] = '-';
    host[1] = '\0';
    return 1;
}

static unsigned fed_member_flags(const chan_t *ch, const char *nick)
{
    const struct member *local;

    if (ch == NULL || nick == NULL) {
        return 0u;
    }
    local = chan_find_nick(ch, nick);
    if (local != NULL) {
        return local->flags;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].nick, nick)) {
            return ch->remotes[i].flags;
        }
    }
    return 0u;
}

int fed_sverb_params(const char *client_verb, const char *target,
                     const char *const *params, int nparams, const char *prefix,
                     const char *self, const chan_t *ch,
                     fed_sverb_scratch_t *scratch, const char **out, int cap)
{
    const char *member = NULL;
    int n = 0;

    if (client_verb == NULL || target == NULL || out == NULL || cap <= 0 ||
        scratch == NULL || (params == NULL && nparams != 0)) {
        return -1;
    }
    if (prefix != NULL) {
        member = fed_prefix_nick(prefix, scratch->nick, sizeof scratch->nick);
        if (member == NULL) {
            return -1;
        }
    }

    /* The table is the gate, and it is asked FIRST: a client verb with no S-verb
     * has no shape here either, and returning -1 is what makes the caller report
     * NO_SVERB rather than build a two-parameter line the peer would misread.
     * The per-verb arms below then cover all seven, and each refuses a client
     * shape it cannot honour rather than emitting a default. */
    if (fed_sverb_for(client_verb) == NULL) {
        return -1;
    }
    (void)self;

    out[n++] = target;
    if (cap < 2) {
        return -1;
    }

    if (strcmp(client_verb, "PRIVMSG") == 0 || strcmp(client_verb, "NOTICE") == 0) {
        /* <target> <text>: the client shape, unchanged. A peer that relayed this
         * has said nothing the client line did not. */
        if (nparams < 1 || params[0] == NULL) {
            return -1;
        }
        out[n++] = params[nparams - 1];
        return n;
    }
    if (member == NULL) {
        /* Every state verb names its subject, and without a prefix there is
         * none. A state change with no actor cannot be relayed, and emitting the
         * shape with an empty member would put a zero-length name on the wire. */
        return -1;
    }

    if (strcmp(client_verb, "JOIN") == 0) {
        /* <channel> <member> <flags> <account> <user> <host>.
         *
         * THE ACCOUNT IS THE FOURTH PARAMETER AND IT IS DERIVED FROM THE CHANNEL
         * HERE, for exactly the reason `<flags>` is: both are properties of the
         * MEMBERSHIP, and the node forwarding the join is the node that just made
         * it, so its own record is the authority for both. A local member's account
         * is `account_name()` on its connection and a remote member's is the field
         * 4.3's SJOIN put on the roster entry; `*` is the protocol's spelling of
         * "not logged in to an account", and it is what BOTH of those render as
         * when there is nothing.
         *
         * <user> and <host> are the 4.3 extension (#563): the member's ident and
         * visible host, read out of the member's OWN CONNECTION -- the same
         * authority the flags and the account come from, because the forwarder
         * is the node that just made the membership. `-` is the empty spelling
         * for both (burst.c's burst_mid_or_dash() contract, mirrored), because
         * a middle parameter cannot be empty on this wire and a connection with
         * no ident is a legal state. The copies cannot truncate: the scratch
         * fields are sized for the widest value each conn_t field can hold.
         *
         * THE PEER ALWAYS GETS THE SAME SIX PARAMETERS, which is the reason the
         * client-facing `extended` shape is not handed to the forward
         * (fanout.h): which of this node's CLIENTS negotiated `extended-join` must
         * not change what this node says to a peer. */
        if (n != 1 || nparams != 0 || cap < 6) {
            return -1;
        }
        if (fed_flag_token(fed_member_flags(ch, member), scratch->flags,
                           sizeof scratch->flags) == NULL) {
            return -1;
        }
        if (fed_member_account(ch, member, scratch->account,
                               sizeof scratch->account) == 0) {
            return -1;
        }
        if (fed_member_hostmask(ch, member, scratch->user, sizeof scratch->user,
                                scratch->host, sizeof scratch->host) == 0) {
            return -1;
        }
        out[n++] = member;
        out[n++] = scratch->flags;
        out[n++] = scratch->account;
        out[n++] = scratch->user;
        out[n++] = scratch->host;
        return n;
    }
    if (strcmp(client_verb, "PART") == 0) {
        /* <member> <channel> [<reason>]: the member comes FIRST, so the channel
         * is not in a fixed position and a reader cannot assume it. */
        if (nparams > 1 || (nparams == 1 && params[0] == NULL) || cap < 3) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        n = 2;
        if (nparams == 1) {
            out[n++] = params[0];
        }
        return n;
    }
    if (strcmp(client_verb, "TOPIC") == 0) {
        /* <member> <channel> <topic>. The topic is always present, so a cleared
         * topic is the literal `:` rather than an absent parameter. */
        if (nparams != 1 || params[0] == NULL || cap < 3) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        out[2] = params[0];
        return 3;
    }
    if (strcmp(client_verb, "MODE") == 0) {
        /* <server> <channel> <modes> [<arg>]. */
        if (nparams < 1 || nparams > 2 || cap < 4 || self == NULL) {
            return -1;
        }
        out[0] = self;
        out[1] = target;
        out[2] = params[0];
        n = 3;
        if (nparams == 2) {
            out[n++] = params[1];
        }
        return n;
    }
    if (strcmp(client_verb, "KICK") == 0) {
        /* <member> <channel> <target> [<reason>]. The member is the KICKER,
         * distinct from <target>: they are two users and a shape that carried
         * one would make every KICK look self-inflicted. */
        if (nparams < 1 || nparams > 2 || cap < 4 || params[0] == NULL) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        out[2] = params[0];
        n = 3;
        if (nparams == 2) {
            out[n++] = params[1];
        }
        return n;
    }
    return -1;
}

const char *fed_prefix_server(const char *prefix, char *out, size_t cap)
{
    const char *at;
    size_t n;

    if (prefix == NULL || prefix[0] == '\0' || out == NULL || cap == 0u) {
        return NULL;
    }
    /* 2.1 splits at the LAST '@', and the split is unambiguous because '@' is
     * not a legal nick character. A server name, by contrast, is an opaque
     * string under the 2.4 tag grammar -- which does admit no '@' either, but
     * the SPLIT still has to be the one 2.1 specifies or a name containing one
     * would be cut in the wrong place. A prefix with no '@' is a SERVER prefix
     * and is the name itself. */
    at = strrchr(prefix, '@');
    if (at == NULL) {
        n = strlen(prefix);
    } else {
        n = strlen(at + 1);
        if (n == 0u) {
            return NULL;
        }
        at++;
        if (n >= cap) {
            return NULL;
        }
        memcpy(out, at, n);
        out[n] = '\0';
        return out;
    }
    if (n >= cap) {
        return NULL;
    }
    memcpy(out, prefix, n);
    out[n] = '\0';
    return out;
}

