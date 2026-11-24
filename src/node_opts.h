/* node_opts.h -- the node's command line: defaults, the parsed options struct,
 * and the parser. Split out of node_main.c (issue #543) along the existing
 * seam: everything here touches argv and nothing else, so a future unit seam
 * can drive node_parse_args() without a process. No behaviour change. */
#ifndef IRC_SERVE_NODE_OPTS_H
#define IRC_SERVE_NODE_OPTS_H

#include <stdint.h>

#include "core/message.h"
#include "core/server.h"

/* The node's own name, when --name is not given. It must satisfy the 2.4 tag
 * grammar, because it is stamped on every outbound irc-serve-origin tag, and a
 * name that cannot be stamped would break the never-forward-own-origin rule at
 * the first relay. It is also the prefix on every numeric (002, 004, 005's
 * context, PONG) and the <target>'s server half. */
#define NODE_NAME "irc.test"

/* The secret when --secret is not given. EMPTY, and that is a real default
 * rather than a placeholder, but what it MEANS changed when the inbound
 * handshake was given a policy.
 *
 * It used to mean "peers are unauthenticated": the secret step compared the
 * offered value against "", and two empty strings compared equal, so on a node
 * with no --secret the secret step could not be failed at all. (How far that
 * reached is worth stating precisely, because it was less than it looks: an
 * empty parameter cannot be put on the wire in a non-final position by this
 * node's parser, so a peer could not actually offer one, and the thing standing
 * between a default-configured node and a stranger was a parser rule rather than
 * a check. Step 2 of fed_check_federate() in federation/link.c says so in full.
 * What is not in dispute is that the startup line said only `secret=none`,
 * which reads like a missing feature rather than a missing credential.)
 *
 * It means now that this node federates with NOBODY. `irc-serve 6667` with no
 * --secret starts, binds, serves clients and prints the same lines it always
 * has -- the client surface is entirely untouched -- and it REFUSES every
 * inbound FEDERATE with its own reason, NO_SECRET, so an operator reading
 * `reason=` can tell "somebody guessed wrong" (BAD_SECRET, a credential under
 * attack) from "this node is not configured to federate" (a missing --secret).
 * Federation is opt-in here: a node federates because it was given a secret.
 *
 * The cost, for anyone who was relying on the old reading: smaller than it first
 * looks, because a node with no --secret could not federate in either direction
 * before this. Dialling one put a FEDERATE with an empty secret parameter on the
 * wire, and message_format() refuses a parameter the wire cannot represent in a
 * non-final position, so the node reported `link_send_failed:
 * reason=UNRENDERABLE` and sent nothing. There is therefore no working
 * all-`--secret`-less mesh for this to break; what changes is that the refusal
 * is now this node's own decision rather than an accident of a parser rule, that
 * it is named NO_SECRET instead of being folded into BAD_SECRET, and that it
 * covers the INBOUND side too. The peer handshake did not exist before Phase 6,
 * so no deployment can have depended on it, and the alternative was shipping a
 * mesh that authenticates nobody by default. See fed_check_federate() in
 * federation/link.c for the argument at the place it is enforced. */
#define NODE_DEFAULT_SECRET ""

#define NODE_DEFAULT_PORT 6667

/* The account the node runs as after the listeners are bound (issue #182), when
 * --user is not given. `nobody` is the conventional least-privilege account: it
 * owns no files and is the user with the least reason to exist for any other
 * purpose, so a compromised node gains nothing that is already somebody's. */
#define NODE_DEFAULT_USER "nobody"

/* How many --peer options are accepted, and why the limit is here rather than
 * only in the table.
 *
 * IRC_FED_MAX_PEERS is core/server.h's INITIAL CAPACITY of the link vector, and
 * the vector grows past it, so it is not a limit on how many peers a node can
 * be linked to. The limit that belongs to this file is the size of a command
 * line, and the number is IRC_FED_MAX_PEERS because a mesh of this design's
 * size is a handful of nodes and a command line with seventeen peers in it is
 * a configuration file that should have been one. The two being different is
 * recorded rather than hidden: the cap here is a CLI-surface decision, the
 * growth in fed_link_configure() is a table decision, and neither one enforces
 * the other. */
#define NODE_MAX_PEERS IRC_FED_MAX_PEERS

/* One --peer argument, split into its three fields. Kept as a struct because
 * the resolution is a separate step that runs in main(): nothing here touches a
 * socket, and the split is the last thing that happens to the string before
 * main() hands each field to a function that owns it. */
typedef struct {
    char     name[IRC_MAX_SERVER_NAME + 1];
    char     host[256];
    char     port[16];
} node_peer_t;

/* The command line, parsed. Defaults are filled in first so that every field is
 * either a default or something the operator asked for, and there is no state
 * in which a field is "unset" -- which is what makes the backward-compatibility
 * argument checkable: with no arguments at all, this struct is exactly what the
 * node used before this phase had a command line. */
typedef struct {
    const char *name;
    /* The account to drop to after bind (issue #182), or NODE_DEFAULT_USER.
     * have_user records whether the operator TYPED --user: a node started by
     * root refuses to run without it, so the default being present is not
     * enough -- the flag has to have been given. */
    const char *user;
    int         have_user;
    const char *secret;
    /* The argv slot --secret's value came from, or NULL. The wipe after
     * fed_open() mutates THROUGH this pointer, so it is a `char *` while
     * `secret` stays a `const char *`: storing the slot here at parse time
     * keeps the wipe free of a const-dropping cast (-Wcast-qual is in the
     * warning set on purpose). NULL unless --secret was given, and never the
     * --secret-file path. */
    char *secret_argv;
    int have_secret;
    const char *secret_file;
    /* The SASL credential store, or NULL. NULL is the DEFAULT and it means "this
     * node authenticates nobody", which is why it is a NULL and not an empty
     * path: a node that was handed a path it cannot read must be visibly
     * different from a node that was never handed one, and the two print
     * different startup lines and advertise different capabilities. */
    const char *sasl_store;
    /* Phase 10.1's ACCOUNT REGISTRY, or NULL, and the NULL default means the same
     * thing here that it means for the credential store above -- with one
     * difference worth stating: a node with no credential store authenticates
     * NOBODY, while a node with no account registry authenticates everybody and
     * identifies nobody. The second is the additive change; the first is Phase
     * 8's and it is why `--sasl-store` and `--account-store` are separate
     * options rather than one flag with two meanings. */
    const char *account_store;
    int         port;
    int         have_port;
    node_peer_t peers[NODE_MAX_PEERS];
    int         npeers;
    /* PHASE 12. Six TLS options and one extra list, and the shape is the same as
     * --sasl-store's: every one is a POINTER or a flag with a defined zero state,
     * so `node_opts_defaults()` produces a struct in which every field is either
     * a default or something the operator typed. There is no "unset" value to
     * interpret, which is what keeps the backward-compatibility argument
     * checkable: with no TLS options at all this struct is exactly what the node
     * had before the phase existed, and the node builds and runs exactly as it
     * did.
     *
     * tls_cert and tls_key are a PAIR and are refused unless both are given. Half a
     * certificate configuration is not a state this binary can be in: a node with a
     * certificate and no key, or the reverse, would advertise nothing and would
     * refuse every STARTTLS for a reason the operator could not read off the
     * startup line. */
    const char *tls_cert;
    const char *tls_key;
    const char *tls_ca;
    int         tls_port;
    int         have_tls_port;
    int         tls_require;
    /* --tls-insecure. The ONLY way this node accepts a peer certificate it cannot
     * verify, and it is a flag rather than an inference from "no --tls-ca" for the
     * reason the usage text gives: a default that silently accepts anything is the
     * failure mode a security option exists to prevent, so the insecure mode has
     * to be written down. */
    int         tls_insecure;
    /* --tls-ocsp-staple PATH, and this pointer is NULL unless an operator gave one.
     * The file is read by the TLS backend at node init -- before the event loop is
     * armed, like every other configuration file -- and stapled on every server-role
     * handshake. It is NOT refreshed: see tls_openssl.c's "STAPLED, NEVER FETCHED"
     * for why, and for the cost that a stale staple stays stale until somebody
     * replaces the file. */
    const char *tls_ocsp_staple;
    /* --tls-staple-permissive: the ONE boolean of the revocation failure policy, and
     * its DEFAULT IS THE OTHER WAY ROUND. Zero here means fail closed -- refuse a
     * peer link whose stapled status is missing, stale, unverifiable or revoked --
     * and one means log the reason and continue. The flag is named for the direction
     * it moves you because the insecure direction is the one that has to be typed;
     * see tls_openssl.c's "THE FAILURE POLICY, AND WHICH DIRECTION IS THE DEFAULT"
     * for the argument and for the cost of failing closed on a mesh whose peers do
     * not staple. */
    int         tls_staple_permissive;
    uint32_t    tls_sts_duration;
    /* The peers whose links must carry TLS. Names rather than indices, because
     * --peer and --peer-tls are separate options in any order and an index would
     * depend on which came first. A name here with no matching --peer is a startup
     * ERROR rather than a setting that quietly does nothing -- see main(). */
    char        tls_peers[NODE_MAX_PEERS][IRC_MAX_SERVER_NAME + 1];
    int         ntls_peers;
    /* MT 2.1 (#240): writer thread count; 0 = single-threaded (only mode yet). */
    int         writers;
} node_opts_t;

/* Fill in defaults: with no arguments at all the result is exactly what the
 * node used before the command line existed. */
void node_opts_defaults(node_opts_t *o);

/* Parse the command line. Returns 0 on success, -1 on a usage error (already
 * reported on stderr), and 1 when --help was asked for. */
int node_parse_args(int argc, char **argv, node_opts_t *o);

#endif
