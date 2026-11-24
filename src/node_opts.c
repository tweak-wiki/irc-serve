/* node_opts.c -- the node's command line, split out of node_main.c (issue
 * #543). Everything here touches argv and nothing else. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "node_opts.h"

/* Parse the port argument. Returns 0 on success, -1 if it is not a number in
 * range, and 1 if no argument was given (which is not an error: the default
 * port applies). */
static int parse_port(const char *arg, int *port)
{
    char *end = NULL;
    long value;

    if (arg == NULL || arg[0] == '\0') {
        return 1;
    }
    errno = 0;
    value = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || value < 0 || value > 65535) {
        return -1;
    }
    *port = (int)value;
    return 0;
}


void node_opts_defaults(node_opts_t *o)
{
    memset(o, 0, sizeof *o);
    o->name = NODE_NAME;
    o->user = NODE_DEFAULT_USER;
    o->secret = NODE_DEFAULT_SECRET;
    o->port = NODE_DEFAULT_PORT;
}

/* Split `spec` into name, host, port. Returns 0 on success, -1 on a malformed
 * specification.
 *
 * Exactly two commas, and the third field is a decimal port. Deliberately
 * strict: a --peer argument that is nearly right must be refused, because the
 * alternative is a node that resolves a hostname built out of two fields and
 * dials something the operator did not name. The hostname field is bounded at
 * sizeof(host) rather than unbounded, which is what keeps the later
 * getaddrinfo() call inside a buffer it does not have to trust. */
static int parse_peer(const char *spec, node_peer_t *out)
{
    const char *first;
    const char *second;
    size_t n;

    if (spec == NULL || out == NULL) {
        return -1;
    }
    first = strchr(spec, ',');
    if (first == NULL) {
        return -1;
    }
    second = strchr(first + 1, ',');
    if (second == NULL || strchr(second + 1, ',') != NULL) {
        return -1;
    }
    n = (size_t)(first - spec);
    if (n == 0u || n > (size_t)IRC_MAX_SERVER_NAME) {
        return -1;
    }
    memcpy(out->name, spec, n);
    out->name[n] = '\0';
    n = (size_t)(second - (first + 1));
    if (n == 0u || n >= sizeof out->host) {
        return -1;
    }
    memcpy(out->host, first + 1, n);
    out->host[n] = '\0';
    n = strlen(second + 1);
    if (n == 0u || n >= sizeof out->port) {
        return -1;
    }
    memcpy(out->port, second + 1, n + 1u);
    /* The port must be DECIMAL, and this check is here rather than left to
     * getaddrinfo for a reason that is not tidiness: getaddrinfo's second
     * argument is a SERVICE, and a service that is not a number is looked up in
     * the system service database. `--peer a,host,ssh` would then quietly mean
     * port 22 on a node where the operator wrote a word, and the link would be
     * refused much later with a much less obvious reason. */
    {
        size_t i;

        for (i = 0; i < n; i++) {
            if (out->port[i] < '0' || out->port[i] > '9') {
                return -1;
            }
        }
    }
    return 0;
}

/* The command line. Returns 0 on success, -1 on a usage error (already
 * reported on stderr), and 1 when --help was asked for.
 *
 * Options are recognised in any position and the bare port is a positional, so
 * `irc-serve --name irc.a 0` and `irc-serve 0 --name irc.a` are the same
 * command. An argument that begins with '-' and is not a known option is an
 * ERROR rather than an unknown positional: a mistyped flag is a mistake, and
 * treating it as a port is how a node ends up listening on a number nobody
 * typed. */
int node_parse_args(int argc, char **argv, node_opts_t *o)
{
    int i;
    int rc;

    node_opts_defaults(o);
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        char *value = NULL;

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            return 1;
        }
        if (strcmp(arg, "--name") == 0 || strcmp(arg, "--secret") == 0 ||
            strcmp(arg, "--secret-file") == 0 ||
            strcmp(arg, "--peer") == 0 || strcmp(arg, "--sasl-store") == 0 ||
            strcmp(arg, "--account-store") == 0 ||
            strcmp(arg, "--user") == 0 || strcmp(arg, "--writers") == 0 ||
            strcmp(arg, "--peer-tls") == 0 || strcmp(arg, "--tls-cert") == 0 ||
            strcmp(arg, "--tls-key") == 0 || strcmp(arg, "--tls-ca") == 0 ||
            strcmp(arg, "--tls-ocsp-staple") == 0 ||
            strcmp(arg, "--tls-sts-duration") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "irc-serve: %s needs a value\n", arg);
                return -1;
            }
            value = argv[++i];
        } else if (strcmp(arg, "--tls-port") == 0) {
            /* A PORT, and it is parsed by the port parser rather than taken as a
             * string, so `--tls-port 6697x` is an error instead of a port the
             * kernel was asked for and refused. */
            if (i + 1 >= argc) {
                fprintf(stderr, "irc-serve: %s needs a value\n", arg);
                return -1;
            }
            value = argv[++i];
            if (parse_port(value, &o->tls_port) != 0) {
                fprintf(stderr, "irc-serve: bad --tls-port argument: %s\n", value);
                return -1;
            }
            o->have_tls_port = 1;
            continue;
        } else if (strcmp(arg, "--tls-require") == 0 ||
                   strcmp(arg, "--tls-insecure") == 0 ||
                   strcmp(arg, "--tls-staple-permissive") == 0) {
            /* FLAGS, and they take no value. Accepting one as `--tls-require=0`
             * is not a thing this parser does for anything else either, and a
             * silently-ignored value on a security flag is the worst outcome
             * available: an operator who typed `--tls-require=no` would get a node
             * that requires TLS and believes it does not. The same argument is why
             * --tls-staple-permissive is here and is named the way it is: the
             * weakening direction is typed, and the default is the strict one. */
            if (strcmp(arg, "--tls-require") == 0) {
                o->tls_require = 1;
            } else if (strcmp(arg, "--tls-insecure") == 0) {
                o->tls_insecure = 1;
            } else {
                o->tls_staple_permissive = 1;
            }
            continue;
        } else if (arg[0] == '-') {
            fprintf(stderr, "irc-serve: unknown option: %s\n", arg);
            return -1;
        } else {
            rc = parse_port(arg, &o->port);
            if (rc != 0 || o->have_port) {
                fprintf(stderr, "irc-serve: bad port argument: %s\n", arg);
                return -1;
            }
            o->have_port = 1;
            continue;
        }

        if (strcmp(arg, "--name") == 0) {
            o->name = value;
        } else if (strcmp(arg, "--user") == 0) {
            if (value[0] == '\0') {
                fprintf(stderr, "irc-serve: --user needs a name\n");
                return -1;
            }
            o->user = value;
            o->have_user = 1;
        } else if (strcmp(arg, "--secret") == 0) {
            o->secret = value;
            o->secret_argv = value;
            o->have_secret = 1;
        } else if (strcmp(arg, "--secret-file") == 0) {
            if (value[0] == '\0') {
                fprintf(stderr, "irc-serve: --secret-file needs a path\n");
                return -1;
            }
            o->secret_file = value;
        } else if (strcmp(arg, "--sasl-store") == 0) {
            o->sasl_store = value;
        } else if (strcmp(arg, "--account-store") == 0) {
            o->account_store = value;
        } else if (strcmp(arg, "--tls-cert") == 0) {
            o->tls_cert = value;
        } else if (strcmp(arg, "--tls-key") == 0) {
            o->tls_key = value;
        } else if (strcmp(arg, "--tls-ca") == 0) {
            o->tls_ca = value;
        } else if (strcmp(arg, "--tls-ocsp-staple") == 0) {
            /* EMPTY IS REFUSED rather than treated as "no staple": it is a flag an
             * operator typed and meant, and a node that quietly treated
             * `--tls-ocsp-staple ""` as absent would staple nothing and print
             * ocsp_staple=none -- which is at least visible, but only after the peer
             * links have already started failing with MISSING_STAPLE. */
            if (value[0] == '\0') {
                fprintf(stderr, "irc-serve: --tls-ocsp-staple needs a path\n");
                return -1;
            }
            o->tls_ocsp_staple = value;
        } else if (strcmp(arg, "--tls-sts-duration") == 0) {
            char *end = NULL;
            long seconds;

            errno = 0;
            seconds = strtol(value, &end, 10);
            if (errno != 0 || end == value || *end != '\0' || seconds < 0 ||
                seconds > 2147483647L) {
                fprintf(stderr, "irc-serve: bad --tls-sts-duration: %s\n", value);
                fprintf(stderr, "  expected a whole number of seconds, 0-%ld\n",
                        2147483647L);
                return -1;
            }
            o->tls_sts_duration = (uint32_t)seconds;
        } else if (strcmp(arg, "--writers") == 0) {
            char *end = NULL;
            long n;

            errno = 0;
            n = strtol(value, &end, 10);
            if (errno != 0 || end == value || *end != '\0' || n < 0) {
                fprintf(stderr, "irc-serve: bad --writers: %s\n", value);
                fprintf(stderr, "  expected a whole number, 0 or more\n");
                return -1;
            }
            o->writers = (int)n;
        } else if (strcmp(arg, "--peer-tls") == 0) {
            /* The name is validated here with the SAME predicate the --peer name
             * goes through, so a --peer-tls naming something that could never be a
             * server name is an error rather than a flag that matches nothing. */
            if (value[0] == '\0' || strlen(value) > (size_t)IRC_MAX_SERVER_NAME ||
                !irc_serve_server_name_valid(value)) {
                fprintf(stderr, "irc-serve: bad --peer-tls name: %s\n", value);
                return -1;
            }
            if (o->ntls_peers >= NODE_MAX_PEERS) {
                fprintf(stderr, "irc-serve: at most %d --peer-tls options\n",
                        NODE_MAX_PEERS);
                return -1;
            }
            memcpy(o->tls_peers[o->ntls_peers], value, strlen(value) + 1u);
            o->ntls_peers++;
        } else {
            if (o->npeers >= NODE_MAX_PEERS) {
                fprintf(stderr, "irc-serve: at most %d --peer options\n",
                        NODE_MAX_PEERS);
                return -1;
            }
            if (parse_peer(value, &o->peers[o->npeers]) != 0) {
                fprintf(stderr, "irc-serve: bad --peer argument: %s\n", value);
                fprintf(stderr, "  expected NAME,HOST,PORT\n");
                return -1;
            }
            o->npeers++;
        }
    }
    /* ONE SOURCE, because two is a configuration that cannot be honoured: the
     * secret on the command line is visible in `ps`, so silently preferring
     * either one would bless the leak or surprise the file's author. */
    if (o->have_secret && o->secret_file != NULL) {
        fprintf(stderr, "irc-serve: --secret and --secret-file are exclusive; "
                        "use --secret-file\n");
        return -1;
    }
    return 0;
}
