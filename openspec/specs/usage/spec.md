# Usage spec

Source of truth for how an operator runs, configures, and stops the node.
Derived from `src/node_main.c` (`usage()`, `parse_args()`, signal setup).
Interface is flags-only: there is no config file, no daemonize, no reload.

## Purpose

One binary, one foreground process, one `poll()` loop plus writer threads.
Everything the node needs is on the command line; changing anything means
restarting it. Write drain runs inline at `--writers 0` (today) and moves to
writer threads at `--writers N` (threading spec).

## Requirements

### Requirement: Invocation

The node SHALL start from flags alone and report itself first.

#### Scenario: Version first
- **WHEN** the node starts (or `--help`/`-h` is given)
- **THEN** the first line printed is `IRC_SERVE_VERSION` — the one macro in
  `src/core/server.h` that CMake, packaging, and `test_version_truth.c`
  also read.

#### Scenario: Usage errors
- **WHEN** arguments fail to parse
- **THEN** usage goes to stderr and the process exits 2 (`--help` exits 0
  after printing to stdout).

#### Scenario: Ephemeral port
- **WHEN** the positional port is 0
- **THEN** the kernel picks a port and the node reports which one it chose.

### Requirement: Flags-only configuration

There SHALL be no config file and no backgrounding.

#### Scenario: No config file
- **WHEN** an operator wants persistent configuration
- **THEN** there is no `--config` and no file format to write — flags are
  the whole interface (a supervisor, shell script, or unit file holds them).

#### Scenario: Foreground only
- **WHEN** the node runs
- **THEN** it stays in the foreground in the same filesystem: no daemonize,
  no chroot. `--user NAME` drops privilege after bind (root MUST pass it
  explicitly; anyone else runs as themselves), and files read after the
  drop (`--secret-file`, `--sasl-store`, `--account-store`) must already be
  readable by NAME.

#### Scenario: Restart to change
- **WHEN** any flag value must change
- **THEN** the node is restarted — no signal reloads configuration (there
  is no HUP handler).
### Requirement: Node identity and secret

The node SHALL take its name and federation secret from flags and report
where the secret came from.

#### Scenario: Secret source reported
- **WHEN** the node starts with `--secret S`, `--secret-file PATH`, or neither
- **THEN** the startup line says `secret_source=argv_warn`, `file`, or
  `secret=none` — argv stays visible in `ps`, so files are preferred.

### Requirement: Stores and peers

Credential stores and peer links SHALL come from flags: `--sasl-store PATH`,
`--account-store PATH`, repeatable `--peer NAME,HOST,PORT`, and
`--peer-tls NAME` to mark a peer TLS-required.

#### Scenario: One-direction dialing
- **WHEN** two nodes both list each other as a peer
- **THEN** both dial and neither accepts — each pair is configured in ONE
  direction.

### Requirement: TLS surface

TLS SHALL stay off unless `--tls-cert PATH` and `--tls-key PATH` are given
together, with `--tls-ca`, `--tls-port`, `--tls-require`, `--tls-insecure`,
`--tls-ocsp-staple`, `--tls-staple-permissive`, and `--tls-sts-duration` as
opt-ins. OpenSSL is the only optional dependency.

#### Scenario: Off by default
- **WHEN** no TLS flags are given
- **THEN** the node serves plaintext only and advertises nothing encrypted.

### Requirement: Signals

Signals SHALL stop the loop, never reconfigure it.

#### Scenario: Clean stop
- **WHEN** SIGTERM or SIGINT arrives
- **THEN** the loop stops and the node shuts down (a goodbye is sent
   best-effort, flushed by a bounded write drain before close; a peer that
   stays unwritable past the budget is marked clean locally instead).

#### Scenario: Pipe and interrupt noise
- **WHEN** a peer write fails with EPIPE, or SIGUSR1 arrives
- **THEN** SIGPIPE is ignored (EPIPE surfaces from the write) and SIGUSR1
  exists only so the `EINTR` path is exercised.
