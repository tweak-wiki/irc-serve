# Federation spec

Source of truth for node-to-node links, bursts, and loop safety.
Derived from docs/SERVER_DESIGN.md §4, docs/AUTO_SCALE_DESIGN.md.

## Purpose

Scale by adding nodes; use cores with writer threads (threading spec).
Peers share the client dispatch path; the only difference is a field on the
connection. Federation control state stays loop-thread-affine — writers
never touch links, bursts, dedup, or nickreg.

## Requirements

### Requirement: Link lifecycle

Links SHALL authenticate fail-closed and recover with backoff.

#### Scenario: Weak secret
- **WHEN** the node is configured with a secret under 16 bytes (outside tests)
- **THEN** startup refuses with `link_open_refused: reason=SECRET_SHORT` — a warning alone is not enough.
- Inbound `FEDERATE` carries no length verdict: a wrong secret of any length is refused as `BAD_SECRET`, so the refusal never oracles the offered length.

#### Scenario: Plaintext peer auth
- **WHEN** a peer is TLS-required and `FEDERATE` arrives on plaintext
- **THEN** the handshake is refused rather than authenticating in the clear.

#### Scenario: Close/reopen
- **WHEN** `fed_close()` runs with any saved dispatch including NULL
- **THEN** dispatch is restored unconditionally, so reopening never wraps
  the hook in itself.

### Requirement: Burst resync

Bursts SHALL replace state atomically at SBURSTE.

#### Scenario: Two peers at once
- **WHEN** a second peer sends burst records while a transaction is open
- **THEN** every non-owner record and commit is refused with BUSY; the
  owner's transaction is untouched.

#### Scenario: Oversized roster
- **WHEN** a burst record would exceed a cap
- **THEN** the whole channel record is discarded before install (two-pass
  commit) — live state never shrinks from a failed re-add.

#### Scenario: Count mismatch
- **WHEN** the SBURSTE counts disagree with accepted records
- **THEN** the burst is discarded, nothing is installed.

#### Scenario: Inbound state emits client lines
- **WHEN** an inbound S-verb (SJOIN/SPART/STOPIC/SSMODE/SKICK/SNICK/SQUIT)
  is applied to this node's cache
- **THEN** the corresponding client-shaped line (JOIN/PART/TOPIC/MODE/
  KICK/NICK/QUIT) is rendered to every local member of the affected
  channel(s) — roster-only convergence (353 on next NAMES) is not enough.

#### Scenario: Notifies are node-local until wire bump
- **WHEN** a SETNAME/AWAY/INVITE notification fires on one node of a mesh
- **THEN** only that node's members observe it; cross-node notify
  delivery (SSETNAME/SAWAY/SINVITE) waits on a 4.3 wire version bump,
  tracked separately.

### Requirement: Loop safety

Federation SHALL NOT circulate or amplify messages.

#### Scenario: Hop cap
- **WHEN** a message's `(origin, epoch, id)` is seen again or exceeds 10 hops
- **THEN** it is dropped by the dedup ring.
