# Channels spec

Source of truth for channel lifecycle and membership.
Derived from docs/SERVER_DESIGN.md §2.2, §4.

## Purpose

Channels are origin-owned: a node stores its own members; a join on a remote
channel costs one message instead of a roster sync. A node never applies
channel state it cannot route to the channel's origin — it refuses.

## Requirements

### Requirement: Ownership

The first server to see a channel SHALL own it (`creation_epoch`, `server_name`).

#### Scenario: Unroutable change
- **WHEN** a channel action cannot be routed to the channel's origin
- **THEN** the node refuses with 437 instead of applying or queueing it.

#### Scenario: Actor's own echo on forwarded change
- **WHEN** a client's state change (JOIN/KICK/MODE/TOPIC) is forwarded to a
  channel origin this node does not own
- **THEN** the issuing client still receives its own client-shaped echo
  synchronously (its `JOIN`/`KICK`/`MODE`/`TOPIC` line) — the forward-only
  rule forbids writing to *other* local members, never to the actor.

#### Scenario: Local preconditions beat routing
- **WHEN** a channel action fails a locally-checkable precondition (not on
  channel, not operator, unknown target, over bound) on an orphaned or
  non-owned channel
- **THEN** the node answers the specific numeric (442/482/401/417) — 437
  is reserved for "the checks passed but the origin is unreachable".


### Requirement: Verb arity and reasons

Every channel verb SHALL enforce arity both ways and strip identically.

#### Scenario: Too many params
- **WHEN** JOIN/PART/TOPIC/KICK/MODE arrives with more parameters than its shape
- **THEN** the node answers 461 and changes nothing.

#### Scenario: Stripped reasons agree
- **WHEN** a PART or KICK reason strips to empty under the shared control-byte rule
- **THEN** both verbs broadcast the cleaned result and log it — same input,
  same output.

#### Scenario: Mode params consumed in order
- **WHEN** a MODE string has several letters that each take a parameter
- **THEN** parameters are consumed one per letter in order (`+oo` = two nicks).

#### Scenario: Empty list elements
- **WHEN** a multi-channel JOIN contains empty elements (`JOIN #a,,#b`)
- **THEN** empty elements are skipped and every valid channel is joined.

#### Scenario: Case-only NICK adopts new spelling
- **WHEN** a client holding `bob` sends `NICK BOB` (folded-equal but byte-different)
- **THEN** the node adopts the new spelling with no 433 and no re-claim.

### Requirement: Bounded enumeration

Membership output SHALL never stall the tick or drown the requester.

#### Scenario: Large enumeration
- **WHEN** LIST/NAMES/WHO/AWAY-notify would exceed its cap
- **THEN** the reply truncates with a flag instead of queueing unbounded output.
