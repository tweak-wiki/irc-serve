# Threading spec

Source of truth for the threading model: one loop thread owns everything;
writer threads drain connection write queues and nothing else.
Derived from `openspec/changes/add-multithreading/design.md`.

## Purpose

`send()`/`SSL_write()` on the loop stalls every client and peer. Writers
take exactly that call — and nothing else — so every registry, fanout, and
federation proof that assumes a single writer still holds.

## Requirements

### Requirement: Writer ownership

Writer threads SHALL drain write queues and nothing else.

#### Scenario: Send offload
- **WHEN** `--writers N` (N > 0) and a connection's write queue is non-empty
- **THEN** a writer thread performs the `send()`/`SSL_write()` calls, and the
  loop thread never calls `send()` on that connection while a writer owns it.

#### Scenario: Default unchanged
- **WHEN** `--writers 0` (the default)
- **THEN** the loop thread drains inline — byte-identical behavior to today.

### Requirement: Ordered delivery per connection

Pipelined replies SHALL arrive in queue order.

#### Scenario: FIFO per conn
- **WHEN** dispatch queues lines A then B on the same connection
- **THEN** the peer receives A before B, regardless of which writer drains.

### Requirement: Producer-consumer exclusion

Queueing and pumping the same connection SHALL be mutually exclusive.

#### Scenario: Grow vs drain
- **WHEN** dispatch appends to `wbuf` while a writer drains it
- **THEN** no byte is lost, duplicated, or reordered, and the buffer is freed
  exactly once (close handoff: loop marks CLOSING, writer releases, reaper frees).

### Requirement: TLS single ownership

One `SSL*` SHALL be driven by one thread at a time.

#### Scenario: Handshake vs record
- **WHEN** a writer performs `SSL_write` on a connection
- **THEN** no other thread calls `SSL_read`/`SSL_write`/`SSL_shutdown` on that
  `SSL*` concurrently; `SSL_CTX` is never mutated after init.

### Requirement: Failure containment
Writer failures SHALL NOT take down the loop or other connections.

#### Scenario: Send error on one conn
- **WHEN** a writer hits a fatal transport error
- **THEN** only that connection is marked CLOSING; the loop reaps it on the
  normal path and all other connections proceed.

### Requirement: Writer-conn stickiness

A connection SHALL be drained by the same writer while the pool is stable and
load is even, so its queue stays hot on one core. Ownership may move only via
demand rebalancing below — never per wakeup, never mid-slice.

#### Scenario: Stable mapping
- **WHEN** `--writers N` is unchanged and no writer's backlog exceeds the
  rebalance bound
- **THEN** the writer owning `fd mod N` drains it — never a different writer.

### Requirement: Demand rebalancing

An idle writer SHALL take work from an overloaded one, moving whole
connections — never half a queue, so FIFO and single-drainer hold throughout
the transfer.

#### Scenario: Steal on overload
- **WHEN** one writer's owned backlog exceeds the rebalance bound (queued
  slices) while another writer has nothing queued
- **THEN** the idle writer takes ownership of whole connections under the
  conn lock and drains them; at most a bounded few per pass, and never a
  connection drained within the last tick (no ping-pong).

### Requirement: Targeted wakeup

Queueing bytes SHALL wake exactly the owning writer — never all of them.

#### Scenario: One wakeup per queue
- **WHEN** dispatch queues onto an idle connection
- **THEN** only that connection's owner is signaled (per-writer eventfd or
  condvar + private runqueue). A wake counter per writer stays at one per
  queued connection per drain turn — no broadcast storm.

### Requirement: Handoff layout

The fields the loop and a writer share SHALL sit apart from loop-only
fields, so the two threads stop bouncing the same cache lines.

#### Scenario: Hot fields grouped
- **WHEN** `conn_t` is laid out (lock, atomic `state`/`want_*`, queue head)
- **THEN** the handoff fields share their own cache lines, separate from
  dispatch-only fields — verified by struct inspection (`pahole`), not by
  benchmark.

### Requirement: Bounded drain slice

One fat connection SHALL NOT starve the others on its writer.

#### Scenario: Slice then yield
- **WHEN** a writer drains a connection with an unbounded backlog
- **THEN** it writes at most one bounded slice (bytes or `send()` calls),
  then moves to the next owned connection with queued bytes — a thin
  connection's reply goes out within one slice of being queued.
