# Tasks: loop + writer threads

## 1. Foundations (no behavior change)

- [x] 1.1 Convert `state`/`want_read`/`want_write` to `_Atomic int` with
  release-publish/acquire-consume; verify with full suite green, `--writers 0`.
  (done: #235, commit 7b84ac7)
- [x] 1.2 Replace bare `pthread` link with `find_package(Threads)`; verify all
  three compilers configure clean. (done: #236, commit 9425ec6)
- [x] 1.3 Add TSan CI cell (ThreadSanitizer, `--writers 4`), mutually exclusive
  with ASan gate; verify it runs and passes on a clean tree.
  (done: #237, commit cbc3278)
- [x] 1.4 Move `file_secret` (`node_main.c:1354`) off static storage; verify
  with ASan + secret-file integration test green. (done: #238, commit af02a75)
- [x] 1.5 Add per-node stop flag alongside `g_stop`; verify two in-process
  nodes stop independently in `test_fed_isolation`-style test.
  (done: #239, commit 6d0dc63)

## 2. Writer pool

- [ ] 2.1 Add per-`conn_t` mutex + `--writers N` flag (default 0) with
  `server_set_writer_threads(s,0)` test seam; verify suite green with N=0
  (byte-identical) and N=4.
- [ ] 2.2 Move `conn_pump` drain to writers (loop never sends when N>0);
  verify `test_partial_write`, TLS handshake, and 417-flush tests pass N=0/4.
- [ ] 2.3 Implement close handoff (reaper waits/revokes before `close`+free);
  verify with fd-churn + concurrent-burst TSan test, no UAF/double-close.
- [ ] 2.4 Writer wakeup on queue (no POLLIN stall on idle sockets); verify with
  idle-conn + queued-burst latency test.

## 3. TLS under writers

- [ ] 3.1 Serialize each `SSL*` under its conn lock; freeze `SSL_CTX` post-init
  (assert on mutation in debug); verify TLS suite + peer-TLS tests N=4.
- [ ] 3.2 Pending-drain (`SSL_pending`) under conn lock; verify with
  multi-record TLS burst test (the #230 scenario).

## 4. Hardening and proof

- [x] 4.1 Ordering test: pipelined A-then-B arrives in order per connection
  under N=4 with concurrent bursts; verify deterministic in 100 runs.
- [x] 4.2 Fault test: fatal send error on one conn closes only it; verify loop
  + all other conns proceed (TSan clean).
- [x] 4.3 Benchmark writers on/off (throughput + footprint) on Linux cell;
  verify no regression at N=0, record scaling at N=2/4 for the default decision.
- [x] 4.4 Full gate: `-Weverything` × 3 compilers × Release/Debug × TLS
  on/off × ASan/TSan cells, 0 warnings, 0 failures.

## 5. Spec and rollout

- [x] 5.1 Update `openspec/config.yaml` context (`no threads` → loop-single-
  writer + writers-only); verify `openspec validate --specs` green.
- [x] 5.2 Document `--writers` in README/DEVELOPMENT (`--help`, default,
  tuning); verify docs-truth check passes.

## 6. Cache scheduling (new 2026-11-21, from `openspec/specs/threading/spec.md`)

- [ ] 6.1 Sticky + rebalance (#366): `fd mod N` ownership; idle writer steals
  whole conns past the backlog bound; verify no ping-pong + FIFO holds.
- [ ] 6.2 Targeted wakeup (#367): per-writer signal + private runqueue;
  verify one wake per queued conn per drain turn via wake counters.
- [ ] 6.3 Handoff layout (#368): group lock/atomics/queue-head on own cache
  lines; verify by struct inspection (`pahole`).
- [ ] 6.4 Drain slice (#369): bounded slice per conn per turn; verify thin
  conn reply latency behind a fat backlog.
