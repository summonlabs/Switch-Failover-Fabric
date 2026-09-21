# Concurrency and ownership audit

Copyright 2026 Summon Software Labs. SPDX-License-Identifier: Apache-2.0

This document records the deliberate ownership and call-path inspection that was performed on the
Switch Failover Fabric runtime, the defects it found, and the rules that keep them from coming back.
It is an engineering record of what was actually inspected, not a claim of formal verification.

## Lock inventory

| Object | Lock | Kind | Notes |
| --- | --- | --- | --- |
| `Coordinator::Impl` | `mutex` | `std::mutex` | Outermost coordinator lock. Never acquired while any other lock is held. |
| `EvidenceStore` | `mutex_` | `std::mutex` | Leaf. |
| `FailureTable` | `mutex_` | `std::mutex` | Leaf. |
| `AuthorityRegistry` | `mutex_` | `std::mutex` | Leaf. |
| `SessionRegistry` | `mutex_` | `std::mutex` | Leaf. |
| `EventLog` | `mutex_` | `std::mutex` | Leaf, always acquired last. |
| `DecisionLog` | `mutex_` | `std::mutex` | Leaf, always acquired last. |
| `DurableStore` | store-internal | leaf | Never written while another subsystem lock is held. |
| `FrameServer` | server-internal | leaf | Held only for bookkeeping; the user handler runs outside every server lock. |

## Stated lock hierarchy

1. The coordinator state mutex is the outermost coordinator lock. It is never acquired while any
   subsystem lock is held.
2. Subsystem locks are leaves. At most one of them is held at a time along any call path; where a
   call seems to need two, the first is released before the second is taken.
3. No user callback, no event emission into user code and no explanation construction happens while
   holding the state mutex, other than appending to the leaf-locked logs.
4. The durable store is never written while another subsystem lock is held.

## Call paths inspected

* `Coordinator::declare_failure` -> `record_failure_locked` (no lock) -> evidence store, failure
  table, durable store.
* `Coordinator::apply_plan` -> authority registry, durable store, decision log.
* `Coordinator::evaluate_restore` -> authority registry, evidence store, failure table.
* `assess_switch` -> evidence store, then failure table, sequentially, never nested.
* `TopologySnapshot::closure` -> immutable snapshot, no locks at all.
* `FrameServer::stop` -> listener shutdown, per-connection shutdown, worker join.

## Defects found and fixed

### 1. Self-deadlock: `declare_failure` re-entered the non-recursive state mutex

`Coordinator::declare_failure` took the coordinator state mutex and then called the public
`record_failure`, which takes the same mutex. Because the mutex is deliberately non-recursive,
the first end-to-end failover deadlocked immediately.

Found by: the first run of the integration suite, which hung rather than failing.

Fixed by: extracting `Coordinator::Impl::record_failure_locked`, a helper that assumes the caller
already holds the mutex, and making both public entry points take the lock exactly once. The rule is
now written into the header that declares the helper.

### 2. Out-of-bounds write in the planner search summary

`summarise` in the planning core built a component-sized choice vector and then indexed it with
*global* demand indices taken from the component's position list. For any instance whose connected
component did not start at demand 0, this wrote past the end of the vector.

Found by: the seeded property suite, which crashed with an access violation at seed 1, step 5.

Fixed by: making the summary component-local (indexed exactly like the evaluations it refers to) and
applying global indices only in the caller, where the mapping is explicit. The property suite now
runs 100k+ invariant checks per pass over the same seeds.

### 3. Historical fences re-denied legitimately re-established authority

`AuthorityRegistry::query` accumulated `fenced_generations` from every withdrawn grant, including
grants that had been fenced long ago and then legitimately replaced by a new grant on a different
generation. `has_authority` required that set to be empty, so a dependent could never regain
authority after any fence, and the restore decision reported `FENCED` forever.

Found by: the integration suite (`proposition_fence_then_reconstruct`).

Fixed by: only the generations that an *active* grant is bound to can deny authority. Historical
fences are still reported for audit, and when no active grant exists at all the query reports
`FENCED` with the history as the explanation. The distinction is documented on
`AuthorityQuery`.

### 4. A fence left outstanding plans applicable

A validated plan produced before a fence could still reference the newly fenced generation, so a
later apply could have preserved authority that depended on a failed generation.

Found by: the seeded property suite (invariant I4).

Fixed by: committing a fence now walks the retained plans and marks every plan that covers or hops
through the fenced generation as `Superseded`, re-sealing each digest. Superseded plans are retained
as history and are not applicable.

## Audited and found correct

* **Read-lock then write-lock re-entry on the same lock**: no `shared_mutex` is used anywhere in
  the runtime; the only re-entrancy hazard was defect 1 above.
* **Write lock held across a helper that re-enters state**: the only two such helpers are
  `record_failure_locked` and `Impl::record_decision`, both of which are documented as
  lock-already-held and take no lock themselves.
* **Event and decision emission beneath internal locks**: both logs are leaf-locked and never call
  back into the runtime, so a bounded append under the state mutex cannot deadlock. Neither log
  invokes user code.
* **Joining workers while holding state they need**: `FrameServer::stop` closes the listener and
  every live connection before joining, and holds no lock while joining. The concurrency suite
  asserts that running workers observe `Closed` promptly after `shutdown`.
* **Cancellation and shutdown with reversed lock ordering**: shutdown takes the state mutex only to
  flip a flag and append a durable record; it never holds it while joining.
* **Blocked socket teardown**: the server shuts down the listen socket and every accepted connection,
  which releases blocked `accept` and `recv` calls without waiting for a peer.
* **Cross-object mutex order inversion**: subsystems never call each other while holding a lock; the
  authority registry, evidence store and failure table are always called sequentially.
* **Moved-from handle ownership**: sockets and the durable store track an explicit open flag, so a
  moved-from handle closes nothing and a double close is a no-op.
* **Close and shutdown races**: `Coordinator::shutdown` is guarded by a compare-exchange, so
  concurrent shutdown calls are idempotent and only one performs the durable close.
* **Callbacks retaining references to mutable state beyond a lock lifetime**: the frame handler is
  invoked with the request frame by value and returns the response by reference to a caller-owned
  frame; the server holds no reference to coordinator state.
* **Borrowed coordinator views**: `topology()` and friends return borrowed pointers, so the header
  states the lifecycle contract explicitly - install inputs during a configuration phase, then begin
  concurrent operation.

## What is not claimed

The audit is a manual inspection plus targeted tests. It is not a formal proof, not a race detector
run, and not a model check. ThreadSanitizer is unavailable on the MSVC toolchain used for this
release, which is recorded as UNSUPPORTED in the README evidence matrix.
