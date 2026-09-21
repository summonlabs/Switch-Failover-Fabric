# Switch Failover Fabric

**Switch Failover Fabric (SFF) 1.0.0** is a portable C++20 infrastructure runtime that answers one
question deterministically and truthfully:

> Given authoritative evidence that a switch **generation** has failed or become unusable, which
> dependent authority must be fenced, what replacement switching resources or path reconstructions
> are eligible, and when may service be restored under current generations?

It is a library plus a small tool, with a proper installable CMake package, no third-party runtime
dependencies, and a verification suite that proves the proposition under stale, partial,
contradictory, restarted, concurrent and adversarial conditions.

Copyright 2026 Summon Software Labs. Apache License 2.0.

---

## 1. Exact systems boundary

**Owned by this runtime**

* deciding which dependent authority a failed switch generation invalidates, over a bounded
  dependency closure computed from supplied structure;
* fencing that authority first, and committing the fence durably before any reconstruction;
* selecting among caller-supplied reconstruction alternatives using generation-qualified
  topology, capability and failure-domain evidence;
* deciding whether service may be restored, and distinguishing proposal from acknowledgement from
  verified effect;
* bounded, deterministic, integrity-checked persistence of lineage, fences and completed outcomes;
* a bounded framed protocol for driving the runtime from another process.

**Explicitly NOT owned**

* topology discovery - the topology snapshot is an input from an authoritative adjacent system;
* general path solving - this runtime **selects among alternatives that another system supplied**
  and validates each one; it never synthesises a forwarding path;
* switch ASIC programming, routing convergence, hardware repair;
* authentication, encryption, or any cryptographic guarantee.

Nothing in the runtime reaches outside that boundary. Where an adjacent input is needed it is an
explicit typed value with a declared provenance and an explicit trust level, never an inference.

---

## 2. Authority and generation model

The model exists so that six confusions are structurally impossible.

| Confusion | How it is prevented |
| --- | --- |
| Matching identity is matching generation | Every authority-bearing relation is keyed on `SwitchKey` (id **and** generation). `GenerationVector::contains` is generation-exact; identity-only matching is a separate, deliberately named call. Generation 0 means "no generation asserted" and never matches. |
| Persistence is liveness | Health observations are dynamic state and are never restored. Restarting restores only definitions, policy, committed lineage, fences and completed outcomes. Every restored grant is forced `Stale`. |
| Observation is authority | `TrustLevel` is a pure function of the evidence source. A health observation from an advisory source can never make a generation usable, and never by itself creates a fence obligation under the default policy. |
| Eligibility is authorization | A replacement generation can be *eligible* (present, capable, separated) while no grant exists. Eligibility never mints authority. |
| Authorization is application | Planning produces a proposal. Only `apply_plan` mints new authority, under the current epoch and incarnation, and it reports acknowledgement - never verified effect. |
| Acknowledgement is verified effect | `ApplyReceipt` counts applied, failed, unverified and verified separately; `fully_verified()` requires independent verification evidence. |

### Runtime identity

* `CoordinatorEpoch` - advances on every process incarnation.
* `BootIncarnation` - process id, boot ordinal and a 128-bit nonce, unique per process start.
* `AttemptSeq` - monotonic per-authority sequence; `StrongId::next()` refuses to hand out a
  replayed identity at sequence exhaustion.
* `GrantId`, `FenceId`, `PlanId`, `DecisionId`, `EvidenceId` - strongly typed and non-interchangeable.
  Identities the runtime mints for itself come from a reserved range that caller-supplied identities
  may not use, so an external record can never collide with an internal one.

### Adjudication

`assess_switch` combines the dynamic evidence store and the durable failure table into a
`SwitchAssessment` whose `outcome` is one of `Ok`, `Unknown`, `Stale`, `Conflict`, `Invalid`,
`Unsupported`. `usable` is true only on an affirmative basis. `fence_required` is true only on an
established failure, an authoritative conflict, or an authoritative administrative decision.

---

## 3. Major invariants

1. **Fence first, reconstruct second.** A plan is refused outright for a generation that is neither
   fenced nor failing. No restore step may contain the failed generation.
2. **No silent omission.** A bounded traversal that stops early reports `ClosureState::Truncated`
   with `omitted_frontier` and `omitted_edges`. A root the snapshot does not contain sets
   `roots_absent` and forces `enumerates_every_root() == false`. A truncated closure is never
   reported as complete and never licenses restoration under the default policy.
3. **No silent loss of dependents.** Every demand is either restored or listed as unresolved with a
   reason that is either a *proven* negative or explicitly not one.
4. **Failure to find is not proof of absence.** `ProvenInfeasible` is emitted only when every
   unresolved dependent carries a proven certificate. A search bound produces
   `SearchLimitReached` instead.
5. **Canonical determinism.** Container, hash, insertion and discovery order cannot change the
   output: generations, nodes, edges, dependencies and plan steps are all canonically ordered, and
   the plan digest covers every meaning-bearing field.
6. **Fences invalidate outstanding plans.** Committing a fence supersedes every retained plan that
   covers or hops through the newly fenced generation.
7. **Fencing is permanent lineage.** A fence record is never removed. Recovery of a generation
   permits new grants; it never restores old ones.
8. **Bounded everything.** Topologies, closures, plans, evidence, events, decisions, sessions,
   grants, fences, explanations and frames all have declared ceilings, and exhaustion is a
   deterministic refusal rather than instability.

---

## 4. Lifecycle and restart semantics

`Coordinator::open` is the only way to obtain a runtime.

* With durability disabled the runtime is entirely in memory and mints a fresh incarnation.
* With durability enabled the journal is replayed first. A record that fails its integrity check
  refuses the open; only a **genuine torn tail** is recovered, and only after it has been proven to
  be a byte-exact prefix.

A restart:

1. advances the epoch and mints a fresh boot incarnation (a new process id, a new nonce);
2. restores **only** durable lineage: committed failures, fences, committed plans, completed apply
   receipts;
3. forces every restored grant to `Stale` (and with `Policy::fence_on_restart`, withdraws them
   entirely);
4. restores **no** health observation, no liveness, no lease, no in-flight authority and no backend
   effect - `RestartReport::dynamic_evidence_restored` is always false, and it exists so the claim
   is explicit;
5. reports what it did in a `RestartReport` with previous and current identity, record counts,
   torn-tail recovery and the reason for every note it emits.

The topology snapshot and the reconstruction candidate table are **inputs**, not durable state of
this runtime: after a restart the authoritative source re-supplies them. That is deliberate - a
persisted copy could silently resurrect stale structure.

---

## 5. Persistence and durability

* One append-only journal plus one snapshot, both versioned and integrity-checked.
* Record layout: 28-byte header (magic `SFF1`, format version, kind, flags, sequence, declared
  length, header CRC-32) followed by the payload and a payload CRC-32.
* `replay()` is a **streaming** reader: it reads one header, validates it, learns the declared
  length from the validated header, reads exactly that many bytes, and decodes. Memory and cost are
  O(1) per record for a journal of any size, and no record can ever straddle an internal window.
* Sequence continuity is anchored on the first record actually present, so a compacted suffix
  replays; every later record must follow it with no gap and no regression. A regression reports
  `Code::Replay`, a gap reports `Code::Corrupt`.
* Rejection rules: wrong magic, bad header CRC, bad payload CRC, impossible or over-ceiling declared
  length, unsupported format version, undefined record kind, non-increasing sequence, trailing
  garbage in a snapshot.
* **Nothing corrupt is ever repaired.** A complete record that fails integrity refuses the open and
  the file is left untouched, byte for byte.
* Snapshots are replaced transactionally: staging file, flush, sync, atomic rename. A crash keeps
  the old snapshot; it can never expose a half-replaced one.
* Ordering: bytes reach the file before the record is considered published.

---

## 6. Framed protocol

A bounded, explicit framing over TCP (loopback by default) for driving the runtime from another
process:

* 52-byte header: magic, format version, message type, flags, session, epoch, boot digest, request
  sequence, declared payload length, header CRC-32; then the payload and a payload CRC-32.
* Decoding is **total** and allocation-free up to the point where the declared length has been
  proven both within `Limits::max_frame_payload` and actually present.
* Undersized, oversized, truncated, corrupt, version-mismatched and unassigned-type frames are each
  refused with an explicit disposition. Nothing is coerced.
* `FrameStreamDecoder` is sticky: once a stream desynchronises it refuses every further frame
  rather than resynchronising.
* Every request carries its session authority in the header, and the server copies that authority
  onto the response, so one session can never answer as another. A replayed or regressed request
  sequence is refused.
* Shutdown releases blocked accepts and reads promptly and deterministically.

**Trust boundary:** the transport is unauthenticated and unencrypted. It binds to loopback by
default and exists for in-host control and multiprocess proof. Authentication and encryption are
outside this boundary and are not claimed.

---

## 7. Tools and examples

```
sffctl selftest                                          # in-process self-check
sffctl demo   [--seed N] [--paths N] [--durable DIR]     # the whole proposition, step by step
sffctl plan   --seed N [--paths N] [--max-closure N]     # the planner objective for one instance
sffctl replay --log DIR                                  # restart report for a durable root
sffctl serve  --port N [--root DIR]                      # framed server over a synthetic runtime
sffctl query  --port N --dependent KIND:ID               # authority query for one dependent
sffctl stop   --port N                                   # deterministic, timer-free shutdown
```

Every command prints machine-readable `key=value` summaries and exits non-zero on refusal, and
never prints a claimed success when the underlying status was not `Ok`.

Three examples show the boundary in code: `example_failover` (fence, plan, validate, apply,
verify), `example_planning` (determinism under shuffled input and a capacity-constrained instance)
and `example_restart` (two sequential incarnations over one durable root).

---

## 8. Building

Requires CMake 3.20+ and a C++20 compiler. Verified with MSVC 19.44 (/W4 /WX /permissive-).

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Options: `SFF_BUILD_TESTS`, `SFF_BUILD_TOOLS`, `SFF_BUILD_EXAMPLES`, `SFF_STRICT_WARNINGS`,
`SFF_WARNINGS_AS_ERRORS`, `SFF_ENABLE_ASAN`, `SFF_ENABLE_UBSAN`, `BUILD_SHARED_LIBS`.

---

## 9. Installing and using from another project

```
cmake --install build --prefix /path/to/prefix
```

The installed package exports `SwitchFailoverFabric::sff` together with its headers, version file
and config file. A downstream project needs nothing else:

```cmake
find_package(SwitchFailoverFabric 1.0 CONFIG REQUIRED)
add_executable(my_tool main.cpp)
target_link_libraries(my_tool PRIVATE SwitchFailoverFabric::sff)
```

`tests/consumer/` is exactly such a project, kept outside the source tree's build, and it is
built, linked and run against the installed prefix as part of release validation. Include the
umbrella header `<sff/sff.hpp>` or any individual header; every public header is self-contained
and this is enforced by a build target that compiles one translation unit per header.

---

## 10. Testing

The suites are proofs, not a count. Each one is a plain executable with no timeout of any kind and
no watchdog thread: a hang is treated as a defect in the runtime, not masked.

| Suite | What it proves |
| --- | --- |
| `test_core` | outcome taxonomy, bounded messages, strongly typed identity, generation vectors, checked arithmetic at the boundaries, limits, event log retention |
| `test_integrity` | CRC-32 known-answer vectors and single-bit sensitivity; digest sensitivity to every byte and length change |
| `test_frame_codec` | every frame prefix, corrupt CRCs, oversized declared lengths, invalid enums, sticky stream failure, trailing bytes |
| `test_persistence` | every payload codec; exhaustive prefix and single-byte corruption sweeps; declared-length, version and kind attacks; real journals; torn tails; tamper-never-repair; sequence regression and gaps; snapshots; path traversal; bounded refusal; journals larger than any internal window |
| `test_topology` | fan-out, fan-in, cycles, duplicate edges, contradictory declarations, bounded truncation, absent roots, canonical ordering, scale |
| `test_evidence` | fail-closed adjudication: absence, advisory-only, authoritative failure and recovery, equal-instant conflict, staleness, generation isolation, durable lineage |
| `test_authority` | grant windows, queries, fencing without cross-generation contamination, re-minting on a newer generation, restart invalidation, expiry, withdrawal, bounded refusal |
| `test_planner` | determinism under shuffled input, fence-first refusal, per-root attribution, objective correctness, capacity, greedy-breaking instances, unresolved taxonomy, truncated closures |
| `test_validator` | independent re-derivation; every tampered plan variant rejected - failed hops, absent hops, superseded generations, fenced hops, zero cost, duplicates, over-capacity, closure disagreement, wrong epoch/boot/topology/policy, missing fence |
| `test_reference_solver` | differential testing against an exhaustive reference solver over thousands of seeded instances |
| `test_property` | seeded operation sequences with the full invariant set re-checked after **every** operation |
| `test_integration` | the product proposition end to end: fence, closure, plan, validate, apply, verify, restore |
| `test_adversarial` | contradictory evidence, stale capability, duplicate declarations, session forgery and replay, partial acknowledgement, restart resurrection, tampered journals, exhaustion, malformed input |
| `test_concurrency` | deterministic latches: exactly-once fencing, exactly-once sequence consumption, readers consistent during a writer fence, shutdown releasing workers, authority churn |
| `test_lifecycle` | idempotent shutdown, closed-runtime refusal, session lifecycle, repeated open/close cycles, no staging debris |
| `test_scale` | exact work counters at 2k/8k/32k dependents, per-element cost stability, bounded retention, exhaustion refusal |
| `test_restart` | real durable reopen, torn tails, tampering, epoch and boot monotonicity across cycles |
| `test_multiprocess` | **real independent OS processes** over **real loopback sockets**, including hard kills at durable boundaries |
| `test_consumer_contract` | the public surface alone is sufficient: umbrella header, version, evidence classes, a full failover |
| header self-containment | one translation unit per public header, each including only that header |

### Verified results on this host

Release (`/W4 /WX /permissive-`), Debug and RelWithDebInfo+AddressSanitizer builds all pass the
whole suite:

| Build | Result |
| --- | --- |
| Release, warnings as errors | 19/19 suites pass |
| Debug, warnings as errors | 19/19 suites pass |
| RelWithDebInfo + AddressSanitizer | 19/19 suites pass, no sanitizer report |
| MSVC `/analyze` static analysis | no actionable finding (see the evidence matrix) |

Across all suites: **157 test cases and 138,194 individual assertions**, all passing. The largest
single contributor is the seeded property suite, which re-checks the full invariant set after every
one of roughly a hundred thousand operations.

### Multiprocess and hard-kill proof

`test_multiprocess` spawns the `mp_worker` executable as a separate operating system process,
reads its readiness line from a pipe, connects over a real loopback socket, and drives a real
failover. It then hard-kills workers at meaningful boundaries - before the durable commit, after
the durable commit but before the acknowledgement, and after the request was written but before the
response was read - and asserts that the resulting durable state is conservative: the committed
lineage and the fence survive, every grant is stale or withdrawn, no authority is resurrected, and
a fresh worker's epoch and boot ordinal are strictly greater than the killed worker's.

---

## 11. Evidence matrix: REAL, SYNTHETIC, UNSUPPORTED

| Claim | Status | Basis |
| --- | --- | --- |
| Failure fencing, closure computation, planning, authority lifecycle, persistence, restart, framing | **REAL** | Executed on this host against the built library. |
| Multiprocess and hard-kill behaviour | **REAL** | Independent OS processes and real loopback sockets. |
| Durable restart, torn-tail recovery, tamper refusal | **REAL** | Real files, real process termination, byte-level assertions. |
| Every fabric fixture used by the suites, the tool and the examples | **SYNTHETIC** | Deterministic in-process generation. No physical switch, NIC, RDMA device or multi-node fabric is exercised. |
| Switch ASIC programming, routing convergence, physical link behaviour | **UNSUPPORTED** | Outside the boundary. Never claimed. |
| RDMA / RoCE / PFC / ECN behaviour | **UNSUPPORTED** | Capability bits are modelled as declared attributes; no hardware behaviour is exercised. |
| Transport authentication and encryption | **UNSUPPORTED** | The transport is unauthenticated and unencrypted by design; it is not secure transport. |
| AddressSanitizer | **REAL on this host** | The whole suite was built and run with `/fsanitize=address` and passed with no sanitizer report. One such run exposed a genuine use-after-scope in a test worker lambda, which was fixed. |
| UndefinedBehaviorSanitizer | **UNSUPPORTED on this host** | The MSVC toolchain used here ships no UBSan runtime; the missing component is the sanitizer runtime library itself, confirmed absent rather than assumed. |
| MSVC `/analyze` static analysis | **REAL, no actionable finding** | The only warnings are a SAL false positive on a masked array index in `crc32_ieee` and two from a Windows SDK header. |
| ThreadSanitizer | **UNSUPPORTED on this host** | Not available for the toolchain used here. |
| CUDA, SmartNIC, DPU, NVLink, InfiniBand, multi-node | **UNSUPPORTED** | Not present, not exercised, not claimed. |

---

## 12. Performance and scale

The scale suite measures **completed work**, not submission latency, and it is anchored on exact
work counters rather than wall-clock time wherever possible:

* the dependency closure is computed once, over a reverse adjacency index built at snapshot
  construction, and reports the exact number of edges it examined;
* the planner's assignment phase uses a greedy fast path that is provably optimal when no
  replacement generation can be oversubscribed, and a bounded backtracking search otherwise;
* the total assignment search work is bounded by one declared number, shared across all connected
  components, so a hostile instance degrades the strength of the answer (to
  `SearchLimitReached`) rather than its truthfulness;
* retained state is bounded by policy: plans, events, decisions, evidence and grants all have
  declared ceilings and report eviction or refuse.

---

## 13. Security and the trust boundary

All external input is treated as untrusted: declared lengths are checked before any allocation,
arithmetic is checked, canonical encodings are decoded totally with sticky failure, and every enum,
range and domain value is validated. Paths are sanitised against traversal. Every collection that
can be driven by input is bounded, and exhaustion is a deterministic refusal.

The runtime deliberately does **not** invent cryptographic security. The framed transport has no
authentication and no encryption. Integrity checks (CRC-32, a non-cryptographic 128-bit digest) are
integrity checks only: they detect corruption and accidental truncation, and they are not a defence
against a determined attacker with write access to the durable root. Deploy the transport only on a
trusted loopback or inside a boundary that supplies its own authentication.

---

## 14. Genuine limitations

* **No topology discovery and no path synthesis.** If an adjacent authoritative system does not
  supply a reconstruction alternative, the runtime reports the dependent as unresolved with a
  proven "no candidate supplied" reason. It will not invent one.
* **Grants are not persisted.** A restored grant could never be `Active`, so authority is
  re-established by reinstalling the authoritative topology rather than by replaying grants. The
  `GrantMinted` and `GrantWithdrawn` record kinds exist and are replayed when present, so a
  deployment that chooses to persist grant lineage is supported.
* **The planner's assignment search is exponential in the worst case.** It is bounded, and it
  reports `SearchLimitReached` rather than an optimality claim when the bound is reached. The
  fast path covers the unconstrained case, which is the common one.
* **The concurrency audit is a manual inspection plus targeted tests.** It is not a formal proof,
  not a race-detector run and not a model check.
* **No physical hardware validation of any kind.** Everything fabric-shaped in this repository is
  SYNTHETIC.
* **Single-writer durability.** One process owns a durable root. There is no leader election and no
  distributed consensus; the epoch exists to fence, not to elect.

---

## 15. Repository layout

```
include/sff/     public headers (core, codec, model, plan, persist, runtime, transport)
src/             implementation
tools/           sffctl
examples/        three runnable examples
tests/           verification suites, fixtures and the downstream consumer project
docs/            concurrency and ownership audit, engineering notes
cmake/           package config template
```

The public header set is frozen for implementers: every header is self-contained and the build
proves it.

---

## License
Apache License 2.0. Copyright 2026 Summon Software Labs.