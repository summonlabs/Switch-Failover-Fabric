# Hardening record

Copyright 2026 Summon Software Labs. SPDX-License-Identifier: Apache-2.0

Every material defect found while building this release, how it was found, and what the fix was.
The point of the list is that a reader can see which classes of mistake this runtime actually made
and how each class is now prevented.

## Authority and adjudication

1. **Historical fences re-denied legitimately re-established authority.**
   `AuthorityRegistry::query` accumulated `fenced_generations` from every withdrawn grant ever
   recorded, including grants fenced long ago and since replaced by a new grant on a different
   generation. `has_authority` required that set to be empty, so a dependent could never regain
   authority after any fence and the restore decision reported `FENCED` forever.
   *Found by:* the integration suite. *Fixed by:* only the generations an *active* grant is bound to
   can deny authority; historical fences are still reported for audit, and when no active grant
   exists at all the query reports `FENCED` with the history as the explanation.

2. **A grant was "active" before it was minted.**
   `AuthorityGrant::active_at` consulted only the expiry. `query(dependent, t)` with a `t` earlier
   than the grant answered affirmatively. *Found by:* an independent test agent probing the public
   API. *Fixed by:* the window is now `granted_at <= now <= expires_at`.

3. **An elapsed validity window was reported as an operator revocation.**
   A grant still nominally `Active` but past its expiry was classified `Denied`, so a caller could
   not tell a lapsed window from a withdrawal without first driving `expire_due`.
   *Found by:* the same probe. *Fixed by:* `Expired`, a new explicit outcome code.

4. **`withdraw_all` claimed a fence that did not exist.**
   It stamped `GrantState::Fenced` for any cause, so the registry contradicted its own fence table
   (`is_fenced` false, `fence_count` zero) and a restart under `fence_on_restart` overwrote the
   "persistence is not liveness" `Stale` signal with a fabricated fence.
   *Found by:* the same probe. *Fixed by:* the resulting state now follows the cause - `Fenced` only
   for a fence, `Stale` for a restart, `Revoked` otherwise.

5. **`StrongId::next()` handed out a replayed identity at sequence exhaustion.**
   Saturating at the maximum value meant the same identifier could be issued twice.
   *Found by:* a boundary test in the core suite. *Fixed by:* the maximum has no successor and
   `next()` returns an invalid id that callers must treat as exhaustion.

## Evidence

6. **Evidence identity was unique only per subject.**
   The same `EvidenceId` admitted under two different subjects was accepted twice.
   *Found by:* an independent test agent. *Fixed by:* a globally enforced identity set, maintained
   across retention eviction.

7. **Adjudication reported ordinary absence where evidence existed.**
   Fresh, valid, trusted records whose kind does not adjudicate switch lifecycle (a `Recovering`
   health state, a capability declaration, effect verification) were ignored and the assessment then
   said "no evidence exists for this generation". The outcome was correctly fail-closed, but the
   explanation mapped UNKNOWN onto absence.
   *Found by:* the same agent. *Fixed by:* the rationale now distinguishes recovering, non-lifecycle
   evidence, stale-only evidence, untrusted-only evidence and genuinely absent evidence.

8. **Runtime-minted evidence could collide with caller-supplied identities.**
   Both started at 1, so the first failure declaration after a batch of caller evidence was refused
   as a duplicate. *Found by:* the integration suite. *Fixed by:* a documented reserved identifier
   range for runtime-minted identities, enforced at every admission point.

## Planning

9. **Out-of-bounds write in the planner's search summary.**
   `summarise` built a component-sized vector and indexed it with *global* demand indices, writing
   past the end whenever a component did not start at demand 0. *Found by:* the seeded property
   suite (access violation at seed 1, step 5). *Fixed by:* the summary is component-local and global
   indices are applied only in the caller, where the mapping is explicit.

10. **A fence left outstanding plans applicable.**
    A plan validated before a fence could still reference the newly fenced generation, so a later
    apply could have preserved authority that depended on a failed generation.
    *Found by:* the property suite (invariant I4). *Fixed by:* committing a fence now supersedes
    every retained plan that covers or hops through the fenced generation.

11. **The candidate table de-duplicated only adjacent entries.**
    It sorted on a digest but compared a different tuple for uniqueness, so equal alternatives that
    were not adjacent survived, and the table (and the plan-input policy digest) depended on
    duplicated input. *Found by:* a planner test agent. *Fixed by:* sorting on exactly the tuple the
    uniqueness predicate compares, with the evidence id as the final tie-break, so the survivor of a
    duplicate group is the canonically smallest one.

12. **A repeated hop inside one alternative oversubscribed its generation.**
    Capacity was charged per hop *occurrence*, so an alternative naming one generation twice produced
    a plan that the library's own validator rejected as over capacity - a plan that fails its own
    independent validation. *Found by:* the same agent. *Fixed by:* capacity counts dependents, not
    occurrences, in the planner and in the validator alike.

13. **An empty scope was labelled as a bound being hit.**
    An exhaustively enumerated closure with no dependents reported `closure_complete == false` and
    `SEARCH_LIMIT_REACHED`, which is not literally true. *Found by:* the same agent.
    *Fixed by:* an empty closure counts as complete when every root was present, and a new explicit
    `PlanFeasibility::NothingToRestore` says exactly what happened instead of borrowing a word that
    means something else.

14. **`service_withheld` was inert.** The flag was never set and the policy knob that should drive
    it was never consulted, so a consumer keying on it saw nothing.
    *Found by:* the CLI agent. *Fixed by:* the flag now states whether the policy deliberately
    permitted leaving dependents unrestored.

15. **The assignment search budget was per component.**
    Total work therefore grew with the number of components. *Found by:* inspection while fixing 9.
    *Fixed by:* one budget shared across all components, so total assignment work is bounded by one
    declared number.

## Persistence

16. **Journals larger than the replay window were silently truncated.**
    `replay()` scanned through a fixed 64 KiB buffer. A record straddling the window edge is complete
    in the file but looks torn in the window, so it was reported as a torn tail - and `open()` then
    truncated that many bytes *from the end of the file*, destroying complete records that the report
    never mentioned. *Found by:* the adversarial persistence suite, which measured 202 complete
    records lost in a 132800-byte journal. *Fixed by:* a streaming reader that validates each header,
    learns the declared length from the validated header, and reads exactly that many bytes. Memory
    and cost are O(1) per record at any journal size, and no record can straddle a window.

17. **A compacted suffix could brick the store.**
    Replay hard-coded the first expected sequence to 1, so a journal compacted to a suffix was
    refused as non-contiguous forever. *Found by:* the same suite. *Fixed by:* continuity is anchored
    on the first record actually present and every later record must follow it exactly - a regression
    reports `Code::Replay`, a gap reports `Code::Corrupt`.

18. **`replay()` returned a `Result` that was always `Ok`.**
    The verdict lived only in `value().status`, so `if (!report.ok())` treated a corrupt scan as a
    success - a direct contradiction of the stated contract that a `Result` never silently discards a
    non-Ok status. *Found by:* the same suite. *Fixed by:* `Result` gained a failed-yet-valued form,
    and replay now returns the report *with* the truthful status attached.

## Validation

19. **`validate_plan` accepted an entirely empty plan.**
    A plan naming no failed generation, fencing nothing and restoring nothing validated as `VALID`,
    which is strictly more permissive than the planner that refuses to produce it - a fail-open
    verdict. *Found by:* the core/validator test agent. *Fixed by:* the failed-generation set must be
    non-empty, the feasibility value must be defined, and known-infeasible/known-feasible plans must
    agree with their restore set.

20. **A failing check was counted twice.** `checks_performed` over-reported exactly where a failure
    happened. *Found by:* the same agent. *Fixed by:* one count per check, findings recorded without
    counting.

## Restart and reporting

21. **A false "plan was in flight" note.**
    Any replayed `PlanCommitted` in state `Applying` produced the note, and it was never retracted
    when a later record showed the plan had been applied. *Found by:* the CLI agent. *Fixed by:* only
    the final restored state of each plan is considered, and only plans whose state is still
    `Applying` produce the note.

22. **`recovered` was true for a brand-new durable root.** *Found by:* the same agent. *Fixed by:*
    it now reflects whether anything was actually replayed.

23. **`plans_restored` counted records, not plans.** *Found by:* the same agent. *Fixed by:*
    counting distinct plan identities.

## Transport

24. **The wire codec could not carry a code this release defines.**
    The enum ceiling was pinned to `PartialClosure` while `Code::Expired` was added later, so an
    expired-authority answer was rejected as an unassigned code and surfaced as `Invalid`.
    *Found by:* the CLI agent. *Fixed by:* pinning the ceiling to the actual highest ordinal.

## Build and headers

25. **`sff/transport/frame.hpp` was not self-contained.**
    It used `SessionBinding` without including the declaring header, so it only compiled when another
    header happened to be included first. *Found by:* two independent agents.
    *Fixed by:* the include, plus a permanent build target that compiles one translation unit per
    public header, each including only that header.

26. **The test harness declared a type it did not include.** Same class of mistake, same fix.

27. **Unspecified argument evaluation order permuted the boot incarnation.**
    `ReconstructionPlan::decode` passed four side-effecting reader calls directly to a constructor;
    MSVC evaluates arguments right-to-left, so the decoded plan carried a permuted boot identity and
    a different digest. *Found by:* the adversarial persistence suite.
    *Fixed by:* reading into named locals in sequence, plus a permanent regression guard that asserts
    the four words land in their documented positions.

## Concurrency

28. **Self-deadlock in the failover pipeline.**
    `declare_failure` took the coordinator state mutex and then called the public `record_failure`,
    which takes the same non-recursive mutex - the first end-to-end failover deadlocked.
    *Found by:* the first run of the integration suite, which hung rather than failing.
    *Fixed by:* an inner helper that assumes the lock is held, with both public entry points taking
    the lock exactly once. The full analysis is in `docs/CONCURRENCY_AUDIT.md`.
