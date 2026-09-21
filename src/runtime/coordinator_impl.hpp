// Switch Failover Fabric - coordinator internals.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Locking contract for the coordinator (also asserted by the concurrency audit test):
//
//   1. The coordinator state mutex is the OUTERMOST coordinator lock. It is never acquired while
//      any subsystem lock is held.
//   2. Subsystem locks (evidence, failure table, authority registry, session registry, event log,
//      decision log, durable store) are leaves. No two of them are held at the same time by a
//      single call path except where a leaf explicitly calls another leaf's const method after
//      releasing its own lock.
//   3. No user callback, no event emission into user code and no explanation construction happens
//      while holding the state mutex except through leaf-locked loggers that never call back.
//   4. The durable store is never written while another subsystem lock is held.
#ifndef SFF_SRC_RUNTIME_COORDINATOR_IMPL_HPP
#define SFF_SRC_RUNTIME_COORDINATOR_IMPL_HPP

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "sff/core/log.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/decision.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/topology.hpp"
#include "sff/persist/store.hpp"
#include "sff/plan/planner.hpp"
#include "sff/runtime/coordinator.hpp"
#include "sff/runtime/session.hpp"

namespace sff {

struct Coordinator::Impl {
  Impl(const CoordinatorConfig& config_in, const Clock* clock_in)
      : config(config_in),
        clock(clock_in),
        policy(config_in.policy),
        limits(config_in.limits),
        events(config_in.event_capacity, clock_in),
        decisions(config_in.decision_capacity),
        sessions(config_in.limits),
        evidence(config_in.limits, clock_in),
        authority(config_in.limits) {}

  CoordinatorConfig config;
  const Clock* clock = nullptr;

  std::mutex mutex;  // outermost coordinator lock; see the contract above

  // --- durable state, replaced transactionally where mutation is claimed ------------------
  std::unique_ptr<DurableStore> store;

  // --- runtime identity -------------------------------------------------------------------
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  std::uint64_t boot_digest = 0;
  Policy policy;
  Limits limits;

  // --- subsystems -------------------------------------------------------------------------
  EventLog events;
  DecisionLog decisions;
  SessionRegistry sessions;
  EvidenceStore evidence;
  FailureTable failures;
  AuthorityRegistry authority;

  // --- supplied definitions (guarded by mutex) --------------------------------------------
  bool topology_present = false;
  TopologySnapshot topology;
  CandidateTable candidates;


  // --- committed lineage and outcomes (guarded by mutex) ----------------------------------
  std::map<PlanId, ReconstructionPlan> plans;
  std::map<std::pair<DependentRef, SwitchKey>, ApplyStepResult> apply_steps;
  RestartReport restart;
  std::uint64_t next_plan = 1;
  std::uint64_t next_evidence = 1;
  bool candidates_present = false;
  std::atomic<bool> stopped{false};

  // --- helpers ----------------------------------------------------------------------------
  TimestampNs now() const noexcept { return clock != nullptr ? clock->now_ns() : 0; }

  /// Named accessor: "evidence" is also a natural local variable name inside the pipeline.
  EvidenceStore& evidence_store_ref() noexcept { return evidence; }

  bool ensure_running(Status& out) const {
    if (stopped.load(std::memory_order_acquire)) {
      out = Status::failure(Code::Closed, "coordinator has been shut down");
      return false;
    }
    return true;
  }

  void append_event(EventKind kind, Code code, std::string_view text, std::uint64_t subject = 0,
                    std::uint64_t generation = 0) {
    events.append(kind, code, text, subject, generation);
  }

  Decision& record_decision(DecisionKind kind, DecisionScope scope, Code outcome, Code reason,
                            GenerationVector bound, Explanation explanation);

  /// Failure recording without taking the state mutex. Callers must already hold it.
  ///
  /// The state mutex is deliberately NOT recursive: a helper that re-entered it would self
  /// deadlock, which the concurrency suite asserts against. Every entry point either takes the
  /// lock exactly once or calls an inner helper that never takes it.
  Result<FailureRecord> record_failure_locked(const FailureDeclaration& declaration);

  /// Build the planning inputs under the current identity. Caller must hold the state mutex.
  PlanInputs make_inputs(PlanId plan_id, TimestampNs now_ns) const;

  Status persist_record(RecordKind kind, const std::vector<std::uint8_t>& payload);

  /// Reconcile durable state after a process boundary. Returns the reconciliation report.
  Result<RestartReport> recover_from_durable();
};

}  // namespace sff

#endif  // SFF_SRC_RUNTIME_COORDINATOR_IMPL_HPP
