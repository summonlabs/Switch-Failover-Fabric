// Switch Failover Fabric - the coordinator runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_RUNTIME_COORDINATOR_HPP
#define SFF_RUNTIME_COORDINATOR_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/log.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/decision.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/topology.hpp"
#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"
#include "sff/plan/validator.hpp"
#include "sff/runtime/failover.hpp"
#include "sff/runtime/policy.hpp"
#include "sff/runtime/session.hpp"
#include "sff/version.hpp"
#include "sff/export.hpp"

namespace sff {

struct SFF_API CoordinatorConfig {
  Limits limits = Limits::defaults();
  Policy policy{};
  std::filesystem::path durable_root;      ///< Empty disables durability entirely.
  bool enable_durability = false;
  EvidenceClass evidence_class = EvidenceClass::Synthetic;
  std::size_t event_capacity = 4096;
  std::size_t decision_capacity = 1024;
  std::uint64_t boot_ordinal = 0;          ///< 0 means: derive from durable lineage.
};

/// The failover coordinator.
///
/// Ownership and locking model, stated here because it is part of the contract:
///   * every subsystem is individually synchronised;
///   * there is no lock held across a call into another subsystem that can call back;
///   * events, decisions and explanations are produced outside any lock that guards state;
///   * shutdown releases blocked accepts and reads before joining workers.
///
/// All public methods are safe to call from multiple threads. A method that returns a Result
/// never throws and never leaves the runtime in a half-applied state.
class SFF_API Coordinator {
 public:
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;
  ~Coordinator();

  /// Open a coordinator. When durability is enabled this replays the journal, advances the
  /// epoch and boot incarnation, restores durable lineage only, and marks every pre-restart
  /// grant stale.
  static Result<std::unique_ptr<Coordinator>> open(const CoordinatorConfig& config,
                                                   const Clock* clock);

  // --- runtime identity -------------------------------------------------------------------
  CoordinatorEpoch epoch() const;
  BootIncarnation boot() const;
  std::uint64_t boot_digest() const;
  EvidenceClass evidence_class() const;
  const Limits& limits() const;
  Policy policy() const;
  bool stopped() const;

  // --- inputs -----------------------------------------------------------------------------
  Status install_topology(TopologySnapshot topology);

  /// Install the caller-supplied reconstruction alternatives. Like the topology, this table is
  /// authoritative input from an adjacent system and is not durable state of this runtime.
  Status install_candidates(CandidateTable candidates);

  Status install_policy(const Policy& policy);
  Status admit_evidence(const EvidenceRecord& record);
  Result<SwitchAssessment> assess(const SwitchKey& subject) const;
  Result<FailureRecord> record_failure(const FailureDeclaration& declaration);

  // --- failover pipeline ------------------------------------------------------------------
  /// Fence first: commit the failure lineage, fence every dependent in the bounded closure, and
  /// revoke the authority of every dependent bound to the failed generation.
  Result<FailoverOutcome> declare_failure(const FailureDeclaration& declaration);

  /// Reconstruct second: produce a plan from current generations. Never preserves authority that
  /// depended on a fenced generation.
  Result<ReconstructionPlan> propose_plan(const GenerationVector& failed);

  /// Mint forwarding authority for a dependent under the current epoch and incarnation.
  ///
  /// Authority is only ever established explicitly. Installing a topology establishes it for
  /// every declared path and link; a caller that owns authority from another source states the
  /// exact generations it is bound to here. The call is refused for a fenced generation.
  Status establish_authority(const DependentRef& dependent, const GenerationVector& bound,
                             std::string_view detail = {});

  /// Withdraw every grant for a dependent.
  Status withdraw_authority(const DependentRef& dependent, RevocationCause cause,
                            std::string_view detail = {});

  /// Independently re-derive and check every claim in a plan against current inputs.
  Result<ValidationReport> validate_plan(const ReconstructionPlan& plan) const;

  /// Turn a validated plan into proposed forwarding effect. An acknowledgement is recorded as an
  /// acknowledgement, never as verified effect.
  Result<ApplyReceipt> apply_plan(const ReconstructionPlan& plan);

  /// Admit independent verification evidence for a previously applied step.
  Status record_effect_verification(const EvidenceRecord& verification);

  /// Decide whether service may be restored for one dependent under current generations.
  Result<RestoreDecision> evaluate_restore(const DependentRef& dependent) const;

  // --- queries ----------------------------------------------------------------------------
  Result<AuthorityQuery> query_authority(const DependentRef& dependent) const;
  Result<ReconstructionPlan> plan_by_id(PlanId id) const;
  std::vector<ReconstructionPlan> plans() const;
  Result<RestartReport> restart_report() const;
  std::vector<EventRecord> events(std::size_t count) const;
  std::vector<Decision> decisions(std::size_t count) const;
  Result<SwitchAssessment> assess_identity(SwitchId id) const;

  // --- sessions ---------------------------------------------------------------------------
  Result<SessionRecord> open_session(std::string_view principal);
  Status close_session(SessionId id);
  Status authorise(const SessionBinding& binding) const;
  std::size_t session_count() const;

  // --- lifecycle --------------------------------------------------------------------------
  /// Flush and close durable state, release waiters, and refuse further mutation. Idempotent.
  Status shutdown();

  /// Borrowed read-only views for tooling and tests.
  ///
  /// Lifecycle contract: inputs are installed during a configuration phase. The borrowed views
  /// must not be read concurrently with install_topology()/install_candidates(); establish the
  /// inputs first, then begin concurrent operation. Operational calls are safe to issue from any
  /// number of threads at any time.
  const TopologySnapshot* topology() const;
  const FailureTable* failures() const;
  const EvidenceStore* evidence() const;
  const AuthorityRegistry* authority() const;

 private:
  explicit Coordinator(const CoordinatorConfig& config, const Clock* clock);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace sff

#endif  // SFF_RUNTIME_COORDINATOR_HPP
