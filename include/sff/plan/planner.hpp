// Switch Failover Fabric - deterministic reconstruction planning.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PLAN_PLANNER_HPP
#define SFF_PLAN_PLANNER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/topology.hpp"
#include "sff/plan/plan.hpp"
#include "sff/export.hpp"

namespace sff {

/// Planning knobs. Defaults are fail-closed.
struct SFF_API PlanningPolicy {
  bool allow_replacement_in_same_failure_domain = false;
  bool require_capability_superset = true;
  bool require_authoritative_candidate_evidence = true;
  bool allow_withhold_on_unresolved = true;
  bool allow_restore_when_closure_truncated = false;
  std::uint32_t max_candidates_per_dependent = 256;

  std::uint64_t digest() const noexcept;
};

/// Canonically ordered table of caller-supplied reconstruction alternatives.
///
/// The table is authoritative input, not inference: this runtime never synthesises a forwarding
/// path, it only selects among alternatives that another authoritative system supplied.
class SFF_API CandidateTable {
 public:
  CandidateTable() = default;

  static Result<CandidateTable> build(std::vector<ReconstructionCandidate> candidates,
                                      const Limits& limits);

  const std::vector<ReconstructionCandidate>& candidates() const noexcept { return candidates_; }
  std::size_t size() const noexcept { return candidates_.size(); }
  std::uint64_t digest() const noexcept { return digest_; }

  /// Every alternative supplied for one dependent, in canonical candidate order.
  std::vector<ReconstructionCandidate> for_dependent(const DependentRef& dependent) const;

 private:
  std::vector<ReconstructionCandidate> candidates_;
  std::uint64_t digest_ = 0;
};

/// Every input a planner, validator or reference solver may consult.
///
/// Pointers are borrowed and must outlive the call. Nothing is cached between calls: a plan is
/// only ever as current as the inputs it was derived from, and re-validation re-reads them.
struct SFF_API PlanInputs {
  const TopologySnapshot* topology = nullptr;
  const CandidateTable* candidates = nullptr;
  const EvidenceStore* evidence = nullptr;
  const FailureTable* failures = nullptr;
  const AuthorityRegistry* authority = nullptr;
  const Clock* clock = nullptr;
  Limits limits = Limits::defaults();
  AssessmentPolicy assessment{};
  PlanningPolicy planning{};
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  PlanId plan_id;
  TimestampNs now_ns = 0;

  Status validate() const;
  std::uint64_t policy_digest() const noexcept;
};

/// Why a particular replacement alternative is or is not admissible.
struct SFF_API CandidateEligibility {
  DependentRef dependent;
  SwitchKey covers_failed;
  std::vector<SwitchKey> hops;
  std::uint32_t cost = 0;
  bool eligible = false;
  Code outcome = Code::Unknown;
  UnresolvedReason reason = UnresolvedReason::Unknown;
  std::string detail;

  std::uint64_t digest() const noexcept;
};

/// Evaluate every supplied alternative for one dependent and one failed generation.
///
/// The enumeration is exhaustive over the supplied candidate set. When it is cut short by a
/// declared bound the result carries SearchLimitReached and is not a proof of absence.
SFF_API std::vector<CandidateEligibility> evaluate_candidates(const DependentRef& dependent,
                                                              const SwitchKey& failed,
                                                              const PlanInputs& inputs);

/// Produce a reconstruction plan under a deterministic total objective.
///
/// Objective, minimised lexicographically:
///   1. number of unresolved dependents,
///   2. total reconstruction cost,
///   3. total replacement hop count,
///   4. canonical assignment sequence.
///
/// The objective is total and the tie-break is canonical, so the output does not depend on
/// container, hash, insertion or discovery order.
SFF_API Result<ReconstructionPlan> plan_reconstruction(const PlanInputs& inputs,
                                                       const GenerationVector& failed_generations);

}  // namespace sff

#endif  // SFF_PLAN_PLANNER_HPP
