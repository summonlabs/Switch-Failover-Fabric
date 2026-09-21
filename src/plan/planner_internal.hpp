// Switch Failover Fabric - internal planning helpers shared by the production planner and the
// reference solver. Not installed and not part of the public interface.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_SRC_PLAN_PLANNER_INTERNAL_HPP
#define SFF_SRC_PLAN_PLANNER_INTERNAL_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/outcome.hpp"
#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"

namespace sff::detail {

/// One unit of reconstruction demand: one dependent that must be moved off one failed generation.
struct Demand {
  DependentRef dependent;
  SwitchKey failed;

  friend bool operator==(const Demand& a, const Demand& b) {
    return a.dependent == b.dependent && a.failed == b.failed;
  }
  friend bool operator<(const Demand& a, const Demand& b) {
    if (a.dependent != b.dependent) return a.dependent < b.dependent;
    return a.failed < b.failed;
  }
};

/// One admissible alternative for a demand.
struct CandidateUse {
  ReconstructionCandidate candidate;
  std::vector<SwitchKey> capacity_keys;  ///< Switch generations whose capacity this use consumes.
};

/// The admissible alternatives for one demand, plus why there are none when there are none.
struct DemandOptions {
  Demand demand;
  std::vector<CandidateUse> eligible;
  std::vector<CandidateEligibility> reports;  ///< Full per-alternative diagnosis, in input order.
  bool enumeration_complete = true;  ///< False when a bound cut the candidate enumeration short.
  UnresolvedReason blocking_reason = UnresolvedReason::NoCandidateSupplied;
  std::string blocking_detail;
};

struct DemandPlan {
  std::vector<Demand> demands;
  std::vector<DemandOptions> options;
  DependencyClosure closure;
  std::vector<FenceStep> fences;
  bool closure_complete = false;
  bool enumeration_complete = true;
};

/// Build the demand set and the admissible alternatives for each demand.
DemandPlan build_demand_plan(const PlanInputs& inputs, const GenerationVector& failed);

/// Eligibility of one supplied alternative. Enumeration is exhaustive over the candidate table.
std::vector<CandidateEligibility> evaluate_candidates_internal(const DependentRef& dependent,
                                                               const SwitchKey& failed,
                                                               const PlanInputs& inputs);

/// Shared entry point. When reference_mode is true the bounded backtracking search is used for
/// every component regardless of capacity pressure, and the greedy fast path is skipped.
/// nodes_out, when supplied, receives the number of search nodes the assignment phase visited.
Result<ReconstructionPlan> plan_internal(const PlanInputs& inputs,
                                         const GenerationVector& failed_generations,
                                         bool reference_mode,
                                         std::uint64_t* nodes_out = nullptr);

/// Capacity of a replacement switch generation, taken from the installed topology descriptor.
std::uint32_t capacity_of(const PlanInputs& inputs, const SwitchKey& key);

}  // namespace sff::detail

#endif  // SFF_SRC_PLAN_PLANNER_INTERNAL_HPP
