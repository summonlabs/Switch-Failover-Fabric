// Switch Failover Fabric - exhaustive reference solver for differential testing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PLAN_REFERENCE_SOLVER_HPP
#define SFF_PLAN_REFERENCE_SOLVER_HPP

#include <cstdint>

#include "sff/core/outcome.hpp"
#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"
#include "sff/export.hpp"

namespace sff {

/// Result of an exhaustive search.
///
/// The reference solver explores the complete admissible assignment space for small instances.
/// When the declared node budget is exhausted it reports SearchLimitReached and returns no
/// optimality claim: failure to find is never reported as proof that no solution exists.
struct SFF_API ReferenceSolution {
  bool optimal_found = false;
  bool exhausted = false;       ///< True only when the whole space was enumerated.
  std::uint64_t nodes_visited = 0;
  std::uint64_t node_budget = 0;
  ReconstructionPlan plan;      ///< Best plan found; meaningful when optimal_found is true.
  Code outcome = Code::Indeterminate;
};

/// Exhaustive search over the admissible assignment space.
///
/// Intended for differential testing against the production planner on instances small enough
/// to enumerate. The objective is identical to the production planner's, so for every instance
/// the production result must be no worse than the reference result under the same total order.
SFF_API ReferenceSolution solve_reference(const PlanInputs& inputs,
                                          const GenerationVector& failed_generations,
                                          std::uint64_t node_budget = 2000000);

}  // namespace sff

#endif  // SFF_PLAN_REFERENCE_SOLVER_HPP
