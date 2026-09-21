// Switch Failover Fabric - exhaustive reference solver for differential testing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/plan/reference_solver.hpp"

#include <algorithm>

#include "plan/planner_internal.hpp"

namespace sff {

ReferenceSolution solve_reference(const PlanInputs& inputs,
                                  const GenerationVector& failed_generations,
                                  std::uint64_t node_budget) {
  ReferenceSolution solution;
  solution.node_budget = node_budget;

  PlanInputs adjusted = inputs;
  const std::uint64_t bounded = std::max<std::uint64_t>(node_budget, 1);
  const std::size_t as_size = bounded > static_cast<std::uint64_t>(SIZE_MAX)
                                  ? SIZE_MAX
                                  : static_cast<std::size_t>(bounded);
  adjusted.limits.max_candidates_evaluated = as_size;

  std::uint64_t nodes = 0;
  Result<ReconstructionPlan> result = detail::plan_internal(adjusted, failed_generations, true, &nodes);
  solution.nodes_visited = nodes;

  if (!result.ok()) {
    solution.outcome = result.status().code();
    return solution;
  }
  solution.plan = std::move(result).value();
  // Only an exhaustive enumeration licenses an optimality or infeasibility claim.
  solution.exhausted = solution.plan.feasibility == PlanFeasibility::ProvenFeasible ||
                       solution.plan.feasibility == PlanFeasibility::ProvenInfeasible;
  solution.optimal_found = solution.exhausted;
  solution.outcome = solution.exhausted ? Code::Ok : Code::SearchLimitReached;
  return solution;
}

}  // namespace sff
