// Switch Failover Fabric - independent plan validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PLAN_VALIDATOR_HPP
#define SFF_PLAN_VALIDATOR_HPP

#include <string>
#include <vector>

#include "sff/core/outcome.hpp"
#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"
#include "sff/export.hpp"

namespace sff {

/// A single validation finding.
struct SFF_API ValidationFinding {
  Code code = Code::Invalid;
  std::string scope;
  std::string detail;
};

/// Independent validation report.
///
/// Validation re-derives every claim in the plan from the inputs instead of trusting the plan's
/// own fields. In particular it checks that no restore step preserves authority that depended on
/// a failed generation, that every hop is generation-current, and that the plan digest matches.
struct SFF_API ValidationReport {
  bool valid = false;
  Code outcome = Code::Invalid;
  std::size_t checks_performed = 0;
  std::vector<ValidationFinding> findings;
  std::uint64_t plan_digest = 0;
  std::uint64_t inputs_digest = 0;

  std::string to_string() const;
};

SFF_API ValidationReport validate_plan(const ReconstructionPlan& plan, const PlanInputs& inputs);

/// Validate only the fence obligations: every failed generation must be fenced and the closure
/// must be recorded as complete or explicitly reported as truncated.
SFF_API ValidationReport validate_fences(const ReconstructionPlan& plan, const PlanInputs& inputs);

}  // namespace sff

#endif  // SFF_PLAN_VALIDATOR_HPP
