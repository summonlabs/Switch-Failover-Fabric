// Switch Failover Fabric - independent plan validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/plan/validator.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>

#include "plan/planner_internal.hpp"

namespace sff {
namespace {

/// Validation findings are bounded: a hostile plan must not be able to grow the report without
/// limit. Truncation is itself recorded as a finding.
constexpr std::size_t kMaxFindings = 256;

class Validator {
 public:
  explicit Validator(const PlanInputs& inputs) : inputs_(inputs) {}

  /// Record a finding without counting a check. Callers that performed a check count exactly once.
  void record(Code code, std::string scope, std::string detail) {
    if (report_.findings.size() >= kMaxFindings) {
      if (report_.findings.size() == kMaxFindings) {
        report_.findings.push_back(ValidationFinding{
            Code::Exhausted, "report", "validation findings were truncated by the report bound"});
      }
      return;
    }
    report_.findings.push_back(ValidationFinding{code, std::move(scope), std::move(detail)});
  }

  void add(Code code, std::string scope, std::string detail) {
    report_.checks_performed += 1;
    record(code, std::move(scope), std::move(detail));
  }

  bool check(bool condition, Code code, std::string scope, std::string detail) {
    report_.checks_performed += 1;
    if (!condition) record(code, std::move(scope), std::move(detail));
    return condition;
  }

  ValidationReport run(const ReconstructionPlan& plan) {
    report_.plan_digest = plan.plan_digest;
    report_.inputs_digest = inputs_.policy_digest();

    if (!check(plan.digest_valid(), Code::Corrupt, "plan",
               "plan digest does not match its contents")) {
      return finish();
    }
    check(plan.epoch == inputs_.epoch, Code::Stale, "plan",
          "plan was produced under a different coordinator epoch");
    check(plan.boot == inputs_.boot, Code::Stale, "plan",
          "plan was produced under a different process incarnation");
    check(plan.topology_digest == inputs_.topology->digest(), Code::Stale, "plan",
          "plan was produced against a different topology snapshot");
    check(plan.policy_digest == inputs_.policy_digest(), Code::Stale, "plan",
          "plan was produced under a different policy");

    // A plan that names no failed generation cannot be a reconstruction plan: it fences nothing and
    // therefore cannot be the authoritative answer to "what must be fenced". Accepting it would be
    // a fail-open verdict, so it is refused before any other check runs.
    check(!plan.failed_generations.empty(), Code::Invalid, "plan",
          "plan names no failed generation and therefore fences nothing");
    if (!check(is_valid_feasibility(plan.feasibility), Code::Invalid, "plan",
               "plan carries an undefined feasibility value")) {
      return finish();
    }
    check(plan.feasibility != PlanFeasibility::ProvenInfeasible ||
              (plan.restores.empty() && !plan.unresolved.empty()),
          Code::Invalid, "plan",
          "a proven-infeasible plan must restore nothing and must explain every unresolved demand");
    check(plan.feasibility != PlanFeasibility::NothingToRestore || plan.restores.empty(),
          Code::Invalid, "plan", "a nothing-to-restore plan must restore nothing");

    validate_fences_internal(plan);
    validate_restores(plan);
    validate_coverage(plan);
    validate_ordering(plan);
    return finish();
  }

  ValidationReport run_fences(const ReconstructionPlan& plan) {
    report_.plan_digest = plan.plan_digest;
    report_.inputs_digest = inputs_.policy_digest();
    if (!check(plan.digest_valid(), Code::Corrupt, "plan",
               "plan digest does not match its contents")) {
      return finish();
    }
    validate_fences_internal(plan);
    return finish();
  }

 private:
  ValidationReport finish() {
    report_.valid = report_.findings.empty();
    if (report_.valid) {
      report_.outcome = Code::Ok;
    } else {
      report_.outcome = report_.findings.front().code;
    }
    return report_;
  }

  void validate_fences_internal(const ReconstructionPlan& plan) {
    std::set<SwitchKey> covered;
    for (const auto& step : plan.fences) {
      covered.insert(step.failed);
      check(step.failed.valid(), Code::Invalid, "fence",
            "fence step names an unqualified generation");
      if (step.closure_state == ClosureState::Truncated) {
        check(plan.closure_complete == false, Code::Invalid, "fence",
              "a truncated closure must not be reported as complete");
      }
      if (!inputs_.authority->is_fenced(step.failed)) {
        add(Code::Fenced, "fence",
            "failed generation is not fenced: " + step.failed.to_string());
      }
    }
    for (const auto& key : plan.failed_generations.keys()) {
      check(covered.find(key) != covered.end(), Code::Fenced,
            "fence",
            "failed generation has no fence step: " + key.to_string());
    }
  }

  void validate_restores(const ReconstructionPlan& plan) {
    std::set<std::pair<DependentRef, SwitchKey>> seen;
    std::map<SwitchKey, std::size_t> usage;
    std::set<SwitchKey> failed(plan.failed_generations.keys().begin(),
                               plan.failed_generations.keys().end());

    for (const auto& step : plan.restores) {
      const std::string scope = step.dependent.to_string() + "->" + step.covers_failed.to_string();
      check(step.dependent.valid(), Code::Invalid, scope, "restore step names an invalid dependent");
      check(step.covers_failed.valid(), Code::Invalid, scope,
            "restore step names an unqualified failed generation");
      check(failed.find(step.covers_failed) != failed.end(), Code::Invalid, scope,
            "restore step covers a generation that is not in the failed set");
      check(step.action == PlanAction::RebindReplacement, Code::Invalid, scope,
            "restore step has an undefined action");
      check(step.hops.size() != 0, Code::Invalid, scope, "restore step supplies no hops");
      check(step.cost != 0, Code::Invalid, scope, "restore step has a zero cost");
      check(step.hops.empty() || step.replacement == step.hops.front(), Code::Invalid, scope,
            "restore step replacement is not the head of its hop set");
      check(seen.insert({step.dependent, step.covers_failed}).second, Code::AlreadyExists, scope,
            "duplicate restore step for the same dependent and failed generation");

      for (const auto& hop : step.hops) {
        check(failed.find(hop) == failed.end(), Code::Fenced, scope,
              "restore step reuses a failed generation: " + hop.to_string());
        if (inputs_.authority->is_fenced(hop)) {
          add(Code::Fenced, scope, "restore step crosses a fenced generation: " + hop.to_string());
          continue;
        }
        const SwitchDescriptor* descriptor = inputs_.topology->find_switch(hop);
        if (descriptor == nullptr) {
          if (inputs_.topology->find_highest_generation(hop.id()) != nullptr) {
            add(Code::Stale, scope,
                "restore step names a superseded generation: " + hop.to_string());
          } else {
            add(Code::NotFound, scope,
                "restore step names a generation absent from the topology: " + hop.to_string());
          }
          continue;
        }
        const EvidenceStore& evidence =
            inputs_.evidence != nullptr ? *inputs_.evidence : empty_evidence();
        const FailureTable& failures =
            inputs_.failures != nullptr ? *inputs_.failures : empty_failures();
        const SwitchAssessment assessment = assess_switch(hop, evidence, failures, inputs_.now_ns,
                                                          inputs_.assessment);
        if (assessment.fence_required) {
          add(Code::Fenced, scope,
              "restore step crosses a generation that carries a fence obligation: " +
                  hop.to_string());
        }
        if (assessment.outcome == Code::Conflict) {
          add(Code::Conflict, scope,
              "authoritative evidence about a hop generation contradicts itself: " +
                  hop.to_string());
        }
      }
      // Count each distinct generation once per step, matching the planner's capacity accounting.
      std::set<SwitchKey> distinct_hops(step.hops.begin(), step.hops.end());
      for (const auto& hop : distinct_hops) usage[hop] += 1;
      for (const auto& link : step.links) {
        check(inputs_.topology->find_link(link) != nullptr, Code::NotFound, scope,
              "restore step names a link the topology does not contain");
      }
    }

    for (const auto& entry : usage) {
      const SwitchDescriptor* descriptor = inputs_.topology->find_switch(entry.first);
      if (descriptor == nullptr) continue;
      if (entry.second > descriptor->capacity_score) {
        add(Code::Exhausted, entry.first.to_string(),
            "assignment exceeds the declared spare capacity of the replacement generation");
      }
    }
  }

  void validate_coverage(const ReconstructionPlan& plan) {
    detail::DemandPlan demand_plan = detail::build_demand_plan(inputs_, plan.failed_generations);

    std::set<std::pair<DependentRef, SwitchKey>> resolved;
    for (const auto& step : plan.restores) resolved.insert({step.dependent, step.covers_failed});
    for (const auto& entry : plan.unresolved) {
      check(is_valid_reason(entry.reason), Code::Invalid, entry.dependent.to_string(),
            "unresolved entry has an undefined reason");
      resolved.insert({entry.dependent, entry.covers_failed});
    }

    for (const auto& demand : demand_plan.demands) {
      if (resolved.find({demand.dependent, demand.failed}) == resolved.end()) {
        add(Code::PartialClosure, demand.dependent.to_string(),
            "dependent invalidated by " + demand.failed.to_string() +
                " appears in neither the restore set nor the unresolved set");
      }
    }
    check(plan.closure_complete == demand_plan.closure_complete, Code::Invalid, "plan",
          "plan closure completeness does not match the closure recomputed from the inputs");
  }

  void validate_ordering(const ReconstructionPlan& plan) {
    const auto restore_order = std::is_sorted(
        plan.restores.begin(), plan.restores.end(),
        [](const RestoreStep& a, const RestoreStep& b) {
          if (a.dependent != b.dependent) return a.dependent < b.dependent;
          if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
          return a.replacement < b.replacement;
        });
    check(restore_order, Code::Invalid, "plan", "restore steps are not in canonical order");
    const auto unresolved_order = std::is_sorted(
        plan.unresolved.begin(), plan.unresolved.end(),
        [](const UnresolvedDependent& a, const UnresolvedDependent& b) {
          if (a.dependent != b.dependent) return a.dependent < b.dependent;
          return a.covers_failed < b.covers_failed;
        });
    check(unresolved_order, Code::Invalid, "plan", "unresolved entries are not in canonical order");
  }

  static bool is_valid_feasibility(PlanFeasibility value) {
    return static_cast<std::uint8_t>(value) <=
           static_cast<std::uint8_t>(PlanFeasibility::NothingToRestore);
  }

  static bool is_valid_reason(UnresolvedReason reason) {
    return static_cast<std::uint8_t>(reason) <=
           static_cast<std::uint8_t>(UnresolvedReason::NonAuthoritativeOrigin);
  }

  static const EvidenceStore& empty_evidence() {
    static const EvidenceStore store(Limits::defaults(), nullptr);
    return store;
  }
  static const FailureTable& empty_failures() {
    static const FailureTable table;
    return table;
  }

  const PlanInputs& inputs_;
  ValidationReport report_;
};

}  // namespace

std::string ValidationReport::to_string() const {
  std::string result = valid ? "VALID" : "INVALID";
  result += " outcome=";
  result += sff::to_string(outcome);
  result += " checks=";
  result += std::to_string(checks_performed);
  result += " findings=";
  result += std::to_string(findings.size());
  for (const auto& finding : findings) {
    result += " [";
    result += sff::to_string(finding.code);
    result += " ";
    result += finding.scope;
    result += ": ";
    result += finding.detail;
    result += "]";
  }
  return result;
}

ValidationReport validate_plan(const ReconstructionPlan& plan, const PlanInputs& inputs) {
  Validator validator(inputs);
  return validator.run(plan);
}

ValidationReport validate_fences(const ReconstructionPlan& plan, const PlanInputs& inputs) {
  Validator validator(inputs);
  return validator.run_fences(plan);
}

}  // namespace sff
