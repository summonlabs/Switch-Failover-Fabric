// Switch Failover Fabric - shared planning core used by the production planner and the
// exhaustive reference solver.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "plan/planner_internal.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "sff/core/checked.hpp"

namespace sff::detail {
namespace {

constexpr std::size_t kSkipped = static_cast<std::size_t>(-1);

const EvidenceStore& empty_evidence() {
  static const EvidenceStore store(Limits::defaults(), nullptr);
  return store;
}

const FailureTable& empty_failures() {
  static const FailureTable table;
  return table;
}

SwitchAssessment assess(const PlanInputs& inputs, const SwitchKey& key) {
  const EvidenceStore& evidence = inputs.evidence != nullptr ? *inputs.evidence : empty_evidence();
  const FailureTable& failures = inputs.failures != nullptr ? *inputs.failures : empty_failures();
  return assess_switch(key, evidence, failures, inputs.now_ns, inputs.assessment);
}

/// Required capability set for a dependent, taken from the authoritative path descriptor.
CapabilityMask required_capabilities(const PlanInputs& inputs, const DependentRef& dependent) {
  if (dependent.kind() != DependentKind::Path) return 0;
  const auto* path = inputs.topology->find_path(PathId(dependent.id()));
  return path != nullptr ? path->required_capabilities : 0;
}

bool candidate_order_less(const ReconstructionCandidate& a, const ReconstructionCandidate& b) {
  if (a.cost != b.cost) return a.cost < b.cost;
  if (a.hops.size() != b.hops.size()) return a.hops.size() < b.hops.size();
  if (a.hops != b.hops) return a.hops < b.hops;
  if (a.links != b.links) return a.links < b.links;
  if (a.capabilities != b.capabilities) return a.capabilities < b.capabilities;
  return a.evidence < b.evidence;
}

struct Assignment {
  std::vector<std::size_t> choice;
  std::size_t skipped = 0;
  std::uint64_t cost = 0;
  std::size_t hops = 0;
};

bool assignment_better(const Assignment& a, const Assignment& b) {
  if (a.skipped != b.skipped) return a.skipped < b.skipped;
  if (a.cost != b.cost) return a.cost < b.cost;
  if (a.hops != b.hops) return a.hops < b.hops;
  return a.choice < b.choice;
}

/// Summarise a component-local assignment. The choice vector is indexed by position WITHIN the
/// component, exactly like the evaluations it refers to; global demand indices are applied by the
/// caller. Indexing this vector with a global index is an out-of-bounds write, which the
/// invariant suite caught.
Assignment summarise(const std::vector<std::size_t>& choice,
                     const std::vector<const DemandOptions*>& evaluations) {
  Assignment result;
  result.choice.assign(evaluations.size(), kSkipped);
  for (std::size_t position = 0; position < evaluations.size(); ++position) {
    const std::size_t selected = choice[position];
    result.choice[position] = selected;
    if (selected == kSkipped) {
      result.skipped += 1;
      continue;
    }
    const CandidateUse& use = evaluations[position]->eligible[selected];
    const std::uint64_t cost = result.cost;
    const std::uint64_t added = use.candidate.cost;
    result.cost = cost > UINT64_MAX - added ? UINT64_MAX : cost + added;
    result.hops += use.candidate.hops.size();
  }
  return result;
}

DemandOptions evaluate_demand(const Demand& demand, const PlanInputs& inputs) {
  DemandOptions evaluation;
  evaluation.demand = demand;

  const std::uint32_t max_candidates = inputs.planning.max_candidates_per_dependent;
  const CapabilityMask required = required_capabilities(inputs, demand.dependent);
  const bool separation_required = !inputs.planning.allow_replacement_in_same_failure_domain;

  const SwitchDescriptor* failed_descriptor = inputs.topology->find_switch(demand.failed);
  const SwitchAssessment failed_assessment = assess(inputs, demand.failed);
  const bool failed_active = failed_assessment.fence_required ||
                             inputs.authority->is_fenced(demand.failed);

  const auto supplied = inputs.candidates->for_dependent(demand.dependent);
  std::size_t examined = 0;
  for (const auto& candidate : supplied) {
    if (examined >= max_candidates) {
      evaluation.enumeration_complete = false;
      break;
    }
    examined += 1;

    CandidateEligibility report;
    report.dependent = demand.dependent;
    report.covers_failed = candidate.covers_failed;
    report.hops = candidate.hops;
    report.cost = candidate.cost;

    const auto reject = [&evaluation, &report](Code outcome, UnresolvedReason reason,
                                               const std::string& detail) {
      report.eligible = false;
      report.outcome = outcome;
      report.reason = reason;
      report.detail = detail;
      evaluation.reports.push_back(report);
    };

    if (candidate.covers_failed != demand.failed) {
      if (candidate.covers_failed.same_identity(demand.failed)) {
        reject(Code::Stale, UnresolvedReason::CandidateGenerationStale,
               "alternative covers a different generation of the same switch identity");
      } else {
        reject(Code::NotFound, UnresolvedReason::NoCandidateSupplied,
               "alternative does not cover this failed generation");
      }
      continue;
    }

    if (inputs.planning.require_authoritative_candidate_evidence &&
        trust_of(candidate.source) != TrustLevel::Authoritative) {
      reject(Code::Unauthorized, UnresolvedReason::NonAuthoritativeOrigin,
             "alternative origin is not an authoritative evidence source");
      continue;
    }

    bool admissible = true;
    std::vector<SwitchKey> capacity_keys;
    for (const auto& hop : candidate.hops) {
      if (hop == demand.failed) {
        reject(Code::Fenced, UnresolvedReason::BehindFence,
               "alternative reuses the failed generation");
        admissible = false;
        break;
      }
      const SwitchDescriptor* descriptor = inputs.topology->find_switch(hop);
      if (descriptor == nullptr) {
        if (inputs.topology->find_highest_generation(hop.id()) != nullptr) {
          reject(Code::Stale, UnresolvedReason::CandidateGenerationStale,
                 "alternative names a superseded generation of a known switch identity");
        } else {
          reject(Code::NotFound, UnresolvedReason::HopNotInTopology,
                 "alternative names a switch generation the topology does not contain");
        }
        admissible = false;
        break;
      }
      if (inputs.authority->is_fenced(hop)) {
        reject(Code::Fenced, UnresolvedReason::BehindFence,
               "alternative crosses a fenced generation");
        admissible = false;
        break;
      }
      const SwitchAssessment hop_assessment = assess(inputs, hop);
      if (hop_assessment.outcome == Code::Conflict) {
        reject(Code::Conflict, UnresolvedReason::ContradictoryEvidence,
               "authoritative evidence about a hop generation contradicts itself");
        admissible = false;
        break;
      }
      if (hop_assessment.fence_required) {
        reject(Code::Fenced, UnresolvedReason::BehindFence,
               "a hop generation carries a fence obligation");
        admissible = false;
        break;
      }
      if (inputs.planning.require_capability_superset) {
        if (!has_all_capabilities(descriptor->capabilities, required)) {
          reject(Code::Unsupported, UnresolvedReason::CapabilityInsufficient,
                 "hop generation does not provide the required capability set");
          admissible = false;
          break;
        }
        if (!has_all_capabilities(candidate.capabilities, required)) {
          reject(Code::Unsupported, UnresolvedReason::CapabilityInsufficient,
                 "alternative does not provide the required capability set");
          admissible = false;
          break;
        }
      }
      if (separation_required) {
        if (failed_descriptor == nullptr || !failed_descriptor->failure_domain.valid() ||
            !descriptor->failure_domain.valid()) {
          reject(Code::Denied, UnresolvedReason::FailureDomainConflict,
                 "failure-domain separation from the failed generation cannot be established");
          admissible = false;
          break;
        }
        if (descriptor->failure_domain == failed_descriptor->failure_domain) {
          reject(Code::Denied, UnresolvedReason::FailureDomainConflict,
                 "alternative reuses the failed generation failure domain");
          admissible = false;
          break;
        }
      }
      if (descriptor->capacity_score == 0) {
        reject(Code::Exhausted, UnresolvedReason::CapacityExhausted,
               "replacement generation declares no spare capacity");
        admissible = false;
        break;
      }
      // Capacity counts dependents, not hop occurrences: an alternative that traverses the same
      // generation twice still consumes exactly one unit of that generation's spare capacity.
      if (std::find(capacity_keys.begin(), capacity_keys.end(), hop) == capacity_keys.end()) {
        capacity_keys.push_back(hop);
      }
    }
    (void)failed_active;

    if (!admissible) continue;

    CandidateUse use;
    use.candidate = candidate;
    use.capacity_keys = std::move(capacity_keys);
    report.eligible = true;
    report.outcome = Code::Ok;
    report.reason = UnresolvedReason::Unknown;
    report.detail = "admissible under current generations";
    evaluation.reports.push_back(report);
    evaluation.eligible.push_back(std::move(use));
  }

  std::sort(evaluation.eligible.begin(), evaluation.eligible.end(),
            [](const CandidateUse& a, const CandidateUse& b) {
              return candidate_order_less(a.candidate, b.candidate);
            });

  // Choose the reported blocking reason deterministically: the first proven negative in
  // canonical order, otherwise the first reported reason, otherwise a bound was hit.
  evaluation.blocking_reason = UnresolvedReason::NoCandidateSupplied;
  evaluation.blocking_detail = "no admissible reconstruction alternative is available";
  for (const auto& report : evaluation.reports) {
    if (report.eligible) continue;
    if (is_proven_negative(report.reason)) {
      evaluation.blocking_reason = report.reason;
      evaluation.blocking_detail = report.detail;
      break;
    }
  }
  if (evaluation.blocking_reason == UnresolvedReason::NoCandidateSupplied && !evaluation.reports.empty()) {
    for (const auto& report : evaluation.reports) {
      if (report.eligible) continue;
      evaluation.blocking_reason = report.reason;
      evaluation.blocking_detail = report.detail;
      break;
    }
  }
  if (!evaluation.enumeration_complete) {
    evaluation.blocking_reason = UnresolvedReason::SearchLimitReached;
    evaluation.blocking_detail = "candidate enumeration was cut short by a declared bound";
  }
  return evaluation;
}

/// Bounded backtracking search over one connected component of demands.
class ComponentSearch {
 public:
  ComponentSearch(std::vector<const DemandOptions*> evaluations,
                  std::vector<std::size_t> positions,
                  std::map<SwitchKey, std::uint32_t> capacity, std::uint64_t& remaining_budget)
      : evaluations_(std::move(evaluations)),
        positions_(std::move(positions)),
        capacity_(std::move(capacity)),
        remaining_(remaining_budget) {}

  Assignment run(bool& exhausted) {
    choices_.assign(evaluations_.size(), kSkipped);
    best_.choice.assign(evaluations_.size(), kSkipped);
    dfs(0, 0, 0, 0);
    exhausted = exhausted_;
    return best_;
  }

  std::uint64_t nodes_visited() const noexcept { return nodes_; }
  bool budget_exhausted() const noexcept { return !exhausted_; }

 private:
  void dfs(std::size_t position, std::size_t partial_skipped, std::uint64_t partial_cost,
           std::size_t partial_hops) {
    if (!exhausted_) return;
    if (have_best_ && partial_skipped > best_.skipped) return;
    if (have_best_ && partial_skipped == best_.skipped && partial_cost > best_.cost) return;

    if (position == evaluations_.size()) {
      Assignment candidate = summarise(choices_, evaluations_);
      if (!have_best_ || assignment_better(candidate, best_)) {
        best_ = candidate;
        have_best_ = true;
      }
      return;
    }

    const DemandOptions& evaluation = *evaluations_[position];
    for (std::size_t index = 0; index < evaluation.eligible.size(); ++index) {
      if (remaining_ == 0) {
        exhausted_ = false;
        return;
      }
      remaining_ -= 1;
      nodes_ += 1;
      const CandidateUse& use = evaluation.eligible[index];
      bool fits = true;
      for (const auto& key : use.capacity_keys) {
        const auto capacity = capacity_.find(key);
        if (capacity == capacity_.end()) continue;
        const auto used = used_.find(key);
        const std::uint32_t current = used == used_.end() ? 0 : used->second;
        if (current >= capacity->second) {
          fits = false;
          break;
        }
      }
      if (!fits) continue;
      for (const auto& key : use.capacity_keys) used_[key] = used_[key] + 1;
      choices_[position] = index;
      dfs(position + 1, partial_skipped,
          partial_cost > UINT64_MAX - use.candidate.cost ? UINT64_MAX
                                                         : partial_cost + use.candidate.cost,
          partial_hops + use.candidate.hops.size());
      for (const auto& key : use.capacity_keys) {
        used_[key] = used_[key] - 1;
        if (used_[key] == 0) used_.erase(key);
      }
      if (!exhausted_) {
        choices_[position] = kSkipped;
        return;
      }
    }

    if (remaining_ == 0) {
      exhausted_ = false;
      return;
    }
    remaining_ -= 1;
    nodes_ += 1;
    choices_[position] = kSkipped;
    dfs(position + 1, partial_skipped + 1, partial_cost, partial_hops);
  }

  std::vector<const DemandOptions*> evaluations_;
  std::vector<std::size_t> positions_;
  std::map<SwitchKey, std::uint32_t> capacity_;
  std::map<SwitchKey, std::uint32_t> used_;
  std::uint64_t& remaining_;
  std::uint64_t nodes_ = 0;
  bool exhausted_ = true;
  bool have_best_ = false;
  std::vector<std::size_t> choices_;
  Assignment best_;
};

class DisjointSet {
 public:
  explicit DisjointSet(std::size_t size) : parent_(size) {
    for (std::size_t index = 0; index < size; ++index) parent_[index] = index;
  }
  std::size_t find(std::size_t value) {
    while (parent_[value] != value) {
      parent_[value] = parent_[parent_[value]];
      value = parent_[value];
    }
    return value;
  }
  void unite(std::size_t a, std::size_t b) {
    const std::size_t root_a = find(a);
    const std::size_t root_b = find(b);
    if (root_a == root_b) return;
    if (root_a < root_b) {
      parent_[root_b] = root_a;
    } else {
      parent_[root_a] = root_b;
    }
  }

 private:
  std::vector<std::size_t> parent_;
};

}  // namespace

std::uint32_t capacity_of(const PlanInputs& inputs, const SwitchKey& key) {
  const SwitchDescriptor* descriptor = inputs.topology->find_switch(key);
  return descriptor != nullptr ? descriptor->capacity_score : 0;
}

std::vector<CandidateEligibility> evaluate_candidates_internal(const DependentRef& dependent,
                                                               const SwitchKey& failed,
                                                               const PlanInputs& inputs) {
  Demand demand;
  demand.dependent = dependent;
  demand.failed = failed;
  DemandOptions evaluation = evaluate_demand(demand, inputs);
  return evaluation.reports;
}

DemandPlan build_demand_plan(const PlanInputs& inputs, const GenerationVector& failed) {
  DemandPlan plan;
  Limits limits = inputs.limits;
  if (!inputs.planning.allow_restore_when_closure_truncated) {
    // The closure bound is still reported exactly as it was; only the strength of the resulting
    // claim changes, which is handled in plan_internal.
  }
  plan.closure = inputs.topology->closure(failed, limits);
  // An empty closure is a complete answer: every root was present and nothing depends on it. Only
  // a bound that actually stopped the traversal makes the closure incomplete.
  const bool enumerated = plan.closure.complete() || plan.closure.state == ClosureState::Empty;
  plan.closure_complete = enumerated && plan.closure.enumerates_every_root();

  std::vector<DependencyClosure> per_root;
  per_root.reserve(failed.size());
  for (const auto& root : failed.keys()) {
    GenerationVector single;
    single.insert(root);
    DependencyClosure root_closure = inputs.topology->closure(single, limits);
    FenceStep step;
    step.failed = root;
    step.closure_digest = root_closure.digest();
    step.closure_state = root_closure.state;
    step.closure_members = root_closure.members.size();
    step.omitted_dependents = root_closure.omitted_frontier;
    plan.fences.push_back(std::move(step));
    per_root.push_back(std::move(root_closure));
  }

  // Attribute each discovered dependent to the failed generations it actually depends on.
  std::map<DependentRef, std::vector<SwitchKey>> attribution;
  for (std::size_t index = 0; index < per_root.size(); ++index) {
    const SwitchKey& root = failed.keys()[index];
    for (const auto& dependent : per_root[index].dependents) {
      attribution[dependent].push_back(root);
    }
  }

  for (auto& entry : attribution) {
    std::sort(entry.second.begin(), entry.second.end());
    entry.second.erase(std::unique(entry.second.begin(), entry.second.end()), entry.second.end());
    for (const auto& root : entry.second) {
      Demand demand;
      demand.dependent = entry.first;
      demand.failed = root;
      plan.demands.push_back(demand);
    }
  }
  std::sort(plan.demands.begin(), plan.demands.end());
  plan.demands.erase(std::unique(plan.demands.begin(), plan.demands.end()), plan.demands.end());

  plan.options.reserve(plan.demands.size());
  for (const auto& demand : plan.demands) {
    DemandOptions evaluation = evaluate_demand(demand, inputs);
    if (!evaluation.enumeration_complete) plan.enumeration_complete = false;
    plan.options.push_back(std::move(evaluation));
  }
  return plan;
}

Result<ReconstructionPlan> plan_internal(const PlanInputs& inputs,
                                         const GenerationVector& failed_generations,
                                         bool reference_mode, std::uint64_t* nodes_out) {
  Status status = inputs.validate();
  if (!status.ok()) return status;
  if (failed_generations.empty()) {
    return Status::failure(Code::Invalid, "planning requires at least one failed generation");
  }
  for (const auto& key : failed_generations.keys()) {
    if (!key.valid()) {
      return Status::failure(Code::Invalid, "failed generation set contains an invalid key");
    }
    const SwitchAssessment assessment = assess(inputs, key);
    if (!inputs.authority->is_fenced(key) && !assessment.fence_required) {
      return Status::failure(
          Code::Invalid,
          "planning was requested for a generation that is neither fenced nor failing: " +
              key.to_string());
    }
  }

  DemandPlan demand_plan = build_demand_plan(inputs, failed_generations);

  ReconstructionPlan plan;
  plan.id = inputs.plan_id;
  if (!plan.id.valid()) plan.id = PlanId(1);
  plan.epoch = inputs.epoch;
  plan.boot = inputs.boot;
  plan.failed_generations = failed_generations;
  plan.fences = demand_plan.fences;
  plan.closure_complete = demand_plan.closure_complete;
  plan.topology_digest = inputs.topology->digest();
  plan.policy_digest = inputs.policy_digest();

  std::vector<std::size_t> positions(demand_plan.options.size());
  for (std::size_t index = 0; index < positions.size(); ++index) positions[index] = index;

  std::vector<const DemandOptions*> evaluation_pointers;
  evaluation_pointers.reserve(demand_plan.options.size());
  for (const auto& option : demand_plan.options) evaluation_pointers.push_back(&option);

  std::map<SwitchKey, std::uint32_t> capacity;
  for (const auto& option : demand_plan.options) {
    for (const auto& use : option.eligible) {
      for (const auto& key : use.capacity_keys) {
        if (capacity.find(key) == capacity.end()) capacity[key] = capacity_of(inputs, key);
      }
    }
  }

  // Capacity fast path: when no switch can be oversubscribed by any assignment, the choice for
  // each demand is independent and the per-demand minimum is globally optimal.
  bool capacity_binding = false;
  {
    std::map<SwitchKey, std::size_t> potential;
    for (const auto& option : demand_plan.options) {
      std::vector<SwitchKey> touched;
      for (const auto& use : option.eligible) {
        for (const auto& key : use.capacity_keys) touched.push_back(key);
      }
      std::sort(touched.begin(), touched.end());
      touched.erase(std::unique(touched.begin(), touched.end()), touched.end());
      for (const auto& key : touched) potential[key] += 1;
    }
    for (const auto& entry : potential) {
      const auto limit = capacity.find(entry.first);
      if (limit == capacity.end() || entry.second > limit->second) {
        capacity_binding = true;
        break;
      }
    }
  }

  Assignment assignment;
  assignment.choice.assign(demand_plan.options.size(), kSkipped);
  bool optimality_proven = true;
  std::uint64_t search_nodes = 0;

  if (!capacity_binding && !reference_mode) {
    std::map<SwitchKey, std::uint32_t> used;
    for (std::size_t index = 0; index < demand_plan.options.size(); ++index) {
      const DemandOptions& option = demand_plan.options[index];
      if (option.eligible.empty()) {
        assignment.skipped += 1;
        continue;
      }
      const CandidateUse& use = option.eligible.front();
      for (const auto& key : use.capacity_keys) used[key] += 1;
      assignment.choice[index] = 0;
      const std::uint64_t added = use.candidate.cost;
      assignment.cost = assignment.cost > UINT64_MAX - added ? UINT64_MAX : assignment.cost + added;
      assignment.hops += use.candidate.hops.size();
    }
  } else {
    DisjointSet sets(demand_plan.options.size());
    std::map<SwitchKey, std::vector<std::size_t>> users;
    for (std::size_t index = 0; index < demand_plan.options.size(); ++index) {
      std::vector<SwitchKey> touched;
      for (const auto& use : demand_plan.options[index].eligible) {
        for (const auto& key : use.capacity_keys) touched.push_back(key);
      }
      std::sort(touched.begin(), touched.end());
      touched.erase(std::unique(touched.begin(), touched.end()), touched.end());
      for (const auto& key : touched) users[key].push_back(index);
    }
    for (const auto& entry : users) {
      for (std::size_t index = 1; index < entry.second.size(); ++index) {
        sets.unite(entry.second.front(), entry.second[index]);
      }
    }

    std::map<std::size_t, std::vector<std::size_t>> components;
    for (std::size_t index = 0; index < demand_plan.options.size(); ++index) {
      components[sets.find(index)].push_back(index);
    }

    // The search budget is shared across every component, so the total assignment-phase work is
    // bounded by one declared number no matter how the demands are distributed.
    std::uint64_t remaining_budget =
        static_cast<std::uint64_t>(inputs.limits.max_candidates_evaluated);
    for (const auto& entry : components) {
      std::vector<const DemandOptions*> evaluations;
      std::map<SwitchKey, std::uint32_t> component_capacity;
      for (const std::size_t index : entry.second) {
        evaluations.push_back(&demand_plan.options[index]);
        for (const auto& use : demand_plan.options[index].eligible) {
          for (const auto& key : use.capacity_keys) {
            component_capacity[key] = capacity_of(inputs, key);
          }
        }
      }
      ComponentSearch search(std::move(evaluations), entry.second, std::move(component_capacity),
                             remaining_budget);
      bool exhausted = true;
      Assignment component = search.run(exhausted);
      search_nodes += search.nodes_visited();
      if (!exhausted) optimality_proven = false;
      for (std::size_t position = 0; position < entry.second.size(); ++position) {
        const std::size_t index = entry.second[position];
        const std::size_t selected = component.choice[position];
        assignment.choice[index] = selected;
        if (selected == kSkipped) {
          assignment.skipped += 1;
          continue;
        }
        const CandidateUse& use = demand_plan.options[index].eligible[selected];
        const std::uint64_t added = use.candidate.cost;
        assignment.cost =
            assignment.cost > UINT64_MAX - added ? UINT64_MAX : assignment.cost + added;
        assignment.hops += use.candidate.hops.size();
      }
    }
  }

  for (std::size_t index = 0; index < demand_plan.options.size(); ++index) {
    const DemandOptions& option = demand_plan.options[index];
    const std::size_t selected = assignment.choice[index];
    if (selected == kSkipped) {
      UnresolvedDependent entry;
      entry.dependent = option.demand.dependent;
      entry.covers_failed = option.demand.failed;
      if (!option.eligible.empty() && optimality_proven) {
        entry.reason = UnresolvedReason::CapacityExhausted;
        entry.detail = "admissible alternatives exist but every assignment saturates them";
      } else if (!option.eligible.empty()) {
        entry.reason = UnresolvedReason::SearchLimitReached;
        entry.detail = "no admissible assignment was found within the declared planning bound";
      } else {
        entry.reason = option.blocking_reason;
        entry.detail = option.blocking_detail;
      }
      plan.unresolved.push_back(std::move(entry));
      continue;
    }
    const CandidateUse& use = option.eligible[selected];
    RestoreStep step;
    step.dependent = option.demand.dependent;
    step.covers_failed = option.demand.failed;
    step.action = PlanAction::RebindReplacement;
    step.hops = use.candidate.hops;
    step.links = use.candidate.links;
    step.replacement = use.candidate.hops.front();
    step.cost = use.candidate.cost;
    step.evidence = use.candidate.evidence;
    plan.restores.push_back(std::move(step));
  }

  std::sort(plan.restores.begin(), plan.restores.end(),
            [](const RestoreStep& a, const RestoreStep& b) {
              if (a.dependent != b.dependent) return a.dependent < b.dependent;
              if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
              return a.replacement < b.replacement;
            });
  std::sort(plan.unresolved.begin(), plan.unresolved.end(),
            [](const UnresolvedDependent& a, const UnresolvedDependent& b) {
              if (a.dependent != b.dependent) return a.dependent < b.dependent;
              return a.covers_failed < b.covers_failed;
            });

  // service_withheld is a policy statement, not a restatement of the unresolved list: it is true
  // only when the policy explicitly permits leaving dependents unrestored. With the default policy
  // an unresolved dependent is a refusal, and saying otherwise would overstate what was decided.
  plan.service_withheld =
      inputs.planning.allow_withhold_on_unresolved && !plan.unresolved.empty();

  const bool self_consistent = demand_plan.options.size() == plan.restores.size() + plan.unresolved.size();
  if (!self_consistent) {
    return Status::failure(Code::Invalid,
                           "plan accounting did not close: every demand must be restored or unresolved");
  }
  if (plan.unresolved.size() > inputs.limits.max_unresolved_dependents) {
    return refuse_exhausted("max_unresolved_dependents", plan.unresolved.size(),
                            inputs.limits.max_unresolved_dependents);
  }

  if (!plan.closure_complete || !demand_plan.enumeration_complete || !optimality_proven) {
    plan.feasibility = PlanFeasibility::SearchLimitReached;
  } else if (demand_plan.demands.empty()) {
    // The scope really is empty: every root was present and nothing depends on it. Claiming
    // feasibility would overstate a solution, and claiming infeasibility would overstate a failure.
    plan.feasibility = PlanFeasibility::NothingToRestore;
  } else if (plan.restores.empty()) {
    // Every dependent in scope carries a proven certificate that it cannot be restored.
    plan.feasibility = PlanFeasibility::ProvenInfeasible;
  } else {
    plan.feasibility = PlanFeasibility::ProvenFeasible;
  }
  plan.state = PlanState::Draft;
  plan.seal();
  if (nodes_out != nullptr) *nodes_out = search_nodes;
  return plan;
}

}  // namespace sff::detail
