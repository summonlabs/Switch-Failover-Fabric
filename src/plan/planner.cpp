// Switch Failover Fabric - deterministic reconstruction planning.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/plan/planner.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "plan/planner_internal.hpp"

namespace sff {

std::uint64_t PlanningPolicy::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.planning-policy.v1");
  digest.absorb_byte(allow_replacement_in_same_failure_domain ? 1 : 0);
  digest.absorb_byte(require_capability_superset ? 1 : 0);
  digest.absorb_byte(require_authoritative_candidate_evidence ? 1 : 0);
  digest.absorb_byte(allow_withhold_on_unresolved ? 1 : 0);
  digest.absorb_byte(allow_restore_when_closure_truncated ? 1 : 0);
  digest.absorb_u64(max_candidates_per_dependent);
  return digest.hi;
}

Status PlanInputs::validate() const {
  if (topology == nullptr) {
    return Status::failure(Code::Unsupported, "planning requires an installed topology");
  }
  if (candidates == nullptr) {
    return Status::failure(Code::Unsupported, "planning requires a supplied candidate table");
  }
  if (authority == nullptr) {
    return Status::failure(Code::Unsupported, "planning requires the authority registry");
  }
  if (!epoch.valid() || !boot.valid()) {
    return Status::failure(Code::Unauthorized, "planning requires a current epoch and boot incarnation");
  }
  return limits.validate();
}

std::uint64_t PlanInputs::policy_digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.plan-inputs-policy.v1");
  digest.absorb_u64(assessment.fence_on_authoritative_conflict ? 1 : 0);
  digest.absorb_u64(assessment.fence_on_missing_health ? 1 : 0);
  digest.absorb_u64(assessment.allow_same_generation_recovery ? 1 : 0);
  digest.absorb_u64(assessment.require_authoritative_failure_evidence ? 1 : 0);
  digest.absorb_u64(assessment.future_skew_tolerance_ns);
  digest.absorb_u64(planning.digest());
  digest.absorb_u64(candidates != nullptr ? candidates->digest() : 0);
  return digest.hi;
}

Result<CandidateTable> CandidateTable::build(std::vector<ReconstructionCandidate> candidates,
                                             const Limits& limits) {
  Status status = limits.validate();
  if (!status.ok()) return status;
  if (candidates.size() > limits.max_candidates_evaluated) {
    return refuse_exhausted("max_candidates_evaluated", candidates.size(),
                            limits.max_candidates_evaluated);
  }
  CandidateTable table;
  for (const auto& candidate : candidates) {
    status = candidate.validate();
    if (!status.ok()) return status;
  }
  // Canonical candidate order: cheapest first, then by hop count and hop set. Every field the
  // uniqueness predicate compares appears in this key, so entries the predicate calls equal sort
  // adjacent and std::unique can actually remove them; the evidence id is the final tie-break, so
  // the survivor of a duplicate group is the canonically smallest one. Sorting on a digest while
  // de-duplicating on the tuple would leave non-adjacent duplicates in the table.
  const auto identity_less = [](const ReconstructionCandidate& a,
                                const ReconstructionCandidate& b) {
    if (a.dependent != b.dependent) return a.dependent < b.dependent;
    if (a.cost != b.cost) return a.cost < b.cost;
    if (a.hops.size() != b.hops.size()) return a.hops.size() < b.hops.size();
    if (a.hops != b.hops) return a.hops < b.hops;
    if (a.links != b.links) return a.links < b.links;
    if (a.capabilities != b.capabilities) return a.capabilities < b.capabilities;
    if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
    return a.evidence < b.evidence;
  };
  std::sort(candidates.begin(), candidates.end(), identity_less);
  candidates.erase(std::unique(candidates.begin(), candidates.end(),
                               [](const ReconstructionCandidate& a,
                                  const ReconstructionCandidate& b) {
                                 return a.dependent == b.dependent &&
                                        a.covers_failed == b.covers_failed && a.hops == b.hops &&
                                        a.links == b.links && a.cost == b.cost &&
                                        a.capabilities == b.capabilities;
                               }),
                   candidates.end());
  Digest128 digest;
  digest.absorb_string("sff.candidate-table.v1");
  digest.absorb_u64(static_cast<std::uint64_t>(candidates.size()));
  for (const auto& candidate : candidates) digest.absorb_u64(candidate.digest());
  table.digest_ = digest.hi;
  table.candidates_ = std::move(candidates);
  return table;
}

std::vector<ReconstructionCandidate> CandidateTable::for_dependent(
    const DependentRef& dependent) const {
  std::vector<ReconstructionCandidate> result;
  const auto lower = std::lower_bound(
      candidates_.begin(), candidates_.end(), dependent,
      [](const ReconstructionCandidate& candidate, const DependentRef& probe) {
        return candidate.dependent < probe;
      });
  for (auto it = lower; it != candidates_.end() && it->dependent == dependent; ++it) {
    result.push_back(*it);
  }
  return result;
}

std::uint64_t CandidateEligibility::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.candidate-eligibility.v1");
  digest.absorb_dependent(dependent);
  digest.absorb_key(covers_failed);
  digest.absorb_u64(static_cast<std::uint64_t>(hops.size()));
  for (const auto& hop : hops) digest.absorb_key(hop);
  digest.absorb_u64(cost);
  digest.absorb_byte(eligible ? 1 : 0);
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  digest.absorb_byte(static_cast<std::uint8_t>(reason));
  digest.absorb_string(detail);
  return digest.hi;
}

std::vector<CandidateEligibility> evaluate_candidates(const DependentRef& dependent,
                                                      const SwitchKey& failed,
                                                      const PlanInputs& inputs) {
  return detail::evaluate_candidates_internal(dependent, failed, inputs);
}

Result<ReconstructionPlan> plan_reconstruction(const PlanInputs& inputs,
                                               const GenerationVector& failed_generations) {
  return detail::plan_internal(inputs, failed_generations, false, nullptr);
}

}  // namespace sff
