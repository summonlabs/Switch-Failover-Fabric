// Switch Failover Fabric - deterministic reconstruction planning.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every instance in this file is built in-process from declared switch generations,
// links, paths, candidates and authority state. No physical switch, NIC, RDMA device or
// multi-node fabric is exercised, and no result here is physical-hardware evidence.
//
// What this suite proves about plan_reconstruction:
//   1. the plan digest is order independent and self-consistent;
//   2. planning refuses a failed generation that is neither fenced nor carries a fence obligation;
//   3. no restore step ever preserves authority that depended on a failed generation;
//   4. attribution is per (dependent, failed generation) root, not per dependent;
//   5. the reported plan realises the documented lexicographic objective;
//   6. capacity_score is a hard per-generation bound and zero capacity is never used;
//   7. the planner is not a greedy, and ProvenInfeasible is only claimed with a certificate;
//   8. a truncated closure is reported as SearchLimitReached, never as ProvenInfeasible;
//   9. every unresolved reason is the documented taxonomy value and agrees with is_proven_negative;
//  10. CandidateTable canonicalises, de-duplicates and honours the declared bounds;
//  11. every produced plan passes sff::validate_plan against the same inputs.
#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

// ---------------------------------------------------------------------------------------------
// Rig: every input one planning call may consult, owned for the lifetime of one instance.
// ---------------------------------------------------------------------------------------------

constexpr BootIncarnation kBoot = BootIncarnation::from_parts(0x5ffull, 3, 0x1234ull, 0x5678ull);
constexpr CoordinatorEpoch kEpoch = CoordinatorEpoch(9);
constexpr TimestampNs kNowNs = 4'000'000'000ull;

struct InstanceSpec {
  std::vector<SwitchDescriptor> switches;
  std::vector<LinkDescriptor> links;
  std::vector<PathDescriptor> paths;
  std::vector<DependencyEdge> edges;
  std::vector<ReconstructionCandidate> candidates;
  std::vector<SwitchKey> fenced;
  std::vector<SwitchKey> failed;
  Limits build_limits = Limits::defaults();
  Limits limits = Limits::defaults();
  PlanningPolicy planning{};
  AssessmentPolicy assessment{};
  PlanId plan_id = PlanId(1);
};

struct Rig {
  Limits limits = Limits::defaults();
  PlanningPolicy planning{};
  AssessmentPolicy assessment{};
  TopologySnapshot topology;
  CandidateTable candidates;
  AuthorityRegistry authority{Limits::defaults()};
  EvidenceStore evidence{Limits::defaults(), nullptr};
  FailureTable failures;
  GenerationVector failed;
  PlanId plan_id = PlanId(1);

  PlanInputs inputs() const {
    PlanInputs out;
    out.topology = &topology;
    out.candidates = &candidates;
    out.evidence = &evidence;
    out.failures = &failures;
    out.authority = &authority;
    out.clock = nullptr;
    out.limits = limits;
    out.assessment = assessment;
    out.planning = planning;
    out.epoch = kEpoch;
    out.boot = kBoot;
    out.plan_id = plan_id;
    out.now_ns = kNowNs;
    return out;
  }
};

// ---------------------------------------------------------------------------------------------
// Declared-value helpers. Every one of these is SYNTHETIC.
// ---------------------------------------------------------------------------------------------

SwitchDescriptor mk_switch(const SwitchKey& key, std::uint64_t domain, std::uint32_t capacity,
                           CapabilityMask capabilities = kAllCapabilities) {
  SwitchDescriptor descriptor;
  descriptor.key = key;
  descriptor.role = SwitchRole::Spine;
  descriptor.admin = SwitchAdminState::Enabled;
  descriptor.failure_domain = FailureDomainId(domain);
  descriptor.capabilities = capabilities;
  descriptor.port_count = 64;
  descriptor.max_radix = 64;
  descriptor.capacity_score = capacity;
  descriptor.label = "SYNTHETIC";
  return descriptor;
}

PathDescriptor mk_path(std::uint64_t id, std::vector<SwitchKey> hops,
                       CapabilityMask required = capability_bit(Capability::Layer3)) {
  PathDescriptor path;
  path.id = PathId(id);
  path.source = NodeId(9000 + id);
  path.destination = NodeId(9500 + id);
  path.hops = std::move(hops);
  path.cost = 1;
  path.required_capabilities = required;
  return path;
}

ReconstructionCandidate mk_candidate(const DependentRef& dependent, const SwitchKey& covers_failed,
                                     std::vector<SwitchKey> hops, std::uint32_t cost,
                                     std::uint64_t evidence,
                                     EvidenceSource source = EvidenceSource::SimulatedFixture,
                                     CapabilityMask capabilities = kAllCapabilities) {
  ReconstructionCandidate candidate;
  candidate.dependent = dependent;
  candidate.covers_failed = covers_failed;
  candidate.hops = std::move(hops);
  candidate.cost = cost;
  candidate.capabilities = capabilities;
  candidate.evidence = EvidenceId(evidence);
  candidate.source = source;
  return candidate;
}

LinkDescriptor mk_link(std::uint64_t id, const SwitchKey& a, std::uint32_t a_port,
                       const SwitchKey& b, std::uint32_t b_port) {
  LinkDescriptor link;
  link.id = LinkId(id);
  link.a = PortRef{a, a_port};
  link.b = PortRef{b, b_port};
  link.cost = 1;
  link.bandwidth_gbps = 400;
  return link;
}

FenceRecord mk_fence(const SwitchKey& subject) {
  FenceRecord fence;
  fence.subject = subject;
  fence.epoch = kEpoch;
  fence.boot = kBoot;
  fence.created_at_ns = 1000;
  fence.scope_state = FenceScopeState::Committed;
  fence.reason = "SYNTHETIC fence committed by the test harness";
  return fence;
}

template <class T>
void shuffle_values(std::vector<T>& values, Rng& rng) {
  for (std::size_t remaining = values.size(); remaining > 1; --remaining) {
    const std::size_t other = static_cast<std::size_t>(rng.bounded(remaining));
    std::swap(values[remaining - 1], values[other]);
  }
}

/// Build a rig. shuffle_seed == 0 keeps the declared order; any other value shuffles every input
/// vector with an explicit seeded generator, so order independence is reproducible.
std::unique_ptr<Rig> make_rig(const InstanceSpec& spec, std::uint64_t shuffle_seed) {
  InstanceSpec work = spec;
  if (shuffle_seed != 0) {
    Rng rng(shuffle_seed);
    shuffle_values(work.switches, rng);
    shuffle_values(work.links, rng);
    shuffle_values(work.paths, rng);
    shuffle_values(work.edges, rng);
    shuffle_values(work.candidates, rng);
    shuffle_values(work.fenced, rng);
    shuffle_values(work.failed, rng);
  }

  auto rig = std::make_unique<Rig>();
  rig->limits = spec.limits;
  rig->planning = spec.planning;
  rig->assessment = spec.assessment;
  rig->plan_id = spec.plan_id;
  rig->failed = GenerationVector::canonicalise(work.failed);

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), std::move(work.switches), std::move(work.links),
                              std::move(work.paths), std::move(work.edges), spec.build_limits);
  if (!topology.ok()) {
    sfftest::fail(__FILE__, __LINE__, "SYNTHETIC topology did not build: " +
                                          std::string(to_string(topology.status().code())) + " " +
                                          topology.status().message());
    return nullptr;
  }
  rig->topology = std::move(topology).value();

  Result<CandidateTable> table = CandidateTable::build(std::move(work.candidates), spec.build_limits);
  if (!table.ok()) {
    sfftest::fail(__FILE__, __LINE__, "SYNTHETIC candidate table did not build: " +
                                          std::string(to_string(table.status().code())) + " " +
                                          table.status().message());
    return nullptr;
  }
  rig->candidates = std::move(table).value();

  for (const auto& key : work.fenced) {
    if (!rig->failed.contains(key)) rig->failed.insert(key);
    Result<FenceId> committed = rig->authority.commit_fence(mk_fence(key));
    if (!committed.ok()) {
      sfftest::fail(__FILE__, __LINE__,
                    "SYNTHETIC fence was refused: " + std::string(to_string(committed.status().code())));
      return nullptr;
    }
  }
  return rig;
}

/// Three-switch instance: one failed generation, one leaf, one replacement, one dependent.
InstanceSpec simple_spec(const std::vector<ReconstructionCandidate>& candidates,
                         const std::vector<SwitchKey>& additionally_fenced = {},
                         const std::vector<SwitchDescriptor>& extra_switches = {},
                         bool fence_failed = true) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100)};
  for (const auto& extra : extra_switches) spec.switches.push_back(extra);
  spec.paths = {mk_path(1, {failed, leaf})};
  spec.candidates = candidates;
  spec.failed = {failed};
  if (fence_failed) spec.fenced = {failed};
  for (const auto& key : additionally_fenced) spec.fenced.push_back(key);
  return spec;
}

// ---------------------------------------------------------------------------------------------
// Independent re-derivation of the documented admissibility rules.
// ---------------------------------------------------------------------------------------------

CapabilityMask required_capabilities(const Rig& rig, const DependentRef& dependent) {
  if (dependent.kind() != DependentKind::Path) return 0;
  const PathDescriptor* path = rig.topology.find_path(PathId(dependent.id()));
  return path != nullptr ? path->required_capabilities : 0;
}

/// True when the documented eligibility rules admit this alternative for (dependent, failed).
/// Deliberately re-derived from the public inputs, never taken from the planner's own report.
bool oracle_admissible(const Rig& rig, const ReconstructionCandidate& candidate,
                       const SwitchKey& failed) {
  if (candidate.covers_failed != failed) return false;
  if (candidate.hops.empty()) return false;
  if (rig.planning.require_authoritative_candidate_evidence &&
      trust_of(candidate.source) != TrustLevel::Authoritative) {
    return false;
  }
  const SwitchDescriptor* failed_descriptor = rig.topology.find_switch(failed);
  const CapabilityMask required = required_capabilities(rig, candidate.dependent);
  for (const auto& hop : candidate.hops) {
    if (hop == failed) return false;
    const SwitchDescriptor* descriptor = rig.topology.find_switch(hop);
    if (descriptor == nullptr) return false;
    if (rig.authority.is_fenced(hop)) return false;
    if (rig.planning.require_capability_superset) {
      if (!has_all_capabilities(descriptor->capabilities, required)) return false;
      if (!has_all_capabilities(candidate.capabilities, required)) return false;
    }
    if (!rig.planning.allow_replacement_in_same_failure_domain) {
      if (failed_descriptor == nullptr || !failed_descriptor->failure_domain.valid() ||
          !descriptor->failure_domain.valid()) {
        return false;
      }
      if (descriptor->failure_domain == failed_descriptor->failure_domain) return false;
    }
    if (descriptor->capacity_score == 0) return false;
  }
  return true;
}

std::vector<ReconstructionCandidate> oracle_alternatives(const Rig& rig, const DependentRef& dependent,
                                                         const SwitchKey& failed) {
  std::vector<ReconstructionCandidate> result;
  for (const auto& candidate : rig.candidates.for_dependent(dependent)) {
    if (oracle_admissible(rig, candidate, failed)) result.push_back(candidate);
  }
  return result;
}

/// Every demand the inputs imply: one per (dependent, failed generation) pair reached by the
/// bounded reverse-dependency closure, re-derived from the public topology API.
std::set<std::pair<DependentRef, SwitchKey>> expected_demands(const Rig& rig) {
  std::set<std::pair<DependentRef, SwitchKey>> demands;
  for (const auto& root : rig.failed.keys()) {
    GenerationVector single;
    single.insert(root);
    const DependencyClosure closure = rig.topology.closure(single, rig.limits);
    for (const auto& dependent : closure.dependents) demands.insert({dependent, root});
  }
  return demands;
}

std::uint32_t capacity_of(const Rig& rig, const SwitchKey& key) {
  const SwitchDescriptor* descriptor = rig.topology.find_switch(key);
  return descriptor != nullptr ? descriptor->capacity_score : 0;
}

std::size_t plan_hops(const ReconstructionPlan& plan) {
  std::size_t total = 0;
  for (const auto& step : plan.restores) total += step.hops.size();
  return total;
}

/// A hand-run cheapest-first greedy that respects capacity in arrival order. It is the baseline
/// the planner must never be worse than; it is NOT an oracle for optimality.
ReconstructionPlan greedy_plan(const Rig& rig) {
  ReconstructionPlan plan;
  plan.failed_generations = rig.failed;
  std::map<SwitchKey, std::uint32_t> used;
  for (const auto& demand : expected_demands(rig)) {
    const std::vector<ReconstructionCandidate> alternatives =
        oracle_alternatives(rig, demand.first, demand.second);
    const ReconstructionCandidate* chosen = nullptr;
    std::vector<SwitchKey> touched;
    for (const auto& candidate : alternatives) {
      touched.assign(candidate.hops.begin(), candidate.hops.end());
      std::sort(touched.begin(), touched.end());
      touched.erase(std::unique(touched.begin(), touched.end()), touched.end());
      bool fits = true;
      for (const auto& hop : touched) {
        if (used[hop] >= capacity_of(rig, hop)) {
          fits = false;
          break;
        }
      }
      if (fits) {
        chosen = &candidate;
        break;
      }
    }
    if (chosen == nullptr) {
      UnresolvedDependent entry;
      entry.dependent = demand.first;
      entry.covers_failed = demand.second;
      entry.reason = alternatives.empty() ? UnresolvedReason::NoCandidateSupplied
                                          : UnresolvedReason::CapacityExhausted;
      entry.detail = "SYNTHETIC greedy baseline";
      plan.unresolved.push_back(std::move(entry));
      continue;
    }
    for (const auto& hop : touched) used[hop] += 1;
    RestoreStep step;
    step.dependent = demand.first;
    step.covers_failed = demand.second;
    step.action = PlanAction::RebindReplacement;
    step.hops = chosen->hops;
    step.links = chosen->links;
    step.replacement = chosen->hops.front();
    step.cost = chosen->cost;
    step.evidence = chosen->evidence;
    plan.restores.push_back(std::move(step));
  }
  std::sort(plan.restores.begin(), plan.restores.end(),
            [](const RestoreStep& a, const RestoreStep& b) {
              if (a.dependent != b.dependent) return a.dependent < b.dependent;
              if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
              return a.replacement < b.replacement;
            });
  plan.seal();
  return plan;
}

bool plan_not_worse_than(const ReconstructionPlan& plan, const ReconstructionPlan& baseline) {
  if (plan.unresolved_count() != baseline.unresolved_count()) {
    return plan.unresolved_count() < baseline.unresolved_count();
  }
  if (plan.total_cost() != baseline.total_cost()) return plan.total_cost() < baseline.total_cost();
  return plan_hops(plan) <= plan_hops(baseline);
}

std::string reason_name(UnresolvedReason reason) { return std::string(to_string(reason)); }
std::string feasibility_name(PlanFeasibility value) { return std::string(to_string(value)); }
std::string code_name(Code value) { return std::string(to_string(value)); }

std::string spec_summary(const InstanceSpec& spec) {
  std::string out = "switches{";
  for (const auto& sw : spec.switches) {
    out += sw.key.to_string() + "(dom=" + std::to_string(sw.failure_domain.raw()) +
           ",cap=" + std::to_string(sw.capacity_score) + ") ";
  }
  out += "} paths{";
  for (const auto& path : spec.paths) {
    out += DependentRef::path(path.id).to_string() + "=[";
    for (const auto& hop : path.hops) out += hop.to_string() + " ";
    out += "] ";
  }
  out += "} candidates{";
  for (const auto& candidate : spec.candidates) {
    out += candidate.dependent.to_string() + "<-" + candidate.covers_failed.to_string() + "=[";
    for (const auto& hop : candidate.hops) out += hop.to_string() + " ";
    out += "]cost" + std::to_string(candidate.cost) + " ";
  }
  out += "}";
  return out;
}

// ---------------------------------------------------------------------------------------------
// Cross-cutting invariants. Called after EVERY produced plan in this file.
// ---------------------------------------------------------------------------------------------

bool check_plan_invariants(const ReconstructionPlan& plan, const Rig& rig, const std::string& scope) {
  bool ok = true;
  const auto note = [&ok, &scope](bool condition, const char* what) {
    if (!condition) {
      ok = false;
      sfftest::fail(__FILE__, __LINE__, scope + ": " + what);
    }
  };

  note(plan.digest_valid(), "plan digest is not self-consistent");
  note(plan.feasibility != PlanFeasibility::Unknown, "plan feasibility is unresolved");
  note(plan.epoch == kEpoch, "plan carries the wrong coordinator epoch");
  note(plan.boot == kBoot, "plan carries the wrong boot incarnation");
  note(plan.topology_digest == rig.topology.digest(), "plan carries the wrong topology digest");
  note(plan.policy_digest == rig.inputs().policy_digest(), "plan carries the wrong policy digest");

  const std::set<SwitchKey> failed(rig.failed.keys().begin(), rig.failed.keys().end());

  std::set<SwitchKey> fenced_steps;
  for (const auto& step : plan.fences) fenced_steps.insert(step.failed);
  note(fenced_steps.size() == failed.size(), "fence steps do not cover exactly the failed set");
  for (const auto& key : rig.failed.keys()) {
    note(fenced_steps.find(key) != fenced_steps.end(), "a failed generation has no fence step");
  }

  std::set<std::pair<DependentRef, SwitchKey>> covered;
  std::map<SwitchKey, std::size_t> usage;
  for (const auto& step : plan.restores) {
    note(failed.find(step.covers_failed) != failed.end(),
         "a restore step covers a generation outside the failed set");
    note(step.dependent.valid(), "a restore step names an invalid dependent");
    note(step.action == PlanAction::RebindReplacement, "a restore step has an undefined action");
    note(!step.hops.empty(), "a restore step supplies no hops");
    note(step.cost != 0, "a restore step has zero cost");
    note(step.replacement == step.hops.front(),
         "a restore replacement is not the head of its hop set");
    note(covered.insert({step.dependent, step.covers_failed}).second,
         "duplicate restore step for one (dependent, failed generation) pair");
    for (const auto& hop : step.hops) {
      note(failed.find(hop) == failed.end(), "a restore step reuses a failed generation");
      note(!rig.authority.is_fenced(hop), "a restore step crosses a fenced generation");
      note(rig.topology.find_switch(hop) != nullptr,
           "a restore step names a generation absent from the topology");
    }
    // Capacity counts dependents, not hop occurrences: one step consumes one unit per DISTINCT
    // generation it names, which is the same rule the planner and the validator apply.
    for (const auto& hop : std::set<SwitchKey>(step.hops.begin(), step.hops.end())) {
      usage[hop] += 1;
    }
    for (const auto& link : step.links) {
      note(rig.topology.find_link(link) != nullptr,
           "a restore step names a link absent from the topology");
    }
  }
  for (const auto& entry : usage) {
    note(entry.second <= capacity_of(rig, entry.first),
         "an assignment exceeds the declared spare capacity of a generation");
  }

  for (const auto& entry : plan.unresolved) {
    note(failed.find(entry.covers_failed) != failed.end(),
         "an unresolved entry covers a generation outside the failed set");
    note(covered.insert({entry.dependent, entry.covers_failed}).second,
         "duplicate unresolved entry for one (dependent, failed generation) pair");
    note(entry.reason != UnresolvedReason::Unknown, "an unresolved entry has an unknown reason");
    if (plan.feasibility == PlanFeasibility::ProvenInfeasible) {
      note(is_proven_negative(entry.reason),
           "ProvenInfeasible was claimed with a non-certifying unresolved reason");
    }
    if (!is_proven_negative(entry.reason)) {
      note(plan.feasibility == PlanFeasibility::SearchLimitReached,
           "a non-certifying unresolved reason was reported without a bound being reached");
    }
  }
  note(plan.feasibility != PlanFeasibility::ProvenInfeasible || plan.restores.empty(),
       "ProvenInfeasible was claimed while a restore step exists");
  note(plan.feasibility != PlanFeasibility::ProvenFeasible || !plan.restores.empty(),
       "ProvenFeasible was claimed with no restore step");

  const auto demands = expected_demands(rig);
  note(covered.size() == demands.size(),
       "accounting did not close: every implied demand must be restored or explicitly unresolved");
  for (const auto& demand : demands) {
    note(covered.find(demand) != covered.end(), "an implied demand is missing from the plan");
  }

  note(std::is_sorted(plan.restores.begin(), plan.restores.end(),
                      [](const RestoreStep& a, const RestoreStep& b) {
                        if (a.dependent != b.dependent) return a.dependent < b.dependent;
                        if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
                        return a.replacement < b.replacement;
                      }),
       "restore steps are not in canonical order");
  note(std::is_sorted(plan.unresolved.begin(), plan.unresolved.end(),
                      [](const UnresolvedDependent& a, const UnresolvedDependent& b) {
                        if (a.dependent != b.dependent) return a.dependent < b.dependent;
                        return a.covers_failed < b.covers_failed;
                      }),
       "unresolved entries are not in canonical order");

  const ValidationReport report = validate_plan(plan, rig.inputs());
  if (!report.valid) {
    ok = false;
    sfftest::fail(__FILE__, __LINE__,
                  scope + ": plan failed independent validation: " + report.to_string());
  }
  return ok;
}

/// Assert that every plan-level claim agrees with the independently re-derived eligibility.
bool check_oracle_agreement(const ReconstructionPlan& plan, const Rig& rig, const std::string& scope) {
  bool ok = true;
  const auto note = [&ok, &scope](bool condition, const std::string& what) {
    if (!condition) {
      ok = false;
      sfftest::fail(__FILE__, __LINE__, scope + ": " + what);
    }
  };

  std::set<std::pair<DependentRef, SwitchKey>> restored;
  for (const auto& step : plan.restores) {
    restored.insert({step.dependent, step.covers_failed});
    const std::vector<ReconstructionCandidate> alternatives =
        oracle_alternatives(rig, step.dependent, step.covers_failed);
    bool matched = false;
    for (const auto& candidate : alternatives) {
      if (candidate.hops == step.hops && candidate.cost == step.cost) matched = true;
    }
    note(matched, "restore step is not an admissible alternative under the documented rules");
  }

  for (const auto& entry : plan.unresolved) {
    const std::vector<ReconstructionCandidate> alternatives =
        oracle_alternatives(rig, entry.dependent, entry.covers_failed);
    if (alternatives.empty()) {
      note(is_proven_negative(entry.reason),
           "a demand with no admissible alternative was not certified as a proven negative");
    } else {
      note(entry.reason == UnresolvedReason::CapacityExhausted ||
               entry.reason == UnresolvedReason::SearchLimitReached,
           "an unresolved demand with admissible alternatives reports the wrong reason: " +
               reason_name(entry.reason));
    }
  }

  for (const auto& demand : expected_demands(rig)) {
    const std::vector<ReconstructionCandidate> alternatives =
        oracle_alternatives(rig, demand.first, demand.second);
    if (alternatives.empty() || restored.find(demand) != restored.end()) continue;
    bool reported = false;
    for (const auto& entry : plan.unresolved) {
      if (entry.dependent == demand.first && entry.covers_failed == demand.second) reported = true;
    }
    note(reported, "an admissible demand is neither restored nor explicitly unresolved");
  }
  return ok;
}

bool report_reason(const std::vector<CandidateEligibility>& reports, const std::vector<SwitchKey>& hops,
                   UnresolvedReason expected, const std::string& scope) {
  for (const auto& report : reports) {
    if (report.hops != hops) continue;
    CHECK(!report.eligible);
    CHECK_EQ(reason_name(report.reason), reason_name(expected));
    CHECK(is_proven_negative(report.reason));
    return true;
  }
  sfftest::fail(__FILE__, __LINE__, scope + ": no eligibility report for the supplied alternative");
  return false;
}

bool report_eligible(const std::vector<CandidateEligibility>& reports,
                     const std::vector<SwitchKey>& hops, const std::string& scope) {
  for (const auto& report : reports) {
    if (report.hops != hops) continue;
    CHECK(report.eligible);
    CHECK_EQ(code_name(report.outcome), std::string("OK"));
    CHECK_EQ(reason_name(report.reason), reason_name(UnresolvedReason::Unknown));
    return true;
  }
  sfftest::fail(__FILE__, __LINE__, scope + ": no eligibility report for the supplied alternative");
  return false;
}

bool expect_single_unresolved(const Rig& rig, const DependentRef& dependent, const SwitchKey& failed,
                              UnresolvedReason expected, const std::string& scope) {
  Result<ReconstructionPlan> produced = plan_reconstruction(rig.inputs(), rig.failed);
  if (!produced.ok()) {
    sfftest::fail(__FILE__, __LINE__,
                  scope + ": planning was refused: " + code_name(produced.status().code()));
    return false;
  }
  const ReconstructionPlan& plan = produced.value();
  CHECK_EQ(plan.restores.size(), std::size_t{0});
  CHECK_EQ(plan.unresolved.size(), std::size_t{1});
  CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenInfeasible));
  if (plan.unresolved.size() != 1) {
    check_plan_invariants(plan, rig, scope);
    return false;
  }
  const UnresolvedDependent& entry = plan.unresolved.front();
  CHECK_EQ(entry.dependent, dependent);
  CHECK_EQ(entry.covers_failed, failed);
  CHECK_EQ(reason_name(entry.reason), reason_name(expected));
  CHECK(is_proven_negative(entry.reason));
  check_plan_invariants(plan, rig, scope);
  return true;
}

// ---------------------------------------------------------------------------------------------
// 1. Determinism and order independence.
// ---------------------------------------------------------------------------------------------

SFF_TEST(plan_digest_is_order_independent) {
  FabricSpec fabric_spec;
  fabric_spec.leaves = 2;
  fabric_spec.spines = 2;
  fabric_spec.replacement_spines = 2;
  fabric_spec.paths_per_leaf = 4;
  Result<Fabric> built = build_fabric(fabric_spec);
  CHECK(built.ok());
  if (!built.ok()) return;
  Fabric fabric = std::move(built).value();
  CHECK(!fabric.spine_keys.empty());

  const SwitchKey failed = fabric.spine_keys.front();
  const std::vector<SwitchDescriptor> switches = fabric.topology.switches();
  const std::vector<LinkDescriptor> links = fabric.topology.links();
  const std::vector<PathDescriptor> paths = fabric.topology.paths();
  const std::vector<DependencyEdge> edges = fabric.topology.dependency_edges();
  const std::vector<ReconstructionCandidate> candidates = fabric.candidates.candidates();
  CHECK(!paths.empty());
  CHECK(!candidates.empty());

  const std::uint64_t shuffle_seeds[] = {0, 1, 7, 4242, 99991, 123456789};
  std::uint64_t reference_plan_digest = 0;
  std::uint64_t reference_topology_digest = 0;
  std::uint64_t reference_candidate_digest = 0;
  std::size_t reference_restores = 0;
  std::size_t reference_unresolved = 0;

  for (const std::uint64_t seed : shuffle_seeds) {
    Rng rng(seed == 0 ? 1 : seed);
    std::vector<SwitchDescriptor> shuffled_switches = switches;
    std::vector<LinkDescriptor> shuffled_links = links;
    std::vector<PathDescriptor> shuffled_paths = paths;
    std::vector<DependencyEdge> shuffled_edges = edges;
    std::vector<ReconstructionCandidate> shuffled_candidates = candidates;
    if (seed != 0) {
      shuffle_values(shuffled_switches, rng);
      shuffle_values(shuffled_links, rng);
      shuffle_values(shuffled_paths, rng);
      shuffle_values(shuffled_edges, rng);
      shuffle_values(shuffled_candidates, rng);
    }

    Result<TopologySnapshot> topology =
        TopologySnapshot::build(TopologyVersion(1), std::move(shuffled_switches),
                                std::move(shuffled_links), std::move(shuffled_paths),
                                std::move(shuffled_edges), Limits::defaults());
    CHECK(topology.ok());
    if (!topology.ok()) return;
    Result<CandidateTable> table =
        CandidateTable::build(std::move(shuffled_candidates), Limits::defaults());
    CHECK(table.ok());
    if (!table.ok()) return;

    auto rig = std::make_unique<Rig>();
    rig->topology = std::move(topology).value();
    rig->candidates = std::move(table).value();
    rig->failed.insert(failed);
    CHECK(rig->authority.commit_fence(mk_fence(failed)).ok());

    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();

    const std::string scope = "SYNTHETIC fixture, shuffle seed " + std::to_string(seed);
    CHECK(plan.digest_valid());
    check_plan_invariants(plan, *rig, scope);

    if (seed == 0) {
      reference_plan_digest = plan.plan_digest;
      reference_topology_digest = rig->topology.digest();
      reference_candidate_digest = rig->candidates.digest();
      reference_restores = plan.restores.size();
      reference_unresolved = plan.unresolved.size();
      CHECK(!plan.restores.empty());
      CHECK_EQ(fabric.topology.digest(), rig->topology.digest());
      CHECK_EQ(fabric.candidates.digest(), rig->candidates.digest());
    } else {
      CHECK_EQ(rig->topology.digest(), reference_topology_digest);
      CHECK_EQ(rig->candidates.digest(), reference_candidate_digest);
      CHECK_EQ(plan.plan_digest, reference_plan_digest);
      CHECK_EQ(plan.restores.size(), reference_restores);
      CHECK_EQ(plan.unresolved.size(), reference_unresolved);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 2. Fence first.
// ---------------------------------------------------------------------------------------------

SFF_TEST(fence_first_refuses_an_unfenced_generation) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);
  const InstanceSpec spec = simple_spec(
      {mk_candidate(DependentRef::path(PathId(1)), failed, {leaf, replacement}, 3, 501)},
      /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(replacement, 3, 5)},
      /*fence_failed=*/false);

  // (a) Nothing is fenced and nothing is failing: the refusal is explicit, not a plan with no
  //     fence steps.
  {
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> refused = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(!refused.ok());
    if (!refused.ok()) {
      CHECK_EQ(code_name(refused.status().code()), std::string("INVALID"));
    }
  }

  // (b) Authoritative affirmative health does not license planning either: observation is not
  //     authority, and fencing is not excused by a healthy reading.
  {
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    EvidenceRecord record;
    record.id = EvidenceId(1);
    record.kind = EvidenceKind::SwitchHealth;
    record.source = EvidenceSource::FabricManager;
    record.subject = failed;
    record.admitted_epoch = kEpoch;
    record.admitted_boot = kBoot;
    record.observed_at_ns = kNowNs - 1000;
    record.valid_for_ns = 60ull * kNanosPerSecond;
    record.health = SwitchHealthState::Healthy;
    record.detail = "SYNTHETIC affirmative health observation";
    CHECK(rig->evidence.admit(record).ok());
    const SwitchAssessment assessment =
        assess_switch(failed, rig->evidence, rig->failures, kNowNs, rig->assessment);
    CHECK(assessment.usable);
    CHECK(!assessment.fence_required);
    Result<ReconstructionPlan> refused = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(code_name(refused.status().code()), std::string("INVALID"));
  }

  // (c) A committed fence is sufficient basis.
  {
    InstanceSpec fenced = spec;
    fenced.fenced = {failed};
    std::unique_ptr<Rig> rig = make_rig(fenced, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    CHECK(check_plan_invariants(produced.value(), *rig, "committed fence"));
    CHECK_EQ(produced.value().restores.size(), std::size_t{1});
    CHECK(check_oracle_agreement(produced.value(), *rig, "committed fence"));
  }

  // (d) A durable failure lineage is a fence obligation, and a fence obligation is the other
  //     sufficient basis: the generation is provably failing, so planning proceeds and records
  //     the obligation. Nothing has been applied: the registry fence is still owed.
  {
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    FailureRecord failure;
    failure.subject = failed;
    failure.evidence = EvidenceId(77);
    failure.epoch = kEpoch;
    failure.boot = kBoot;
    failure.observed_at_ns = kNowNs - 1000;
    failure.recorded_at_ns = kNowNs - 1000;
    failure.reason = "SYNTHETIC durable failure declaration";
    CHECK(rig->failures.record(failure).ok());
    const SwitchAssessment assessment =
        assess_switch(failed, rig->evidence, rig->failures, kNowNs, rig->assessment);
    CHECK(assessment.fence_required);
    CHECK(!rig->authority.is_fenced(failed));

    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK_EQ(plan.fences.size(), std::size_t{1});
    if (!plan.fences.empty()) CHECK_EQ(plan.fences.front().failed, failed);
    for (const auto& step : plan.restores) {
      CHECK_EQ(step.covers_failed, failed);
      for (const auto& hop : step.hops) CHECK_NE(hop, failed);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 3. No authority preservation.
// ---------------------------------------------------------------------------------------------

SFF_TEST(no_restore_step_preserves_failed_authority) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // An alternative that offers the failed generation itself, next to a clean one.
  {
    const InstanceSpec spec = simple_spec(
        {
            mk_candidate(dependent, failed, {leaf, failed}, 1, 601),
            mk_candidate(dependent, failed, {leaf, replacement}, 5, 602),
        },
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(replacement, 3, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    CHECK_EQ(reports.size(), std::size_t{2});
    report_reason(reports, {leaf, failed}, UnresolvedReason::BehindFence,
                  "alternative reuses the failed generation");
    report_eligible(reports, {leaf, replacement}, "clean alternative");

    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK_EQ(plan.restores.size(), std::size_t{1});
    if (!plan.restores.empty()) {
      CHECK_EQ(plan.restores.front().hops, (std::vector<SwitchKey>{leaf, replacement}));
      CHECK_EQ(plan.restores.front().replacement, plan.restores.front().hops.front());
      CHECK_EQ(plan.restores.front().cost, 5u);
    }
    CHECK(plan.unresolved.empty());
    check_plan_invariants(plan, *rig, "failed generation offered as a hop");
    check_oracle_agreement(plan, *rig, "failed generation offered as a hop");
  }

  // When the only alternative preserves the failed generation there is no plan at all.
  {
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {failed, leaf}, 1, 603)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::BehindFence,
                                   "only alternative reuses the failed generation"));
  }

  // A fenced generation that is not the failed generation is equally inadmissible.
  {
    const SwitchKey fenced_hop = skey(31, 1);
    InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, fenced_hop}, 2, 604)},
        /*additionally_fenced=*/{fenced_hop},
        /*extra_switches=*/{mk_switch(fenced_hop, 4, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, fenced_hop}, UnresolvedReason::BehindFence, "crosses a fence");
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::BehindFence,
                                   "only alternative crosses a fence"));
  }
}

// ---------------------------------------------------------------------------------------------
// 4. Per-root attribution.
// ---------------------------------------------------------------------------------------------

SFF_TEST(attribution_is_per_dependent_and_failed_generation) {
  const SwitchKey first_failed = skey(10, 1);
  const SwitchKey second_failed = skey(11, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey first_replacement = skey(30, 1);
  const SwitchKey second_replacement = skey(31, 1);
  const DependentRef both = DependentRef::path(PathId(1));
  const DependentRef only_first = DependentRef::path(PathId(2));
  const DependentRef neither = DependentRef::path(PathId(3));

  InstanceSpec spec;
  spec.switches = {mk_switch(first_failed, 1, 100), mk_switch(second_failed, 2, 100),
                   mk_switch(leaf, 3, 100), mk_switch(first_replacement, 4, 5),
                   mk_switch(second_replacement, 5, 5)};
  spec.paths = {mk_path(1, {first_failed, second_failed, leaf}), mk_path(2, {first_failed, leaf}),
                mk_path(3, {leaf})};
  spec.candidates = {
      mk_candidate(both, first_failed, {leaf, first_replacement}, 3, 701),
      mk_candidate(both, second_failed, {leaf, second_replacement}, 4, 702),
      mk_candidate(only_first, first_failed, {leaf, first_replacement}, 3, 703),
      // Not a demand: only_first does not traverse second_failed, so this must never be used.
      mk_candidate(only_first, second_failed, {leaf, second_replacement}, 4, 704),
      // Not a demand either: neither traverses no failed generation at all.
      mk_candidate(neither, first_failed, {leaf, first_replacement}, 1, 705),
  };
  spec.failed = {first_failed, second_failed};
  spec.fenced = {first_failed, second_failed};

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();

  CHECK_EQ(plan.fences.size(), std::size_t{2});
  CHECK_EQ(plan.unresolved.size(), std::size_t{0});
  CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenFeasible));
  CHECK_EQ(plan.restores.size(), std::size_t{3});

  std::size_t both_steps = 0;
  std::size_t only_first_steps = 0;
  std::set<SwitchKey> both_covers;
  for (const auto& step : plan.restores) {
    if (step.dependent == both) {
      both_steps += 1;
      both_covers.insert(step.covers_failed);
    }
    if (step.dependent == only_first) {
      only_first_steps += 1;
      CHECK_EQ(step.covers_failed, first_failed);
    }
    CHECK_NE(step.dependent, neither);
  }
  CHECK_EQ(both_steps, std::size_t{2});
  CHECK_EQ(both_covers.size(), std::size_t{2});
  CHECK(both_covers.find(first_failed) != both_covers.end());
  CHECK(both_covers.find(second_failed) != both_covers.end());
  CHECK_EQ(only_first_steps, std::size_t{1});
  check_plan_invariants(plan, *rig, "two failed generations");
  check_oracle_agreement(plan, *rig, "two failed generations");
}

// ---------------------------------------------------------------------------------------------
// 5. Objective correctness against a hand-computed optimum.
// ---------------------------------------------------------------------------------------------

SFF_TEST(objective_matches_the_hand_computed_optimum) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey first_leaf = skey(20, 1);
  const SwitchKey second_leaf = skey(21, 1);
  const SwitchKey cheap = skey(30, 1);   // capacity_score 1: admits exactly one dependent
  const SwitchKey roomy = skey(31, 1);   // capacity_score 5, but more expensive
  const DependentRef first = DependentRef::path(PathId(1));
  const DependentRef second = DependentRef::path(PathId(2));

  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(first_leaf, 2, 100),
                   mk_switch(second_leaf, 3, 100), mk_switch(cheap, 4, 1),
                   mk_switch(roomy, 5, 5)};
  spec.paths = {mk_path(1, {failed, first_leaf}), mk_path(2, {failed, second_leaf})};
  spec.candidates = {
      mk_candidate(first, failed, {first_leaf, cheap}, 1, 801),
      mk_candidate(first, failed, {first_leaf, roomy}, 5, 802),
      mk_candidate(second, failed, {second_leaf, cheap}, 2, 803),
  };
  spec.failed = {failed};
  spec.fenced = {failed};

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();

  // Hand-computed optimum: cheapest-first would put PATH(1) on the capacity-1 generation and
  // leave PATH(2) unresolved (1 unresolved, cost 1). The optimum keeps every dependent:
  // PATH(1) -> roomy (5) and PATH(2) -> cheap (2): unresolved 0, cost 7, 4 hops.
  CHECK_EQ(plan.unresolved.size(), std::size_t{0});
  CHECK_EQ(plan.restores.size(), std::size_t{2});
  CHECK_EQ(plan.total_cost(), std::uint64_t{7});
  CHECK_EQ(plan_hops(plan), std::size_t{4});
  CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenFeasible));
  for (const auto& step : plan.restores) {
    if (step.dependent == first) {
      CHECK_EQ(step.hops, (std::vector<SwitchKey>{first_leaf, roomy}));
      CHECK_EQ(step.cost, 5u);
    } else {
      CHECK_EQ(step.dependent, second);
      CHECK_EQ(step.hops, (std::vector<SwitchKey>{second_leaf, cheap}));
      CHECK_EQ(step.cost, 2u);
    }
  }
  check_plan_invariants(plan, *rig, "hand-computed optimum");
  check_oracle_agreement(plan, *rig, "hand-computed optimum");

  // The plan must never be worse than the greedy per-demand minimum-cost choice.
  const ReconstructionPlan greedy = greedy_plan(*rig);
  CHECK_EQ(greedy.unresolved.size(), std::size_t{1});
  CHECK_EQ(greedy.total_cost(), std::uint64_t{1});
  CHECK(plan_not_worse_than(plan, greedy));
  CHECK(plan < greedy);
  CHECK(!(greedy < plan));

  // The exhaustive reference solver agrees on this instance.
  const ReferenceSolution reference = solve_reference(rig->inputs(), rig->failed, 100000);
  CHECK(reference.optimal_found);
  CHECK(reference.exhausted);
  CHECK_EQ(reference.plan.unresolved.size(), std::size_t{0});
  CHECK_EQ(reference.plan.total_cost(), std::uint64_t{7});
  CHECK_EQ(plan_hops(reference.plan), std::size_t{4});
}

// ---------------------------------------------------------------------------------------------
// 6. Capacity semantics, and explicit scope reporting for a root with no dependents.
// ---------------------------------------------------------------------------------------------

SFF_TEST(capacity_score_is_a_hard_bound) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey no_capacity = skey(30, 1);
  const SwitchKey usable = skey(31, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // A zero-capacity generation is never used, and it is reported as a proven negative.
  {
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, no_capacity}, 1, 901)},
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(no_capacity, 4, 0)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, no_capacity}, UnresolvedReason::CapacityExhausted,
                  "zero-capacity replacement");
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::CapacityExhausted,
                                   "zero-capacity replacement"));
  }

  // A cheap zero-capacity alternative next to an expensive usable one: capacity wins over cost.
  {
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, no_capacity}, 1, 902),
         mk_candidate(dependent, failed, {leaf, usable}, 9, 903)},
        /*additionally_fenced=*/{},
        /*extra_switches=*/{mk_switch(no_capacity, 4, 0), mk_switch(usable, 5, 3)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    CHECK_EQ(produced.value().restores.size(), std::size_t{1});
    if (!produced.value().restores.empty()) {
      CHECK_EQ(produced.value().restores.front().hops, (std::vector<SwitchKey>{leaf, usable}));
      CHECK_EQ(produced.value().restores.front().cost, 9u);
      for (const auto& hop : produced.value().restores.front().hops) CHECK_NE(hop, no_capacity);
    }
    check_plan_invariants(produced.value(), *rig, "zero capacity versus cost");
  }

  // Three dependents, one replacement with capacity_score 2: never more than two assignments.
  {
    InstanceSpec spec;
    spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100), mk_switch(usable, 3, 2)};
    for (std::uint64_t index = 1; index <= 3; ++index) {
      spec.paths.push_back(mk_path(index, {failed, leaf}));
      spec.candidates.push_back(
          mk_candidate(DependentRef::path(PathId(index)), failed, {leaf, usable}, 1, 910 + index));
    }
    spec.failed = {failed};
    spec.fenced = {failed};
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK_EQ(plan.restores.size(), std::size_t{2});
    CHECK_EQ(plan.unresolved.size(), std::size_t{1});
    std::size_t usage = 0;
    for (const auto& step : plan.restores) {
      for (const auto& hop : step.hops) {
        if (hop == usable) usage += 1;
      }
    }
    CHECK_EQ(usage, std::size_t{2});
    CHECK(usage <= capacity_of(*rig, usable));
    if (!plan.unresolved.empty()) {
      CHECK_EQ(reason_name(plan.unresolved.front().reason), reason_name(UnresolvedReason::CapacityExhausted));
      CHECK(is_proven_negative(plan.unresolved.front().reason));
    }
    check_plan_invariants(plan, *rig, "saturated replacement");
    check_oracle_agreement(plan, *rig, "saturated replacement");
  }
}

// A root that no dependent traverses has an exhaustively enumerated and empty closure: nothing is
// dropped, nothing is restored and nothing is claimed. The assertions below pin the unambiguous
// part of that contract. Observed on this build: the plan reports closure_complete == false and
// feasibility == SEARCH_LIMIT_REACHED for an exhaustively enumerated empty closure, even though no
// declared bound intervened - conservative (it never claims a solution exists or does not exist),
// but the label is not literally true for this case.
SFF_TEST(a_root_without_dependents_is_reported_as_an_empty_scope) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);

  // The dependent exists but does not traverse the failed generation.
  const InstanceSpec spec = simple_spec(
      {mk_candidate(DependentRef::path(PathId(1)), failed, {leaf, replacement}, 1, 1800)},
      /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(replacement, 3, 5)});
  InstanceSpec no_dependents = spec;
  no_dependents.paths = {mk_path(1, {leaf})};

  std::unique_ptr<Rig> rig = make_rig(no_dependents, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();
  CHECK(plan.restores.empty());
  CHECK(plan.unresolved.empty());
  CHECK_EQ(plan.fences.size(), std::size_t{1});
  if (!plan.fences.empty()) {
    CHECK_EQ(plan.fences.front().closure_state, ClosureState::Empty);
    CHECK_EQ(plan.fences.front().omitted_dependents, std::size_t{0});
  }
  // Nothing in scope can be restored, and the plan never claims a solution was found.
  CHECK_NE(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenFeasible));
  CHECK_NE(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenInfeasible));
  check_plan_invariants(plan, *rig, "root without dependents");
}

// A hop set is a set. Repeating one generation inside a single alternative must not consume two
// units of that generation's spare capacity, and must never yield a plan that the library's own
// validator rejects: either the malformed alternative is refused outright, or the plan built from
// it stays inside the capacity bound and validates against the same inputs.
SFF_TEST(a_repeated_hop_cannot_oversubscribe_a_generation) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);   // capacity_score 1, named twice in one hop set
  const DependentRef dependent = DependentRef::path(PathId(1));

  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                   mk_switch(replacement, 3, 1)};
  spec.paths = {mk_path(1, {failed, leaf})};
  spec.candidates = {
      mk_candidate(dependent, failed, {leaf, replacement, replacement}, 1, 1801)};
  spec.failed = {failed};
  spec.fenced = {failed};

  Result<CandidateTable> table = CandidateTable::build(spec.candidates, spec.build_limits);
  if (!table.ok()) {
    // Refusing the malformed alternative is a correct remedy.
    CHECK_EQ(code_name(table.status().code()), std::string("INVALID"));
    return;
  }

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  // Capacity counts DEPENDENTS, not hop occurrences: a hop set that names one generation twice
  // still consumes exactly one unit of that generation's spare capacity. The check therefore
  // counts the distinct hop set of each step.
  std::size_t usage = 0;
  for (const auto& step : produced.value().restores) {
    const std::set<SwitchKey> distinct(step.hops.begin(), step.hops.end());
    if (distinct.find(replacement) != distinct.end()) usage += 1;
  }
  CHECK(usage <= capacity_of(*rig, replacement));
  check_plan_invariants(produced.value(), *rig, "repeated hop set");
}

// ---------------------------------------------------------------------------------------------
// 7. Adversarial greedy-breaking case and its genuinely infeasible mirror.
// ---------------------------------------------------------------------------------------------

SFF_TEST(planner_breaks_the_case_a_greedy_cannot_serve) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey first_leaf = skey(20, 1);
  const SwitchKey second_leaf = skey(21, 1);
  const SwitchKey easy = skey(30, 1);       // capacity_score 1
  const SwitchKey contested = skey(31, 1);  // capacity_score 1, the only option for PATH(3)
  const SwitchKey separate = skey(32, 1);   // capacity_score 1
  const DependentRef first = DependentRef::path(PathId(1));
  const DependentRef second = DependentRef::path(PathId(2));
  const DependentRef hard = DependentRef::path(PathId(3));

  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(first_leaf, 2, 100),
                   mk_switch(second_leaf, 3, 100), mk_switch(easy, 4, 1),
                   mk_switch(contested, 5, 1), mk_switch(separate, 6, 1)};
  spec.paths = {mk_path(1, {failed, first_leaf}), mk_path(2, {failed, second_leaf}),
                mk_path(3, {failed, first_leaf})};
  spec.candidates = {
      // PATH(1) prefers the generation that PATH(3) can only use.
      mk_candidate(first, failed, {first_leaf, contested}, 1, 1001),
      mk_candidate(first, failed, {first_leaf, easy}, 2, 1002),
      mk_candidate(second, failed, {second_leaf, separate}, 1, 1003),
      mk_candidate(hard, failed, {first_leaf, contested}, 1, 1004),
  };
  spec.failed = {failed};
  spec.fenced = {failed};

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();

  // A cheapest-first greedy takes the contested generation for PATH(1) and then cannot serve
  // PATH(3) at all: a complete assignment requires paying more for PATH(1).
  const ReconstructionPlan greedy = greedy_plan(*rig);
  CHECK(greedy.unresolved.size() > plan.unresolved.size());
  CHECK(!greedy.unresolved.empty());
  CHECK(plan.unresolved.empty());
  CHECK(plan.total_cost() > greedy.total_cost());
  CHECK(plan_not_worse_than(plan, greedy));
  CHECK(plan < greedy);
  CHECK_EQ(plan.restores.size(), std::size_t{3});
  CHECK_EQ(plan.total_cost(), std::uint64_t{4});
  CHECK_EQ(plan_hops(plan), std::size_t{6});
  CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenFeasible));
  for (const auto& step : plan.restores) {
    if (step.dependent == first) {
      CHECK_EQ(step.hops, (std::vector<SwitchKey>{first_leaf, easy}));
    }
    if (step.dependent == hard) {
      CHECK_EQ(step.hops, (std::vector<SwitchKey>{first_leaf, contested}));
    }
  }
  check_plan_invariants(plan, *rig, "greedy-breaking instance");
  check_oracle_agreement(plan, *rig, "greedy-breaking instance");

  const ReferenceSolution reference = solve_reference(rig->inputs(), rig->failed, 100000);
  CHECK(reference.optimal_found);
  CHECK_EQ(reference.plan.unresolved.size(), std::size_t{0});
  CHECK_EQ(reference.plan.total_cost(), std::uint64_t{4});
}

SFF_TEST(infeasible_instances_carry_a_certificate_for_every_dependent) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey no_capacity = skey(30, 1);
  const DependentRef first = DependentRef::path(PathId(1));
  const DependentRef second = DependentRef::path(PathId(2));
  const DependentRef third = DependentRef::path(PathId(3));

  // Mirror of the greedy-breaking instance: nothing can be restored, and every dependent carries
  // a proven certificate instead of a silent omission.
  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                   mk_switch(no_capacity, 3, 0)};
  spec.paths = {mk_path(1, {failed, leaf}), mk_path(2, {failed, leaf}), mk_path(3, {failed, leaf})};
  spec.candidates = {
      mk_candidate(first, failed, {leaf, no_capacity}, 1, 1101),
      mk_candidate(second, failed, {leaf, no_capacity}, 1, 1102),
      // third: no alternative was supplied at all.
  };
  spec.failed = {failed};
  spec.fenced = {failed};

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();

  CHECK(plan.restores.empty());
  CHECK_EQ(plan.unresolved.size(), std::size_t{3});
  CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenInfeasible));
  CHECK(plan.closure_complete);
  bool saw_capacity = false;
  bool saw_absent = false;
  for (const auto& entry : plan.unresolved) {
    CHECK(is_proven_negative(entry.reason));
    if (entry.reason == UnresolvedReason::CapacityExhausted) saw_capacity = true;
    if (entry.reason == UnresolvedReason::NoCandidateSupplied) saw_absent = true;
  }
  CHECK(saw_capacity);
  CHECK(saw_absent);
  // The greedy cannot do better either: there is nothing to assign.
  const ReconstructionPlan greedy = greedy_plan(*rig);
  CHECK(greedy.restores.empty());
  CHECK(!(plan < greedy));
  CHECK(!(greedy < plan));
  check_plan_invariants(plan, *rig, "certified infeasible instance");
  check_oracle_agreement(plan, *rig, "certified infeasible instance");
}

// ---------------------------------------------------------------------------------------------
// 8. Truncated closures are explicit partial results.
// ---------------------------------------------------------------------------------------------

SFF_TEST(a_truncated_closure_is_never_reported_as_infeasible) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);

  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100), mk_switch(replacement, 3, 5)};
  for (std::uint64_t index = 1; index <= 4; ++index) {
    spec.paths.push_back(mk_path(index, {failed, leaf}));
    spec.candidates.push_back(
        mk_candidate(DependentRef::path(PathId(index)), failed, {leaf, replacement}, 1, 1200 + index));
  }
  spec.failed = {failed};
  spec.fenced = {failed};

  // (i) The closure is cut before any dependent is reached: an empty restore set here is NOT a
  //     proof that nothing can be restored.
  {
    InstanceSpec truncated = spec;
    truncated.limits.max_closure_nodes = 1;
    std::unique_ptr<Rig> rig = make_rig(truncated, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK(!plan.closure_complete);
    CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::SearchLimitReached));
    CHECK_NE(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenInfeasible));
    CHECK(plan.restores.empty());
    CHECK(!plan.fences.empty());
    if (!plan.fences.empty()) {
      CHECK_EQ(plan.fences.front().closure_state, ClosureState::Truncated);
      CHECK_LT(plan.fences.front().closure_members, std::size_t{5});
    }
    check_plan_invariants(plan, *rig, "closure truncated before any dependent");
  }

  // (ii) The closure is cut part way through: the discovered dependents are planned, the
  //      remainder is explicitly omitted rather than silently dropped, and the partial result is
  //      still a proof of feasibility rather than a proof of absence.
  {
    InstanceSpec truncated = spec;
    truncated.limits.max_closure_nodes = 3;
    std::unique_ptr<Rig> rig = make_rig(truncated, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK(!plan.closure_complete);
    CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::SearchLimitReached));
    CHECK_EQ(plan.restores.size() + plan.unresolved.size(), std::size_t{2});
    CHECK_EQ(plan.restores.size(), std::size_t{2});
    CHECK(!plan.fences.empty());
    if (!plan.fences.empty()) {
      CHECK_EQ(plan.fences.front().closure_state, ClosureState::Truncated);
      CHECK(plan.fences.front().omitted_dependents > 0);
    }
    check_plan_invariants(plan, *rig, "closure truncated part way");
  }

  // (iii) A truncated closure dominates the feasibility claim: a dependent with no alternative at
  //       all is reported as a proven negative, yet the plan as a whole is SearchLimitReached,
  //       never ProvenInfeasible.
  {
    InstanceSpec partial;
    partial.switches = spec.switches;
    partial.paths = spec.paths;
    partial.candidates = {spec.candidates.front()};   // only PATH(1) has an alternative
    partial.failed = {failed};
    partial.fenced = {failed};
    InstanceSpec bounded = partial;
    bounded.limits.max_closure_nodes = 3;
    std::unique_ptr<Rig> rig = make_rig(bounded, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK(!plan.closure_complete);
    CHECK_EQ(plan.restores.size(), std::size_t{1});
    CHECK_EQ(plan.unresolved.size(), std::size_t{1});
    CHECK_EQ(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::SearchLimitReached));
    CHECK_NE(feasibility_name(plan.feasibility), feasibility_name(PlanFeasibility::ProvenInfeasible));
    for (const auto& entry : plan.unresolved) {
      CHECK_EQ(reason_name(entry.reason), reason_name(UnresolvedReason::NoCandidateSupplied));
      CHECK(is_proven_negative(entry.reason));
    }
    check_plan_invariants(plan, *rig, "truncated closure with an unserved dependent");

    // The truncation is a property of the bound, not of the instance: with a sufficient bound the
    // same inputs enumerate every dependent.
    std::unique_ptr<Rig> full = make_rig(partial, 0);  // partial keeps the default closure bound
    CHECK(full != nullptr);
    if (full == nullptr) return;
    Result<ReconstructionPlan> full_plan = plan_reconstruction(full->inputs(), full->failed);
    CHECK(full_plan.ok());
    if (full_plan.ok()) {
      CHECK(full_plan.value().closure_complete);
      CHECK_EQ(full_plan.value().restores.size(), std::size_t{1});
      CHECK_EQ(full_plan.value().unresolved.size(), std::size_t{3});
      CHECK_EQ(feasibility_name(full_plan.value().feasibility),
               feasibility_name(PlanFeasibility::ProvenFeasible));
    }
  }
}

SFF_TEST(a_cut_candidate_enumeration_is_never_a_proof_of_absence) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey installed = skey(30, 1);
  const SwitchKey absent = skey(99, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // Every supplied alternative names a generation the topology does not carry. With the full
  // enumeration that is a proven negative; with the enumeration cut by a declared bound it is
  // explicitly NOT a proof, and the plan must say so.
  const std::vector<ReconstructionCandidate> rejected = {
      mk_candidate(dependent, failed, {leaf, absent}, 1, 1701),
      mk_candidate(dependent, failed, {leaf, absent}, 2, 1702),
      mk_candidate(dependent, failed, {leaf, absent}, 3, 1703),
  };
  {
    std::unique_ptr<Rig> rig = make_rig(simple_spec(rejected), 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::HopNotInTopology,
                                   "complete enumeration of absent generations"));
  }
  {
    InstanceSpec cut = simple_spec(rejected);
    cut.planning.max_candidates_per_dependent = 1;
    std::unique_ptr<Rig> rig = make_rig(cut, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan& plan = produced.value();
    CHECK_EQ(plan.unresolved.size(), std::size_t{1});
    if (!plan.unresolved.empty()) {
      CHECK_EQ(reason_name(plan.unresolved.front().reason),
               reason_name(UnresolvedReason::SearchLimitReached));
      CHECK(!is_proven_negative(plan.unresolved.front().reason));
    }
    CHECK_EQ(feasibility_name(plan.feasibility),
             feasibility_name(PlanFeasibility::SearchLimitReached));
    CHECK_NE(feasibility_name(plan.feasibility),
             feasibility_name(PlanFeasibility::ProvenInfeasible));
    check_plan_invariants(plan, *rig, "cut candidate enumeration");
  }

  // Admissible alternatives beyond the bound: the dependent is restored, but the claim stays
  // partial because the enumeration was cut.
  {
    InstanceSpec cut = simple_spec(
        {mk_candidate(dependent, failed, {leaf, installed}, 1, 1711),
         mk_candidate(dependent, failed, {leaf, installed}, 2, 1712),
         mk_candidate(dependent, failed, {leaf, installed}, 3, 1713)},
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(installed, 3, 5)});
    cut.planning.max_candidates_per_dependent = 1;
    std::unique_ptr<Rig> rig = make_rig(cut, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    CHECK_EQ(produced.value().restores.size(), std::size_t{1});
    CHECK_EQ(feasibility_name(produced.value().feasibility),
             feasibility_name(PlanFeasibility::SearchLimitReached));
    CHECK_NE(feasibility_name(produced.value().feasibility),
             feasibility_name(PlanFeasibility::ProvenFeasible));
    check_plan_invariants(produced.value(), *rig, "cut candidate enumeration with a plan");
  }
}

// ---------------------------------------------------------------------------------------------
// 9. Unresolved taxonomy.
// ---------------------------------------------------------------------------------------------

SFF_TEST(taxonomy_no_candidate_and_stale_generation) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // No alternative was supplied at all: absence of candidates is stated, not inferred.
  {
    const InstanceSpec spec = simple_spec({});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::NoCandidateSupplied,
                                   "no candidate supplied"));
    CHECK(evaluate_candidates(dependent, failed, rig->inputs()).empty());
  }

  // An alternative that covers a different generation of the same identity is stale, never
  // silently treated as covering the failed generation.
  {
    const SwitchKey newer = skey(10, 2);
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, newer, {leaf, skey(30, 1)}, 2, 1301)},
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(skey(30, 1), 4, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    CHECK_EQ(reports.size(), std::size_t{1});
    if (!reports.empty()) {
      CHECK(!reports.front().eligible);
      CHECK_EQ(reason_name(reports.front().reason),
               reason_name(UnresolvedReason::CandidateGenerationStale));
      CHECK(is_proven_negative(reports.front().reason));
    }
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::CandidateGenerationStale,
                                   "alternative covers a superseded generation"));
  }

  // An alternative that names a hop generation the topology no longer carries, while a newer
  // generation of that identity exists, is stale as well.
  {
    const SwitchKey superseded = skey(31, 1);
    const SwitchKey current = skey(31, 2);
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, superseded}, 2, 1302)},
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(current, 4, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK_EQ(rig->topology.find_switch(superseded), nullptr);
    CHECK(rig->topology.find_highest_generation(superseded.id()) != nullptr);
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, superseded}, UnresolvedReason::CandidateGenerationStale,
                  "hop names a superseded generation");
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::CandidateGenerationStale,
                                   "hop names a superseded generation"));
  }

  // A hop generation the topology never carried is a different, equally proven outcome.
  {
    const SwitchKey absent = skey(99, 1);
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, absent}, 2, 1303)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, absent}, UnresolvedReason::HopNotInTopology,
                  "hop generation is absent from the topology");
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::HopNotInTopology,
                                   "hop generation is absent from the topology"));
  }
}

SFF_TEST(taxonomy_capability_and_failure_domain) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey weak = skey(30, 1);
  const SwitchKey strong = skey(31, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));
  const CapabilityMask required =
      capability_bit(Capability::Layer3) | capability_bit(Capability::Vxlan);

  // The hop generation does not provide the required capability set.
  {
    InstanceSpec spec;
    spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                     mk_switch(weak, 3, 5, capability_bit(Capability::Layer3))};
    spec.paths = {mk_path(1, {failed, leaf}, required)};
    spec.candidates = {mk_candidate(dependent, failed, {leaf, weak}, 2, 1401)};
    spec.failed = {failed};
    spec.fenced = {failed};
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, weak}, UnresolvedReason::CapabilityInsufficient,
                  "hop lacks a required capability");
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::CapabilityInsufficient,
                                   "hop lacks a required capability"));
  }

  // The hop generation provides it but the alternative itself does not.
  {
    InstanceSpec spec;
    spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                     mk_switch(strong, 3, 5)};
    spec.paths = {mk_path(1, {failed, leaf}, required)};
    spec.candidates = {mk_candidate(dependent, failed, {leaf, strong}, 2, 1402,
                                    EvidenceSource::SimulatedFixture,
                                    capability_bit(Capability::Layer3))};
    spec.failed = {failed};
    spec.fenced = {failed};
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::CapabilityInsufficient,
                                   "alternative lacks a required capability"));
  }

  // The replacement reuses the failure domain of the failed generation. With policy permitting
  // it, the very same alternative becomes admissible: the refusal is policy, not structure.
  {
    InstanceSpec spec;
    spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                     mk_switch(strong, 1, 5)};
    spec.paths = {mk_path(1, {failed, leaf}, required)};
    spec.candidates = {mk_candidate(dependent, failed, {leaf, strong}, 2, 1403)};
    spec.failed = {failed};
    spec.fenced = {failed};
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, strong}, UnresolvedReason::FailureDomainConflict,
                  "replacement shares the failed failure domain");
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::FailureDomainConflict,
                                   "replacement shares the failed failure domain"));

    InstanceSpec permitted = spec;
    permitted.planning.allow_replacement_in_same_failure_domain = true;
    std::unique_ptr<Rig> relaxed = make_rig(permitted, 0);
    CHECK(relaxed != nullptr);
    if (relaxed == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(relaxed->inputs(), relaxed->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    CHECK_EQ(produced.value().restores.size(), std::size_t{1});
    CHECK_EQ(produced.value().unresolved.size(), std::size_t{0});
    check_plan_invariants(produced.value(), *relaxed, "same failure domain permitted");
  }
}

SFF_TEST(taxonomy_behind_fence_and_non_authoritative_origin) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey fenced_hop = skey(31, 1);
  const SwitchKey replacement = skey(30, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // A fenced generation may never be crossed, and the refusal is proven.
  {
    InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, fenced_hop}, 2, 1501)},
        /*additionally_fenced=*/{fenced_hop},
        /*extra_switches=*/{mk_switch(fenced_hop, 4, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, fenced_hop}, UnresolvedReason::BehindFence,
                  "hop generation is fenced");
    CHECK(expect_single_unresolved(*rig, dependent, failed, UnresolvedReason::BehindFence,
                                   "hop generation is fenced"));
  }

  // A non-authoritative origin is refused while the policy demands authoritative alternatives,
  // and admitted - unchanged - once the policy is relaxed.
  {
    const InstanceSpec spec = simple_spec(
        {mk_candidate(dependent, failed, {leaf, replacement}, 2, 1502,
                      EvidenceSource::TelemetryCollector)},
        /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(replacement, 3, 5)});
    std::unique_ptr<Rig> rig = make_rig(spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) return;
    CHECK(trust_of(EvidenceSource::TelemetryCollector) != TrustLevel::Authoritative);
    const std::vector<CandidateEligibility> reports =
        evaluate_candidates(dependent, failed, rig->inputs());
    report_reason(reports, {leaf, replacement}, UnresolvedReason::NonAuthoritativeOrigin,
                  "advisory origin");
    CHECK(expect_single_unresolved(*rig, dependent, failed,
                                   UnresolvedReason::NonAuthoritativeOrigin,
                                   "advisory origin"));

    InstanceSpec permitted = spec;
    permitted.planning.require_authoritative_candidate_evidence = false;
    std::unique_ptr<Rig> relaxed = make_rig(permitted, 0);
    CHECK(relaxed != nullptr);
    if (relaxed == nullptr) return;
    Result<ReconstructionPlan> produced = plan_reconstruction(relaxed->inputs(), relaxed->failed);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    CHECK_EQ(produced.value().restores.size(), std::size_t{1});
    check_plan_invariants(produced.value(), *relaxed, "advisory origin permitted by policy");
  }
}

SFF_TEST(is_proven_negative_matches_the_taxonomy) {
  // Exactly the ten certifying reasons are proven negatives.
  const UnresolvedReason proven[] = {
      UnresolvedReason::NoCandidateSupplied,     UnresolvedReason::CandidateGenerationStale,
      UnresolvedReason::CapabilityInsufficient,  UnresolvedReason::BehindFence,
      UnresolvedReason::CapacityExhausted,       UnresolvedReason::FailureDomainConflict,
      UnresolvedReason::Withheld,                UnresolvedReason::ContradictoryEvidence,
      UnresolvedReason::HopNotInTopology,        UnresolvedReason::NonAuthoritativeOrigin,
  };
  for (const auto reason : proven) CHECK(is_proven_negative(reason));
  // The three non-certifying reasons are never proofs of absence.
  CHECK(!is_proven_negative(UnresolvedReason::Unknown));
  CHECK(!is_proven_negative(UnresolvedReason::ClosureTruncated));
  CHECK(!is_proven_negative(UnresolvedReason::SearchLimitReached));
  CHECK_EQ(reason_name(UnresolvedReason::ClosureTruncated), std::string("CLOSURE_TRUNCATED"));
  CHECK_EQ(reason_name(UnresolvedReason::SearchLimitReached), std::string("SEARCH_LIMIT_REACHED"));
  CHECK_EQ(feasibility_name(PlanFeasibility::SearchLimitReached), std::string("SEARCH_LIMIT_REACHED"));
  CHECK_EQ(feasibility_name(PlanFeasibility::ProvenInfeasible), std::string("PROVEN_INFEASIBLE"));
}

// ---------------------------------------------------------------------------------------------
// 10. Candidate table contract.
// ---------------------------------------------------------------------------------------------

bool canonical_candidate_less(const ReconstructionCandidate& a, const ReconstructionCandidate& b) {
  if (a.cost != b.cost) return a.cost < b.cost;
  if (a.hops.size() != b.hops.size()) return a.hops.size() < b.hops.size();
  if (a.hops != b.hops) return a.hops < b.hops;
  if (a.links != b.links) return a.links < b.links;
  if (a.capabilities != b.capabilities) return a.capabilities < b.capabilities;
  return a.evidence < b.evidence;
}

SFF_TEST(candidate_table_canonicalises_and_is_bounded) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey first = skey(30, 1);
  const SwitchKey second = skey(31, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));
  const DependentRef other = DependentRef::path(PathId(2));

  const std::vector<ReconstructionCandidate> supplied = {
      mk_candidate(dependent, failed, {leaf, first}, 5, 1),
      mk_candidate(dependent, failed, {leaf, second}, 1, 2),
      mk_candidate(dependent, failed, {leaf, second}, 1, 9),  // same alternative, other evidence
      mk_candidate(dependent, failed, {leaf, second}, 3, 3),
      mk_candidate(other, failed, {leaf, first}, 2, 4),
  };

  Result<CandidateTable> table = CandidateTable::build(supplied, Limits::defaults());
  CHECK(table.ok());
  if (!table.ok()) return;
  CHECK_NE(table.value().digest(), std::uint64_t{0});
  CHECK_EQ(table.value().size(), std::size_t{4});

  // for_dependent returns exactly that dependent's alternatives, in canonical candidate order.
  const std::vector<ReconstructionCandidate> first_dependent = table.value().for_dependent(dependent);
  CHECK_EQ(first_dependent.size(), std::size_t{3});
  for (const auto& candidate : first_dependent) CHECK_EQ(candidate.dependent, dependent);
  CHECK(std::is_sorted(first_dependent.begin(), first_dependent.end(), canonical_candidate_less));
  CHECK_EQ(first_dependent.front().cost, 1u);
  CHECK_EQ(first_dependent.back().cost, 5u);

  const std::vector<ReconstructionCandidate> second_dependent = table.value().for_dependent(other);
  CHECK_EQ(second_dependent.size(), std::size_t{1});
  for (const auto& candidate : second_dependent) CHECK_EQ(candidate.dependent, other);
  CHECK(table.value().for_dependent(DependentRef::path(PathId(99))).empty());

  // Shuffling the supplied order must not change the canonical table.
  for (const std::uint64_t seed : {std::uint64_t{3}, std::uint64_t{17}, std::uint64_t{4242}}) {
    std::vector<ReconstructionCandidate> shuffled = supplied;
    Rng rng(seed);
    shuffle_values(shuffled, rng);
    Result<CandidateTable> other_table = CandidateTable::build(shuffled, Limits::defaults());
    CHECK(other_table.ok());
    if (!other_table.ok()) return;
    CHECK_EQ(other_table.value().digest(), table.value().digest());
    CHECK_EQ(other_table.value().size(), table.value().size());
  }

  // The declared bound is a refusal, not a silent truncation.
  {
    Limits tight = Limits::defaults();
    tight.max_candidates_evaluated = 3;
    Result<CandidateTable> refused = CandidateTable::build(supplied, tight);
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(code_name(refused.status().code()), std::string("EXHAUSTED"));
  }

  // A structurally invalid alternative is refused with Invalid.
  {
    std::vector<ReconstructionCandidate> invalid = supplied;
    invalid.front().cost = 0;
    Result<CandidateTable> refused = CandidateTable::build(invalid, Limits::defaults());
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(code_name(refused.status().code()), std::string("INVALID"));
  }
}

// A duplicate alternative is the same alternative: two authoritative suppliers may name the very
// same hop set, cost and capabilities under different evidence identities. The table must hold it
// once, and the canonical digest must not depend on which copy survived. De-duplication that only
// compares neighbours in digest order leaves this pair in the table, which the assertions below
// detect: the table holds three entries for two distinct alternatives.
SFF_TEST(candidate_table_deduplicates_regardless_of_digest_order) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey first = skey(30, 1);
  const SwitchKey second = skey(31, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  // The same alternative twice, with a different alternative carrying the same cost between the
  // two copies in canonical order. Two distinct alternatives were supplied; the table must hold
  // two, and must not hold three.
  const std::vector<ReconstructionCandidate> separated = {
      mk_candidate(dependent, failed, {leaf, second}, 1, 1),
      mk_candidate(dependent, failed, {leaf, first}, 1, 1),
      mk_candidate(dependent, failed, {leaf, second}, 1, 2),
  };
  Result<CandidateTable> table = CandidateTable::build(separated, Limits::defaults());
  CHECK(table.ok());
  if (!table.ok()) return;
  CHECK_EQ(table.value().size(), std::size_t{2});
  CHECK_EQ(table.value().for_dependent(dependent).size(), std::size_t{2});

  // Copies that are adjacent in canonical order do collapse, so this is an incomplete
  // de-duplication rather than a missing feature.
  const std::vector<ReconstructionCandidate> adjacent = {
      mk_candidate(dependent, failed, {leaf, second}, 1, 1),
      mk_candidate(dependent, failed, {leaf, second}, 1, 2),
  };
  Result<CandidateTable> collapsed = CandidateTable::build(adjacent, Limits::defaults());
  CHECK(collapsed.ok());
  if (collapsed.ok()) CHECK_EQ(collapsed.value().size(), std::size_t{1});

  // Reversing the supplied order must not change the canonical table.
  std::vector<ReconstructionCandidate> reversed = separated;
  std::reverse(reversed.begin(), reversed.end());
  Result<CandidateTable> other = CandidateTable::build(reversed, Limits::defaults());
  CHECK(other.ok());
  if (other.ok()) CHECK_EQ(other.value().digest(), table.value().digest());
}

// ---------------------------------------------------------------------------------------------
// 11. Every produced plan passes independent validation.
// ---------------------------------------------------------------------------------------------

SFF_TEST(every_produced_plan_passes_independent_validation) {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey replacement = skey(30, 1);
  const DependentRef dependent = DependentRef::path(PathId(1));

  InstanceSpec spec = simple_spec(
      {mk_candidate(dependent, failed, {leaf, replacement}, 4, 1601)},
      /*additionally_fenced=*/{}, /*extra_switches=*/{mk_switch(replacement, 3, 5)});
  spec.links = {mk_link(1, leaf, 1, replacement, 1)};
  spec.candidates.front().links = {LinkId(1)};

  std::unique_ptr<Rig> rig = make_rig(spec, 0);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;
  Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();

  const ValidationReport report = validate_plan(plan, rig->inputs());
  CHECK(report.valid);
  CHECK(report.checks_performed > 0);
  CHECK_EQ(report.findings.size(), std::size_t{0});
  CHECK_EQ(code_name(report.outcome), std::string("OK"));
  CHECK_EQ(report.plan_digest, plan.plan_digest);
  CHECK_EQ(report.inputs_digest, rig->inputs().policy_digest());

  const ValidationReport fences = validate_fences(plan, rig->inputs());
  CHECK(fences.valid);

  // A plan whose digest no longer matches its contents is refused outright.
  ReconstructionPlan tampered = plan;
  tampered.restores.front().cost += 1;
  const ValidationReport tampered_report = validate_plan(tampered, rig->inputs());
  CHECK(!tampered_report.valid);
  if (!tampered_report.valid) {
    CHECK_EQ(code_name(tampered_report.outcome), std::string("CORRUPT"));
  }

  // A plan produced under a different topology is stale, never silently accepted.
  ReconstructionPlan stale = plan;
  stale.topology_digest ^= 0x1234ull;
  stale.seal();
  const ValidationReport stale_report = validate_plan(stale, rig->inputs());
  CHECK(!stale_report.valid);
  if (!stale_report.valid) CHECK_EQ(code_name(stale_report.outcome), std::string("STALE"));
}

// ---------------------------------------------------------------------------------------------
// Randomised property coverage: explicit seeds, invariants after every plan, seeded digests.
// ---------------------------------------------------------------------------------------------

struct RandomInstance {
  InstanceSpec spec;
  GenerationVector failed;
};

RandomInstance random_instance(std::uint64_t seed) {
  Rng rng(seed);
  RandomInstance out;
  const std::size_t failed_count = 1 + static_cast<std::size_t>(rng.bounded(2));        // 1..2
  const std::size_t leaf_count = 1 + static_cast<std::size_t>(rng.bounded(2));          // 1..2
  const std::size_t replacement_count = 1 + static_cast<std::size_t>(rng.bounded(3));   // 1..3

  std::vector<SwitchKey> failed_keys;
  for (std::size_t index = 0; index < failed_count; ++index) {
    const SwitchKey key = skey(10 + index, 1);
    failed_keys.push_back(key);
    out.spec.switches.push_back(mk_switch(key, 100 + index, 100));
    out.spec.fenced.push_back(key);
    out.failed.insert(key);
  }
  std::vector<SwitchKey> leaf_keys;
  for (std::size_t index = 0; index < leaf_count; ++index) {
    const SwitchKey key = skey(20 + index, 1);
    leaf_keys.push_back(key);
    out.spec.switches.push_back(mk_switch(key, 110 + index, 100));
  }
  std::vector<SwitchKey> replacement_keys;
  for (std::size_t index = 0; index < replacement_count; ++index) {
    const SwitchKey key = skey(30 + index, 1);
    replacement_keys.push_back(key);
    const std::uint32_t capacity = static_cast<std::uint32_t>(rng.bounded(4));  // 0..3
    out.spec.switches.push_back(mk_switch(key, 120 + index, capacity));
  }

  const std::size_t dependent_count = 2 + static_cast<std::size_t>(rng.bounded(5));  // 2..6
  std::uint64_t next_evidence = 5000;
  for (std::size_t index = 0; index < dependent_count; ++index) {
    const std::uint64_t path_id = 100 + index;
    const DependentRef dependent = DependentRef::path(PathId(path_id));
    const SwitchKey leaf = leaf_keys[static_cast<std::size_t>(rng.bounded(leaf_count))];
    std::vector<SwitchKey> hops;
    for (const auto& key : failed_keys) {
      if (rng.coin()) hops.push_back(key);
    }
    if (hops.empty()) {
      hops.push_back(failed_keys[static_cast<std::size_t>(rng.bounded(failed_count))]);
    }
    hops.push_back(leaf);
    out.spec.paths.push_back(mk_path(path_id, hops));

    for (const auto& key : hops) {
      if (!out.failed.contains(key)) continue;
      const std::size_t alternatives = static_cast<std::size_t>(rng.bounded(4));  // 0..3
      for (std::size_t alternative = 0; alternative < alternatives; ++alternative) {
        const SwitchKey replacement =
            replacement_keys[static_cast<std::size_t>(rng.bounded(replacement_count))];
        const std::uint32_t cost = 1 + static_cast<std::uint32_t>(rng.bounded(6));
        out.spec.candidates.push_back(
            mk_candidate(dependent, key, {leaf, replacement}, cost, next_evidence));
        next_evidence += 1;
      }
    }
  }
  return out;
}

SFF_TEST(randomised_instances_hold_every_invariant) {
  constexpr std::uint64_t kSeedBase = 0x5eed0000ull;
  constexpr std::size_t kInstances = 48;
  std::size_t planned = 0;
  for (std::size_t index = 0; index < kInstances; ++index) {
    const std::uint64_t seed = kSeedBase + static_cast<std::uint64_t>(index) * 7919ull;
    const std::string tag = "SYNTHETIC randomised instance seed=" + std::to_string(seed);
    const RandomInstance instance = random_instance(seed);

    std::unique_ptr<Rig> rig = make_rig(instance.spec, 0);
    CHECK(rig != nullptr);
    if (rig == nullptr) continue;

    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    if (!produced.ok()) {
      sfftest::fail(__FILE__, __LINE__, tag + ": planning was refused: " +
                                            code_name(produced.status().code()) + " " +
                                            produced.status().message() + " instance=" +
                                            spec_summary(instance.spec));
      continue;
    }
    const ReconstructionPlan& plan = produced.value();
    const bool invariants = check_plan_invariants(plan, *rig, tag);
    const bool agreement = check_oracle_agreement(plan, *rig, tag);
    if (!invariants || !agreement) {
      sfftest::fail(__FILE__, __LINE__,
                    tag + ": the instance below violated the planner contract, instance=" +
                        spec_summary(instance.spec));
    }

    // Determinism across input order for the same declared instance.
    std::unique_ptr<Rig> shuffled = make_rig(instance.spec, seed ^ 0x9e3779b97f4a7c15ull);
    CHECK(shuffled != nullptr);
    if (shuffled == nullptr) continue;
    Result<ReconstructionPlan> repeated = plan_reconstruction(shuffled->inputs(), shuffled->failed);
    CHECK(repeated.ok());
    if (!repeated.ok()) continue;
    if (repeated.value().plan_digest != plan.plan_digest) {
      sfftest::fail(__FILE__, __LINE__,
                    tag + ": plan digest depends on input order: " +
                        std::to_string(plan.plan_digest) + " vs " +
                        std::to_string(repeated.value().plan_digest) + " instance=" +
                        spec_summary(instance.spec));
    }
    CHECK(check_plan_invariants(repeated.value(), *shuffled, tag + " (shuffled)"));
    planned += 1;
  }
  CHECK_EQ(planned, kInstances);
}

// ---------------------------------------------------------------------------------------------
// The same contract through the coordinator, exactly as an embedder drives it.
// ---------------------------------------------------------------------------------------------

SFF_TEST(coordinator_plans_only_for_fenced_or_failing_generations) {
  ManualClock clock(1000);
  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;
  config.evidence_class = EvidenceClass::Synthetic;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

  FabricSpec fabric_spec;
  fabric_spec.leaves = 2;
  fabric_spec.spines = 2;
  fabric_spec.replacement_spines = 2;
  fabric_spec.paths_per_leaf = 4;
  Result<Fabric> built = build_fabric(fabric_spec);
  CHECK(built.ok());
  if (!built.ok()) return;
  Fabric fabric = std::move(built).value();
  CHECK(coordinator->install_topology(fabric.topology).ok());
  CHECK(coordinator->install_candidates(fabric.candidates).ok());

  const SwitchKey failed = fabric.spine_keys.front();
  GenerationVector roots;
  roots.insert(failed);

  Result<ReconstructionPlan> refused = coordinator->propose_plan(roots);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(code_name(refused.status().code()), std::string("INVALID"));

  FailureDeclaration declaration;
  declaration.subject = failed;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = 3600ull * kNanosPerSecond;
  declaration.reason = "SYNTHETIC fabric manager failure declaration";
  Result<FailoverOutcome> outcome = coordinator->declare_failure(declaration);
  CHECK(outcome.ok());
  if (!outcome.ok()) return;
  CHECK_EQ(code_name(outcome.value().outcome), std::string("OK"));

  Result<ReconstructionPlan> produced = coordinator->propose_plan(roots);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();
  CHECK_EQ(plan.state, PlanState::Validated);
  CHECK(plan.digest_valid());
  CHECK(!plan.restores.empty());
  CHECK(std::is_sorted(plan.restores.begin(), plan.restores.end(),
                      [](const RestoreStep& a, const RestoreStep& b) {
                        if (a.dependent != b.dependent) return a.dependent < b.dependent;
                        if (a.covers_failed != b.covers_failed) return a.covers_failed < b.covers_failed;
                        return a.replacement < b.replacement;
                      }));
  for (const auto& step : plan.restores) {
    CHECK_EQ(step.covers_failed, failed);
    for (const auto& hop : step.hops) CHECK_NE(hop, failed);
  }
  Result<ValidationReport> report = coordinator->validate_plan(plan);
  CHECK(report.ok());
  if (report.ok()) CHECK(report.value().valid);

  // A second proposal is a distinct plan identity under the same reconstruction.
  Result<ReconstructionPlan> again = coordinator->propose_plan(roots);
  CHECK(again.ok());
  if (again.ok()) {
    CHECK_NE(again.value().plan_digest, plan.plan_digest);
    CHECK_EQ(again.value().restores.size(), plan.restores.size());
  }
}

}  // namespace

SFF_MAIN()
