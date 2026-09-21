// Switch Failover Fabric - differential testing against the exhaustive reference solver.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every instance in this file is generated in-process from declared switch
// generations, paths, candidates and authority state. No physical switch, NIC, RDMA device or
// multi-node fabric is exercised, and no result here is physical-hardware evidence.
//
// What this suite proves about solve_reference:
//   - it explores the complete admissible assignment space for small instances and reports
//     exhausted/optimal_found only when it really enumerated everything;
//   - the production planner is never worse than that optimum under the shared total order
//     (unresolved count, then total cost, then total hop count);
//   - a claim of ProvenInfeasible by the production planner is never contradicted by a plan the
//     reference solver can produce;
//   - SearchLimitReached is never converted into an infeasibility proof, by either solver;
//   - the reference solver is deterministic (same instance, same plan digest);
//   - hand-computed optima on tiny instances are reproduced exactly.
#include <algorithm>
#include <cstdint>
#include <cstdio>
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

constexpr BootIncarnation kBoot = BootIncarnation::from_parts(0x5ffull, 5, 0xfeedull, 0x1234ull);
constexpr CoordinatorEpoch kEpoch = CoordinatorEpoch(11);
constexpr TimestampNs kNowNs = 8'000'000'000ull;
constexpr std::uint64_t kGenerousBudget = 200000;

// ---------------------------------------------------------------------------------------------
// Rig: the complete input set for one instance.
// ---------------------------------------------------------------------------------------------

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
    out.plan_id = PlanId(1);
    out.now_ns = kNowNs;
    return out;
  }
};

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

PathDescriptor mk_path(std::uint64_t id, std::vector<SwitchKey> hops) {
  PathDescriptor path;
  path.id = PathId(id);
  path.source = NodeId(9000 + id);
  path.destination = NodeId(9500 + id);
  path.hops = std::move(hops);
  path.cost = 1;
  path.required_capabilities = capability_bit(Capability::Layer3);
  return path;
}

ReconstructionCandidate mk_candidate(const DependentRef& dependent, const SwitchKey& covers_failed,
                                     std::vector<SwitchKey> hops, std::uint32_t cost,
                                     std::uint64_t evidence,
                                     EvidenceSource source = EvidenceSource::SimulatedFixture) {
  ReconstructionCandidate candidate;
  candidate.dependent = dependent;
  candidate.covers_failed = covers_failed;
  candidate.hops = std::move(hops);
  candidate.cost = cost;
  candidate.capabilities = kAllCapabilities;
  candidate.evidence = EvidenceId(evidence);
  candidate.source = source;
  return candidate;
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

std::unique_ptr<Rig> make_rig(const InstanceSpec& spec, std::string* error) {
  auto rig = std::make_unique<Rig>();
  rig->limits = spec.limits;
  rig->planning = spec.planning;
  rig->assessment = spec.assessment;
  rig->failed = GenerationVector::canonicalise(spec.failed);

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), spec.switches, spec.links, spec.paths, spec.edges,
                              spec.build_limits);
  if (!topology.ok()) {
    if (error != nullptr) {
      *error = std::string("topology build refused: ") + to_string(topology.status().code()) + " " +
               topology.status().message();
    }
    return nullptr;
  }
  rig->topology = std::move(topology).value();

  Result<CandidateTable> table = CandidateTable::build(spec.candidates, spec.build_limits);
  if (!table.ok()) {
    if (error != nullptr) {
      *error = std::string("candidate table refused: ") + to_string(table.status().code()) + " " +
               table.status().message();
    }
    return nullptr;
  }
  rig->candidates = std::move(table).value();

  for (const auto& key : spec.fenced) {
    Result<FenceId> committed = rig->authority.commit_fence(mk_fence(key));
    if (!committed.ok()) {
      if (error != nullptr) {
        *error = std::string("fence refused: ") + to_string(committed.status().code());
      }
      return nullptr;
    }
  }
  return rig;
}

// ---------------------------------------------------------------------------------------------
// Plan scoring under the documented total order.
// ---------------------------------------------------------------------------------------------

struct PlanScore {
  std::size_t unresolved = 0;
  std::uint64_t cost = 0;
  std::size_t hops = 0;
};

PlanScore score_of(const ReconstructionPlan& plan) {
  PlanScore score;
  score.unresolved = plan.unresolved.size();
  score.cost = plan.total_cost();
  for (const auto& step : plan.restores) score.hops += step.hops.size();
  return score;
}

/// True when a is not worse than b under (unresolved, cost, hops).
bool no_worse(const PlanScore& a, const PlanScore& b) {
  if (a.unresolved != b.unresolved) return a.unresolved < b.unresolved;
  if (a.cost != b.cost) return a.cost < b.cost;
  return a.hops <= b.hops;
}

std::string score_text(const PlanScore& score) {
  return "unresolved=" + std::to_string(score.unresolved) + " cost=" + std::to_string(score.cost) +
         " hops=" + std::to_string(score.hops);
}

std::string spec_summary(const InstanceSpec& spec) {
  std::string out = "failed{";
  for (const auto& key : spec.failed) out += key.to_string() + " ";
  out += "} switches{";
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

/// Collects counterexamples so one systematic defect produces one readable failure line per
/// assertion class instead of thousands of identical ones.
class Findings {
 public:
  void note(const std::string& message) {
    count_ += 1;
    if (count_ <= 4) {
      if (!samples_.empty()) samples_ += " | ";
      samples_ += message;
    }
  }

  std::size_t count() const { return count_; }

  std::string report(const std::string& what) const {
    std::string out = std::to_string(count_) + " " + what;
    if (count_ > 4) out += " (first 4 shown)";
    out += ": ";
    out += samples_;
    return out;
  }

 private:
  std::size_t count_ = 0;
  std::string samples_;
};

// ---------------------------------------------------------------------------------------------
// Randomised SYNTHETIC instance generator: explicit seed, 1-3 failed generations, 2-6
// dependents, 1-4 alternatives each, small replacement capacity scores.
// ---------------------------------------------------------------------------------------------

struct RandomInstance {
  InstanceSpec spec;
};

RandomInstance random_instance(std::uint64_t seed) {
  Rng rng(seed);
  RandomInstance instance;
  InstanceSpec& spec = instance.spec;

  const std::size_t failed_count = 1 + static_cast<std::size_t>(rng.bounded(3));      // 1..3
  const std::size_t leaf_count = 1 + static_cast<std::size_t>(rng.bounded(2));        // 1..2
  const std::size_t replacement_count = 1 + static_cast<std::size_t>(rng.bounded(3)); // 1..3

  std::vector<SwitchKey> failed_keys;
  for (std::size_t index = 0; index < failed_count; ++index) {
    const SwitchKey key = skey(10 + index, 1);
    failed_keys.push_back(key);
    spec.switches.push_back(mk_switch(key, 100 + index, 100));
    spec.fenced.push_back(key);
    spec.failed.push_back(key);
  }
  std::vector<SwitchKey> leaf_keys;
  for (std::size_t index = 0; index < leaf_count; ++index) {
    const SwitchKey key = skey(20 + index, 1);
    leaf_keys.push_back(key);
    spec.switches.push_back(mk_switch(key, 110 + index, 100));
  }
  std::vector<SwitchKey> replacement_keys;
  for (std::size_t index = 0; index < replacement_count; ++index) {
    const SwitchKey key = skey(30 + index, 1);
    replacement_keys.push_back(key);
    // Small capacity scores, deliberately including zero: a replacement with no spare capacity
    // must never be used, and must be reported as a proven negative instead.
    const std::uint32_t capacity = static_cast<std::uint32_t>(rng.bounded(4));  // 0..3
    // Failure domains are drawn from a small pool so that same-domain replacements occur.
    const std::uint64_t domain = 100 + static_cast<std::uint64_t>(rng.bounded(5));
    spec.switches.push_back(mk_switch(key, domain, capacity));
  }

  // The pool every hop set is drawn from: a small set of generation-qualified switches.
  std::vector<SwitchKey> hop_pool = leaf_keys;
  hop_pool.insert(hop_pool.end(), replacement_keys.begin(), replacement_keys.end());
  hop_pool.insert(hop_pool.end(), failed_keys.begin(), failed_keys.end());

  const std::size_t dependent_count = 2 + static_cast<std::size_t>(rng.bounded(5));  // 2..6
  std::uint64_t next_evidence = 20000;
  for (std::size_t index = 0; index < dependent_count; ++index) {
    const std::uint64_t path_id = 100 + index;
    const DependentRef dependent = DependentRef::path(PathId(path_id));

    std::vector<SwitchKey> path_hops;
    for (const auto& key : failed_keys) {
      if (rng.coin()) path_hops.push_back(key);
    }
    if (path_hops.empty()) {
      path_hops.push_back(failed_keys[static_cast<std::size_t>(rng.bounded(failed_count))]);
    }
    // A dependent also traverses ordinary switches, so its invalidation is attributable to the
    // failed generations only.
    const SwitchKey extra = leaf_keys[static_cast<std::size_t>(rng.bounded(leaf_count))];
    if (std::find(path_hops.begin(), path_hops.end(), extra) == path_hops.end()) {
      path_hops.push_back(extra);
    }
    spec.paths.push_back(mk_path(path_id, path_hops));

    for (const auto& failed : path_hops) {
      if (std::find(failed_keys.begin(), failed_keys.end(), failed) == failed_keys.end()) continue;
      const std::size_t alternatives = 1 + static_cast<std::size_t>(rng.bounded(4));  // 1..4
      for (std::size_t alternative = 0; alternative < alternatives; ++alternative) {
        const std::size_t hop_count = 2 + static_cast<std::size_t>(rng.bounded(2));  // 2..3
        std::vector<SwitchKey> hops;
        for (std::size_t attempt = 0; attempt < hop_count; ++attempt) {
          const SwitchKey hop = hop_pool[static_cast<std::size_t>(rng.bounded(hop_pool.size()))];
          if (std::find(hops.begin(), hops.end(), hop) == hops.end()) hops.push_back(hop);
        }
        if (hops.empty()) hops.push_back(replacement_keys.front());
        const std::uint32_t cost = 1 + static_cast<std::uint32_t>(rng.bounded(8));  // 1..8
        const EvidenceSource source = rng.bounded(8) == 0 ? EvidenceSource::SwitchAgent
                                                          : EvidenceSource::SimulatedFixture;
        spec.candidates.push_back(
            mk_candidate(dependent, failed, hops, cost, next_evidence, source));
        next_evidence += 1;
      }
    }
  }
  return instance;
}

// ---------------------------------------------------------------------------------------------
// Hand-built instances with a hand-computed optimum.
// ---------------------------------------------------------------------------------------------

struct HandBuilt {
  const char* name;
  InstanceSpec spec;
  std::size_t expected_unresolved;
  std::uint64_t expected_cost;
  std::size_t expected_hops;
  PlanFeasibility expected_feasibility;
};

std::vector<HandBuilt> hand_built_instances() {
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey first_leaf = skey(21, 1);
  const SwitchKey cheap = skey(30, 1);
  const SwitchKey roomy = skey(31, 1);
  const SwitchKey contested = skey(32, 1);
  const SwitchKey separate = skey(33, 1);
  const SwitchKey dead = skey(34, 1);
  const SwitchKey another_failed = skey(11, 1);
  const DependentRef first = DependentRef::path(PathId(1));
  const DependentRef second = DependentRef::path(PathId(2));
  const DependentRef third = DependentRef::path(PathId(3));

  std::vector<HandBuilt> cases;

  // (a) One dependent, two admissible alternatives: the cheaper one wins.
  {
    HandBuilt built{"single_dependent_cheapest_wins", {}, 0, 2, 2, PlanFeasibility::ProvenFeasible};
    built.spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                           mk_switch(cheap, 3, 4), mk_switch(roomy, 4, 4)};
    built.spec.paths = {mk_path(1, {failed, leaf})};
    built.spec.candidates = {mk_candidate(first, failed, {leaf, roomy}, 5, 1),
                             mk_candidate(first, failed, {leaf, cheap}, 2, 2)};
    built.spec.failed = {failed};
    built.spec.fenced = {failed};
    cases.push_back(std::move(built));
  }

  // (b) One alternative is cheaper but its generation admits a single dependent. The optimum
  //     keeps both dependents: cost 5 + 2 = 7 over four hops.
  {
    HandBuilt built{"capacity_beats_cost", {}, 0, 7, 4, PlanFeasibility::ProvenFeasible};
    built.spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                           mk_switch(first_leaf, 3, 100), mk_switch(cheap, 4, 1),
                           mk_switch(roomy, 5, 4)};
    built.spec.paths = {mk_path(1, {failed, leaf}), mk_path(2, {failed, first_leaf})};
    built.spec.candidates = {mk_candidate(first, failed, {leaf, cheap}, 1, 1),
                             mk_candidate(first, failed, {leaf, roomy}, 5, 2),
                             mk_candidate(second, failed, {first_leaf, cheap}, 2, 3)};
    built.spec.failed = {failed};
    built.spec.fenced = {failed};
    cases.push_back(std::move(built));
  }

  // (c) Greedy-breaking: the cheapest alternative for PATH(1) is the only generation PATH(3)
  //     can use, so a complete assignment costs 2 + 1 + 1 = 4 over six hops.
  {
    HandBuilt built{"greedy_breaking", {}, 0, 4, 6, PlanFeasibility::ProvenFeasible};
    built.spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                           mk_switch(first_leaf, 3, 100), mk_switch(cheap, 4, 1),
                           mk_switch(contested, 5, 1), mk_switch(separate, 6, 1)};
    built.spec.paths = {mk_path(1, {failed, leaf}), mk_path(2, {failed, first_leaf}),
                        mk_path(3, {failed, leaf})};
    built.spec.candidates = {mk_candidate(first, failed, {leaf, contested}, 1, 1),
                             mk_candidate(first, failed, {leaf, cheap}, 2, 2),
                             mk_candidate(second, failed, {first_leaf, separate}, 1, 3),
                             mk_candidate(third, failed, {leaf, contested}, 1, 4)};
    built.spec.failed = {failed};
    built.spec.fenced = {failed};
    cases.push_back(std::move(built));
  }

  // (d) Two failed generations, one dependent traversing both: two independent demands, each
  //     with its own alternative. Cost 3 + 4 = 7 over four hops.
  {
    HandBuilt built{"two_roots", {}, 0, 7, 4, PlanFeasibility::ProvenFeasible};
    built.spec.switches = {mk_switch(failed, 1, 100), mk_switch(another_failed, 2, 100),
                           mk_switch(leaf, 3, 100), mk_switch(cheap, 4, 4),
                           mk_switch(roomy, 5, 4)};
    built.spec.paths = {mk_path(1, {failed, another_failed, leaf})};
    built.spec.candidates = {mk_candidate(first, failed, {leaf, cheap}, 3, 1),
                             mk_candidate(first, another_failed, {leaf, roomy}, 4, 2)};
    built.spec.failed = {failed, another_failed};
    built.spec.fenced = {failed, another_failed};
    cases.push_back(std::move(built));
  }

  // (e) Genuinely infeasible: every alternative names a generation with no spare capacity, so
  //     the optimum is one unresolved dependent and no restore step at all.
  {
    HandBuilt built{"certified_infeasible", {}, 1, 0, 0, PlanFeasibility::ProvenInfeasible};
    built.spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100),
                           mk_switch(dead, 3, 0)};
    built.spec.paths = {mk_path(1, {failed, leaf})};
    built.spec.candidates = {mk_candidate(first, failed, {leaf, dead}, 1, 1),
                             mk_candidate(first, failed, {leaf, dead}, 3, 2)};
    built.spec.failed = {failed};
    built.spec.fenced = {failed};
    cases.push_back(std::move(built));
  }

  return cases;
}

// ---------------------------------------------------------------------------------------------
// Differential loop.
// ---------------------------------------------------------------------------------------------

SFF_TEST(production_planner_is_never_worse_than_the_exhaustive_reference) {
  constexpr std::uint64_t kSeedBase = 0xd1ff0000ull;
  constexpr std::size_t kInstances = 2200;

  Findings worse_than_reference;
  Findings contradicted_infeasibility;
  Findings reference_not_deterministic;
  Findings production_refused;

  std::size_t exhausted_instances = 0;
  std::size_t infeasible_instances = 0;
  std::uint64_t reference_nodes = 0;
  std::size_t checked = 0;

  for (std::size_t index = 0; index < kInstances; ++index) {
    const std::uint64_t seed = kSeedBase + static_cast<std::uint64_t>(index) * 2654435761ull;
    const std::string tag = "seed=" + std::to_string(seed);
    const RandomInstance instance = random_instance(seed);

    std::string error;
    std::unique_ptr<Rig> rig = make_rig(instance.spec, &error);
    if (rig == nullptr) {
      production_refused.note(tag + " " + error + " instance=" + spec_summary(instance.spec));
      continue;
    }

    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    if (!produced.ok()) {
      production_refused.note(tag + " planning refused: " +
                              std::string(to_string(produced.status().code())) + " " +
                              produced.status().message() + " instance=" +
                              spec_summary(instance.spec));
      continue;
    }
    const ReconstructionPlan& plan = produced.value();

    const ReferenceSolution reference = solve_reference(rig->inputs(), rig->failed, kGenerousBudget);
    reference_nodes += reference.nodes_visited;
    if (reference.exhausted) exhausted_instances += 1;

    // Determinism: the same instance must give the same reference plan digest.
    const ReferenceSolution repeat = solve_reference(rig->inputs(), rig->failed, kGenerousBudget);
    reference_nodes += repeat.nodes_visited;
    if (repeat.plan.plan_digest != reference.plan.plan_digest ||
        repeat.nodes_visited != reference.nodes_visited || repeat.exhausted != reference.exhausted ||
        repeat.optimal_found != reference.optimal_found) {
      reference_not_deterministic.note(tag + " digest " + std::to_string(reference.plan.plan_digest) +
                                       " vs " + std::to_string(repeat.plan.plan_digest) +
                                       " nodes " + std::to_string(reference.nodes_visited) + " vs " +
                                       std::to_string(repeat.nodes_visited));
    }

    // The reference only claims optimality when it enumerated the whole space.
    if (reference.optimal_found != reference.exhausted) {
      reference_not_deterministic.note(tag + " optimal_found does not follow exhausted");
    }
    if (!reference.exhausted && reference.plan.feasibility == PlanFeasibility::ProvenInfeasible) {
      reference_not_deterministic.note(
          tag + " a truncated reference search reported ProvenInfeasible");
    }

    // The production plan must be no worse than the proven optimum.
    if (reference.optimal_found) {
      const PlanScore production_score = score_of(plan);
      const PlanScore reference_score = score_of(reference.plan);
      if (!no_worse(production_score, reference_score)) {
        worse_than_reference.note(tag + " production " + score_text(production_score) +
                                  " worse than reference " + score_text(reference_score) +
                                  " instance=" + spec_summary(instance.spec));
      }
    }

    // A proven infeasibility claim must never be contradicted by a plan the reference finds.
    if (plan.feasibility == PlanFeasibility::ProvenInfeasible) {
      infeasible_instances += 1;
      if (!reference.optimal_found || !reference.plan.restores.empty()) {
        contradicted_infeasibility.note(
            tag + " production claimed ProvenInfeasible while the reference restored " +
            std::to_string(reference.plan.restores.size()) + " dependents, instance=" +
            spec_summary(instance.spec));
      }
      for (const auto& entry : plan.unresolved) {
        if (!is_proven_negative(entry.reason)) {
          contradicted_infeasibility.note(tag + " ProvenInfeasible with a non-certifying reason " +
                                          std::string(to_string(entry.reason)));
        }
      }
    }

    // Whenever the reference could not conclude, the production planner must not convert that
    // absence of a solution into a proof that none exists.
    if (!reference.exhausted && plan.feasibility == PlanFeasibility::ProvenInfeasible) {
      contradicted_infeasibility.note(
          tag + " production claimed ProvenInfeasible while the reference reached its search limit");
    }
    checked += 1;
  }

  std::printf("reference differential: instances=%zu checked=%zu reference_exhausted=%zu "
              "production_infeasible=%zu reference_nodes=%llu\n",
              kInstances, checked, exhausted_instances, infeasible_instances,
              static_cast<unsigned long long>(reference_nodes));

  if (production_refused.count() != 0) {
    sfftest::fail(__FILE__, __LINE__, production_refused.report("instances could not be planned"));
  }
  if (reference_not_deterministic.count() != 0) {
    sfftest::fail(__FILE__, __LINE__,
                  reference_not_deterministic.report("reference solver inconsistencies"));
  }
  if (worse_than_reference.count() != 0) {
    sfftest::fail(__FILE__, __LINE__,
                  worse_than_reference.report("instances where production was worse than the "
                                              "exhaustive optimum"));
  }
  if (contradicted_infeasibility.count() != 0) {
    sfftest::fail(__FILE__, __LINE__,
                  contradicted_infeasibility.report("infeasibility claims contradicted by a plan"));
  }

  CHECK_EQ(checked, kInstances);
  CHECK_EQ(exhausted_instances, kInstances);
  CHECK_EQ(production_refused.count(), std::size_t{0});
  CHECK_EQ(reference_not_deterministic.count(), std::size_t{0});
  CHECK_EQ(worse_than_reference.count(), std::size_t{0});
  CHECK_EQ(contradicted_infeasibility.count(), std::size_t{0});
}

// ---------------------------------------------------------------------------------------------
// SearchLimitReached is never an infeasibility proof.
// ---------------------------------------------------------------------------------------------

SFF_TEST(a_search_limit_is_never_an_infeasibility_proof) {
  // Capacity is binding in these instances, so the production planner uses the same bounded
  // assignment search as the reference solver instead of the independent-per-demand fast path.
  const SwitchKey failed = skey(10, 1);
  const SwitchKey leaf = skey(20, 1);
  const SwitchKey shared = skey(30, 1);
  const SwitchKey other = skey(31, 1);

  InstanceSpec spec;
  spec.switches = {mk_switch(failed, 1, 100), mk_switch(leaf, 2, 100), mk_switch(shared, 3, 1),
                   mk_switch(other, 4, 1)};
  for (std::uint64_t index = 1; index <= 4; ++index) {
    spec.paths.push_back(mk_path(index, {failed, leaf}));
    spec.candidates.push_back(
        mk_candidate(DependentRef::path(PathId(index)), failed, {leaf, shared}, 1, 300 + index));
  }
  spec.candidates.push_back(
      mk_candidate(DependentRef::path(PathId(1)), failed, {leaf, other}, 2, 400));
  spec.failed = {failed};
  spec.fenced = {failed};

  std::string error;
  std::unique_ptr<Rig> rig = make_rig(spec, &error);
  CHECK(rig != nullptr);
  if (rig == nullptr) return;

  const std::uint64_t budgets[] = {1, 2, 3, 5, 8};
  std::uint64_t total_nodes = 0;
  for (const std::uint64_t budget : budgets) {
    const ReferenceSolution reference = solve_reference(rig->inputs(), rig->failed, budget);
    total_nodes += reference.nodes_visited;
    CHECK(!reference.exhausted);
    CHECK(!reference.optimal_found);
    CHECK_EQ(std::string(to_string(reference.outcome)), std::string("SEARCH_LIMIT_REACHED"));
    CHECK_EQ(reference.plan.feasibility, PlanFeasibility::SearchLimitReached);
    CHECK_NE(reference.plan.feasibility, PlanFeasibility::ProvenInfeasible);
    for (const auto& entry : reference.plan.unresolved) {
      CHECK(!is_proven_negative(entry.reason));
      CHECK_EQ(entry.reason, UnresolvedReason::SearchLimitReached);
    }

    // The very same bound applied to the production planner produces an explicit partial result
    // and never a claim that no solution exists.
    PlanInputs bounded = rig->inputs();
    bounded.limits.max_candidates_evaluated = static_cast<std::size_t>(budget);
    Result<ReconstructionPlan> produced = plan_reconstruction(bounded, rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) continue;
    CHECK_NE(produced.value().feasibility, PlanFeasibility::ProvenInfeasible);
    CHECK(produced.value().digest_valid());
    for (const auto& entry : produced.value().unresolved) {
      CHECK(!is_proven_negative(entry.reason));
    }
    if (!produced.value().unresolved.empty()) {
      CHECK_EQ(produced.value().feasibility, PlanFeasibility::SearchLimitReached);
    }
  }

  // With a generous budget the same instance is solved completely: the partial results above were
  // a property of the bound, not of the instance.
  const ReferenceSolution complete = solve_reference(rig->inputs(), rig->failed, kGenerousBudget);
  total_nodes += complete.nodes_visited;
  CHECK(complete.exhausted);
  CHECK(complete.optimal_found);
  CHECK_EQ(complete.plan.feasibility, PlanFeasibility::ProvenFeasible);
  // Two dependents are servable (one on the shared generation, one on the spare alternative) and
  // two are genuinely unservable, which the exhaustive solver proves.
  CHECK_EQ(complete.plan.restores.size(), std::size_t{2});
  CHECK_EQ(complete.plan.unresolved.size(), std::size_t{2});
  CHECK_EQ(complete.plan.total_cost(), std::uint64_t{3});
  for (const auto& entry : complete.plan.unresolved) {
    CHECK(is_proven_negative(entry.reason));
    CHECK_EQ(entry.reason, UnresolvedReason::CapacityExhausted);
  }
  std::printf("search limit differential: budgets=%zu nodes=%llu completed_cost=%llu\n",
              sizeof(budgets) / sizeof(budgets[0]),
              static_cast<unsigned long long>(total_nodes),
              static_cast<unsigned long long>(complete.plan.total_cost()));
}

// ---------------------------------------------------------------------------------------------
// Hand-computed optima, confirmed exhaustively.
// ---------------------------------------------------------------------------------------------

SFF_TEST(hand_computed_optima_are_confirmed_exhaustively) {
  std::size_t checked = 0;
  for (const HandBuilt& built : hand_built_instances()) {
    const std::string scope = std::string("hand-built instance ") + built.name;
    std::string error;
    std::unique_ptr<Rig> rig = make_rig(built.spec, &error);
    if (rig == nullptr) {
      sfftest::fail(__FILE__, __LINE__, scope + ": " + error);
      continue;
    }

    const ReferenceSolution reference = solve_reference(rig->inputs(), rig->failed, kGenerousBudget);
    CHECK(reference.exhausted);
    CHECK(reference.optimal_found);
    const PlanScore reference_score = score_of(reference.plan);
    CHECK_EQ(reference_score.unresolved, built.expected_unresolved);
    CHECK_EQ(reference_score.cost, built.expected_cost);
    CHECK_EQ(reference_score.hops, built.expected_hops);
    CHECK_EQ(reference.plan.feasibility, built.expected_feasibility);

    // Determinism on the same instance.
    const ReferenceSolution repeat = solve_reference(rig->inputs(), rig->failed, kGenerousBudget);
    CHECK_EQ(repeat.plan.plan_digest, reference.plan.plan_digest);
    CHECK_EQ(repeat.nodes_visited, reference.nodes_visited);

    // The production planner agrees with the exhaustive optimum on every component.
    Result<ReconstructionPlan> produced = plan_reconstruction(rig->inputs(), rig->failed);
    CHECK(produced.ok());
    if (!produced.ok()) continue;
    const PlanScore production_score = score_of(produced.value());
    CHECK_EQ(production_score.unresolved, built.expected_unresolved);
    CHECK_EQ(production_score.cost, built.expected_cost);
    CHECK_EQ(production_score.hops, built.expected_hops);
    CHECK_EQ(produced.value().feasibility, built.expected_feasibility);
    CHECK(produced.value().digest_valid());
    CHECK(no_worse(production_score, reference_score));
    // Every restore step moves the dependent off a failed generation and crosses no failed or
    // fenced generation.
    for (const auto& step : produced.value().restores) {
      for (const auto& hop : step.hops) {
        CHECK(std::find(built.spec.failed.begin(), built.spec.failed.end(), hop) ==
              built.spec.failed.end());
        CHECK(!rig->authority.is_fenced(hop));
      }
      CHECK_EQ(step.replacement, step.hops.front());
      CHECK(step.cost != 0);
    }
    checked += 1;
  }
  CHECK_EQ(checked, hand_built_instances().size());
  std::printf("hand-built optima: confirmed=%zu\n", checked);
}

}  // namespace

SFF_MAIN()
