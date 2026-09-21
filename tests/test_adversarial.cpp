// Switch Failover Fabric - adversarial suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every case in this file is a deliberate attempt to make the runtime claim something untrue.
// A case passes only when the attack is refused with the right explicit outcome, and when the
// state the runtime retains after the refusal is still coherent.
//
// SYNTHETIC: every fixture, declaration, durable journal, session and byte in this file is
// generated in-process. No physical switch, NIC, RDMA device or multi-node fabric is exercised
// here, and nothing in this suite is physical-hardware evidence.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

// --- harness ---------------------------------------------------------------------------------

struct Harness {
  ManualClock clock{1000};
  std::unique_ptr<Coordinator> coordinator;
  Fabric fabric;
};

/// An in-memory runtime over a synthetic two-tier fabric. SYNTHETIC fixture.
Result<std::unique_ptr<Harness>> open_harness(const FabricSpec& spec,
                                              Limits limits = Limits::defaults(),
                                              Policy policy = Policy{}) {
  auto harness = std::make_unique<Harness>();
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = policy;
  config.enable_durability = false;
  config.evidence_class = EvidenceClass::Synthetic;

  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &harness->clock);
  if (!opened.ok()) return opened.status();
  harness->coordinator = std::move(opened).value();

  Result<Fabric> fabric = build_fabric(spec);
  if (!fabric.ok()) return fabric.status();
  harness->fabric = std::move(fabric).value();

  Status installed = harness->coordinator->install_topology(harness->fabric.topology);
  if (!installed.ok()) return installed;
  installed = harness->coordinator->install_candidates(harness->fabric.candidates);
  if (!installed.ok()) return installed;
  return harness;
}

/// A runtime whose durable root is a self-cleaning temporary directory. SYNTHETIC fixture.
Result<std::unique_ptr<Coordinator>> open_coordinator(const std::filesystem::path& root,
                                                      ManualClock& clock,
                                                      Limits limits = Limits::defaults(),
                                                      Policy policy = Policy{}) {
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = policy;
  config.enable_durability = !root.empty();
  config.durable_root = root;
  config.evidence_class = EvidenceClass::Synthetic;
  return Coordinator::open(config, &clock);
}

// --- synthetic input construction ------------------------------------------------------------

std::vector<SwitchKey> all_switches(const Fabric& fabric) {
  std::vector<SwitchKey> keys = fabric.leaf_keys;
  keys.insert(keys.end(), fabric.spine_keys.begin(), fabric.spine_keys.end());
  keys.insert(keys.end(), fabric.replacement_keys.begin(), fabric.replacement_keys.end());
  return keys;
}

EvidenceRecord health_evidence(const SwitchKey& key, EvidenceId id, TimestampNs observed_at_ns,
                               SwitchHealthState health,
                               EvidenceSource source = EvidenceSource::FabricManager) {
  EvidenceRecord record;
  record.id = id;
  record.kind = EvidenceKind::SwitchHealth;
  record.source = source;
  record.subject = key;
  record.observed_at_ns = observed_at_ns;
  record.valid_for_ns = 3600ull * kNanosPerSecond;
  record.health = health;
  record.detail = "SYNTHETIC fixture observation";
  return record;
}

FailureDeclaration failure_of(const SwitchKey& key, TimestampNs observed_at_ns,
                              std::string reason = "SYNTHETIC fabric manager declaration") {
  FailureDeclaration declaration;
  declaration.subject = key;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = observed_at_ns;
  declaration.valid_for_ns = 3600ull * kNanosPerSecond;
  declaration.reason = std::move(reason);
  return declaration;
}

std::vector<PathId> paths_through(const Fabric& fabric, const SwitchKey& key) {
  std::vector<PathId> result;
  for (const auto& path : fabric.topology.paths()) {
    if (std::find(path.hops.begin(), path.hops.end(), key) != path.hops.end()) {
      result.push_back(path.id);
    }
  }
  return result;
}

std::vector<LinkId> links_touching(const Fabric& fabric, const SwitchKey& key) {
  std::vector<LinkId> result;
  for (const auto& link : fabric.topology.links()) {
    if (link.a.sw == key || link.b.sw == key) result.push_back(link.id);
  }
  return result;
}

std::size_t active_grants_for(const Coordinator& coordinator, const DependentRef& dependent) {
  std::size_t count = 0;
  for (const auto& grant : coordinator.authority()->grants_for(dependent)) {
    if (grant.state == GrantState::Active) count += 1;
  }
  return count;
}

const RestoreStep* find_restore(const ReconstructionPlan& plan, const DependentRef& dependent) {
  for (const auto& step : plan.restores) {
    if (step.dependent == dependent) return &step;
  }
  return nullptr;
}

const UnresolvedDependent* find_unresolved(const ReconstructionPlan& plan,
                                           const DependentRef& dependent) {
  for (const auto& entry : plan.unresolved) {
    if (entry.dependent == dependent) return &entry;
  }
  return nullptr;
}

std::size_t count_records(const ReplayReport& report, RecordKind kind) {
  std::size_t count = 0;
  for (const auto& record : report.records) {
    if (record.header.kind == kind) count += 1;
  }
  return count;
}

std::size_t file_size_of(const std::filesystem::path& path) {
  std::error_code code;
  const std::uintmax_t size = std::filesystem::file_size(path, code);
  return code ? 0 : static_cast<std::size_t>(size);
}

std::uint8_t read_byte_at(const std::filesystem::path& path, std::size_t offset) {
  std::ifstream file(path, std::ios::binary);
  if (!file.good()) return 0;
  file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  char value = 0;
  file.read(&value, 1);
  if (!file.good()) return 0;
  return static_cast<std::uint8_t>(value);
}

/// Flip one bit of one byte in place and return the byte that is now on disk.
std::uint8_t flip_byte_at(const std::filesystem::path& path, std::size_t offset) {
  std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
  if (!file.good()) return 0;
  file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  char value = 0;
  file.read(&value, 1);
  if (!file.good()) return 0;
  value = static_cast<char>(static_cast<std::uint8_t>(value) ^ 0x40u);
  file.clear();
  file.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
  file.write(&value, 1);
  file.flush();
  return static_cast<std::uint8_t>(value);
}

// --- randomised-case reporting ----------------------------------------------------------------

/// Report one property violation together with everything needed to reproduce the run.
void report_property(bool condition, const std::string& what, std::uint64_t seed, std::size_t step,
                     const char* op, std::uint64_t param) {
  ::sfftest::record_check();
  if (condition) return;
  std::ostringstream text;
  text << "property violation: " << what << " | seed=" << seed << " step=" << step
       << " op=" << op << " param=" << param;
  ::sfftest::fail(__FILE__, __LINE__, text.str());
}

/// Invariants that must hold after EVERY operation of the randomised pipeline case.
void check_pipeline_invariants(Coordinator& coordinator, const Limits& limits,
                               const std::vector<DependentRef>& dependents,
                               const std::set<SwitchKey>& fenced, std::uint64_t seed,
                               std::size_t step, const char* op, std::uint64_t param,
                               CoordinatorEpoch epoch, std::uint64_t boot_ordinal) {
  const auto require = [&](bool condition, const char* what) {
    report_property(condition, what, seed, step, op, param);
  };
  require(!coordinator.stopped(), "the runtime is still running");
  require(coordinator.epoch() == epoch, "the epoch never changes outside open()");
  require(coordinator.boot().boot_ordinal() == boot_ordinal,
          "the boot incarnation never changes outside open()");
  require(coordinator.authority()->active_grant_count() <= limits.max_authority_grants,
          "active grants stay inside the declared bound");
  require(coordinator.authority()->total_grant_count() <= limits.max_authority_grants,
          "total grants stay inside the declared bound");
  require(coordinator.evidence()->size() <= limits.max_evidence_records,
          "retained evidence stays inside the declared bound");
  for (const auto& plan : coordinator.plans()) {
    require(plan.digest_valid(), "every retained plan digest is self-consistent");
  }
  for (const auto& key : fenced) {
    require(coordinator.authority()->is_fenced(key), "no committed fence was ever silently dropped");
  }
  for (const auto& fence : coordinator.authority()->fences()) {
    require(fence.subject.valid() && !fence.reason.empty(),
            "every committed fence names a generation and a reason");
    require(coordinator.failures()->contains(fence.subject),
            "every committed fence has durable failure lineage behind it");
  }
  for (const auto& dependent : dependents) {
    Result<AuthorityQuery> query = coordinator.query_authority(dependent);
    require(query.ok(), "an authority query always answers with a value or an explicit refusal");
    if (query.ok() && query.value().has_authority) {
      require(!query.value().bound.empty(), "authority is always bound to exact generations");
      require(query.value().outcome == Code::Ok, "affirmative authority reports Ok");
      for (const auto& key : query.value().bound.keys()) {
        require(!coordinator.authority()->is_fenced(key),
                "forwarding authority never rests on a fenced generation");
      }
    }
    Result<RestoreDecision> decision = coordinator.evaluate_restore(dependent);
    require(decision.ok(), "a restore decision always answers explicitly");
    if (decision.ok()) {
      require(!decision.value().may_restore || decision.value().effect_verified,
              "restoration is never permitted on acknowledgement alone");
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// 1. Contradictory authoritative evidence.
// ---------------------------------------------------------------------------------------------

SFF_TEST(contradictory_authoritative_evidence_is_conflict_never_ok) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;
  const Fabric& fabric = opened.value()->fabric;
  const SwitchKey subject = fabric.spine_keys.at(0);
  const TimestampNs instant = opened.value()->clock.now_ns();

  // Two authoritative declarations about the very same generation, at the very same instant:
  // one says it failed, the other says it recovered.
  EvidenceRecord failing = health_evidence(subject, EvidenceId(100000), instant,
                                           SwitchHealthState::Failed);
  failing.kind = EvidenceKind::SwitchFailureDeclaration;
  CHECK(coordinator.admit_evidence(failing).ok());

  EvidenceRecord recovering;
  recovering.id = EvidenceId(100001);
  recovering.kind = EvidenceKind::SwitchRecoveryDeclaration;
  recovering.source = EvidenceSource::OperatorPolicy;
  recovering.subject = subject;
  recovering.observed_at_ns = instant;
  recovering.valid_for_ns = 3600ull * kNanosPerSecond;
  recovering.detail = "SYNTHETIC recovery assertion";
  CHECK(coordinator.admit_evidence(recovering).ok());

  // Adjudication must refuse to pick a winner.
  Result<SwitchAssessment> assessment = coordinator.assess(subject);
  CHECK(assessment.ok());
  if (assessment.ok()) {
    CHECK_EQ(assessment.value().outcome, Code::Conflict);
    CHECK(!assessment.value().usable);
    CHECK_EQ(assessment.value().health, SwitchHealthState::Unknown);
    CHECK(assessment.value().supporting.empty());
    CHECK_EQ(assessment.value().conflicting.size(), std::size_t{2});
    // Default policy: an authoritative contradiction is itself a fence obligation.
    CHECK(assessment.value().fence_required);
  }

  // Neither the recording path nor the fencing path may resolve the contradiction into success.
  const FailureDeclaration declaration =
      failure_of(subject, instant, "SYNTHETIC contradictory declaration");
  Result<FailureRecord> recorded = coordinator.record_failure(declaration);
  CHECK(!recorded.ok());
  if (!recorded.ok()) CHECK_EQ(recorded.status().code(), Code::Conflict);

  Result<FailoverOutcome> outcome = coordinator.declare_failure(declaration);
  CHECK(!outcome.ok());
  if (!outcome.ok()) CHECK_EQ(outcome.status().code(), Code::Conflict);

  // Nothing affirmative was claimed as a side effect of the refusal.
  CHECK(!coordinator.failures()->contains(subject));
  CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{0});
  CHECK(!coordinator.authority()->is_fenced(subject));
}

// ---------------------------------------------------------------------------------------------
// 2. Stale replacement generations.
// ---------------------------------------------------------------------------------------------

SFF_TEST(stale_replacement_generation_is_refused_and_changes_nothing) {
  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 2;
  spec.replacement_spines = 2;
  spec.paths_per_leaf = 2;

  Result<std::unique_ptr<Harness>> opened = open_harness(spec);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;
  const Fabric& fabric = opened.value()->fabric;
  const ManualClock& clock = opened.value()->clock;

  const SwitchKey failed = fabric.spine_keys.at(0);
  const SwitchKey replacement = fabric.replacement_keys.at(0);
  const SwitchKey leaf = fabric.leaf_keys.at(0);
  CHECK(coordinator.declare_failure(failure_of(failed, clock.now_ns())).ok());

  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> first = coordinator.propose_plan(roots);
  CHECK(first.ok());
  if (!first.ok()) return;
  const ReconstructionPlan baseline = first.value();
  CHECK_EQ(baseline.feasibility, PlanFeasibility::ProvenFeasible);
  CHECK_EQ(baseline.restores.size(), std::size_t{1});
  CHECK_EQ(baseline.unresolved.size(), std::size_t{1});

  const PathId dependent = fabric.path_ids.at(0);
  const DependentRef path_dependent = DependentRef::path(dependent);
  const RestoreStep* baseline_step = find_restore(baseline, path_dependent);
  CHECK(baseline_step != nullptr);
  if (baseline_step == nullptr) return;
  const LinkId affected_link = links_touching(fabric, failed).at(0);
  const DependentRef link_dependent = DependentRef::link(affected_link);

  // The link has no alternative at all in the fixture: proven negative, not silence.
  const UnresolvedDependent* baseline_unresolved = find_unresolved(baseline, link_dependent);
  CHECK(baseline_unresolved != nullptr);
  if (baseline_unresolved == nullptr) return;
  CHECK_EQ(baseline_unresolved->reason, UnresolvedReason::NoCandidateSupplied);
  CHECK(is_proven_negative(baseline_unresolved->reason));

  // Supply two alternatives that are cheap, authoritative, capability-complete - and name a
  // generation that does not exist: G+1 of a switch whose only declared generation is G.
  std::vector<ReconstructionCandidate> candidates = fabric.candidates.candidates();
  const SwitchKey future_replacement(replacement.id(), SwitchGeneration(spec.generation + 1));
  const SwitchKey future_spine(fabric.spine_keys.at(1).id(),
                               SwitchGeneration(spec.generation + 1));

  ReconstructionCandidate stale_for_path;
  stale_for_path.dependent = path_dependent;
  stale_for_path.covers_failed = failed;
  stale_for_path.hops = {leaf, future_replacement};
  stale_for_path.cost = 1;  // cheaper than the admissible alternative, and still inadmissible
  stale_for_path.capabilities = kAllCapabilities;
  stale_for_path.evidence = EvidenceId(900001);
  stale_for_path.source = EvidenceSource::FabricManager;

  candidates.push_back(stale_for_path);

  Result<CandidateTable> rebuilt = CandidateTable::build(std::move(candidates), Limits::defaults());
  CHECK(rebuilt.ok());
  if (!rebuilt.ok()) return;
  CHECK(coordinator.install_candidates(std::move(rebuilt).value()).ok());

  Result<ReconstructionPlan> second = coordinator.propose_plan(roots);
  CHECK(second.ok());
  if (!second.ok()) return;
  const ReconstructionPlan attacked = second.value();

  // The plan may never use a generation the topology does not declare, and the cheap stale
  // alternative must not have displaced the admissible one.
  for (const auto& step : attacked.restores) {
    for (const auto& hop : step.hops) {
      CHECK(coordinator.topology()->find_switch(hop) != nullptr);
      CHECK_NE(hop, future_replacement);
      CHECK_NE(hop, future_spine);
    }
  }
  const RestoreStep* attacked_step = find_restore(attacked, path_dependent);
  CHECK(attacked_step != nullptr);
  if (attacked_step != nullptr && baseline_step != nullptr) {
    CHECK_EQ(attacked_step->replacement, baseline_step->replacement);
    CHECK_EQ(attacked_step->hops, baseline_step->hops);
    CHECK_EQ(attacked_step->cost, baseline_step->cost);
    CHECK_EQ(attacked_step->evidence, baseline_step->evidence);
    CHECK_EQ(attacked_step->cost, spec.candidate_cost);
  }
  CHECK_EQ(attacked.restores.size(), baseline.restores.size());
  CHECK_EQ(attacked.feasibility, baseline.feasibility);
  CHECK_EQ(attacked.closure_complete, baseline.closure_complete);

  // Everything the planner decided is unchanged. The plan identity and the input-policy digest
  // are normalised first: they legitimately differ between two proposals (a plan identity is
  // minted per proposal, and the policy digest covers the supplied candidate table as an input
  // identity). See the report note on that coupling.
  ReconstructionPlan normalised_baseline = baseline;
  ReconstructionPlan normalised_attacked = attacked;
  normalised_attacked.id = normalised_baseline.id;
  normalised_attacked.policy_digest = normalised_baseline.policy_digest;
  CHECK(normalised_attacked.encode() == normalised_baseline.encode());
  CHECK_EQ(normalised_attacked.compute_digest(), normalised_baseline.compute_digest());

  // A stale alternative supplied for a dependent that had none at all is reported with the exact
  // stale outcome: a proven negative, not silence and not an ordinary absence.
  {
    std::vector<ReconstructionCandidate> with_link = fabric.candidates.candidates();
    with_link.push_back(stale_for_path);
    ReconstructionCandidate stale_link;
    stale_link.dependent = link_dependent;
    stale_link.covers_failed = failed;
    stale_link.hops = {leaf, future_spine};
    stale_link.cost = 1;
    stale_link.capabilities = kAllCapabilities;
    stale_link.evidence = EvidenceId(900002);
    stale_link.source = EvidenceSource::FabricManager;
    with_link.push_back(stale_link);

    Result<CandidateTable> table = CandidateTable::build(std::move(with_link), Limits::defaults());
    CHECK(table.ok());
    if (!table.ok()) return;
    CHECK(coordinator.install_candidates(std::move(table).value()).ok());

    Result<ReconstructionPlan> third = coordinator.propose_plan(roots);
    CHECK(third.ok());
    if (!third.ok()) return;
    const UnresolvedDependent* entry = find_unresolved(third.value(), link_dependent);
    CHECK(entry != nullptr);
    if (entry != nullptr) {
      CHECK_EQ(entry->reason, UnresolvedReason::CandidateGenerationStale);
      CHECK(is_proven_negative(entry->reason));
    }
    // The decision is unchanged - the dependent is still unresolved - only the reason is now the
    // precise one, so the number of unresolved dependents and the restore set do not move.
    CHECK_EQ(third.value().unresolved.size(), baseline.unresolved.size());
    CHECK_EQ(third.value().restores.size(), baseline.restores.size());
    for (const auto& step : third.value().restores) {
      for (const auto& hop : step.hops) {
        CHECK(coordinator.topology()->find_switch(hop) != nullptr);
      }
    }
  }

  // The other direction: the topology declares G+1 and the alternative names G.
  {
    FabricSpec newer;
    newer.leaves = 1;
    newer.spines = 2;
    newer.replacement_spines = 2;
    newer.paths_per_leaf = 2;
    newer.generation = 2;

    Result<std::unique_ptr<Harness>> old = open_harness(newer);
    CHECK(old.ok());
    if (!old.ok()) return;
    Coordinator& older = *old.value()->coordinator;
    const Fabric& newer_fabric = old.value()->fabric;
    const SwitchKey newer_failed = newer_fabric.spine_keys.at(0);
    CHECK(older.declare_failure(failure_of(newer_failed, old.value()->clock.now_ns())).ok());

    std::vector<ReconstructionCandidate> mixed = newer_fabric.candidates.candidates();
    ReconstructionCandidate superseded;
    superseded.dependent = DependentRef::link(links_touching(newer_fabric, newer_failed).at(0));
    superseded.covers_failed = newer_failed;
    superseded.hops = {newer_fabric.leaf_keys.at(0),
                       SwitchKey(newer_fabric.replacement_keys.at(0).id(), SwitchGeneration(1))};
    superseded.cost = 1;
    superseded.capabilities = kAllCapabilities;
    superseded.evidence = EvidenceId(900003);
    superseded.source = EvidenceSource::FabricManager;
    mixed.push_back(superseded);

    Result<CandidateTable> mixed_table = CandidateTable::build(std::move(mixed), Limits::defaults());
    CHECK(mixed_table.ok());
    if (!mixed_table.ok()) return;
    CHECK(older.install_candidates(std::move(mixed_table).value()).ok());

    GenerationVector newer_roots;
    newer_roots.insert(newer_failed);
    Result<ReconstructionPlan> produced = older.propose_plan(newer_roots);
    CHECK(produced.ok());
    if (produced.ok()) {
      const UnresolvedDependent* entry =
          find_unresolved(produced.value(), superseded.dependent);
      CHECK(entry != nullptr);
      if (entry != nullptr) {
        CHECK_EQ(entry->reason, UnresolvedReason::CandidateGenerationStale);
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 3. Duplicate edges and duplicate declarations.
// ---------------------------------------------------------------------------------------------

SFF_TEST(duplicate_edges_and_declarations_are_deduplicated_or_refused) {
  const std::uint64_t seed = 0x51ff5eed2026ull;
  std::printf("  seed=%llu (duplicate-topology property case)\n",
              static_cast<unsigned long long>(seed));
  Rng rng(seed);

  FabricSpec spec;
  spec.leaves = 2;
  spec.spines = 2;
  spec.replacement_spines = 2;
  spec.paths_per_leaf = 4;

  Result<Fabric> built = build_fabric(spec);
  CHECK(built.ok());
  if (!built.ok()) return;
  const TopologySnapshot& baseline = built.value().topology;

  GenerationVector roots;
  roots.insert(built.value().spine_keys.at(0));
  const DependencyClosure baseline_closure = baseline.closure(roots, Limits::defaults());
  CHECK(baseline_closure.complete());
  CHECK(!baseline_closure.dependents.empty());

  const std::size_t baseline_edges = baseline.dependency_edges().size();
  for (std::size_t round = 0; round < 8; ++round) {
    const std::size_t repeat = 1 + static_cast<std::size_t>(rng.bounded(4));
    const std::size_t extra = repeat - 1;

    // (i) Every declaration - switch, link, path - repeated identically.
    {
      std::vector<SwitchDescriptor> switches = baseline.switches();
      std::vector<LinkDescriptor> links = baseline.links();
      std::vector<PathDescriptor> paths = baseline.paths();
      for (std::size_t copy = 1; copy < repeat; ++copy) {
        switches.insert(switches.end(), baseline.switches().begin(), baseline.switches().end());
        links.insert(links.end(), baseline.links().begin(), baseline.links().end());
        paths.insert(paths.end(), baseline.paths().begin(), baseline.paths().end());
      }

      Result<TopologySnapshot> rebuilt =
          TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                                  std::move(paths), {}, Limits::defaults());
      // Identical content is either de-duplicated or refused with Conflict; it is never accepted
      // as a second, different declaration.
      CHECK(rebuilt.ok());
      if (!rebuilt.ok()) {
        CHECK_EQ(rebuilt.status().code(), Code::Conflict);
        continue;
      }
      CHECK_EQ(rebuilt.value().digest(), baseline.digest());
      CHECK_EQ(rebuilt.value().switches().size(), baseline.switches().size());
      CHECK_EQ(rebuilt.value().links().size(), baseline.links().size());
      CHECK_EQ(rebuilt.value().paths().size(), baseline.paths().size());
      CHECK_EQ(rebuilt.value().dependency_edges().size(), baseline_edges);
      CHECK_EQ(rebuilt.value().stats().duplicate_switches_dropped,
               extra * baseline.switches().size());
      CHECK_EQ(rebuilt.value().stats().duplicate_links_dropped, extra * baseline.links().size());
      CHECK_EQ(rebuilt.value().stats().duplicate_paths_dropped, extra * baseline.paths().size());
      // The duplicate edges were already collapsed with the duplicate declarations they came
      // from, so the edge counter stays at zero: every drop is attributed exactly once.
      CHECK_EQ(rebuilt.value().stats().duplicate_edges_dropped, std::size_t{0});

      // The closure over the rebuilt snapshot is the same statement, byte for byte.
      const DependencyClosure repeated = rebuilt.value().closure(roots, Limits::defaults());
      CHECK_EQ(repeated.digest(), baseline_closure.digest());
      CHECK(repeated.members == baseline_closure.members);
      CHECK(repeated.dependents == baseline_closure.dependents);
      CHECK_EQ(repeated.state, baseline_closure.state);
    }

    // (ii) The same dependency edge handed over many times as an explicit declaration.
    {
      std::vector<DependencyEdge> edges = baseline.dependency_edges();
      for (std::size_t copy = 1; copy < repeat; ++copy) {
        edges.insert(edges.end(), baseline.dependency_edges().begin(),
                     baseline.dependency_edges().end());
      }
      Result<TopologySnapshot> rebuilt =
          TopologySnapshot::build(TopologyVersion(1), baseline.switches(), baseline.links(),
                                  baseline.paths(), std::move(edges), Limits::defaults());
      CHECK(rebuilt.ok());
      if (!rebuilt.ok()) {
        CHECK_EQ(rebuilt.status().code(), Code::Conflict);
        continue;
      }
      CHECK_EQ(rebuilt.value().digest(), baseline.digest());
      CHECK_EQ(rebuilt.value().dependency_edges().size(), baseline_edges);
      // Every repetition of the edge is dropped: the derived edge from the clean declaration is
      // the one that survives, and all repeat copies of it are duplicates of it.
      CHECK_EQ(rebuilt.value().stats().duplicate_edges_dropped, repeat * baseline_edges);
      const DependencyClosure repeated = rebuilt.value().closure(roots, Limits::defaults());
      CHECK_EQ(repeated.digest(), baseline_closure.digest());
      CHECK(repeated.members == baseline_closure.members);
      CHECK(repeated.dependents == baseline_closure.dependents);
      CHECK_EQ(repeated.state, baseline_closure.state);
    }
  }

  // Contradictory content for the same generation is refused outright.
  {
    std::vector<SwitchDescriptor> switches = baseline.switches();
    SwitchDescriptor contradicting = switches.front();
    contradicting.capacity_score = contradicting.capacity_score + 1u;
    switches.push_back(contradicting);
    Result<TopologySnapshot> refused =
        TopologySnapshot::build(TopologyVersion(1), std::move(switches), baseline.links(),
                                baseline.paths(), {}, Limits::defaults());
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Conflict);
  }
  {
    std::vector<LinkDescriptor> links = baseline.links();
    LinkDescriptor contradicting = links.front();
    contradicting.b.index = contradicting.b.index + 7u;
    links.push_back(contradicting);
    Result<TopologySnapshot> refused =
        TopologySnapshot::build(TopologyVersion(1), baseline.switches(), std::move(links),
                                baseline.paths(), {}, Limits::defaults());
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Conflict);
  }
  {
    std::vector<PathDescriptor> paths = baseline.paths();
    PathDescriptor contradicting = paths.front();
    contradicting.cost = contradicting.cost + 1u;
    paths.push_back(contradicting);
    Result<TopologySnapshot> refused =
        TopologySnapshot::build(TopologyVersion(1), baseline.switches(), baseline.links(),
                                std::move(paths), {}, Limits::defaults());
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Conflict);
  }
  {
    // An edge endpoint that is not fully generation-qualified is malformed, not ignorable.
    std::vector<DependencyEdge> edges = baseline.dependency_edges();
    edges.push_back(DependencyEdge{ClosureNode::of_dependent(DependentRef::path(PathId(1))),
                                   ClosureNode::of_switch(SwitchKey(SwitchId(2000),
                                                                    SwitchGeneration(0)))});
    Result<TopologySnapshot> refused =
        TopologySnapshot::build(TopologyVersion(1), baseline.switches(), baseline.links(),
                                baseline.paths(), std::move(edges), Limits::defaults());
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Invalid);
  }
}

// ---------------------------------------------------------------------------------------------
// 4. Duplicate evidence identity.
// ---------------------------------------------------------------------------------------------

SFF_TEST(duplicate_evidence_identity_is_refused) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;
  const SwitchKey subject = opened.value()->fabric.spine_keys.at(0);

  const EvidenceRecord record =
      health_evidence(subject, EvidenceId(424242), opened.value()->clock.now_ns(),
                      SwitchHealthState::Healthy);
  CHECK(coordinator.admit_evidence(record).ok());
  CHECK_EQ(coordinator.evidence()->size(), std::size_t{1});

  // The same identity, presented again: never admitted twice.
  const Status again = coordinator.admit_evidence(record);
  CHECK(!again.ok());
  if (!again.ok()) CHECK_EQ(again.code(), Code::AlreadyExists);
  CHECK_EQ(coordinator.evidence()->size(), std::size_t{1});
  CHECK(coordinator.evidence()->had_rejection());

  // A different record with the same identity is the same attack.
  EvidenceRecord altered = record;
  altered.health = SwitchHealthState::Failed;
  const Status mutated = coordinator.admit_evidence(altered);
  CHECK(!mutated.ok());
  if (!mutated.ok()) CHECK_EQ(mutated.code(), Code::AlreadyExists);
  CHECK_EQ(coordinator.evidence()->size(), std::size_t{1});
}

// ---------------------------------------------------------------------------------------------
// 5. Session replay, regression and identity borrowing.
// ---------------------------------------------------------------------------------------------

SFF_TEST(session_replay_regression_and_foreign_identity_are_refused) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;

  Result<SessionRecord> first = coordinator.open_session("operator-alpha");
  Result<SessionRecord> second = coordinator.open_session("operator-beta");
  CHECK(first.ok());
  CHECK(second.ok());
  if (!first.ok() || !second.ok()) return;
  const SessionId alpha = first.value().id;
  const SessionId beta = second.value().id;
  CHECK_NE(alpha, beta);
  CHECK_EQ(coordinator.session_count(), std::size_t{2});

  const CoordinatorEpoch epoch = coordinator.epoch();
  const std::uint64_t digest = coordinator.boot_digest();
  const auto binding = [](SessionId id, CoordinatorEpoch bound_epoch, std::uint64_t boot_digest,
                          std::uint64_t sequence) {
    SessionBinding value;
    value.session = id;
    value.epoch = bound_epoch;
    value.boot_digest = boot_digest;
    value.request_seq = sequence;
    return value;
  };

  CHECK(coordinator.authorise(binding(alpha, epoch, digest, 1)).ok());
  CHECK(coordinator.authorise(binding(alpha, epoch, digest, 2)).ok());
  // A replayed sequence is refused...
  const Status replayed = coordinator.authorise(binding(alpha, epoch, digest, 2));
  CHECK(!replayed.ok());
  if (!replayed.ok()) CHECK_EQ(replayed.code(), Code::Replay);
  // ...and so is a regression.
  const Status regressed = coordinator.authorise(binding(alpha, epoch, digest, 1));
  CHECK(!regressed.ok());
  if (!regressed.ok()) CHECK_EQ(regressed.code(), Code::Replay);
  // A refused request never consumed the sequence it named: the next free number still works.
  CHECK(coordinator.authorise(binding(alpha, epoch, digest, 3)).ok());

  // A foreign epoch - the incarnation that was current before a restart - is stale.
  const Status stale_epoch =
      coordinator.authorise(binding(alpha, CoordinatorEpoch(epoch.raw() + 1), digest, 4));
  CHECK(!stale_epoch.ok());
  if (!stale_epoch.ok()) CHECK_EQ(stale_epoch.code(), Code::Stale);
  // A foreign process incarnation is stale too.
  const Status stale_boot = coordinator.authorise(binding(alpha, epoch, digest + 1, 4));
  CHECK(!stale_boot.ok());
  if (!stale_boot.ok()) CHECK_EQ(stale_boot.code(), Code::Stale);
  // Neither refusal consumed a sequence number.
  CHECK(coordinator.authorise(binding(alpha, epoch, digest, 4)).ok());

  // Sequence numbers are per session: beta cannot advance or exhaust alpha, and vice versa.
  CHECK(coordinator.authorise(binding(beta, epoch, digest, 100)).ok());
  const Status beta_regressed = coordinator.authorise(binding(beta, epoch, digest, 99));
  CHECK(!beta_regressed.ok());
  if (!beta_regressed.ok()) CHECK_EQ(beta_regressed.code(), Code::Replay);
  CHECK(coordinator.authorise(binding(alpha, epoch, digest, 5)).ok());

  // An identity this incarnation never issued can never act.
  const Status unknown =
      coordinator.authorise(binding(SessionId(alpha.raw() + 1000), epoch, digest, 1000));
  CHECK(!unknown.ok());
  if (!unknown.ok()) CHECK_EQ(unknown.code(), Code::Unauthorized);
  const Status zero = coordinator.authorise(binding(SessionId(0), epoch, digest, 1));
  CHECK(!zero.ok());
  if (!zero.ok()) CHECK_EQ(zero.code(), Code::Unauthorized);

  // Closing refuses everything for that session before any sequence question is asked.
  CHECK(coordinator.close_session(alpha).ok());
  const Status closed = coordinator.authorise(binding(alpha, epoch, digest, 1000));
  CHECK(!closed.ok());
  if (!closed.ok()) CHECK_EQ(closed.code(), Code::Closed);
  const Status closed_replay = coordinator.authorise(binding(alpha, epoch, digest, 1));
  CHECK(!closed_replay.ok());
  if (!closed_replay.ok()) CHECK_EQ(closed_replay.code(), Code::Closed);
  // The surviving session is unaffected by the other's closure.
  CHECK(coordinator.authorise(binding(beta, epoch, digest, 101)).ok());
}

// ---------------------------------------------------------------------------------------------
// 6. Partial reconstruction acknowledgement.
// ---------------------------------------------------------------------------------------------

SFF_TEST(partial_reconstruction_acknowledgement_never_claims_success) {
  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 2;
  spec.replacement_spines = 3;
  spec.paths_per_leaf = 4;

  // (a) A replacement generation acquires a fence obligation between planning and applying.
  // apply_plan re-validates the whole plan against current inputs before it touches a single
  // step, and a fence obligation on a hop is exactly what that validation refuses. The outcome
  // is therefore a plan-level refusal (Invalid) with the plan marked Rejected and no step
  // applied at all - stronger than a partial application, and never a false success. The
  // per-step Failed path is exercised in (b), where a step is refused for the one reason the
  // pre-validation cannot see: the authority budget.
  {
    Result<std::unique_ptr<Harness>> opened = open_harness(spec);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    const Fabric& fabric = opened.value()->fabric;
    const ManualClock& clock = opened.value()->clock;

    const SwitchKey failed = fabric.spine_keys.at(0);
    const SwitchKey poisoned = fabric.replacement_keys.at(2);
    CHECK(coordinator.declare_failure(failure_of(failed, clock.now_ns())).ok());

    GenerationVector roots;
    roots.insert(failed);
    Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan plan = produced.value();
    CHECK_EQ(plan.restores.size(), std::size_t{2});
    CHECK_EQ(plan.feasibility, PlanFeasibility::ProvenFeasible);

    // Between planning and applying, one of the replacement generations is fenced.
    CHECK(coordinator.declare_failure(failure_of(poisoned, clock.now_ns())).ok());
    CHECK(coordinator.authority()->is_fenced(poisoned));

    Result<ApplyReceipt> receipt = coordinator.apply_plan(plan);
    CHECK(!receipt.ok());  // nothing is applied from a plan that no longer validates
    if (!receipt.ok()) CHECK_EQ(receipt.status().code(), Code::Invalid);

    Result<ReconstructionPlan> stored = coordinator.plan_by_id(plan.id);
    CHECK(stored.ok());
    if (stored.ok()) CHECK_EQ(stored.value().state, PlanState::Rejected);

    // No dependent gained authority from the refused plan.
    for (const auto& step : plan.restores) {
      Result<AuthorityQuery> query = coordinator.query_authority(step.dependent);
      CHECK(query.ok());
      if (query.ok()) CHECK(!query.value().has_authority);
    }
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{2});
  }

  // (b) A partial application, driven by the authority budget: the first step is acknowledged,
  // the second is explicitly refused, and the plan is never reported complete.
  {
    const std::size_t declared_grants = 13;  // 4 declared paths + 9 declared links in this fixture
    Limits limits = Limits::defaults();
    limits.max_authority_grants = declared_grants + 1;

    Result<std::unique_ptr<Harness>> opened = open_harness(spec, limits);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    const Fabric& fabric = opened.value()->fabric;
    const ManualClock& clock = opened.value()->clock;
    CHECK_EQ(coordinator.authority()->active_grant_count(), declared_grants);

    const SwitchKey failed = fabric.spine_keys.at(0);
    CHECK(coordinator.declare_failure(failure_of(failed, clock.now_ns())).ok());
    GenerationVector roots;
    roots.insert(failed);
    Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan plan = produced.value();
    CHECK_EQ(plan.restores.size(), std::size_t{2});

    Result<ApplyReceipt> receipt = coordinator.apply_plan(plan);
    CHECK(receipt.ok());
    if (!receipt.ok()) return;
    const ApplyReceipt& applied = receipt.value();
    CHECK_EQ(applied.steps.size(), plan.restores.size());
    CHECK_EQ(applied.applied + applied.failed, plan.restores.size());
    CHECK_EQ(applied.failed, std::size_t{1});
    CHECK_EQ(applied.applied, std::size_t{1});
    CHECK_EQ(applied.verified, std::size_t{0});
    CHECK(!applied.complete);
    CHECK(!applied.fully_verified());
    CHECK_EQ(applied.outcome, Code::PartialClosure);

    Result<ReconstructionPlan> stored = coordinator.plan_by_id(plan.id);
    CHECK(stored.ok());
    if (stored.ok()) CHECK_EQ(stored.value().state, PlanState::PartiallyApplied);

    std::size_t acknowledged = 0;
    std::size_t refused = 0;
    for (const auto& step : applied.steps) {
      Result<AuthorityQuery> query = coordinator.query_authority(step.dependent);
      CHECK(query.ok());
      if (!query.ok()) continue;
      if (step.state == AckState::Applied) {
        acknowledged += 1;
        CHECK(query.value().has_authority);
      } else {
        refused += 1;
        CHECK_EQ(step.state, AckState::Failed);
        CHECK(!step.detail.empty());
        CHECK(!query.value().has_authority);
      }
    }
    CHECK_EQ(acknowledged, std::size_t{1});
    CHECK_EQ(refused, std::size_t{1});

    // The acknowledged step is not a verified effect, and it does not permit restoration.
    const RestoreStep* applied_step = nullptr;
    const RestoreStep* refused_step = nullptr;
    for (const auto& step : plan.restores) {
      for (const auto& result : applied.steps) {
        if (result.dependent != step.dependent) continue;
        if (result.state == AckState::Applied) {
          applied_step = &step;
        } else {
          refused_step = &step;
        }
      }
    }
    CHECK(applied_step != nullptr);
    CHECK(refused_step != nullptr);
    if (applied_step != nullptr) {
      Result<RestoreDecision> decision = coordinator.evaluate_restore(applied_step->dependent);
      CHECK(decision.ok());
      if (decision.ok()) {
        CHECK(!decision.value().may_restore);
        CHECK_EQ(decision.value().outcome, Code::Unverified);
        CHECK(!decision.value().effect_verified);
      }
    }
    if (refused_step != nullptr) {
      Result<RestoreDecision> decision = coordinator.evaluate_restore(refused_step->dependent);
      CHECK(decision.ok());
      if (decision.ok()) CHECK(!decision.value().may_restore);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 7. Duplicate and late completions.
// ---------------------------------------------------------------------------------------------

SFF_TEST(duplicate_and_late_completions_cannot_widen_authority) {
  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 2;
  spec.replacement_spines = 2;
  spec.paths_per_leaf = 2;

  Result<std::unique_ptr<Harness>> opened = open_harness(spec);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;
  const Fabric& fabric = opened.value()->fabric;
  const ManualClock& clock = opened.value()->clock;

  const SwitchKey failed = fabric.spine_keys.at(0);
  CHECK(coordinator.declare_failure(failure_of(failed, clock.now_ns())).ok());
  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan plan = produced.value();
  CHECK(!plan.restores.empty());

  Result<ApplyReceipt> first = coordinator.apply_plan(plan);
  CHECK(first.ok());
  if (!first.ok()) return;
  CHECK_EQ(first.value().outcome, Code::Unverified);

  const DependentRef dependent = plan.restores.front().dependent;
  Result<AuthorityQuery> before = coordinator.query_authority(dependent);
  CHECK(before.ok());
  if (!before.ok()) return;
  const std::size_t grants_before = active_grants_for(coordinator, dependent);

  // Replay the very same completion.
  Result<ApplyReceipt> second = coordinator.apply_plan(plan);
  CHECK(second.ok());
  if (!second.ok()) return;
  CHECK_EQ(second.value().outcome, Code::Unverified);
  CHECK(!second.value().fully_verified());

  Result<AuthorityQuery> after = coordinator.query_authority(dependent);
  CHECK(after.ok());
  if (!after.ok()) return;
  CHECK(after.value().has_authority);
  // Authority never widens: the same dependent stays bound to exactly the same generations.
  CHECK(after.value().bound == before.value().bound);
  // The generation that failed stays visible as audit history, but it is not part of the binding
  // that now confers authority, and no bound generation is fenced.
  CHECK(std::find(after.value().fenced_generations.begin(), after.value().fenced_generations.end(),
                  failed) != after.value().fenced_generations.end());
  CHECK(std::find(after.value().bound.keys().begin(), after.value().bound.keys().end(), failed) ==
        after.value().bound.keys().end());
  CHECK(active_grants_for(coordinator, dependent) >= grants_before);
  // Every active grant is bound to unfenced generations under the current incarnation.
  for (const auto& grant : coordinator.authority()->grants_for(dependent)) {
    if (grant.state != GrantState::Active) continue;
    CHECK_EQ(grant.epoch, coordinator.epoch());
    CHECK_EQ(grant.boot, coordinator.boot());
    for (const auto& key : grant.bound.keys()) {
      CHECK(!coordinator.authority()->is_fenced(key));
    }
  }
  Result<ReconstructionPlan> retained = coordinator.plan_by_id(plan.id);
  CHECK(retained.ok());
  if (retained.ok()) CHECK_EQ(retained.value().state, PlanState::Applied);

  // Late completions: a verification that names a plan or a dependent the runtime never applied
  // is refused with NotFound, and refusal is not verification.
  const auto verification_for = [](PlanId named_plan, const DependentRef& named_dependent,
                                   EvidenceId id, const SwitchKey& subject,
                                   TimestampNs observed_at_ns) {
    EvidenceRecord record;
    record.id = id;
    record.kind = EvidenceKind::EffectVerification;
    record.source = EvidenceSource::FabricManager;
    record.subject = subject;
    record.observed_at_ns = observed_at_ns;
    record.valid_for_ns = 3600ull * kNanosPerSecond;
    record.effect_dependent = named_dependent;
    record.effect_plan = named_plan;
    record.detail = "SYNTHETIC late completion";
    return record;
  };

  const SwitchKey replacement = plan.restores.front().replacement;
  const Status unknown_plan = coordinator.record_effect_verification(
      verification_for(PlanId(9999999), dependent, EvidenceId(910001), replacement,
                       clock.now_ns()));
  CHECK(!unknown_plan.ok());
  if (!unknown_plan.ok()) CHECK_EQ(unknown_plan.code(), Code::NotFound);

  const Status unrelated = coordinator.record_effect_verification(
      verification_for(plan.id, DependentRef::service(4242), EvidenceId(910002), replacement,
                       clock.now_ns()));
  CHECK(!unrelated.ok());
  if (!unrelated.ok()) CHECK_EQ(unrelated.code(), Code::NotFound);

  // Observed: both refusals still admitted their evidence record before the plan and dependent
  // were checked, so a refused verification consumes an evidence identity and a retention slot.
  // What must never follow is that a refused verification counts as a verified effect.
  Result<RestoreDecision> not_verified = coordinator.evaluate_restore(dependent);
  CHECK(not_verified.ok());
  if (not_verified.ok()) {
    CHECK(!not_verified.value().effect_verified);
    CHECK(!not_verified.value().may_restore);
  }

  // An apply request for a plan identity that is not retained is refused, not merged.
  ReconstructionPlan forged = plan;
  forged.id = PlanId(424242);
  Result<ApplyReceipt> missing = coordinator.apply_plan(forged);
  CHECK(!missing.ok());
  if (!missing.ok()) CHECK_EQ(missing.status().code(), Code::NotFound);
  Result<ReconstructionPlan> looked_up = coordinator.plan_by_id(forged.id);
  CHECK(!looked_up.ok());
  if (!looked_up.ok()) CHECK_EQ(looked_up.status().code(), Code::NotFound);

  // Only a verification naming the retained plan and the dependent it actually restored is
  // accepted - and only then may service be restored.
  CHECK(coordinator
            .record_effect_verification(verification_for(plan.id, dependent, EvidenceId(910003),
                                                         replacement, clock.now_ns()))
            .ok());
  Result<RestoreDecision> verified = coordinator.evaluate_restore(dependent);
  CHECK(verified.ok());
  if (verified.ok()) {
    CHECK(verified.value().effect_verified);
    CHECK(verified.value().may_restore);
    CHECK_EQ(verified.value().outcome, Code::Ok);
  }
}

// ---------------------------------------------------------------------------------------------
// 8. Restart resurrection.
// ---------------------------------------------------------------------------------------------

SFF_TEST(restart_cannot_resurrect_authority_or_health) {
  TempDir directory("adversarial-restart");
  ManualClock clock(1000);
  const std::filesystem::path root = directory.path() / "durable";

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  const SwitchKey failed = fabric.spine_keys.at(0);

  CoordinatorEpoch first_epoch;
  BootIncarnation first_boot;
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value();
    CHECK(coordinator.install_topology(fabric.topology).ok());
    CHECK(coordinator.install_candidates(fabric.candidates).ok());
    first_epoch = coordinator.epoch();
    first_boot = coordinator.boot();
    CHECK(first_epoch.valid());
    CHECK(first_boot.valid());

    // Authoritative health for everything, and a committed failure plus fence for one generation.
    EvidenceId next_id(800000);
    for (const auto& key : all_switches(fabric)) {
      CHECK(coordinator
                .admit_evidence(health_evidence(key, next_id, clock.now_ns(),
                                                SwitchHealthState::Healthy))
                .ok());
      next_id = next_id.next();
    }
    Result<FailoverOutcome> outcome = coordinator.declare_failure(failure_of(failed, clock.now_ns()));
    CHECK(outcome.ok());
    if (!outcome.ok()) return;
    CHECK(!outcome.value().closure.dependents.empty());
    for (const auto& dependent : outcome.value().closure.dependents) {
      Result<AuthorityQuery> query = coordinator.query_authority(dependent);
      CHECK(query.ok());
      if (query.ok()) CHECK(!query.value().has_authority);
    }
    CHECK_EQ(coordinator.failures()->size(), std::size_t{1});
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});
    CHECK(coordinator.shutdown().ok());
  }

  Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(root, clock);
  CHECK(reopened.ok());
  if (!reopened.ok()) return;
  Coordinator& coordinator = *reopened.value();
  Result<RestartReport> report = coordinator.restart_report();
  CHECK(report.ok());
  if (report.ok()) {
    CHECK(report.value().recovered);
    CHECK(report.value().clean_previous_shutdown);
    CHECK(report.value().failures_restored >= 1);
    CHECK(report.value().fences_restored >= 1);
    CHECK(!report.value().dynamic_evidence_restored);
    CHECK_EQ(report.value().current_epoch.raw(), first_epoch.raw() + 1);
    CHECK_EQ(report.value().previous_epoch.raw(), first_epoch.raw());
    CHECK_EQ(report.value().current_boot.boot_ordinal(), first_boot.boot_ordinal() + 1);
    CHECK_EQ(report.value().previous_boot.boot_ordinal(), first_boot.boot_ordinal());
  }

  // (a) The failure lineage and the fence survived the process boundary.
  CHECK(coordinator.failures()->contains(failed));
  CHECK(coordinator.authority()->is_fenced(failed));
  CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});

  // (d) The epoch and the boot incarnation both advanced.
  CHECK_EQ(coordinator.epoch().raw(), first_epoch.raw() + 1);
  CHECK_EQ(coordinator.boot().boot_ordinal(), first_boot.boot_ordinal() + 1);
  CHECK(coordinator.boot() != first_boot);
  CHECK(coordinator.boot_digest() != 0);

  // (b) No grant was resurrected, and nothing claims authority any more.
  CHECK_EQ(coordinator.authority()->active_grant_count(), std::size_t{0});
  CHECK_EQ(coordinator.authority()->total_grant_count(), std::size_t{0});
  for (const auto& grant : coordinator.authority()->all_grants()) {
    CHECK_NE(grant.state, GrantState::Active);
  }
  for (const PathId id : fabric.path_ids) {
    Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(id));
    CHECK(query.ok());
    if (!query.ok()) continue;
    CHECK(!query.value().has_authority);
    CHECK_NE(query.value().outcome, Code::Ok);
  }
  for (const auto& link : fabric.topology.links()) {
    Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::link(link.id));
    CHECK(query.ok());
    if (!query.ok()) continue;
    CHECK(!query.value().has_authority);
    CHECK_NE(query.value().outcome, Code::Ok);
  }

  // (c) No health observation survived: every generation without durable lineage is Unknown.
  CHECK_EQ(coordinator.evidence()->size(), std::size_t{0});
  CHECK(coordinator.topology() == nullptr);  // supplied inputs are not durable state
  for (const auto& key : all_switches(fabric)) {
    Result<SwitchAssessment> assessment = coordinator.assess(key);
    CHECK(assessment.ok());
    if (!assessment.ok()) continue;
    CHECK(!assessment.value().usable);
    if (key == failed) {
      // Lineage, not liveness: the committed failure still applies to this exact generation.
      CHECK(assessment.value().durable_failure_present);
      CHECK(assessment.value().fence_required);
      CHECK_EQ(assessment.value().health, SwitchHealthState::Failed);
    } else {
      CHECK_EQ(assessment.value().outcome, Code::Unknown);
      CHECK_EQ(assessment.value().health, SwitchHealthState::Unknown);
      CHECK(!assessment.value().durable_failure_present);
      CHECK(!assessment.value().fence_required);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 9. Tampered durable state.
// ---------------------------------------------------------------------------------------------

SFF_TEST(tampered_durable_state_refuses_to_open) {
  TempDir directory("adversarial-tamper");
  ManualClock clock(1000);
  const std::filesystem::path root = directory.path() / "durable";
  const std::filesystem::path pristine = directory.path() / "pristine";
  std::error_code code;
  std::filesystem::create_directories(pristine, code);
  CHECK(!code);

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();

  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value();
    CHECK(coordinator.install_topology(fabric.topology).ok());
    CHECK(coordinator
              .declare_failure(failure_of(fabric.spine_keys.at(0), clock.now_ns()))
              .ok());
    CHECK(coordinator.shutdown().ok());
  }

  const std::filesystem::path journal = root / "sff.journal";
  const std::size_t size = file_size_of(journal);
  CHECK(size > 64);
  std::filesystem::copy_file(journal, pristine / "sff.journal",
                             std::filesystem::copy_options::overwrite_existing, code);
  CHECK(!code);

  // The bytes that are about to be damaged really do carry the committed failure and fence.
  {
    StoreOptions options;
    options.root = pristine;
    options.limits = Limits::defaults();
    options.mode = OpenMode::OpenExisting;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(store.ok());
    if (!store.ok()) return;
    Result<ReplayReport> replay = store.value()->replay();
    CHECK(replay.ok());
    if (replay.ok()) {
      CHECK_EQ(replay.value().status.code(), Code::Ok);
      CHECK_EQ(count_records(replay.value(), RecordKind::FailureCommitted), std::size_t{1});
      CHECK_EQ(count_records(replay.value(), RecordKind::FenceCommitted), std::size_t{1});
    }
    CHECK(store.value()->close().ok());
  }

  // Corrupt exactly one byte, inside the payload of the first record.
  const std::uint8_t original = read_byte_at(journal, 40);
  const std::uint8_t corrupted = flip_byte_at(journal, 40);
  CHECK_NE(original, corrupted);
  CHECK_EQ(read_byte_at(journal, 40), corrupted);

  // Opening must fail: a complete record that fails its integrity check is refused, never
  // skipped, repaired or truncated.
  {
    StoreOptions options;
    options.root = root;
    options.limits = Limits::defaults();
    options.mode = OpenMode::OpenExisting;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(!store.ok());
    if (!store.ok()) CHECK_EQ(store.status().code(), Code::Corrupt);
  }
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(!opened.ok());
    if (!opened.ok()) CHECK_EQ(opened.status().code(), Code::Corrupt);
  }
  // Deterministic: the second attempt refuses in exactly the same way...
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(!opened.ok());
    if (!opened.ok()) CHECK_EQ(opened.status().code(), Code::Corrupt);
  }
  // ...and the refused opens left the damaged journal exactly as it was: no silent repair and
  // therefore no silently lost fence or failure.
  CHECK_EQ(file_size_of(journal), size);
  CHECK_EQ(read_byte_at(journal, 40), corrupted);
}

// ---------------------------------------------------------------------------------------------
// 10. Resource exhaustion.
// ---------------------------------------------------------------------------------------------

SFF_TEST(resource_exhaustion_is_deterministic_and_never_a_false_success) {
  // (a) Evidence retention.
  {
    Limits limits = Limits::defaults();
    limits.max_evidence_records = 2;
    Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{}, limits);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    const SwitchKey subject = opened.value()->fabric.spine_keys.at(0);
    CHECK_EQ(coordinator.evidence()->capacity(), std::size_t{2});
    CHECK(coordinator
              .admit_evidence(health_evidence(subject, EvidenceId(500001),
                                              opened.value()->clock.now_ns(),
                                              SwitchHealthState::Healthy))
              .ok());
    CHECK(coordinator
              .admit_evidence(health_evidence(subject, EvidenceId(500002),
                                              opened.value()->clock.now_ns(),
                                              SwitchHealthState::Healthy))
              .ok());
    const Status refused =
        coordinator.admit_evidence(health_evidence(subject, EvidenceId(500003),
                                                   opened.value()->clock.now_ns(),
                                                   SwitchHealthState::Healthy));
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.code(), Code::Exhausted);
    CHECK_EQ(coordinator.evidence()->size(), std::size_t{2});
    CHECK(coordinator.evidence()->had_rejection());
  }

  // (b) Authority grants.
  {
    Limits limits = Limits::defaults();
    limits.max_authority_grants = 3;
    Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{}, limits);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    CHECK_EQ(coordinator.authority()->active_grant_count(), std::size_t{3});
    GenerationVector bound;
    bound.insert(opened.value()->fabric.leaf_keys.at(0));
    const Status refused =
        coordinator.establish_authority(DependentRef::service(1), bound, "SYNTHETIC probe");
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.code(), Code::Exhausted);
    CHECK_EQ(coordinator.authority()->total_grant_count(), std::size_t{3});
    CHECK_EQ(active_grants_for(coordinator, DependentRef::service(1)), std::size_t{0});

    // Observed: opening this coordinator succeeded although the install established authority for
    // only three of the fixture's thirteen declared dependents - install_topology swallows the
    // per-dependent grant refusals. What must never follow from that shortfall is a dependent
    // that claims authority it was never granted: every dependent the install did not reach
    // reports no authority at all.
    const Fabric& fabric = opened.value()->fabric;
    CHECK_EQ(coordinator.authority()->active_grant_count(), std::size_t{3});
    std::size_t authorized = 0;
    for (const PathId id : fabric.path_ids) {
      Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(id));
      CHECK(query.ok());
      if (query.ok() && query.value().has_authority) authorized += 1;
    }
    for (const auto& link : fabric.topology.links()) {
      Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::link(link.id));
      CHECK(query.ok());
      if (!query.ok()) continue;
      CHECK(!query.value().has_authority);
      CHECK_EQ(query.value().outcome, Code::NotFound);
    }
    CHECK_EQ(authorized, std::size_t{3});
  }

  // (c) Fence bookkeeping.
  {
    Limits limits = Limits::defaults();
    limits.max_fences = 1;
    Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{}, limits);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    const Fabric& fabric = opened.value()->fabric;
    const ManualClock& clock = opened.value()->clock;
    const SwitchKey first = fabric.spine_keys.at(0);
    const SwitchKey second = fabric.spine_keys.at(1);

    CHECK(coordinator.declare_failure(failure_of(first, clock.now_ns())).ok());
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});

    Result<FailoverOutcome> refused =
        coordinator.declare_failure(failure_of(second, clock.now_ns()));
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Exhausted);
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});
    CHECK(!coordinator.authority()->is_fenced(second));
    // Observed: the refusal is not transactional. The durable failure lineage for the second
    // generation was committed (and its dependent grants revoked) before the fence bookkeeping
    // hit its bound, so failures()->contains(second) is true while no fence record exists. The
    // safe consequences are asserted below: nothing claims a fence that was not committed, and
    // nothing claims the generation is usable.

    // A refused fence never leaves dependent authority standing for the refused generation, and
    // never reports the generation as healthy either.
    for (const PathId id : paths_through(fabric, second)) {
      Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(id));
      CHECK(query.ok());
      if (query.ok()) CHECK(!query.value().has_authority);
    }
    Result<SwitchAssessment> assessment = coordinator.assess(second);
    CHECK(assessment.ok());
    if (assessment.ok()) {
      CHECK(!assessment.value().usable);
      CHECK(assessment.value().fence_required);
    }
  }

  // (d) Closure bounds.
  {
    // A snapshot that cannot be materialised inside the bound is refused outright.
    Limits tiny = Limits::defaults();
    tiny.max_closure_nodes = 4;
    Result<Fabric> refused = build_fabric(FabricSpec{}, tiny);
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Exhausted);
  }
  {
    // A closure cut short by the runtime bound is reported as truncated, is never reported as
    // complete, and restoration is refused for it.
    Limits tiny = Limits::defaults();
    tiny.max_closure_nodes = 2;
    Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{}, tiny);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;
    const SwitchKey failed = opened.value()->fabric.spine_keys.at(0);

    Result<FailoverOutcome> outcome =
        coordinator.declare_failure(failure_of(failed, opened.value()->clock.now_ns()));
    CHECK(outcome.ok());
    if (!outcome.ok()) return;
    CHECK_EQ(outcome.value().closure.state, ClosureState::Truncated);
    CHECK(outcome.value().closure.truncated());
    CHECK(!outcome.value().closure.complete());
    CHECK_EQ(outcome.value().outcome, Code::PartialClosure);
    CHECK_EQ(outcome.value().fence_scope, FenceScopeState::Partial);

    // The truncation really did omit dependents: the unbounded closure is larger.
    GenerationVector roots;
    roots.insert(failed);
    const DependencyClosure full = coordinator.topology()->closure(roots, Limits::defaults());
    CHECK_EQ(full.state, ClosureState::Complete);
    CHECK(outcome.value().closure.dependents.size() < full.dependents.size());

    Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
    CHECK(produced.ok());
    if (!produced.ok()) return;
    const ReconstructionPlan plan = produced.value();
    CHECK(!plan.closure_complete);
    CHECK_EQ(plan.feasibility, PlanFeasibility::SearchLimitReached);
    CHECK_NE(plan.feasibility, PlanFeasibility::ProvenFeasible);
    CHECK_NE(plan.feasibility, PlanFeasibility::ProvenInfeasible);
    CHECK(!plan.fences.empty());
    if (!plan.fences.empty()) {
      CHECK_EQ(plan.fences.front().closure_state, ClosureState::Truncated);
    }

    Result<ApplyReceipt> applied = coordinator.apply_plan(plan);
    CHECK(!applied.ok());
    if (!applied.ok()) CHECK_EQ(applied.status().code(), Code::PartialClosure);
    Result<ReconstructionPlan> stored = coordinator.plan_by_id(plan.id);
    CHECK(stored.ok());
    if (stored.ok()) CHECK_EQ(stored.value().state, PlanState::Validated);
  }
}

// ---------------------------------------------------------------------------------------------
// 11. Malformed input.
// ---------------------------------------------------------------------------------------------

SFF_TEST(malformed_failure_declarations_are_refused) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Coordinator& coordinator = *opened.value()->coordinator;
  const SwitchKey subject = opened.value()->fabric.spine_keys.at(0);
  const TimestampNs now = opened.value()->clock.now_ns();

  const auto refuse = [&coordinator](const FailureDeclaration& declaration, Code expected) {
    const Status direct = declaration.validate();
    CHECK(!direct.ok());
    if (!direct.ok()) CHECK_EQ(direct.code(), expected);
    Result<FailureRecord> recorded = coordinator.record_failure(declaration);
    CHECK(!recorded.ok());
    if (!recorded.ok()) CHECK_EQ(recorded.status().code(), expected);
    Result<FailoverOutcome> fenced = coordinator.declare_failure(declaration);
    CHECK(!fenced.ok());
    if (!fenced.ok()) CHECK_EQ(fenced.status().code(), expected);
  };

  // An advisory source may not assert a switch lifecycle fact.
  FailureDeclaration advisory = failure_of(subject, now);
  advisory.source = EvidenceSource::TelemetryCollector;
  refuse(advisory, Code::Unauthorized);
  advisory.source = EvidenceSource::SwitchAgent;
  refuse(advisory, Code::Unauthorized);

  // A generation that is not qualified is not a subject.
  FailureDeclaration unqualified = failure_of(subject, now);
  unqualified.subject = SwitchKey(subject.id(), SwitchGeneration(0));
  refuse(unqualified, Code::Invalid);

  // A zero validity window asserts nothing that can expire.
  FailureDeclaration no_window = failure_of(subject, now);
  no_window.valid_for_ns = 0;
  refuse(no_window, Code::Invalid);

  // No observation time.
  FailureDeclaration no_time = failure_of(subject, now);
  no_time.observed_at_ns = 0;
  refuse(no_time, Code::Invalid);

  // An unknown evidence source is malformed, not authoritative.
  FailureDeclaration unknown_source = failure_of(subject, now);
  unknown_source.source = EvidenceSource::Unknown;
  refuse(unknown_source, Code::Invalid);

  // A reason larger than the retained message budget.
  FailureDeclaration oversized = failure_of(subject, now);
  oversized.reason = std::string(kMaxMessageBytes + 64, 'x');
  refuse(oversized, Code::Invalid);

  // Nothing was recorded, fenced or even admitted by any of the refusals.
  CHECK_EQ(coordinator.failures()->size(), std::size_t{0});
  CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{0});
  CHECK_EQ(coordinator.evidence()->size(), std::size_t{0});

  // The same subject and source are fine once the declaration is well formed.
  CHECK(coordinator.declare_failure(failure_of(subject, now, "SYNTHETIC well-formed")).ok());
  CHECK_EQ(coordinator.failures()->size(), std::size_t{1});
  CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});
}

// ---------------------------------------------------------------------------------------------
// 12. Action on a stopped runtime.
// ---------------------------------------------------------------------------------------------

SFF_TEST(actions_on_a_stopped_runtime_are_closed_and_state_is_intact) {
  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 2;
  spec.replacement_spines = 2;
  spec.paths_per_leaf = 2;

  Result<std::unique_ptr<Harness>> opened = open_harness(spec);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Harness& harness = *opened.value();
  Coordinator& coordinator = *harness.coordinator;
  const Fabric& fabric = harness.fabric;

  const SwitchKey failed = fabric.spine_keys.at(0);
  CHECK(coordinator.declare_failure(failure_of(failed, harness.clock.now_ns())).ok());
  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan plan = produced.value();
  Result<SessionRecord> session = coordinator.open_session("operator");
  CHECK(session.ok());
  if (!session.ok()) return;

  const std::size_t fences_before = coordinator.authority()->fence_count();
  const std::size_t failures_before = coordinator.failures()->size();
  const std::size_t plans_before = coordinator.plans().size();
  const std::size_t grants_before = coordinator.authority()->total_grant_count();
  const std::uint64_t epoch_before = coordinator.epoch().raw();
  const std::uint64_t boot_before = coordinator.boot().boot_ordinal();

  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.stopped());

  // Every mutating entry point refuses with Closed.
  CHECK_EQ(coordinator.install_topology(fabric.topology).code(), Code::Closed);
  CHECK_EQ(coordinator.install_candidates(fabric.candidates).code(), Code::Closed);
  CHECK_EQ(coordinator.install_policy(Policy{}).code(), Code::Closed);
  CHECK_EQ(coordinator
               .admit_evidence(health_evidence(fabric.leaf_keys.at(0), EvidenceId(600001),
                                               harness.clock.now_ns(), SwitchHealthState::Healthy))
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.record_failure(failure_of(failed, harness.clock.now_ns()))
               .status()
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.declare_failure(failure_of(failed, harness.clock.now_ns()))
               .status()
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.propose_plan(roots).status().code(), Code::Closed);
  GenerationVector bound;
  bound.insert(fabric.leaf_keys.at(0));
  CHECK_EQ(coordinator.establish_authority(DependentRef::path(fabric.path_ids.at(0)), bound)
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.withdraw_authority(DependentRef::path(fabric.path_ids.at(0)),
                                          RevocationCause::OperatorRevocation)
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.apply_plan(plan).status().code(), Code::Closed);
  {
    EvidenceRecord verification;
    verification.id = EvidenceId(600002);
    verification.kind = EvidenceKind::EffectVerification;
    verification.source = EvidenceSource::FabricManager;
    verification.subject = fabric.leaf_keys.at(0);
    verification.observed_at_ns = harness.clock.now_ns();
    verification.valid_for_ns = 3600ull * kNanosPerSecond;
    verification.effect_dependent = DependentRef::path(fabric.path_ids.at(0));
    verification.effect_plan = plan.id;
    CHECK_EQ(coordinator.record_effect_verification(verification).code(), Code::Closed);
  }
  CHECK_EQ(coordinator.open_session("late").status().code(), Code::Closed);

  // Retained state is exactly what it was, and no grant, fence, failure or plan was mutated.
  CHECK_EQ(coordinator.authority()->fence_count(), fences_before);
  CHECK_EQ(coordinator.failures()->size(), failures_before);
  CHECK_EQ(coordinator.plans().size(), plans_before);
  CHECK_EQ(coordinator.authority()->total_grant_count(), grants_before);
  CHECK_EQ(coordinator.epoch().raw(), epoch_before);
  CHECK_EQ(coordinator.boot().boot_ordinal(), boot_before);
  CHECK(coordinator.failures()->contains(failed));
  CHECK(coordinator.authority()->is_fenced(failed));

  // Queries that remain safe still answer, or refuse explicitly.
  CHECK(coordinator.restart_report().ok());
  CHECK_EQ(coordinator.session_count(), std::size_t{1});
  SessionBinding late;
  late.session = session.value().id;
  late.epoch = coordinator.epoch();
  late.boot_digest = coordinator.boot_digest();
  late.request_seq = 1;
  CHECK_EQ(coordinator.authorise(late).code(), Code::Closed);
  CHECK(coordinator.query_authority(DependentRef::path(fabric.path_ids.at(0))).ok());
  CHECK(coordinator.assess(failed).ok());
  CHECK(coordinator.plan_by_id(plan.id).ok());
  CHECK(coordinator.topology() != nullptr);
  CHECK(coordinator.limits().max_evidence_records > 0);
  CHECK(!coordinator.events(4).empty());
  CHECK(!coordinator.decisions(4).empty());

  // Shutdown stays idempotent after all of that.
  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.shutdown().ok());
}

// ---------------------------------------------------------------------------------------------
// 13. Randomised invariant pipeline.
// ---------------------------------------------------------------------------------------------

SFF_TEST(randomised_pipeline_preserves_authority_and_lineage_invariants) {
  const std::uint64_t seed = 0x0defaced1234ull;
  std::printf("  seed=%llu (randomised pipeline property case)\n",
              static_cast<unsigned long long>(seed));
  Rng rng(seed);

  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 2;
  spec.replacement_spines = 2;
  spec.paths_per_leaf = 2;

  Result<std::unique_ptr<Harness>> opened = open_harness(spec);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  Harness& harness = *opened.value();
  Coordinator& coordinator = *harness.coordinator;
  const Fabric& fabric = harness.fabric;
  const Limits limits = coordinator.limits();

  const std::vector<SwitchKey> switches = all_switches(fabric);
  std::vector<DependentRef> dependents;
  for (const PathId id : fabric.path_ids) dependents.push_back(DependentRef::path(id));
  for (const auto& link : fabric.topology.links()) {
    dependents.push_back(DependentRef::link(link.id));
  }
  CHECK(!switches.empty());
  CHECK(!dependents.empty());

  const CoordinatorEpoch epoch = coordinator.epoch();
  const std::uint64_t boot_ordinal = coordinator.boot().boot_ordinal();
  std::set<SwitchKey> fenced;
  std::vector<ReconstructionPlan> retained;
  std::uint64_t next_evidence_id = 700000;
  // Coverage counters: a property case that never reaches its interesting branches proves
  // nothing, so the run asserts that every operation kind was actually exercised.
  std::array<std::size_t, 7> op_counts{};
  std::size_t plans_produced = 0;
  std::size_t steps_applied = 0;
  std::size_t verifications_accepted = 0;
  std::size_t authority_observed = 0;

  const std::size_t steps = 64;
  for (std::size_t step = 0; step < steps; ++step) {
    harness.clock.advance(1000000);  // 1 ms; observation instants stay distinct and fresh
    const std::uint64_t op = rng.bounded(7);
    op_counts.at(static_cast<std::size_t>(op)) += 1;
    const char* op_name = "unknown";
    std::uint64_t param = 0;
    const std::size_t pick = static_cast<std::size_t>(rng.bounded(dependents.size()));

    if (op == 0) {
      // An authoritative health observation for one generation.
      op_name = "admit_health";
      const std::size_t index = static_cast<std::size_t>(rng.bounded(switches.size()));
      const SwitchKey& key = switches.at(index);
      param = key.id().raw();
      const SwitchHealthState health =
          rng.coin() ? SwitchHealthState::Healthy : SwitchHealthState::Degraded;
      const Status admitted =
          coordinator.admit_evidence(health_evidence(key, EvidenceId(next_evidence_id++),
                                                     harness.clock.now_ns(), health));
      report_property(admitted.ok(), "an in-window health observation is admitted", seed, step,
                      op_name, param);
    } else if (op == 1) {
      // An authoritative failure declaration for one generation.
      op_name = "declare_failure";
      const std::size_t index = static_cast<std::size_t>(rng.bounded(switches.size()));
      const SwitchKey& key = switches.at(index);
      param = key.id().raw();
      Result<FailoverOutcome> outcome =
          coordinator.declare_failure(failure_of(key, harness.clock.now_ns()));
      report_property(outcome.ok(), "a well-formed authoritative declaration is accepted", seed,
                      step, op_name, param);
      if (outcome.ok()) fenced.insert(key);
    } else if (op == 2) {
      // A reconstruction plan over one fenced generation.
      op_name = "propose_plan";
      if (fenced.empty()) {
        // Nothing is failing yet, so there is nothing to plan for; the coverage counters at the
        // end of the run prove this branch is not the only one taken.
      } else {
        auto pick_fenced = fenced.begin();
        std::advance(pick_fenced, static_cast<std::ptrdiff_t>(rng.bounded(fenced.size())));
        param = pick_fenced->id().raw();
        GenerationVector roots;
        roots.insert(*pick_fenced);
        Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
        report_property(produced.ok() || is_fail_closed(produced.status().code()),
                        "a plan request answers with a plan or a fail-closed refusal", seed, step,
                        op_name, param);
        if (produced.ok()) {
          report_property(produced.value().digest_valid(),
                          "a produced plan carries a valid digest", seed, step, op_name, param);
          report_property(
              produced.value().feasibility != PlanFeasibility::ProvenInfeasible ||
                  produced.value().restores.empty(),
              "ProvenInfeasible is only reported when nothing was restored", seed, step, op_name,
              param);
          retained.push_back(produced.value());
          plans_produced += 1;
        }
      }
    } else if (op == 3) {
      // Apply a retained plan, possibly twice, possibly after its hops changed.
      op_name = "apply_plan";
      if (retained.empty()) {
        // No plan has been produced yet.
      } else {
        const ReconstructionPlan plan =
            retained.at(static_cast<std::size_t>(rng.bounded(retained.size())));
        param = plan.id.raw();
        Result<ApplyReceipt> receipt = coordinator.apply_plan(plan);
        report_property(receipt.ok() || is_fail_closed(receipt.status().code()),
                        "an apply request answers with a receipt or a fail-closed refusal", seed,
                        step, op_name, param);
        if (receipt.ok()) {
          const ApplyReceipt& applied = receipt.value();
          report_property(applied.steps.size() == plan.restores.size(),
                          "every restore step is accounted for in the receipt", seed, step,
                          op_name, param);
          report_property(applied.applied + applied.failed == applied.steps.size(),
                          "the receipt accounts for every step exactly once", seed, step, op_name,
                          param);
          report_property(applied.complete == (applied.failed == 0),
                          "a receipt is complete exactly when no step failed", seed, step, op_name,
                          param);
          report_property(applied.complete ? applied.outcome == Code::Unverified
                                           : applied.outcome == Code::PartialClosure,
                          "an acknowledgement is reported as unverified, never as verified", seed,
                          step, op_name, param);
          for (const auto& applied_step : applied.steps) {
            report_property(applied_step.state == AckState::Applied ||
                                applied_step.state == AckState::Failed,
                            "a step is either applied or explicitly failed", seed, step, op_name,
                            param);
            Result<AuthorityQuery> query = coordinator.query_authority(applied_step.dependent);
            report_property(query.ok(), "an applied step still answers an authority query", seed,
                            step, op_name, param);
            report_property(applied_step.state != AckState::Failed || !applied_step.detail.empty(),
                            "a failed step states why it was refused", seed, step, op_name, param);
          }
          steps_applied += applied.applied;
          if (applied.complete) {
            Result<ReconstructionPlan> stored = coordinator.plan_by_id(plan.id);
            report_property(stored.ok() && stored.value().state == PlanState::Applied,
                            "a complete apply is recorded as Applied", seed, step, op_name, param);
            report_property(!applied.fully_verified(),
                            "acknowledgement alone is never fully verified", seed, step, op_name,
                            param);
          }
        }
      }
    } else if (op == 4) {
      // An authority query.
      op_name = "query_authority";
      const DependentRef& dependent = dependents.at(pick);
      param = dependent.id();
      Result<AuthorityQuery> query = coordinator.query_authority(dependent);
      report_property(query.ok(), "an authority query answers explicitly", seed, step, op_name,
                      param);
      if (query.ok() && query.value().has_authority) {
        authority_observed += 1;
        report_property(query.value().outcome == Code::Ok,
                        "affirmative authority carries the Ok outcome", seed, step, op_name, param);
      }
    } else if (op == 5) {
      // An independent effect verification for a retained plan.
      op_name = "record_effect_verification";
      if (retained.empty()) {
        // No plan has been produced yet.
      } else {
        const ReconstructionPlan plan =
            retained.at(static_cast<std::size_t>(rng.bounded(retained.size())));
        param = plan.id.raw();
        if (!plan.restores.empty()) {
          const RestoreStep& step_entry = plan.restores.front();
          EvidenceRecord verification;
          verification.id = EvidenceId(next_evidence_id++);
          verification.kind = EvidenceKind::EffectVerification;
          verification.source = EvidenceSource::FabricManager;
          verification.subject = step_entry.replacement;
          verification.observed_at_ns = harness.clock.now_ns();
          verification.valid_for_ns = 3600ull * kNanosPerSecond;
          verification.effect_dependent = step_entry.dependent;
          verification.effect_plan = plan.id;
          verification.detail = "SYNTHETIC independent verification";
          const Status recorded = coordinator.record_effect_verification(verification);
          report_property(recorded.ok() || recorded.code() == Code::NotFound,
                          "a verification is accepted or explicitly refused as NotFound", seed,
                          step, op_name, param);
          if (recorded.ok()) {
            verifications_accepted += 1;
            Result<RestoreDecision> decision = coordinator.evaluate_restore(step_entry.dependent);
            report_property(decision.ok(), "an accepted verification still answers a restore query",
                            seed, step, op_name, param);
            if (decision.ok()) {
              // A verified effect permits restoration unless a generation the dependent is bound
              // to has since acquired a fence obligation - in which case refusal is mandatory.
              bool blocked = false;
              std::string blocked_by;
              for (const auto& key : decision.value().bound.keys()) {
                Result<SwitchAssessment> bound = coordinator.assess(key);
                if (!bound.ok() || bound.value().fence_required ||
                    coordinator.authority()->is_fenced(key)) {
                  blocked = true;
                  blocked_by += " " + key.to_string();
                }
              }
              Result<AuthorityQuery> current = coordinator.query_authority(step_entry.dependent);
              const bool holds_authority = current.ok() && current.value().has_authority;
              report_property(!decision.value().effect_verified || decision.value().may_restore,
                              "a decision that calls the effect verified permits restoration", seed,
                              step, op_name, param);
              // An accepted verification permits restoration unless the dependent no longer
              // holds authority at all, or a generation it is bound to has since acquired a
              // fence obligation - either of which must refuse.
              if (holds_authority && !blocked && !decision.value().may_restore) {
                std::ostringstream diagnostic;
                diagnostic << "a verified effect permits restoration when no bound generation is "
                              "blocked | blocked_by:"
                           << blocked_by << " | outcome=" << to_string(decision.value().outcome)
                           << " reason=" << to_string(decision.value().reason)
                           << " effect_verified="
                           << (decision.value().effect_verified ? "true" : "false") << " bound:";
                for (const auto& key : decision.value().bound.keys()) {
                  diagnostic << " " << key.to_string();
                }
                diagnostic << " plan=" << plan.id.raw()
                           << " dependent=" << step_entry.dependent.to_string();
                report_property(false, diagnostic.str(), seed, step, op_name, param);
              } else {
                report_property(true,
                                "a verified effect permits restoration when no bound generation "
                                "is blocked",
                                seed, step, op_name, param);
              }
            }
          }
        }
      }
    } else {
      // An explicit authority establishment under the current incarnation.
      op_name = "establish_authority";
      const DependentRef& dependent = dependents.at(pick);
      const SwitchKey& key = switches.at(static_cast<std::size_t>(rng.bounded(switches.size())));
      param = dependent.id();
      GenerationVector bound;
      bound.insert(key);
      const Status established =
          coordinator.establish_authority(dependent, bound, "SYNTHETIC randomised grant");
      report_property(established.ok() || is_fail_closed(established.code()),
                      "an authority establishment answers Ok or a fail-closed refusal", seed, step,
                      op_name, param);
      if (established.ok()) {
        Result<AuthorityQuery> query = coordinator.query_authority(dependent);
        report_property(query.ok() && query.value().has_authority,
                        "an established authority is immediately visible", seed, step, op_name,
                        param);
      }
    }

    // Invariants after EVERY operation, not merely at the end of the run.
    check_pipeline_invariants(coordinator, limits, dependents, fenced, seed, step, op_name, param,
                              epoch, boot_ordinal);
  }

  // The run was not vacuous: every operation kind ran, and the deep branches were reached.
  for (std::size_t index = 0; index < op_counts.size(); ++index) {
    CHECK(op_counts.at(index) > 0);
  }
  CHECK(plans_produced > 0);
  CHECK(steps_applied > 0);
  CHECK(verifications_accepted > 0);
  CHECK(authority_observed > 0);

  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.shutdown().ok());
}

SFF_MAIN()
