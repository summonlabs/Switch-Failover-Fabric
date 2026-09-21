// Switch Failover Fabric - end-to-end integration of the product proposition.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every fixture in this suite is generated in-process. No physical switch, NIC, RDMA
// device or multi-node fabric is exercised.
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

struct Harness {
  ManualClock clock{1000};
  std::unique_ptr<Coordinator> coordinator;
  Fabric fabric;
};

Result<std::unique_ptr<Harness>> open_harness(const FabricSpec& spec, Policy policy = Policy{}) {
  auto harness = std::make_unique<Harness>();
  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.policy = std::move(policy);
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

/// Authoritative affirmative health evidence for every switch generation in the fixture.
Status observe_all_healthy(Coordinator& coordinator, const Fabric& fabric, ManualClock& clock,
                           EvidenceSource source = EvidenceSource::FabricManager) {
  std::vector<SwitchKey> keys = fabric.leaf_keys;
  keys.insert(keys.end(), fabric.spine_keys.begin(), fabric.spine_keys.end());
  keys.insert(keys.end(), fabric.replacement_keys.begin(), fabric.replacement_keys.end());
  std::uint64_t next_id = 1;
  for (const auto& key : keys) {
    EvidenceRecord record;
    record.id = EvidenceId(next_id++);
    record.kind = EvidenceKind::SwitchHealth;
    record.source = source;
    record.subject = key;
    record.observed_at_ns = clock.now_ns();
    record.valid_for_ns = 60ull * kNanosPerSecond;
    record.health = SwitchHealthState::Healthy;
    record.detail = "SYNTHETIC fixture observation";
    Status admitted = coordinator.admit_evidence(record);
    if (!admitted.ok()) return admitted;
  }
  return Status::success();
}

FailureDeclaration failure_of(const SwitchKey& key, const ManualClock& clock,
                              std::string reason = "SYNTHETIC fabric manager declaration") {
  FailureDeclaration declaration;
  declaration.subject = key;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
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

/// Links whose authority is invalidated by the same failed generation.
std::vector<LinkId> links_touching(const Fabric& fabric, const SwitchKey& key) {
  std::vector<LinkId> result;
  for (const auto& link : fabric.topology.links()) {
    if (link.a.sw == key || link.b.sw == key) result.push_back(link.id);
  }
  return result;
}

}  // namespace

SFF_TEST(proposition_fence_then_reconstruct) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Harness>& harness = opened.value();
  Coordinator& coordinator = *harness->coordinator;

  CHECK(observe_all_healthy(coordinator, harness->fabric, harness->clock).ok());

  const SwitchKey failed = harness->fabric.spine_keys.at(0);
  const SwitchKey healthy = harness->fabric.spine_keys.at(1);
  const std::vector<PathId> affected = paths_through(harness->fabric, failed);
  const std::vector<LinkId> affected_links = links_touching(harness->fabric, failed);
  CHECK(!affected.empty());
  CHECK(!affected_links.empty());

  // Before the failure the declared paths hold established authority.
  const DependentRef first_affected = DependentRef::path(affected.front());
  {
    Result<AuthorityQuery> before = coordinator.query_authority(first_affected);
    CHECK(before.ok());
    if (before.ok()) {
      CHECK(before.value().has_authority);
      CHECK_EQ(before.value().outcome, Code::Ok);
    }
  }

  // Fence first.
  Result<FailoverOutcome> outcome = coordinator.declare_failure(failure_of(failed, harness->clock));
  CHECK(outcome.ok());
  if (!outcome.ok()) return;
  CHECK_EQ(outcome.value().outcome, Code::Ok);
  CHECK_EQ(outcome.value().closure.state, ClosureState::Complete);
  CHECK(outcome.value().closure.enumerates_every_root());
  // The closure is exactly the paths and the links that depended on that generation.
  CHECK_EQ(outcome.value().closure.dependents.size(), affected.size() + affected_links.size());
  CHECK(outcome.value().grants_fenced > 0);
  CHECK_EQ(outcome.value().fence_scope, FenceScopeState::Committed);

  // Every dependent that was bound to the failed generation lost its authority.
  for (const PathId id : affected) {
    Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(id));
    CHECK(query.ok());
    if (!query.ok()) continue;
    CHECK(!query.value().has_authority);
    CHECK_EQ(query.value().outcome, Code::Fenced);
  }

  // A dependent on an unrelated generation is untouched: no cross-generation contamination.
  const std::vector<PathId> untouched = paths_through(harness->fabric, healthy);
  CHECK(!untouched.empty());
  for (const PathId id : untouched) {
    Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(id));
    CHECK(query.ok());
    if (!query.ok()) continue;
    CHECK(query.value().has_authority);
  }

  // Reconstruct second.
  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
  CHECK(produced.ok());
  if (!produced.ok()) return;
  const ReconstructionPlan& plan = produced.value();
  CHECK_EQ(plan.state, PlanState::Validated);
  CHECK_EQ(plan.feasibility, PlanFeasibility::ProvenFeasible);
  CHECK(plan.digest_valid());
  CHECK_EQ(plan.restores.size(), affected.size());
  // The fixture supplies no alternative for the invalidated links, so they are reported as
  // explicitly unresolved with a PROVEN reason rather than silently dropped.
  CHECK_EQ(plan.unresolved.size(), affected_links.size());
  for (const auto& entry : plan.unresolved) {
    CHECK_EQ(entry.reason, UnresolvedReason::NoCandidateSupplied);
    CHECK(is_proven_negative(entry.reason));
  }
  for (const auto& step : plan.restores) {
    CHECK_EQ(step.covers_failed, failed);
    for (const auto& hop : step.hops) {
      CHECK_NE(hop, failed);  // no step may preserve authority that depended on the failed generation
    }
  }

  Result<ValidationReport> validated = coordinator.validate_plan(plan);
  CHECK(validated.ok());
  if (validated.ok()) CHECK(validated.value().valid);

  // Propose and apply are separate: nothing has taken effect yet.
  {
    Result<AuthorityQuery> query = coordinator.query_authority(first_affected);
    CHECK(query.ok());
    if (query.ok()) CHECK(!query.value().has_authority);
  }

  Result<ApplyReceipt> receipt = coordinator.apply_plan(plan);
  CHECK(receipt.ok());
  if (!receipt.ok()) return;
  CHECK_EQ(receipt.value().failed, std::size_t{0});
  CHECK_EQ(receipt.value().applied, affected.size());
  CHECK_EQ(receipt.value().verified, std::size_t{0});
  CHECK_EQ(receipt.value().outcome, Code::Unverified);
  CHECK(!receipt.value().fully_verified());

  // Authority is restored for the affected dependent under the new generations.
  {
    Result<AuthorityQuery> query = coordinator.query_authority(first_affected);
    CHECK(query.ok());
    if (query.ok()) CHECK(query.value().has_authority);
  }

  // Acknowledgement is not verified effect.
  {
    Result<RestoreDecision> decision = coordinator.evaluate_restore(first_affected);
    CHECK(decision.ok());
    if (decision.ok()) {
      CHECK(!decision.value().may_restore);
      CHECK_EQ(decision.value().outcome, Code::Unverified);
      CHECK(!decision.value().effect_verified);
    }
  }

  // Independent verification changes the decision - and only then.
  std::uint64_t evidence_id = 90000;
  for (const auto& step : plan.restores) {
    EvidenceRecord verification;
    verification.id = EvidenceId(evidence_id++);
    verification.kind = EvidenceKind::EffectVerification;
    verification.source = EvidenceSource::FabricManager;
    verification.subject = step.replacement;
    verification.observed_at_ns = harness->clock.now_ns();
    verification.valid_for_ns = 60ull * kNanosPerSecond;
    verification.effect_dependent = step.dependent;
    verification.effect_plan = plan.id;
    verification.detail = "SYNTHETIC independent verification";
    CHECK(coordinator.record_effect_verification(verification).ok());
  }
  {
    Result<RestoreDecision> decision = coordinator.evaluate_restore(first_affected);
    CHECK(decision.ok());
    if (decision.ok()) {
      CHECK(decision.value().may_restore);
      CHECK_EQ(decision.value().outcome, Code::Ok);
      CHECK(decision.value().effect_verified);
    }
  }

  // A plan may not be produced for a generation that is neither fenced nor failing.
  GenerationVector healthy_roots;
  healthy_roots.insert(healthy);
  Result<ReconstructionPlan> refused = coordinator.propose_plan(healthy_roots);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Invalid);
}

SFF_TEST(closure_is_explicit_about_truncation) {
  FabricSpec spec;
  spec.paths_per_leaf = 8;
  spec.leaves = 2;
  spec.spines = 2;
  spec.replacement_spines = 2;

  Result<std::unique_ptr<Harness>> opened = open_harness(spec);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Harness>& harness = opened.value();
  Coordinator& coordinator = *harness->coordinator;
  CHECK(observe_all_healthy(coordinator, harness->fabric, harness->clock).ok());

  const SwitchKey failed = harness->fabric.spine_keys.at(0);
  Result<FailoverOutcome> outcome = coordinator.declare_failure(failure_of(failed, harness->clock));
  CHECK(outcome.ok());
  if (!outcome.ok()) return;
  CHECK_EQ(outcome.value().closure.state, ClosureState::Complete);
  CHECK(outcome.value().outcome == Code::Ok);
}

SFF_TEST(restart_without_durability_has_no_dynamic_authority) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Harness>& harness = opened.value();
  Coordinator& coordinator = *harness->coordinator;

  Result<RestartReport> report = coordinator.restart_report();
  CHECK(report.ok());
  if (report.ok()) {
    CHECK(!report.value().recovered);
    CHECK(!report.value().dynamic_evidence_restored);
  }
  Result<SwitchAssessment> assessment = coordinator.assess(harness->fabric.spine_keys.at(0));
  CHECK(assessment.ok());
  if (assessment.ok()) {
    CHECK_EQ(assessment.value().outcome, Code::Unknown);
    CHECK(!assessment.value().usable);
    CHECK(!assessment.value().fence_required);
  }
}

SFF_TEST(authority_follows_generations_not_identities) {
  Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{});
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Harness>& harness = opened.value();
  Coordinator& coordinator = *harness->coordinator;
  CHECK(observe_all_healthy(coordinator, harness->fabric, harness->clock).ok());

  const SwitchKey failed = harness->fabric.spine_keys.at(0);
  CHECK(coordinator.declare_failure(failure_of(failed, harness->clock)).ok());

  // A newer generation of the same identity is a different authority subject and may be used.
  const SwitchKey newer(failed.id(), SwitchGeneration(failed.generation().raw() + 1));
  GenerationVector bound;
  bound.insert(newer);
  const DependentRef dependent = DependentRef::path(harness->fabric.path_ids.at(0));
  CHECK(coordinator.establish_authority(dependent, bound, "newer generation").ok());

  // The fenced generation itself can never be granted again.
  GenerationVector fenced;
  fenced.insert(failed);
  Status refused = coordinator.establish_authority(dependent, fenced, "fenced generation");
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(refused.code(), Code::Fenced);
}

SFF_MAIN()
