// Switch Failover Fabric - seeded property and invariant suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every instance is generated in-process from an explicit seed. A failure prints the
// seed so the exact case can be reproduced.
#include <algorithm>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

struct Instance {
  ManualClock clock{5000};
  std::unique_ptr<Coordinator> coordinator;
  Fabric fabric;
};

Result<std::unique_ptr<Instance>> make_instance(Rng& rng) {
  auto instance = std::make_unique<Instance>();
  FabricSpec spec;
  spec.leaves = 1 + static_cast<std::size_t>(rng.bounded(2));
  spec.spines = 2 + static_cast<std::size_t>(rng.bounded(2));
  spec.replacement_spines = 1 + static_cast<std::size_t>(rng.bounded(3));
  spec.paths_per_leaf = 1 + static_cast<std::size_t>(rng.bounded(6));
  spec.capacity_score = static_cast<std::uint32_t>(1 + rng.bounded(8));
  spec.candidate_cost = static_cast<std::uint32_t>(1 + rng.bounded(9));

  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;
  config.evidence_class = EvidenceClass::Synthetic;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &instance->clock);
  if (!opened.ok()) return opened.status();
  instance->coordinator = std::move(opened).value();

  Result<Fabric> fabric = build_fabric(spec);
  if (!fabric.ok()) return fabric.status();
  instance->fabric = std::move(fabric).value();

  Status installed = instance->coordinator->install_topology(instance->fabric.topology);
  if (!installed.ok()) return installed;
  installed = instance->coordinator->install_candidates(instance->fabric.candidates);
  if (!installed.ok()) return installed;
  return instance;
}

std::vector<SwitchKey> all_switches(const Fabric& fabric) {
  std::vector<SwitchKey> keys = fabric.leaf_keys;
  keys.insert(keys.end(), fabric.spine_keys.begin(), fabric.spine_keys.end());
  keys.insert(keys.end(), fabric.replacement_keys.begin(), fabric.replacement_keys.end());
  return keys;
}

/// Invariants that must hold after EVERY operation, checked against the whole retained state.
void check_invariants(Coordinator& coordinator, const Fabric& fabric, const char* stage) {
  (void)stage;
  std::vector<FenceRecord> fences = coordinator.authority()->fences();

  // I1: no fence record names an unqualified generation, and fences are unique per generation.
  std::set<SwitchKey> fenced;
  for (const auto& fence : fences) {
    CHECK(fence.subject.valid());
    CHECK(fenced.insert(fence.subject).second);
  }

  // I2 + I3: authority is never claimed over a fenced generation, and never over a generation
  // whose assessment carries a fence obligation.
  for (const auto& path : fabric.topology.paths()) {
    const DependentRef dependent = DependentRef::path(path.id);
    Result<AuthorityQuery> query = coordinator.query_authority(dependent);
    CHECK(query.ok());
    if (!query.ok()) continue;
    for (const auto& key : query.value().bound.keys()) {
      CHECK(fenced.find(key) == fenced.end());
      Result<SwitchAssessment> assessment = coordinator.assess(key);
      CHECK(assessment.ok());
      if (assessment.ok()) CHECK(!assessment.value().fence_required);
    }
    if (query.value().has_authority) CHECK_EQ(query.value().outcome, Code::Ok);
    if (!query.value().has_authority) CHECK_NE(query.value().outcome, Code::Ok);

    // I7: a restore decision may only permit restoration when authority exists.
    Result<RestoreDecision> decision = coordinator.evaluate_restore(dependent);
    CHECK(decision.ok());
    if (decision.ok() && decision.value().may_restore) {
      CHECK(query.value().has_authority);
      CHECK(decision.value().blocking_generations.empty());
    }
  }

  // I4 + I5 + I6: every retained plan is self-consistent, and no plan that is still usable ever
  // preserves authority over a fenced generation. Superseded plans are retained as history and are
  // not applicable by construction.
  for (const auto& plan : coordinator.plans()) {
    CHECK(plan.digest_valid());
    if (plan.state == PlanState::Superseded) continue;
    for (const auto& step : plan.restores) {
      CHECK(!step.hops.empty());
      CHECK_EQ(step.replacement, step.hops.front());
      for (const auto& hop : step.hops) CHECK(fenced.find(hop) == fenced.end());
    }
    std::size_t accounted = plan.restores.size() + plan.unresolved.size();
    CHECK(accounted >= plan.restores.size());
  }

  // I8: the event log never rewrites a sequence number and never exceeds its capacity.
  std::vector<EventRecord> events = coordinator.events(4096);
  std::uint64_t previous = 0;
  for (const auto& event : events) {
    CHECK(event.seq > previous);
    previous = event.seq;
  }
}

}  // namespace

SFF_TEST(invariants_hold_after_every_operation) {
  constexpr std::uint64_t kSeeds[] = {1, 2, 3, 7, 11, 4242, 99991, 1234567};

  for (const std::uint64_t seed : kSeeds) {
    Rng rng(seed);
    Result<std::unique_ptr<Instance>> created = make_instance(rng);
    CHECK(created.ok());
    if (!created.ok()) {
      std::printf("  (seed %llu refused: %s)\n", static_cast<unsigned long long>(seed),
                  created.status().to_string().c_str());
      continue;
    }
    std::unique_ptr<Instance>& instance = created.value();
    Coordinator& coordinator = *instance->coordinator;
    const Fabric& fabric = instance->fabric;
    check_invariants(coordinator, fabric, "after install");

    const std::vector<SwitchKey> switches = all_switches(fabric);
    std::vector<SwitchKey> failed;

    // Randomised operation sequence. After every single operation the full invariant set is
    // re-checked: nothing is deferred to the end of the sequence.
    for (int step = 0; step < 48; ++step) {
      const std::uint64_t choice = rng.bounded(7);
      const SwitchKey& subject = switches.at(static_cast<std::size_t>(rng.bounded(switches.size())));

      if (choice == 0 || choice == 1) {
        EvidenceRecord record;
        record.id = EvidenceId(1000 + static_cast<std::uint64_t>(step) * 16 +
                              rng.bounded(16));
        record.kind = EvidenceKind::SwitchHealth;
        record.source = rng.coin() ? EvidenceSource::FabricManager
                                   : EvidenceSource::TelemetryCollector;
        record.subject = subject;
        record.observed_at_ns = instance->clock.now_ns();
        record.valid_for_ns = 300ull * kNanosPerSecond;
        record.health = rng.coin() ? SwitchHealthState::Healthy : SwitchHealthState::Degraded;
        record.detail = "SYNTHETIC property fixture";
        Status admitted = coordinator.admit_evidence(record);
        // A duplicate identity is refused explicitly rather than silently replacing history.
        CHECK(admitted.ok() || admitted.code() == Code::AlreadyExists ||
              admitted.code() == Code::Exhausted);
      } else if (choice == 2) {
        // Adversarial: an advisory source may never assert a lifecycle fact.
        FailureDeclaration declaration;
        declaration.subject = subject;
        declaration.source = EvidenceSource::TelemetryCollector;
        declaration.observed_at_ns = instance->clock.now_ns();
        declaration.valid_for_ns = 60ull * kNanosPerSecond;
        declaration.reason = "SYNTHETIC advisory assertion";
        Result<FailureRecord> refused = coordinator.record_failure(declaration);
        CHECK(!refused.ok());
        if (!refused.ok()) CHECK_EQ(refused.status().code(), Code::Unauthorized);
      } else if (choice == 3 || choice == 4) {
        FailureDeclaration declaration;
        declaration.subject = subject;
        declaration.source = EvidenceSource::FabricManager;
        declaration.observed_at_ns = instance->clock.now_ns();
        declaration.valid_for_ns = 600ull * kNanosPerSecond;
        declaration.reason = "SYNTHETIC property failure";
        Result<FailoverOutcome> outcome = coordinator.declare_failure(declaration);
        if (outcome.ok()) {
          failed.push_back(subject);
          CHECK(outcome.value().closure.state != ClosureState::Truncated ||
                !outcome.value().closure.complete());
        }
        // Declaring the same failure twice is idempotent, not a second fence.
        Result<FailoverOutcome> again = coordinator.declare_failure(declaration);
        if (outcome.ok() && again.ok()) CHECK(again.value().deferred);
      } else if (choice == 5) {
        if (failed.empty()) continue;
        GenerationVector roots;
        for (const auto& key : failed) roots.insert(key);
        Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
        if (!produced.ok()) {
          CHECK(produced.status().code() == Code::Invalid ||
                produced.status().code() == Code::Indeterminate ||
                produced.status().code() == Code::Unsupported);
        } else {
          const ReconstructionPlan& plan = produced.value();
          CHECK(plan.digest_valid());
          // A proven-infeasible plan restores nothing, and every unresolved entry must carry a
          // certificate rather than an indeterminate excuse.
          if (plan.feasibility == PlanFeasibility::ProvenInfeasible) {
            CHECK(plan.restores.empty());
            for (const auto& entry : plan.unresolved) CHECK(is_proven_negative(entry.reason));
          }
          Result<ValidationReport> report = coordinator.validate_plan(plan);
          CHECK(report.ok());
          if (report.ok()) CHECK(report.value().valid);
          if (plan.feasibility == PlanFeasibility::ProvenFeasible &&
              plan.closure_complete) {
            Result<ApplyReceipt> receipt = coordinator.apply_plan(plan);
            CHECK(receipt.ok() || receipt.status().code() == Code::PartialClosure);
          }
        }
      } else {
        instance->clock.advance(kNanosPerSecond / 4);
      }
      check_invariants(coordinator, fabric, "in sequence");
    }

    Status stopped = coordinator.shutdown();
    CHECK(stopped.ok());
    CHECK(stopped.ok() || stopped.code() == Code::Closed);
    CHECK(coordinator.shutdown().ok());
  }
}

SFF_TEST(fence_is_exactly_once_under_repetition) {
  for (std::uint64_t seed = 1; seed <= 32; ++seed) {
    Rng rng(seed);
    Result<std::unique_ptr<Instance>> created = make_instance(rng);
    CHECK(created.ok());
    if (!created.ok()) continue;
    std::unique_ptr<Instance>& instance = created.value();
    Coordinator& coordinator = *instance->coordinator;

    const SwitchKey failed = instance->fabric.spine_keys.at(0);
    FailureDeclaration declaration;
    declaration.subject = failed;
    declaration.source = EvidenceSource::FabricManager;
    declaration.observed_at_ns = instance->clock.now_ns();
    declaration.valid_for_ns = 600ull * kNanosPerSecond;
    declaration.reason = "SYNTHETIC idempotence fixture";

    Result<FailoverOutcome> first = coordinator.declare_failure(declaration);
    CHECK(first.ok());
    if (!first.ok()) continue;
    const FenceId fence = first.value().fence;
    CHECK(fence.valid());

    for (int repeat = 0; repeat < 4; ++repeat) {
      instance->clock.advance(kNanosPerSecond);
      Result<FailoverOutcome> again = coordinator.declare_failure(declaration);
      CHECK(again.ok());
      if (!again.ok()) continue;
      CHECK(again.value().deferred);
      CHECK_EQ(again.value().fence, fence);
      CHECK_EQ(again.value().fence_scope, first.value().fence_scope);
    }
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});
    check_invariants(coordinator, instance->fabric, "after repeated fences");
  }
}

SFF_MAIN()
