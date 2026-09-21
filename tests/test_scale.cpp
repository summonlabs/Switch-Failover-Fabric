// Switch Failover Fabric - scale and work-accounting proof.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC fixtures. The proof is deliberately built on exact WORK COUNTERS rather than on wall
// clock time: a work counter cannot be fooled by a fast machine, and it is what actually proves the
// traversal is linear rather than accidentally quadratic.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

struct ScaleResult {
  std::size_t dependents = 0;
  std::size_t members = 0;
  std::size_t edges_examined = 0;
  std::size_t restores = 0;
  std::size_t unresolved = 0;
  std::size_t search_nodes = 0;
  double closure_ms = 0.0;
  double plan_ms = 0.0;
  double apply_ms = 0.0;
  bool ok = false;
};

ScaleResult run_scale(std::size_t paths) {
  ScaleResult result;
  ManualClock clock(1000);

  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 4;
  spec.replacement_spines = 4;
  spec.paths_per_leaf = paths;
  // Capacity is deliberately generous here: the point of this suite is traversal and assignment
  // cost, not capacity pressure. Capacity-constrained search is proven in the planner suite.
  spec.capacity_score = 100000000u;

  Result<Fabric> fabric = build_fabric(spec);
  if (!fabric.ok()) return result;
  Fabric built = std::move(fabric).value();

  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;
  config.evidence_class = EvidenceClass::Synthetic;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  if (!opened.ok()) return result;
  std::unique_ptr<Coordinator>& coordinator = opened.value();

  if (!coordinator->install_topology(built.topology).ok()) return result;
  if (!coordinator->install_candidates(built.candidates).ok()) return result;

  const SwitchKey failed = built.spine_keys.at(0);
  FailureDeclaration declaration;
  declaration.subject = failed;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = 3600ull * kNanosPerSecond;
  declaration.reason = "SYNTHETIC scale failure";

  const auto closure_started = std::chrono::steady_clock::now();
  Result<FailoverOutcome> outcome = coordinator->declare_failure(declaration);
  const auto closure_finished = std::chrono::steady_clock::now();
  if (!outcome.ok()) return result;
  result.closure_ms = std::chrono::duration<double, std::milli>(closure_finished - closure_started).count();
  result.dependents = outcome.value().closure.dependents.size();
  result.members = outcome.value().closure.members.size();
  result.edges_examined = outcome.value().closure.edges_examined;

  GenerationVector roots;
  roots.insert(failed);
  const auto plan_started = std::chrono::steady_clock::now();
  Result<ReconstructionPlan> plan = coordinator->propose_plan(roots);
  const auto plan_finished = std::chrono::steady_clock::now();
  if (!plan.ok()) return result;
  result.plan_ms = std::chrono::duration<double, std::milli>(plan_finished - plan_started).count();
  result.restores = plan.value().restores.size();
  result.unresolved = plan.value().unresolved.size();

  const auto apply_started = std::chrono::steady_clock::now();
  Result<ApplyReceipt> receipt = coordinator->apply_plan(plan.value());
  const auto apply_finished = std::chrono::steady_clock::now();
  if (!receipt.ok()) return result;
  result.apply_ms = std::chrono::duration<double, std::milli>(apply_finished - apply_started).count();
  result.ok = true;
  return result;
}

}  // namespace

SFF_TEST(thousands_of_dependents_scale_linearly) {
  const std::vector<std::size_t> sizes = {2000, 8000, 32000};
  std::vector<ScaleResult> results;
  results.reserve(sizes.size());
  for (const std::size_t size : sizes) {
    ScaleResult result = run_scale(size);
    CHECK(result.ok);
    if (!result.ok) return;

    // The failed generation is one of four spines, so a quarter of the paths traverse it. Every
    // such path contributes itself and its two hops to the member set; the dependent set is exactly
    // those paths plus the links that terminate on the failed generation.
    const std::size_t expected_paths = size / 4;  // path_index % 4 == 0 maps onto spine 0 of 4
    CHECK_EQ(result.restores, expected_paths);
    // Exactly one declared link terminates on the failed generation, and the fixture supplies no
    // alternative for links, so it is reported as an explicitly unresolved dependent.
    CHECK_EQ(result.unresolved, std::size_t{1});
    CHECK_EQ(result.dependents, expected_paths + 1);
    std::printf(
        "  scale paths=%zu dependents=%zu members=%zu edges_examined=%zu restores=%zu "
        "unresolved=%zu closure_ms=%.3f plan_ms=%.3f apply_ms=%.3f\n",
        size, result.dependents, result.members, result.edges_examined, result.restores,
        result.unresolved, result.closure_ms, result.plan_ms, result.apply_ms);
    results.push_back(result);
  }

  // Work accounting: the traversal examines exactly two reverse edges per traversed path plus the
  // edges of the two affected links. Doubling the input must double the work - a quadratic
  // traversal would quadruple it.
  for (std::size_t index = 1; index < results.size(); ++index) {
    const std::size_t previous = sizes[index - 1];
    const std::size_t current = sizes[index];
    const double input_ratio = static_cast<double>(current) / static_cast<double>(previous);
    const double edge_ratio = static_cast<double>(results[index].edges_examined) /
                              static_cast<double>(std::max<std::size_t>(1, results[index - 1].edges_examined));
    CHECK_LT(edge_ratio, input_ratio * 1.25);
  }

  // Per-element closure time must not grow with the size of the input. A quadratic traversal would
  // multiply it by the input ratio; a generous 4x allowance keeps this robust on a loaded machine
  // while still failing loudly on accidental O(N^2) behaviour.
  const double smallest_per_element =
      results.front().closure_ms / static_cast<double>(sizes.front());
  const double largest_per_element =
      results.back().closure_ms / static_cast<double>(sizes.back());
  CHECK_LT(largest_per_element, std::max(1e-5, smallest_per_element * 4.0));
}

SFF_TEST(retained_state_stays_bounded) {
  ManualClock clock(1000);
  FabricSpec spec;
  spec.leaves = 1;
  spec.spines = 4;
  spec.replacement_spines = 4;
  spec.paths_per_leaf = 4000;
  spec.capacity_score = 100000000u;

  Result<Fabric> fabric = build_fabric(spec);
  CHECK(fabric.ok());
  if (!fabric.ok()) return;
  Fabric built = std::move(fabric).value();

  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;
  config.event_capacity = 512;
  config.decision_capacity = 256;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Coordinator>& coordinator = opened.value();
  CHECK(coordinator->install_topology(built.topology).ok());
  CHECK(coordinator->install_candidates(built.candidates).ok());

  // Produce far more plans and events than the retention bounds allow.
  for (int round = 0; round < 40; ++round) {
    const SwitchKey failed = built.spine_keys.at(static_cast<std::size_t>(round % 4));
    FailureDeclaration declaration;
    declaration.subject = failed;
    declaration.source = EvidenceSource::FabricManager;
    declaration.observed_at_ns = clock.now_ns() + static_cast<std::uint64_t>(round) + 1;
    declaration.valid_for_ns = 3600ull * kNanosPerSecond;
    declaration.reason = "SYNTHETIC bounded retention";
    Result<FailoverOutcome> outcome = coordinator->declare_failure(declaration);
    if (outcome.ok()) {
      GenerationVector roots;
      roots.insert(failed);
      (void)coordinator->propose_plan(roots);
    }
    clock.advance(kNanosPerSecond);
  }

  CHECK(coordinator->events(100000).size() <= 512);
  CHECK(coordinator->decisions(100000).size() <= 256);
  // Plan retention is bounded by the policy, not by the number of proposals.
  CHECK(coordinator->plans().size() <= coordinator->policy().max_retained_plans);
  CHECK(coordinator->authority()->fence_count() <= Limits::defaults().max_fences);
  const std::size_t grants = coordinator->authority()->total_grant_count();
  CHECK(grants <= Limits::defaults().max_authority_grants);
  std::printf("  bounded retention: grants=%zu fences=%zu events=%zu decisions=%zu\n", grants,
              coordinator->authority()->fence_count(), coordinator->events(100000).size(),
              coordinator->decisions(100000).size());
}

SFF_TEST(exhausted_bounds_refuse_rather_than_degrade) {
  ManualClock clock(1000);
  FabricSpec spec;
  spec.leaves = 2;
  spec.spines = 4;
  spec.replacement_spines = 1;
  spec.paths_per_leaf = 6000;
  spec.capacity_score = 100000000u;

  Result<Fabric> fabric = build_fabric(spec);
  CHECK(fabric.ok());
  if (!fabric.ok()) return;
  Fabric built = std::move(fabric).value();

  Limits limits = Limits::defaults();
  limits.max_closure_nodes = 100;  // far below the number of reachable dependents
  CoordinatorConfig config;
  config.limits = limits;
  config.enable_durability = false;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Coordinator>& coordinator = opened.value();
  CHECK(coordinator->install_topology(built.topology).ok());
  CHECK(coordinator->install_candidates(built.candidates).ok());

  const SwitchKey failed = built.spine_keys.at(0);
  FailureDeclaration declaration;
  declaration.subject = failed;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = 3600ull * kNanosPerSecond;
  declaration.reason = "SYNTHETIC truncation";
  Result<FailoverOutcome> outcome = coordinator->declare_failure(declaration);
  CHECK(outcome.ok());
  if (!outcome.ok()) return;

  // The bound was hit, so the closure must SAY so and the fence must be scoped as partial. A short
  // closure must never be presented as a complete one.
  CHECK(outcome.value().closure.truncated());
  CHECK(!outcome.value().closure.complete());
  CHECK(outcome.value().closure.omitted_frontier > 0);
  CHECK_EQ(outcome.value().fence_scope, FenceScopeState::Partial);
  CHECK_EQ(outcome.value().outcome, Code::PartialClosure);

  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> plan = coordinator->propose_plan(roots);
  CHECK(plan.ok());
  if (plan.ok()) {
    CHECK(!plan.value().closure_complete);
    CHECK_NE(plan.value().feasibility, PlanFeasibility::ProvenFeasible);
    Result<ApplyReceipt> receipt = coordinator->apply_plan(plan.value());
    CHECK(!receipt.ok());
    if (!receipt.ok()) CHECK_EQ(receipt.status().code(), Code::PartialClosure);
  }
}

SFF_MAIN()
