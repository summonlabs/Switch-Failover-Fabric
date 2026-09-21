// Switch Failover Fabric - independent plan validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: the instance below is constructed in-process. No physical switch, NIC or multi-node
// fabric is involved.
//
// The proposition under test: a plan is only ever accepted when an independent re-derivation from
// the inputs confirms every one of its claims. A plan that has been re-sealed so its digest is
// self-consistent must still be refused when a single semantic claim is false.
//
// Test shape: accept tampering one at a time. Every mutant is re-sealed so that the digest check
// passes and only the specific semantic check listed in the case name can catch it.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/generation.hpp"
#include "sff/model/switch.hpp"
#include "sff/model/topology.hpp"
#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"
#include "sff/plan/validator.hpp"

#include "test_support.hpp"

using namespace sff;

namespace {

SwitchKey key_of(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

bool restore_order_less(const RestoreStep& left, const RestoreStep& right) {
  if (left.dependent != right.dependent) return left.dependent < right.dependent;
  if (left.covers_failed != right.covers_failed) return left.covers_failed < right.covers_failed;
  return left.replacement < right.replacement;
}

/// The canonical restore-step order the validator enforces, applied after a mutation.
void canonicalise_restores(ReconstructionPlan& plan) {
  std::sort(plan.restores.begin(), plan.restores.end(), restore_order_less);
}

/// One synthetic instance, owned in place so that the borrowed pointers inside PlanInputs stay
/// valid for the whole test.
struct Instance {
  Instance() : evidence(limits, &clock) {}
  Instance(const Instance&) = delete;
  Instance& operator=(const Instance&) = delete;

  ManualClock clock{1000000};
  Limits limits = Limits::defaults();
  EvidenceStore evidence;
  FailureTable failures;
  AuthorityRegistry authority{Limits::defaults()};
  TopologySnapshot topology;
  TopologySnapshot other_topology;
  CandidateTable candidates;
  CoordinatorEpoch epoch{1};
  BootIncarnation boot = BootIncarnation::from_parts(4242, 7, 0xabcdu, 0xef01u);
  PlanId plan_id{1};

  const SwitchKey failed = key_of(100, 1);            ///< The failed generation.
  const SwitchKey replacement = key_of(200, 1);       ///< The one admissible replacement (capacity 1).
  const SwitchKey fenced_switch = key_of(300, 1);     ///< Present in the topology, fenced in the registry.
  const SwitchKey newer_generation = key_of(400, 5);  ///< Only generation 5 is installed.
  const SwitchKey absent = key_of(999, 1);            ///< No such identity in the topology.
  const DependentRef path_one = DependentRef::path(PathId(1));
  const DependentRef path_two = DependentRef::path(PathId(2));

  Status build();
  PlanInputs inputs() const;
  GenerationVector failed_set() const;
};

Status Instance::build() {
  const auto make_switch = [](const SwitchKey& key, std::uint64_t domain, std::uint32_t capacity) {
    SwitchDescriptor descriptor;
    descriptor.key = key;
    descriptor.role = SwitchRole::Spine;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(domain);
    descriptor.capabilities = kAllCapabilities;
    descriptor.port_count = 32;
    descriptor.max_radix = 32;
    descriptor.capacity_score = capacity;
    descriptor.label = key.to_string();
    return descriptor;
  };

  std::vector<SwitchDescriptor> switches;
  switches.push_back(make_switch(failed, 10, 8));
  // Deliberately scarce: two dependents compete for one unit of spare capacity, which is what
  // makes the oversubscription check observable.
  switches.push_back(make_switch(replacement, 20, 1));
  switches.push_back(make_switch(fenced_switch, 30, 8));
  switches.push_back(make_switch(newer_generation, 40, 8));

  std::vector<PathDescriptor> paths;
  for (const DependentRef& dependent : {path_one, path_two}) {
    PathDescriptor path;
    path.id = PathId(dependent.id());
    path.source = NodeId(900);
    path.destination = NodeId(901);
    path.hops = {failed};
    path.cost = 1;
    path.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(path);
  }

  Result<TopologySnapshot> built = TopologySnapshot::build(TopologyVersion(1), switches, {}, paths,
                                                           {}, limits);
  if (!built.ok()) return built.status();
  topology = std::move(built).value();

  // A second snapshot with one extra switch: used to prove that a plan is bound to the exact
  // topology it was derived from.
  std::vector<SwitchDescriptor> extended = switches;
  extended.push_back(make_switch(key_of(500, 1), 50, 8));
  Result<TopologySnapshot> built_other =
      TopologySnapshot::build(TopologyVersion(2), extended, {}, paths, {}, limits);
  if (!built_other.ok()) return built_other.status();
  other_topology = std::move(built_other).value();

  std::vector<ReconstructionCandidate> entries;
  for (const DependentRef& dependent : {path_one, path_two}) {
    ReconstructionCandidate candidate;
    candidate.dependent = dependent;
    candidate.covers_failed = failed;
    candidate.hops = {replacement};
    candidate.cost = 5;
    candidate.capabilities = kAllCapabilities;
    candidate.evidence = EvidenceId(dependent.id() + 100);
    candidate.source = EvidenceSource::SimulatedFixture;  // authoritative for synthetic proof
    entries.push_back(candidate);
  }
  Result<CandidateTable> table = CandidateTable::build(std::move(entries), limits);
  if (!table.ok()) return table.status();
  candidates = std::move(table).value();

  FenceRecord failure_fence;
  failure_fence.subject = failed;
  failure_fence.epoch = epoch;
  failure_fence.boot = boot;
  failure_fence.created_at_ns = clock.now_ns();
  failure_fence.scope_state = FenceScopeState::Committed;
  failure_fence.reason = "synthetic failure declaration";
  Result<FenceId> committed = authority.commit_fence(failure_fence);
  if (!committed.ok()) return committed.status();

  FenceRecord unrelated_fence;
  unrelated_fence.subject = fenced_switch;
  unrelated_fence.epoch = epoch;
  unrelated_fence.boot = boot;
  unrelated_fence.created_at_ns = clock.now_ns();
  unrelated_fence.scope_state = FenceScopeState::Committed;
  unrelated_fence.reason = "synthetic unrelated fence";
  Result<FenceId> unrelated = authority.commit_fence(unrelated_fence);
  if (!unrelated.ok()) return unrelated.status();

  return Status::success();
}

PlanInputs Instance::inputs() const {
  PlanInputs value;
  value.topology = &topology;
  value.candidates = &candidates;
  value.evidence = &evidence;
  value.failures = &failures;
  value.authority = &authority;
  value.clock = &clock;
  value.limits = limits;
  value.epoch = epoch;
  value.boot = boot;
  value.plan_id = plan_id;
  value.now_ns = clock.now_ns();
  return value;
}

GenerationVector Instance::failed_set() const {
  GenerationVector set;
  set.insert(failed);
  return set;
}

bool has_finding(const ValidationReport& report, Code code, const std::string& fragment) {
  for (const ValidationFinding& finding : report.findings) {
    if (finding.code == code && finding.detail.find(fragment) != std::string::npos) return true;
  }
  return false;
}

#define CHECK_FINDING(report, expected_code, fragment)                                   \
  do {                                                                                   \
    const ValidationReport& sff_report_ = (report);                                       \
    CHECK(!sff_report_.valid);                                                            \
    CHECK(sff_report_.outcome != Code::Ok);                                               \
    CHECK(has_finding(sff_report_, (expected_code), std::string(fragment)));              \
  } while (false)

/// Build the instance and the accepted plan every mutation case starts from.
#define SETUP_ACCEPTED_PLAN(instance, plan)                                              \
  Instance instance;                                                                     \
  CHECK(instance.build().ok());                                                          \
  const Result<ReconstructionPlan> produced_ =                                           \
      plan_reconstruction(instance.inputs(), instance.failed_set());                      \
  CHECK(produced_.ok());                                                                 \
  if (!produced_.ok()) return;                                                            \
  const ReconstructionPlan plan = produced_.value();                                      \
  CHECK(sff::validate_plan(plan, instance.inputs()).valid)

}  // namespace

// ---------------------------------------------------------------------------------------------
// The accepted baseline
// ---------------------------------------------------------------------------------------------

SFF_TEST(generated_plan_passes_independent_validation) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  // The accepted plan really is the one the objective describes: one dependent moved onto the
  // scarce replacement, one left explicitly unresolved rather than silently dropped.
  CHECK_EQ(plan.restores.size(), std::size_t{1});
  CHECK_EQ(plan.unresolved.size(), std::size_t{1});
  CHECK(plan.restores[0].dependent == instance.path_one);
  CHECK(plan.restores[0].covers_failed == instance.failed);
  CHECK(plan.restores[0].replacement == instance.replacement);
  CHECK(plan.restores[0].hops.size() == 1 && plan.restores[0].hops[0] == instance.replacement);
  CHECK_EQ(plan.restores[0].cost, std::uint32_t{5});
  CHECK(plan.unresolved[0].dependent == instance.path_two);
  CHECK(plan.unresolved[0].reason == UnresolvedReason::CapacityExhausted);
  CHECK(plan.feasibility == PlanFeasibility::ProvenFeasible);
  CHECK(plan.state == PlanState::Draft);
  CHECK(plan.closure_complete);
  CHECK(plan.digest_valid());

  CHECK_EQ(plan.fences.size(), std::size_t{1});
  CHECK(plan.fences[0].failed == instance.failed);
  CHECK(plan.fences[0].closure_state == ClosureState::Complete);
  CHECK_EQ(plan.fences[0].closure_members, std::size_t{3});
  CHECK_EQ(plan.fences[0].omitted_dependents, std::size_t{0});

  const PlanInputs inputs = instance.inputs();
  const ValidationReport report = sff::validate_plan(plan, inputs);
  CHECK(report.valid);
  CHECK(report.outcome == Code::Ok);
  CHECK(report.findings.empty());
  CHECK(report.checks_performed > 0);
  CHECK_EQ(report.plan_digest, plan.plan_digest);
  CHECK_EQ(report.inputs_digest, inputs.policy_digest());

  // Validation is a pure function of (plan, inputs): the same pair yields the same report.
  const ValidationReport again = sff::validate_plan(plan, inputs);
  CHECK_EQ(again.checks_performed, report.checks_performed);
  CHECK(again.valid);

  // Fence obligations alone are also satisfied.
  const ValidationReport fences = sff::validate_fences(plan, inputs);
  CHECK(fences.valid);
  CHECK(fences.checks_performed > 0);
  CHECK(fences.checks_performed < report.checks_performed);
}

// KNOWN GAP - reported with this suite, deliberately NOT asserted here.
//
// A plan with an empty failed_generations set, no fence steps, no restore steps and no unresolved
// entries validates as VALID (outcome Ok, zero findings) as long as its epoch, boot, topology and
// policy bindings match the inputs: an empty closure recomputes to closure_complete == false, the
// plan says false, and every other check is vacuous. plan_reconstruction refuses to produce such a
// plan ("planning requires at least one failed generation"), so the validator is strictly more
// permissive than the planner for exactly the plan that fences and restores nothing.
//
// Encoding that verdict as an expected pass would enshrine a fail-open outcome, so it is reported
// instead of asserted. The correct verdict for an empty failed set is Invalid (or, at minimum,
// Indeterminate), not Ok.

SFF_TEST(planning_for_an_unfenced_generation_is_refused) {
  Instance instance;
  CHECK(instance.build().ok());

  // Same inputs, but no fence has ever been committed for the generation.
  AuthorityRegistry unfenced(Limits::defaults());
  PlanInputs inputs = instance.inputs();
  inputs.authority = &unfenced;

  const Result<ReconstructionPlan> produced = plan_reconstruction(inputs, instance.failed_set());
  CHECK(!produced.ok());
  CHECK(produced.status().code() == Code::Invalid);
  CHECK(!produced.status().message().empty());
}

// ---------------------------------------------------------------------------------------------
// Tampering
// ---------------------------------------------------------------------------------------------

SFF_TEST(any_field_change_without_resealing_is_a_corrupt_plan) {
  SETUP_ACCEPTED_PLAN(instance, plan);
  const PlanInputs inputs = instance.inputs();
  const ValidationReport baseline = sff::validate_plan(plan, inputs);
  CHECK(baseline.valid);

  ReconstructionPlan tampered = plan;
  tampered.service_withheld = !tampered.service_withheld;  // one bit of one field
  CHECK(!tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, inputs);
  CHECK(!report.valid);
  CHECK(report.outcome == Code::Corrupt);
  CHECK_EQ(report.findings.size(), std::size_t{1});
  CHECK(has_finding(report, Code::Corrupt, "plan digest does not match its contents"));
  // The digest gate runs first: the semantic checks were never reached.
  CHECK(report.checks_performed < baseline.checks_performed);

  ReconstructionPlan cost_flip = plan;
  cost_flip.restores[0].cost = cost_flip.restores[0].cost ^ 1u;
  CHECK(!cost_flip.digest_valid());
  const ValidationReport cost_report = sff::validate_plan(cost_flip, inputs);
  CHECK(!cost_report.valid);
  CHECK(cost_report.outcome == Code::Corrupt);
  CHECK_EQ(cost_report.findings.size(), std::size_t{1});
}

SFF_TEST(a_restore_hop_reusing_the_failed_generation_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores[0].hops = {instance.failed};
  tampered.restores[0].replacement = instance.failed;
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Fenced, "restore step reuses a failed generation");
}

SFF_TEST(a_restore_hop_absent_from_the_topology_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores[0].hops = {instance.absent};
  tampered.restores[0].replacement = instance.absent;
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::NotFound, "restore step names a generation absent from the topology");
  CHECK(!has_finding(report, Code::Stale, "restore step names a superseded generation"));
}

SFF_TEST(a_restore_hop_naming_a_superseded_generation_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  // The identity is installed, but only at generation 5: generation 4 is a superseded generation.
  ReconstructionPlan tampered = plan;
  tampered.restores[0].hops = {key_of(400, 4)};
  tampered.restores[0].replacement = key_of(400, 4);
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Stale, "restore step names a superseded generation");
  CHECK(instance.topology.find_switch(key_of(400, 4)) == nullptr);
  CHECK(instance.topology.find_highest_generation(SwitchId(400)) != nullptr);
}

SFF_TEST(a_restore_hop_that_is_fenced_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores[0].hops = {instance.fenced_switch};
  tampered.restores[0].replacement = instance.fenced_switch;
  tampered.seal();
  CHECK(tampered.digest_valid());

  // The hop is present in the topology, so only the fence state can refuse it.
  CHECK(instance.topology.find_switch(instance.fenced_switch) != nullptr);
  CHECK(instance.authority.is_fenced(instance.fenced_switch));

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Fenced, "restore step crosses a fenced generation");
}

SFF_TEST(a_zero_cost_restore_step_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores[0].cost = 0;
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Invalid, "restore step has a zero cost");
}

SFF_TEST(a_duplicate_restore_step_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores.push_back(tampered.restores[0]);
  canonicalise_restores(tampered);
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::AlreadyExists,
                "duplicate restore step for the same dependent and failed generation");
}

SFF_TEST(a_restore_step_covering_a_generation_outside_the_failed_set_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.restores[0].covers_failed = instance.newer_generation;
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Invalid, "restore step covers a generation that is not in the failed set");
  // Every demand must still be accounted for: the displaced demand is reported, not ignored.
  CHECK(has_finding(report, Code::PartialClosure, "appears in neither the restore set nor the unresolved set"));
}

SFF_TEST(an_oversubscribed_replacement_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  // The accepted plan leaves the second demand unresolved because the replacement declares one
  // unit of spare capacity. Resolving it anyway oversubscribes that generation.
  ReconstructionPlan tampered = plan;
  RestoreStep extra;
  extra.dependent = instance.path_two;
  extra.covers_failed = instance.failed;
  extra.action = PlanAction::RebindReplacement;
  extra.replacement = instance.replacement;
  extra.hops = {instance.replacement};
  extra.cost = 6;
  extra.evidence = EvidenceId(2);
  tampered.restores.push_back(extra);
  tampered.unresolved.clear();
  canonicalise_restores(tampered);
  tampered.seal();
  CHECK(tampered.digest_valid());
  CHECK_EQ(tampered.restores.size(), std::size_t{2});
  CHECK(tampered.unresolved.empty());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Exhausted,
                "assignment exceeds the declared spare capacity of the replacement generation");
  // Nothing else is wrong with this mutant: the oversubscription check is what refuses it.
  CHECK_EQ(report.findings.size(), std::size_t{1});
  CHECK_EQ(report.findings[0].scope, instance.replacement.to_string());
}

SFF_TEST(a_closure_completeness_claim_that_does_not_recompute_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan tampered = plan;
  tampered.closure_complete = !tampered.closure_complete;
  tampered.seal();
  CHECK(tampered.digest_valid());

  const ValidationReport report = sff::validate_plan(tampered, instance.inputs());
  CHECK_FINDING(report, Code::Invalid,
                "plan closure completeness does not match the closure recomputed from the inputs");
  CHECK_EQ(report.findings.size(), std::size_t{1});
}

SFF_TEST(a_plan_bound_to_a_stale_epoch_boot_topology_or_policy_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan other_epoch = plan;
  other_epoch.epoch = CoordinatorEpoch(instance.epoch.raw() + 1);
  other_epoch.seal();
  CHECK(other_epoch.digest_valid());
  {
    const ValidationReport report = sff::validate_plan(other_epoch, instance.inputs());
    CHECK_FINDING(report, Code::Stale, "plan was produced under a different coordinator epoch");
    CHECK_EQ(report.findings.size(), std::size_t{1});
  }

  ReconstructionPlan other_boot = plan;
  other_boot.boot = BootIncarnation::from_parts(1, 2, 3, 4);
  other_boot.seal();
  CHECK(other_boot.digest_valid());
  {
    const ValidationReport report = sff::validate_plan(other_boot, instance.inputs());
    CHECK_FINDING(report, Code::Stale, "plan was produced under a different process incarnation");
    CHECK_EQ(report.findings.size(), std::size_t{1});
  }

  ReconstructionPlan other_topology = plan;
  other_topology.topology_digest = instance.other_topology.digest();
  CHECK(instance.other_topology.digest() != instance.topology.digest());
  other_topology.seal();
  CHECK(other_topology.digest_valid());
  {
    const ValidationReport report = sff::validate_plan(other_topology, instance.inputs());
    CHECK_FINDING(report, Code::Stale, "plan was produced against a different topology snapshot");
    CHECK_EQ(report.findings.size(), std::size_t{1});
  }

  ReconstructionPlan other_policy = plan;
  other_policy.policy_digest = plan.policy_digest ^ 0x1ull;
  other_policy.seal();
  CHECK(other_policy.digest_valid());
  {
    const ValidationReport report = sff::validate_plan(other_policy, instance.inputs());
    CHECK_FINDING(report, Code::Stale, "plan was produced under a different policy");
    CHECK_EQ(report.findings.size(), std::size_t{1});
  }
}

SFF_TEST(a_failed_generation_without_a_fence_step_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  ReconstructionPlan missing_fence = plan;
  missing_fence.fences.clear();
  missing_fence.seal();
  CHECK(missing_fence.digest_valid());
  {
    const ValidationReport report = sff::validate_plan(missing_fence, instance.inputs());
    CHECK_FINDING(report, Code::Fenced, "failed generation has no fence step");
    CHECK_EQ(report.findings.size(), std::size_t{1});
  }

  // The fence-only entry point refuses the same plan for the same reason.
  const ValidationReport fences = sff::validate_fences(missing_fence, instance.inputs());
  CHECK(!fences.valid);
  CHECK(has_finding(fences, Code::Fenced, "failed generation has no fence step"));

  // A truncated closure may never be recorded as complete.
  ReconstructionPlan truncated = plan;
  truncated.fences[0].closure_state = ClosureState::Truncated;
  truncated.seal();
  CHECK(truncated.digest_valid());
  const ValidationReport truncated_report = sff::validate_plan(truncated, instance.inputs());
  CHECK_FINDING(truncated_report, Code::Invalid,
                "a truncated closure must not be reported as complete");
}

SFF_TEST(a_fence_claim_the_authority_registry_does_not_support_is_rejected) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  // The plan is untouched; the inputs no longer contain the fence it claims.
  AuthorityRegistry unfenced(Limits::defaults());
  PlanInputs inputs = instance.inputs();
  inputs.authority = &unfenced;

  const ValidationReport report = sff::validate_plan(plan, inputs);
  CHECK_FINDING(report, Code::Fenced, "failed generation is not fenced");
  CHECK_EQ(report.findings.size(), std::size_t{1});

  // The same plan stays valid against the inputs that do contain the fence.
  CHECK(sff::validate_plan(plan, instance.inputs()).valid);
}

SFF_TEST(findings_are_bounded_while_checks_continue) {
  SETUP_ACCEPTED_PLAN(instance, plan);

  // A hostile plan must not be able to grow the report without bound, and the truncation itself
  // must be recorded rather than hidden.
  ReconstructionPlan flooded = plan;
  for (std::size_t index = 0; index < 300; ++index) {
    FenceStep bogus;
    bogus.failed = SwitchKey(SwitchId(0), SwitchGeneration(0));
    flooded.fences.push_back(bogus);
  }
  flooded.seal();
  CHECK(flooded.digest_valid());

  const ValidationReport report = sff::validate_plan(flooded, instance.inputs());
  CHECK(!report.valid);
  CHECK_EQ(report.findings.size(), std::size_t{257});
  CHECK(report.findings.back().code == Code::Exhausted);
  CHECK_EQ(report.findings.back().scope, std::string("report"));
  CHECK_EQ(report.findings.back().detail,
           std::string("validation findings were truncated by the report bound"));
  // Every injected claim was still examined: bounding the findings never stops the checking.
  CHECK(report.checks_performed >= 600);
  CHECK(report.checks_performed > report.findings.size());
}

SFF_MAIN()
