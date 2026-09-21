// Switch Failover Fabric - example: fence a failed switch generation, then reconstruct.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This program is deliberately small and deliberately explicit. It answers the product question
// on a SYNTHETIC instance built in-process:
//
//   given authoritative evidence that a switch GENERATION has failed, which dependent authority
//   must be fenced, which supplied replacement resources are eligible, and when may service be
//   restored under current generations?
//
// It never talks to hardware, never discovers a topology and never invents a forwarding path: the
// topology and every replacement alternative are supplied as authoritative input, which is the
// exact systems boundary of this runtime.
#include "sff/sff.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace sff;

/// Every freshness decision below is made against a deterministic clock, so the program prints
/// exactly the same reasoning on every run.
constexpr TimestampNs kStartNs = 1000000000ull;
constexpr std::uint64_t kWindowNs = 30ull * kNanosPerSecond;

int g_refusals = 0;

int refuse(const char* step, const Status& status) {
  g_refusals += 1;
  std::cout << "REFUSED step=" << step << " code=" << to_string(status.code()) << " detail=\""
            << status.message() << "\"\n";
  std::cout << "example_failover_status=refused exit=1\n";
  return 1;
}

}  // namespace

int main() {
  const Limits limits = Limits::defaults();

  // -------------------------------------------------------------------------------------------
  // 1. The SYNTHETIC instance.
  //
  // Switch identity 1 has TWO declared generations. That is the point: matching identity is not
  // matching generation, so generation 1 failing says nothing about generation 2.
  // -------------------------------------------------------------------------------------------
  const SwitchKey failed(SwitchId(1), SwitchGeneration(1));
  const SwitchKey same_identity_next_generation(SwitchId(1), SwitchGeneration(2));
  const SwitchKey spine(SwitchId(2), SwitchGeneration(1));

  const CapabilityMask base = capability_bit(Capability::Layer2) | capability_bit(Capability::Layer3);

  std::vector<SwitchDescriptor> switches;
  {
    SwitchDescriptor descriptor;
    descriptor.key = failed;
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(10);  // the generation that will be declared failed
    descriptor.capabilities = base;
    descriptor.port_count = 16;
    descriptor.max_radix = 16;
    descriptor.capacity_score = 4;
    descriptor.label = "synthetic-leaf-generation-1";
    switches.push_back(descriptor);

    descriptor.key = same_identity_next_generation;
    descriptor.failure_domain = FailureDomainId(10);
    descriptor.label = "synthetic-leaf-generation-2";
    switches.push_back(descriptor);

    descriptor.key = spine;
    descriptor.role = SwitchRole::Spine;
    descriptor.failure_domain = FailureDomainId(20);  // a different failure domain: usable as cover
    descriptor.port_count = 32;
    descriptor.max_radix = 32;
    descriptor.capacity_score = 8;
    descriptor.label = "synthetic-spine";
    switches.push_back(descriptor);
  }

  std::vector<LinkDescriptor> links;
  {
    LinkDescriptor link;
    link.id = LinkId(1);
    link.a.sw = failed;
    link.a.index = 1;
    link.b.sw = spine;
    link.b.index = 1;
    link.cost = 1;
    link.bandwidth_gbps = 100;
    link.latency_ns = 500;
    links.push_back(link);
  }

  std::vector<PathDescriptor> paths;
  {
    // A forwarding path that traverses the generation which is about to fail.
    PathDescriptor path;
    path.id = PathId(1);
    path.source = NodeId(1);
    path.destination = NodeId(9);
    path.hops.push_back(failed);
    path.hops.push_back(spine);
    path.links.push_back(LinkId(1));
    path.cost = 2;
    path.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(path);

    // A forwarding path over the other generation of the same switch identity. It must remain
    // untouched, because generation 2 is not generation 1.
    PathDescriptor unaffected;
    unaffected.id = PathId(2);
    unaffected.source = NodeId(2);
    unaffected.destination = NodeId(9);
    unaffected.hops.push_back(same_identity_next_generation);
    unaffected.hops.push_back(spine);
    unaffected.cost = 3;
    unaffected.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(unaffected);
  }

  std::vector<DependencyEdge> edges;
  {
    // A service that depends on path 1. Services and ports are supplied explicitly because this
    // runtime does not own service or port discovery.
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::service(5));
    edge.to = ClosureNode::of_dependent(DependentRef::path(PathId(1)));
    edges.push_back(edge);
  }

  // The supplied reconstruction alternatives. Nothing here is synthesised by the runtime: an
  // adjacent authoritative system supplies the hops, the cost and the capability set, and this
  // runtime only decides which of them are admissible under current generations.
  std::vector<ReconstructionCandidate> supplied;
  {
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::link(LinkId(1));
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine);
    candidate.cost = 1;
    candidate.capabilities = base;
    candidate.evidence = EvidenceId(101);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::path(PathId(1));
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine);
    candidate.cost = 3;
    candidate.capabilities = capability_bit(Capability::Layer3);
    candidate.evidence = EvidenceId(102);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(5);
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine);
    candidate.cost = 2;
    candidate.capabilities = capability_bit(Capability::Layer3);
    candidate.evidence = EvidenceId(103);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);
  }

  Result<TopologySnapshot> topology = TopologySnapshot::build(
      TopologyVersion(1), std::move(switches), std::move(links), std::move(paths), std::move(edges),
      limits);
  if (!topology.ok()) return refuse("topology_build", topology.status());
  Result<CandidateTable> candidates = CandidateTable::build(std::move(supplied), limits);
  if (!candidates.ok()) return refuse("candidate_build", candidates.status());

  std::cout << "synthetic=true switches=" << topology.value().switches().size()
            << " links=" << topology.value().links().size()
            << " paths=" << topology.value().paths().size()
            << " candidates=" << candidates.value().size() << "\n";

  // -------------------------------------------------------------------------------------------
  // 2. Open the runtime. Durability is off: this example is about one incarnation's reasoning.
  // -------------------------------------------------------------------------------------------
  ManualClock clock(kStartNs);
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = Policy{};  // fail-closed defaults: acknowledgement never restores service
  config.evidence_class = EvidenceClass::Synthetic;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  if (!opened.ok()) return refuse("coordinator_open", opened.status());
  std::unique_ptr<Coordinator> runtime = std::move(opened).value();

  Status step = runtime->install_topology(topology.value());
  if (!step.ok()) return refuse("install_topology", step);
  step = runtime->install_candidates(candidates.value());
  if (!step.ok()) return refuse("install_candidates", step);

  // -------------------------------------------------------------------------------------------
  // 3. Declare one switch generation failed.
  //
  // The declaration is not authority by itself: it becomes evidence, is adjudicated against
  // policy, and only then produces a fence obligation. An advisory source is refused outright.
  // -------------------------------------------------------------------------------------------
  FailureDeclaration declaration;
  declaration.subject = failed;
  declaration.source = EvidenceSource::SimulatedFixture;  // authoritative, and labelled SYNTHETIC
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = kWindowNs;
  declaration.reason = "synthetic fixture: leaf generation 1 stopped forwarding";

  FailureDeclaration advisory = declaration;
  advisory.source = EvidenceSource::TelemetryCollector;
  const Status advisory_refusal = runtime->declare_failure(advisory).status();
  std::cout << "advisory_declaration_refused=" << (advisory_refusal.ok() ? "false" : "true")
            << " code=" << to_string(advisory_refusal.code()) << "\n";

  Result<FailoverOutcome> failover = runtime->declare_failure(declaration);
  if (!failover.ok()) return refuse("declare_failure", failover.status());
  const FailoverOutcome outcome = failover.value();

  // -------------------------------------------------------------------------------------------
  // 4. The fence and the bounded dependency closure it covers.
  // -------------------------------------------------------------------------------------------
  std::cout << "failed_generation=" << outcome.failed.to_string() << "\n";
  std::cout << "fence_id=" << outcome.fence.raw() << " fence_scope=" << to_string(outcome.fence_scope)
            << " grants_fenced=" << outcome.grants_fenced << "\n";
  std::cout << "closure_state=" << to_string(outcome.closure.state)
            << " members=" << outcome.closure.members.size()
            << " dependents=" << outcome.closure.dependents.size()
            << " edges_examined=" << outcome.closure.edges_examined
            << " truncated=" << (outcome.closure.truncated() ? "true" : "false") << "\n";
  for (const DependentRef& dependent : outcome.closure.dependents) {
    const std::vector<AuthorityGrant> grants = runtime->authority()->grants_for(dependent);
    std::cout << "fenced_scope dependent=" << dependent.to_string() << " grants=" << grants.size();
    for (const AuthorityGrant& grant : grants) {
      std::cout << " state=" << to_string(grant.state);
    }
    std::cout << "\n";
  }
  // The fence is bound to one exact generation. The other generation of the same identity - and
  // every dependent that only touches it - is untouched.
  std::cout << "fenced_exact_generation="
            << (runtime->authority()->is_fenced(failed) ? "true" : "false")
            << " fenced_other_generation="
            << (runtime->authority()->is_fenced(same_identity_next_generation) ? "true" : "false")
            << "\n";
  const Result<AuthorityQuery> unaffected = runtime->query_authority(DependentRef::path(PathId(2)));
  if (unaffected.ok()) {
    std::cout << "unaffected_dependent=" << unaffected.value().dependent.to_string()
              << " has_authority=" << (unaffected.value().has_authority ? "true" : "false") << "\n";
  }

  // -------------------------------------------------------------------------------------------
  // 5. Propose a plan from current generations, then re-validate it independently.
  // -------------------------------------------------------------------------------------------
  GenerationVector failed_set;
  failed_set.insert(failed);
  Result<ReconstructionPlan> proposed = runtime->propose_plan(failed_set);
  if (!proposed.ok()) return refuse("propose_plan", proposed.status());
  const ReconstructionPlan plan = proposed.value();

  Result<ValidationReport> validation = runtime->validate_plan(plan);
  if (!validation.ok()) return refuse("validate_plan", validation.status());
  if (!validation.value().valid) {
    return refuse("validate_plan",
                  Status::failure(validation.value().outcome, validation.value().to_string()));
  }

  std::cout << "plan_id=" << plan.id.raw() << " feasibility=" << to_string(plan.feasibility)
            << " restores=" << plan.restores.size() << " unresolved=" << plan.unresolved.size()
            << " total_cost=" << plan.total_cost()
            << " closure_complete=" << (plan.closure_complete ? "true" : "false") << "\n";
  for (const RestoreStep& restore : plan.restores) {
    std::cout << "plan_step dependent=" << restore.dependent.to_string()
              << " moves_off=" << restore.covers_failed.to_string()
              << " onto=" << restore.replacement.to_string() << " cost=" << restore.cost << "\n";
  }

  // -------------------------------------------------------------------------------------------
  // 6. Apply the plan. The receipt distinguishes what was issued and acknowledged from what was
  //    independently verified - and nothing here has been verified.
  // -------------------------------------------------------------------------------------------
  Result<ApplyReceipt> applied = runtime->apply_plan(plan);
  if (!applied.ok()) return refuse("apply_plan", applied.status());
  const ApplyReceipt receipt = applied.value();
  std::cout << "receipt applied=" << receipt.applied << " failed=" << receipt.failed
            << " verified=" << receipt.verified << " unverified=" << receipt.unverified
            << " complete=" << (receipt.complete ? "true" : "false")
            << " outcome=" << to_string(receipt.outcome) << "\n";
  std::cout << "applied_and_acknowledged_is_not_verified_effect=true fully_verified="
            << (receipt.fully_verified() ? "true" : "false") << "\n";

  // -------------------------------------------------------------------------------------------
  // 7. Restoration: it is refused until independent verification evidence exists.
  // -------------------------------------------------------------------------------------------
  const DependentRef dependent = DependentRef::service(5);
  const Result<RestoreDecision> before = runtime->evaluate_restore(dependent);
  if (!before.ok()) return refuse("evaluate_restore_before", before.status());
  std::cout << "restore_before_verification dependent=" << dependent.to_string()
            << " outcome=" << to_string(before.value().outcome)
            << " may_restore=" << (before.value().may_restore ? "true" : "false")
            << " effect_verified=" << (before.value().effect_verified ? "true" : "false") << "\n";

  AttemptSeq attempt;
  SwitchKey replacement;
  for (const ApplyStepResult& applied_step : receipt.steps) {
    if (applied_step.dependent != dependent) continue;
    attempt = applied_step.attempt;
    replacement = applied_step.replacement;
  }

  EvidenceRecord verification;
  verification.id = EvidenceId(9001);
  verification.kind = EvidenceKind::EffectVerification;
  verification.source = EvidenceSource::SimulatedFixture;
  verification.subject = replacement;  // evidence is always generation-qualified
  verification.observed_at_ns = clock.now_ns();
  verification.valid_for_ns = kWindowNs;
  verification.effect_dependent = dependent;
  verification.effect_plan = plan.id;
  verification.effect_attempt = attempt;
  verification.detail = "synthetic independent observation of the reconstructed forwarding state";
  const Status recorded = runtime->record_effect_verification(verification);
  if (!recorded.ok()) return refuse("record_effect_verification", recorded);

  const Result<RestoreDecision> after = runtime->evaluate_restore(dependent);
  if (!after.ok()) return refuse("evaluate_restore_after", after.status());
  std::cout << "restore_after_verification dependent=" << dependent.to_string()
            << " outcome=" << to_string(after.value().outcome)
            << " may_restore=" << (after.value().may_restore ? "true" : "false")
            << " effect_verified=" << (after.value().effect_verified ? "true" : "false") << "\n";

  const Status shutdown = runtime->shutdown();
  if (!shutdown.ok()) return refuse("shutdown", shutdown);

  std::cout << "example_failover_summary synthetic=true closure="
            << to_string(outcome.closure.state) << " dependents=" << outcome.closure.dependents.size()
            << " grants_fenced=" << outcome.grants_fenced << " restores=" << plan.restores.size()
            << " unresolved=" << plan.unresolved.size() << " applied=" << receipt.applied
            << " verified=" << receipt.verified << " restore_before="
            << to_string(before.value().outcome) << " restore_after="
            << to_string(after.value().outcome) << " refusals=" << g_refusals << "\n";
  return g_refusals == 0 ? 0 : 1;
}
