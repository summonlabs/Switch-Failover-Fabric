// Switch Failover Fabric - example: planner determinism and the reconstruction objective.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Two claims are demonstrated here on SYNTHETIC instances:
//
//   1. the planner is order-independent and deterministic: the same instance built from a
//      shuffled input stream produces a byte-identical plan, because the objective is total and
//      the tie-break is canonical;
//   2. spare capacity on a replacement generation is a real constraint, not a preference: an
//      assignment that looks cheapest demand-by-demand can be inadmissible, the planner searches
//      for the best admissible assignment, and when no assignment can cover everything it says
//      so with a proven reason instead of quietly dropping a dependent.
//
// The objective is minimised lexicographically: unresolved dependents, then total cost, then
// total replacement hops, then the canonical assignment sequence.
#include "sff/sff.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace sff;

constexpr TimestampNs kStartNs = 1000000000ull;
constexpr std::uint64_t kPlanSeed = 0x51ff0001ull;

/// A complete planning instance. The containers are owned here and never copied after the inputs
/// have been wired up, because PlanInputs borrows them.
struct Instance {
  TopologySnapshot topology;
  CandidateTable candidates;
  FailureTable failures;
  AuthorityRegistry authority;
  EvidenceStore evidence{Limits::defaults(), nullptr};
};

PlanInputs make_inputs(const Instance& instance, const ManualClock& clock, PlanId plan_id) {
  PlanInputs inputs;
  inputs.topology = &instance.topology;
  inputs.candidates = &instance.candidates;
  inputs.evidence = &instance.evidence;
  inputs.failures = &instance.failures;
  inputs.authority = &instance.authority;
  inputs.clock = &clock;
  inputs.limits = Limits::defaults();
  inputs.assessment = AssessmentPolicy{};
  inputs.planning = PlanningPolicy{};
  inputs.epoch = CoordinatorEpoch(1);
  inputs.boot = BootIncarnation::from_parts(7, 1, 0x11223344ull, 0x55667788ull);
  inputs.plan_id = plan_id;
  inputs.now_ns = clock.now_ns();
  return inputs;
}

/// A committed fence for one exact generation. Planning refuses to plan for a generation that is
/// neither fenced nor failing, and the validator re-derives that the fenced generation really is
/// fenced rather than trusting the plan's own fence step.
Status commit_fence(Instance& instance, const SwitchKey& subject, std::size_t closure_members) {
  FenceRecord fence;
  fence.subject = subject;
  fence.epoch = CoordinatorEpoch(1);
  fence.boot = BootIncarnation::from_parts(7, 1, 0x11223344ull, 0x55667788ull);
  fence.created_at_ns = kStartNs;
  fence.scope_state = FenceScopeState::Committed;
  fence.closure_members = closure_members;
  fence.reason = "synthetic fixture: generation declared unusable";
  Result<FenceId> committed = instance.authority.commit_fence(fence);
  return committed.ok() ? Status::success() : committed.status();
}

/// A durable failure for one exact generation is what makes planning admissible: the planner
/// refuses to plan for a generation that is neither fenced nor failing.
Status record_failure(Instance& instance, const SwitchKey& subject) {
  FailureRecord record;
  record.subject = subject;
  record.evidence = EvidenceId(1);
  record.epoch = CoordinatorEpoch(1);
  record.boot = BootIncarnation::from_parts(7, 1, 0x11223344ull, 0x55667788ull);
  record.observed_at_ns = kStartNs;
  record.recorded_at_ns = kStartNs;
  record.reason = "synthetic fixture: generation declared unusable";
  return instance.failures.record(record);
}

std::string key_list(const std::vector<SwitchKey>& keys) {
  std::string text;
  for (const SwitchKey& key : keys) {
    if (!text.empty()) text += ",";
    text += key.to_string();
  }
  return text;
}

/// Build the shared instance. input_seed only changes the ORDER in which the identical inputs are
/// handed to the builder, never their content.
bool build_main_instance(Instance& out, std::uint64_t input_seed, std::string& error) {
  const SwitchKey failed(SwitchId(1), SwitchGeneration(1));
  const SwitchKey cover_a(SwitchId(2), SwitchGeneration(1));
  const SwitchKey cover_b(SwitchId(3), SwitchGeneration(1));
  const CapabilityMask l2 = capability_bit(Capability::Layer2);
  const CapabilityMask l3 = capability_bit(Capability::Layer3);

  std::vector<SwitchDescriptor> switches;
  {
    SwitchDescriptor descriptor;
    descriptor.key = failed;
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(100);
    descriptor.capabilities = l2 | l3;
    descriptor.port_count = 16;
    descriptor.max_radix = 16;
    descriptor.capacity_score = 4;
    descriptor.label = "synthetic-failed-leaf";
    switches.push_back(descriptor);

    descriptor.key = cover_a;
    descriptor.role = SwitchRole::Spine;
    descriptor.failure_domain = FailureDomainId(200);
    descriptor.port_count = 32;
    descriptor.max_radix = 32;
    descriptor.capacity_score = 16;
    descriptor.label = "synthetic-cover-a";
    switches.push_back(descriptor);

    descriptor.key = cover_b;
    descriptor.failure_domain = FailureDomainId(300);
    descriptor.label = "synthetic-cover-b";
    switches.push_back(descriptor);
  }

  std::vector<LinkDescriptor> links;
  {
    LinkDescriptor link;
    link.id = LinkId(1);
    link.a.sw = failed;
    link.a.index = 1;
    link.b.sw = cover_a;
    link.b.index = 1;
    link.cost = 1;
    links.push_back(link);

    link.id = LinkId(2);
    link.a.sw = failed;
    link.a.index = 2;
    link.b.sw = cover_b;
    link.b.index = 1;
    links.push_back(link);
  }

  std::vector<PathDescriptor> paths;
  for (std::size_t index = 0; index < 2; ++index) {
    PathDescriptor path;
    path.id = PathId(10 + index);
    path.source = NodeId(1);
    path.destination = NodeId(9);
    path.hops.push_back(failed);
    path.hops.push_back(index == 0 ? cover_a : cover_b);
    path.links.push_back(index == 0 ? LinkId(1) : LinkId(2));
    path.cost = 2;
    path.required_capabilities = l3;
    paths.push_back(path);
  }

  std::vector<DependencyEdge> edges;
  for (std::size_t index = 0; index < 2; ++index) {
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::service(20 + index));
    edge.to = ClosureNode::of_dependent(DependentRef::path(PathId(10 + index)));
    edges.push_back(edge);
  }

  std::vector<ReconstructionCandidate> supplied;
  for (std::size_t index = 0; index < 2; ++index) {
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::path(PathId(10 + index));
    candidate.covers_failed = failed;
    candidate.hops.push_back(index == 0 ? cover_a : cover_b);
    candidate.cost = 3;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(300 + index);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(20 + index);
    candidate.covers_failed = failed;
    candidate.hops.push_back(index == 0 ? cover_a : cover_b);
    candidate.cost = 2;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(320 + index);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::link(LinkId(1 + index));
    candidate.covers_failed = failed;
    candidate.hops.push_back(index == 0 ? cover_a : cover_b);
    candidate.cost = 1;
    candidate.capabilities = l2 | l3;
    candidate.evidence = EvidenceId(340 + index);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);
  }

  std::mt19937_64 rng(input_seed == 0 ? kPlanSeed : input_seed);
  std::shuffle(switches.begin(), switches.end(), rng);
  std::shuffle(links.begin(), links.end(), rng);
  std::shuffle(paths.begin(), paths.end(), rng);
  std::shuffle(edges.begin(), edges.end(), rng);
  std::shuffle(supplied.begin(), supplied.end(), rng);

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                              std::move(paths), std::move(edges), Limits::defaults());
  if (!topology.ok()) {
    error = topology.status().to_string();
    return false;
  }
  Result<CandidateTable> table = CandidateTable::build(std::move(supplied), Limits::defaults());
  if (!table.ok()) {
    error = table.status().to_string();
    return false;
  }
  out.topology = std::move(topology).value();
  out.candidates = std::move(table).value();
  const Status recorded = record_failure(out, failed);
  if (!recorded.ok()) {
    error = recorded.to_string();
    return false;
  }
  const Status fenced = commit_fence(out, failed, out.topology.nodes().size());
  if (!fenced.ok()) {
    error = fenced.to_string();
    return false;
  }
  return true;
}

/// The capacity instance: one replacement generation with exactly one unit of spare capacity, a
/// second replacement with plenty, and three dependents that all want the scarce one.
struct CapacityScenario {
  Instance instance;
  SwitchKey failed;
  SwitchKey scarce;
  SwitchKey roomy;
  GenerationVector failed_set;
};

bool build_capacity_instance(CapacityScenario& out, std::string& error) {
  const SwitchKey failed(SwitchId(1), SwitchGeneration(1));
  const SwitchKey scarce(SwitchId(10), SwitchGeneration(1));
  const SwitchKey roomy(SwitchId(11), SwitchGeneration(1));
  const CapabilityMask l2 = capability_bit(Capability::Layer2);

  std::vector<SwitchDescriptor> switches;
  {
    SwitchDescriptor descriptor;
    descriptor.key = failed;
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(100);
    descriptor.capabilities = l2;
    descriptor.port_count = 16;
    descriptor.capacity_score = 4;
    descriptor.label = "synthetic-failed-leaf";
    switches.push_back(descriptor);

    descriptor.key = scarce;
    descriptor.role = SwitchRole::Spine;
    descriptor.failure_domain = FailureDomainId(200);
    descriptor.capabilities = l2;
    descriptor.port_count = 8;
    descriptor.capacity_score = 1;  // exactly one dependent can be covered by this generation
    descriptor.label = "synthetic-scarce-cover";
    switches.push_back(descriptor);

    descriptor.key = roomy;
    descriptor.failure_domain = FailureDomainId(300);
    descriptor.port_count = 32;
    descriptor.capacity_score = 8;
    descriptor.label = "synthetic-roomy-cover";
    switches.push_back(descriptor);
  }

  // The dependents are wired straight to the failed generation: they are services supplied by an
  // adjacent system, and this runtime owns the dependency relation, not service discovery.
  std::vector<DependencyEdge> edges;
  for (std::uint64_t id = 1; id <= 3; ++id) {
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::service(id));
    edge.to = ClosureNode::of_switch(failed);
    edges.push_back(edge);
  }

  std::vector<ReconstructionCandidate> supplied;
  {
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::service(1);
    candidate.covers_failed = failed;
    candidate.hops.push_back(scarce);
    candidate.cost = 1;  // cheapest demand-by-demand choice
    candidate.capabilities = l2;
    candidate.evidence = EvidenceId(401);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(2);
    candidate.covers_failed = failed;
    candidate.hops.push_back(scarce);
    candidate.cost = 3;
    candidate.capabilities = l2;
    candidate.evidence = EvidenceId(402);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(2);
    candidate.covers_failed = failed;
    candidate.hops.push_back(roomy);
    candidate.cost = 4;
    candidate.capabilities = l2;
    candidate.evidence = EvidenceId(403);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(3);
    candidate.covers_failed = failed;
    candidate.hops.push_back(scarce);
    candidate.cost = 5;
    candidate.capabilities = l2;
    candidate.evidence = EvidenceId(404);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);
  }

  Result<TopologySnapshot> topology = TopologySnapshot::build(
      TopologyVersion(1), std::move(switches), {}, {}, std::move(edges), Limits::defaults());
  if (!topology.ok()) {
    error = topology.status().to_string();
    return false;
  }
  Result<CandidateTable> table = CandidateTable::build(std::move(supplied), Limits::defaults());
  if (!table.ok()) {
    error = table.status().to_string();
    return false;
  }
  out.instance.topology = std::move(topology).value();
  out.instance.candidates = std::move(table).value();
  out.failed = failed;
  out.scarce = scarce;
  out.roomy = roomy;
  out.failed_set.insert(failed);
  const Status recorded = record_failure(out.instance, failed);
  if (!recorded.ok()) {
    error = recorded.to_string();
    return false;
  }
  const Status fenced = commit_fence(out.instance, failed, out.instance.topology.nodes().size());
  if (!fenced.ok()) {
    error = fenced.to_string();
    return false;
  }
  return true;
}

std::size_t hops_of(const ReconstructionPlan& plan) {
  std::size_t hops = 0;
  for (const RestoreStep& step : plan.restores) hops += step.hops.size();
  return hops;
}

void report_objective(const ReconstructionPlan& plan) {
  std::cout << "objective=(unresolved=" << plan.unresolved_count() << ", cost=" << plan.total_cost()
            << ", hops=" << hops_of(plan) << ")\n";
}

}  // namespace

int main() {
  ManualClock clock(kStartNs);

  // -------------------------------------------------------------------------------------------
  // 1. The same instance, built twice from differently ordered input streams.
  // -------------------------------------------------------------------------------------------
  Instance first;
  Instance second;
  std::string error;
  if (!build_main_instance(first, 0x1234ull, error)) {
    std::cout << "REFUSED instance code=Invalid detail=\"" << error << "\"\n";
    return 1;
  }
  if (!build_main_instance(second, 0xfeedfaceull, error)) {
    std::cout << "REFUSED instance code=Invalid detail=\"" << error << "\"\n";
    return 1;
  }

  const bool same_topology = first.topology.digest() == second.topology.digest();
  const bool same_candidates = first.candidates.digest() == second.candidates.digest();
  std::cout << "synthetic=true topology_digest_a=0x" << std::hex << first.topology.digest()
            << std::dec << " topology_digest_b=0x" << std::hex << second.topology.digest()
            << std::dec << "\n";
  std::cout << "input_order_invariant topology=" << (same_topology ? "true" : "false")
            << " candidates=" << (same_candidates ? "true" : "false") << "\n";
  if (!same_topology || !same_candidates) {
    std::cout << "REFUSED determinism code=Conflict detail=\"input order changed the instance\"\n";
    return 1;
  }

  const SwitchKey failed_generation(SwitchId(1), SwitchGeneration(1));
  if (first.topology.find_switch(failed_generation) == nullptr) {
    std::cout << "REFUSED fixture code=NotFound detail=\"failed generation missing\"\n";
    return 1;
  }
  GenerationVector failed_set;
  failed_set.insert(failed_generation);

  const PlanInputs inputs_a = make_inputs(first, clock, PlanId(1));
  const PlanInputs inputs_b = make_inputs(second, clock, PlanId(1));

  Result<ReconstructionPlan> plan_a = plan_reconstruction(inputs_a, failed_set);
  if (!plan_a.ok()) {
    std::cout << "REFUSED plan_a code=" << to_string(plan_a.status().code()) << " detail=\""
              << plan_a.status().message() << "\"\n";
    return 1;
  }
  Result<ReconstructionPlan> plan_b = plan_reconstruction(inputs_b, failed_set);
  if (!plan_b.ok()) {
    std::cout << "REFUSED plan_b code=" << to_string(plan_b.status().code()) << " detail=\""
              << plan_b.status().message() << "\"\n";
    return 1;
  }

  // Digests must agree, and so must the canonical encoding: a plan is data, and identical inputs
  // must produce identical data rather than merely equivalent data.
  const std::uint64_t digest_a = plan_a.value().compute_digest();
  const std::uint64_t digest_b = plan_b.value().compute_digest();
  const std::vector<std::uint8_t> bytes_a = plan_a.value().encode();
  const std::vector<std::uint8_t> bytes_b = plan_b.value().encode();
  const bool identical_digests = digest_a == digest_b;
  const bool identical_bytes = bytes_a == bytes_b;
  const bool sealed = plan_a.value().digest_valid() && plan_b.value().digest_valid();
  std::cout << "plan_digest_a=0x" << std::hex << digest_a << std::dec << " plan_digest_b=0x"
            << std::hex << digest_b << std::dec << "\n";
  std::cout << "identical_digests=" << (identical_digests ? "true" : "false")
            << " identical_encoding=" << (identical_bytes ? "true" : "false")
            << " digest_valid=" << (sealed ? "true" : "false") << "\n";
  std::cout << "feasibility=" << to_string(plan_a.value().feasibility)
            << " restores=" << plan_a.value().restores.size()
            << " unresolved=" << plan_a.value().unresolved_count() << "\n";
  report_objective(plan_a.value());
  if (!identical_digests || !identical_bytes || !sealed) {
    std::cout << "REFUSED determinism code=Conflict detail=\"plans differed across input orders\"\n";
    return 1;
  }

  // -------------------------------------------------------------------------------------------
  // 2. Capacity on the replacement generation.
  // -------------------------------------------------------------------------------------------
  CapacityScenario capacity;
  if (!build_capacity_instance(capacity, error)) {
    std::cout << "REFUSED capacity_instance code=Invalid detail=\"" << error << "\"\n";
    return 1;
  }
  const PlanInputs capacity_inputs = make_inputs(capacity.instance, clock, PlanId(2));
  const SwitchDescriptor* scarce_descriptor = capacity.instance.topology.find_switch(capacity.scarce);
  std::cout << "capacity_replacement=" << capacity.scarce.to_string()
            << " capacity=" << (scarce_descriptor != nullptr ? scarce_descriptor->capacity_score : 0)
            << " roomy_replacement=" << capacity.roomy.to_string() << "\n";

  Result<ReconstructionPlan> capacity_plan =
      plan_reconstruction(capacity_inputs, capacity.failed_set);
  if (!capacity_plan.ok()) {
    std::cout << "REFUSED capacity_plan code=" << to_string(capacity_plan.status().code())
              << " detail=\"" << capacity_plan.status().message() << "\"\n";
    return 1;
  }
  const ReconstructionPlan chosen = capacity_plan.value();
  std::cout << "capacity_feasibility=" << to_string(chosen.feasibility) << "\n";
  report_objective(chosen);
  for (const RestoreStep& step : chosen.restores) {
    std::cout << "capacity_assignment dependent=" << step.dependent.to_string()
              << " onto=" << step.replacement.to_string() << " cost=" << step.cost << "\n";
  }
  for (const UnresolvedDependent& entry : chosen.unresolved) {
    std::cout << "capacity_unresolved dependent=" << entry.dependent.to_string()
              << " reason=" << to_string(entry.reason)
              << " proven=" << (is_proven_negative(entry.reason) ? "true" : "false")
              << " detail=\"" << entry.detail << "\"\n";
  }

  // The assignment a demand-by-demand greedy pass would produce: give every dependent its own
  // cheapest admissible alternative. It is cheaper on paper and it is inadmissible, because the
  // scarce replacement generation is asked for three times and declares one unit of capacity.
  ReconstructionPlan greedy = chosen;
  std::vector<RestoreStep> greedy_steps;
  for (std::uint64_t id = 1; id <= 3; ++id) {
    RestoreStep step;
    step.dependent = DependentRef::service(id);
    step.covers_failed = capacity.failed;
    step.action = PlanAction::RebindReplacement;
    step.hops.push_back(capacity.scarce);
    step.replacement = capacity.scarce;
    step.cost = id == 1 ? 1u : (id == 2 ? 3u : 5u);
    step.evidence = EvidenceId(500 + id);
    greedy_steps.push_back(step);
  }
  greedy.restores = greedy_steps;
  greedy.unresolved.clear();
  greedy.seal();
  const ValidationReport greedy_report = validate_plan(greedy, capacity_inputs);
  std::cout << "greedy_plan_valid=" << (greedy_report.valid ? "true" : "false")
            << " outcome=" << to_string(greedy_report.outcome)
            << " findings=" << greedy_report.findings.size() << "\n";
  for (const ValidationFinding& finding : greedy_report.findings) {
    std::cout << "greedy_finding code=" << to_string(finding.code) << " scope=" << finding.scope
              << " detail=\"" << finding.detail << "\"\n";
  }

  const ReconstructionPlan chosen_validation = chosen;
  const ValidationReport chosen_report = validate_plan(chosen_validation, capacity_inputs);
  std::cout << "chosen_plan_valid=" << (chosen_report.valid ? "true" : "false")
            << " checks=" << chosen_report.checks_performed << "\n";

  bool proven_negative_reported = false;
  for (const UnresolvedDependent& entry : chosen.unresolved) {
    if (is_proven_negative(entry.reason)) proven_negative_reported = true;
  }
  const bool demonstrated = !greedy_report.valid && chosen_report.valid && proven_negative_reported;

  std::size_t chosen_hops = 0;
  for (const RestoreStep& step : chosen.restores) chosen_hops += step.hops.size();

  std::cout << "example_planning_summary synthetic=true deterministic="
            << (identical_digests && identical_bytes ? "true" : "false")
            << " plan_digest=0x" << std::hex << digest_a << std::dec
            << " main_unresolved=" << plan_a.value().unresolved_count()
            << " main_cost=" << plan_a.value().total_cost()
            << " main_hops=" << hops_of(plan_a.value()) << " capacity_unresolved="
            << chosen.unresolved_count() << " capacity_cost=" << chosen.total_cost()
            << " capacity_hops=" << chosen_hops
            << " greedy_rejected=" << (!greedy_report.valid ? "true" : "false")
            << " capacity_demonstrated=" << (demonstrated ? "true" : "false") << "\n";
  return demonstrated ? 0 : 1;
}
