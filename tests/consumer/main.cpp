// Switch Failover Fabric - downstream consumer program.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Compiled and linked ONLY against an installed prefix of the package. Every fixture here is
// SYNTHETIC: no physical switch, NIC, RDMA device or multi-node fabric is exercised.
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <sff/sff.hpp>

namespace {

int failures = 0;

void require(bool condition, const char* what) {
  if (condition) return;
  failures += 1;
  std::printf("  consumer FAIL: %s\n", what);
}

}  // namespace

int main() {
  std::printf("Switch Failover Fabric consumer, package version %s\n", sff::kVersionString);
  require(std::string(sff::kVersionString) == "1.0.0", "version string");
  require(sff::kVersionMajor == 1 && sff::kVersionMinor == 0 && sff::kVersionPatch == 0,
          "version components");
  require(std::string(sff::to_string(sff::EvidenceClass::Synthetic)) == "SYNTHETIC",
          "evidence class rendering");

  sff::ManualClock clock(1000);

  // A two-switch fabric with one dependent path and one supplied reconstruction alternative.
  const sff::SwitchKey primary(sff::SwitchId(1), sff::SwitchGeneration(1));
  const sff::SwitchKey backup(sff::SwitchId(2), sff::SwitchGeneration(1));

  std::vector<sff::SwitchDescriptor> switches;
  for (const sff::SwitchKey& key : {primary, backup}) {
    sff::SwitchDescriptor descriptor;
    descriptor.key = key;
    descriptor.role = sff::SwitchRole::Leaf;
    descriptor.admin = sff::SwitchAdminState::Enabled;
    descriptor.failure_domain = sff::FailureDomainId(key.id().raw());
    descriptor.capabilities = sff::kAllCapabilities;
    descriptor.port_count = 32;
    descriptor.capacity_score = 64;
    descriptor.label = "consumer-fixture";
    switches.push_back(descriptor);
  }

  std::vector<sff::LinkDescriptor> links;
  sff::LinkDescriptor link;
  link.id = sff::LinkId(1);
  link.a = sff::PortRef{primary, 1};
  link.b = sff::PortRef{backup, 1};
  link.cost = 1;
  links.push_back(link);

  sff::PathDescriptor path;
  path.id = sff::PathId(1);
  path.source = sff::NodeId(10);
  path.destination = sff::NodeId(11);
  path.hops = {primary, backup};
  path.cost = 2;
  path.required_capabilities = sff::capability_bit(sff::Capability::Layer3);

  sff::Result<sff::TopologySnapshot> topology = sff::TopologySnapshot::build(
      sff::TopologyVersion(1), switches, links, {path}, {}, sff::Limits::defaults());
  require(topology.ok(), "topology build");
  if (!topology.ok()) return 1;

  sff::ReconstructionCandidate candidate;
  candidate.dependent = sff::DependentRef::path(path.id);
  candidate.covers_failed = primary;
  candidate.hops = {backup};
  candidate.cost = 5;
  candidate.capabilities = sff::kAllCapabilities;
  candidate.evidence = sff::EvidenceId(1);
  candidate.source = sff::EvidenceSource::OperatorPolicy;
  sff::Result<sff::CandidateTable> table =
      sff::CandidateTable::build({candidate}, sff::Limits::defaults());
  require(table.ok(), "candidate table build");
  if (!table.ok()) return 1;

  sff::CoordinatorConfig config;
  config.enable_durability = false;
  config.evidence_class = sff::EvidenceClass::Synthetic;
  sff::Result<std::unique_ptr<sff::Coordinator>> opened = sff::Coordinator::open(config, &clock);
  require(opened.ok(), "coordinator open");
  if (!opened.ok()) return 1;
  std::unique_ptr<sff::Coordinator>& coordinator = opened.value();

  require(coordinator->install_topology(std::move(topology).value()).ok(), "install topology");
  require(coordinator->install_candidates(std::move(table).value()).ok(), "install candidates");

  sff::FailureDeclaration declaration;
  declaration.subject = primary;
  declaration.source = sff::EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = 60ull * sff::kNanosPerSecond;
  declaration.reason = "consumer synthetic failure";
  sff::Result<sff::FailoverOutcome> outcome = coordinator->declare_failure(declaration);
  require(outcome.ok(), "declare failure");
  if (!outcome.ok()) return 1;
  require(outcome.value().fence_scope == sff::FenceScopeState::Committed, "fence committed");
  require(!outcome.value().closure.dependents.empty(), "closure found the dependent");

  sff::GenerationVector roots;
  roots.insert(primary);
  sff::Result<sff::ReconstructionPlan> plan = coordinator->propose_plan(roots);
  require(plan.ok(), "propose plan");
  if (!plan.ok()) return 1;
  require(plan.value().digest_valid(), "plan digest");
  require(plan.value().feasibility == sff::PlanFeasibility::ProvenFeasible, "plan feasibility");

  sff::Result<sff::ValidationReport> report = coordinator->validate_plan(plan.value());
  require(report.ok() && report.value().valid, "independent validation");

  sff::Result<sff::ApplyReceipt> receipt = coordinator->apply_plan(plan.value());
  require(receipt.ok(), "apply plan");
  if (receipt.ok()) {
    require(receipt.value().verified == 0, "acknowledgement is not verified effect");
    require(receipt.value().outcome == sff::Code::Unverified, "apply outcome is unverified");
  }

  sff::Result<sff::RestoreDecision> decision =
      coordinator->evaluate_restore(sff::DependentRef::path(path.id));
  require(decision.ok(), "restore decision");
  if (decision.ok()) {
    require(!decision.value().may_restore, "restore refused until the effect is verified");
    require(decision.value().outcome == sff::Code::Unverified, "restore outcome unverified");
  }

  require(coordinator->shutdown().ok(), "shutdown");
  std::printf("consumer failures=%d\n", failures);
  return failures == 0 ? 0 : 1;
}
