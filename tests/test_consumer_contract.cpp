// Switch Failover Fabric - downstream consumer contract.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: the fabric below is generated in-process. No physical switch, NIC or multi-node
// fabric is exercised, and nothing here is reported as physical-hardware evidence.
//
// This translation unit includes ONLY <sff/sff.hpp>. That is the contract: a downstream consumer
// must be able to open a coordinator, install authoritative inputs, declare a failure, produce a
// plan and validate it without reaching for an internal header.
//
// The product proposition asserted end to end:
//   given authoritative evidence that a switch generation failed,
//     * the dependent authority bound to it is fenced;
//     * a supplied replacement alternative is selected under current generations;
//     * the plan is independently re-derived and accepted;
//     * acknowledgement is recorded as acknowledgement, never as verified effect;
//     * service may only be restored once independent verification exists.
// Every refusal is an explicit non-Ok outcome, and nothing that fails is ever reported as Ok.

#include <sff/sff.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "test_support.hpp"

using namespace sff;

namespace {

SwitchKey key_of(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

/// A synthetic one-hop fabric: one path that traverses the switch generation that will fail, and
/// one authoritative replacement alternative for it.
struct ConsumerFabric {
  ManualClock clock{1000000};
  Limits limits = Limits::defaults();
  TopologySnapshot topology;
  CandidateTable candidates;
  SwitchKey failed = key_of(100, 1);
  SwitchKey replacement = key_of(200, 1);
  DependentRef path = DependentRef::path(PathId(1));

  Status build() {
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
    switches.push_back(make_switch(replacement, 20, 8));

    PathDescriptor path_descriptor;
    path_descriptor.id = PathId(path.id());
    path_descriptor.source = NodeId(900);
    path_descriptor.destination = NodeId(901);
    path_descriptor.hops = {failed};
    path_descriptor.cost = 1;
    path_descriptor.required_capabilities = capability_bit(Capability::Layer3);

    Result<TopologySnapshot> built =
        TopologySnapshot::build(TopologyVersion(1), switches, {},
                                std::vector<PathDescriptor>{path_descriptor}, {}, limits);
    if (!built.ok()) return built.status();
    topology = std::move(built).value();

    ReconstructionCandidate candidate;
    candidate.dependent = path;
    candidate.covers_failed = failed;
    candidate.hops = {replacement};
    candidate.cost = 5;
    candidate.capabilities = kAllCapabilities;
    candidate.evidence = EvidenceId(7);
    candidate.source = EvidenceSource::SimulatedFixture;

    Result<CandidateTable> table =
        CandidateTable::build(std::vector<ReconstructionCandidate>{candidate}, limits);
    if (!table.ok()) return table.status();
    candidates = std::move(table).value();
    return Status::success();
  }

  GenerationVector failed_set() const {
    GenerationVector set;
    set.insert(failed);
    return set;
  }
};

/// A Result that fails must carry an explicit non-Ok code and an explanation.
#define CHECK_FAILED_RESULT(result_expr)                                \
  do {                                                                  \
    const auto& sff_result_ = (result_expr);                            \
    CHECK(!sff_result_.ok());                                           \
    CHECK(!sff_result_.status().ok());                                  \
    CHECK(sff_result_.status().code() != Code::Ok);                     \
    CHECK(sff::is_fail_closed(sff_result_.status().code()));            \
    CHECK(!sff_result_.status().message().empty());                     \
  } while (false)

/// The Status-returning half of the same contract.
#define CHECK_NON_OK_STATUS(status_expr)                                \
  do {                                                                  \
    const Status sff_status_ = (status_expr);                           \
    CHECK(!sff_status_.ok());                                           \
    CHECK(sff_status_.code() != Code::Ok);                              \
    CHECK(sff::is_fail_closed(sff_status_.code()));                     \
    CHECK(!sff_status_.message().empty());                              \
  } while (false)

}  // namespace

// ---------------------------------------------------------------------------------------------
// Version and provenance surface
// ---------------------------------------------------------------------------------------------

SFF_TEST(version_identity_is_exact_and_consistent) {
  CHECK_EQ(std::string(kVersionString), std::string("1.0.0"));
  CHECK_EQ(kVersionMajor, std::uint32_t{1});
  CHECK_EQ(kVersionMinor, std::uint32_t{0});
  CHECK_EQ(kVersionPatch, std::uint32_t{0});
  CHECK_EQ(kVersionCode, static_cast<std::uint32_t>((kVersionMajor << 16) | (kVersionMinor << 8) |
                                                    kVersionPatch));
  CHECK(std::string(kProductName) != std::string(kProductShortName));
}

SFF_TEST(every_evidence_class_renders_distinctly) {
  const EvidenceClass classes[] = {EvidenceClass::Real, EvidenceClass::Synthetic,
                                   EvidenceClass::Unsupported};
  const char* expected[] = {"REAL", "SYNTHETIC", "UNSUPPORTED"};
  for (std::size_t index = 0; index < 3; ++index) {
    CHECK_EQ(std::string(to_string(classes[index])), std::string(expected[index]));
  }
  CHECK(std::string(to_string(classes[0])) != std::string(to_string(classes[1])));
  CHECK(std::string(to_string(classes[0])) != std::string(to_string(classes[2])));
  CHECK(std::string(to_string(classes[1])) != std::string(to_string(classes[2])));

  // An undefined provenance value is reported as unrecognised rather than silently mapped onto a
  // real class.
  const std::string undefined = to_string(static_cast<EvidenceClass>(200));
  CHECK(!undefined.empty());
  CHECK(undefined != "REAL");
  CHECK(undefined != "SYNTHETIC");
  CHECK(undefined != "UNSUPPORTED");
}

// ---------------------------------------------------------------------------------------------
// The whole pipeline, through the umbrella header only
// ---------------------------------------------------------------------------------------------

SFF_TEST(the_failover_proposition_holds_through_the_public_surface) {
  ConsumerFabric fabric;
  CHECK(fabric.build().ok());

  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;  // durability explicitly disabled
  config.evidence_class = EvidenceClass::Synthetic;

  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &fabric.clock);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Coordinator> coordinator = std::move(opened).value();
  CHECK(coordinator != nullptr);
  CHECK(!coordinator->stopped());
  CHECK(coordinator->epoch().valid());
  CHECK(coordinator->boot().valid());
  CHECK(coordinator->boot_digest() != 0);
  CHECK(coordinator->evidence_class() == EvidenceClass::Synthetic);
  CHECK_EQ(coordinator->session_count(), std::size_t{0});

  // Absence of observation is Unknown, never Healthy, and is never usable authority.
  const Result<SwitchAssessment> before = coordinator->assess(fabric.failed);
  CHECK(before.ok());
  CHECK(before.value().outcome == Code::Unknown);
  CHECK(before.value().health == SwitchHealthState::Unknown);
  CHECK(!before.value().usable);
  CHECK(!before.value().durable_failure_present);

  CHECK(coordinator->install_topology(fabric.topology).ok());
  CHECK(coordinator->topology() != nullptr);
  CHECK(coordinator->install_candidates(fabric.candidates).ok());

  // Fence first: an authoritative failure declaration for the exact generation.
  FailureDeclaration declaration;
  declaration.subject = fabric.failed;
  declaration.source = EvidenceSource::SimulatedFixture;
  declaration.observed_at_ns = fabric.clock.now_ns();
  declaration.valid_for_ns = 30ull * kNanosPerSecond;
  declaration.reason = "synthetic switch generation failed";
  CHECK(declaration.validate().ok());

  const Result<FailoverOutcome> failover = coordinator->declare_failure(declaration);
  CHECK(failover.ok());
  if (!failover.ok()) return;
  CHECK(failover.value().outcome == Code::Ok);
  CHECK(failover.value().failed == fabric.failed);
  CHECK(failover.value().fence.valid());
  CHECK(failover.value().fence_scope == FenceScopeState::Committed);
  CHECK_EQ(failover.value().dependents_affected, std::size_t{1});
  CHECK_EQ(failover.value().grants_fenced, std::size_t{1});
  CHECK(!failover.value().deferred);
  CHECK(failover.value().failure.subject == fabric.failed);
  CHECK(coordinator->failures() != nullptr);
  CHECK(coordinator->failures()->contains(fabric.failed));
  CHECK(coordinator->authority() != nullptr);
  CHECK(coordinator->authority()->is_fenced(fabric.failed));
  CHECK(coordinator->evidence() != nullptr);
  CHECK_EQ(coordinator->evidence()->size(), std::size_t{1});

  // The failure lineage changes the assessment, and fencing is still not restoration.
  const Result<SwitchAssessment> after = coordinator->assess(fabric.failed);
  CHECK(after.ok());
  CHECK(after.value().durable_failure_present);
  CHECK(after.value().fence_required);
  CHECK(!after.value().usable);
  CHECK(after.value().health == SwitchHealthState::Failed);

  const Result<AuthorityQuery> fenced = coordinator->query_authority(fabric.path);
  CHECK(fenced.ok());
  CHECK(!fenced.value().has_authority);
  CHECK(fenced.value().outcome == Code::Fenced);
  CHECK(fenced.value().active_grants.empty());
  CHECK(!fenced.value().withdrawn_grants.empty());

  // Reconstruct second: the supplied alternative is selected under current generations.
  const Result<ReconstructionPlan> proposed = coordinator->propose_plan(fabric.failed_set());
  CHECK(proposed.ok());
  if (!proposed.ok()) return;
  const ReconstructionPlan plan = proposed.value();
  CHECK(plan.digest_valid());
  CHECK(plan.state == PlanState::Validated);
  CHECK(plan.epoch == coordinator->epoch());
  CHECK(plan.boot == coordinator->boot());
  CHECK(plan.closure_complete);
  CHECK(plan.feasibility == PlanFeasibility::ProvenFeasible);
  CHECK_EQ(plan.restores.size(), std::size_t{1});
  CHECK(plan.unresolved.empty());
  CHECK(plan.restores[0].dependent == fabric.path);
  CHECK(plan.restores[0].covers_failed == fabric.failed);
  CHECK(plan.restores[0].replacement == fabric.replacement);
  CHECK(plan.restores[0].hops.size() == 1 && plan.restores[0].hops[0] == fabric.replacement);

  const Result<ValidationReport> validation = coordinator->validate_plan(plan);
  CHECK(validation.ok());
  CHECK(validation.value().valid);
  CHECK(validation.value().outcome == Code::Ok);
  CHECK(validation.value().checks_performed > 0);
  CHECK_EQ(validation.value().plan_digest, plan.plan_digest);

  CHECK_EQ(coordinator->plans().size(), std::size_t{1});
  const Result<ReconstructionPlan> fetched = coordinator->plan_by_id(plan.id);
  CHECK(fetched.ok());
  CHECK(fetched.value().digest_valid());
  CHECK_EQ(fetched.value().plan_digest, plan.plan_digest);

  // A tampered plan is reported as invalid; the runtime never claims it is current.
  ReconstructionPlan tampered = plan;
  tampered.restores[0].cost = 0;
  const Result<ValidationReport> tampered_report = coordinator->validate_plan(tampered);
  CHECK(tampered_report.ok());
  CHECK(!tampered_report.value().valid);
  CHECK(tampered_report.value().outcome != Code::Ok);
  CHECK(!tampered_report.value().findings.empty());

  // Authorization is not application: minting authority requires an explicit apply.
  const Result<RestoreDecision> before_apply = coordinator->evaluate_restore(fabric.path);
  CHECK(before_apply.ok());
  CHECK(!before_apply.value().may_restore);
  CHECK(before_apply.value().outcome != Code::Ok);

  const Result<ApplyReceipt> receipt = coordinator->apply_plan(plan);
  CHECK(receipt.ok());
  if (!receipt.ok()) return;
  CHECK(receipt.value().complete);
  CHECK_EQ(receipt.value().applied, std::size_t{1});
  CHECK_EQ(receipt.value().failed, std::size_t{0});
  CHECK_EQ(receipt.value().verified, std::size_t{0});
  CHECK_EQ(receipt.value().unverified, std::size_t{1});
  CHECK(receipt.value().outcome == Code::Unverified);
  CHECK(!receipt.value().fully_verified());  // acknowledgement is not verified effect

  const Result<RestoreDecision> acknowledged = coordinator->evaluate_restore(fabric.path);
  CHECK(acknowledged.ok());
  CHECK(!acknowledged.value().may_restore);
  CHECK(!acknowledged.value().effect_verified);
  CHECK(acknowledged.value().outcome == Code::Unverified);

  // Independent verification is what finally licenses restoration.
  EvidenceRecord verification;
  verification.id = EvidenceId(900);
  verification.kind = EvidenceKind::EffectVerification;
  verification.source = EvidenceSource::TelemetryCollector;
  verification.subject = fabric.replacement;
  verification.observed_at_ns = fabric.clock.now_ns();
  verification.valid_for_ns = 30ull * kNanosPerSecond;
  verification.effect_dependent = fabric.path;
  verification.effect_plan = plan.id;
  verification.detail = "synthetic independent verification of the applied effect";
  CHECK(verification.validate(Limits::defaults()).ok());
  CHECK(coordinator->record_effect_verification(verification).ok());

  const Result<RestoreDecision> verified = coordinator->evaluate_restore(fabric.path);
  CHECK(verified.ok());
  CHECK(verified.value().may_restore);
  CHECK(verified.value().effect_verified);
  CHECK(verified.value().outcome == Code::Ok);

  CHECK(!coordinator->events(64).empty());
  CHECK(!coordinator->decisions(64).empty());
  const Result<RestartReport> restart = coordinator->restart_report();
  CHECK(restart.ok());
  CHECK(!restart.value().recovered);  // durability was disabled
  CHECK(!restart.value().dynamic_evidence_restored);

  CHECK(coordinator->shutdown().ok());
  CHECK(coordinator->shutdown().ok());  // idempotent
  CHECK(coordinator->stopped());
}

// ---------------------------------------------------------------------------------------------
// Refusals are explicit
// ---------------------------------------------------------------------------------------------

SFF_TEST(refusals_are_explicit_non_ok_outcomes) {
  ManualClock clock(1000);
  ConsumerFabric fabric;
  CHECK(fabric.build().ok());

  // Durability requested without a durable root.
  CoordinatorConfig no_root;
  no_root.enable_durability = true;
  CHECK_FAILED_RESULT(Coordinator::open(no_root, &clock));

  // A zero limit is refused outright rather than silently defaulted.
  CoordinatorConfig zero_limit;
  zero_limit.limits.max_switches = 0;
  CHECK_FAILED_RESULT(Coordinator::open(zero_limit, &clock));

  // Contradictory policy: acknowledgement-only restore while verified effect is required.
  CoordinatorConfig contradictory;
  contradictory.policy.allow_acknowledgement_restore = true;
  CHECK_FAILED_RESULT(Coordinator::open(contradictory, &clock));

  // A well-formed coordinator that has not been given any authoritative input.
  CoordinatorConfig config;
  config.enable_durability = false;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  CHECK(opened.ok());
  if (!opened.ok()) return;
  std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

  CHECK_NON_OK_STATUS(coordinator->install_topology(TopologySnapshot{}));
  CHECK(coordinator->topology() == nullptr);

  // Absence of supplied alternatives is not evidence that none exist.
  CHECK_FAILED_RESULT(coordinator->propose_plan(fabric.failed_set()));
  CHECK_FAILED_RESULT(coordinator->plan_by_id(PlanId(404)));
  CHECK_FAILED_RESULT(coordinator->evaluate_restore(DependentRef{}));

  // Installing a topology is not a grant of authority for anything that was never declared.
  CHECK(coordinator->install_topology(fabric.topology).ok());
  const Result<AuthorityQuery> undeclared = coordinator->query_authority(DependentRef::path(PathId(77)));
  CHECK(undeclared.ok());
  CHECK(!undeclared.value().has_authority);
  CHECK(undeclared.value().outcome != Code::Ok);

  // An unknown switch generation is adjudicated explicitly, never optimistically.
  const Result<SwitchAssessment> unknown = coordinator->assess(key_of(987654, 3));
  CHECK(unknown.ok());
  CHECK(unknown.value().outcome == Code::Unknown);
  CHECK(!unknown.value().usable);
  CHECK(unknown.value().health == SwitchHealthState::Unknown);

  CHECK(coordinator->shutdown().ok());
  CHECK_NON_OK_STATUS(coordinator->install_topology(fabric.topology));
  CHECK_NON_OK_STATUS(coordinator->install_candidates(fabric.candidates));
  CHECK_FAILED_RESULT(coordinator->propose_plan(fabric.failed_set()));
}

SFF_MAIN()
