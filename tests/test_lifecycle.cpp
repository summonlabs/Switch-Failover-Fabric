// Switch Failover Fabric - lifecycle suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Lifecycle is where a fail-closed runtime is easiest to break by accident: a second close, a
// missing close, a session that outlives its incarnation, an epoch that fails to advance, or a
// staging file left behind. Every case below asserts those edges directly.
//
// SYNTHETIC: every fixture, journal and session in this file is generated in-process. No physical
// switch, NIC, RDMA device or multi-node fabric is exercised.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
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

EvidenceRecord health_evidence(const SwitchKey& key, EvidenceId id, TimestampNs observed_at_ns) {
  EvidenceRecord record;
  record.id = id;
  record.kind = EvidenceKind::SwitchHealth;
  record.source = EvidenceSource::FabricManager;
  record.subject = key;
  record.observed_at_ns = observed_at_ns;
  record.valid_for_ns = 3600ull * kNanosPerSecond;
  record.health = SwitchHealthState::Healthy;
  record.detail = "SYNTHETIC fixture observation";
  return record;
}

Result<std::unique_ptr<DurableStore>> open_store(const std::filesystem::path& root,
                                                 OpenMode mode = OpenMode::OpenOrCreate) {
  StoreOptions options;
  options.root = root;
  options.limits = Limits::defaults();
  options.mode = mode;
  options.durable_writes = true;
  return DurableStore::open(options);
}

std::vector<std::string> directory_entries(const std::filesystem::path& root, bool& failed) {
  std::vector<std::string> names;
  std::error_code code;
  for (const auto& entry : std::filesystem::directory_iterator(root, code)) {
    names.push_back(entry.path().filename().string());
  }
  failed = static_cast<bool>(code);
  std::sort(names.begin(), names.end());
  return names;
}

SessionBinding binding_of(SessionId id, CoordinatorEpoch epoch, std::uint64_t boot_digest,
                          std::uint64_t sequence) {
  SessionBinding value;
  value.session = id;
  value.epoch = epoch;
  value.boot_digest = boot_digest;
  value.request_seq = sequence;
  return value;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// shutdown()
// ---------------------------------------------------------------------------------------------

SFF_TEST(shutdown_is_idempotent_and_every_mutating_call_is_closed) {
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

  CHECK(!coordinator.stopped());
  // Idempotent: every call reports success, and the first one really did the work.
  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.stopped());
  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.stopped());

  // Every mutating entry point refuses with Closed after shutdown.
  CHECK_EQ(coordinator.install_topology(fabric.topology).code(), Code::Closed);
  CHECK_EQ(coordinator.install_candidates(fabric.candidates).code(), Code::Closed);
  CHECK_EQ(coordinator.install_policy(Policy{}).code(), Code::Closed);
  CHECK_EQ(coordinator
               .admit_evidence(health_evidence(fabric.leaf_keys.at(0), EvidenceId(770001),
                                               harness.clock.now_ns()))
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
                                          RevocationCause::Shutdown)
               .code(),
           Code::Closed);
  CHECK_EQ(coordinator.apply_plan(plan).status().code(), Code::Closed);
  {
    EvidenceRecord verification;
    verification.id = EvidenceId(770002);
    verification.kind = EvidenceKind::EffectVerification;
    verification.source = EvidenceSource::FabricManager;
    verification.subject = fabric.leaf_keys.at(0);
    verification.observed_at_ns = harness.clock.now_ns();
    verification.valid_for_ns = 3600ull * kNanosPerSecond;
    verification.effect_dependent = DependentRef::path(fabric.path_ids.at(0));
    verification.effect_plan = plan.id;
    CHECK_EQ(coordinator.record_effect_verification(verification).code(), Code::Closed);
  }
  CHECK_EQ(coordinator.open_session("after-shutdown").status().code(), Code::Closed);

  // Nothing was mutated by any of those refusals.
  CHECK_EQ(coordinator.authority()->fence_count(), fences_before);
  CHECK_EQ(coordinator.failures()->size(), failures_before);
  CHECK_EQ(coordinator.plans().size(), plans_before);
  CHECK_EQ(coordinator.authority()->total_grant_count(), grants_before);

  // Queries that remain safe still answer, and the sessions are all closed.
  CHECK(coordinator.restart_report().ok());
  CHECK_EQ(coordinator.session_count(), std::size_t{1});
  CHECK_EQ(coordinator.authorise(binding_of(session.value().id, coordinator.epoch(),
                                            coordinator.boot_digest(), 1))
               .code(),
           Code::Closed);
  CHECK(coordinator.query_authority(DependentRef::path(fabric.path_ids.at(0))).ok());
  CHECK(coordinator.assess(failed).ok());
  CHECK(coordinator.plan_by_id(plan.id).ok());
  CHECK(coordinator.topology() != nullptr);
  CHECK(coordinator.failures()->contains(failed));
  CHECK(coordinator.authority()->is_fenced(failed));
  CHECK(coordinator.limits().max_sessions > 0);
  CHECK_EQ(coordinator.epoch().raw(), std::uint64_t{1});
  CHECK(coordinator.boot().valid());
}

// ---------------------------------------------------------------------------------------------
// destructors
// ---------------------------------------------------------------------------------------------

SFF_TEST(destructor_with_and_without_shutdown_leaves_a_replayable_journal) {
  TempDir directory("lifecycle-destructor");
  ManualClock clock(1000);
  const std::filesystem::path root = directory.path() / "durable";

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  const SwitchKey failed = fabric.spine_keys.at(0);

  // A coordinator constructed in a scope and destroyed WITHOUT shutdown.
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value();
    CHECK(coordinator.install_topology(fabric.topology).ok());
    CHECK(coordinator.declare_failure(failure_of(failed, clock.now_ns())).ok());
    CHECK(!coordinator.stopped());
    // No shutdown(): the destructor must close the journal without corrupting it.
  }

  // The journal it wrote is still replayable by a fresh DurableStore.
  {
    Result<std::unique_ptr<DurableStore>> store = open_store(root, OpenMode::OpenExisting);
    CHECK(store.ok());
    if (!store.ok()) return;
    CHECK(!store.value()->closed());
    Result<ReplayReport> replay = store.value()->replay();
    CHECK(replay.ok());
    if (replay.ok()) {
      CHECK(!replay.value().records.empty());
      CHECK_EQ(replay.value().status.code(), Code::Ok);
      CHECK_EQ(replay.value().corrupt_records, std::size_t{0});
      CHECK_EQ(replay.value().torn_records, std::size_t{0});
      CHECK_EQ(replay.value().unsupported_records, std::size_t{0});
      // No clean-shutdown marker was written, and that is reported, not hidden.
      CHECK(!replay.value().clean_shutdown);
    }
    // Closing the borrowed store must not disturb the journal either.
    CHECK(store.value()->close().ok());
    CHECK(store.value()->closed());
    CHECK(store.value()->close().ok());
  }

  // A fresh coordinator recovers the lineage and reports the previous shutdown as unclean.
  {
    Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(root, clock);
    CHECK(reopened.ok());
    if (!reopened.ok()) return;
    Coordinator& coordinator = *reopened.value();
    Result<RestartReport> report = coordinator.restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().recovered);
      CHECK(!report.value().clean_previous_shutdown);
      CHECK(report.value().failures_restored >= 1);
      CHECK(report.value().fences_restored >= 1);
    }
    CHECK(coordinator.failures()->contains(failed));
    CHECK(coordinator.authority()->is_fenced(failed));
    CHECK(coordinator.shutdown().ok());
  }

  // Destroying a coordinator that was already shut down must not double-close or corrupt.
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    CHECK(opened.value()->shutdown().ok());
    CHECK(opened.value()->shutdown().ok());
    CHECK(opened.value()->stopped());
  }
  {
    Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(root, clock);
    CHECK(reopened.ok());
    if (!reopened.ok()) return;
    Result<RestartReport> report = reopened.value()->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().clean_previous_shutdown);
      CHECK(report.value().failures_restored >= 1);
      CHECK(report.value().fences_restored >= 1);
    }
    CHECK(reopened.value()->failures()->contains(failed));
    CHECK(reopened.value()->authority()->is_fenced(failed));
    CHECK(reopened.value()->shutdown().ok());
  }
}

// ---------------------------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------------------------

SFF_TEST(sessions_open_authorise_close_and_exhaust) {
  // Registry level: the bound, the monotonic sequence and close_all().
  {
    Limits limits = Limits::defaults();
    limits.max_sessions = 2;
    const CoordinatorEpoch epoch(7);
    const BootIncarnation boot = BootIncarnation::from_parts(11, 3, 5, 7);
    SessionRegistry registry(limits);

    Result<SessionRecord> alpha = registry.open("alpha", epoch, boot, 1000);
    Result<SessionRecord> beta = registry.open("beta", epoch, boot, 1001);
    CHECK(alpha.ok());
    CHECK(beta.ok());
    if (!alpha.ok() || !beta.ok()) return;
    CHECK_EQ(alpha.value().principal, std::string("alpha"));
    CHECK_EQ(registry.size(), std::size_t{2});

    Result<SessionRecord> gamma = registry.open("gamma", epoch, boot, 1002);
    CHECK(!gamma.ok());
    if (!gamma.ok()) CHECK_EQ(gamma.status().code(), Code::Exhausted);
    CHECK_EQ(registry.size(), std::size_t{2});

    SessionBinding binding = binding_of(alpha.value().id, epoch, 12345, 1);
    CHECK(registry.authorise(binding, epoch, 12345).ok());
    binding.request_seq = 1;
    CHECK_EQ(registry.authorise(binding, epoch, 12345).code(), Code::Replay);
    binding.request_seq = 2;
    CHECK(registry.authorise(binding, epoch, 12345).ok());
    // A refused request never consumed the number it named: 2 is still a replay after 2 was
    // accepted, and 3 is still available.
    binding.request_seq = 2;
    CHECK_EQ(registry.authorise(binding, epoch, 12345).code(), Code::Replay);
    binding.request_seq = 1;
    CHECK_EQ(registry.authorise(binding, epoch, 12345).code(), Code::Replay);
    binding.request_seq = 3;
    CHECK(registry.authorise(binding, epoch, 12345).ok());
    // A different epoch or incarnation is stale, whatever the sequence says.
    CHECK_EQ(registry.authorise(binding_of(alpha.value().id, CoordinatorEpoch(8), 12345, 4), epoch,
                                12345)
                 .code(),
             Code::Stale);
    CHECK_EQ(registry.authorise(binding_of(alpha.value().id, epoch, 999, 4), epoch, 12345).code(),
             Code::Stale);
    // Sequence numbers are per session.
    CHECK(registry.authorise(binding_of(beta.value().id, epoch, 12345, 1), epoch, 12345).ok());

    // close_all() invalidates everything it holds.
    CHECK_EQ(registry.close_all(), std::size_t{2});
    CHECK(registry.contains(alpha.value().id));
    CHECK_EQ(registry.authorise(binding_of(alpha.value().id, epoch, 12345, 100), epoch, 12345)
                 .code(),
             Code::Closed);
    CHECK_EQ(registry.authorise(binding_of(beta.value().id, epoch, 12345, 100), epoch, 12345)
                 .code(),
             Code::Closed);
    // Idempotent, and closing an unknown identity is an explicit refusal.
    CHECK_EQ(registry.close_all(), std::size_t{0});
    CHECK(registry.close(alpha.value().id).ok());
    CHECK_EQ(registry.close(SessionId(9999)).code(), Code::NotFound);
    CHECK_EQ(registry.close(SessionId(0)).code(), Code::NotFound);
  }

  // Coordinator level: the same rules through the runtime boundary.
  {
    Limits limits = Limits::defaults();
    limits.max_sessions = 2;
    Result<std::unique_ptr<Harness>> opened = open_harness(FabricSpec{}, limits);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value()->coordinator;

    Result<SessionRecord> one = coordinator.open_session("one");
    Result<SessionRecord> two = coordinator.open_session("two");
    CHECK(one.ok());
    CHECK(two.ok());
    if (!one.ok() || !two.ok()) return;
    CHECK_EQ(coordinator.session_count(), std::size_t{2});

    Result<SessionRecord> three = coordinator.open_session("three");
    CHECK(!three.ok());
    if (!three.ok()) CHECK_EQ(three.status().code(), Code::Exhausted);
    CHECK_EQ(coordinator.session_count(), std::size_t{2});

    const CoordinatorEpoch epoch = coordinator.epoch();
    const std::uint64_t digest = coordinator.boot_digest();
    CHECK(coordinator.authorise(binding_of(one.value().id, epoch, digest, 1)).ok());
    CHECK(coordinator.close_session(one.value().id).ok());
    // A closed session refuses further requests.
    CHECK_EQ(coordinator.authorise(binding_of(one.value().id, epoch, digest, 2)).code(),
             Code::Closed);
    // Closing again is idempotent; closing an unknown identity is NotFound.
    CHECK(coordinator.close_session(one.value().id).ok());
    CHECK_EQ(coordinator.close_session(SessionId(4242)).code(), Code::NotFound);
    // The surviving session is untouched by the other session's closure.
    CHECK(coordinator.authorise(binding_of(two.value().id, epoch, digest, 1)).ok());

    // Shutdown closes everything that is left.
    CHECK(coordinator.shutdown().ok());
    CHECK_EQ(coordinator.authorise(binding_of(two.value().id, epoch, digest, 2)).code(),
             Code::Closed);
    CHECK_EQ(coordinator.session_count(), std::size_t{2});
  }
}

// ---------------------------------------------------------------------------------------------
// durable restart reports
// ---------------------------------------------------------------------------------------------

SFF_TEST(durable_restart_reports_clean_and_unclean_shutdowns) {
  TempDir directory("lifecycle-shutdown-report");
  ManualClock clock(1000);
  const std::filesystem::path clean_root = directory.path() / "clean";
  const std::filesystem::path unclean_root = directory.path() / "unclean";

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  const SwitchKey failed = fabric.spine_keys.at(0);

  // A fresh durable root has nothing to recover and no clean shutdown behind it.
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(clean_root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Result<RestartReport> report = opened.value()->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      // Nothing was recovered from a brand-new journal, so nothing may claim recovery.
      CHECK(!report.value().recovered);
      CHECK(!report.value().clean_previous_shutdown);
      CHECK_EQ(report.value().records_replayed, std::size_t{0});
      CHECK_EQ(report.value().failures_restored, std::size_t{0});
      CHECK_EQ(report.value().fences_restored, std::size_t{0});
      CHECK(!report.value().dynamic_evidence_restored);
      CHECK(report.value().status.ok());
    }
    CHECK(opened.value()->install_topology(fabric.topology).ok());
    CHECK(opened.value()->declare_failure(failure_of(failed, clock.now_ns())).ok());
    CHECK(opened.value()->shutdown().ok());
  }
  {
    Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(clean_root, clock);
    CHECK(reopened.ok());
    if (!reopened.ok()) return;
    Result<RestartReport> report = reopened.value()->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().recovered);
      CHECK(report.value().clean_previous_shutdown);
      CHECK(report.value().records_replayed > 0);
      CHECK(report.value().failures_restored >= 1);
      CHECK(report.value().fences_restored >= 1);
      CHECK_EQ(report.value().previous_epoch.raw(), std::uint64_t{1});
      CHECK_EQ(report.value().current_epoch.raw(), std::uint64_t{2});
      CHECK_EQ(report.value().previous_boot.boot_ordinal(), std::uint64_t{1});
      CHECK_EQ(report.value().current_boot.boot_ordinal(), std::uint64_t{2});
    }
    CHECK(reopened.value()->failures()->contains(failed));
    CHECK(reopened.value()->authority()->is_fenced(failed));
    CHECK(reopened.value()->shutdown().ok());
  }

  // The same lifecycle without shutdown reports the previous run as unclean - and still recovers
  // the durable lineage, because lineage is not liveness.
  {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(unclean_root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    CHECK(opened.value()->install_topology(fabric.topology).ok());
    CHECK(opened.value()->declare_failure(failure_of(failed, clock.now_ns())).ok());
  }
  {
    Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(unclean_root, clock);
    CHECK(reopened.ok());
    if (!reopened.ok()) return;
    Result<RestartReport> report = reopened.value()->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().recovered);
      CHECK(!report.value().clean_previous_shutdown);
      CHECK(report.value().failures_restored >= 1);
      CHECK(report.value().fences_restored >= 1);
      CHECK(!report.value().dynamic_evidence_restored);
    }
    CHECK(reopened.value()->failures()->contains(failed));
    CHECK(reopened.value()->authority()->is_fenced(failed));
    CHECK_EQ(reopened.value()->evidence()->size(), std::size_t{0});
    CHECK(reopened.value()->topology() == nullptr);
    CHECK(reopened.value()->shutdown().ok());
  }
}

// ---------------------------------------------------------------------------------------------
// repeated open/close cycles
// ---------------------------------------------------------------------------------------------

SFF_TEST(repeated_open_close_cycles_advance_epoch_and_boot_monotonically) {
  TempDir directory("lifecycle-cycles");
  ManualClock clock(1000);
  const std::filesystem::path root = directory.path() / "durable";

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();

  std::uint64_t previous_epoch = 0;
  std::uint64_t previous_boot = 0;
  const std::uint64_t last_cycle = 6;
  for (std::uint64_t cycle = 1; cycle <= last_cycle; ++cycle) {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value();

    // Both counters advance monotonically, and by exactly one step per clean cycle.
    CHECK_LT(previous_epoch, coordinator.epoch().raw());
    CHECK_LT(previous_boot, coordinator.boot().boot_ordinal());
    CHECK_EQ(coordinator.epoch().raw(), cycle);
    CHECK_EQ(coordinator.boot().boot_ordinal(), cycle);
    CHECK(coordinator.boot().valid());

    Result<RestartReport> report = coordinator.restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK_EQ(report.value().previous_epoch.raw(), previous_epoch);
      CHECK_EQ(report.value().current_epoch.raw(), cycle);
      CHECK_EQ(report.value().previous_boot.boot_ordinal(), previous_boot);
      CHECK_EQ(report.value().current_boot.boot_ordinal(), cycle);
      CHECK_EQ(report.value().clean_previous_shutdown, cycle > 1);
      // Cycle one starts from an empty journal; every later cycle replays real lineage.
      CHECK_EQ(report.value().recovered, cycle > 1);
      CHECK_EQ(report.value().records_replayed > 0, cycle > 1);
      CHECK(!report.value().dynamic_evidence_restored);
    }

    // The runtime is fully usable in every cycle, and refuses mutation once it is stopped.
    CHECK(coordinator.install_topology(fabric.topology).ok());
    CHECK(coordinator.install_candidates(fabric.candidates).ok());
    CHECK(coordinator.open_session("cycle-operator").ok());
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{0});
    CHECK(coordinator.shutdown().ok());
    CHECK(coordinator.shutdown().ok());
    CHECK(coordinator.stopped());
    CHECK_EQ(coordinator
                 .declare_failure(failure_of(fabric.spine_keys.at(0), clock.now_ns()))
                 .status()
                 .code(),
             Code::Closed);

    previous_epoch = coordinator.epoch().raw();
    previous_boot = coordinator.boot().boot_ordinal();
  }
  CHECK_EQ(previous_epoch, last_cycle);
  CHECK_EQ(previous_boot, last_cycle);
}

// ---------------------------------------------------------------------------------------------
// clean lifecycle leaves nothing behind
// ---------------------------------------------------------------------------------------------

SFF_TEST(a_clean_lifecycle_leaves_no_staging_files_behind) {
  TempDir directory("lifecycle-clean");
  ManualClock clock(1000);
  const std::filesystem::path root = directory.path() / "durable";

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();

  // Two complete durable lifecycles, each cleanly shut down.
  for (std::uint64_t cycle = 1; cycle <= 2; ++cycle) {
    Result<std::unique_ptr<Coordinator>> opened = open_coordinator(root, clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Coordinator& coordinator = *opened.value();
    CHECK(coordinator.install_topology(fabric.topology).ok());
    CHECK(coordinator.install_candidates(fabric.candidates).ok());
    CHECK(coordinator
              .declare_failure(failure_of(fabric.spine_keys.at(0), clock.now_ns(),
                                          "SYNTHETIC cycle declaration"))
              .ok());
    CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});
    CHECK(coordinator.shutdown().ok());
  }

  bool failed = false;
  const std::vector<std::string> names = directory_entries(root, failed);
  CHECK(!failed);
  CHECK(!names.empty());
  for (const auto& name : names) {
    // Only the journal and, if one were ever published, the snapshot may exist.
    CHECK(name == std::string("sff.journal") || name == std::string("sff.snapshot"));
    CHECK(name.find(".staging") == std::string::npos);
    CHECK(name.find(".tmp") == std::string::npos);
    CHECK(name.find("~") == std::string::npos);
  }
  CHECK_EQ(std::count(names.begin(), names.end(), std::string("sff.journal")),
           static_cast<std::ptrdiff_t>(1));

  // The root is still readable and carries the lineage written across both cycles.
  {
    Result<std::unique_ptr<Coordinator>> reopened = open_coordinator(root, clock);
    CHECK(reopened.ok());
    if (!reopened.ok()) return;
    Result<RestartReport> report = reopened.value()->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().clean_previous_shutdown);
      CHECK(report.value().failures_restored >= 1);
      CHECK(report.value().fences_restored >= 1);
      CHECK_EQ(report.value().torn_records, std::size_t{0});
      CHECK_EQ(report.value().corrupt_records, std::size_t{0});
      CHECK_EQ(report.value().unsupported_records, std::size_t{0});
    }
    CHECK(reopened.value()->shutdown().ok());
  }

  // Shutdown did not create a staging file either.
  bool second_failed = false;
  const std::vector<std::string> after = directory_entries(root, second_failed);
  CHECK(!second_failed);
  CHECK(after == names);
}

SFF_MAIN()
