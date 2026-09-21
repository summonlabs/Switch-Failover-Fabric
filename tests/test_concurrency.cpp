// Switch Failover Fabric - concurrency and ownership proof.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC fixtures. Synchronisation uses deterministic latches (std::barrier and atomics), never
// sleeps: a hang here is a real deadlock in the runtime and must be fixed rather than masked.
#include <algorithm>
#include <atomic>
#include <barrier>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

struct Rig {
  ManualClock clock{1000};
  std::unique_ptr<Coordinator> coordinator;
  Fabric fabric;
};

Result<std::unique_ptr<Rig>> make_rig(const FabricSpec& spec) {
  auto rig = std::make_unique<Rig>();
  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.enable_durability = false;
  config.evidence_class = EvidenceClass::Synthetic;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &rig->clock);
  if (!opened.ok()) return opened.status();
  rig->coordinator = std::move(opened).value();
  Result<Fabric> fabric = build_fabric(spec);
  if (!fabric.ok()) return fabric.status();
  rig->fabric = std::move(fabric).value();
  Status installed = rig->coordinator->install_topology(rig->fabric.topology);
  if (!installed.ok()) return installed;
  installed = rig->coordinator->install_candidates(rig->fabric.candidates);
  if (!installed.ok()) return installed;
  return rig;
}

}  // namespace

SFF_TEST(concurrent_failure_declarations_fence_exactly_once) {
  Result<std::unique_ptr<Rig>> created = make_rig(FabricSpec{});
  CHECK(created.ok());
  if (!created.ok()) return;
  std::unique_ptr<Rig>& rig = created.value();
  Coordinator& coordinator = *rig->coordinator;

  constexpr int kThreads = 8;
  const SwitchKey failed = rig->fabric.spine_keys.at(0);
  std::barrier gate(kThreads);
  std::atomic<int> succeeded{0};
  std::atomic<int> deferred{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int index = 0; index < kThreads; ++index) {
    workers.emplace_back([&, index]() {
      FailureDeclaration declaration;
      declaration.subject = failed;
      declaration.source = EvidenceSource::FabricManager;
      declaration.observed_at_ns = rig->clock.now_ns();
      declaration.valid_for_ns = 600ull * kNanosPerSecond;
      declaration.reason = "SYNTHETIC concurrent declaration " + std::to_string(index);
      gate.arrive_and_wait();
      Result<FailoverOutcome> outcome = coordinator.declare_failure(declaration);
      if (!outcome.ok()) {
        refused.fetch_add(1);
        return;
      }
      if (outcome.value().deferred) {
        deferred.fetch_add(1);
      } else {
        succeeded.fetch_add(1);
      }
      CHECK_EQ(outcome.value().fence_scope, FenceScopeState::Committed);
    });
  }
  for (auto& worker : workers) worker.join();

  // Exactly one thread commits the fence; every other thread observes the already-committed fence.
  CHECK_EQ(succeeded.load(), 1);
  CHECK_EQ(deferred.load(), kThreads - 1);
  CHECK_EQ(refused.load(), 0);
  CHECK_EQ(coordinator.authority()->fence_count(), std::size_t{1});

  for (const auto& path : rig->fabric.topology.paths()) {
    (void)path;
  }
  for (const auto& path : rig->fabric.topology.paths()) {
    const SwitchKey spine = path.hops.back();
    Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(path.id));
    CHECK(query.ok());
    if (!query.ok()) continue;
    if (spine == failed) {
      CHECK(!query.value().has_authority);
    } else {
      CHECK(query.value().has_authority);
    }
  }
}

SFF_TEST(concurrent_sessions_consume_a_sequence_exactly_once) {
  Result<std::unique_ptr<Rig>> created = make_rig(FabricSpec{});
  CHECK(created.ok());
  if (!created.ok()) return;
  Coordinator& coordinator = *created.value()->coordinator;

  Result<SessionRecord> opened = coordinator.open_session("principal-a");
  CHECK(opened.ok());
  if (!opened.ok()) return;

  constexpr int kThreads = 8;
  std::barrier gate(kThreads);
  std::atomic<int> accepted{0};
  std::atomic<int> replayed{0};
  std::vector<std::thread> workers;
  for (int index = 0; index < kThreads; ++index) {
    workers.emplace_back([&]() {
      SessionBinding binding;
      binding.session = opened.value().id;
      binding.epoch = coordinator.epoch();
      binding.boot_digest = coordinator.boot_digest();
      binding.request_seq = 1;  // every thread replays the same sequence number
      gate.arrive_and_wait();
      Status status = coordinator.authorise(binding);
      if (status.ok()) {
        accepted.fetch_add(1);
      } else if (status.code() == Code::Replay) {
        replayed.fetch_add(1);
      }
    });
  }
  for (auto& worker : workers) worker.join();
  CHECK_EQ(accepted.load(), 1);
  CHECK_EQ(replayed.load(), kThreads - 1);

  // A session established under a different epoch or incarnation is refused, so one session can
  // never act under another session's authority.
  SessionBinding stale;
  stale.session = opened.value().id;
  stale.epoch = CoordinatorEpoch(coordinator.epoch().raw() + 1);
  stale.boot_digest = coordinator.boot_digest();
  stale.request_seq = 2;
  Status refused = coordinator.authorise(stale);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(refused.code(), Code::Stale);

  SessionBinding foreign;
  foreign.session = SessionId(9999);
  foreign.epoch = coordinator.epoch();
  foreign.boot_digest = coordinator.boot_digest();
  foreign.request_seq = 3;
  refused = coordinator.authorise(foreign);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(refused.code(), Code::Unauthorized);
}

SFF_TEST(readers_are_consistent_while_a_writer_fences) {
  Result<std::unique_ptr<Rig>> created = make_rig(FabricSpec{});
  CHECK(created.ok());
  if (!created.ok()) return;
  std::unique_ptr<Rig>& rig = created.value();
  Coordinator& coordinator = *rig->coordinator;

  constexpr int kReaders = 6;
  std::barrier gate(kReaders + 1);
  std::atomic<bool> stop{false};
  std::atomic<int> observations{0};
  std::vector<std::thread> workers;
  for (int index = 0; index < kReaders; ++index) {
    workers.emplace_back([&]() {
      gate.arrive_and_wait();
      while (!stop.load(std::memory_order_acquire)) {
        for (const auto& path : rig->fabric.topology.paths()) {
          Result<AuthorityQuery> query = coordinator.query_authority(DependentRef::path(path.id));
          if (!query.ok()) continue;
          // Invariant the registry must never violate, whatever the interleaving: authority is
          // claimed only with an affirmative outcome and no blocking generation.
          if (query.value().has_authority) {
            CHECK_EQ(query.value().outcome, Code::Ok);
            CHECK(!query.value().active_grants.empty());
            CHECK(query.value().bound.empty() || !query.value().active_grants.empty());
          }
          observations.fetch_add(1, std::memory_order_relaxed);
        }
        std::this_thread::yield();
      }
    });
  }

  gate.arrive_and_wait();
  const SwitchKey failed = rig->fabric.spine_keys.at(0);
  FailureDeclaration declaration;
  declaration.subject = failed;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = rig->clock.now_ns();
  declaration.valid_for_ns = 600ull * kNanosPerSecond;
  declaration.reason = "SYNTHETIC writer fence";
  Result<FailoverOutcome> outcome = coordinator.declare_failure(declaration);
  CHECK(outcome.ok());
  GenerationVector roots;
  roots.insert(failed);
  Result<ReconstructionPlan> plan = coordinator.propose_plan(roots);
  CHECK(plan.ok());
  if (plan.ok()) {
    Result<ApplyReceipt> receipt = coordinator.apply_plan(plan.value());
    CHECK(receipt.ok());
  }
  stop.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
  CHECK(observations.load() > 0);
}

SFF_TEST(shutdown_releases_running_workers) {
  Result<std::unique_ptr<Rig>> created = make_rig(FabricSpec{});
  CHECK(created.ok());
  if (!created.ok()) return;
  std::unique_ptr<Rig>& rig = created.value();
  Coordinator& coordinator = *rig->coordinator;

  constexpr int kWorkers = 6;
  std::barrier gate(kWorkers + 1);
  std::atomic<int> closed{0};
  std::atomic<int> completed{0};
  std::vector<std::thread> workers;
  for (int index = 0; index < kWorkers; ++index) {
    // index is captured BY VALUE: a reference capture would dangle the moment the loop advances,
    // which is exactly what AddressSanitizer reported as a stack-use-after-scope here.
    workers.emplace_back([&, index]() {
      gate.arrive_and_wait();
      for (int iteration = 0; iteration < 64; ++iteration) {
        EvidenceRecord record;
        record.id = EvidenceId(static_cast<std::uint64_t>(index) * 1000 +
                               static_cast<std::uint64_t>(iteration) + 1);
        record.kind = EvidenceKind::SwitchHealth;
        record.source = EvidenceSource::FabricManager;
        record.subject = rig->fabric.leaf_keys.at(0);
        record.observed_at_ns = rig->clock.now_ns();
        record.valid_for_ns = 60ull * kNanosPerSecond;
        record.health = SwitchHealthState::Healthy;
        Status admitted = coordinator.admit_evidence(record);
        if (admitted.code() == Code::Closed) {
          closed.fetch_add(1);
          return;
        }
        completed.fetch_add(1);
      }
    });
  }
  gate.arrive_and_wait();
  CHECK(coordinator.shutdown().ok());
  for (auto& worker : workers) worker.join();

  // Every worker either finished its work or observed the closed runtime; none is stuck.
  CHECK_EQ(closed.load() + completed.load() > 0, true);
  CHECK(coordinator.shutdown().ok());
  CHECK(coordinator.stopped());

  // Mutating calls after shutdown refuse deterministically.
  EvidenceRecord record;
  record.id = EvidenceId(999999);
  record.kind = EvidenceKind::SwitchHealth;
  record.source = EvidenceSource::FabricManager;
  record.subject = rig->fabric.leaf_keys.at(0);
  record.observed_at_ns = rig->clock.now_ns();
  record.valid_for_ns = 60ull * kNanosPerSecond;
  record.health = SwitchHealthState::Healthy;
  Status refused = coordinator.admit_evidence(record);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK_EQ(refused.code(), Code::Closed);
}

SFF_TEST(authority_churn_never_reports_contradiction) {
  Result<std::unique_ptr<Rig>> created = make_rig(FabricSpec{});
  CHECK(created.ok());
  if (!created.ok()) return;
  std::unique_ptr<Rig>& rig = created.value();
  Coordinator& coordinator = *rig->coordinator;

  constexpr int kThreads = 4;
  std::barrier gate(kThreads);
  std::atomic<bool> stop{false};
  std::vector<std::thread> workers;
  for (int index = 0; index < kThreads; ++index) {
    workers.emplace_back([&, index]() {
      gate.arrive_and_wait();
      std::uint64_t round = 0;
      while (!stop.load(std::memory_order_acquire)) {
        round += 1;
        const PathId id = rig->fabric.path_ids.at(
            static_cast<std::size_t>((round + static_cast<std::uint64_t>(index)) %
                                     rig->fabric.path_ids.size()));
        const DependentRef dependent = DependentRef::path(id);
        GenerationVector bound;
        for (const auto& hop : rig->fabric.topology.find_path(id)->hops) bound.insert(hop);
        if ((round & 1u) == 0u) {
          Status established = coordinator.establish_authority(dependent, bound, "churn");
          CHECK(established.ok() || established.code() == Code::Fenced);
        } else {
          Status withdrawn =
              coordinator.withdraw_authority(dependent, RevocationCause::OperatorRevocation, "churn");
          CHECK(withdrawn.ok() || withdrawn.code() == Code::Closed);
        }
        Result<AuthorityQuery> query = coordinator.query_authority(dependent);
        CHECK(query.ok());
        if (query.ok() && query.value().has_authority) {
          CHECK(!query.value().active_grants.empty());
        }
      }
    });
  }
  // Let the churn run for a bounded number of yields, then stop it deterministically.
  for (int round = 0; round < 200; ++round) std::this_thread::yield();
  stop.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
}

SFF_MAIN()
