// Switch Failover Fabric - restart, torn-tail and corruption proof.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every fixture in this suite is generated in-process by sfftest::build_fabric. No
// physical switch, NIC, RDMA device or multi-node fabric is exercised, and nothing here is
// hardware evidence.
//
// These cases drive real DurableStore files in a self-cleaning temporary directory. They prove
// what survives a process boundary (failure lineage, fences) and what explicitly does not
// (dynamic evidence, sessions, liveness, active authority).
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "sff/sff.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

constexpr const char* kJournalName = "sff.journal";

/// Trailing payload integrity word of one durable record. Named separately from the frame
/// trailer so the two protocol layers are never confused.
constexpr std::size_t kRecordTrailerBytes = 4;

// --- journal helpers ------------------------------------------------------------------------

std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::vector<std::uint8_t> bytes;
  if (!input) return bytes;
  std::uint8_t chunk[4096];
  while (input) {
    input.read(reinterpret_cast<char*>(chunk), static_cast<std::streamsize>(sizeof(chunk)));
    const std::streamsize got = input.gcount();
    if (got <= 0) break;
    bytes.insert(bytes.end(), chunk, chunk + static_cast<std::size_t>(got));
  }
  return bytes;
}

void append_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::app);
  if (!output) return;
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  output.flush();
}

void overwrite_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) return;
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  output.flush();
}

/// Every record that decodes cleanly from the front of the byte range. Stops at the first
/// non-Complete disposition, which is exactly what a replay does.
std::vector<Record> decode_prefix(const std::vector<std::uint8_t>& bytes, const Limits& limits,
                                  DecodeDisposition* stop = nullptr) {
  std::vector<Record> records;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const DecodeResult decoded = decode_record(bytes.data() + offset, bytes.size() - offset, limits);
    if (decoded.disposition != DecodeDisposition::Complete) {
      if (stop != nullptr) *stop = decoded.disposition;
      return records;
    }
    records.push_back(decoded.record);
    offset += decoded.consumed;
  }
  if (stop != nullptr) *stop = DecodeDisposition::Complete;
  return records;
}

std::size_t journal_record_count(const std::filesystem::path& journal, const Limits& limits) {
  return decode_prefix(read_bytes(journal), limits).size();
}

std::size_t record_offset(const std::vector<Record>& records, std::size_t index) {
  std::size_t offset = 0;
  for (std::size_t current = 0; current < index; ++current) {
    offset += kRecordHeaderBytes + records.at(current).payload.size() + kRecordTrailerBytes;
  }
  return offset;
}

// --- coordinator helpers --------------------------------------------------------------------

CoordinatorConfig durable_config(const std::filesystem::path& root,
                                 std::size_t event_capacity = 256,
                                 std::size_t decision_capacity = 256) {
  CoordinatorConfig config;
  config.limits = Limits::defaults();
  config.evidence_class = EvidenceClass::Synthetic;
  config.enable_durability = true;
  config.durable_root = root;
  config.event_capacity = event_capacity;
  config.decision_capacity = decision_capacity;
  return config;
}

/// SYNTHETIC affirmative health for every switch generation in the fixture.
Status observe_all_healthy(Coordinator& coordinator, const Fabric& fabric, ManualClock& clock) {
  std::vector<SwitchKey> keys = fabric.leaf_keys;
  keys.insert(keys.end(), fabric.spine_keys.begin(), fabric.spine_keys.end());
  keys.insert(keys.end(), fabric.replacement_keys.begin(), fabric.replacement_keys.end());
  std::uint64_t next_id = 1;
  for (const SwitchKey& key : keys) {
    EvidenceRecord record;
    record.id = EvidenceId(next_id++);
    record.kind = EvidenceKind::SwitchHealth;
    record.source = EvidenceSource::FabricManager;
    record.subject = key;
    record.observed_at_ns = clock.now_ns();
    record.valid_for_ns = 60ull * kNanosPerSecond;
    record.health = SwitchHealthState::Healthy;
    record.detail = "SYNTHETIC fixture observation";
    const Status admitted = coordinator.admit_evidence(record);
    if (!admitted.ok()) return admitted;
  }
  return Status::success();
}

FailureDeclaration failure_of(const SwitchKey& key, const ManualClock& clock) {
  FailureDeclaration declaration;
  declaration.subject = key;
  declaration.source = EvidenceSource::FabricManager;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = 3600ull * kNanosPerSecond;
  declaration.reason = "SYNTHETIC fabric manager declaration";
  return declaration;
}

/// One incarnation that leaves a genuinely mixed record sequence behind: topology, admitted
/// evidence, a committed failure, a committed fence, a plan and its application.
struct Incarnation {
  SwitchKey failed;
  DependentRef dependent;
  PlanId plan;
  FenceId fence;
  CoordinatorEpoch epoch;
  std::uint64_t boot_ordinal = 0;
};

Result<Incarnation> drive_incarnation(Coordinator& coordinator, const Fabric& fabric,
                                      ManualClock& clock, bool shut_down) {
  Status installed = coordinator.install_topology(fabric.topology);
  if (!installed.ok()) return installed;
  installed = coordinator.install_candidates(fabric.candidates);
  if (!installed.ok()) return installed;
  const Status healthy = observe_all_healthy(coordinator, fabric, clock);
  if (!healthy.ok()) return healthy;

  Incarnation state;
  state.epoch = coordinator.epoch();
  state.boot_ordinal = coordinator.boot().boot_ordinal();
  state.failed = fabric.spine_keys.at(0);

  Result<FailoverOutcome> outcome = coordinator.declare_failure(failure_of(state.failed, clock));
  if (!outcome.ok()) return outcome.status();
  state.fence = outcome.value().fence;

  GenerationVector roots;
  roots.insert(state.failed);
  Result<ReconstructionPlan> produced = coordinator.propose_plan(roots);
  if (!produced.ok()) return produced.status();
  state.plan = produced.value().id;

  Result<ApplyReceipt> receipt = coordinator.apply_plan(produced.value());
  if (!receipt.ok()) return receipt.status();

  // The dependent whose authority the failed generation carried: a declared path through it.
  for (const PathDescriptor& path : fabric.topology.paths()) {
    if (std::find(path.hops.begin(), path.hops.end(), state.failed) != path.hops.end()) {
      state.dependent = DependentRef::path(path.id);
      break;
    }
  }
  if (!state.dependent.valid()) {
    return Status::failure(Code::NotFound, "fixture declares no path through the failed switch");
  }

  if (shut_down) {
    const Status shut = coordinator.shutdown();
    if (!shut.ok()) return shut;
  }
  return state;
}

bool any_grant_is_active(const AuthorityRegistry& authority) {
  for (const AuthorityGrant& grant : authority.all_grants()) {
    if (grant.state == GrantState::Active) return true;
  }
  return false;
}

bool has_record_kind(const std::vector<Record>& records, RecordKind kind) {
  for (const Record& record : records) {
    if (record.header.kind == kind) return true;
  }
  return false;
}

std::size_t count_record_kind(const std::vector<Record>& records, RecordKind kind) {
  std::size_t count = 0;
  for (const Record& record : records) {
    if (record.header.kind == kind) count += 1;
  }
  return count;
}

}  // namespace

// ---------------------------------------------------------------------------------------------

SFF_TEST(restart_report_restores_lineage_and_never_restores_authority) {
  TempDir dir("restart-report");
  const std::filesystem::path root = dir.file("durable");
  const std::filesystem::path journal = root / kJournalName;
  const Limits limits = Limits::defaults();

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  ManualClock clock{1000};

  // Seed pre-restart authority lineage directly, because the runtime itself never persists a
  // grant: a grant that existed before a process boundary is exactly what must not survive it.
  const DependentRef seeded_dependent = DependentRef::path(fabric.path_ids.at(1));
  GenerationVector seeded_bound;
  seeded_bound.insert(fabric.leaf_keys.at(0));
  seeded_bound.insert(fabric.spine_keys.at(1));
  {
    StoreOptions options;
    options.root = root;
    options.limits = limits;
    options.mode = OpenMode::OpenOrCreate;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(store.ok());
    if (!store.ok()) return;

    AuthorityGrant grant;
    grant.id = GrantId(1);
    grant.dependent = seeded_dependent;
    grant.bound = seeded_bound;
    grant.epoch = CoordinatorEpoch(1);
    grant.boot = BootIncarnation::from_parts(4242, 1, 0, 0);
    grant.attempt = AttemptSeq(1);
    grant.granted_at_ns = clock.now_ns();
    grant.expires_at_ns = clock.now_ns() + 3600ull * kNanosPerSecond;
    grant.state = GrantState::Active;
    grant.detail = "SYNTHETIC pre-restart authority lineage";

    CHECK(store.value()
              ->append(RecordKind::StreamHeader,
                       encode_stream_header(kRecordFormatVersion, 1, 4242, 1, 0, 0))
              .ok());
    CHECK(store.value()->append(RecordKind::GrantMinted, encode_grant_record(grant)).ok());
    CHECK(store.value()->close().ok());
  }
  CHECK(std::filesystem::exists(journal));

  // --- first incarnation: replay the seeded lineage, then produce a mixed record sequence.
  CoordinatorEpoch first_epoch;
  std::uint64_t first_boot = 0;
  {
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

    Result<RestartReport> report = coordinator->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().recovered);
      // The seeded journal ends with a grant record, not with a clean-shutdown marker, so the
      // previous writer is reported as not cleanly shut down. "Clean" is a positive claim that
      // must be earned by the marker, never inferred from the absence of corruption.
      CHECK(!report.value().clean_previous_shutdown);
      CHECK_EQ(report.value().records_replayed, std::size_t{2});
      CHECK_EQ(report.value().grants_invalidated, std::size_t{1});
      CHECK_EQ(report.value().previous_epoch.raw(), std::uint64_t{1});
      CHECK_EQ(report.value().previous_boot.boot_ordinal(), std::uint64_t{1});
      CHECK_LT(report.value().previous_epoch.raw(), report.value().current_epoch.raw());
      CHECK_LT(report.value().previous_boot.boot_ordinal(),
               report.value().current_boot.boot_ordinal());
      CHECK(!report.value().dynamic_evidence_restored);
    }

    // Persistence is not liveness: the seeded grant exists, and it confers no authority.
    CHECK_EQ(coordinator->authority()->total_grant_count(), std::size_t{1});
    CHECK(!any_grant_is_active(*coordinator->authority()));
    {
      Result<AuthorityQuery> query = coordinator->query_authority(seeded_dependent);
      CHECK(query.ok());
      if (query.ok()) {
        CHECK(!query.value().has_authority);
        CHECK_EQ(query.value().outcome, Code::Stale);
        CHECK_EQ(query.value().withdrawn_grants.size(), std::size_t{1});
      }
    }
    // A session that existed before the restart cannot be restored, because none ever is.
    CHECK_EQ(coordinator->session_count(), std::size_t{0});
    {
      Result<SessionRecord> session = coordinator->open_session("restart-report");
      CHECK(session.ok());
      if (session.ok()) CHECK_EQ(session.value().epoch.raw(), coordinator->epoch().raw());
      CHECK_EQ(coordinator->session_count(), std::size_t{1});
    }

    Result<Incarnation> driven = drive_incarnation(*coordinator, fabric, clock, true);
    CHECK(driven.ok());
    if (!driven.ok()) return;
    first_epoch = driven.value().epoch;
    first_boot = driven.value().boot_ordinal;

    // A shut-down runtime refuses further mutation rather than silently accepting it.
    CHECK(coordinator->stopped());
    const Status refused = coordinator->install_topology(fabric.topology);
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK_EQ(refused.code(), Code::Closed);
  }

  // The mixed sequence is really mixed.
  const std::vector<Record> records = decode_prefix(read_bytes(journal), limits);
  CHECK(has_record_kind(records, RecordKind::StreamHeader));
  CHECK(has_record_kind(records, RecordKind::TopologyInstalled));
  CHECK(has_record_kind(records, RecordKind::FailureCommitted));
  CHECK(has_record_kind(records, RecordKind::FenceCommitted));
  CHECK(has_record_kind(records, RecordKind::PlanCommitted));
  CHECK(has_record_kind(records, RecordKind::ApplyCompleted));
  CHECK(has_record_kind(records, RecordKind::ShutdownClean));

  // --- second incarnation: everything durable comes back, nothing dynamic does.
  CoordinatorEpoch second_epoch;
  std::uint64_t second_boot = 0;
  {
    const std::size_t records_before = records.size();
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

    Result<RestartReport> report = coordinator->restart_report();
    CHECK(report.ok());
    if (!report.ok()) return;
    // A clean previous shutdown is reported exactly when the previous run wrote its marker.
    CHECK(report.value().recovered);
    CHECK(report.value().clean_previous_shutdown);
    CHECK(!report.value().torn_tail_truncated);
    CHECK_EQ(report.value().records_replayed, records_before);
    CHECK_EQ(report.value().corrupt_records, std::size_t{0});
    CHECK_EQ(report.value().torn_records, std::size_t{0});
    CHECK_EQ(report.value().previous_epoch.raw(), first_epoch.raw());
    CHECK_EQ(report.value().previous_boot.boot_ordinal(), first_boot);
    CHECK_EQ(report.value().current_epoch.raw(), first_epoch.raw() + 1);
    CHECK_EQ(report.value().current_boot.boot_ordinal(), first_boot + 1);
    CHECK_LT(report.value().previous_epoch.raw(), report.value().current_epoch.raw());
    CHECK_LT(report.value().previous_boot.boot_ordinal(),
             report.value().current_boot.boot_ordinal());
    CHECK_EQ(report.value().failures_restored, std::size_t{1});
    CHECK_EQ(report.value().fences_restored, std::size_t{1});
    CHECK(!report.value().dynamic_evidence_restored);

    // Durable lineage is back.
    CHECK_EQ(coordinator->failures()->size(), std::size_t{1});
    CHECK(coordinator->failures()->contains(fabric.spine_keys.at(0)));
    CHECK_EQ(coordinator->authority()->fence_count(), std::size_t{1});
    CHECK(coordinator->authority()->is_fenced(fabric.spine_keys.at(0)));

    // Dynamic state is not: no evidence, no sessions, and no active authority of any kind.
    CHECK_EQ(coordinator->evidence()->size(), std::size_t{0});
    CHECK_EQ(coordinator->session_count(), std::size_t{0});
    CHECK(!any_grant_is_active(*coordinator->authority()));
    {
      Result<AuthorityQuery> query =
          coordinator->query_authority(DependentRef::path(fabric.path_ids.at(0)));
      CHECK(query.ok());
      if (query.ok()) CHECK(!query.value().has_authority);
    }

    // Dynamic evidence really is gone: the same affirmative health that was admitted before the
    // restart must be supplied again, and until it is, the generation is not usable.
    {
      Result<SwitchAssessment> assessment = coordinator->assess(fabric.spine_keys.at(1));
      CHECK(assessment.ok());
      if (assessment.ok()) {
        CHECK(!assessment.value().usable);
        CHECK_EQ(assessment.value().outcome, Code::Unknown);
      }
    }

    second_epoch = coordinator->epoch();
    second_boot = coordinator->boot().boot_ordinal();

    // This incarnation is destroyed without a clean shutdown marker, deliberately.
  }

  // --- third incarnation: an unclean previous run is reported as unclean.
  {
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

    Result<RestartReport> report = coordinator->restart_report();
    CHECK(report.ok());
    if (!report.ok()) return;
    CHECK(report.value().recovered);
    CHECK(!report.value().clean_previous_shutdown);
    CHECK_EQ(report.value().previous_epoch.raw(), second_epoch.raw());
    CHECK_EQ(report.value().previous_boot.boot_ordinal(), second_boot);
    CHECK_EQ(report.value().current_epoch.raw(), second_epoch.raw() + 1);
    CHECK_EQ(report.value().current_boot.boot_ordinal(), second_boot + 1);
    CHECK_EQ(report.value().failures_restored, std::size_t{1});
    CHECK_EQ(report.value().fences_restored, std::size_t{1});
    CHECK(coordinator->shutdown().ok());
  }
}

SFF_TEST(torn_tail_is_recovered_and_the_journal_stays_byte_exact) {
  TempDir dir("restart-torn");
  const std::filesystem::path root = dir.file("durable");
  const std::filesystem::path journal = root / kJournalName;
  const Limits limits = Limits::defaults();

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  ManualClock clock{1000};

  {
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Result<Incarnation> driven = drive_incarnation(*opened.value(), fabric, clock, true);
    CHECK(driven.ok());
    if (!driven.ok()) return;
  }

  const std::vector<std::uint8_t> intact = read_bytes(journal);
  CHECK(!intact.empty());
  const std::vector<Record> intact_records = decode_prefix(intact, limits);
  CHECK(!intact_records.empty());
  if (intact_records.empty()) return;
  const std::uint64_t intact_last_sequence = intact_records.back().header.seq;
  CHECK_EQ(intact_records.back().header.kind, RecordKind::ShutdownClean);

  // A genuine torn tail: the physical prefix of a record that was being appended when the process
  // ended. It is a real prefix of a real encoding, never arbitrary noise.
  FailureRecord pending;
  pending.subject = fabric.spine_keys.at(1);
  pending.evidence = EvidenceId(4242);
  pending.epoch = CoordinatorEpoch(3);
  pending.boot = BootIncarnation::from_parts(7, 3, 0, 0);
  pending.observed_at_ns = 5000;
  pending.recorded_at_ns = 5000;
  pending.reason = "SYNTHETIC record interrupted mid-append";
  Record candidate;
  candidate.header.kind = RecordKind::FailureCommitted;
  candidate.header.seq = intact_last_sequence + 1;
  candidate.payload = encode_failure_record(pending);
  Result<std::vector<std::uint8_t>> encoded = encode_record(candidate, limits);
  CHECK(encoded.ok());
  if (!encoded.ok()) return;
  CHECK(encoded.value().size() > 30);
  if (encoded.value().size() <= 30) return;
  const std::vector<std::uint8_t> torn_prefix(encoded.value().begin(),
                                              encoded.value().begin() + 30);

  // (1) The durable store recovers it at open and physically drops exactly the torn bytes.
  {
    append_bytes(journal, torn_prefix);
    CHECK_EQ(read_bytes(journal).size(), intact.size() + torn_prefix.size());

    StoreOptions options;
    options.root = root;
    options.limits = limits;
    options.mode = OpenMode::OpenOrCreate;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(store.ok());
    if (!store.ok()) return;
    const ReplayReport& report = store.value()->open_report();
    CHECK(report.status.ok());
    CHECK(report.truncated_tail);
    CHECK_EQ(report.torn_records, std::size_t{1});
    CHECK_EQ(report.corrupt_records, std::size_t{0});
    CHECK_EQ(report.unsupported_records, std::size_t{0});
    CHECK_EQ(report.recovered_bytes, torn_prefix.size());
    CHECK_EQ(report.records.size(), intact_records.size());
    CHECK_EQ(report.last_sequence, intact_last_sequence);
    CHECK(report.clean_shutdown);
    CHECK(store.value()->torn_bytes_recovered() == torn_prefix.size());
    CHECK(store.value()->close().ok());
  }

  // Byte-exact: the recovered journal is exactly the intact prefix, with no residue and no
  // re-encoding drift.
  const std::vector<std::uint8_t> recovered = read_bytes(journal);
  CHECK_EQ(recovered.size(), intact.size());
  CHECK(recovered == intact);

  // Replayable: the same records, in the same order, with the same sequence numbers.
  {
    StoreOptions options;
    options.root = root;
    options.limits = limits;
    options.mode = OpenMode::OpenExisting;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(store.ok());
    if (!store.ok()) return;
    Result<ReplayReport> replay = store.value()->replay();
    CHECK(replay.ok());
    if (replay.ok()) {
      CHECK_EQ(replay.value().records.size(), intact_records.size());
      CHECK_EQ(replay.value().last_sequence, intact_last_sequence);
      CHECK_EQ(replay.value().corrupt_records, std::size_t{0});
      CHECK_EQ(replay.value().torn_records, std::size_t{0});
      CHECK(replay.value().clean_shutdown);
      for (std::size_t index = 0; index < intact_records.size(); ++index) {
        CHECK_EQ(replay.value().records.at(index).header.kind,
                 intact_records.at(index).header.kind);
        CHECK_EQ(replay.value().records.at(index).header.seq,
                 intact_records.at(index).header.seq);
      }
    }
    CHECK(store.value()->close().ok());
  }

  // (2) The coordinator itself recovers the same torn tail and reports it.
  {
    append_bytes(journal, torn_prefix);
    CHECK_EQ(read_bytes(journal).size(), intact.size() + torn_prefix.size());

    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    std::unique_ptr<Coordinator> coordinator = std::move(opened).value();
    Result<RestartReport> report = coordinator->restart_report();
    CHECK(report.ok());
    if (report.ok()) {
      CHECK(report.value().recovered);
      CHECK(report.value().torn_tail_truncated);
      CHECK_EQ(report.value().torn_records, std::size_t{1});
      CHECK_EQ(report.value().corrupt_records, std::size_t{0});
      CHECK_EQ(report.value().records_replayed, intact_records.size());
      CHECK(report.value().clean_previous_shutdown);
      CHECK_EQ(report.value().failures_restored, std::size_t{1});
      CHECK_EQ(report.value().fences_restored, std::size_t{1});
    }
    CHECK(coordinator->failures()->contains(fabric.spine_keys.at(0)));
    CHECK(coordinator->authority()->is_fenced(fabric.spine_keys.at(0)));
    CHECK(coordinator->shutdown().ok());
  }

  // The torn tail never became a record: the lineage is exactly the one that was committed.
  const std::vector<Record> final_records = decode_prefix(read_bytes(journal), limits);
  CHECK_EQ(count_record_kind(final_records, RecordKind::FailureCommitted), std::size_t{1});
  CHECK_EQ(count_record_kind(final_records, RecordKind::FenceCommitted), std::size_t{1});
}

SFF_TEST(corruption_refuses_reopen_and_leaves_the_file_untouched) {
  TempDir dir("restart-corrupt");
  const std::filesystem::path root = dir.file("durable");
  const std::filesystem::path journal = root / kJournalName;
  const Limits limits = Limits::defaults();

  Result<Fabric> built = build_fabric(FabricSpec{});
  CHECK(built.ok());
  if (!built.ok()) return;
  const Fabric& fabric = built.value();
  ManualClock clock{1000};

  {
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Result<Incarnation> driven = drive_incarnation(*opened.value(), fabric, clock, true);
    CHECK(driven.ok());
    if (!driven.ok()) return;
  }

  std::vector<std::uint8_t> bytes = read_bytes(journal);
  const std::vector<Record> records = decode_prefix(bytes, limits);
  CHECK(records.size() >= 4);
  if (records.size() < 4) return;
  CHECK(records.at(1).payload.size() > 2);
  if (records.at(1).payload.size() <= 2) return;

  // Corrupt exactly one byte inside the payload of a complete record. Its header CRC still
  // matches, so only the payload integrity check can catch it - and it must.
  const std::size_t target = record_offset(records, 1) + kRecordHeaderBytes + 1;
  CHECK(target < bytes.size());
  if (target >= bytes.size()) return;
  bytes[target] = static_cast<std::uint8_t>(bytes[target] ^ 0x5Au);
  overwrite_bytes(journal, bytes);

  const std::vector<std::uint8_t> corrupted = read_bytes(journal);
  CHECK(corrupted == bytes);

  // The store refuses to open: a complete record that fails its integrity check is never skipped
  // and never repaired.
  {
    StoreOptions options;
    options.root = root;
    options.limits = limits;
    options.mode = OpenMode::OpenExisting;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    CHECK(!store.ok());
    if (!store.ok()) CHECK_EQ(store.status().code(), Code::Corrupt);
  }
  // So does the coordinator.
  {
    Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(durable_config(root), &clock);
    CHECK(!opened.ok());
    if (!opened.ok()) CHECK_EQ(opened.status().code(), Code::Corrupt);
  }

  // The file is left exactly as it was: refused, not rewritten, not truncated, not "repaired".
  const std::vector<std::uint8_t> after = read_bytes(journal);
  CHECK_EQ(after.size(), corrupted.size());
  CHECK(after == corrupted);
}

SFF_TEST(six_open_shutdown_cycles_advance_identity_and_accumulate_nothing) {
  TempDir dir("restart-cycles");
  const std::filesystem::path root = dir.file("durable");
  const std::filesystem::path journal = root / kJournalName;
  const Limits limits = Limits::defaults();
  constexpr std::size_t kCycles = 7;  // the requirement is at least six successive cycles
  constexpr std::size_t kEventCapacity = 16;
  constexpr std::size_t kDecisionCapacity = 8;

  // Seed one complete incarnation first, so that every measured cycle opens a journal that already
  // holds durable state: "recovered" then means the same thing under every reading of the flag.
  {
    ManualClock seed_clock{1000};
    Result<std::unique_ptr<Coordinator>> opened =
        Coordinator::open(durable_config(root, kEventCapacity, kDecisionCapacity), &seed_clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    Result<RestartReport> first = opened.value()->restart_report();
    CHECK(first.ok());
    if (first.ok()) {
      CHECK_EQ(first.value().records_replayed, std::size_t{0});  // a brand new journal
      CHECK_EQ(first.value().previous_epoch.raw(), std::uint64_t{0});
      CHECK_EQ(first.value().current_epoch.raw(), std::uint64_t{1});
      CHECK(!first.value().dynamic_evidence_restored);
    }
    CHECK(opened.value()->shutdown().ok());
  }
  const std::size_t seeded = journal_record_count(journal, limits);
  CHECK(seeded >= std::size_t{2});  // at least a stream header and a clean shutdown marker

  CoordinatorEpoch previous_epoch;
  std::uint64_t previous_boot = 0;
  bool have_previous = false;
  std::size_t reference_delta = 0;

  for (std::size_t cycle = 0; cycle < kCycles; ++cycle) {
    // Invariant before every operation, not only at the end: the journal is a clean sequence of
    // complete records before this incarnation starts writing.
    {
      DecodeDisposition stop = DecodeDisposition::Complete;
      const std::vector<Record> before = decode_prefix(read_bytes(journal), limits, &stop);
      CHECK(stop == DecodeDisposition::Complete || before.empty());
      CHECK_EQ(before.size(), journal_record_count(journal, limits));
    }
    const std::size_t records_at_open = journal_record_count(journal, limits);

    ManualClock clock{1000};
    Result<std::unique_ptr<Coordinator>> opened =
        Coordinator::open(durable_config(root, kEventCapacity, kDecisionCapacity), &clock);
    CHECK(opened.ok());
    if (!opened.ok()) return;
    std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

    Result<RestartReport> report = coordinator->restart_report();
    CHECK(report.ok());
    if (!report.ok()) return;
    CHECK(report.value().recovered);
    CHECK_EQ(report.value().corrupt_records, std::size_t{0});
    CHECK_EQ(report.value().torn_records, std::size_t{0});
    CHECK(!report.value().dynamic_evidence_restored);
    CHECK_EQ(report.value().records_replayed, records_at_open);
    CHECK_LT(report.value().previous_epoch.raw(), report.value().current_epoch.raw());
    CHECK_LT(report.value().previous_boot.boot_ordinal(),
             report.value().current_boot.boot_ordinal());

    // Epoch and boot ordinal increase strictly monotonically across incarnations.
    if (have_previous) {
      CHECK_LT(previous_epoch.raw(), coordinator->epoch().raw());
      CHECK_LT(previous_boot, coordinator->boot().boot_ordinal());
    }
    previous_epoch = coordinator->epoch();
    previous_boot = coordinator->boot().boot_ordinal();
    have_previous = true;

    // Nothing accumulates without bound inside the runtime either.
    Result<SessionRecord> session = coordinator->open_session("cycle");
    CHECK(session.ok());
    CHECK_EQ(coordinator->session_count(), std::size_t{1});
    CHECK(coordinator->plans().empty());
    CHECK_EQ(coordinator->failures()->size(), std::size_t{0});
    CHECK_EQ(coordinator->evidence()->size(), std::size_t{0});
    CHECK_EQ(coordinator->authority()->total_grant_count(), std::size_t{0});
    CHECK(coordinator->events(kEventCapacity * 4).size() <= kEventCapacity);
    CHECK(coordinator->decisions(kDecisionCapacity * 4).size() <= kDecisionCapacity);

    CHECK(coordinator->shutdown().ok());
    CHECK(coordinator->stopped());

    const std::size_t records_after = journal_record_count(journal, limits);
    CHECK(records_after > records_at_open);
    const std::size_t delta = records_after - records_at_open;
    // Every incarnation writes the same, constant number of records: identity, at most one epoch
    // advance and the clean shutdown marker. Nothing is re-persisted wholesale per restart, so the
    // journal cannot grow faster than the cycle count.
    CHECK(delta >= std::size_t{2});
    if (cycle == 0) {
      reference_delta = delta;
    } else {
      CHECK_EQ(delta, reference_delta);
    }
  }

  // The journal is a linear function of the cycle count, so nothing grows super-linearly.
  CHECK_EQ(journal_record_count(journal, limits), seeded + kCycles * reference_delta);
}

SFF_MAIN()
