// Switch Failover Fabric - adversarial persistence suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC: every journal, snapshot, record and corruption in this suite is generated
// in-process inside a self-cleaning temporary directory. No physical device, fabric or
// crash-consistent storage is exercised.
//
// The durable format is treated here as hostile input, not as a trusted artefact:
//   * every RecordKind payload codec is round-tripped and re-encoded byte-for-byte;
//   * every prefix of a real record is decoded (torn-tail completeness);
//   * every single-byte corruption of a real record is applied (integrity completeness);
//   * declared lengths, format versions and record kinds are attacked directly;
//   * real journals are torn, tampered with, replayed and reopened through DurableStore.
//
// Permanent rule: no timeout, no watchdog thread, no sleep. A hang is a defect to diagnose.
//
// Three defects this suite exposed are fixed, and the cases that found them are kept as permanent
// regression guards:
//   * replay() scanned through a fixed 64 KiB window, so a record that straddled the window edge
//     looked torn while being complete in the file, and open() then truncated the journal by the
//     bytes left in the WINDOW rather than the bytes at the end of the file. It is now a streaming
//     reader (validated header, then exactly payload_len + 4 body bytes). See
//     journal_larger_than_any_internal_window_replays_without_loss.
//   * compact() wrote the supplied records verbatim while replay() insisted a journal start at
//     sequence 1, so compacting to a suffix produced a journal this build refused to reopen.
//     Continuity is now anchored on the first record actually present. See
//     compaction_that_keeps_a_suffix_replays_correctly.
//   * ReconstructionPlan::decode permuted the four boot-incarnation words through an unspecified
//     argument evaluation order. See plan_boot_incarnation_field_order_is_reported.
#define _CRT_SECURE_NO_WARNINGS 1

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

#include "sff/codec/integrity.hpp"
#include "sff/core/limits.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/generation.hpp"
#include "sff/persist/records.hpp"
#include "sff/persist/store.hpp"
#include "sff/plan/plan.hpp"
#include "test_support.hpp"

using namespace sff;
using namespace sfftest;

namespace {

// ---------------------------------------------------------------------------------------------
// Byte-level helpers
// ---------------------------------------------------------------------------------------------

constexpr const char* kJournalName = "sff.journal";
constexpr const char* kSnapshotName = "sff.snapshot";
constexpr const char* kSnapshotStagingName = "sff.snapshot.staging";

void push_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

void push_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu));
  }
}

void push_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu));
  }
}

std::uint32_t peek_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) return 0;
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(bytes[offset + index]) << (8 * index);
  }
  return value;
}

void patch_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xffu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
}

void patch_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu);
  }
}

/// Recompute the stored header CRC exactly as the format prescribes: crc32 over the first 24 bytes.
void refresh_header_crc(std::vector<std::uint8_t>& bytes) {
  patch_u32(bytes, 24, crc32_ieee(bytes.data(), 24));
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
  std::vector<std::uint8_t> out;
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) return out;
  if (std::fseek(file, 0, SEEK_END) == 0) {
    const long length = std::ftell(file);
    if (length > 0) {
      std::fseek(file, 0, SEEK_SET);
      out.assign(static_cast<std::size_t>(length), 0);
      const std::size_t got = std::fread(out.data(), 1, out.size(), file);
      out.resize(got);
    }
  }
  std::fclose(file);
  return out;
}

bool write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::FILE* file = std::fopen(path.string().c_str(), "wb");
  if (file == nullptr) return false;
  const std::size_t wrote =
      bytes.empty() ? 0 : std::fwrite(bytes.data(), 1, bytes.size(), file);
  const bool closed = std::fclose(file) == 0;
  return closed && wrote == bytes.size();
}

bool append_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::FILE* file = std::fopen(path.string().c_str(), "ab");
  if (file == nullptr) return false;
  const std::size_t wrote =
      bytes.empty() ? 0 : std::fwrite(bytes.data(), 1, bytes.size(), file);
  const bool closed = std::fclose(file) == 0;
  return closed && wrote == bytes.size();
}

/// Resize a real file to an exact length: the only honest way to model a crash mid-append.
/// Deliberately not named resize_file: argument-dependent lookup would find the std overload.
bool truncate_file_to(const std::filesystem::path& path, std::size_t length) {
  std::error_code code;
  std::filesystem::resize_file(path, length, code);
  return !code;
}

std::uintmax_t file_size_of(const std::filesystem::path& path) {
  std::error_code code;
  const std::uintmax_t size = std::filesystem::file_size(path, code);
  return code ? static_cast<std::uintmax_t>(~static_cast<std::uintmax_t>(0)) : size;
}

std::vector<std::uint8_t> concat(const std::vector<std::vector<std::uint8_t>>& parts) {
  std::vector<std::uint8_t> out;
  for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
  return out;
}

std::string hex_preview(const std::vector<std::uint8_t>& bytes) {
  static const char* kDigits = "0123456789abcdef";
  std::string text;
  const std::size_t shown = bytes.size() < 32 ? bytes.size() : 32;
  for (std::size_t index = 0; index < shown; ++index) {
    text.push_back(kDigits[(bytes[index] >> 4) & 0x0fu]);
    text.push_back(kDigits[bytes[index] & 0x0fu]);
  }
  if (bytes.size() > shown) text += "...";
  text += " (" + std::to_string(bytes.size()) + " bytes)";
  return text;
}

/// First offset at which two byte strings differ, or npos when they are equal.
std::size_t first_difference(const std::vector<std::uint8_t>& left,
                             const std::vector<std::uint8_t>& right) {
  const std::size_t common = left.size() < right.size() ? left.size() : right.size();
  for (std::size_t index = 0; index < common; ++index) {
    if (left[index] != right[index]) return index;
  }
  return left.size() == right.size() ? std::string::npos : common;
}

void check_bytes_equal(const char* file, int line, const std::vector<std::uint8_t>& left,
                       const std::vector<std::uint8_t>& right, const char* text) {
  ::sfftest::record_check();
  if (left == right) return;
  const std::size_t offset = first_difference(left, right);
  ::sfftest::fail(file, line,
                  std::string(text) + " (first difference at byte " + std::to_string(offset) +
                      "; left=" + hex_preview(left) + " right=" + hex_preview(right) + ")");
}

#define CHECK_BYTES_EQ(left, right) \
  ::check_bytes_equal(__FILE__, __LINE__, (left), (right), #left " == " #right)

/// Report the declared payload length alongside the disposition it produced, so a failing
/// declared-length attack names the exact length that was refused the wrong way.
void check_declared_length_disposition(const char* file, int line, std::uint32_t declared_length,
                                       std::size_t supplied, DecodeDisposition observed,
                                       DecodeDisposition expected, const char* rule) {
  ::sfftest::record_check();
  if (observed == expected) return;
  ::sfftest::fail(file, line, "declared payload_len=" + std::to_string(declared_length) +
                                  " with " + std::to_string(supplied) +
                                  " bytes supplied: disposition " +
                                  std::string(to_string(observed)) + " but " + rule + " requires " +
                                  std::string(to_string(expected)));
}

#define CHECK_DECLARED_LENGTH(declared, supplied, observed, expected, rule) \
  ::check_declared_length_disposition(__FILE__, __LINE__, (declared), (supplied), (observed), \
                                      (expected), (rule))

// ---------------------------------------------------------------------------------------------
// Durable fixtures. Every value is synthetic and deterministic.
// ---------------------------------------------------------------------------------------------

BootIncarnation sample_boot() {
  return BootIncarnation::from_parts(4242, 7, 0x1122334455667788ull, 0x99aabbccddeeff00ull);
}

SwitchKey sample_key(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

DependentRef sample_dependent() { return DependentRef::path(PathId(31)); }

FailureRecord sample_failure() {
  FailureRecord record;
  record.subject = sample_key(11, 3);
  record.evidence = EvidenceId(9001);
  record.epoch = CoordinatorEpoch(5);
  record.boot = sample_boot();
  record.observed_at_ns = 1000;
  record.recorded_at_ns = 1001;
  record.reason = "SYNTHETIC declared failure";
  return record;
}

FenceRecord sample_fence() {
  FenceRecord record;
  record.id = FenceId(4);
  record.subject = sample_key(11, 3);
  record.epoch = CoordinatorEpoch(5);
  record.boot = sample_boot();
  record.created_at_ns = 1002;
  record.scope_state = FenceScopeState::Partial;
  record.closure_digest = 0xfeedfaceull;
  record.closure_members = 12;
  record.fenced_grants = 3;
  record.omitted_dependents = 1;
  record.reason = "SYNTHETIC fence with a truncated closure";
  return record;
}

AuthorityGrant sample_grant() {
  AuthorityGrant grant;
  grant.id = GrantId(8);
  grant.dependent = sample_dependent();
  grant.bound = GenerationVector::canonicalise({sample_key(11, 3), sample_key(2, 1)});
  grant.epoch = CoordinatorEpoch(5);
  grant.boot = sample_boot();
  grant.attempt = AttemptSeq(2);
  grant.granted_at_ns = 1000;
  grant.expires_at_ns = 2000;
  grant.state = GrantState::Stale;
  grant.cause = RevocationCause::Restart;
  grant.detail = "SYNTHETIC grant detail";
  return grant;
}

WithdrawRecord sample_withdraw() {
  WithdrawRecord record;
  record.grant = GrantId(8);
  record.cause = static_cast<std::uint8_t>(RevocationCause::Fence);
  record.detail = "SYNTHETIC withdrawal";
  return record;
}

ReconstructionPlan sample_plan() {
  ReconstructionPlan plan;
  plan.id = PlanId(77);
  plan.epoch = CoordinatorEpoch(9);
  plan.boot = sample_boot();
  plan.failed_generations = GenerationVector::canonicalise({sample_key(11, 3), sample_key(2, 1)});

  FenceStep fence;
  fence.failed = sample_key(11, 3);
  fence.closure_digest = 0x1234abcdull;
  fence.closure_state = ClosureState::Truncated;
  fence.closure_members = 5;
  fence.omitted_dependents = 2;
  plan.fences.push_back(fence);

  RestoreStep restore;
  restore.dependent = sample_dependent();
  restore.covers_failed = sample_key(11, 3);
  restore.action = PlanAction::RebindReplacement;
  restore.replacement = sample_key(21, 4);
  restore.hops = {sample_key(21, 4), sample_key(22, 1)};
  restore.links = {LinkId(41), LinkId(42)};
  restore.cost = 9;
  restore.evidence = EvidenceId(555);
  plan.restores.push_back(restore);

  UnresolvedDependent unresolved;
  unresolved.dependent = DependentRef::link(LinkId(63));
  unresolved.covers_failed = sample_key(2, 1);
  unresolved.reason = UnresolvedReason::ClosureTruncated;
  unresolved.detail = "SYNTHETIC truncated closure";
  plan.unresolved.push_back(unresolved);

  plan.feasibility = PlanFeasibility::ProvenFeasible;
  plan.state = PlanState::Committed;
  plan.closure_complete = false;
  plan.service_withheld = true;
  plan.topology_digest = 0xaaaa1111ull;
  plan.policy_digest = 0xbbbb2222ull;
  plan.seal();
  return plan;
}

/// The sample plan with a caller-chosen boot incarnation, re-sealed.
ReconstructionPlan plan_with_boot(const BootIncarnation& boot) {
  ReconstructionPlan plan = sample_plan();
  plan.boot = boot;
  plan.seal();
  return plan;
}

ApplyReceipt sample_receipt() {
  ApplyReceipt receipt;
  receipt.plan = PlanId(77);
  receipt.epoch = CoordinatorEpoch(9);
  receipt.boot = sample_boot();

  ApplyStepResult first;
  first.dependent = sample_dependent();
  first.replacement = sample_key(21, 4);
  first.state = AckState::Verified;
  first.attempt = AttemptSeq(3);
  first.verification = EvidenceId(777);
  first.detail = "SYNTHETIC verified effect";
  receipt.steps.push_back(first);

  ApplyStepResult second;
  second.dependent = DependentRef::port(17);
  second.replacement = sample_key(22, 1);
  second.state = AckState::Unverified;
  second.attempt = AttemptSeq(4);
  second.detail = "SYNTHETIC unverified effect";
  receipt.steps.push_back(second);

  receipt.applied = 2;
  receipt.verified = 1;
  receipt.failed = 0;
  receipt.unverified = 1;
  receipt.complete = true;
  receipt.outcome = Code::Unverified;
  return receipt;
}

RestoreDecision sample_decision() {
  RestoreDecision decision;
  decision.dependent = sample_dependent();
  decision.outcome = Code::Ok;
  decision.reason = Code::Ok;
  decision.may_restore = true;
  decision.effect_verified = true;
  decision.bound = GenerationVector::canonicalise({sample_key(2, 1), sample_key(11, 3)});
  decision.plan = PlanId(77);
  decision.grants = {GrantId(8), GrantId(9)};
  decision.blocking_generations = {sample_key(11, 3)};
  // Deliberately below the term budget: a truncated explanation is a different value and is
  // covered by its own check.
  decision.explanation = Explanation(16);
  decision.explanation.add("stage", "SYNTHETIC").add_u64("hops", 2);
  return decision;
}

/// A mixed sequence covering every record kind that carries a distinct payload codec.
std::vector<std::pair<RecordKind, std::vector<std::uint8_t>>> mixed_sequence() {
  std::vector<std::pair<RecordKind, std::vector<std::uint8_t>>> out;
  out.emplace_back(RecordKind::StreamHeader,
                   encode_stream_header(kRecordFormatVersion, 7, 4242, 1, 0x1111222233334444ull,
                                        0x5555666677778888ull));
  out.emplace_back(RecordKind::BootRegistered, encode_u64_payload(4242));
  out.emplace_back(RecordKind::TopologyInstalled, encode_u64_payload(0xabcdeful));
  out.emplace_back(RecordKind::PolicyInstalled, encode_u64_payload(7));
  out.emplace_back(RecordKind::FailureCommitted, encode_failure_record(sample_failure()));
  out.emplace_back(RecordKind::FenceCommitted, encode_fence_record(sample_fence()));
  out.emplace_back(RecordKind::GrantMinted, encode_grant_record(sample_grant()));
  out.emplace_back(RecordKind::GrantWithdrawn, encode_withdraw_record(sample_withdraw()));
  out.emplace_back(RecordKind::PlanCommitted, encode_plan_record(sample_plan()));
  out.emplace_back(RecordKind::ApplyCompleted, encode_apply_receipt(sample_receipt()));
  out.emplace_back(RecordKind::RestoreDecided, encode_restore_decision(sample_decision()));
  out.emplace_back(RecordKind::EpochAdvance, encode_u64_payload(2));
  out.emplace_back(RecordKind::Checkpoint, std::vector<std::uint8_t>{});
  out.emplace_back(RecordKind::ShutdownClean, encode_u64_payload(1));
  return out;
}

/// Canonical bytes of a record exactly as the store would publish it.
std::vector<std::uint8_t> encoded_record(std::uint64_t seq, RecordKind kind,
                                         const std::vector<std::uint8_t>& payload,
                                         std::uint32_t flags, const Limits& limits) {
  Record record;
  record.header.magic = kRecordMagic;
  record.header.format_version = kRecordFormatVersion;
  record.header.kind = kind;
  record.header.flags = flags;
  record.header.seq = seq;
  record.payload = payload;
  Result<std::vector<std::uint8_t>> encoded = encode_record(record, limits);
  if (!encoded.ok()) {
    CHECK(encoded.ok());
    return {};
  }
  return encoded.value();
}

/// Delete every file this suite could create inside a root, so the tree is left as found.
void remove_store_files(const std::filesystem::path& root) {
  std::error_code code;
  for (const char* name : {kJournalName, kSnapshotName, kSnapshotStagingName, "sff.journal.staging"}) {
    std::filesystem::remove(root / name, code);
    code.clear();
  }
}

struct StoreHandle {
  std::unique_ptr<DurableStore> store;
  Status open_status;
  bool ok = false;
};

StoreHandle open_store(const std::filesystem::path& root, OpenMode mode, const Limits& limits) {
  StoreOptions options;
  options.root = root;
  options.mode = mode;
  options.limits = limits;
  StoreHandle handle;
  Result<std::unique_ptr<DurableStore>> opened = DurableStore::open(options);
  handle.ok = opened.ok();
  handle.open_status = opened.status();
  if (handle.ok) handle.store = std::move(opened).value();
  return handle;
}

// ---------------------------------------------------------------------------------------------
// 1. Payload codecs
// ---------------------------------------------------------------------------------------------

SFF_TEST(round_trip_every_payload_codec_is_byte_identical) {
  const Limits limits = Limits::defaults();

  // Stream header. This is the one payload with no decoder in the public surface, so its
  // canonical layout is asserted byte-for-byte instead of round-tripped.
  {
    const std::vector<std::uint8_t> payload =
        encode_stream_header(1, 7, 4242, 9, 0x1122334455667788ull, 0x99aabbccddeeff00ull);
    std::vector<std::uint8_t> expected;
    expected.push_back(1);  // payload format tag
    push_u16(expected, 1);
    push_u64(expected, 7);
    push_u64(expected, 4242);
    push_u64(expected, 9);
    push_u64(expected, 0x1122334455667788ull);
    push_u64(expected, 0x99aabbccddeeff00ull);
    CHECK_BYTES_EQ(payload, expected);

    // And it survives journal framing unchanged.
    const std::vector<std::uint8_t> framed =
        encoded_record(1, RecordKind::StreamHeader, payload, 0, limits);
    DecodeResult decoded = decode_record(framed.data(), framed.size(), limits);
    CHECK_EQ(decoded.disposition, DecodeDisposition::Complete);
    CHECK_BYTES_EQ(decoded.record.payload, payload);
    CHECK_BYTES_EQ(encoded_record(decoded.record.header.seq, decoded.record.header.kind,
                                  decoded.record.payload, decoded.record.header.flags, limits),
                   framed);
  }

  // u64 payloads, including the extremes.
  for (const std::uint64_t value : {0ull, 1ull, 0x8000000000000000ull, 0xffffffffffffffffull}) {
    const std::vector<std::uint8_t> payload = encode_u64_payload(value);
    Result<std::uint64_t> decoded = decode_u64_payload(payload);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value(), value);
    CHECK_BYTES_EQ(encode_u64_payload(decoded.value()), payload);
  }

  // Failure record.
  {
    const std::vector<std::uint8_t> payload = encode_failure_record(sample_failure());
    Result<FailureRecord> decoded = decode_failure_record(payload);
    CHECK(decoded.ok());
    CHECK(decoded.value().subject == sample_failure().subject);
    CHECK_EQ(decoded.value().reason, sample_failure().reason);
    CHECK_BYTES_EQ(encode_failure_record(decoded.value()), payload);
  }

  // Fence record.
  {
    const std::vector<std::uint8_t> payload = encode_fence_record(sample_fence());
    Result<FenceRecord> decoded = decode_fence_record(payload);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value().scope_state, FenceScopeState::Partial);
    CHECK_EQ(decoded.value().closure_members, sample_fence().closure_members);
    CHECK_BYTES_EQ(encode_fence_record(decoded.value()), payload);
  }

  // Grant record.
  {
    const std::vector<std::uint8_t> payload = encode_grant_record(sample_grant());
    Result<AuthorityGrant> decoded = decode_grant_record(payload);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value().state, GrantState::Stale);
    CHECK_EQ(decoded.value().cause, RevocationCause::Restart);
    CHECK(decoded.value().bound == sample_grant().bound);
    CHECK_BYTES_EQ(encode_grant_record(decoded.value()), payload);
  }

  // Withdraw record.
  {
    const std::vector<std::uint8_t> payload = encode_withdraw_record(sample_withdraw());
    Result<WithdrawRecord> decoded = decode_withdraw_record(payload);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value().cause, sample_withdraw().cause);
    CHECK_BYTES_EQ(encode_withdraw_record(decoded.value()), payload);
  }

  // Reconstruction plan. The first fixture uses a deliberately symmetric boot incarnation (all
  // four components equal) and the second the ordinary asymmetric one, so the round trip is
  // pinned both when the four words are interchangeable and when they are not.
  {
    const ReconstructionPlan plan = plan_with_boot(BootIncarnation::from_parts(0x51515151ull,
                                                                              0x51515151ull,
                                                                              0x51515151ull,
                                                                              0x51515151ull));
    CHECK(plan.digest_valid());
    const std::vector<std::uint8_t> payload = encode_plan_record(plan);
    Result<ReconstructionPlan> decoded = decode_plan_record(payload, limits);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value().plan_digest, plan.plan_digest);
    CHECK(decoded.value().boot == plan.boot);
    CHECK_EQ(decoded.value().restores.size(), plan.restores.size());
    CHECK_EQ(decoded.value().unresolved.size(), plan.unresolved.size());
    CHECK(decoded.value().digest_valid());
    CHECK_BYTES_EQ(encode_plan_record(decoded.value()), payload);
    // The same strict round trip through the durable record framing.
    const std::vector<std::uint8_t> framed =
        encoded_record(1, RecordKind::PlanCommitted, payload, 0, limits);
    DecodeResult framed_decoded = decode_record(framed.data(), framed.size(), limits);
    CHECK_EQ(framed_decoded.disposition, DecodeDisposition::Complete);
    CHECK_BYTES_EQ(encode_plan_record(decode_plan_record(framed_decoded.record.payload, limits)
                                          .value()),
                   payload);
  }

  // The same strict round trip with an asymmetric boot incarnation. This is the regression guard
  // for the argument-evaluation-order defect that once permuted the four boot words on decode.
  {
    const ReconstructionPlan plan = sample_plan();
    CHECK(plan.boot.process_id() != plan.boot.nonce_hi());
    CHECK(plan.boot.boot_ordinal() != plan.boot.nonce_lo());
    const std::vector<std::uint8_t> payload = encode_plan_record(plan);
    Result<ReconstructionPlan> decoded = decode_plan_record(payload, limits);
    CHECK(decoded.ok());
    CHECK(decoded.value().boot == plan.boot);
    CHECK_EQ(decoded.value().plan_digest, plan.plan_digest);
    CHECK(decoded.value().digest_valid());
    CHECK_BYTES_EQ(encode_plan_record(decoded.value()), payload);
  }

  // Apply receipt.
  {
    const std::vector<std::uint8_t> payload = encode_apply_receipt(sample_receipt());
    Result<ApplyReceipt> decoded = decode_apply_receipt(payload);
    CHECK(decoded.ok());
    CHECK_EQ(decoded.value().steps.size(), std::size_t{2});
    CHECK_EQ(decoded.value().verified, std::size_t{1});
    CHECK_EQ(decoded.value().outcome, Code::Unverified);
    CHECK_BYTES_EQ(encode_apply_receipt(decoded.value()), payload);
  }

  // Restore decision.
  {
    const std::vector<std::uint8_t> payload = encode_restore_decision(sample_decision());
    Result<RestoreDecision> decoded = decode_restore_decision(payload);
    CHECK(decoded.ok());
    CHECK(decoded.value().may_restore);
    CHECK(decoded.value().bound == sample_decision().bound);
    CHECK_BYTES_EQ(encode_restore_decision(decoded.value()), payload);
  }

  // Framing round trip for every defined record kind.
  const auto sequence = mixed_sequence();
  std::uint64_t seq = 1;
  for (const auto& entry : sequence) {
    const std::vector<std::uint8_t> framed =
        encoded_record(seq, entry.first, entry.second, 0x5a5a5a5au, limits);
    DecodeResult decoded = decode_record(framed.data(), framed.size(), limits);
    CHECK_EQ(decoded.disposition, DecodeDisposition::Complete);
    CHECK_EQ(decoded.consumed, framed.size());
    CHECK_EQ(decoded.record.header.kind, entry.first);
    CHECK_EQ(decoded.record.header.seq, seq);
    CHECK_EQ(decoded.record.header.flags, 0x5a5a5a5au);
    CHECK_BYTES_EQ(decoded.record.payload, entry.second);
    CHECK_BYTES_EQ(encoded_record(seq, entry.first, decoded.record.payload, 0x5a5a5a5au, limits),
                   framed);
    seq += 1;
  }
}

// ---------------------------------------------------------------------------------------------
// 2. Plan boot incarnation field order (regression guard)
// ---------------------------------------------------------------------------------------------

// ReconstructionPlan::decode used to read the four BootIncarnation components by passing four
// side-effecting reader.u64() calls straight into BootIncarnation::from_parts. C++ leaves the
// evaluation order of function arguments unspecified and MSVC evaluates them right-to-left, so
// the decoded incarnation came back as (nonce_lo, nonce_hi, boot_ordinal, process_id): a plan
// persisted by one build did not decode to the same value, or the same digest, in another. The
// defect is fixed by reading named locals in sequence; this case is the permanent guard. It
// asserts the components land in their documented positions, that nothing is invented or dropped,
// and that every other field of the plan survives byte-for-byte, and it still reports the
// deviation loudly if it ever returns.
SFF_TEST(plan_boot_incarnation_field_order_is_reported) {
  const Limits limits = Limits::defaults();
  const BootIncarnation asymmetric = BootIncarnation::from_parts(
      0x1111111111111111ull, 0x2222222222222222ull, 0x3333333333333333ull, 0x4444444444444444ull);
  const ReconstructionPlan plan = plan_with_boot(asymmetric);
  const std::vector<std::uint8_t> payload = encode_plan_record(plan);

  Result<ReconstructionPlan> decoded = decode_plan_record(payload, limits);
  CHECK(decoded.ok());
  if (!decoded.ok()) return;
  const BootIncarnation decoded_boot = decoded.value().boot;

  std::vector<std::uint64_t> supplied = {asymmetric.process_id(), asymmetric.boot_ordinal(),
                                         asymmetric.nonce_hi(), asymmetric.nonce_lo()};
  std::vector<std::uint64_t> produced = {decoded_boot.process_id(), decoded_boot.boot_ordinal(),
                                         decoded_boot.nonce_hi(), decoded_boot.nonce_lo()};
  std::sort(supplied.begin(), supplied.end());
  std::sort(produced.begin(), produced.end());
  CHECK(supplied == produced);
  // The components must also stay in their documented positions: this is the regression guard for
  // the right-to-left argument-evaluation defect this probe was written for.
  CHECK(decoded_boot == asymmetric);

  // Every other meaning-bearing field survives the byte round trip untouched.
  ReconstructionPlan normalised = decoded.value();
  normalised.boot = asymmetric;
  normalised.seal();
  CHECK_BYTES_EQ(encode_plan_record(normalised), payload);

  if (decoded_boot != asymmetric) {
    std::printf(
        "  [!] DEFECT: ReconstructionPlan::decode reversed the boot incarnation fields "
        "(in=%llx/%llx/%llx/%llx out=%llx/%llx/%llx/%llx, plan_digest_preserved=%d)\n",
        static_cast<unsigned long long>(asymmetric.process_id()),
        static_cast<unsigned long long>(asymmetric.boot_ordinal()),
        static_cast<unsigned long long>(asymmetric.nonce_hi()),
        static_cast<unsigned long long>(asymmetric.nonce_lo()),
        static_cast<unsigned long long>(decoded_boot.process_id()),
        static_cast<unsigned long long>(decoded_boot.boot_ordinal()),
        static_cast<unsigned long long>(decoded_boot.nonce_hi()),
        static_cast<unsigned long long>(decoded_boot.nonce_lo()),
        decoded.value().plan_digest == plan.plan_digest ? 1 : 0);
    std::fflush(stdout);
  }
}

// ---------------------------------------------------------------------------------------------
// 3. Truncation sweep
// ---------------------------------------------------------------------------------------------

SFF_TEST(every_prefix_of_a_real_record_is_a_torn_tail) {
  const Limits limits = Limits::defaults();

  struct Shape {
    const char* name;
    std::vector<std::uint8_t> payload;
  };
  std::vector<Shape> shapes;
  shapes.push_back(Shape{"empty", std::vector<std::uint8_t>{}});
  shapes.push_back(Shape{"small", encode_failure_record(sample_failure())});
  shapes.push_back(Shape{"page", std::vector<std::uint8_t>(4096, 0x5au)});

  for (const auto& shape : shapes) {
    const std::vector<std::uint8_t> framed =
        encoded_record(1, RecordKind::FailureCommitted, shape.payload, 0, limits);
    CHECK_EQ(framed.size(), kRecordHeaderBytes + shape.payload.size() + 4);

    for (std::size_t prefix = 0; prefix < framed.size(); ++prefix) {
      DecodeResult result = decode_record(framed.data(), prefix, limits);
      CHECK_EQ(result.disposition, DecodeDisposition::TornTail);
      CHECK_EQ(result.consumed, prefix);
      CHECK(result.status.ok());
      CHECK(result.record.payload.empty());
    }

    DecodeResult whole = decode_record(framed.data(), framed.size(), limits);
    CHECK_EQ(whole.disposition, DecodeDisposition::Complete);
    CHECK_EQ(whole.consumed, framed.size());
    CHECK_BYTES_EQ(whole.record.payload, shape.payload);
  }

  // An empty range is a zero-length torn tail, and a null range with a zero length is not a crash.
  DecodeResult empty = decode_record(nullptr, 0, limits);
  CHECK_EQ(empty.disposition, DecodeDisposition::TornTail);
  CHECK_EQ(empty.consumed, std::size_t{0});
  DecodeResult null_range = decode_record(nullptr, 16, limits);
  CHECK_EQ(null_range.disposition, DecodeDisposition::Corrupt);
}

// ---------------------------------------------------------------------------------------------
// 4. Corruption sweep
// ---------------------------------------------------------------------------------------------

SFF_TEST(one_byte_corruption_is_never_complete_or_torn) {
  const Limits limits = Limits::defaults();
  Rng rng(0x5eed1234ull);

  struct Shape {
    const char* name;
    std::uint64_t seq;
    std::vector<std::uint8_t> payload;
  };
  std::vector<Shape> shapes;
  shapes.push_back(Shape{"empty", 1, std::vector<std::uint8_t>{}});
  shapes.push_back(Shape{"small", 9, encode_fence_record(sample_fence())});
  shapes.push_back(Shape{"wide", 0x1234, std::vector<std::uint8_t>(256, 0x33)});

  for (const auto& shape : shapes) {
    const std::vector<std::uint8_t> clean =
        encoded_record(shape.seq, RecordKind::FenceCommitted, shape.payload, 0x0f0f0f0fu, limits);
    DecodeResult sanity = decode_record(clean.data(), clean.size(), limits);
    CHECK_EQ(sanity.disposition, DecodeDisposition::Complete);

    for (std::size_t offset = 0; offset < clean.size(); ++offset) {
      const std::uint8_t delta = static_cast<std::uint8_t>(rng.bounded(255) + 1);
      std::vector<std::uint8_t> damaged = clean;
      damaged[offset] = static_cast<std::uint8_t>(damaged[offset] ^ delta);

      DecodeResult result = decode_record(damaged.data(), damaged.size(), limits);
      const bool refused = result.disposition == DecodeDisposition::Corrupt ||
                           result.disposition == DecodeDisposition::Unsupported;
      CHECK(refused);
      CHECK_NE(result.disposition, DecodeDisposition::TornTail);
      CHECK_NE(result.disposition, DecodeDisposition::Complete);
      CHECK_EQ(result.consumed, std::size_t{0});
      CHECK(result.record.payload.empty());
      if (result.disposition == DecodeDisposition::Unsupported) {
        // Only a version or kind this build does not define may be reported as unsupported.
        const bool explained = result.status.code() == Code::VersionMismatch ||
                               result.status.code() == Code::Unsupported;
        CHECK(explained);
      } else {
        CHECK_EQ(result.status.code(), Code::Corrupt);
      }
    }
  }

  // A flipped magic byte in the very first position is refused before anything else is parsed.
  const std::vector<std::uint8_t> clean = encoded_record(1, RecordKind::Checkpoint, {}, 0, limits);
  std::vector<std::uint8_t> bad_magic = clean;
  bad_magic[0] = static_cast<std::uint8_t>(bad_magic[0] ^ 0xffu);
  DecodeResult result = decode_record(bad_magic.data(), bad_magic.size(), limits);
  CHECK_EQ(result.disposition, DecodeDisposition::Corrupt);
}

// ---------------------------------------------------------------------------------------------
// 5. Declared-length attacks
// ---------------------------------------------------------------------------------------------

SFF_TEST(declared_length_attacks_are_refused_without_allocation) {
  const Limits limits = Limits::defaults();
  const std::vector<std::uint8_t> base =
      encoded_record(1, RecordKind::FailureCommitted, encode_failure_record(sample_failure()), 0,
                     limits);

  const std::vector<std::uint32_t> attacks = {
      0u, 1u, static_cast<std::uint32_t>(kMaxRecordPayload),
      static_cast<std::uint32_t>(kMaxRecordPayload + 1), 0xffffffffu};

  for (const std::uint32_t declared : attacks) {
    // (a) A rewritten declared length whose header CRC was not refreshed is refused outright:
    //     the length is never believed and nothing is allocated for it.
    std::vector<std::uint8_t> tampered = base;
    patch_u32(tampered, 20, declared);
    CHECK_EQ(peek_u32(tampered, 20), declared);
    DecodeResult result = decode_record(tampered.data(), tampered.size(), limits);
    CHECK_EQ(result.disposition, DecodeDisposition::Corrupt);
    CHECK_EQ(result.consumed, std::size_t{0});
    CHECK(result.record.payload.empty());

    // (b) A *consistent* header (CRC recomputed) may never be trusted either. Above the ceiling
    //     the declaration is refused as Corrupt; inside it the record is judged on the bytes
    //     actually present, so a length that outruns the buffer is a torn tail of exactly those
    //     bytes and a length that still fits is refused by the CRC that moved with it.
    std::vector<std::uint8_t> consistent = base;
    patch_u32(consistent, 20, declared);
    refresh_header_crc(consistent);
    DecodeResult checked = decode_record(consistent.data(), consistent.size(), limits);
    const std::size_t declared_total =
        kRecordHeaderBytes + static_cast<std::size_t>(declared) + 4;
    if (declared > kMaxRecordPayload) {
      CHECK_DECLARED_LENGTH(declared, consistent.size(), checked.disposition,
                            DecodeDisposition::Corrupt,
                            "the ceiling rule: payload_len > min(max_document_bytes, kMaxRecordPayload)");
      CHECK(checked.record.payload.empty());
    } else if (declared_total > consistent.size()) {
      CHECK_DECLARED_LENGTH(declared, consistent.size(), checked.disposition,
                            DecodeDisposition::TornTail,
                            "the torn-tail rule: a header proved complete whose body is absent");
      CHECK_EQ(checked.consumed, consistent.size());
      CHECK(checked.record.payload.empty());
      CHECK(checked.status.ok());
    } else {
      CHECK_DECLARED_LENGTH(declared, consistent.size(), checked.disposition,
                            DecodeDisposition::Corrupt,
                            "the payload integrity rule: the trailer moved with the length");
      CHECK(checked.record.payload.empty());
    }
    CHECK_LT(checked.consumed, consistent.size() + 1);
    CHECK_LT(checked.record.payload.size(), static_cast<std::size_t>(kMaxRecordPayload));
  }

  // (c) A ceiling-sized declaration with only the header present is a torn tail of exactly the
  //     bytes supplied: no payload buffer is materialised for the declared 16 MiB.
  {
    std::vector<std::uint8_t> header_only(base.begin(),
                                          base.begin() + static_cast<std::ptrdiff_t>(kRecordHeaderBytes));
    patch_u32(header_only, 20, static_cast<std::uint32_t>(kMaxRecordPayload));
    refresh_header_crc(header_only);
    DecodeResult result = decode_record(header_only.data(), header_only.size(), limits);
    CHECK_EQ(result.disposition, DecodeDisposition::TornTail);
    CHECK_EQ(result.consumed, kRecordHeaderBytes);
    CHECK(result.record.payload.empty());
    CHECK(result.status.ok());
  }

  // (d) The declared length is bounded by the configured document ceiling, not by the maximum
  //     the field can hold: a reduced ceiling refuses a length that is otherwise legal.
  {
    Limits tight = Limits::defaults();
    tight.max_document_bytes = 4096;
    tight.max_frame_payload = 4096;
    CHECK(tight.validate().ok());
    std::vector<std::uint8_t> header_only(base.begin(),
                                          base.begin() + static_cast<std::ptrdiff_t>(kRecordHeaderBytes));
    patch_u32(header_only, 20, static_cast<std::uint32_t>(kMaxRecordPayload));
    refresh_header_crc(header_only);
    DecodeResult result = decode_record(header_only.data(), header_only.size(), tight);
    CHECK_EQ(result.disposition, DecodeDisposition::Corrupt);
    CHECK_EQ(result.consumed, std::size_t{0});
  }

  // (e) Encoding refuses a payload above the same ceiling instead of truncating it.
  {
    Limits tight = Limits::defaults();
    tight.max_document_bytes = 4096;
    tight.max_frame_payload = 4096;
    Record oversized;
    oversized.header.kind = RecordKind::Checkpoint;
    oversized.payload.assign(5000, 0u);
    Result<std::vector<std::uint8_t>> encoded = encode_record(oversized, tight);
    CHECK(!encoded.ok());
    CHECK_EQ(encoded.status().code(), Code::Exhausted);
  }
}

// ---------------------------------------------------------------------------------------------
// 6. Version and kind attacks
// ---------------------------------------------------------------------------------------------

SFF_TEST(unknown_version_or_kind_is_unsupported) {
  const Limits limits = Limits::defaults();
  const std::vector<std::uint8_t> base =
      encoded_record(3, RecordKind::GrantMinted, encode_grant_record(sample_grant()), 0, limits);

  for (const std::uint16_t version : {static_cast<std::uint16_t>(0), static_cast<std::uint16_t>(2),
                                      static_cast<std::uint16_t>(0xffff)}) {
    for (const bool refreshed : {false, true}) {
      std::vector<std::uint8_t> damaged = base;
      patch_u16(damaged, 4, version);
      if (refreshed) refresh_header_crc(damaged);
      DecodeResult result = decode_record(damaged.data(), damaged.size(), limits);
      CHECK_EQ(result.disposition, DecodeDisposition::Unsupported);
      CHECK_EQ(result.status.code(), Code::VersionMismatch);
      CHECK_EQ(result.consumed, std::size_t{0});
      CHECK(result.record.payload.empty());
    }
  }

  // Kind 0 is the reserved Unknown kind; 15 and 0xffff are not assigned by this build.
  CHECK(!is_valid_record_kind(0));
  CHECK(!is_valid_record_kind(15));
  CHECK(!is_valid_record_kind(0xffff));
  CHECK(is_valid_record_kind(1));
  CHECK(is_valid_record_kind(14));

  for (const std::uint16_t kind : {static_cast<std::uint16_t>(0), static_cast<std::uint16_t>(15),
                                   static_cast<std::uint16_t>(0xffff)}) {
    for (const bool refreshed : {false, true}) {
      std::vector<std::uint8_t> damaged = base;
      patch_u16(damaged, 6, kind);
      if (refreshed) refresh_header_crc(damaged);
      DecodeResult result = decode_record(damaged.data(), damaged.size(), limits);
      CHECK_EQ(result.disposition, DecodeDisposition::Unsupported);
      CHECK_EQ(result.status.code(), Code::Unsupported);
      CHECK_EQ(result.consumed, std::size_t{0});
    }
  }

  // A version bump is refused, never silently reinterpreted as version 1.
  std::vector<std::uint8_t> future = base;
  patch_u16(future, 4, static_cast<std::uint16_t>(kRecordFormatVersion + 1));
  refresh_header_crc(future);
  DecodeResult result = decode_record(future.data(), future.size(), limits);
  CHECK_EQ(result.disposition, DecodeDisposition::Unsupported);
  CHECK(!result.complete());
}

// ---------------------------------------------------------------------------------------------
// 7. Real journal round trip
// ---------------------------------------------------------------------------------------------

SFF_TEST(journal_round_trip_is_byte_identical) {
  TempDir dir("persist-roundtrip");
  const Limits limits = Limits::defaults();
  const auto sequence = mixed_sequence();

  std::vector<std::vector<std::uint8_t>> expected;
  for (std::size_t index = 0; index < sequence.size(); ++index) {
    expected.push_back(encoded_record(index + 1, sequence[index].first, sequence[index].second,
                                      0x01020304u, limits));
  }
  CHECK_LT(concat(expected).size(), std::size_t{64} * 1024);

  {
    StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    for (std::size_t index = 0; index < sequence.size(); ++index) {
      Status appended = handle.store->append(sequence[index].first, sequence[index].second,
                                             0x01020304u);
      CHECK(appended.ok());
      if (!appended.ok()) return;
    }
    CHECK_EQ(handle.store->next_sequence(), sequence.size() + 1);
    CHECK_EQ(handle.store->records_written(), sequence.size());

    Result<ReplayReport> live = handle.store->replay();
    CHECK(live.ok());
    CHECK_EQ(live.value().records.size(), sequence.size());
    CHECK_EQ(live.value().corrupt_records, std::size_t{0});
    CHECK_EQ(live.value().torn_records, std::size_t{0});
    CHECK(!live.value().truncated_tail);
    CHECK(live.value().clean_shutdown);
    CHECK_EQ(live.value().last_sequence, sequence.size());
    for (std::size_t index = 0; index < sequence.size(); ++index) {
      CHECK_EQ(live.value().records[index].header.seq, index + 1);
      CHECK_EQ(live.value().records[index].header.kind, sequence[index].first);
      CHECK_BYTES_EQ(live.value().records[index].payload, sequence[index].second);
      CHECK_BYTES_EQ(encode_record(live.value().records[index], limits).value(), expected[index]);
    }
    CHECK(handle.store->close().ok());
  }

  // The file on disk is exactly the concatenation of the canonical records: no padding, no
  // rewriting, no framework bytes.
  const std::filesystem::path journal = dir.file(kJournalName);
  CHECK_BYTES_EQ(read_file(journal), concat(expected));

  // Reopen: the replayed records are byte-identical and the sequence continues past them.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK_EQ(handle.store->open_report().records.size(), sequence.size());
    CHECK_EQ(handle.store->open_report().last_sequence, sequence.size());
    CHECK(!handle.store->open_report().truncated_tail);
    CHECK_EQ(handle.store->torn_bytes_recovered(), std::size_t{0});
    CHECK_EQ(handle.store->next_sequence(), sequence.size() + 1);

    Result<ReplayReport> again = handle.store->replay();
    CHECK(again.ok());
    CHECK_EQ(again.value().records.size(), sequence.size());
    for (std::size_t index = 0; index < sequence.size(); ++index) {
      CHECK_BYTES_EQ(encode_record(again.value().records[index], limits).value(), expected[index]);
    }

    // A record appended after reopening continues the same sequence.
    Status appended = handle.store->append(RecordKind::EpochAdvance, encode_u64_payload(99));
    CHECK(appended.ok());
    CHECK_EQ(handle.store->next_sequence(), sequence.size() + 2);
    CHECK(handle.store->close().ok());
  }

  // Closing with a new file mode is refused, and nothing else is created in the root.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
    CHECK(!handle.ok);
    CHECK_EQ(handle.store, nullptr);
  }
  std::error_code code;
  CHECK(!std::filesystem::exists(dir.file(kSnapshotName), code));
  CHECK(!std::filesystem::exists(dir.file(kSnapshotStagingName), code));
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 8. Genuine torn tail
// ---------------------------------------------------------------------------------------------

SFF_TEST(genuine_torn_tail_is_recovered_exactly) {
  TempDir dir("persist-torn");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  std::vector<std::vector<std::uint8_t>> frames;
  std::vector<RecordKind> kinds = {RecordKind::StreamHeader, RecordKind::BootRegistered,
                                   RecordKind::ShutdownClean};
  std::vector<std::vector<std::uint8_t>> payloads = {
      encode_stream_header(1, 7, 4242, 1, 0xaaaa, 0xbbbb), encode_u64_payload(4242),
      encode_u64_payload(1)};
  for (std::size_t index = 0; index < kinds.size(); ++index) {
    frames.push_back(encoded_record(index + 1, kinds[index], payloads[index], 0, limits));
  }
  const std::vector<std::uint8_t> whole = concat(frames);
  CHECK(write_file(journal, whole));

  // Cut the journal in the middle of its third record: exactly torn_prefix bytes of that record
  // reached the disk, which is the byte-exact torn tail a crash there would leave behind.
  const std::size_t torn_prefix = 13;
  CHECK_LT(torn_prefix, frames[2].size());
  const std::size_t torn_at = frames[0].size() + frames[1].size() + torn_prefix;
  CHECK(truncate_file_to(journal, torn_at));
  const std::vector<std::uint8_t> torn = read_file(journal);
  CHECK_EQ(torn.size(), torn_at);
  CHECK_EQ(file_size_of(journal), torn.size());
  CHECK_BYTES_EQ(torn, concat({frames[0], frames[1],
                               std::vector<std::uint8_t>(
                                   frames[2].begin(),
                                   frames[2].begin() + static_cast<std::ptrdiff_t>(torn_prefix))}));

  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenOrCreate, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;

    const ReplayReport& report = handle.store->open_report();
    CHECK(report.truncated_tail);
    CHECK_EQ(report.torn_records, std::size_t{1});
    CHECK_EQ(report.corrupt_records, std::size_t{0});
    CHECK_EQ(report.recovered_bytes, torn_prefix);
    CHECK(report.status.ok());
    CHECK_EQ(report.records.size(), std::size_t{2});
    CHECK_EQ(report.last_sequence, std::uint64_t{2});
    CHECK_EQ(handle.store->torn_bytes_recovered(), torn_prefix);
    CHECK_EQ(handle.store->next_sequence(), std::uint64_t{3});

    // The genuine torn tail has been dropped physically: the journal is byte-exact again.
    CHECK_EQ(file_size_of(journal), torn_at - torn_prefix);
    CHECK_BYTES_EQ(read_file(journal), concat({frames[0], frames[1]}));

    // ... and it replays cleanly with no trace of the discarded prefix.
    Result<ReplayReport> after = handle.store->replay();
    CHECK(after.ok());
    CHECK(!after.value().truncated_tail);
    CHECK_EQ(after.value().records.size(), std::size_t{2});
    CHECK_EQ(after.value().recovered_bytes, std::size_t{0});

    // The store stays usable and continues the sequence where the intact journal stopped.
    CHECK(handle.store->append(RecordKind::EpochAdvance, encode_u64_payload(2)).ok());
    CHECK_EQ(handle.store->next_sequence(), std::uint64_t{4});
    CHECK(handle.store->close().ok());
  }

  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 9. truncate_torn_tail directly
// ---------------------------------------------------------------------------------------------

SFF_TEST(truncate_torn_tail_drops_exactly_the_requested_bytes) {
  TempDir dir("persist-truncate");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;
  CHECK(handle.store->append(RecordKind::BootRegistered, encode_u64_payload(1)).ok());
  CHECK(handle.store->append(RecordKind::Checkpoint, std::vector<std::uint8_t>{}).ok());
  const std::vector<std::uint8_t> intact = read_file(journal);
  CHECK_EQ(file_size_of(journal), intact.size());

  // A refusal larger than the journal is refused and changes nothing at all.
  Status too_large = handle.store->truncate_torn_tail(intact.size() + 1);
  CHECK(!too_large.ok());
  CHECK_EQ(too_large.code(), Code::Invalid);
  CHECK_EQ(file_size_of(journal), intact.size());
  CHECK_BYTES_EQ(read_file(journal), intact);

  // Model a crash mid-append: a byte-exact prefix of a real record lands at the end of the file.
  const std::vector<std::uint8_t> partial =
      encoded_record(3, RecordKind::FailureCommitted, encode_failure_record(sample_failure()), 0,
                     limits);
  const std::vector<std::uint8_t> stub(partial.begin(),
                                       partial.begin() + static_cast<std::ptrdiff_t>(11));
  CHECK(append_file(journal, stub));
  CHECK_EQ(file_size_of(journal), intact.size() + stub.size());

  Result<ReplayReport> with_tail = handle.store->replay();
  CHECK(with_tail.ok());
  CHECK(with_tail.value().truncated_tail);
  CHECK_EQ(with_tail.value().recovered_bytes, stub.size());
  CHECK_EQ(with_tail.value().records.size(), std::size_t{2});

  Status dropped = handle.store->truncate_torn_tail(stub.size());
  CHECK(dropped.ok());
  CHECK_EQ(file_size_of(journal), intact.size());
  CHECK_BYTES_EQ(read_file(journal), intact);

  Result<ReplayReport> after = handle.store->replay();
  CHECK(after.ok());
  CHECK(!after.value().truncated_tail);
  CHECK_EQ(after.value().records.size(), std::size_t{2});
  CHECK_EQ(after.value().recovered_bytes, std::size_t{0});

  // Truncating zero bytes is a no-op, not an error.
  CHECK(handle.store->truncate_torn_tail(0).ok());
  CHECK_BYTES_EQ(read_file(journal), intact);

  CHECK(handle.store->close().ok());
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 10. Tampering is never repaired
// ---------------------------------------------------------------------------------------------

SFF_TEST(tampering_inside_a_complete_record_is_never_repaired) {
  TempDir dir("persist-tamper");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  std::vector<std::vector<std::uint8_t>> frames;
  frames.push_back(encoded_record(1, RecordKind::BootRegistered, encode_u64_payload(4242), 0, limits));
  frames.push_back(encoded_record(2, RecordKind::FailureCommitted,
                                  encode_failure_record(sample_failure()), 0, limits));
  frames.push_back(encoded_record(3, RecordKind::ShutdownClean, encode_u64_payload(1), 0, limits));
  CHECK(write_file(journal, concat(frames)));

  // Sanity: the untouched journal opens and replays.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK_EQ(handle.store->open_report().records.size(), std::size_t{3});
    CHECK(handle.store->close().ok());
  }

  // Corrupt exactly one byte inside the payload of the *complete* second record.
  std::vector<std::uint8_t> damaged = concat(frames);
  const std::size_t victim = frames[0].size() + kRecordHeaderBytes + 5;
  CHECK_LT(victim, damaged.size());
  damaged[victim] = static_cast<std::uint8_t>(damaged[victim] ^ 0x40u);
  CHECK(write_file(journal, damaged));
  const std::uintmax_t size_before = file_size_of(journal);

  // Opening refuses; it never repairs, truncates or skips the offending record.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenOrCreate, limits);
    CHECK(!handle.ok);
    CHECK_EQ(handle.store, nullptr);
    StoreOptions options;
    options.root = dir.path();
    options.mode = OpenMode::OpenExisting;
    options.limits = limits;
    Result<std::unique_ptr<DurableStore>> refused = DurableStore::open(options);
    CHECK(!refused.ok());
    CHECK_EQ(refused.status().code(), Code::Corrupt);
  }

  // Not one byte was discarded, and the size is untouched.
  CHECK_EQ(file_size_of(journal), size_before);
  CHECK_BYTES_EQ(read_file(journal), damaged);

  // A live replay of an already-open journal reports the same verdict instead of hiding it.
  {
    // Start from a healthy journal so the store opens, then damage the file underneath it.
    CHECK(write_file(journal, concat(frames)));
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK(write_file(journal, damaged));
    Result<ReplayReport> replayed = handle.store->replay();
    // The Result status mirrors the report status, so a corrupt scan is never a successful Result.
    // The scan must classify the tampered record as corrupt, must not skip past it silently, and
    // must not accept anything beyond the last intact record.
    CHECK(!replayed.ok());
    CHECK_EQ(replayed.status().code(), Code::Corrupt);
    CHECK_EQ(replayed.value().status.code(), Code::Corrupt);
    CHECK(replayed.value().corrupt_records >= 1);
    CHECK_EQ(replayed.value().records.size(), std::size_t{1});
    CHECK_EQ(replayed.value().truncated_tail, false);
    CHECK(std::filesystem::file_size(journal) == size_before);
    CHECK_BYTES_EQ(read_file(journal), damaged);
    CHECK(handle.store->close().ok());
    CHECK_BYTES_EQ(read_file(journal), damaged);
  }

  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 11. A corrupt tail is never mistaken for a torn tail
// ---------------------------------------------------------------------------------------------

// Only a byte-exact prefix of a record may be recovered: replay() validates the tail before it is
// allowed to call it torn. A tail of arbitrary bytes - or of a header whose magic is wrong - is
// corruption, and corruption is refused rather than truncated away. The four recoverable shapes
// below also pin the exact recovered_bytes for a partial header, a whole header with no body, and
// a header whose body stopped part way.
SFF_TEST(a_corrupt_tail_is_never_mistaken_for_a_torn_tail) {
  TempDir dir("persist-tail-classify");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  const std::vector<std::uint8_t> intact =
      concat({encoded_record(1, RecordKind::BootRegistered, encode_u64_payload(1), 0, limits),
              encoded_record(2, RecordKind::BootRegistered, encode_u64_payload(2), 0, limits)});
  const std::vector<std::uint8_t> third =
      encoded_record(3, RecordKind::BootRegistered, encode_u64_payload(3), 0, limits);
  CHECK_LT(std::size_t{28 + 5}, third.size());

  std::vector<std::uint8_t> broken_magic(third.begin(), third.begin() + 9);
  broken_magic[1] = static_cast<std::uint8_t>(broken_magic[1] ^ 0xffu);

  // A complete header whose stored header CRC is wrong, and one that names an undefined kind.
  std::vector<std::uint8_t> header_bad_crc(28, 0);
  header_bad_crc[0] = 'S';
  header_bad_crc[1] = 'F';
  header_bad_crc[2] = 'F';
  header_bad_crc[3] = '1';
  header_bad_crc[4] = 1;  // format version 1
  header_bad_crc[6] = 1;  // StreamHeader
  header_bad_crc[24] = 0xef;
  header_bad_crc[25] = 0xbe;
  header_bad_crc[26] = 0xad;
  header_bad_crc[27] = 0xde;
  std::vector<std::uint8_t> header_unknown_kind = header_bad_crc;
  patch_u16(header_unknown_kind, 6, 0xffff);
  refresh_header_crc(header_unknown_kind);

  struct TailCase {
    const char* name;
    std::vector<std::uint8_t> tail;
    DecodeDisposition expected;
  };
  std::vector<TailCase> cases;
  cases.push_back(TailCase{"one byte of a real header", {third[0]}, DecodeDisposition::TornTail});
  cases.push_back(TailCase{"27 bytes of a real header",
                           std::vector<std::uint8_t>(third.begin(), third.begin() + 27),
                           DecodeDisposition::TornTail});
  cases.push_back(TailCase{"a whole real header with no body",
                           std::vector<std::uint8_t>(third.begin(), third.begin() + 28),
                           DecodeDisposition::TornTail});
  cases.push_back(TailCase{"a real header whose body stopped part way",
                           std::vector<std::uint8_t>(third.begin(), third.begin() + 28 + 5),
                           DecodeDisposition::TornTail});
  // Below a full header the decoder can only verify the magic, so a short tail that carries the
  // magic counts as a recoverable prefix by the documented rule even though its trailing bytes are
  // arbitrary. It is bounded by 27 bytes and fully reported in recovered_bytes.
  cases.push_back(TailCase{"six bytes whose only valid part is the magic",
                           std::vector<std::uint8_t>{'S', 'F', 'F', '1', 0xff, 0xff},
                           DecodeDisposition::TornTail});
  cases.push_back(TailCase{"nine zero bytes", std::vector<std::uint8_t>(9, 0x00),
                           DecodeDisposition::Corrupt});
  cases.push_back(
      TailCase{"a partial header with a broken magic", broken_magic, DecodeDisposition::Corrupt});
  cases.push_back(
      TailCase{"a whole header with a broken header CRC", header_bad_crc, DecodeDisposition::Corrupt});
  cases.push_back(TailCase{"a whole header naming an undefined kind", header_unknown_kind,
                           DecodeDisposition::Unsupported});

  for (const auto& entry : cases) {
    const std::vector<std::uint8_t> bytes = concat({intact, entry.tail});
    CHECK(write_file(journal, bytes));
    const std::uintmax_t size_before = file_size_of(journal);

    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    if (entry.expected == DecodeDisposition::TornTail) {
      CHECK(handle.ok);
      if (!handle.ok) continue;
      const ReplayReport& report = handle.store->open_report();
      CHECK(report.truncated_tail);
      CHECK_EQ(report.recovered_bytes, entry.tail.size());
      CHECK_EQ(report.torn_records, std::size_t{1});
      CHECK_EQ(report.corrupt_records, std::size_t{0});
      CHECK_EQ(report.unsupported_records, std::size_t{0});
      CHECK_EQ(report.records.size(), std::size_t{2});
      CHECK_EQ(handle.store->torn_bytes_recovered(), entry.tail.size());
      CHECK_EQ(file_size_of(journal), size_before - entry.tail.size());
      CHECK_BYTES_EQ(read_file(journal), intact);
      CHECK(handle.store->close().ok());
    } else {
      CHECK(!handle.ok);
      CHECK_EQ(handle.store, nullptr);
      CHECK_EQ(handle.open_status.code(), entry.expected == DecodeDisposition::Unsupported
                                              ? Code::Unsupported
                                              : Code::Corrupt);
      // Nothing was repaired: no byte was dropped and the size is untouched.
      CHECK_EQ(file_size_of(journal), size_before);
      CHECK_BYTES_EQ(read_file(journal), bytes);
    }
  }
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 12. Sequence integrity
// ---------------------------------------------------------------------------------------------

SFF_TEST(sequence_regression_is_replay_and_gaps_are_corrupt) {
  TempDir dir("persist-sequence");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  const auto frame = [&limits](std::uint64_t seq) {
    return encoded_record(seq, RecordKind::BootRegistered, encode_u64_payload(seq), 0, limits);
  };

  // Sanity: a contiguous journal opens.
  {
    CHECK(write_file(journal, concat({frame(1), frame(2), frame(3)})));
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (handle.ok) {
      CHECK_EQ(handle.store->open_report().last_sequence, std::uint64_t{3});
      CHECK(handle.store->close().ok());
    }
  }

  // A sequence that goes backwards (duplicated or regressed) is a replay, not new durable state,
  // and is refused with the precise Code::Replay. A sequence that jumps ahead is a hole in the
  // journal and is refused with Code::Corrupt. Both are non-Ok and fail closed, and neither
  // rewrites or trims the bytes it refused.
  struct Case {
    const char* name;
    std::vector<std::uint64_t> sequences;
    Code expected;
  };
  const std::vector<Case> cases = {
      {"duplicate", {1, 2, 2}, Code::Replay},
      {"regressed", {1, 2, 1}, Code::Replay},
      {"restart at one", {1, 2, 3, 1}, Code::Replay},
      {"gap", {1, 2, 4}, Code::Corrupt},
      {"hole at the head", {2, 4}, Code::Corrupt},
  };

  for (const auto& entry : cases) {
    std::vector<std::vector<std::uint8_t>> built;
    for (const std::uint64_t seq : entry.sequences) built.push_back(frame(seq));
    const std::vector<std::uint8_t> bytes = concat(built);
    CHECK(write_file(journal, bytes));
    const std::uintmax_t size_before = file_size_of(journal);

    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(!handle.ok);
    CHECK_EQ(handle.store, nullptr);
    CHECK_EQ(handle.open_status.code(), entry.expected);
    CHECK(!handle.open_status.ok());
    CHECK_EQ(file_size_of(journal), size_before);
    CHECK_BYTES_EQ(read_file(journal), bytes);
  }

  // The same verdict is reachable from replay() on an open journal: a duplicated sequence
  // appended after a healthy journal is refused, and the refusal is not a silent skip.
  {
    CHECK(write_file(journal, concat({frame(1), frame(2), frame(3)})));
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK_EQ(handle.store->next_sequence(), std::uint64_t{4});
    CHECK(append_file(journal, frame(3)));
    Result<ReplayReport> replayed = handle.store->replay();
    CHECK(!replayed.ok());
    CHECK_EQ(replayed.status().code(), Code::Replay);
    CHECK_EQ(replayed.value().status.code(), Code::Replay);
    CHECK(replayed.value().corrupt_records >= 1);
    CHECK_EQ(replayed.value().last_sequence, std::uint64_t{3});
    CHECK_EQ(replayed.value().records.size(), std::size_t{3});
    CHECK(handle.store->close().ok());
  }

  // A record that jumps ahead of the expected sequence is refused as a hole, and the bytes are
  // left exactly as they were found.
  {
    CHECK(write_file(journal, concat({frame(1), frame(2), frame(3)})));
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    const std::vector<std::uint8_t> before = read_file(journal);
    CHECK(append_file(journal, frame(7)));
    const std::vector<std::uint8_t> after_append = read_file(journal);
    CHECK_LT(before.size(), after_append.size());
    Result<ReplayReport> replayed = handle.store->replay();
    CHECK(!replayed.ok());
    CHECK_EQ(replayed.status().code(), Code::Corrupt);
    CHECK_EQ(replayed.value().status.code(), Code::Corrupt);
    CHECK(replayed.value().corrupt_records >= 1);
    CHECK_EQ(replayed.value().records.size(), std::size_t{3});
    CHECK_BYTES_EQ(read_file(journal), after_append);
    CHECK(handle.store->close().ok());
  }

  // A journal that legitimately starts later - a compacted suffix - is anchored on its first
  // record and is not a hole. Only a break *after* that anchor is refused.
  {
    CHECK(write_file(journal, concat({frame(5), frame(6), frame(7)})));
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK_EQ(handle.store->open_report().records.size(), std::size_t{3});
    CHECK_EQ(handle.store->open_report().last_sequence, std::uint64_t{7});
    CHECK_EQ(handle.store->next_sequence(), std::uint64_t{8});
    CHECK(handle.store->open_report().status.ok());
    CHECK(handle.store->close().ok());
  }

  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 13. Snapshot
// ---------------------------------------------------------------------------------------------

SFF_TEST(snapshot_round_trip_replacement_and_no_staging_left_behind) {
  TempDir dir("persist-snapshot");
  const Limits limits = Limits::defaults();

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  CHECK(!handle.store->has_snapshot());
  Result<std::vector<std::uint8_t>> missing = handle.store->read_snapshot();
  CHECK(!missing.ok());
  CHECK_EQ(missing.status().code(), Code::NotFound);

  const std::vector<std::uint8_t> first_document = {1, 2, 3, 4, 5, 6, 7, 8};
  CHECK(handle.store->write_snapshot(first_document).ok());
  CHECK(handle.store->has_snapshot());
  Result<std::vector<std::uint8_t>> read_back = handle.store->read_snapshot();
  CHECK(read_back.ok());
  CHECK_BYTES_EQ(read_back.value(), first_document);
  // The document is stored verbatim, followed by exactly one 4-byte integrity trailer.
  std::vector<std::uint8_t> on_disk = first_document;
  push_u32(on_disk, crc32_ieee(first_document));
  CHECK_BYTES_EQ(read_file(dir.file(kSnapshotName)), on_disk);

  // A second snapshot replaces the first, transactionally and without leaving staging debris.
  const std::vector<std::uint8_t> second_document(4096, 0x5au);
  CHECK(handle.store->write_snapshot(second_document).ok());
  Result<std::vector<std::uint8_t>> replaced = handle.store->read_snapshot();
  CHECK(replaced.ok());
  CHECK_BYTES_EQ(replaced.value(), second_document);
  CHECK_NE(replaced.value().size(), first_document.size());
  std::error_code code;
  CHECK(!std::filesystem::exists(dir.file(kSnapshotStagingName), code));

  // An empty document is a legal snapshot: four bytes of trailer and nothing else.
  CHECK(handle.store->write_snapshot({}).ok());
  Result<std::vector<std::uint8_t>> empty = handle.store->read_snapshot();
  CHECK(empty.ok());
  CHECK_EQ(empty.value().size(), std::size_t{0});
  CHECK_EQ(file_size_of(dir.file(kSnapshotName)), std::uintmax_t{4});
  CHECK(!std::filesystem::exists(dir.file(kSnapshotStagingName), code));

  // A document above the configured ceiling is refused and leaves the previous snapshot intact.
  {
    Limits tight = Limits::defaults();
    tight.max_document_bytes = 4096;
    tight.max_frame_payload = 4096;
    StoreHandle limited = open_store(dir.path(), OpenMode::OpenExisting, tight);
    CHECK(limited.ok);
    if (limited.ok) {
      Status refused = limited.store->write_snapshot(std::vector<std::uint8_t>(5000, 0u));
      CHECK(!refused.ok());
      CHECK_EQ(refused.code(), Code::Exhausted);
      Result<std::vector<std::uint8_t>> survivor = limited.store->read_snapshot();
      CHECK(survivor.ok());
      CHECK_EQ(survivor.value().size(), std::size_t{0});
      CHECK(limited.store->close().ok());
    }
  }

  CHECK(handle.store->close().ok());
  remove_store_files(dir.path());
}

SFF_TEST(snapshot_trailer_corruption_and_trailing_garbage_are_corrupt) {
  TempDir dir("persist-snapshot-bad");
  const Limits limits = Limits::defaults();
  const std::filesystem::path snapshot = dir.file(kSnapshotName);

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  const std::vector<std::uint8_t> document(64, 0x11);
  CHECK(handle.store->write_snapshot(document).ok());
  std::vector<std::uint8_t> good = read_file(snapshot);
  CHECK_EQ(good.size(), document.size() + 4);

  // Flip one byte of the integrity trailer.
  std::vector<std::uint8_t> broken_trailer = good;
  broken_trailer.back() = static_cast<std::uint8_t>(broken_trailer.back() ^ 0x01u);
  CHECK(write_file(snapshot, broken_trailer));
  Result<std::vector<std::uint8_t>> refused = handle.store->read_snapshot();
  CHECK(!refused.ok());
  CHECK_EQ(refused.status().code(), Code::Corrupt);
  CHECK_BYTES_EQ(read_file(snapshot), broken_trailer);

  // Trailing garbage: the last four bytes are no longer the document's CRC.
  std::vector<std::uint8_t> garbage = good;
  for (std::size_t index = 0; index < 9; ++index) garbage.push_back(0x7fu);
  CHECK(write_file(snapshot, garbage));
  Result<std::vector<std::uint8_t>> with_garbage = handle.store->read_snapshot();
  CHECK(!with_garbage.ok());
  CHECK_EQ(with_garbage.status().code(), Code::Corrupt);
  CHECK_BYTES_EQ(read_file(snapshot), garbage);

  // A document byte flipped underneath a valid trailer is also refused.
  std::vector<std::uint8_t> flipped_document = good;
  flipped_document[7] = static_cast<std::uint8_t>(flipped_document[7] ^ 0x80u);
  CHECK(write_file(snapshot, flipped_document));
  Result<std::vector<std::uint8_t>> damaged = handle.store->read_snapshot();
  CHECK(!damaged.ok());
  CHECK_EQ(damaged.status().code(), Code::Corrupt);

  // A snapshot shorter than its own trailer is truncated, never guessed at.
  CHECK(write_file(snapshot, std::vector<std::uint8_t>{0x01, 0x02}));
  Result<std::vector<std::uint8_t>> short_snapshot = handle.store->read_snapshot();
  CHECK(!short_snapshot.ok());
  CHECK_EQ(short_snapshot.status().code(), Code::Truncated);

  // A repaired snapshot is read back exactly: corruption never sticks.
  CHECK(handle.store->write_snapshot(document).ok());
  Result<std::vector<std::uint8_t>> healed = handle.store->read_snapshot();
  CHECK(healed.ok());
  CHECK_BYTES_EQ(healed.value(), document);
  std::error_code code;
  CHECK(!std::filesystem::exists(dir.file(kSnapshotStagingName), code));

  CHECK(handle.store->close().ok());
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 14. Path hardening
// ---------------------------------------------------------------------------------------------

SFF_TEST(sanitise_path_rejects_traversal_and_absolutises_relative) {
  Result<std::filesystem::path> empty = sanitise_path(std::filesystem::path{});
  CHECK(!empty.ok());
  CHECK_EQ(empty.status().code(), Code::Invalid);

  const std::vector<std::string> traversal = {"..", "../escape", "a/../b", "a/b/..", "..\\escape",
                                              "a/..", "a/b/../../c"};
  for (const auto& text : traversal) {
    Result<std::filesystem::path> refused = sanitise_path(std::filesystem::path(text));
    CHECK(!refused.ok());
    CHECK_EQ(refused.status().code(), Code::Invalid);
  }

  const std::vector<std::string> accepted = {"relative/dir", "plain", "a/b/c", "./relative/dir"};
  for (const auto& text : accepted) {
    Result<std::filesystem::path> resolved = sanitise_path(std::filesystem::path(text));
    CHECK(resolved.ok());
    if (!resolved.ok()) continue;
    CHECK(resolved.value().is_absolute());
    for (const auto& component : resolved.value()) CHECK_NE(component.string(), std::string(".."));
    const std::filesystem::path expected =
        std::filesystem::absolute(std::filesystem::path(text)).lexically_normal();
    CHECK_EQ(resolved.value(), expected);
  }

  // The store applies the same hardening to its root: a traversal root never opens a journal.
  TempDir dir("persist-path");
  StoreOptions options;
  options.root = dir.path() / ".." / "escape";
  Result<std::unique_ptr<DurableStore>> refused = DurableStore::open(options);
  CHECK(!refused.ok());
  CHECK_EQ(refused.status().code(), Code::Invalid);
  std::error_code code;
  CHECK(!std::filesystem::exists(dir.path() / ".." / "escape", code));

  StoreOptions empty_root;
  empty_root.root = std::filesystem::path{};
  Result<std::unique_ptr<DurableStore>> no_root = DurableStore::open(empty_root);
  CHECK(!no_root.ok());
  CHECK_EQ(no_root.status().code(), Code::Invalid);
}

// ---------------------------------------------------------------------------------------------
// 15. Durability ordering
// ---------------------------------------------------------------------------------------------

SFF_TEST(append_is_visible_to_a_fresh_replay_and_close_is_stable) {
  TempDir dir("persist-durability");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  const std::vector<std::uint8_t> payload = encode_failure_record(sample_failure());
  const std::vector<std::uint8_t> expected =
      encoded_record(1, RecordKind::FailureCommitted, payload, 0, limits);
  CHECK(handle.store->append(RecordKind::FailureCommitted, payload).ok());

  // The published bytes are physically in the file the moment append() reports success.
  CHECK_BYTES_EQ(read_file(journal), expected);

  // A fresh scan of the same file sees the record.
  Result<ReplayReport> fresh = handle.store->replay();
  CHECK(fresh.ok());
  CHECK_EQ(fresh.value().records.size(), std::size_t{1});
  CHECK_BYTES_EQ(encode_record(fresh.value().records[0], limits).value(), expected);

  CHECK(handle.store->flush().ok());
  CHECK(handle.store->sync().ok());
  const std::uintmax_t size_open = file_size_of(journal);
  CHECK_EQ(size_open, std::uintmax_t{expected.size()});

  CHECK(handle.store->close().ok());
  CHECK(handle.store->closed());
  const std::uintmax_t size_closed = file_size_of(journal);
  CHECK_EQ(size_closed, size_open);
  CHECK_BYTES_EQ(read_file(journal), expected);

  // Appending to a closed store is refused without touching the file.
  Status refused = handle.store->append(RecordKind::Checkpoint, std::vector<std::uint8_t>{});
  CHECK(!refused.ok());
  CHECK_EQ(refused.code(), Code::Closed);
  CHECK_EQ(file_size_of(journal), size_closed);
  CHECK_BYTES_EQ(read_file(journal), expected);

  // Reopening and closing again is size-stable, and the record survives the round trip.
  {
    StoreHandle again = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(again.ok);
    if (!again.ok) return;
    CHECK_EQ(again.store->open_report().records.size(), std::size_t{1});
    CHECK_BYTES_EQ(read_file(journal), expected);
    CHECK(again.store->close().ok());
  }
  CHECK_EQ(file_size_of(journal), size_closed);
  CHECK_BYTES_EQ(read_file(journal), expected);

  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 16. Bounded refusal
// ---------------------------------------------------------------------------------------------

SFF_TEST(max_journal_records_refuses_instead_of_growing) {
  TempDir dir("persist-bounded");
  const std::filesystem::path journal = dir.file(kJournalName);

  Limits limits = Limits::defaults();
  limits.max_journal_records = 3;
  CHECK(limits.validate().ok());

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  for (std::uint64_t index = 1; index <= 3; ++index) {
    Status appended = handle.store->append(RecordKind::BootRegistered, encode_u64_payload(index));
    CHECK(appended.ok());
  }
  const std::uintmax_t size_at_limit = file_size_of(journal);
  const std::uint64_t sequence_at_limit = handle.store->next_sequence();
  CHECK_EQ(sequence_at_limit, std::uint64_t{4});
  CHECK_EQ(handle.store->records_written(), std::uint64_t{3});

  for (int attempt = 0; attempt < 3; ++attempt) {
    Status refused = handle.store->append(RecordKind::BootRegistered, encode_u64_payload(99));
    CHECK(!refused.ok());
    CHECK_EQ(refused.code(), Code::Exhausted);
  }
  // A refused append writes nothing, moves no sequence number and leaves replay healthy.
  CHECK_EQ(file_size_of(journal), size_at_limit);
  CHECK_EQ(handle.store->next_sequence(), sequence_at_limit);
  CHECK_EQ(handle.store->records_written(), std::uint64_t{3});

  Result<ReplayReport> report = handle.store->replay();
  CHECK(report.ok());
  CHECK_EQ(report.value().records.size(), std::size_t{3});
  CHECK_EQ(report.value().corrupt_records, std::size_t{0});
  CHECK(handle.store->close().ok());

  // The replay bound is enforced on the read path too: a journal with more records than the
  // configured ceiling is refused rather than materialised without bound.
  {
    Limits narrow = Limits::defaults();
    narrow.max_journal_records = 2;
    CHECK(narrow.validate().ok());
    StoreHandle limited = open_store(dir.path(), OpenMode::OpenExisting, narrow);
    CHECK(!limited.ok);
    CHECK_EQ(limited.store, nullptr);
    StoreOptions options;
    options.root = dir.path();
    options.mode = OpenMode::OpenExisting;
    options.limits = narrow;
    Result<std::unique_ptr<DurableStore>> refused = DurableStore::open(options);
    CHECK(!refused.ok());
    CHECK_EQ(refused.status().code(), Code::Exhausted);
    // The refusal never rewrites or trims the journal it refused to materialise.
    CHECK_EQ(file_size_of(journal), size_at_limit);
  }

  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 17. An unrecognised kind cannot be appended
// ---------------------------------------------------------------------------------------------

SFF_TEST(store_refuses_to_persist_an_undefined_record_kind) {
  TempDir dir("persist-kind");
  const Limits limits = Limits::defaults();

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  const std::vector<std::uint8_t> payload = encode_u64_payload(1);
  Status unknown = handle.store->append(RecordKind::Unknown, payload);
  CHECK(!unknown.ok());
  CHECK_EQ(unknown.code(), Code::Invalid);

  Status unassigned = handle.store->append(static_cast<RecordKind>(15), payload);
  CHECK(!unassigned.ok());
  CHECK_EQ(unassigned.code(), Code::Invalid);

  Status absurd = handle.store->append(static_cast<RecordKind>(0xffff), payload);
  CHECK(!absurd.ok());
  CHECK_EQ(absurd.code(), Code::Invalid);

  CHECK_EQ(handle.store->next_sequence(), std::uint64_t{1});
  CHECK_EQ(file_size_of(dir.file(kJournalName)), std::uintmax_t{0});

  CHECK(handle.store->append(RecordKind::BootRegistered, payload).ok());
  CHECK_EQ(handle.store->next_sequence(), std::uint64_t{2});
  CHECK(handle.store->close().ok());
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 18. Rewriting the journal through compact() keeps the format canonical
// ---------------------------------------------------------------------------------------------

// replay() requires a journal to start at sequence 1 and to stay contiguous, so a compaction that
// keeps a *suffix* of the original records produces a journal that the same library then refuses
// to open at all. That deviation is probed at the end of this case and reported; the assertions
// below use the renumbered form that keeps the journal replayable, which is what a compaction
// that drops a superseded prefix must produce.
SFF_TEST(compaction_rewrites_a_canonical_journal) {
  TempDir dir("persist-compact");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;

  for (std::uint64_t seq = 1; seq <= 5; ++seq) {
    CHECK(handle.store->append(RecordKind::BootRegistered, encode_u64_payload(seq)).ok());
  }

  std::vector<Record> kept;
  for (std::uint64_t seq = 1; seq <= 3; ++seq) {
    Record record;
    record.header.magic = kRecordMagic;
    record.header.format_version = kRecordFormatVersion;
    record.header.kind = RecordKind::BootRegistered;
    record.header.seq = seq;
    record.payload = encode_u64_payload(seq + 2);
    kept.push_back(record);
  }
  CHECK(handle.store->compact(kept).ok());
  CHECK_EQ(handle.store->next_sequence(), std::uint64_t{4});

  std::vector<std::vector<std::uint8_t>> expected;
  for (const auto& record : kept) expected.push_back(encode_record(record, limits).value());
  CHECK_BYTES_EQ(read_file(journal), concat(expected));
  CHECK_EQ(file_size_of(journal), std::uintmax_t{concat(expected).size()});

  Result<ReplayReport> report = handle.store->replay();
  CHECK(report.value().status.ok());
  CHECK_EQ(report.value().records.size(), std::size_t{3});
  CHECK_EQ(report.value().last_sequence, std::uint64_t{3});
  CHECK_EQ(report.value().corrupt_records, std::size_t{0});
  CHECK(report.value().clean_shutdown == false);

  // A record that cannot be encoded refuses the whole compaction and leaves the journal intact.
  {
    const std::vector<std::uint8_t> before = read_file(journal);
    std::vector<Record> oversized = kept;
    oversized.push_back(Record{});
    oversized.back().header.kind = RecordKind::Checkpoint;
    oversized.back().header.seq = 6;
    oversized.back().payload.assign(kMaxRecordPayload + 1, 0u);
    Status refused = handle.store->compact(oversized);
    CHECK(!refused.ok());
    CHECK_BYTES_EQ(read_file(journal), before);
    std::error_code staging_code;
    CHECK(!std::filesystem::exists(dir.file("sff.journal.staging"), staging_code));

    // The store is still usable after the refusal and the journal still replays.
    CHECK(handle.store->append(RecordKind::EpochAdvance, encode_u64_payload(4)).ok());
    Result<ReplayReport> after = handle.store->replay();
    CHECK(after.ok());
    CHECK_EQ(after.value().records.size(), std::size_t{4});
    const std::vector<std::uint8_t> grown = read_file(journal);
    CHECK_LT(before.size(), grown.size());
    CHECK_BYTES_EQ(std::vector<std::uint8_t>(grown.begin(),
                                             grown.begin() + static_cast<std::ptrdiff_t>(before.size())),
                   before);
  }

  CHECK(handle.store->close().ok());
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 19. compact() that keeps a suffix
// ---------------------------------------------------------------------------------------------

// compact() writes the supplied records verbatim, so a compaction that drops a superseded prefix
// produces a journal whose first record is no longer sequence 1. replay() anchors sequence
// continuity on the first record actually present, so that journal must reopen and continue.
SFF_TEST(compaction_that_keeps_a_suffix_replays_correctly) {
  TempDir dir("persist-compact-suffix");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);

  StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
  CHECK(handle.ok);
  if (!handle.ok) return;
  for (std::uint64_t seq = 1; seq <= 3; ++seq) {
    CHECK(handle.store->append(RecordKind::BootRegistered, encode_u64_payload(seq)).ok());
  }

  // Keep only the newest record, exactly as a compaction that drops a superseded prefix would.
  Record survivor;
  survivor.header.magic = kRecordMagic;
  survivor.header.format_version = kRecordFormatVersion;
  survivor.header.kind = RecordKind::BootRegistered;
  survivor.header.seq = 3;
  survivor.payload = encode_u64_payload(3);
  CHECK(handle.store->compact({survivor}).ok());
  CHECK_EQ(handle.store->next_sequence(), std::uint64_t{4});
  CHECK_BYTES_EQ(read_file(journal), encode_record(survivor, limits).value());
  CHECK(handle.store->close().ok());

  StoreHandle again = open_store(dir.path(), OpenMode::OpenExisting, limits);
  CHECK(again.ok);
  if (!again.ok) return;
  CHECK_EQ(again.store->open_report().records.size(), std::size_t{1});
  CHECK_EQ(again.store->open_report().last_sequence, std::uint64_t{3});
  CHECK(!again.store->open_report().truncated_tail);
  CHECK_EQ(again.store->next_sequence(), std::uint64_t{4});

  // The compacted journal is a live journal: the next append continues the sequence and the file
  // is exactly the kept record followed by the new one.
  const std::vector<std::uint8_t> continuation =
      encoded_record(4, RecordKind::EpochAdvance, encode_u64_payload(4), 0, limits);
  CHECK(again.store->append(RecordKind::EpochAdvance, encode_u64_payload(4)).ok());
  std::vector<std::uint8_t> expected = encode_record(survivor, limits).value();
  expected.insert(expected.end(), continuation.begin(), continuation.end());
  CHECK_BYTES_EQ(read_file(journal), expected);
  Result<ReplayReport> report = again.store->replay();
  CHECK(report.ok());
  CHECK_EQ(report.value().records.size(), std::size_t{2});
  CHECK_EQ(report.value().last_sequence, std::uint64_t{4});
  CHECK(again.store->close().ok());
  remove_store_files(dir.path());
}

// ---------------------------------------------------------------------------------------------
// 20. A journal larger than any internal replay window
// ---------------------------------------------------------------------------------------------

// This case exists because replay() once scanned through a fixed 64 KiB window: a record that
// straddled the window edge looked torn while being complete in the file, and open() then
// truncated the journal by the bytes left in the WINDOW, which is not the number of bytes at the
// end of the file, so any journal past 64 KiB lost complete records. replay() is now a streaming
// reader - validated 28-byte header, then exactly payload_len + 4 bytes of body - so journal size
// is unbounded and nothing straddles anything. The assertions below are the contract that must
// hold for any journal size: every appended record comes back byte-identical, re-encoding the
// whole replay reproduces the file byte for byte, and no byte is dropped by open+close. The
// companion case genuine_torn_tail_is_recovered_exactly keeps the other half of the contract:
// a journal that really does end mid-record still reports truncated_tail with an exact
// recovered_bytes, so a genuine torn tail is never hidden.
SFF_TEST(journal_larger_than_any_internal_window_replays_without_loss) {
  TempDir dir("persist-window");
  const Limits limits = Limits::defaults();
  const std::filesystem::path journal = dir.file(kJournalName);
  const std::vector<std::uint8_t> payload(300, 0x5a);
  const std::uint64_t total_records = 400;  // 400 x 332 bytes = 132800 bytes, well past 64 KiB
  const std::vector<std::uint8_t> frame =
      encoded_record(1, RecordKind::BootRegistered, payload, 0, limits);
  CHECK_LT(std::size_t{64} * 1024, frame.size() * static_cast<std::size_t>(total_records));

  std::vector<std::uint8_t> appended_bytes;
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::CreateNew, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    for (std::uint64_t index = 0; index < total_records; ++index) {
      CHECK(handle.store->append(RecordKind::BootRegistered, payload).ok());
      const std::vector<std::uint8_t> canonical =
          encoded_record(index + 1, RecordKind::BootRegistered, payload, 0, limits);
      appended_bytes.insert(appended_bytes.end(), canonical.begin(), canonical.end());
    }
    CHECK_EQ(file_size_of(journal),
             static_cast<std::uintmax_t>(frame.size() * static_cast<std::size_t>(total_records)));
    CHECK(handle.store->close().ok());
  }

  const std::uintmax_t size_before = file_size_of(journal);
  CHECK_BYTES_EQ(read_file(journal), appended_bytes);

  // Reopening replays every record: nothing is torn, nothing is corrupt, nothing is dropped.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    const ReplayReport& report = handle.store->open_report();
    CHECK_EQ(report.records.size(), static_cast<std::size_t>(total_records));
    CHECK(!report.truncated_tail);
    CHECK_EQ(report.torn_records, std::size_t{0});
    CHECK_EQ(report.recovered_bytes, std::size_t{0});
    CHECK_EQ(report.corrupt_records, std::size_t{0});
    CHECK_EQ(report.unsupported_records, std::size_t{0});
    CHECK_EQ(report.last_sequence, total_records);
    CHECK(report.status.ok());
    CHECK_EQ(handle.store->torn_bytes_recovered(), std::size_t{0});
    CHECK_EQ(handle.store->next_sequence(), total_records + 1);

    // Every replayed record is byte-identical to the record that was appended, and re-encoding
    // the whole replay reproduces the journal byte for byte.
    std::vector<std::uint8_t> replayed_bytes;
    for (std::size_t index = 0; index < report.records.size(); ++index) {
      const Record& record = report.records[index];
      CHECK_EQ(record.header.seq, static_cast<std::uint64_t>(index) + 1);
      CHECK_EQ(record.header.kind, RecordKind::BootRegistered);
      CHECK_BYTES_EQ(record.payload, payload);
      const std::vector<std::uint8_t> canonical = encode_record(record, limits).value();
      CHECK_BYTES_EQ(canonical,
                     encoded_record(record.header.seq, RecordKind::BootRegistered, payload, 0,
                                    limits));
      replayed_bytes.insert(replayed_bytes.end(), canonical.begin(), canonical.end());
    }
    CHECK_BYTES_EQ(replayed_bytes, appended_bytes);
    CHECK_BYTES_EQ(read_file(journal), appended_bytes);

    // A fresh scan of the same file reaches the same verdict.
    Result<ReplayReport> fresh = handle.store->replay();
    CHECK(fresh.ok());
    CHECK_EQ(fresh.value().records.size(), static_cast<std::size_t>(total_records));
    CHECK(!fresh.value().truncated_tail);
    CHECK_EQ(fresh.value().recovered_bytes, std::size_t{0});

    CHECK(handle.store->close().ok());
  }

  // Opening and closing a journal past the old window drops nothing at all.
  CHECK_EQ(file_size_of(journal), size_before);
  CHECK_BYTES_EQ(read_file(journal), appended_bytes);

  // The store stays usable and continues the sequence where the replayed journal ended.
  {
    StoreHandle handle = open_store(dir.path(), OpenMode::OpenExisting, limits);
    CHECK(handle.ok);
    if (!handle.ok) return;
    CHECK_EQ(handle.store->next_sequence(), total_records + 1);
    const std::vector<std::uint8_t> tail =
        encoded_record(total_records + 1, RecordKind::EpochAdvance, encode_u64_payload(1), 0,
                       limits);
    CHECK(handle.store->append(RecordKind::EpochAdvance, encode_u64_payload(1)).ok());
    std::vector<std::uint8_t> expected = appended_bytes;
    expected.insert(expected.end(), tail.begin(), tail.end());
    CHECK_BYTES_EQ(read_file(journal), expected);
    Result<ReplayReport> report = handle.store->replay();
    CHECK(report.ok());
    CHECK_EQ(report.value().records.size(), static_cast<std::size_t>(total_records) + 1);
    CHECK_EQ(report.value().last_sequence, total_records + 1);
    CHECK(handle.store->close().ok());
  }

  remove_store_files(dir.path());
}

}  // namespace

SFF_MAIN()
