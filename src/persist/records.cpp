// Switch Failover Fabric - versioned, integrity-checked durable records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/persist/records.hpp"

#include <algorithm>
#include <string>

#include "sff/codec/bytes.hpp"
#include "sff/codec/integrity.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/generation.hpp"
#include "sff/plan/plan.hpp"

namespace sff {
namespace {

/// The four on-wire magic bytes: 'S','F','F','1'.
constexpr std::uint8_t kMagicBytes[4] = {0x53, 0x46, 0x46, 0x31};

/// Payload format tag. Present at the head of every record payload so that an older encoding is
/// refused instead of misread.
constexpr std::uint8_t kPayloadFormatTag = 1;

void write_u32_le(std::uint8_t* out, std::uint32_t value) noexcept {
  for (std::size_t index = 0; index < 4; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu);
  }
}

void write_u64_le(std::uint8_t* out, std::uint64_t value) noexcept {
  for (std::size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu);
  }
}

std::uint32_t read_u32_le(const std::uint8_t* in) noexcept {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(in[index]) << (8 * index);
  }
  return value;
}

std::uint64_t read_u64_le(const std::uint8_t* in) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(in[index]) << (8 * index);
  }
  return value;
}

void write_key(ByteWriter& writer, const SwitchKey& key) {
  writer.u64(key.id().raw());
  writer.u64(key.generation().raw());
}

SwitchKey read_key(ByteReader& reader) {
  const SwitchId id(reader.u64());
  const SwitchGeneration generation(reader.u64());
  return SwitchKey(id, generation);
}

void write_dependent(ByteWriter& writer, const DependentRef& dependent) {
  writer.u8(static_cast<std::uint8_t>(dependent.kind()));
  writer.u64(dependent.id());
}

DependentRef read_dependent(ByteReader& reader) {
  const std::uint8_t kind = reader.u8();
  const std::uint64_t id = reader.u64();
  if (!reader.ok()) return DependentRef{};
  if (!is_valid_dependent_kind(kind)) {
    reader.fail(Code::Invalid, "durable dependent kind is not defined");
    return DependentRef{};
  }
  return DependentRef(static_cast<DependentKind>(kind), id);
}

void write_boot(ByteWriter& writer, const BootIncarnation& boot) {
  writer.u64(boot.process_id());
  writer.u64(boot.boot_ordinal());
  writer.u64(boot.nonce_hi());
  writer.u64(boot.nonce_lo());
}

BootIncarnation read_boot(ByteReader& reader) {
  const std::uint64_t process_id = reader.u64();
  const std::uint64_t boot_ordinal = reader.u64();
  const std::uint64_t nonce_hi = reader.u64();
  const std::uint64_t nonce_lo = reader.u64();
  return BootIncarnation::from_parts(process_id, boot_ordinal, nonce_hi, nonce_lo);
}

void write_explanation(ByteWriter& writer, const Explanation& explanation) {
  writer.u32(static_cast<std::uint32_t>(explanation.terms().size()));
  for (const auto& term : explanation.terms()) {
    writer.string(term.key);
    writer.string(term.value);
  }
  writer.boolean(explanation.truncated());
}

Explanation read_explanation(ByteReader& reader, const Limits& limits) {
  Explanation explanation(limits.max_explanation_terms);
  const std::size_t count = reader.list_count(8);
  for (std::size_t index = 0; index < count; ++index) {
    const std::string key = reader.string();
    const std::string value = reader.string();
    if (!reader.ok()) return explanation;
    explanation.add(key, value);
  }
  const bool truncated = reader.boolean();
  if (truncated) explanation.add("__truncated__", "true");
  return explanation;
}

}  // namespace

const char* to_string(RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::Unknown: return "UNKNOWN";
    case RecordKind::StreamHeader: return "STREAM_HEADER";
    case RecordKind::EpochAdvance: return "EPOCH_ADVANCE";
    case RecordKind::BootRegistered: return "BOOT_REGISTERED";
    case RecordKind::TopologyInstalled: return "TOPOLOGY_INSTALLED";
    case RecordKind::PolicyInstalled: return "POLICY_INSTALLED";
    case RecordKind::FailureCommitted: return "FAILURE_COMMITTED";
    case RecordKind::FenceCommitted: return "FENCE_COMMITTED";
    case RecordKind::GrantMinted: return "GRANT_MINTED";
    case RecordKind::GrantWithdrawn: return "GRANT_WITHDRAWN";
    case RecordKind::PlanCommitted: return "PLAN_COMMITTED";
    case RecordKind::ApplyCompleted: return "APPLY_COMPLETED";
    case RecordKind::RestoreDecided: return "RESTORE_DECIDED";
    case RecordKind::Checkpoint: return "CHECKPOINT";
    case RecordKind::ShutdownClean: return "SHUTDOWN_CLEAN";
  }
  return "UNRECOGNISED_RECORD_KIND";
}

bool is_valid_record_kind(std::uint16_t raw) noexcept {
  return raw >= static_cast<std::uint16_t>(RecordKind::StreamHeader) &&
         raw <= static_cast<std::uint16_t>(RecordKind::ShutdownClean);
}

const char* to_string(DecodeDisposition disposition) noexcept {
  switch (disposition) {
    case DecodeDisposition::Complete: return "COMPLETE";
    case DecodeDisposition::TornTail: return "TORN_TAIL";
    case DecodeDisposition::Corrupt: return "CORRUPT";
    case DecodeDisposition::Unsupported: return "UNSUPPORTED";
  }
  return "UNRECOGNISED_DECODE_DISPOSITION";
}

std::uint32_t RecordHeader::compute_crc() const noexcept {
  std::uint8_t buffer[24];
  write_u32_le(buffer + 0, magic);
  buffer[4] = static_cast<std::uint8_t>(format_version & 0xffu);
  buffer[5] = static_cast<std::uint8_t>((format_version >> 8) & 0xffu);
  buffer[6] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(kind) & 0xffu);
  buffer[7] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(kind) >> 8) & 0xffu);
  write_u32_le(buffer + 8, flags);
  write_u64_le(buffer + 12, seq);
  write_u32_le(buffer + 20, payload_len);
  return crc32_ieee(buffer, sizeof(buffer));
}

std::vector<std::uint8_t> RecordHeader::encode() const {
  std::vector<std::uint8_t> bytes(kRecordHeaderBytes, 0);
  write_u32_le(bytes.data() + 0, magic);
  bytes[4] = static_cast<std::uint8_t>(format_version & 0xffu);
  bytes[5] = static_cast<std::uint8_t>((format_version >> 8) & 0xffu);
  bytes[6] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(kind) & 0xffu);
  bytes[7] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(kind) >> 8) & 0xffu);
  write_u32_le(bytes.data() + 8, flags);
  write_u64_le(bytes.data() + 12, seq);
  write_u32_le(bytes.data() + 20, payload_len);
  write_u32_le(bytes.data() + 24, header_crc);
  return bytes;
}

Status RecordHeader::validate(const Limits& limits) const {
  if (magic != kRecordMagic) {
    return Status::failure(Code::Corrupt, "record magic does not match");
  }
  if (format_version != kRecordFormatVersion) {
    return Status::failure(Code::VersionMismatch, "record format version is not supported");
  }
  if (!is_valid_record_kind(static_cast<std::uint16_t>(kind))) {
    return Status::failure(Code::Unsupported, "record kind is not defined by this build");
  }
  const std::size_t ceiling = std::min(limits.max_document_bytes, kMaxRecordPayload);
  if (static_cast<std::size_t>(payload_len) > ceiling) {
    return Status::failure(Code::Corrupt, "record declares an impossible payload length");
  }
  if (compute_crc() != header_crc) {
    return Status::failure(Code::Corrupt, "record header integrity check failed");
  }
  return Status::success();
}

std::uint64_t Record::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.record.v1");
  digest.absorb_u64(header.seq);
  digest.absorb_byte(static_cast<std::uint8_t>(static_cast<std::uint16_t>(header.kind) & 0xffu));
  digest.absorb_byte(static_cast<std::uint8_t>((static_cast<std::uint16_t>(header.kind) >> 8) & 0xffu));
  digest.absorb_u64(header.flags);
  digest.absorb_u64(payload.size());
  digest.absorb_bytes(payload.data(), payload.size());
  return digest.hi;
}

DecodeResult decode_record(const std::uint8_t* data, std::size_t size, const Limits& limits) {
  DecodeResult result;
  if (data == nullptr && size != 0) {
    result.disposition = DecodeDisposition::Corrupt;
    result.status = Status::failure(Code::Corrupt, "record range is null");
    return result;
  }
  if (size == 0) {
    result.disposition = DecodeDisposition::TornTail;
    result.consumed = 0;
    result.status = Status::success();
    return result;
  }

  const std::size_t magic_prefix = std::min<std::size_t>(size, 4);
  for (std::size_t index = 0; index < magic_prefix; ++index) {
    if (data[index] != kMagicBytes[index]) {
      result.disposition = DecodeDisposition::Corrupt;
      result.status = Status::failure(Code::Corrupt, "record does not begin with the SFF1 magic");
      return result;
    }
  }
  if (size < kRecordHeaderBytes) {
    result.disposition = DecodeDisposition::TornTail;
    result.consumed = size;
    result.status = Status::success();
    return result;
  }

  RecordHeader header;
  header.magic = read_u32_le(data + 0);
  header.format_version = static_cast<std::uint16_t>(read_u32_le(data + 4) & 0xffffu);
  header.format_version = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(data[4]) | (static_cast<std::uint16_t>(data[5]) << 8));
  header.kind = static_cast<RecordKind>(static_cast<std::uint16_t>(data[6]) |
                                        (static_cast<std::uint16_t>(data[7]) << 8));
  header.flags = read_u32_le(data + 8);
  header.seq = read_u64_le(data + 12);
  header.payload_len = read_u32_le(data + 20);
  header.header_crc = read_u32_le(data + 24);

  Status header_status = header.validate(limits);
  if (!header_status.ok()) {
    result.status = header_status;
    result.disposition = header_status.code() == Code::VersionMismatch ||
                                 header_status.code() == Code::Unsupported
                             ? DecodeDisposition::Unsupported
                             : DecodeDisposition::Corrupt;
    return result;
  }

  const std::size_t total =
      kRecordHeaderBytes + static_cast<std::size_t>(header.payload_len) + 4;
  if (size < total) {
    // The header was complete and passed its integrity check, so the caller can trust
    // record.header - including payload_len - to know how many bytes a whole record needs.
    result.disposition = DecodeDisposition::TornTail;
    result.record.header = header;
    result.consumed = size;
    result.status = Status::success();
    return result;
  }

  const std::uint8_t* payload = data + kRecordHeaderBytes;
  const std::uint32_t stored_crc = read_u32_le(payload + header.payload_len);
  const std::uint32_t computed_crc = crc32_ieee(payload, header.payload_len);
  if (stored_crc != computed_crc) {
    result.disposition = DecodeDisposition::Corrupt;
    result.status = Status::failure(
        Code::Corrupt, "record payload integrity check failed; the record is refused, not truncated");
    return result;
  }

  result.disposition = DecodeDisposition::Complete;
  result.record.header = header;
  result.record.payload.assign(payload, payload + header.payload_len);
  result.consumed = total;
  result.status = Status::success();
  return result;
}

Result<std::vector<std::uint8_t>> encode_record(const Record& record, const Limits& limits) {
  const std::size_t ceiling = std::min(limits.max_document_bytes, kMaxRecordPayload);
  if (record.payload.size() > ceiling) {
    return refuse_exhausted("record payload", record.payload.size(), ceiling);
  }
  RecordHeader header = record.header;
  header.magic = kRecordMagic;
  header.format_version = kRecordFormatVersion;
  header.payload_len = static_cast<std::uint32_t>(record.payload.size());
  header.header_crc = header.compute_crc();
  Status status = header.validate(limits);
  if (!status.ok()) return status;

  std::vector<std::uint8_t> bytes = header.encode();
  bytes.insert(bytes.end(), record.payload.begin(), record.payload.end());
  const std::uint32_t payload_crc = crc32_ieee(record.payload);
  std::uint8_t crc_bytes[4];
  write_u32_le(crc_bytes, payload_crc);
  bytes.insert(bytes.end(), crc_bytes, crc_bytes + 4);
  return bytes;
}

// ---------------------------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------------------------

std::vector<std::uint8_t> encode_stream_header(std::uint16_t format_version, std::uint64_t boot_ordinal,
                                               std::uint64_t process_id, std::uint64_t epoch,
                                               std::uint64_t nonce_hi, std::uint64_t nonce_lo) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u16(format_version);
  writer.u64(boot_ordinal);
  writer.u64(process_id);
  writer.u64(epoch);
  writer.u64(nonce_hi);
  writer.u64(nonce_lo);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_u64_payload(std::uint64_t value) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u64(value);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_failure_record(const FailureRecord& record) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  write_key(writer, record.subject);
  writer.u64(record.evidence.raw());
  writer.u64(record.epoch.raw());
  write_boot(writer, record.boot);
  writer.u64(record.observed_at_ns);
  writer.u64(record.recorded_at_ns);
  writer.string(record.reason);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_fence_record(const FenceRecord& record) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u64(record.id.raw());
  write_key(writer, record.subject);
  writer.u64(record.epoch.raw());
  write_boot(writer, record.boot);
  writer.u64(record.created_at_ns);
  writer.u8(static_cast<std::uint8_t>(record.scope_state));
  writer.u64(record.closure_digest);
  writer.u64(record.closure_members);
  writer.u64(record.fenced_grants);
  writer.u64(record.omitted_dependents);
  writer.string(record.reason);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_grant_record(const AuthorityGrant& grant) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u64(grant.id.raw());
  write_dependent(writer, grant.dependent);
  writer.u32(static_cast<std::uint32_t>(grant.bound.size()));
  for (const auto& key : grant.bound.keys()) write_key(writer, key);
  writer.u64(grant.epoch.raw());
  write_boot(writer, grant.boot);
  writer.u64(grant.attempt.raw());
  writer.u64(grant.granted_at_ns);
  writer.u64(grant.expires_at_ns);
  writer.u8(static_cast<std::uint8_t>(grant.state));
  writer.u8(static_cast<std::uint8_t>(grant.cause));
  writer.string(grant.detail);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_withdraw_record(const WithdrawRecord& record) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u64(record.grant.raw());
  writer.u8(record.cause);
  writer.string(record.detail);
  return writer.bytes();
}

std::vector<std::uint8_t> encode_plan_record(const ReconstructionPlan& plan) {
  return plan.encode();
}

std::vector<std::uint8_t> encode_apply_receipt(const ApplyReceipt& receipt) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  writer.u64(receipt.plan.raw());
  writer.u64(receipt.epoch.raw());
  write_boot(writer, receipt.boot);
  writer.u32(static_cast<std::uint32_t>(receipt.steps.size()));
  for (const auto& step : receipt.steps) {
    write_dependent(writer, step.dependent);
    write_key(writer, step.replacement);
    writer.u8(static_cast<std::uint8_t>(step.state));
    writer.u64(step.attempt.raw());
    writer.u64(step.verification.raw());
    writer.string(step.detail);
  }
  writer.u64(receipt.applied);
  writer.u64(receipt.verified);
  writer.u64(receipt.failed);
  writer.u64(receipt.unverified);
  writer.boolean(receipt.complete);
  writer.u16(static_cast<std::uint16_t>(receipt.outcome));
  return writer.bytes();
}

std::vector<std::uint8_t> encode_restore_decision(const RestoreDecision& decision) {
  ByteWriter writer;
  writer.u8(kPayloadFormatTag);
  write_dependent(writer, decision.dependent);
  writer.u16(static_cast<std::uint16_t>(decision.outcome));
  writer.u16(static_cast<std::uint16_t>(decision.reason));
  writer.boolean(decision.may_restore);
  writer.boolean(decision.effect_verified);
  writer.u32(static_cast<std::uint32_t>(decision.bound.size()));
  for (const auto& key : decision.bound.keys()) write_key(writer, key);
  writer.u64(decision.plan.raw());
  writer.u32(static_cast<std::uint32_t>(decision.grants.size()));
  for (const auto& id : decision.grants) writer.u64(id.raw());
  writer.u32(static_cast<std::uint32_t>(decision.blocking_generations.size()));
  for (const auto& key : decision.blocking_generations) write_key(writer, key);
  write_explanation(writer, decision.explanation);
  return writer.bytes();
}

Result<std::uint64_t> decode_u64_payload(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  const std::uint64_t value = reader.u64();
  Status end = reader.require_end();
  if (!end.ok()) return end;
  return value;
}

Result<FailureRecord> decode_failure_record(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  FailureRecord record;
  record.subject = read_key(reader);
  record.evidence = EvidenceId(reader.u64());
  record.epoch = CoordinatorEpoch(reader.u64());
  record.boot = read_boot(reader);
  record.observed_at_ns = reader.u64();
  record.recorded_at_ns = reader.u64();
  record.reason = reader.string();
  Status end = reader.require_end();
  if (!end.ok()) return end;
  if (!record.subject.valid() || record.observed_at_ns == 0) {
    return Status::failure(Code::Invalid, "durable failure record is not a valid lineage entry");
  }
  return record;
}

Result<FenceRecord> decode_fence_record(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  FenceRecord record;
  record.id = FenceId(reader.u64());
  record.subject = read_key(reader);
  record.epoch = CoordinatorEpoch(reader.u64());
  record.boot = read_boot(reader);
  record.created_at_ns = reader.u64();
  const std::uint8_t scope = reader.u8();
  record.closure_digest = reader.u64();
  record.closure_members = reader.u64();
  record.fenced_grants = reader.u64();
  record.omitted_dependents = reader.u64();
  record.reason = reader.string();
  if (!reader.ok()) return reader.status();
  if (scope > static_cast<std::uint8_t>(FenceScopeState::Committed)) {
    return Status::failure(Code::Invalid, "durable fence record has an undefined scope state");
  }
  record.scope_state = static_cast<FenceScopeState>(scope);
  Status end = reader.require_end();
  if (!end.ok()) return end;
  if (!record.subject.valid()) {
    return Status::failure(Code::Invalid, "durable fence record is not generation-qualified");
  }
  return record;
}

Result<AuthorityGrant> decode_grant_record(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(1u << 20);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  AuthorityGrant grant;
  grant.id = GrantId(reader.u64());
  grant.dependent = read_dependent(reader);
  const std::size_t count = reader.list_count(16);
  std::vector<SwitchKey> keys;
  keys.reserve(count);
  for (std::size_t index = 0; index < count; ++index) keys.push_back(read_key(reader));
  grant.bound = GenerationVector::canonicalise(std::move(keys));
  grant.epoch = CoordinatorEpoch(reader.u64());
  grant.boot = read_boot(reader);
  grant.attempt = AttemptSeq(reader.u64());
  grant.granted_at_ns = reader.u64();
  grant.expires_at_ns = reader.u64();
  const std::uint8_t state = reader.u8();
  const std::uint8_t cause = reader.u8();
  grant.detail = reader.string();
  if (!reader.ok()) return reader.status();
  if (state > static_cast<std::uint8_t>(GrantState::Fenced)) {
    return Status::failure(Code::Invalid, "durable grant record has an undefined state");
  }
  if (cause > static_cast<std::uint8_t>(RevocationCause::Shutdown)) {
    return Status::failure(Code::Invalid, "durable grant record has an undefined cause");
  }
  grant.state = static_cast<GrantState>(state);
  grant.cause = static_cast<RevocationCause>(cause);
  Status end = reader.require_end();
  if (!end.ok()) return end;
  if (!grant.id.valid() || !grant.dependent.valid()) {
    return Status::failure(Code::Invalid, "durable grant record is malformed");
  }
  return grant;
}

Result<WithdrawRecord> decode_withdraw_record(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  WithdrawRecord record;
  record.grant = GrantId(reader.u64());
  record.cause = reader.u8();
  record.detail = reader.string();
  if (!reader.ok()) return reader.status();
  if (record.cause > static_cast<std::uint8_t>(RevocationCause::Shutdown)) {
    return Status::failure(Code::Invalid, "withdraw record has an undefined cause");
  }
  Status end = reader.require_end();
  if (!end.ok()) return end;
  if (!record.grant.valid()) {
    return Status::failure(Code::Invalid, "withdraw record names no grant");
  }
  return record;
}

Result<ReconstructionPlan> decode_plan_record(const std::vector<std::uint8_t>& payload,
                                              const Limits& limits) {
  return ReconstructionPlan::decode(payload, limits);
}

Result<ApplyReceipt> decode_apply_receipt(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(1u << 20);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  ApplyReceipt receipt;
  receipt.plan = PlanId(reader.u64());
  receipt.epoch = CoordinatorEpoch(reader.u64());
  receipt.boot = read_boot(reader);
  const std::size_t count = reader.list_count(32);
  receipt.steps.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    ApplyStepResult step;
    step.dependent = read_dependent(reader);
    step.replacement = read_key(reader);
    const std::uint8_t state = reader.u8();
    step.attempt = AttemptSeq(reader.u64());
    step.verification = EvidenceId(reader.u64());
    step.detail = reader.string();
    if (!reader.ok()) return reader.status();
    if (state > static_cast<std::uint8_t>(AckState::Unverified)) {
      return Status::failure(Code::Invalid, "apply receipt step has an undefined state");
    }
    step.state = static_cast<AckState>(state);
    receipt.steps.push_back(std::move(step));
  }
  receipt.applied = static_cast<std::size_t>(reader.u64());
  receipt.verified = static_cast<std::size_t>(reader.u64());
  receipt.failed = static_cast<std::size_t>(reader.u64());
  receipt.unverified = static_cast<std::size_t>(reader.u64());
  receipt.complete = reader.boolean();
  receipt.outcome = static_cast<Code>(reader.u16());
  Status end = reader.require_end();
  if (!end.ok()) return end;
  if (receipt.applied + receipt.verified + receipt.failed + receipt.unverified > receipt.steps.size() * 2) {
    return Status::failure(Code::Invalid, "apply receipt counters are inconsistent");
  }
  return receipt;
}

Result<RestoreDecision> decode_restore_decision(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(1u << 20);
  const Limits limits = Limits::defaults();
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPayloadFormatTag) {
    return Status::failure(Code::VersionMismatch, "payload format tag is unsupported");
  }
  RestoreDecision decision;
  decision.dependent = read_dependent(reader);
  decision.outcome = static_cast<Code>(reader.u16());
  decision.reason = static_cast<Code>(reader.u16());
  decision.may_restore = reader.boolean();
  decision.effect_verified = reader.boolean();
  const std::size_t bound_count = reader.list_count(16);
  std::vector<SwitchKey> keys;
  keys.reserve(bound_count);
  for (std::size_t index = 0; index < bound_count; ++index) keys.push_back(read_key(reader));
  decision.bound = GenerationVector::canonicalise(std::move(keys));
  decision.plan = PlanId(reader.u64());
  const std::size_t grant_count = reader.list_count(8);
  decision.grants.reserve(grant_count);
  for (std::size_t index = 0; index < grant_count; ++index) {
    decision.grants.push_back(GrantId(reader.u64()));
  }
  const std::size_t blocking_count = reader.list_count(16);
  decision.blocking_generations.reserve(blocking_count);
  for (std::size_t index = 0; index < blocking_count; ++index) {
    decision.blocking_generations.push_back(read_key(reader));
  }
  decision.explanation = read_explanation(reader, limits);
  if (!reader.ok()) return reader.status();
  Status end = reader.require_end();
  if (!end.ok()) return end;
  return decision;
}

}  // namespace sff
