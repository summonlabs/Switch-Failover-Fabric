// Switch Failover Fabric - versioned, integrity-checked durable records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PERSIST_RECORDS_HPP
#define SFF_PERSIST_RECORDS_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Little-endian magic for a durable record header: ASCII "SFF1" read as a u32.
inline constexpr std::uint32_t kRecordMagic = 0x31464653u;

/// Durable format version. Bumped whenever the encoding of any record kind changes.
inline constexpr std::uint16_t kRecordFormatVersion = 1;

/// Fixed on-disk header size: magic(4) + format(2) + kind(2) + flags(4) + seq(8) + len(4) + crc(4).
inline constexpr std::size_t kRecordHeaderBytes = 28;

/// Maximum payload for a single durable record.
inline constexpr std::size_t kMaxRecordPayload = std::size_t{16} << 20;

/// Record kinds. The numbering is durable and never reused.
enum class RecordKind : std::uint16_t {
  Unknown = 0,
  StreamHeader = 1,     ///< Exactly one per journal, first in file: version, boot, epoch.
  EpochAdvance = 2,
  BootRegistered = 3,
  TopologyInstalled = 4,
  PolicyInstalled = 5,
  FailureCommitted = 6,
  FenceCommitted = 7,
  GrantMinted = 8,
  GrantWithdrawn = 9,
  PlanCommitted = 10,
  ApplyCompleted = 11,
  RestoreDecided = 12,
  Checkpoint = 13,
  ShutdownClean = 14,
};

SFF_API const char* to_string(RecordKind kind) noexcept;
SFF_API bool is_valid_record_kind(std::uint16_t raw) noexcept;

/// Decoded record header.
struct SFF_API RecordHeader {
  std::uint32_t magic = kRecordMagic;
  std::uint16_t format_version = kRecordFormatVersion;
  RecordKind kind = RecordKind::Unknown;
  std::uint32_t flags = 0;
  std::uint64_t seq = 0;
  std::uint32_t payload_len = 0;
  std::uint32_t header_crc = 0;

  /// Canonical 28-byte encoding. The stored header CRC covers the first 24 bytes.
  std::vector<std::uint8_t> encode() const;
  std::uint32_t compute_crc() const noexcept;
  Status validate(const Limits& limits) const;
};

/// A complete durable record.
struct SFF_API Record {
  RecordHeader header;
  std::vector<std::uint8_t> payload;

  std::uint64_t digest() const noexcept;
};

/// Every way a byte range can be interpreted.
enum class DecodeDisposition : std::uint8_t {
  Complete = 0,     ///< A whole, integrity-checked record was decoded.
  TornTail = 1,     ///< A genuine prefix of a record at end of file. Safely recoverable.
  Corrupt = 2,      ///< Integrity failure on a complete-looking record. Never silently truncated.
  Unsupported = 3,  ///< Well-formed but a version or kind this build does not understand.
};

SFF_API const char* to_string(DecodeDisposition disposition) noexcept;

/// Decode result. The consumed field is meaningful for Complete and for the recognised prefix
/// of a TornTail; it is zero for Corrupt and Unsupported.
struct SFF_API DecodeResult {
  DecodeDisposition disposition = DecodeDisposition::Corrupt;
  Record record;
  std::size_t consumed = 0;
  Status status;

  bool complete() const noexcept { return disposition == DecodeDisposition::Complete; }
};

/// Total decoder. Never reads past the supplied range, never allocates before the declared
/// length has been proven both in range and within the configured ceiling.
SFF_API DecodeResult decode_record(const std::uint8_t* data, std::size_t size,
                                   const Limits& limits);

/// Encode a record with a correct header CRC and a validated payload length.
SFF_API Result<std::vector<std::uint8_t>> encode_record(const Record& record, const Limits& limits);

// --- canonical payload codecs -------------------------------------------------------------

SFF_API std::vector<std::uint8_t> encode_stream_header(std::uint16_t format_version,
                                                       std::uint64_t boot_ordinal,
                                                       std::uint64_t process_id,
                                                       std::uint64_t epoch,
                                                       std::uint64_t nonce_hi,
                                                       std::uint64_t nonce_lo);

SFF_API std::vector<std::uint8_t> encode_u64_payload(std::uint64_t value);

SFF_API std::vector<std::uint8_t> encode_failure_record(const struct FailureRecord& record);
SFF_API std::vector<std::uint8_t> encode_fence_record(const struct FenceRecord& record);
SFF_API std::vector<std::uint8_t> encode_grant_record(const struct AuthorityGrant& grant);
/// Payload of a GrantWithdrawn record.
struct SFF_API WithdrawRecord {
  GrantId grant;
  std::uint8_t cause = 0;  ///< Ordinal of RevocationCause; validated on decode.
  std::string detail;
};

SFF_API std::vector<std::uint8_t> encode_withdraw_record(const WithdrawRecord& record);
SFF_API std::vector<std::uint8_t> encode_plan_record(const class ReconstructionPlan& plan);
SFF_API std::vector<std::uint8_t> encode_apply_receipt(const struct ApplyReceipt& receipt);
SFF_API std::vector<std::uint8_t> encode_restore_decision(const struct RestoreDecision& decision);

SFF_API Result<std::uint64_t> decode_u64_payload(const std::vector<std::uint8_t>& payload);
SFF_API Result<FailureRecord> decode_failure_record(const std::vector<std::uint8_t>& payload);
SFF_API Result<FenceRecord> decode_fence_record(const std::vector<std::uint8_t>& payload);
SFF_API Result<AuthorityGrant> decode_grant_record(const std::vector<std::uint8_t>& payload);
SFF_API Result<ReconstructionPlan> decode_plan_record(const std::vector<std::uint8_t>& payload,
                                                      const Limits& limits);
SFF_API Result<ApplyReceipt> decode_apply_receipt(const std::vector<std::uint8_t>& payload);
SFF_API Result<RestoreDecision> decode_restore_decision(const std::vector<std::uint8_t>& payload);
SFF_API Result<WithdrawRecord> decode_withdraw_record(const std::vector<std::uint8_t>& payload);

}  // namespace sff

#endif  // SFF_PERSIST_RECORDS_HPP
