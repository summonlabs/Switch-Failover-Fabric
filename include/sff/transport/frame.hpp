// Switch Failover Fabric - bounded framed protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_TRANSPORT_FRAME_HPP
#define SFF_TRANSPORT_FRAME_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/evidence.hpp"
#include "sff/runtime/session.hpp"
#include "sff/export.hpp"

namespace sff {

/// On-wire frame magic: the four bytes 'S','F','F','1'. Read as a little-endian u32 that is
/// 0x31464653. The magic is written as four explicit bytes, never as a native integer.
inline constexpr std::uint32_t kFrameMagic = 0x31464653u;

/// Frame format version, negotiated at handshake time. A mismatch is refused, not coerced.
inline constexpr std::uint16_t kFrameFormatVersion = 1;

/// Fixed header size:
/// magic(4) format(2) type(2) flags(4) session(8) epoch(8) boot_digest(8) request_seq(8)
/// payload_len(4) header_crc(4) = 52 bytes. The header CRC covers the first 48 bytes.
inline constexpr std::size_t kFrameHeaderBytes = 52;

/// Trailing payload CRC.
inline constexpr std::size_t kFrameTrailerBytes = 4;

/// Message types. Unknown or unassigned values are refused during decoding.
enum class MessageType : std::uint16_t {
  Unknown = 0,
  Hello = 1,
  HelloAck = 2,
  QueryAuthority = 3,
  AuthorityResult = 4,
  DeclareFailure = 5,
  FailoverResult = 6,
  ProposePlan = 7,
  PlanResult = 8,
  ApplyPlan = 9,
  ApplyResult = 10,
  QueryRestore = 11,
  RestoreResult = 12,
  SnapshotRequest = 13,
  SnapshotResult = 14,
  Error = 15,
  Goodbye = 16,
};

SFF_API const char* to_string(MessageType type) noexcept;
SFF_API bool is_valid_message_type(std::uint16_t raw) noexcept;

struct SFF_API FrameHeader {
  std::uint32_t magic = kFrameMagic;
  std::uint16_t format_version = kFrameFormatVersion;
  MessageType type = MessageType::Unknown;
  std::uint32_t flags = 0;
  SessionId session;
  CoordinatorEpoch epoch;
  std::uint64_t boot_digest = 0;
  std::uint64_t request_seq = 0;
  std::uint32_t payload_len = 0;
  std::uint32_t header_crc = 0;

  std::vector<std::uint8_t> encode() const;
  std::uint32_t compute_crc() const noexcept;
  Status validate(const Limits& limits) const;

  /// The authority binding this frame carries.
  SessionBinding binding() const noexcept;
};

struct SFF_API Frame {
  FrameHeader header;
  std::vector<std::uint8_t> payload;
  std::uint32_t payload_crc = 0;

  std::uint64_t digest() const noexcept;
};

/// Every way a byte range can be interpreted at the framing layer.
enum class FrameDisposition : std::uint8_t {
  Complete = 0,
  Incomplete = 1,  ///< A genuine prefix; more bytes may complete it.
  Corrupt = 2,     ///< Integrity failure on complete-looking input. Sticky.
  Unsupported = 3, ///< Version or type this build does not implement. Sticky.
};

SFF_API const char* to_string(FrameDisposition disposition) noexcept;

struct SFF_API FrameDecodeResult {
  FrameDisposition disposition = FrameDisposition::Incomplete;
  Frame frame;
  std::size_t consumed = 0;
  Status status;
};

/// Encode a frame. Refuses oversized payloads before allocating.
SFF_API Result<std::vector<std::uint8_t>> encode_frame(const Frame& frame, const Limits& limits);

/// Total decoder for a single frame at the head of a byte range.
SFF_API FrameDecodeResult decode_frame(const std::uint8_t* data, std::size_t size,
                                       const Limits& limits);

/// Incremental stream decoder with a bounded buffer and sticky failure.
///
/// Once the decoder reports Corrupt or Unsupported it refuses every further frame: a stream that
/// has desynchronised is never silently resynchronised.
class SFF_API FrameStreamDecoder {
 public:
  explicit FrameStreamDecoder(Limits limits = Limits::defaults());

  Status feed(const std::uint8_t* data, std::size_t size);
  FrameDecodeResult next();

  Status status() const;
  std::size_t buffered() const;
  bool failed() const;
  void reset();

 private:
  Limits limits_;
  std::vector<std::uint8_t> buffer_;
  Status status_;
  bool sticky_ = false;
};

// --- canonical payload codecs -------------------------------------------------------------

struct SFF_API HelloRequest {
  std::string principal;
  std::uint16_t format_version = kFrameFormatVersion;
};

struct SFF_API HelloResponse {
  SessionId session;
  CoordinatorEpoch epoch;
  std::uint64_t boot_digest = 0;
  std::uint32_t format_version = kFrameFormatVersion;
  std::uint32_t max_payload = 0;
  Code outcome = Code::Unknown;
};

struct SFF_API AuthorityQueryRequest {
  DependentRef dependent;
};

struct SFF_API AuthorityQueryResponse {
  Code outcome = Code::Unknown;
  Code reason = Code::Unknown;
  bool has_authority = false;
  std::size_t active_grants = 0;
  std::size_t withdrawn_grants = 0;
  std::size_t fenced_generations = 0;
  std::uint64_t digest = 0;
};

struct SFF_API FailoverRequest {
  SwitchKey subject;
  EvidenceSource source = EvidenceSource::Unknown;
  std::uint64_t observed_at_ns = 0;
  std::uint64_t valid_for_ns = 0;
  std::string reason;
};

struct SFF_API FailoverResponse {
  Code outcome = Code::Unknown;
  std::uint64_t fence_id = 0;
  std::uint32_t fence_scope = 0;
  bool closure_complete = false;
  std::size_t closure_members = 0;
  std::size_t grants_fenced = 0;
  std::uint64_t closure_digest = 0;
};

struct SFF_API RestoreQueryRequest {
  DependentRef dependent;
};

struct SFF_API RestoreQueryResponse {
  Code outcome = Code::Unknown;
  Code reason = Code::Unknown;
  bool may_restore = false;
  bool effect_verified = false;
  std::size_t blocking_generations = 0;
};

struct SFF_API SnapshotResponse {
  Code outcome = Code::Unknown;
  std::uint64_t epoch = 0;
  std::uint64_t boot_ordinal = 0;
  std::size_t switches = 0;
  std::size_t fences = 0;
  std::size_t failures = 0;
  std::size_t active_grants = 0;
  std::size_t retained_events = 0;
  bool durability_enabled = false;
};

SFF_API std::vector<std::uint8_t> encode_hello_request(const HelloRequest& request);
SFF_API Result<HelloRequest> decode_hello_request(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_hello_response(const HelloResponse& response);
SFF_API Result<HelloResponse> decode_hello_response(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_authority_query(const AuthorityQueryRequest& request);
SFF_API Result<AuthorityQueryRequest> decode_authority_query(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_authority_response(const AuthorityQueryResponse& response);
SFF_API Result<AuthorityQueryResponse> decode_authority_response(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_failover_request(const FailoverRequest& request);
SFF_API Result<FailoverRequest> decode_failover_request(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_failover_response(const FailoverResponse& response);
SFF_API Result<FailoverResponse> decode_failover_response(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_restore_query(const RestoreQueryRequest& request);
SFF_API Result<RestoreQueryRequest> decode_restore_query(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_restore_response(const RestoreQueryResponse& response);
SFF_API Result<RestoreQueryResponse> decode_restore_response(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_snapshot_response(const SnapshotResponse& response);
SFF_API Result<SnapshotResponse> decode_snapshot_response(const std::vector<std::uint8_t>& payload);
SFF_API std::vector<std::uint8_t> encode_error_payload(Code code, std::string_view detail);
SFF_API Result<std::pair<Code, std::string>> decode_error_payload(const std::vector<std::uint8_t>& payload);

}  // namespace sff

#endif  // SFF_TRANSPORT_FRAME_HPP
