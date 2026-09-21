// Switch Failover Fabric - bounded framed protocol codec.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Wire format (all integers little-endian):
//
//   header : magic(4)='S','F','F','1'  format(2)  type(2)  flags(4)  session(8)  epoch(8)
//            boot_digest(8)  request_seq(8)  payload_len(4)  header_crc(4)          = 52 bytes
//   payload: payload_len bytes
//   trailer: payload_crc(4) = crc32_ieee(payload)                                   = 4 bytes
//
// header_crc covers the first 48 header bytes. The decoder is total: it never reads past the
// supplied range and never allocates from payload_len before that length has been proven to be
// within the configured bound *and* the whole frame has been proven present.

// NOTE: sff/transport/frame.hpp declares FrameHeader::binding() returning SessionBinding without
// including sff/runtime/session.hpp, so the declaring header must precede it. The public header is
// frozen; this ordering is the workaround, and the defect is reported rather than patched.
#include "sff/runtime/session.hpp"

#include "sff/transport/frame.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sff/codec/bytes.hpp"
#include "sff/codec/integrity.hpp"
#include "sff/core/checked.hpp"
#include "sff/model/evidence.hpp"

namespace sff {
namespace {

/// Number of header bytes covered by header_crc.
constexpr std::size_t kHeaderCrcOffset = kFrameHeaderBytes - kFrameTrailerBytes;

/// Payload ceiling actually enforced: the caller's bound, clamped by the hard ceiling.
std::size_t payload_ceiling(const Limits& limits) noexcept {
  return std::min<std::size_t>(limits.max_frame_payload, kHardMaxFramePayload);
}

void store_le16(std::uint8_t* out, std::uint16_t value) noexcept {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void store_le32(std::uint8_t* out, std::uint32_t value) noexcept {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  out[3] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
}

void store_le64(std::uint8_t* out, std::uint64_t value) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu);
  }
}

std::uint16_t load_le16(const std::uint8_t* in) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint32_t>(in[0]) |
                                    (static_cast<std::uint32_t>(in[1]) << 8u));
}

std::uint32_t load_le32(const std::uint8_t* in) noexcept {
  return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8u) |
         (static_cast<std::uint32_t>(in[2]) << 16u) | (static_cast<std::uint32_t>(in[3]) << 24u);
}

std::uint64_t load_le64(const std::uint8_t* in) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(in[i]) << (8u * i);
  }
  return value;
}

/// The 48 canonical header bytes covered by header_crc. The magic is written as four explicit
/// bytes so that the encoding never depends on host byte order.
void write_header_prefix(std::uint8_t* out, const FrameHeader& header) noexcept {
  out[0] = static_cast<std::uint8_t>('S');
  out[1] = static_cast<std::uint8_t>('F');
  out[2] = static_cast<std::uint8_t>('F');
  out[3] = static_cast<std::uint8_t>('1');
  store_le16(out + 4, header.format_version);
  store_le16(out + 6, static_cast<std::uint16_t>(header.type));
  store_le32(out + 8, header.flags);
  store_le64(out + 12, header.session.raw());
  store_le64(out + 20, header.epoch.raw());
  store_le64(out + 28, header.boot_digest);
  store_le64(out + 36, header.request_seq);
  store_le32(out + 44, header.payload_len);
}

void append_header(std::vector<std::uint8_t>& out, const FrameHeader& header) {
  std::uint8_t buffer[kFrameHeaderBytes] = {};
  write_header_prefix(buffer, header);
  const std::uint32_t crc = crc32_ieee(buffer, kHeaderCrcOffset);
  store_le32(buffer + kHeaderCrcOffset, crc);
  out.insert(out.end(), buffer, buffer + kFrameHeaderBytes);
}

FrameDecodeResult make_failure(FrameDisposition disposition, Code code,
                               std::string_view message) {
  FrameDecodeResult result;
  result.disposition = disposition;
  result.status = Status::failure(code, message);
  result.consumed = 0;
  return result;
}

FrameDecodeResult incomplete() {
  return make_failure(FrameDisposition::Incomplete, Code::Truncated, "incomplete frame");
}

/// The largest enumerator of Code; anything above it is not a code this build assigns.
// Highest Code ordinal this build defines. A code above it is refused as unassigned, so a newer
// peer's code can never be silently reinterpreted as an older one.
constexpr std::uint16_t kLastCode = static_cast<std::uint16_t>(Code::Expired);

bool is_known_code(std::uint16_t raw) noexcept { return raw <= kLastCode; }

Result<Code> read_code(ByteReader& reader) {
  const std::uint16_t raw = reader.u16();
  if (const Status status = reader.status(); !status.ok()) return Result<Code>(status);
  if (!is_known_code(raw)) {
    return Result<Code>(Status::failure(Code::Invalid, "payload carries an unassigned outcome code"));
  }
  return Result<Code>(static_cast<Code>(raw));
}

/// Finish a payload decode: propagate the reader's sticky failure, then reject trailing bytes.
Status finish_payload(ByteReader& reader) {
  if (const Status status = reader.status(); !status.ok()) return status;
  return reader.require_end();
}

Result<std::size_t> read_size(ByteReader& reader) {
  const std::uint64_t raw = reader.u64();
  if (const Status status = reader.status(); !status.ok()) return Result<std::size_t>(status);
  const auto narrowed = narrow_size(raw);
  if (!narrowed) {
    return Result<std::size_t>(
        Status::failure(Code::Invalid, "payload carries a count that is not representable"));
  }
  return Result<std::size_t>(*narrowed);
}

// Per-payload writer budgets. Every payload is small and fixed-shape except for the optional
// bounded text fields.
constexpr std::size_t kTextBudget = kMaxMessageBytes + 64;
constexpr std::size_t kFixedPayloadBudget = 256;

Result<DependentRef> read_dependent(ByteReader& reader) {
  const std::uint8_t kind = reader.u8();
  const std::uint64_t id = reader.u64();
  if (const Status status = reader.status(); !status.ok()) return Result<DependentRef>(status);
  if (!is_valid_dependent_kind(kind)) {
    return Result<DependentRef>(
        Status::failure(Code::Invalid, "payload carries an unassigned dependent kind"));
  }
  const DependentRef dependent(static_cast<DependentKind>(kind), id);
  if (!dependent.valid()) {
    return Result<DependentRef>(Status::failure(Code::Invalid, "payload carries a zero dependent id"));
  }
  return Result<DependentRef>(dependent);
}

void write_dependent(ByteWriter& writer, const DependentRef& dependent) {
  writer.u8(static_cast<std::uint8_t>(dependent.kind()));
  writer.u64(dependent.id());
}

}  // namespace

// --- message types ------------------------------------------------------------------------

const char* to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Unknown:
      return "Unknown";
    case MessageType::Hello:
      return "Hello";
    case MessageType::HelloAck:
      return "HelloAck";
    case MessageType::QueryAuthority:
      return "QueryAuthority";
    case MessageType::AuthorityResult:
      return "AuthorityResult";
    case MessageType::DeclareFailure:
      return "DeclareFailure";
    case MessageType::FailoverResult:
      return "FailoverResult";
    case MessageType::ProposePlan:
      return "ProposePlan";
    case MessageType::PlanResult:
      return "PlanResult";
    case MessageType::ApplyPlan:
      return "ApplyPlan";
    case MessageType::ApplyResult:
      return "ApplyResult";
    case MessageType::QueryRestore:
      return "QueryRestore";
    case MessageType::RestoreResult:
      return "RestoreResult";
    case MessageType::SnapshotRequest:
      return "SnapshotRequest";
    case MessageType::SnapshotResult:
      return "SnapshotResult";
    case MessageType::Error:
      return "Error";
    case MessageType::Goodbye:
      return "Goodbye";
  }
  return "Unassigned";
}

bool is_valid_message_type(std::uint16_t raw) noexcept {
  return raw >= static_cast<std::uint16_t>(MessageType::Hello) &&
         raw <= static_cast<std::uint16_t>(MessageType::Goodbye);
}

const char* to_string(FrameDisposition disposition) noexcept {
  switch (disposition) {
    case FrameDisposition::Complete:
      return "Complete";
    case FrameDisposition::Incomplete:
      return "Incomplete";
    case FrameDisposition::Corrupt:
      return "Corrupt";
    case FrameDisposition::Unsupported:
      return "Unsupported";
  }
  return "Unknown";
}

// --- header -------------------------------------------------------------------------------

std::vector<std::uint8_t> FrameHeader::encode() const {
  std::vector<std::uint8_t> out;
  out.reserve(kFrameHeaderBytes);
  append_header(out, *this);
  return out;
}

std::uint32_t FrameHeader::compute_crc() const noexcept {
  std::uint8_t buffer[kHeaderCrcOffset] = {};
  write_header_prefix(buffer, *this);
  return crc32_ieee(buffer, kHeaderCrcOffset);
}

Status FrameHeader::validate(const Limits& limits) const {
  if (magic != kFrameMagic) {
    return Status::failure(Code::Corrupt, "frame magic mismatch");
  }
  if (format_version != kFrameFormatVersion) {
    return Status::failure(Code::VersionMismatch, "unsupported frame format version");
  }
  if (!is_valid_message_type(static_cast<std::uint16_t>(type))) {
    return Status::failure(Code::Unsupported, "unassigned message type");
  }
  if (payload_len > payload_ceiling(limits)) {
    return Status::failure(Code::Corrupt, "frame payload length exceeds the configured bound");
  }
  return Status::success();
}

SessionBinding FrameHeader::binding() const noexcept {
  SessionBinding binding;
  binding.session = session;
  binding.epoch = epoch;
  binding.boot_digest = boot_digest;
  binding.request_seq = request_seq;
  return binding;
}

std::uint64_t Frame::digest() const noexcept {
  // The digest is a function of the frame's logical content only. payload_len is derived from the
  // payload rather than carried independently, so a frame and its decoded form always agree.
  FrameHeader canonical = header;
  canonical.magic = kFrameMagic;
  canonical.payload_len = static_cast<std::uint32_t>(payload.size());
  std::uint8_t prefix[kHeaderCrcOffset] = {};
  write_header_prefix(prefix, canonical);
  Digest128 accumulator;
  accumulator.absorb_bytes(prefix, sizeof(prefix));
  if (!payload.empty()) {
    accumulator.absorb_bytes(payload.data(), payload.size());
  }
  return mix64(accumulator.hi ^ accumulator.lo);
}

// --- framing ------------------------------------------------------------------------------

Result<std::vector<std::uint8_t>> encode_frame(const Frame& frame, const Limits& limits) {
  const std::size_t ceiling = payload_ceiling(limits);
  if (frame.payload.size() > ceiling) {
    return Result<std::vector<std::uint8_t>>(
        refuse_exhausted("frame payload", frame.payload.size(), ceiling));
  }

  FrameHeader header = frame.header;
  header.magic = kFrameMagic;
  header.payload_len = static_cast<std::uint32_t>(frame.payload.size());

  std::vector<std::uint8_t> out;
  try {
    out.reserve(kFrameHeaderBytes + frame.payload.size() + kFrameTrailerBytes);
    append_header(out, header);
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    std::uint8_t trailer[kFrameTrailerBytes] = {};
    store_le32(trailer, crc32_ieee(frame.payload.empty() ? nullptr : frame.payload.data(),
                                   frame.payload.size()));
    out.insert(out.end(), trailer, trailer + kFrameTrailerBytes);
  } catch (const std::bad_alloc&) {
    return Result<std::vector<std::uint8_t>>(
        Status::failure(Code::Exhausted, "frame encoding allocation failed"));
  }
  return Result<std::vector<std::uint8_t>>(std::move(out));
}

FrameDecodeResult decode_frame(const std::uint8_t* data, std::size_t size, const Limits& limits) {
  if (data == nullptr) {
    if (size != 0) {
      return make_failure(FrameDisposition::Corrupt, Code::Invalid, "null frame buffer");
    }
    return incomplete();
  }
  if (size < 4) {
    return incomplete();
  }
  if (load_le32(data) != kFrameMagic) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt, "frame magic mismatch");
  }
  if (size < kFrameHeaderBytes) {
    return incomplete();
  }

  FrameHeader header;
  header.magic = kFrameMagic;
  header.format_version = load_le16(data + 4);
  const std::uint16_t raw_type = load_le16(data + 6);
  header.type = static_cast<MessageType>(raw_type);
  header.flags = load_le32(data + 8);
  header.session = SessionId(load_le64(data + 12));
  header.epoch = CoordinatorEpoch(load_le64(data + 20));
  header.boot_digest = load_le64(data + 28);
  header.request_seq = load_le64(data + 36);
  header.payload_len = load_le32(data + 44);
  header.header_crc = load_le32(data + 48);

  if (header.header_crc != crc32_ieee(data, kHeaderCrcOffset)) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt, "frame header CRC mismatch");
  }
  if (header.format_version != kFrameFormatVersion) {
    return make_failure(FrameDisposition::Unsupported, Code::VersionMismatch,
                        "unsupported frame format version");
  }
  if (!is_valid_message_type(raw_type)) {
    return make_failure(FrameDisposition::Unsupported, Code::Unsupported, "unassigned message type");
  }

  const std::size_t ceiling = payload_ceiling(limits);
  if (static_cast<std::size_t>(header.payload_len) > ceiling) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt,
                        "frame payload length exceeds the configured bound");
  }

  const auto body = checked_add(kFrameHeaderBytes, static_cast<std::size_t>(header.payload_len));
  if (!body) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt, "frame length overflow");
  }
  const auto total = checked_add(*body, kFrameTrailerBytes);
  if (!total) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt, "frame length overflow");
  }
  if (size < *total) {
    return incomplete();
  }

  const std::uint8_t* payload = data + kFrameHeaderBytes;
  const std::uint32_t payload_crc = load_le32(payload + header.payload_len);
  if (payload_crc != crc32_ieee(payload, header.payload_len)) {
    return make_failure(FrameDisposition::Corrupt, Code::Corrupt, "frame payload CRC mismatch");
  }

  FrameDecodeResult result;
  result.disposition = FrameDisposition::Complete;
  result.status = Status::success();
  result.consumed = *total;
  result.frame.header = header;
  result.frame.payload_crc = payload_crc;
  try {
    result.frame.payload.assign(payload, payload + header.payload_len);
  } catch (const std::bad_alloc&) {
    return make_failure(FrameDisposition::Corrupt, Code::Exhausted,
                        "frame payload allocation failed");
  }
  return result;
}

// --- incremental stream decoder -------------------------------------------------------------

FrameStreamDecoder::FrameStreamDecoder(Limits limits) : limits_(limits) {}

Status FrameStreamDecoder::feed(const std::uint8_t* data, std::size_t size) {
  if (sticky_) {
    return status_;
  }
  if (size == 0) {
    return Status::success();
  }
  if (data == nullptr) {
    return Status::failure(Code::Invalid, "null feed buffer");
  }

  const auto body = checked_add(kFrameHeaderBytes, payload_ceiling(limits_));
  const auto frame_bytes =
      body ? checked_add(*body, kFrameTrailerBytes) : std::optional<std::size_t>();
  const auto capacity =
      frame_bytes ? checked_mul(*frame_bytes, std::size_t{2}) : std::optional<std::size_t>();
  const std::size_t buffered = buffer_.size();
  if (capacity && (buffered > *capacity || size > *capacity - buffered)) {
    return Status::failure(Code::Exhausted,
                           "stream decoder buffer bound reached; no bytes were appended");
  }
  try {
    buffer_.insert(buffer_.end(), data, data + size);
  } catch (const std::bad_alloc&) {
    return Status::failure(Code::Exhausted, "stream decoder allocation failed");
  }
  return Status::success();
}

FrameDecodeResult FrameStreamDecoder::next() {
  if (sticky_) {
    const bool unsupported = status_.code() == Code::Unsupported ||
                             status_.code() == Code::VersionMismatch;
    return make_failure(unsupported ? FrameDisposition::Unsupported : FrameDisposition::Corrupt,
                        status_.code(), status_.message());
  }

  FrameDecodeResult result = decode_frame(buffer_.data(), buffer_.size(), limits_);
  if (result.disposition == FrameDisposition::Complete) {
    if (result.consumed > 0 && result.consumed <= buffer_.size()) {
      buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(result.consumed));
    }
  } else if (result.disposition == FrameDisposition::Corrupt ||
             result.disposition == FrameDisposition::Unsupported) {
    sticky_ = true;
    status_ = result.status;
  }
  return result;
}

Status FrameStreamDecoder::status() const { return status_; }

std::size_t FrameStreamDecoder::buffered() const { return buffer_.size(); }

bool FrameStreamDecoder::failed() const { return sticky_; }

void FrameStreamDecoder::reset() {
  buffer_.clear();
  status_ = Status::success();
  sticky_ = false;
}

// --- canonical payload codecs ---------------------------------------------------------------
// Every payload is a canonical fixed-shape record: no padding, no optional fields, no trailing
// bytes. Decoding validates each enum and each bound and rejects anything left over.

std::vector<std::uint8_t> encode_hello_request(const HelloRequest& request) {
  ByteWriter writer(kTextBudget);
  writer.set_limit(kTextBudget);
  writer.u16(request.format_version);
  writer.string(bounded_message(request.principal));
  return std::move(writer).take();
}

Result<HelloRequest> decode_hello_request(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(kMaxMessageBytes);
  HelloRequest request;
  request.format_version = reader.u16();
  request.principal = reader.string();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<HelloRequest>(status);
  }
  return Result<HelloRequest>(std::move(request));
}

std::vector<std::uint8_t> encode_hello_response(const HelloResponse& response) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  writer.u16(static_cast<std::uint16_t>(response.outcome));
  writer.u64(response.session.raw());
  writer.u64(response.epoch.raw());
  writer.u64(response.boot_digest);
  writer.u32(response.format_version);
  writer.u32(response.max_payload);
  return std::move(writer).take();
}

Result<HelloResponse> decode_hello_response(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  HelloResponse response;
  const Result<Code> outcome = read_code(reader);
  const std::uint64_t session = reader.u64();
  const std::uint64_t epoch = reader.u64();
  response.boot_digest = reader.u64();
  response.format_version = reader.u32();
  response.max_payload = reader.u32();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<HelloResponse>(status);
  }
  if (!outcome.ok()) return Result<HelloResponse>(outcome.status());
  response.outcome = outcome.value();
  response.session = SessionId(session);
  response.epoch = CoordinatorEpoch(epoch);
  if (response.outcome == Code::Ok && (!response.session.valid() || !response.epoch.valid())) {
    return Result<HelloResponse>(
        Status::failure(Code::Invalid, "accepted hello response carries no session authority"));
  }
  return Result<HelloResponse>(std::move(response));
}

std::vector<std::uint8_t> encode_authority_query(const AuthorityQueryRequest& request) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  write_dependent(writer, request.dependent);
  return std::move(writer).take();
}

Result<AuthorityQueryRequest> decode_authority_query(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const Result<DependentRef> dependent = read_dependent(reader);
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<AuthorityQueryRequest>(status);
  }
  if (!dependent.ok()) return Result<AuthorityQueryRequest>(dependent.status());
  AuthorityQueryRequest request;
  request.dependent = dependent.value();
  return Result<AuthorityQueryRequest>(std::move(request));
}

std::vector<std::uint8_t> encode_authority_response(const AuthorityQueryResponse& response) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  writer.u16(static_cast<std::uint16_t>(response.outcome));
  writer.u16(static_cast<std::uint16_t>(response.reason));
  writer.boolean(response.has_authority);
  writer.u64(static_cast<std::uint64_t>(response.active_grants));
  writer.u64(static_cast<std::uint64_t>(response.withdrawn_grants));
  writer.u64(static_cast<std::uint64_t>(response.fenced_generations));
  writer.u64(response.digest);
  return std::move(writer).take();
}

Result<AuthorityQueryResponse> decode_authority_response(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  AuthorityQueryResponse response;
  const Result<Code> outcome = read_code(reader);
  const Result<Code> reason = read_code(reader);
  response.has_authority = reader.boolean();
  const Result<std::size_t> active = read_size(reader);
  const Result<std::size_t> withdrawn = read_size(reader);
  const Result<std::size_t> fenced = read_size(reader);
  response.digest = reader.u64();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<AuthorityQueryResponse>(status);
  }
  if (!outcome.ok()) return Result<AuthorityQueryResponse>(outcome.status());
  if (!reason.ok()) return Result<AuthorityQueryResponse>(reason.status());
  if (!active.ok()) return Result<AuthorityQueryResponse>(active.status());
  if (!withdrawn.ok()) return Result<AuthorityQueryResponse>(withdrawn.status());
  if (!fenced.ok()) return Result<AuthorityQueryResponse>(fenced.status());
  response.outcome = outcome.value();
  response.reason = reason.value();
  response.active_grants = active.value();
  response.withdrawn_grants = withdrawn.value();
  response.fenced_generations = fenced.value();
  // has_authority is runtime adjudication state, not a framing invariant. The codec validates
  // structure, enums and bounds; it never re-decides the runtime's outcome.
  return Result<AuthorityQueryResponse>(std::move(response));
}

std::vector<std::uint8_t> encode_failover_request(const FailoverRequest& request) {
  ByteWriter writer(kTextBudget);
  writer.set_limit(kTextBudget);
  writer.u64(request.subject.id().raw());
  writer.u64(request.subject.generation().raw());
  writer.u8(static_cast<std::uint8_t>(request.source));
  writer.u64(request.observed_at_ns);
  writer.u64(request.valid_for_ns);
  writer.string(bounded_message(request.reason));
  return std::move(writer).take();
}

Result<FailoverRequest> decode_failover_request(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(kMaxMessageBytes);
  FailoverRequest request;
  const std::uint64_t id = reader.u64();
  const std::uint64_t generation = reader.u64();
  const std::uint8_t source = reader.u8();
  request.observed_at_ns = reader.u64();
  request.valid_for_ns = reader.u64();
  request.reason = reader.string();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<FailoverRequest>(status);
  }
  if (!is_valid_evidence_source(source)) {
    return Result<FailoverRequest>(
        Status::failure(Code::Invalid, "failover request carries an unassigned evidence source"));
  }
  request.subject = SwitchKey(SwitchId(id), SwitchGeneration(generation));
  request.source = static_cast<EvidenceSource>(source);
  if (!request.subject.valid()) {
    return Result<FailoverRequest>(
        Status::failure(Code::Invalid, "failover request carries an invalid switch key"));
  }
  return Result<FailoverRequest>(std::move(request));
}

std::vector<std::uint8_t> encode_failover_response(const FailoverResponse& response) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  writer.u16(static_cast<std::uint16_t>(response.outcome));
  writer.u64(response.fence_id);
  writer.u32(response.fence_scope);
  writer.boolean(response.closure_complete);
  writer.u64(static_cast<std::uint64_t>(response.closure_members));
  writer.u64(static_cast<std::uint64_t>(response.grants_fenced));
  writer.u64(response.closure_digest);
  return std::move(writer).take();
}

Result<FailoverResponse> decode_failover_response(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  FailoverResponse response;
  const Result<Code> outcome = read_code(reader);
  response.fence_id = reader.u64();
  response.fence_scope = reader.u32();
  response.closure_complete = reader.boolean();
  const Result<std::size_t> members = read_size(reader);
  const Result<std::size_t> fenced = read_size(reader);
  response.closure_digest = reader.u64();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<FailoverResponse>(status);
  }
  if (!outcome.ok()) return Result<FailoverResponse>(outcome.status());
  if (!members.ok()) return Result<FailoverResponse>(members.status());
  if (!fenced.ok()) return Result<FailoverResponse>(fenced.status());
  response.outcome = outcome.value();
  response.closure_members = members.value();
  response.grants_fenced = fenced.value();
  return Result<FailoverResponse>(std::move(response));
}

std::vector<std::uint8_t> encode_restore_query(const RestoreQueryRequest& request) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  write_dependent(writer, request.dependent);
  return std::move(writer).take();
}

Result<RestoreQueryRequest> decode_restore_query(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  const Result<DependentRef> dependent = read_dependent(reader);
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<RestoreQueryRequest>(status);
  }
  if (!dependent.ok()) return Result<RestoreQueryRequest>(dependent.status());
  RestoreQueryRequest request;
  request.dependent = dependent.value();
  return Result<RestoreQueryRequest>(std::move(request));
}

std::vector<std::uint8_t> encode_restore_response(const RestoreQueryResponse& response) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  writer.u16(static_cast<std::uint16_t>(response.outcome));
  writer.u16(static_cast<std::uint16_t>(response.reason));
  writer.boolean(response.may_restore);
  writer.boolean(response.effect_verified);
  writer.u64(static_cast<std::uint64_t>(response.blocking_generations));
  return std::move(writer).take();
}

Result<RestoreQueryResponse> decode_restore_response(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  RestoreQueryResponse response;
  const Result<Code> outcome = read_code(reader);
  const Result<Code> reason = read_code(reader);
  response.may_restore = reader.boolean();
  response.effect_verified = reader.boolean();
  const Result<std::size_t> blocking = read_size(reader);
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<RestoreQueryResponse>(status);
  }
  if (!outcome.ok()) return Result<RestoreQueryResponse>(outcome.status());
  if (!reason.ok()) return Result<RestoreQueryResponse>(reason.status());
  if (!blocking.ok()) return Result<RestoreQueryResponse>(blocking.status());
  response.outcome = outcome.value();
  response.reason = reason.value();
  response.blocking_generations = blocking.value();
  // may_restore is runtime adjudication state: a policy may permit restoration on an
  // acknowledgement alone, which is reported with a non-affirmative outcome. The codec carries
  // that pair unchanged rather than re-deciding it.
  return Result<RestoreQueryResponse>(std::move(response));
}

std::vector<std::uint8_t> encode_snapshot_response(const SnapshotResponse& response) {
  ByteWriter writer(kFixedPayloadBudget);
  writer.set_limit(kFixedPayloadBudget);
  writer.u16(static_cast<std::uint16_t>(response.outcome));
  writer.u64(response.epoch);
  writer.u64(response.boot_ordinal);
  writer.u64(static_cast<std::uint64_t>(response.switches));
  writer.u64(static_cast<std::uint64_t>(response.fences));
  writer.u64(static_cast<std::uint64_t>(response.failures));
  writer.u64(static_cast<std::uint64_t>(response.active_grants));
  writer.u64(static_cast<std::uint64_t>(response.retained_events));
  writer.boolean(response.durability_enabled);
  return std::move(writer).take();
}

Result<SnapshotResponse> decode_snapshot_response(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  SnapshotResponse response;
  const Result<Code> outcome = read_code(reader);
  response.epoch = reader.u64();
  response.boot_ordinal = reader.u64();
  const Result<std::size_t> switches = read_size(reader);
  const Result<std::size_t> fences = read_size(reader);
  const Result<std::size_t> failures = read_size(reader);
  const Result<std::size_t> grants = read_size(reader);
  const Result<std::size_t> events = read_size(reader);
  response.durability_enabled = reader.boolean();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<SnapshotResponse>(status);
  }
  if (!outcome.ok()) return Result<SnapshotResponse>(outcome.status());
  if (!switches.ok()) return Result<SnapshotResponse>(switches.status());
  if (!fences.ok()) return Result<SnapshotResponse>(fences.status());
  if (!failures.ok()) return Result<SnapshotResponse>(failures.status());
  if (!grants.ok()) return Result<SnapshotResponse>(grants.status());
  if (!events.ok()) return Result<SnapshotResponse>(events.status());
  response.outcome = outcome.value();
  response.switches = switches.value();
  response.fences = fences.value();
  response.failures = failures.value();
  response.active_grants = grants.value();
  response.retained_events = events.value();
  return Result<SnapshotResponse>(std::move(response));
}

std::vector<std::uint8_t> encode_error_payload(Code code, std::string_view detail) {
  ByteWriter writer(kTextBudget);
  writer.set_limit(kTextBudget);
  writer.u16(static_cast<std::uint16_t>(code));
  writer.string(bounded_message(detail));
  return std::move(writer).take();
}

Result<std::pair<Code, std::string>> decode_error_payload(const std::vector<std::uint8_t>& payload) {
  ByteReader reader(payload);
  reader.set_element_limit(kMaxMessageBytes);
  const Result<Code> code = read_code(reader);
  std::string detail = reader.string();
  if (const Status status = finish_payload(reader); !status.ok()) {
    return Result<std::pair<Code, std::string>>(status);
  }
  if (!code.ok()) return Result<std::pair<Code, std::string>>(code.status());
  return Result<std::pair<Code, std::string>>(std::make_pair(code.value(), std::move(detail)));
}

}  // namespace sff
