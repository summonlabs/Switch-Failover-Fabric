// Switch Failover Fabric - framed protocol codec verification.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Self-contained: no third-party framework, no timeouts, no threads, no clock. Every input buffer
// is allocated at exactly the size handed to the decoder, so an out-of-range read is a real
// out-of-bounds access (visible to ASan) rather than a read of slack bytes.
//
// Exits non-zero when any check fails and prints a one-line summary.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

// sff/transport/frame.hpp uses SessionBinding in FrameHeader::binding() without including its
// declaring header, so the declaring header must precede it. The public header is frozen.
#include "sff/runtime/session.hpp"

#include "sff/codec/bytes.hpp"
#include "sff/codec/integrity.hpp"
#include "sff/core/checked.hpp"
#include "sff/transport/frame.hpp"

namespace {

int g_checks = 0;
int g_failures = 0;

void report(bool condition, const char* text, int line) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::printf("FAIL line %d: %s\n", line, text);
  }
}

#define CHECK(condition) report((condition), #condition, __LINE__)

using sff::Code;
using sff::CoordinatorEpoch;
using sff::Frame;
using sff::FrameDecodeResult;
using sff::FrameDisposition;
using sff::FrameStreamDecoder;
using sff::Limits;
using sff::MessageType;
using sff::SessionId;
using sff::Status;

constexpr std::size_t kHeaderCrcOffset = sff::kFrameHeaderBytes - sff::kFrameTrailerBytes;

Limits small_limits() {
  Limits limits = Limits::defaults();
  limits.max_frame_payload = 4096;
  return limits;
}

Frame make_request(MessageType type, std::vector<std::uint8_t> payload, std::uint64_t sequence = 1) {
  Frame frame;
  frame.header.magic = sff::kFrameMagic;
  frame.header.format_version = sff::kFrameFormatVersion;
  frame.header.type = type;
  frame.header.flags = 0x0000000Fu;
  frame.header.session = SessionId(0x1122334455667788ull);
  frame.header.epoch = CoordinatorEpoch(9);
  frame.header.boot_digest = 0xDEADBEEFCAFEF00Dull;
  frame.header.request_seq = sequence;
  frame.payload = std::move(payload);
  return frame;
}

std::vector<std::uint8_t> encode_or_empty(const Frame& frame, const Limits& limits) {
  const auto encoded = sff::encode_frame(frame, limits);
  CHECK(encoded.ok());
  if (!encoded.ok()) return {};
  return encoded.value();
}

void store_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  if (offset + 2 > bytes.size()) return;
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void store_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  if (offset + 4 > bytes.size()) return;
  for (std::size_t i = 0; i < 4; ++i) {
    bytes[offset + i] = static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu);
  }
}

/// Recompute the header CRC after a deliberate field edit, so the frame is corrupt in exactly the
/// dimension under test and not in its checksum.
void fix_header_crc(std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < sff::kFrameHeaderBytes) return;
  store_u32(bytes, kHeaderCrcOffset, sff::crc32_ieee(bytes.data(), kHeaderCrcOffset));
}

std::vector<std::uint8_t> trailing(std::vector<std::uint8_t> payload) {
  payload.push_back(0x5Au);
  return payload;
}

// --- framing layout ---------------------------------------------------------------------------

void test_header_layout() {
  const Frame frame = make_request(MessageType::QueryAuthority, {1, 2, 3, 4, 5});
  const std::vector<std::uint8_t> header = frame.header.encode();
  CHECK(header.size() == sff::kFrameHeaderBytes);
  CHECK(sff::kFrameHeaderBytes == 52);
  CHECK(sff::kFrameTrailerBytes == 4);
  CHECK(header[0] == static_cast<std::uint8_t>('S'));
  CHECK(header[1] == static_cast<std::uint8_t>('F'));
  CHECK(header[2] == static_cast<std::uint8_t>('F'));
  CHECK(header[3] == static_cast<std::uint8_t>('1'));
  CHECK(sff::kFrameMagic == 0x31464653u);

  // Little-endian field placement. QueryAuthority is type 3 and sits at offset 6.
  CHECK(header[6] == 3 && header[7] == 0);
  CHECK(header[12] == 0x88 && header[19] == 0x11);
  CHECK(header[20] == 9 && header[21] == 0);
  CHECK(header[48] == static_cast<std::uint8_t>(frame.header.compute_crc() & 0xFFu));
  CHECK(sff::crc32_ieee(header.data(), kHeaderCrcOffset) == frame.header.compute_crc());
  CHECK(sff::crc32_ieee("123456789", 9) == 0xCBF43926u);  // standard CRC-32 check value

  // A stale header_crc member never changes what encode() writes: the CRC is recomputed.
  Frame other = frame;
  other.header.header_crc = 0x12345678u;
  CHECK(other.header.encode() == header);

  // binding() carries exactly what the wire carries.
  const sff::SessionBinding binding = frame.header.binding();
  CHECK(binding.session == frame.header.session);
  CHECK(binding.epoch == frame.header.epoch);
  CHECK(binding.boot_digest == frame.header.boot_digest);
  CHECK(binding.request_seq == frame.header.request_seq);
}

void test_round_trip(const Limits& limits) {
  const std::vector<std::uint8_t> payload(300, 0xA5u);
  const Frame sent = make_request(MessageType::AuthorityResult, payload, 42);
  const std::vector<std::uint8_t> bytes = encode_or_empty(sent, limits);
  CHECK(bytes.size() == sff::kFrameHeaderBytes + payload.size() + sff::kFrameTrailerBytes);

  const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
  CHECK(decoded.disposition == FrameDisposition::Complete);
  CHECK(decoded.status.ok());
  CHECK(decoded.consumed == bytes.size());
  CHECK(decoded.frame.header.type == MessageType::AuthorityResult);
  CHECK(decoded.frame.header.session == sent.header.session);
  CHECK(decoded.frame.header.epoch == sent.header.epoch);
  CHECK(decoded.frame.header.boot_digest == sent.header.boot_digest);
  CHECK(decoded.frame.header.request_seq == 42);
  CHECK(decoded.frame.header.flags == sent.header.flags);
  CHECK(decoded.frame.header.payload_len == payload.size());
  CHECK(decoded.frame.payload == payload);
  CHECK(decoded.frame.payload_crc == sff::crc32_ieee(payload.data(), payload.size()));
  CHECK(decoded.frame.digest() == sent.digest());

  // Trailing bytes beyond one frame are the caller's business, not an error.
  std::vector<std::uint8_t> padded = bytes;
  padded.push_back(0x00u);
  const FrameDecodeResult first = sff::decode_frame(padded.data(), padded.size(), limits);
  CHECK(first.disposition == FrameDisposition::Complete);
  CHECK(first.consumed == bytes.size());

  // A digest is content sensitive.
  Frame changed = sent;
  changed.payload[0] = 0x5Au;
  CHECK(changed.digest() != sent.digest());
}

// --- truncation ---------------------------------------------------------------------------------

void test_every_truncated_prefix() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> payload(300, 0x3Cu);
  const Frame sent = make_request(MessageType::DeclareFailure, payload);
  const std::vector<std::uint8_t> bytes = encode_or_empty(sent, limits);

  for (std::size_t length = 0; length < bytes.size(); ++length) {
    // Exactly length bytes: reading one past the end would be a genuine out-of-bounds access.
    const std::vector<std::uint8_t> prefix(bytes.begin(),
                                           bytes.begin() + static_cast<std::ptrdiff_t>(length));
    const FrameDecodeResult decoded = sff::decode_frame(prefix.data(), prefix.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Incomplete);
    CHECK(decoded.consumed == 0);
    CHECK(decoded.frame.payload.empty());
    CHECK(!decoded.status.ok());
  }

  // A prefix that already contains a whole inner frame is still just payload bytes.
  const std::vector<std::uint8_t> nested =
      encode_or_empty(make_request(MessageType::Hello, {1, 2, 3}), limits);
  const std::vector<std::uint8_t> outer =
      encode_or_empty(make_request(MessageType::SnapshotRequest, nested), limits);
  for (std::size_t length = 4; length < outer.size(); ++length) {
    const std::vector<std::uint8_t> prefix(outer.begin(),
                                           outer.begin() + static_cast<std::ptrdiff_t>(length));
    CHECK(sff::decode_frame(prefix.data(), prefix.size(), limits).disposition ==
          FrameDisposition::Incomplete);
  }

  // One byte short of a complete frame is Incomplete, never a truncated-but-accepted frame.
  const FrameDecodeResult short_frame = sff::decode_frame(bytes.data(), bytes.size() - 1, limits);
  CHECK(short_frame.disposition == FrameDisposition::Incomplete);
  CHECK(short_frame.frame.payload.empty());

  // Null range handling stays total.
  CHECK(sff::decode_frame(nullptr, 0, limits).disposition == FrameDisposition::Incomplete);
  CHECK(sff::decode_frame(nullptr, 8, limits).disposition == FrameDisposition::Corrupt);
}

// --- payload bounds ------------------------------------------------------------------------------

void test_payload_bounds() {
  const Limits limits = small_limits();

  // Zero length payload: no payload bytes, CRC of an empty range.
  {
    const Frame sent = make_request(MessageType::Hello, {});
    const std::vector<std::uint8_t> bytes = encode_or_empty(sent, limits);
    CHECK(bytes.size() == sff::kFrameHeaderBytes + sff::kFrameTrailerBytes);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Complete);
    CHECK(decoded.frame.payload.empty());
    CHECK(decoded.frame.payload_crc == sff::crc32_ieee(nullptr, 0));
    CHECK(decoded.frame.payload_crc == 0u);
    CHECK(decoded.consumed == sff::kFrameHeaderBytes + sff::kFrameTrailerBytes);
  }

  // Exactly the maximum payload length.
  {
    const std::vector<std::uint8_t> payload(limits.max_frame_payload, 0x77u);
    const Frame sent = make_request(MessageType::SnapshotResult, payload);
    const std::vector<std::uint8_t> bytes = encode_or_empty(sent, limits);
    CHECK(bytes.size() ==
          sff::kFrameHeaderBytes + limits.max_frame_payload + sff::kFrameTrailerBytes);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Complete);
    CHECK(decoded.frame.payload.size() == limits.max_frame_payload);
    CHECK(decoded.frame.payload == payload);
    CHECK(decoded.consumed == bytes.size());
  }

  // The default limit is the production bound: exercise it once at full length.
  {
    const Limits defaults = Limits::defaults();
    const std::vector<std::uint8_t> payload(defaults.max_frame_payload, 0x01u);
    const std::vector<std::uint8_t> bytes =
        encode_or_empty(make_request(MessageType::SnapshotResult, payload), defaults);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), defaults);
    CHECK(decoded.disposition == FrameDisposition::Complete);
    CHECK(decoded.frame.payload.size() == defaults.max_frame_payload);
    CHECK(decoded.consumed ==
          sff::kFrameHeaderBytes + defaults.max_frame_payload + sff::kFrameTrailerBytes);
  }

  // One byte over the bound is refused before it is ever encoded or materialised.
  {
    const std::vector<std::uint8_t> payload(limits.max_frame_payload + 1, 0x77u);
    const Frame sent = make_request(MessageType::SnapshotResult, payload);
    const auto encoded = sff::encode_frame(sent, limits);
    CHECK(!encoded.ok());
    CHECK(encoded.status().code() == Code::Exhausted);
  }

  // Declared payload one byte over the bound, header CRC valid, full frame present, so the only
  // reason to refuse is the declared length.
  {
    const std::vector<std::uint8_t> payload(limits.max_frame_payload, 0x77u);
    std::vector<std::uint8_t> bytes =
        encode_or_empty(make_request(MessageType::SnapshotResult, payload), limits);
    store_u32(bytes, 44, static_cast<std::uint32_t>(limits.max_frame_payload + 1));
    fix_header_crc(bytes);
    bytes.resize(sff::kFrameHeaderBytes + limits.max_frame_payload + 1 + sff::kFrameTrailerBytes, 0);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Corrupt);
    CHECK(decoded.status.code() == Code::Corrupt);
    CHECK(decoded.consumed == 0);
    CHECK(decoded.frame.payload.empty());
  }

  // The same declared length without a valid header CRC is corrupt either way.
  {
    std::vector<std::uint8_t> bytes = encode_or_empty(make_request(MessageType::Hello, {}), limits);
    store_u32(bytes, 44, static_cast<std::uint32_t>(limits.max_frame_payload + 1));
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Corrupt);
  }

  // Within the bound but not yet present is Incomplete, never Corrupt and never Complete.
  {
    const std::vector<std::uint8_t> payload(limits.max_frame_payload, 0x77u);
    const std::vector<std::uint8_t> bytes =
        encode_or_empty(make_request(MessageType::SnapshotResult, payload), limits);
    const FrameDecodeResult decoded =
        sff::decode_frame(bytes.data(), sff::kFrameHeaderBytes + 10, limits);
    CHECK(decoded.disposition == FrameDisposition::Incomplete);
  }
}

void test_oversized_declared_payload_does_not_allocate() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> bytes =
      encode_or_empty(make_request(MessageType::Hello, {1, 2}), limits);

  // A declared 4 GiB payload inside a 58-byte range. Nothing may be allocated for it and nothing
  // may be read past the range: the frame is refused on the declaration alone.
  std::vector<std::uint8_t> liar = bytes;
  store_u32(liar, 44, 0xFFFFFFFFu);
  fix_header_crc(liar);
  const FrameDecodeResult decoded = sff::decode_frame(liar.data(), liar.size(), limits);
  CHECK(decoded.disposition == FrameDisposition::Corrupt);
  CHECK(decoded.status.code() == Code::Corrupt);
  CHECK(decoded.consumed == 0);
  CHECK(decoded.frame.payload.empty());
  CHECK(decoded.frame.payload.capacity() == 0);

  // Even with an absurd caller limit, the hard ceiling holds.
  Limits absurd = Limits::defaults();
  absurd.max_frame_payload = std::numeric_limits<std::size_t>::max();
  store_u32(liar, 44, 0xFFFFFF00u);
  fix_header_crc(liar);
  const FrameDecodeResult clamped = sff::decode_frame(liar.data(), liar.size(), absurd);
  CHECK(clamped.disposition == FrameDisposition::Corrupt);
  CHECK(clamped.frame.payload.empty());

  // Through the stream decoder the same declaration is a hard, sticky failure.
  FrameStreamDecoder decoder(limits);
  CHECK(decoder.feed(liar.data(), liar.size()).ok());
  const FrameDecodeResult streamed = decoder.next();
  CHECK(streamed.disposition == FrameDisposition::Corrupt);
  CHECK(decoder.failed());
  CHECK(decoder.buffered() == liar.size());
}

// --- corruption and unsupported input --------------------------------------------------------

void test_corruption() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> payload(64, 0x11u);
  const Frame sent = make_request(MessageType::ProposePlan, payload);
  const std::vector<std::uint8_t> good = encode_or_empty(sent, limits);
  CHECK(sff::decode_frame(good.data(), good.size(), limits).disposition ==
        FrameDisposition::Complete);

  // Wrong magic.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes[0] = static_cast<std::uint8_t>('X');
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Corrupt);
    CHECK(decoded.status.code() == Code::Corrupt);
  }
  // Wrong magic with only five bytes present is still decidable.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes[3] = static_cast<std::uint8_t>('9');
    CHECK(sff::decode_frame(bytes.data(), 5, limits).disposition == FrameDisposition::Corrupt);
  }
  // Corrupted header field without a matching header CRC.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes[8] = static_cast<std::uint8_t>(bytes[8] ^ 0x01u);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Corrupt);
    CHECK(decoded.consumed == 0);
    CHECK(decoded.frame.payload.empty());
  }
  // Corrupted header CRC itself.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes[48] = static_cast<std::uint8_t>(bytes[48] ^ 0xFFu);
    CHECK(sff::decode_frame(bytes.data(), bytes.size(), limits).disposition ==
          FrameDisposition::Corrupt);
  }
  // Corrupted payload: the header CRC still matches, the payload CRC does not.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes[sff::kFrameHeaderBytes + 5] =
        static_cast<std::uint8_t>(bytes[sff::kFrameHeaderBytes + 5] ^ 0x80u);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Corrupt);
    CHECK(decoded.status.code() == Code::Corrupt);
  }
  // Corrupted trailer.
  {
    std::vector<std::uint8_t> bytes = good;
    bytes.back() = static_cast<std::uint8_t>(bytes.back() ^ 0x01u);
    CHECK(sff::decode_frame(bytes.data(), bytes.size(), limits).disposition ==
          FrameDisposition::Corrupt);
  }
  // A shortened declared length whose trailer no longer matches is not accepted as a short frame.
  {
    std::vector<std::uint8_t> bytes = good;
    store_u32(bytes, 44, 8);
    fix_header_crc(bytes);
    CHECK(sff::decode_frame(bytes.data(), bytes.size(), limits).disposition ==
          FrameDisposition::Corrupt);
  }
}

void test_unsupported() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> good =
      encode_or_empty(make_request(MessageType::ApplyPlan, {9, 9, 9}), limits);

  // Format version this build does not implement.
  {
    std::vector<std::uint8_t> bytes = good;
    store_u16(bytes, 4, static_cast<std::uint16_t>(sff::kFrameFormatVersion + 1));
    fix_header_crc(bytes);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Unsupported);
    CHECK(decoded.status.code() == Code::VersionMismatch);
    CHECK(decoded.consumed == 0);
    CHECK(decoded.frame.payload.empty());
  }
  // Unassigned message type.
  {
    std::vector<std::uint8_t> bytes = good;
    store_u16(bytes, 6, 999);
    fix_header_crc(bytes);
    const FrameDecodeResult decoded = sff::decode_frame(bytes.data(), bytes.size(), limits);
    CHECK(decoded.disposition == FrameDisposition::Unsupported);
    CHECK(decoded.status.code() == Code::Unsupported);
  }
  // The reserved zero type is unassigned, not unknown-but-acceptable.
  {
    std::vector<std::uint8_t> bytes = good;
    store_u16(bytes, 6, 0);
    fix_header_crc(bytes);
    CHECK(sff::decode_frame(bytes.data(), bytes.size(), limits).disposition ==
          FrameDisposition::Unsupported);
  }
  for (std::uint16_t raw = 1; raw <= 16; ++raw) {
    CHECK(sff::is_valid_message_type(raw));
    CHECK(std::string(sff::to_string(static_cast<MessageType>(raw))) != "Unassigned");
  }
  CHECK(!sff::is_valid_message_type(0));
  CHECK(!sff::is_valid_message_type(17));
  CHECK(std::string(sff::to_string(MessageType::HelloAck)) == "HelloAck");
  CHECK(std::string(sff::to_string(FrameDisposition::Incomplete)) == "Incomplete");
}

// --- stream decoder ----------------------------------------------------------------------------

void test_stream_two_frames_one_byte_at_a_time() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> first_payload(40, 0x21u);
  const std::vector<std::uint8_t> second_payload(7, 0x42u);
  const std::vector<std::uint8_t> first =
      encode_or_empty(make_request(MessageType::ApplyPlan, first_payload, 1), limits);
  const std::vector<std::uint8_t> second =
      encode_or_empty(make_request(MessageType::ApplyResult, second_payload, 2), limits);

  std::vector<std::uint8_t> stream = first;
  stream.insert(stream.end(), second.begin(), second.end());

  FrameStreamDecoder decoder(limits);
  std::vector<Frame> decoded;
  for (std::size_t index = 0; index < stream.size(); ++index) {
    const Status fed = decoder.feed(&stream[index], 1);
    CHECK(fed.ok());
    for (;;) {
      const FrameDecodeResult result = decoder.next();
      if (result.disposition == FrameDisposition::Complete) {
        decoded.push_back(result.frame);
        continue;
      }
      CHECK(result.disposition == FrameDisposition::Incomplete);
      break;
    }
  }

  CHECK(decoded.size() == 2);
  if (decoded.size() == 2) {
    CHECK(decoded[0].header.type == MessageType::ApplyPlan);
    CHECK(decoded[0].header.request_seq == 1);
    CHECK(decoded[0].payload == first_payload);
    CHECK(decoded[1].header.type == MessageType::ApplyResult);
    CHECK(decoded[1].header.request_seq == 2);
    CHECK(decoded[1].payload == second_payload);
  }
  CHECK(decoder.buffered() == 0);
  CHECK(decoder.next().disposition == FrameDisposition::Incomplete);
  CHECK(decoder.status().ok());
  CHECK(!decoder.failed());
}

void test_stream_chunked_feed() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> payload(100, 0x5Au);
  const std::vector<std::uint8_t> bytes =
      encode_or_empty(make_request(MessageType::QueryRestore, payload), limits);

  // Uneven chunking must produce exactly one frame and never a partial accept.
  FrameStreamDecoder decoder(limits);
  const std::size_t chunks[] = {1u, 3u, 17u, 29u, 5u};
  std::size_t offset = 0;
  std::size_t chunk_index = 0;
  bool complete = false;
  while (offset < bytes.size()) {
    const std::size_t want = chunks[chunk_index % 5];
    const std::size_t take = (offset + want <= bytes.size()) ? want : (bytes.size() - offset);
    CHECK(decoder.feed(bytes.data() + offset, take).ok());
    offset += take;
    ++chunk_index;
    const FrameDecodeResult result = decoder.next();
    if (result.disposition == FrameDisposition::Complete) {
      complete = true;
      CHECK(result.frame.payload == payload);
      CHECK(result.consumed == bytes.size());
      break;
    }
    CHECK(result.disposition == FrameDisposition::Incomplete);
  }
  CHECK(complete);
  CHECK(decoder.buffered() == 0);

  // A zero-length feed is a no-op, not a failure.
  CHECK(decoder.feed(nullptr, 0).ok());
  CHECK(decoder.feed(bytes.data(), 0).ok());
}

void test_stream_sticky_failure() {
  const Limits limits = small_limits();
  const std::vector<std::uint8_t> good =
      encode_or_empty(make_request(MessageType::QueryAuthority, {1, 2, 3}), limits);
  std::vector<std::uint8_t> corrupt = good;
  corrupt[0] = static_cast<std::uint8_t>('Z');

  FrameStreamDecoder decoder(limits);
  CHECK(decoder.feed(good.data(), good.size()).ok());
  CHECK(decoder.feed(corrupt.data(), corrupt.size()).ok());

  const FrameDecodeResult first = decoder.next();
  CHECK(first.disposition == FrameDisposition::Complete);
  CHECK(decoder.buffered() == corrupt.size());
  CHECK(decoder.status().ok());
  CHECK(!decoder.failed());

  const FrameDecodeResult second = decoder.next();
  CHECK(second.disposition == FrameDisposition::Corrupt);
  CHECK(second.status.code() == Code::Corrupt);
  CHECK(decoder.failed());
  CHECK(!decoder.status().ok());
  const Code sticky_code = decoder.status().code();
  const std::size_t retained = decoder.buffered();

  // Every later attempt keeps failing with the same code, including a feed of a valid frame.
  for (int attempt = 0; attempt < 3; ++attempt) {
    const FrameDecodeResult repeat = decoder.next();
    CHECK(repeat.disposition == FrameDisposition::Corrupt);
    CHECK(repeat.status.code() == sticky_code);
    CHECK(repeat.consumed == 0);
  }
  const Status refused = decoder.feed(good.data(), good.size());
  CHECK(!refused.ok());
  CHECK(refused.code() == sticky_code);
  CHECK(decoder.buffered() == retained);

  // reset() clears the buffer and both failure flags.
  decoder.reset();
  CHECK(decoder.status().ok());
  CHECK(!decoder.failed());
  CHECK(decoder.buffered() == 0);
  CHECK(decoder.feed(good.data(), good.size()).ok());
  CHECK(decoder.next().disposition == FrameDisposition::Complete);

  // Unsupported is sticky in exactly the same way.
  FrameStreamDecoder versioned(limits);
  std::vector<std::uint8_t> future = good;
  store_u16(future, 4, static_cast<std::uint16_t>(sff::kFrameFormatVersion + 7));
  fix_header_crc(future);
  CHECK(versioned.feed(future.data(), future.size()).ok());
  CHECK(versioned.next().disposition == FrameDisposition::Unsupported);
  CHECK(versioned.failed());
  CHECK(versioned.next().disposition == FrameDisposition::Unsupported);
  CHECK(versioned.next().status.code() == Code::VersionMismatch);
  CHECK(!versioned.feed(good.data(), good.size()).ok());
  versioned.reset();
  CHECK(versioned.feed(good.data(), good.size()).ok());
  CHECK(versioned.next().disposition == FrameDisposition::Complete);
}

void test_stream_buffer_bound() {
  Limits limits = small_limits();
  limits.max_frame_payload = 16;
  FrameStreamDecoder decoder(limits);
  const std::vector<std::uint8_t> block(1024, 0x00u);
  const Status fed = decoder.feed(block.data(), block.size());
  CHECK(!fed.ok());
  CHECK(fed.code() == Code::Exhausted);
  CHECK(decoder.buffered() == 0);
  CHECK(decoder.status().ok());  // a refusal is not a desynchronisation
  CHECK(!decoder.failed());
  CHECK(decoder.feed(nullptr, 0).ok());
}

// --- payload codecs ------------------------------------------------------------------------------

void test_payload_codecs() {
  // Hello request and response.
  {
    sff::HelloRequest request;
    request.principal = "coordinator";
    request.format_version = sff::kFrameFormatVersion;
    const std::vector<std::uint8_t> encoded = sff::encode_hello_request(request);
    const auto decoded = sff::decode_hello_request(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().principal == request.principal);
      CHECK(decoded.value().format_version == request.format_version);
    }
    CHECK(!sff::decode_hello_request(trailing(encoded)).ok());
    CHECK(!sff::decode_hello_request({encoded.begin(), encoded.end() - 1}).ok());
    CHECK(!sff::decode_hello_request({}).ok());

    sff::HelloResponse response;
    response.session = SessionId(11);
    response.epoch = CoordinatorEpoch(4);
    response.boot_digest = 0xABCDEFull;
    response.format_version = sff::kFrameFormatVersion;
    response.max_payload = 4096;
    response.outcome = Code::Ok;
    const std::vector<std::uint8_t> encoded_response = sff::encode_hello_response(response);
    const auto decoded_response = sff::decode_hello_response(encoded_response);
    CHECK(decoded_response.ok());
    if (decoded_response.ok()) {
      CHECK(decoded_response.value().session == response.session);
      CHECK(decoded_response.value().epoch == response.epoch);
      CHECK(decoded_response.value().boot_digest == response.boot_digest);
      CHECK(decoded_response.value().max_payload == response.max_payload);
      CHECK(decoded_response.value().outcome == Code::Ok);
    }
    CHECK(!sff::decode_hello_response(trailing(encoded_response)).ok());

    // Accepted response with no session authority, and an unassigned outcome code.
    std::vector<std::uint8_t> no_authority = encoded_response;
    for (std::size_t i = 2; i < 18; ++i) no_authority[i] = 0;
    CHECK(!sff::decode_hello_response(no_authority).ok());
    std::vector<std::uint8_t> bad_code = encoded_response;
    store_u16(bad_code, 0, 60000);
    CHECK(!sff::decode_hello_response(bad_code).ok());
    CHECK(sff::decode_hello_response(bad_code).status().code() == Code::Invalid);
  }

  // Authority query and result.
  {
    sff::AuthorityQueryRequest request;
    request.dependent = sff::DependentRef::link(sff::LinkId(77));
    const std::vector<std::uint8_t> encoded = sff::encode_authority_query(request);
    const auto decoded = sff::decode_authority_query(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().dependent == request.dependent);
      CHECK(decoded.value().dependent.valid());
    }
    CHECK(!sff::decode_authority_query(trailing(encoded)).ok());

    // An unassigned enum value and the reserved Unknown kind are both refused.
    std::vector<std::uint8_t> bad_kind = encoded;
    bad_kind[0] = 200;
    CHECK(!sff::decode_authority_query(bad_kind).ok());
    CHECK(sff::decode_authority_query(bad_kind).status().code() == Code::Invalid);
    std::vector<std::uint8_t> unknown_kind = encoded;
    unknown_kind[0] = 0;
    CHECK(!sff::decode_authority_query(unknown_kind).ok());

    // A zero identifier is not a dependent.
    std::vector<std::uint8_t> zero_id = encoded;
    for (std::size_t i = 1; i < 9; ++i) zero_id[i] = 0;
    CHECK(!sff::decode_authority_query(zero_id).ok());

    sff::AuthorityQueryResponse response;
    response.outcome = Code::Ok;
    response.reason = Code::Unknown;
    response.has_authority = true;
    response.active_grants = 3;
    response.withdrawn_grants = 1;
    response.fenced_generations = 2;
    response.digest = 0xFEEDFACEull;
    const std::vector<std::uint8_t> encoded_response = sff::encode_authority_response(response);
    const auto decoded_response = sff::decode_authority_response(encoded_response);
    CHECK(decoded_response.ok());
    if (decoded_response.ok()) {
      CHECK(decoded_response.value().outcome == Code::Ok);
      CHECK(decoded_response.value().has_authority);
      CHECK(decoded_response.value().active_grants == 3);
      CHECK(decoded_response.value().fenced_generations == 2);
      CHECK(decoded_response.value().digest == 0xFEEDFACEull);
    }
    CHECK(!sff::decode_authority_response(trailing(encoded_response)).ok());
    std::vector<std::uint8_t> bad_outcome = encoded_response;
    store_u16(bad_outcome, 0, 40000);
    CHECK(!sff::decode_authority_response(bad_outcome).ok());
  }

  // Failover request and result, including the evidence-source enum.
  {
    sff::FailoverRequest request;
    request.subject = sff::SwitchKey(sff::SwitchId(5), sff::SwitchGeneration(6));
    request.source = sff::EvidenceSource::FabricManager;
    request.observed_at_ns = 123456789;
    request.valid_for_ns = 1000;
    request.reason = "link down";
    const std::vector<std::uint8_t> encoded = sff::encode_failover_request(request);
    const auto decoded = sff::decode_failover_request(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().subject == request.subject);
      CHECK(decoded.value().source == request.source);
      CHECK(decoded.value().observed_at_ns == request.observed_at_ns);
      CHECK(decoded.value().reason == request.reason);
    }
    CHECK(!sff::decode_failover_request(trailing(encoded)).ok());
    std::vector<std::uint8_t> bad_source = encoded;
    bad_source[16] = 200;
    CHECK(!sff::decode_failover_request(bad_source).ok());
    CHECK(sff::decode_failover_request(bad_source).status().code() == Code::Invalid);
    std::vector<std::uint8_t> unknown_source = encoded;
    unknown_source[16] = 0;
    CHECK(!sff::decode_failover_request(unknown_source).ok());
    std::vector<std::uint8_t> zero_generation = encoded;
    for (std::size_t i = 8; i < 16; ++i) zero_generation[i] = 0;
    CHECK(!sff::decode_failover_request(zero_generation).ok());

    sff::FailoverResponse response;
    response.outcome = Code::Fenced;
    response.fence_id = 99;
    response.fence_scope = 7;
    response.closure_complete = true;
    response.closure_members = 12;
    response.grants_fenced = 4;
    response.closure_digest = 0x1234ull;
    const std::vector<std::uint8_t> encoded_response = sff::encode_failover_response(response);
    const auto decoded_response = sff::decode_failover_response(encoded_response);
    CHECK(decoded_response.ok());
    if (decoded_response.ok()) {
      CHECK(decoded_response.value().outcome == Code::Fenced);
      CHECK(decoded_response.value().fence_id == 99);
      CHECK(decoded_response.value().closure_complete);
      CHECK(decoded_response.value().closure_members == 12);
      CHECK(decoded_response.value().grants_fenced == 4);
    }
    CHECK(!sff::decode_failover_response(trailing(encoded_response)).ok());
  }

  // Restore query and result.
  {
    sff::RestoreQueryRequest request;
    request.dependent = sff::DependentRef::port(4242);
    const std::vector<std::uint8_t> encoded = sff::encode_restore_query(request);
    const auto decoded = sff::decode_restore_query(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) CHECK(decoded.value().dependent == request.dependent);
    CHECK(!sff::decode_restore_query(trailing(encoded)).ok());

    sff::RestoreQueryResponse response;
    response.outcome = Code::Denied;
    response.reason = Code::Fenced;
    response.may_restore = false;
    response.effect_verified = true;
    response.blocking_generations = 2;
    const std::vector<std::uint8_t> encoded_response = sff::encode_restore_response(response);
    const auto decoded_response = sff::decode_restore_response(encoded_response);
    CHECK(decoded_response.ok());
    if (decoded_response.ok()) {
      CHECK(decoded_response.value().outcome == Code::Denied);
      CHECK(decoded_response.value().reason == Code::Fenced);
      CHECK(!decoded_response.value().may_restore);
      CHECK(decoded_response.value().effect_verified);
      CHECK(decoded_response.value().blocking_generations == 2);
    }
    CHECK(!sff::decode_restore_response(trailing(encoded_response)).ok());

    // A policy that permits restoration on an acknowledgement alone reports may_restore together
    // with an Unverified outcome. That is legitimate runtime adjudication state, and the codec
    // carries it unchanged instead of re-deciding it.
    sff::RestoreQueryResponse acknowledged;
    acknowledged.outcome = Code::Unverified;
    acknowledged.reason = Code::Unverified;
    acknowledged.may_restore = true;
    acknowledged.effect_verified = false;
    acknowledged.blocking_generations = 0;
    const auto decoded_acknowledged =
        sff::decode_restore_response(sff::encode_restore_response(acknowledged));
    CHECK(decoded_acknowledged.ok());
    if (decoded_acknowledged.ok()) {
      CHECK(decoded_acknowledged.value().may_restore);
      CHECK(decoded_acknowledged.value().outcome == Code::Unverified);
      CHECK(!decoded_acknowledged.value().effect_verified);
    }

    // The same holds for an authority response that reports a refusal.
    sff::AuthorityQueryResponse refused;
    refused.outcome = Code::Fenced;
    refused.reason = Code::Fenced;
    refused.has_authority = false;
    refused.fenced_generations = 1;
    const auto decoded_refused =
        sff::decode_authority_response(sff::encode_authority_response(refused));
    CHECK(decoded_refused.ok());
    if (decoded_refused.ok()) {
      CHECK(!decoded_refused.value().has_authority);
      CHECK(decoded_refused.value().outcome == Code::Fenced);
    }
  }

  // Snapshot result.
  {
    sff::SnapshotResponse response;
    response.outcome = Code::Ok;
    response.epoch = 17;
    response.boot_ordinal = 3;
    response.switches = 9;
    response.fences = 2;
    response.failures = 1;
    response.active_grants = 4;
    response.retained_events = 55;
    response.durability_enabled = true;
    const std::vector<std::uint8_t> encoded = sff::encode_snapshot_response(response);
    const auto decoded = sff::decode_snapshot_response(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().epoch == 17);
      CHECK(decoded.value().boot_ordinal == 3);
      CHECK(decoded.value().switches == 9);
      CHECK(decoded.value().retained_events == 55);
      CHECK(decoded.value().durability_enabled);
    }
    CHECK(!sff::decode_snapshot_response(trailing(encoded)).ok());
  }

  // Error payload.
  {
    const std::vector<std::uint8_t> encoded =
        sff::encode_error_payload(Code::Unauthorized, "no session");
    const auto decoded = sff::decode_error_payload(encoded);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().first == Code::Unauthorized);
      CHECK(decoded.value().second == "no session");
    }
    CHECK(!sff::decode_error_payload(trailing(encoded)).ok());
    CHECK(!sff::decode_error_payload({encoded.begin(), encoded.end() - 1}).ok());
    std::vector<std::uint8_t> bad_code = encoded;
    store_u16(bad_code, 0, 65000);
    CHECK(!sff::decode_error_payload(bad_code).ok());

    // Enormous text is bounded by the library message budget, never materialised whole.
    const std::string huge(64 * 1024, 'x');
    const auto bounded = sff::decode_error_payload(sff::encode_error_payload(Code::Invalid, huge));
    CHECK(bounded.ok());
    if (bounded.ok()) CHECK(bounded.value().second.size() <= sff::kMaxMessageBytes);
  }
}

void test_header_validation() {
  const Limits limits = small_limits();
  const Frame frame = make_request(MessageType::Hello, {1, 2, 3});
  CHECK(frame.header.validate(limits).ok());

  sff::FrameHeader bad_magic = frame.header;
  bad_magic.magic = 0;
  CHECK(bad_magic.validate(limits).code() == Code::Corrupt);

  sff::FrameHeader bad_version = frame.header;
  bad_version.format_version = static_cast<std::uint16_t>(sff::kFrameFormatVersion + 1);
  CHECK(bad_version.validate(limits).code() == Code::VersionMismatch);

  sff::FrameHeader bad_type = frame.header;
  bad_type.type = static_cast<MessageType>(900);
  CHECK(bad_type.validate(limits).code() == Code::Unsupported);

  sff::FrameHeader oversized = frame.header;
  oversized.payload_len = static_cast<std::uint32_t>(limits.max_frame_payload + 1);
  CHECK(oversized.validate(limits).code() == Code::Corrupt);
}

}  // namespace

int main() {
  test_header_layout();
  test_round_trip(small_limits());
  test_round_trip(Limits::defaults());
  test_every_truncated_prefix();
  test_payload_bounds();
  test_oversized_declared_payload_does_not_allocate();
  test_corruption();
  test_unsupported();
  test_stream_two_frames_one_byte_at_a_time();
  test_stream_chunked_feed();
  test_stream_sticky_failure();
  test_stream_buffer_bound();
  test_payload_codecs();
  test_header_validation();

  std::printf("test_frame_codec: %d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
