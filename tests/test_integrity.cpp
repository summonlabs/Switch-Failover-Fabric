// Switch Failover Fabric - integrity primitive verification.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// CRC-32/IEEE is verified against published check values, against the documented seed convention,
// and exhaustively against every single-bit and single-byte mutation of a short buffer. The
// 128-bit accumulator is verified the same way. Integrity is not authenticity: these checks prove
// that corruption is detected, never that a frame came from a trusted peer.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sff/codec/integrity.hpp"
#include "sff/core/identity.hpp"
// test_support.hpp renders sff::GenerationVector in its failure output but does not include the
// header that declares it, so the declaring header must come first. See the report accompanying
// this suite: the harness header, not the frozen public surface, is the one at fault.
#include "sff/model/generation.hpp"

#include "test_support.hpp"

namespace {

using sff::Digest128;

std::uint32_t crc_of(const std::string& text) {
  return sff::crc32_ieee(text.data(), text.size());
}

std::vector<std::uint8_t> bytes_of(const std::string& text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

bool digests_differ(const Digest128& left, const Digest128& right) {
  return left.hi != right.hi || left.lo != right.lo;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Known-answer vectors
// ---------------------------------------------------------------------------------------------

SFF_TEST(crc32_matches_published_check_values) {
  struct Vector {
    const char* text;
    std::uint32_t expected;
  };
  // The canonical CRC-32/IEEE check value for "123456789" is 0xCBF43926; the remaining values are
  // reference values of the same reflected polynomial (0xEDB88320, init/final 0xFFFFFFFF).
  const Vector vectors[] = {
      {"", 0x00000000u},
      {"123456789", 0xCBF43926u},
      {"a", 0xE8B7BE43u},
      {"abc", 0x352441C2u},
      {"message digest", 0x20159D7Fu},
      {"abcdefghijklmnopqrstuvwxyz", 0x4C2750BDu},
      {"The quick brown fox jumps over the lazy dog", 0x414FA339u},
      {"switch failover fabric", 0xF48AFF50u},
  };
  for (const Vector& vector : vectors) {
    const std::string text(vector.text);
    CHECK_EQ(sff::crc32_ieee(text.data(), text.size()), vector.expected);
    CHECK_EQ(sff::crc32_ieee(bytes_of(text)), vector.expected);
    CHECK_EQ(sff::crc32_ieee(text.data(), text.size(), 0u), vector.expected);
  }

  // Single-byte and short-range vectors: a zero byte is 0xD202EF8D, an all-ones byte 0xFF000000.
  const std::uint8_t zero = 0x00;
  CHECK_EQ(sff::crc32_ieee(&zero, 1), 0xD202EF8Du);
  const std::uint8_t all_ones = 0xFF;
  CHECK_EQ(sff::crc32_ieee(&all_ones, 1), 0xFF000000u);

  std::uint8_t ascending[16] = {0};
  for (std::size_t index = 0; index < 16; ++index) {
    ascending[index] = static_cast<std::uint8_t>(index);
  }
  CHECK_EQ(sff::crc32_ieee(ascending, sizeof(ascending)), 0xCECEE288u);

  // The empty range is the empty digest whatever pointer carries it.
  CHECK_EQ(sff::crc32_ieee(ascending, 0), 0x00000000u);
  CHECK_EQ(sff::crc32_ieee(nullptr, 0), 0x00000000u);
}

// ---------------------------------------------------------------------------------------------
// Sensitivity
// ---------------------------------------------------------------------------------------------

SFF_TEST(crc32_is_order_sensitive_and_detects_every_single_bit_flip) {
  const std::uint8_t baseline_bytes[8] = {'s', 'f', 'f', ':', '1', '2', '3', '4'};
  const std::uint32_t baseline = sff::crc32_ieee(baseline_bytes, sizeof(baseline_bytes));

  std::uint8_t swapped[8] = {0};
  for (std::size_t index = 0; index < 8; ++index) swapped[index] = baseline_bytes[index];
  const std::uint8_t first = swapped[0];
  swapped[0] = swapped[1];
  swapped[1] = first;
  CHECK(sff::crc32_ieee(swapped, sizeof(swapped)) != baseline);
  CHECK_EQ(sff::crc32_ieee(baseline_bytes, sizeof(baseline_bytes)), baseline);

  std::size_t detected = 0;
  std::size_t restored = 0;
  for (std::size_t bit = 0; bit < 64; ++bit) {
    std::uint8_t mutated[8] = {0};
    for (std::size_t index = 0; index < 8; ++index) mutated[index] = baseline_bytes[index];
    const std::uint8_t mask = static_cast<std::uint8_t>(1u << (bit % 8));
    mutated[bit / 8] = static_cast<std::uint8_t>(mutated[bit / 8] ^ mask);
    if (sff::crc32_ieee(mutated, sizeof(mutated)) != baseline) detected += 1;
    // Flipping the same bit back must reproduce the original digest exactly, which proves the
    // mutation above was a single-bit change and not an accidental truncation.
    mutated[bit / 8] = static_cast<std::uint8_t>(mutated[bit / 8] ^ mask);
    if (sff::crc32_ieee(mutated, sizeof(mutated)) == baseline) restored += 1;
  }
  CHECK_EQ(detected, std::size_t{64});
  CHECK_EQ(restored, std::size_t{64});

  std::uint8_t truncated[7] = {0};
  for (std::size_t index = 0; index < 7; ++index) truncated[index] = baseline_bytes[index];
  CHECK(sff::crc32_ieee(truncated, sizeof(truncated)) != baseline);
}

SFF_TEST(crc32_seed_round_trips_across_an_arbitrary_split) {
  sfftest::Rng rng(0x5ffc0c0aull);
  std::vector<std::uint8_t> data(64);
  for (std::size_t index = 0; index < data.size(); ++index) {
    data[index] = static_cast<std::uint8_t>(rng.bounded(256));
  }
  const std::uint32_t whole = sff::crc32_ieee(data);

  for (std::size_t split = 0; split <= data.size(); ++split) {
    const std::uint32_t head = sff::crc32_ieee(data.data(), split);
    const std::uint32_t resumed =
        sff::crc32_ieee(data.data() + split, data.size() - split, head);
    CHECK_EQ(resumed, whole);  // the seed continues the digest instead of restarting it
  }

  // The default seed is the documented zero seed, and a different seed really does change the
  // result.
  CHECK_EQ(sff::crc32_ieee(data.data(), data.size()), sff::crc32_ieee(data.data(), data.size(), 0u));
  CHECK(sff::crc32_ieee(data.data(), data.size(), 1u) != whole);
  CHECK(sff::crc32_ieee(data.data(), data.size(), 0xFFFFFFFFu) != whole);

  // Continuing an empty range leaves the running digest untouched.
  CHECK_EQ(sff::crc32_ieee(data.data(), 0, whole), whole);
  CHECK_EQ(sff::crc32_ieee(data.data(), 0, 0x1234ABCDu), 0x1234ABCDu);

  // A single flipped bit anywhere in the buffer changes the whole-buffer digest.
  for (std::size_t index = 0; index < data.size(); index += 7) {
    std::vector<std::uint8_t> mutated = data;
    mutated[index] = static_cast<std::uint8_t>(mutated[index] ^ 0x80u);
    CHECK(sff::crc32_ieee(mutated) != whole);
  }
}

SFF_TEST(digest128_detects_every_byte_change_and_every_length_change) {
  std::vector<std::uint8_t> baseline_bytes(24);
  for (std::size_t index = 0; index < baseline_bytes.size(); ++index) {
    baseline_bytes[index] = static_cast<std::uint8_t>(index * 7 + 1);
  }
  const Digest128 baseline = sff::digest128_of(baseline_bytes);

  std::size_t detected = 0;
  for (std::size_t position = 0; position < baseline_bytes.size(); ++position) {
    for (int value = 0; value < 256; ++value) {
      if (static_cast<std::uint8_t>(value) == baseline_bytes[position]) continue;
      std::vector<std::uint8_t> mutated = baseline_bytes;
      mutated[position] = static_cast<std::uint8_t>(value);
      if (digests_differ(sff::digest128_of(mutated), baseline)) detected += 1;
    }
  }
  CHECK_EQ(detected, baseline_bytes.size() * 255);

  // Length is part of the digest: truncation, extension and re-splitting all differ.
  CHECK(digests_differ(sff::digest128_of(baseline_bytes.data(), baseline_bytes.size() - 1),
                       baseline));
  CHECK(digests_differ(sff::digest128_of(baseline_bytes.data(), 0), baseline));
  std::vector<std::uint8_t> extended = baseline_bytes;
  extended.push_back(0);
  CHECK(digests_differ(sff::digest128_of(extended), baseline));
  std::vector<std::uint8_t> reversed(baseline_bytes.rbegin(), baseline_bytes.rend());
  CHECK(digests_differ(sff::digest128_of(reversed), baseline));

  // Order within the same bytes matters, and the vector overload agrees with the pointer one.
  CHECK_EQ(sff::digest128_of(baseline_bytes).to_hex(),
           sff::digest128_of(baseline_bytes.data(), baseline_bytes.size()).to_hex());
  CHECK_EQ(sff::to_hex(baseline), baseline.to_hex());
  CHECK_EQ(baseline.to_hex().size(), std::size_t{32});

  // The empty range leaves the documented initial accumulator untouched.
  const Digest128 pristine;
  const Digest128 empty = sff::digest128_of(baseline_bytes.data(), 0);
  CHECK_EQ(empty.hi, pristine.hi);
  CHECK_EQ(empty.lo, pristine.lo);
  CHECK_EQ(sff::digest128_of(std::vector<std::uint8_t>{}).to_hex(), pristine.to_hex());
}

SFF_MAIN()
