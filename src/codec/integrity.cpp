// Switch Failover Fabric - non-cryptographic integrity primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/codec/integrity.hpp"

#include <array>

namespace sff {
namespace {

constexpr std::array<std::uint32_t, 256> make_crc_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < 256; ++index) {
    std::uint32_t value = index;
    for (int bit = 0; bit < 8; ++bit) {
      value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
    }
    table[index] = value;
  }
  return table;
}

constexpr auto kCrcTable = make_crc_table();

}  // namespace

std::uint32_t crc32_ieee(const void* data, std::size_t size, std::uint32_t seed) noexcept {
  std::uint32_t crc = ~seed;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  if (bytes != nullptr) {
    for (std::size_t index = 0; index < size; ++index) {
      crc = kCrcTable[(crc ^ bytes[index]) & 0xffu] ^ (crc >> 8);
    }
  }
  return ~crc;
}

std::uint32_t crc32_ieee(const std::vector<std::uint8_t>& data, std::uint32_t seed) noexcept {
  return crc32_ieee(data.data(), data.size(), seed);
}

Digest128 digest128_of(const void* data, std::size_t size) noexcept {
  Digest128 digest;
  digest.absorb_bytes(data, size);
  return digest;
}

Digest128 digest128_of(const std::vector<std::uint8_t>& data) noexcept {
  return digest128_of(data.data(), data.size());
}

std::string to_hex(std::uint64_t value, int width) {
  static const char* digits = "0123456789abcdef";
  std::string result;
  const int bounded_width = width <= 0 ? 16 : (width > 16 ? 16 : width);
  result.reserve(static_cast<std::size_t>(bounded_width));
  for (int index = bounded_width - 1; index >= 0; --index) {
    result.push_back(digits[(value >> (4 * index)) & 0xfu]);
  }
  return result;
}

std::string to_hex(const Digest128& digest) { return digest.to_hex(); }

}  // namespace sff
