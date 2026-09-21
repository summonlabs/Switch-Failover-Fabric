// Switch Failover Fabric - non-cryptographic integrity primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CODEC_INTEGRITY_HPP
#define SFF_CODEC_INTEGRITY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/export.hpp"

namespace sff {

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), used for frame and record integrity.
///
/// This is an integrity check, not a security control. The transport boundary documented in
/// README.md is explicitly unauthenticated; CRC-32 detects corruption and accidental truncation.
SFF_API std::uint32_t crc32_ieee(const void* data, std::size_t size, std::uint32_t seed = 0) noexcept;

/// CRC-32 over a byte vector.
SFF_API std::uint32_t crc32_ieee(const std::vector<std::uint8_t>& data, std::uint32_t seed = 0) noexcept;

/// Canonical 128-bit digest of a byte range.
SFF_API Digest128 digest128_of(const void* data, std::size_t size) noexcept;

/// Canonical 128-bit digest of a byte vector.
SFF_API Digest128 digest128_of(const std::vector<std::uint8_t>& data) noexcept;

/// Lower-case hexadecimal rendering, fixed width.
SFF_API std::string to_hex(std::uint64_t value, int width = 16);
SFF_API std::string to_hex(const Digest128& digest);

}  // namespace sff

#endif  // SFF_CODEC_INTEGRITY_HPP
