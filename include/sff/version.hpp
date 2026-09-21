// Switch Failover Fabric - version identity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_VERSION_HPP
#define SFF_VERSION_HPP

#include <cstdint>

#include "sff/export.hpp"

namespace sff {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// Single monotonic integer used for durable-format gating and frame negotiation.
inline constexpr std::uint32_t kVersionCode = (kVersionMajor << 16) | (kVersionMinor << 8) | kVersionPatch;

inline constexpr const char* kVersionString = "1.0.0";
inline constexpr const char* kProductName = "Switch Failover Fabric";
inline constexpr const char* kProductShortName = "SFF";

/// Explicit provenance tag. Never inferred, always carried with a claim.
enum class EvidenceClass : std::uint8_t {
  Real = 0,
  Synthetic = 1,
  Unsupported = 2,
};

SFF_API const char* to_string(EvidenceClass value) noexcept;

}  // namespace sff

#endif  // SFF_VERSION_HPP
