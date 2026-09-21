// Switch Failover Fabric - generation-qualified switch descriptors and capabilities.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_SWITCH_HPP
#define SFF_MODEL_SWITCH_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Structural role of a switch in the fabric. Descriptive only: role never confers authority.
enum class SwitchRole : std::uint8_t {
  Unknown = 0,
  Leaf = 1,
  Spine = 2,
  TopOfRack = 3,
  Core = 4,
  Edge = 5,
};

SFF_API const char* to_string(SwitchRole role) noexcept;
SFF_API bool is_valid_switch_role(std::uint8_t raw) noexcept;

/// Administrative state as declared by the fabric authority.
enum class SwitchAdminState : std::uint8_t {
  Unknown = 0,
  Enabled = 1,
  Disabled = 2,
  Maintenance = 3,
};

SFF_API const char* to_string(SwitchAdminState state) noexcept;
SFF_API bool is_valid_admin_state(std::uint8_t raw) noexcept;

/// Observed health of a switch generation. Absence of observation is Unknown, never Healthy.
enum class SwitchHealthState : std::uint8_t {
  Unknown = 0,
  Healthy = 1,
  Degraded = 2,
  Unreachable = 3,
  Suspect = 4,
  Failed = 5,
  Recovering = 6,
};

SFF_API const char* to_string(SwitchHealthState state) noexcept;
SFF_API bool is_valid_health_state(std::uint8_t raw) noexcept;

/// Switching capability bits. Replacement eligibility is computed over these, and they are
/// always carried by a generation-qualified descriptor, never by a bare switch identity.
enum class Capability : std::uint32_t {
  None = 0,
  Layer2 = 1u << 0,
  Layer3 = 1u << 1,
  Vxlan = 1u << 2,
  Roce = 1u << 3,
  LosslessPfc = 1u << 4,
  EcnMarking = 1u << 5,
  Ecmp = 1u << 6,
  HighRadix = 1u << 7,
  Telemetry = 1u << 8,
  ProgrammablePipeline = 1u << 9,
};

using CapabilityMask = std::uint32_t;

constexpr CapabilityMask capability_bit(Capability capability) noexcept {
  return static_cast<CapabilityMask>(capability);
}

SFF_API const char* to_string(Capability capability) noexcept;
SFF_API bool is_valid_capability(std::uint32_t raw) noexcept;

/// All capability bits this release defines.
inline constexpr CapabilityMask kAllCapabilities =
    capability_bit(Capability::Layer2) | capability_bit(Capability::Layer3) |
    capability_bit(Capability::Vxlan) | capability_bit(Capability::Roce) |
    capability_bit(Capability::LosslessPfc) | capability_bit(Capability::EcnMarking) |
    capability_bit(Capability::Ecmp) | capability_bit(Capability::HighRadix) |
    capability_bit(Capability::Telemetry) | capability_bit(Capability::ProgrammablePipeline);

SFF_API bool has_capability(CapabilityMask mask, Capability capability) noexcept;
SFF_API bool has_all_capabilities(CapabilityMask mask, CapabilityMask required) noexcept;
SFF_API std::string capabilities_to_string(CapabilityMask mask);
SFF_API Status validate_capability_mask(CapabilityMask mask);

/// Generation-qualified description of one switch incarnation.
struct SFF_API SwitchDescriptor {
  SwitchKey key;
  SwitchRole role = SwitchRole::Unknown;
  SwitchAdminState admin = SwitchAdminState::Unknown;
  FailureDomainId failure_domain;
  CapabilityMask capabilities = 0;
  std::uint32_t port_count = 0;
  std::uint32_t max_radix = 0;
  std::uint32_t capacity_score = 100;  ///< Higher is more spare capacity.
  std::string label;                   ///< Descriptive only; never used for matching.

  bool valid() const noexcept { return key.valid(); }
  std::uint64_t digest() const noexcept;
  Status validate() const;
};

/// Externally supplied capability evidence, always bound to the generation it describes.
///
/// Capability asserted for generation G is not capability for generation G+1. A candidate whose
/// descriptor generation differs from the capability evidence generation is STALE, never
/// silently eligible.
struct SFF_API CapabilityEvidence {
  /// Opaque source marker supplied by the caller's evidence pipeline. Values are compared for
  /// equality only; this runtime does not interpret them.
  using SourceTag = std::uint32_t;

  SwitchKey key;
  CapabilityMask capabilities = 0;
  std::uint32_t capacity_score = 0;
  FailureDomainId failure_domain;
  EvidenceId evidence;
  SourceTag source_tag = 0;
};

}  // namespace sff

#endif  // SFF_MODEL_SWITCH_HPP
