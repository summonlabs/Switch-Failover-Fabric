// Switch Failover Fabric - switch descriptors and capabilities.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/switch.hpp"

namespace sff {

const char* to_string(SwitchRole role) noexcept {
  switch (role) {
    case SwitchRole::Unknown: return "UNKNOWN";
    case SwitchRole::Leaf: return "LEAF";
    case SwitchRole::Spine: return "SPINE";
    case SwitchRole::TopOfRack: return "TOR";
    case SwitchRole::Core: return "CORE";
    case SwitchRole::Edge: return "EDGE";
  }
  return "UNRECOGNISED_SWITCH_ROLE";
}

bool is_valid_switch_role(std::uint8_t raw) noexcept {
  return raw <= static_cast<std::uint8_t>(SwitchRole::Edge);
}

const char* to_string(SwitchAdminState state) noexcept {
  switch (state) {
    case SwitchAdminState::Unknown: return "UNKNOWN";
    case SwitchAdminState::Enabled: return "ENABLED";
    case SwitchAdminState::Disabled: return "DISABLED";
    case SwitchAdminState::Maintenance: return "MAINTENANCE";
  }
  return "UNRECOGNISED_ADMIN_STATE";
}

bool is_valid_admin_state(std::uint8_t raw) noexcept {
  return raw <= static_cast<std::uint8_t>(SwitchAdminState::Maintenance);
}

const char* to_string(SwitchHealthState state) noexcept {
  switch (state) {
    case SwitchHealthState::Unknown: return "UNKNOWN";
    case SwitchHealthState::Healthy: return "HEALTHY";
    case SwitchHealthState::Degraded: return "DEGRADED";
    case SwitchHealthState::Unreachable: return "UNREACHABLE";
    case SwitchHealthState::Suspect: return "SUSPECT";
    case SwitchHealthState::Failed: return "FAILED";
    case SwitchHealthState::Recovering: return "RECOVERING";
  }
  return "UNRECOGNISED_HEALTH_STATE";
}

bool is_valid_health_state(std::uint8_t raw) noexcept {
  return raw <= static_cast<std::uint8_t>(SwitchHealthState::Recovering);
}

const char* to_string(Capability capability) noexcept {
  switch (capability) {
    case Capability::None: return "NONE";
    case Capability::Layer2: return "L2";
    case Capability::Layer3: return "L3";
    case Capability::Vxlan: return "VXLAN";
    case Capability::Roce: return "ROCE";
    case Capability::LosslessPfc: return "PFC";
    case Capability::EcnMarking: return "ECN";
    case Capability::Ecmp: return "ECMP";
    case Capability::HighRadix: return "HIGH_RADIX";
    case Capability::Telemetry: return "TELEMETRY";
    case Capability::ProgrammablePipeline: return "PROGRAMMABLE";
  }
  return "UNRECOGNISED_CAPABILITY";
}

bool is_valid_capability(std::uint32_t raw) noexcept {
  if (raw == 0) return false;
  if ((raw & (raw - 1u)) != 0u) return false;  // not a single bit
  return (raw & kAllCapabilities) == raw;
}

bool has_capability(CapabilityMask mask, Capability capability) noexcept {
  return (mask & capability_bit(capability)) != 0u;
}

bool has_all_capabilities(CapabilityMask mask, CapabilityMask required) noexcept {
  return (mask & required) == required;
}

std::string capabilities_to_string(CapabilityMask mask) {
  if (mask == 0) return "NONE";
  static const Capability kOrder[] = {
      Capability::Layer2,       Capability::Layer3,       Capability::Vxlan,
      Capability::Roce,         Capability::LosslessPfc,  Capability::EcnMarking,
      Capability::Ecmp,         Capability::HighRadix,    Capability::Telemetry,
      Capability::ProgrammablePipeline,
  };
  std::string result;
  for (const Capability capability : kOrder) {
    if (!has_capability(mask, capability)) continue;
    if (!result.empty()) result += "|";
    result += to_string(capability);
  }
  return result;
}

Status validate_capability_mask(CapabilityMask mask) {
  if ((mask & ~kAllCapabilities) != 0u) {
    return Status::failure(Code::Invalid, "capability mask contains undefined bits");
  }
  return Status::success();
}

std::uint64_t SwitchDescriptor::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.switch-descriptor.v1");
  digest.absorb_key(key);
  digest.absorb_byte(static_cast<std::uint8_t>(role));
  digest.absorb_byte(static_cast<std::uint8_t>(admin));
  digest.absorb_u64(failure_domain.raw());
  digest.absorb_u64(capabilities);
  digest.absorb_u64(port_count);
  digest.absorb_u64(max_radix);
  digest.absorb_u64(capacity_score);
  digest.absorb_string(label);
  return digest.hi;
}

Status SwitchDescriptor::validate() const {
  if (!key.valid()) {
    return Status::failure(Code::Invalid, "switch descriptor carries an unqualified generation");
  }
  if (!is_valid_switch_role(static_cast<std::uint8_t>(role))) {
    return Status::failure(Code::Invalid, "switch descriptor has an invalid role");
  }
  if (!is_valid_admin_state(static_cast<std::uint8_t>(admin))) {
    return Status::failure(Code::Invalid, "switch descriptor has an invalid admin state");
  }
  Status s = validate_capability_mask(capabilities);
  if (!s.ok()) return s;
  if (port_count == 0) {
    return Status::failure(Code::Invalid, "switch descriptor declares zero ports");
  }
  if (key.id().valid() != failure_domain.valid()) {
    // A switch with no failure domain is admissible; a failure domain without a switch is not.
    if (failure_domain.valid() && !key.id().valid()) {
      return Status::failure(Code::Invalid, "failure domain without a switch identity");
    }
  }
  return Status::success();
}

}  // namespace sff
