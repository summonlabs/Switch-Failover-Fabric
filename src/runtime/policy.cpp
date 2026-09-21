// Switch Failover Fabric - runtime policy.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/runtime/policy.hpp"

#include "sff/codec/bytes.hpp"

namespace sff {
namespace {
constexpr std::uint8_t kPolicyFormatTag = 1;
}

Status Policy::validate() const {
  if (format_version != 1) {
    return Status::failure(Code::VersionMismatch, "policy format version is not supported");
  }
  if (grant_ttl_ns == 0) {
    return Status::failure(Code::Invalid, "grant_ttl_ns must be positive");
  }
  if (max_retained_plans == 0 || max_retained_plans > kHardMaxElements) {
    return Status::failure(Code::Invalid, "max_retained_plans is outside the supported range");
  }
  if (planning.max_candidates_per_dependent == 0 ||
      planning.max_candidates_per_dependent > kHardMaxElements) {
    return Status::failure(Code::Invalid,
                           "max_candidates_per_dependent is outside the supported range");
  }
  if (allow_acknowledgement_restore && require_verified_effect_for_restore) {
    return Status::failure(
        Code::Invalid,
        "acknowledgement-only restore contradicts the verified-effect requirement");
  }
  return Status::success();
}

std::uint64_t Policy::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.policy.v1");
  digest.absorb_u64(format_version);
  digest.absorb_byte(assessment.fence_on_authoritative_conflict ? 1 : 0);
  digest.absorb_byte(assessment.fence_on_missing_health ? 1 : 0);
  digest.absorb_byte(assessment.allow_same_generation_recovery ? 1 : 0);
  digest.absorb_byte(assessment.require_authoritative_failure_evidence ? 1 : 0);
  digest.absorb_u64(assessment.future_skew_tolerance_ns);
  digest.absorb_u64(planning.digest());
  digest.absorb_byte(require_verified_effect_for_restore ? 1 : 0);
  digest.absorb_byte(allow_acknowledgement_restore ? 1 : 0);
  digest.absorb_byte(allow_restore_when_closure_truncated ? 1 : 0);
  digest.absorb_byte(fence_on_restart ? 1 : 0);
  digest.absorb_u64(grant_ttl_ns);
  digest.absorb_u64(max_retained_plans);
  return digest.hi;
}

std::vector<std::uint8_t> Policy::encode() const {
  ByteWriter writer;
  writer.u8(kPolicyFormatTag);
  writer.u32(format_version);
  writer.boolean(assessment.fence_on_authoritative_conflict);
  writer.boolean(assessment.fence_on_missing_health);
  writer.boolean(assessment.allow_same_generation_recovery);
  writer.boolean(assessment.require_authoritative_failure_evidence);
  writer.u64(assessment.future_skew_tolerance_ns);
  writer.boolean(planning.allow_replacement_in_same_failure_domain);
  writer.boolean(planning.require_capability_superset);
  writer.boolean(planning.require_authoritative_candidate_evidence);
  writer.boolean(planning.allow_withhold_on_unresolved);
  writer.boolean(planning.allow_restore_when_closure_truncated);
  writer.u32(planning.max_candidates_per_dependent);
  writer.boolean(require_verified_effect_for_restore);
  writer.boolean(allow_acknowledgement_restore);
  writer.boolean(allow_restore_when_closure_truncated);
  writer.boolean(fence_on_restart);
  writer.u64(grant_ttl_ns);
  writer.u64(max_retained_plans);
  return writer.bytes();
}

Result<Policy> Policy::decode(const std::vector<std::uint8_t>& bytes) {
  ByteReader reader(bytes);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPolicyFormatTag) {
    return Status::failure(Code::VersionMismatch, "policy format tag is unsupported");
  }
  Policy policy;
  policy.format_version = reader.u32();
  policy.assessment.fence_on_authoritative_conflict = reader.boolean();
  policy.assessment.fence_on_missing_health = reader.boolean();
  policy.assessment.allow_same_generation_recovery = reader.boolean();
  policy.assessment.require_authoritative_failure_evidence = reader.boolean();
  policy.assessment.future_skew_tolerance_ns = reader.u64();
  policy.planning.allow_replacement_in_same_failure_domain = reader.boolean();
  policy.planning.require_capability_superset = reader.boolean();
  policy.planning.require_authoritative_candidate_evidence = reader.boolean();
  policy.planning.allow_withhold_on_unresolved = reader.boolean();
  policy.planning.allow_restore_when_closure_truncated = reader.boolean();
  policy.planning.max_candidates_per_dependent = reader.u32();
  policy.require_verified_effect_for_restore = reader.boolean();
  policy.allow_acknowledgement_restore = reader.boolean();
  policy.allow_restore_when_closure_truncated = reader.boolean();
  policy.fence_on_restart = reader.boolean();
  policy.grant_ttl_ns = reader.u64();
  policy.max_retained_plans = static_cast<std::size_t>(reader.u64());
  Status end = reader.require_end();
  if (!end.ok()) return end;
  Status valid = policy.validate();
  if (!valid.ok()) return valid;
  return policy;
}

}  // namespace sff
