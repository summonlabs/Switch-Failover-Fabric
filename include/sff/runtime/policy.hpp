// Switch Failover Fabric - runtime policy.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_RUNTIME_POLICY_HPP
#define SFF_RUNTIME_POLICY_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/evidence.hpp"
#include "sff/plan/planner.hpp"
#include "sff/export.hpp"

namespace sff {

/// Runtime policy. Defaults are deliberately fail-closed: every knob that could convert an
/// unproven state into affirmative authority defaults to refusing.
struct SFF_API Policy {
  std::uint32_t format_version = 1;

  AssessmentPolicy assessment{};
  PlanningPolicy planning{};

  /// Service restoration requires verified forwarding effect, not merely an acknowledgement.
  bool require_verified_effect_for_restore = true;

  /// Allow restoration on acknowledgement alone. Off by default; when enabled, restoration is
  /// reported as Unverified rather than Ok.
  bool allow_acknowledgement_restore = false;

  /// Allow restoration when the dependency closure was truncated. Off by default: an incomplete
  /// closure cannot prove that every dependent is safe.
  bool allow_restore_when_closure_truncated = false;

  /// Fence every grant minted before the current boot instead of merely marking it stale.
  bool fence_on_restart = false;

  /// Validity window for newly minted authority grants.
  std::uint64_t grant_ttl_ns = 30ull * kNanosPerSecond;

  /// Retain at most this many pre-restart plans as history.
  std::size_t max_retained_plans = 256;

  Status validate() const;
  std::uint64_t digest() const noexcept;

  std::vector<std::uint8_t> encode() const;
  static Result<Policy> decode(const std::vector<std::uint8_t>& bytes);
};

}  // namespace sff

#endif  // SFF_RUNTIME_POLICY_HPP
