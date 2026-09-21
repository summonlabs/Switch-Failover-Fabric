// Switch Failover Fabric - generation vectors and generation-qualified authority binding.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_GENERATION_HPP
#define SFF_MODEL_GENERATION_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Ordered, deduplicated set of generation-qualified switch keys.
///
/// This is the unit of authority binding. A decision that depends on switches carries a
/// GenerationVector; the decision is legal only while every member is still current and
/// affirmative. Matching a SwitchId without its generation is never performed implicitly -
/// callers must ask for identity-only matching explicitly and are told so by the method name.
class SFF_API GenerationVector {
 public:
  GenerationVector() = default;

  /// Canonicalise an arbitrary sequence: sorts by (id, generation) and removes duplicates.
  static GenerationVector canonicalise(std::vector<SwitchKey> keys);

  bool empty() const noexcept { return keys_.empty(); }
  std::size_t size() const noexcept { return keys_.size(); }
  const std::vector<SwitchKey>& keys() const noexcept { return keys_; }

  /// Exact generation-qualified membership.
  bool contains(const SwitchKey& key) const noexcept;

  /// Identity-only membership. Deliberately named so that callers cannot mistake it for an
  /// exact generation match.
  bool contains_identity_deliberately(SwitchId id) const noexcept;

  bool contains_all(const GenerationVector& other) const noexcept;
  bool intersects(const GenerationVector& other) const noexcept;

  /// Insert preserving canonical order. Returns false when the key was already present.
  bool insert(const SwitchKey& key);

  GenerationVector united(const GenerationVector& other) const;
  GenerationVector intersected(const GenerationVector& other) const;

  /// Remove every key whose identity matches, regardless of generation.
  GenerationVector without_identity(SwitchId id) const;

  std::uint64_t digest() const noexcept;
  std::string to_string() const;

  friend bool operator==(const GenerationVector& a, const GenerationVector& b) noexcept {
    return a.keys_ == b.keys_;
  }
  friend bool operator!=(const GenerationVector& a, const GenerationVector& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const GenerationVector& a, const GenerationVector& b) noexcept {
    return a.keys_ < b.keys_;
  }

 private:
  std::vector<SwitchKey> keys_;
};

/// A durable, generation-bound assertion that a switch generation reached a terminal condition.
///
/// Failure lineage is durable: a restart must never un-fail a switch. The record is superseded
/// only by an authoritative recovery declaration that arrives strictly later.
struct SFF_API FailureRecord {
  SwitchKey subject;
  EvidenceId evidence;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  TimestampNs observed_at_ns = 0;
  TimestampNs recorded_at_ns = 0;
  std::string reason;

  std::uint64_t digest() const noexcept;
};

}  // namespace sff

#endif  // SFF_MODEL_GENERATION_HPP
