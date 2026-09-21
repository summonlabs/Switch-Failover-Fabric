// Switch Failover Fabric - generation vectors and failure lineage.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/generation.hpp"

#include <algorithm>
#include <iterator>

namespace sff {

GenerationVector GenerationVector::canonicalise(std::vector<SwitchKey> keys) {
  keys.erase(std::remove_if(keys.begin(), keys.end(),
                            [](const SwitchKey& key) { return !key.valid(); }),
             keys.end());
  std::sort(keys.begin(), keys.end());
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
  GenerationVector result;
  result.keys_ = std::move(keys);
  return result;
}

bool GenerationVector::contains(const SwitchKey& key) const noexcept {
  return std::binary_search(keys_.begin(), keys_.end(), key);
}

bool GenerationVector::contains_identity_deliberately(SwitchId id) const noexcept {
  for (const auto& key : keys_) {
    if (key.id() == id) return true;
  }
  return false;
}

bool GenerationVector::contains_all(const GenerationVector& other) const noexcept {
  for (const auto& key : other.keys_) {
    if (!contains(key)) return false;
  }
  return true;
}

bool GenerationVector::intersects(const GenerationVector& other) const noexcept {
  std::size_t left = 0;
  std::size_t right = 0;
  while (left < keys_.size() && right < other.keys_.size()) {
    if (keys_[left] == other.keys_[right]) return true;
    if (keys_[left] < other.keys_[right]) {
      ++left;
    } else {
      ++right;
    }
  }
  return false;
}

bool GenerationVector::insert(const SwitchKey& key) {
  if (!key.valid()) return false;
  const auto position = std::lower_bound(keys_.begin(), keys_.end(), key);
  if (position != keys_.end() && *position == key) return false;
  keys_.insert(position, key);
  return true;
}

GenerationVector GenerationVector::united(const GenerationVector& other) const {
  std::vector<SwitchKey> merged;
  merged.reserve(keys_.size() + other.keys_.size());
  std::set_union(keys_.begin(), keys_.end(), other.keys_.begin(), other.keys_.end(),
                 std::back_inserter(merged));
  return canonicalise(std::move(merged));
}

GenerationVector GenerationVector::intersected(const GenerationVector& other) const {
  std::vector<SwitchKey> merged;
  merged.reserve(std::min(keys_.size(), other.keys_.size()));
  std::set_intersection(keys_.begin(), keys_.end(), other.keys_.begin(), other.keys_.end(),
                        std::back_inserter(merged));
  return canonicalise(std::move(merged));
}

GenerationVector GenerationVector::without_identity(SwitchId id) const {
  std::vector<SwitchKey> kept;
  kept.reserve(keys_.size());
  for (const auto& key : keys_) {
    if (key.id() != id) kept.push_back(key);
  }
  return canonicalise(std::move(kept));
}

std::uint64_t GenerationVector::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.generation-vector.v1");
  digest.absorb_u64(static_cast<std::uint64_t>(keys_.size()));
  for (const auto& key : keys_) digest.absorb_key(key);
  return digest.hi;
}

std::string GenerationVector::to_string() const {
  std::string result = "[";
  for (std::size_t index = 0; index < keys_.size(); ++index) {
    if (index != 0) result += ",";
    result += keys_[index].to_string();
  }
  result += "]";
  return result;
}

std::uint64_t FailureRecord::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.failure-record.v1");
  digest.absorb_key(subject);
  digest.absorb_u64(evidence.raw());
  digest.absorb_u64(epoch.raw());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_u64(boot.process_id());
  digest.absorb_u64(observed_at_ns);
  digest.absorb_u64(recorded_at_ns);
  digest.absorb_string(reason);
  return digest.hi;
}

}  // namespace sff
