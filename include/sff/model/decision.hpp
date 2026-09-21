// Switch Failover Fabric - decisions, scopes and bounded explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_DECISION_HPP
#define SFF_MODEL_DECISION_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"
#include "sff/version.hpp"
#include "sff/export.hpp"

namespace sff {

enum class DecisionKind : std::uint8_t {
  Unknown = 0,
  SwitchFailure = 1,
  FenceCommit = 2,
  ClosureComputation = 3,
  ReplacementEligibility = 4,
  ReconstructionPlan = 5,
  PlanValidation = 6,
  ApplyEffect = 7,
  ServiceRestore = 8,
  AuthorityQuery = 9,
  RestartReconciliation = 10,
  EvidenceAdmission = 11,
};

SFF_API const char* to_string(DecisionKind kind) noexcept;

enum class DecisionSubjectKind : std::uint8_t {
  None = 0,
  Switch = 1,
  Dependent = 2,
  Plan = 3,
  Runtime = 4,
};

SFF_API const char* to_string(DecisionSubjectKind kind) noexcept;

/// The exact subject a decision applies to. Matching is always structural; the descriptive
/// label is never used for identity.
struct SFF_API DecisionScope {
  DecisionSubjectKind kind = DecisionSubjectKind::None;
  SwitchKey subject;
  DependentRef dependent;
  PlanId plan;
  std::string label;

  static DecisionScope of_switch(const SwitchKey& key, std::string_view label = {});
  static DecisionScope of_dependent(const DependentRef& dependent, std::string_view label = {});
  static DecisionScope of_plan(PlanId plan, std::string_view label = {});
  static DecisionScope of_runtime(std::string_view label = {});

  bool valid() const noexcept;
  std::uint64_t digest() const noexcept;
  std::string to_string() const;
};

/// One bounded key/value term of an explanation.
struct SFF_API ExplanationTerm {
  std::string key;
  std::string value;
};

/// Bounded explanation. Growth is refused past the configured term budget and the truncation
/// is reported rather than hidden.
class SFF_API Explanation {
 public:
  Explanation() = default;
  explicit Explanation(std::size_t term_limit);

  Explanation& add(std::string_view key, std::string_view value);
  Explanation& add_u64(std::string_view key, std::uint64_t value);
  Explanation& add_bool(std::string_view key, bool value);
  Explanation& add_code(std::string_view key, Code code);
  Explanation& add_key(std::string_view key, const SwitchKey& switch_key);
  Explanation& add_dependent(std::string_view key, const DependentRef& dependent);

  const std::vector<ExplanationTerm>& terms() const noexcept { return terms_; }
  std::size_t size() const noexcept { return terms_.size(); }
  std::size_t limit() const noexcept { return limit_; }
  bool truncated() const noexcept { return truncated_; }

  std::string canonical() const;
  std::uint64_t digest() const noexcept;

 private:
  std::vector<ExplanationTerm> terms_;
  std::size_t limit_ = 64;
  bool truncated_ = false;
};

/// An externally visible decision. Every field required by the boundary is present:
/// the exact scope, the binding generations, the resolving codes, and bounded explanation data.
struct SFF_API Decision {
  DecisionId id;
  DecisionKind kind = DecisionKind::Unknown;
  DecisionScope scope;
  Code outcome = Code::Unknown;
  Code reason = Code::Unknown;
  GenerationVector bound;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  EvidenceClass evidence_class = EvidenceClass::Unsupported;
  Explanation explanation;
  TimestampNs recorded_at_ns = 0;

  std::uint64_t digest() const noexcept;
  std::string to_string() const;
};

/// Bounded retention of recent decisions. This is an audit surface: decision history is not
/// authority, and eviction is reported.
class SFF_API DecisionLog {
 public:
  explicit DecisionLog(std::size_t capacity = 1024);

  void append(Decision decision);
  std::vector<Decision> tail(std::size_t count) const;
  std::size_t size() const;
  std::size_t capacity() const;
  std::uint64_t dropped() const;
  std::uint64_t last_id() const;
  void clear();

 private:
  mutable std::mutex mutex_;
  std::deque<Decision> decisions_;
  std::size_t capacity_;
  std::uint64_t next_id_ = 1;
  std::uint64_t dropped_ = 0;
};

}  // namespace sff

#endif  // SFF_MODEL_DECISION_HPP
