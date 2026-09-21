// Switch Failover Fabric - evidence admission and fail-closed adjudication.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_EVIDENCE_HPP
#define SFF_MODEL_EVIDENCE_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"
#include "sff/model/switch.hpp"
#include "sff/export.hpp"

namespace sff {

/// Origin of an evidence record. Trust is a pure function of the origin; it is never asserted
/// by the record itself.
enum class EvidenceSource : std::uint8_t {
  Unknown = 0,
  SimulatedFixture = 1,   ///< Deterministic synthetic input supplied by a test or harness.
  TelemetryCollector = 2, ///< Passive sampling. Advisory only: silence is not failure.
  SwitchAgent = 3,        ///< On-switch agent. Advisory.
  TopologyService = 4,    ///< Authoritative for structure, not for liveness.
  FabricManager = 5,      ///< Authoritative for switch lifecycle.
  OperatorPolicy = 6,     ///< Authoritative human/policy declaration.
};

SFF_API const char* to_string(EvidenceSource source) noexcept;
SFF_API bool is_valid_evidence_source(std::uint8_t raw) noexcept;

enum class TrustLevel : std::uint8_t {
  Untrusted = 0,
  Advisory = 1,
  Authoritative = 2,
};

SFF_API const char* to_string(TrustLevel level) noexcept;
SFF_API TrustLevel trust_of(EvidenceSource source) noexcept;

enum class EvidenceKind : std::uint8_t {
  Unknown = 0,
  SwitchHealth = 1,               ///< Advisory observation of a switch generation.
  SwitchFailureDeclaration = 2,   ///< Authoritative assertion that a generation is unusable.
  SwitchRecoveryDeclaration = 3,  ///< Authoritative assertion that a generation is usable again.
  CapabilityDeclaration = 4,      ///< Generation-qualified capability of a switch.
  AdminStateDeclaration = 5,      ///< Administrative enable/disable/maintenance.
  EffectVerification = 6,         ///< Confirms that a proposed forwarding effect was applied.
  EffectFailure = 7,              ///< Confirms that a proposed forwarding effect did not apply.
};

SFF_API const char* to_string(EvidenceKind kind) noexcept;
SFF_API bool is_valid_evidence_kind(std::uint8_t raw) noexcept;

/// A single bounded evidence record.
///
/// Records carry the boot incarnation and epoch under which they were admitted, so evidence
/// that predates a process boundary can always be identified and refused.
struct SFF_API EvidenceRecord {
  EvidenceId id;
  EvidenceKind kind = EvidenceKind::Unknown;
  EvidenceSource source = EvidenceSource::Unknown;
  SwitchKey subject;
  CoordinatorEpoch admitted_epoch;
  BootIncarnation admitted_boot;
  TimestampNs observed_at_ns = 0;
  std::uint64_t valid_for_ns = 0;
  SwitchHealthState health = SwitchHealthState::Unknown;
  SwitchAdminState admin = SwitchAdminState::Unknown;
  CapabilityMask capabilities = 0;
  DependentRef effect_dependent;
  PlanId effect_plan;
  AttemptSeq effect_attempt;
  std::string detail;

  std::uint64_t digest() const noexcept;

  /// Structural validation. Never consults current time; freshness is a separate question.
  Status validate(const Limits& limits) const;

  bool fresh_at(TimestampNs now) const noexcept;
  TimestampNs expires_at_ns() const noexcept { return observed_at_ns + valid_for_ns; }
};

/// Adjudication knobs, kept separate from the runtime policy so that the assessment function
/// has no dependency on the runtime layer.
struct SFF_API AssessmentPolicy {
  bool fence_on_authoritative_conflict = true;
  bool fence_on_missing_health = false;
  bool allow_same_generation_recovery = true;
  bool require_authoritative_failure_evidence = true;
  std::uint64_t future_skew_tolerance_ns = kNanosPerSecond;
};

/// Durable, committed failure lineage.
///
/// Failure lineage survives restart: a switch that was committed failed stays failed until an
/// authoritative recovery declaration arrives strictly later. Liveness observations do not.
class SFF_API FailureTable {
 public:
  FailureTable() = default;

  Status record(const FailureRecord& record);
  bool contains(const SwitchKey& key) const;
  const FailureRecord* find(const SwitchKey& key) const;
  std::vector<FailureRecord> all() const;
  std::size_t size() const;
  void clear();

  /// Supersede a durable failure with a later authoritative recovery. Refuses when the recovery
  /// is not strictly newer than the recorded failure.
  Status supersede(const SwitchKey& key, TimestampNs recovery_observed_at_ns);

 private:
  mutable std::mutex mutex_;
  std::map<SwitchKey, FailureRecord> entries_;
};

/// Bounded, thread-safe store of dynamic (non-durable) evidence.
///
/// Nothing in this store survives a restart, and nothing in it is restored from durable state.
class SFF_API EvidenceStore {
 public:
  explicit EvidenceStore(Limits limits, const Clock* clock);

  /// Admit a record. Returns a non-Ok status and stores nothing when the record is malformed,
  /// pre-restart, out of window, or when the retention bound is reached.
  Status admit(const EvidenceRecord& record);

  /// All retained records in canonical order.
  std::vector<EvidenceRecord> records() const;

  /// Retained records for an exact generation-qualified subject.
  std::vector<EvidenceRecord> for_subject(const SwitchKey& subject) const;

  std::size_t size() const;
  std::size_t capacity() const;
  std::size_t rejected() const;
  std::size_t evicted() const;

  /// Drop every record. Used at shutdown and when a test needs a pristine store.
  void clear();

  /// True when at least one admission has been refused since construction.
  bool had_rejection() const;

  const Limits& limits() const noexcept { return limits_; }

 private:
  mutable std::mutex mutex_;
  Limits limits_;
  const Clock* clock_;
  std::map<SwitchKey, std::vector<EvidenceRecord>> by_subject_;
  std::set<EvidenceId> identities_;  ///< Admitted identities are globally unique, not per subject.
  std::size_t total_ = 0;
  std::size_t rejected_ = 0;
  std::size_t evicted_ = 0;
};

/// Result of adjudicating all evidence about one switch generation.
struct SFF_API SwitchAssessment {
  SwitchKey subject;
  SwitchHealthState health = SwitchHealthState::Unknown;

  /// Resolution of the adjudication itself. Ok means the assessment resolved to a definite
  /// state; Unknown/Stale/Conflict/Unsupported mean no affirmative conclusion was possible.
  Code outcome = Code::Unknown;

  /// Affirmative basis to keep forwarding authority on this exact generation. False whenever
  /// authority cannot be proven - absence of evidence is never treated as proof of health.
  bool usable = false;

  /// The generation must be fenced before any reconstruction is applied.
  bool fence_required = false;

  bool durable_failure_present = false;
  FailureRecord durable_failure;

  std::vector<EvidenceId> supporting;
  std::vector<EvidenceId> conflicting;
  std::vector<EvidenceId> stale;
  std::vector<EvidenceId> untrusted;
  std::vector<EvidenceId> out_of_window;

  std::string rationale;
  std::uint64_t digest() const noexcept;
};

/// Fail-closed adjudication over the dynamic store and the durable failure lineage.
SFF_API SwitchAssessment assess_switch(const SwitchKey& subject,
                                       const EvidenceStore& evidence,
                                       const FailureTable& failures,
                                       TimestampNs now_ns,
                                       const AssessmentPolicy& policy);

}  // namespace sff

#endif  // SFF_MODEL_EVIDENCE_HPP
