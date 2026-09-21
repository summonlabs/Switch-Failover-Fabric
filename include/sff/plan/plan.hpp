// Switch Failover Fabric - reconstruction plans and effect accounting.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PLAN_PLAN_HPP
#define SFF_PLAN_PLAN_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/authority.hpp"
#include "sff/model/decision.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/topology.hpp"
#include "sff/export.hpp"

namespace sff {

/// A caller-supplied admissible reconstruction alternative.
///
/// This runtime never synthesises forwarding paths: it selects among alternatives that an
/// authoritative adjacent system supplied, and it validates every one of them against current
/// generations before selection. That is the exact systems boundary.
struct SFF_API ReconstructionCandidate {
  DependentRef dependent;
  SwitchKey covers_failed;           ///< The failed generation this alternative replaces.
  std::vector<SwitchKey> hops;       ///< Exact, generation-qualified replacement hop set.
  std::vector<LinkId> links;
  std::uint32_t cost = 0;
  CapabilityMask capabilities = 0;
  EvidenceId evidence;               ///< Authoritative origin of this alternative.
  EvidenceSource source = EvidenceSource::Unknown;

  std::uint64_t digest() const noexcept;
  Status validate() const;
};

/// Why a dependent could not be restored.
enum class UnresolvedReason : std::uint8_t {
  Unknown = 0,
  NoCandidateSupplied = 1,      ///< Proven: the input contained no alternative for this dependent.
  CandidateGenerationStale = 2, ///< Proven: every alternative names a generation that is gone.
  CapabilityInsufficient = 3,   ///< Proven: no alternative meets the required capability set.
  BehindFence = 4,              ///< Proven: every alternative crosses a fenced generation.
  CapacityExhausted = 5,        ///< Proven: admissible alternatives exist but all are saturated.
  FailureDomainConflict = 6,    ///< Proven: policy forbids reuse of the failed failure domain.
  Withheld = 7,                 ///< Deliberately withheld by policy; not an error.
  ClosureTruncated = 8,         ///< NOT proven: the dependency closure was cut by a bound.
  SearchLimitReached = 9,       ///< NOT proven: planning bounds stopped the search.
  ContradictoryEvidence = 10,   ///< Proven: authoritative inputs contradict each other.
  HopNotInTopology = 11,        ///< Proven: the alternative names a switch generation not installed.
  NonAuthoritativeOrigin = 12,  ///< Proven: the alternative carries no authoritative origin.
};

SFF_API const char* to_string(UnresolvedReason reason) noexcept;

/// True when the reason constitutes a valid certificate that no admissible alternative exists.
SFF_API bool is_proven_negative(UnresolvedReason reason) noexcept;

struct SFF_API UnresolvedDependent {
  DependentRef dependent;
  SwitchKey covers_failed;  ///< The failed generation that could not be moved off.
  UnresolvedReason reason = UnresolvedReason::Unknown;
  std::string detail;
  std::uint64_t digest() const noexcept;
};

enum class PlanAction : std::uint8_t {
  Unknown = 0,
  RebindReplacement = 1,  ///< Move the dependent onto a supplied replacement hop set.
};

SFF_API const char* to_string(PlanAction action) noexcept;

/// One fence obligation inside a plan.
struct SFF_API FenceStep {
  SwitchKey failed;
  std::uint64_t closure_digest = 0;
  ClosureState closure_state = ClosureState::Empty;
  std::size_t closure_members = 0;
  std::size_t omitted_dependents = 0;

  std::uint64_t digest() const noexcept;
};

/// One proposed forwarding reconstruction. Proposal is not effect: nothing here has been applied.
struct SFF_API RestoreStep {
  DependentRef dependent;
  SwitchKey covers_failed;  ///< The failed generation this step moves the dependent off.
  PlanAction action = PlanAction::Unknown;
  SwitchKey replacement;
  std::vector<SwitchKey> hops;
  std::vector<LinkId> links;
  std::uint32_t cost = 0;
  EvidenceId evidence;

  std::uint64_t digest() const noexcept;
};

enum class PlanFeasibility : std::uint8_t {
  Unknown = 0,
  ProvenFeasible = 1,     ///< A validated plan exists for at least part of the scope.
  ProvenInfeasible = 2,   ///< Certificates prove no dependent in scope can be restored.
  Indeterminate = 3,      ///< No conclusion: a bound or an unresolved ambiguity intervened.
  SearchLimitReached = 4, ///< A declared planning bound stopped the search.
  NothingToRestore = 5,   ///< The scope was exhaustively enumerated and is empty: the failed
                          ///< generation invalidated no dependent at all, so there is neither a
                          ///< solution to apply nor an infeasibility to report.
};

SFF_API const char* to_string(PlanFeasibility feasibility) noexcept;

enum class PlanState : std::uint8_t {
  Draft = 0,
  Validated = 1,
  Rejected = 2,
  Committed = 3,
  Applying = 4,
  Applied = 5,
  PartiallyApplied = 6,
  Failed = 7,
  Superseded = 8,
};

SFF_API const char* to_string(PlanState state) noexcept;

/// The authoritative reconstruction plan.
///
/// The plan is pure data: it can be canonicalised, digested, persisted, replayed and
/// independently re-validated. Its digest covers every field that carries meaning.
class SFF_API ReconstructionPlan {
 public:
  PlanId id;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  GenerationVector failed_generations;
  std::vector<FenceStep> fences;
  std::vector<RestoreStep> restores;
  std::vector<UnresolvedDependent> unresolved;
  PlanFeasibility feasibility = PlanFeasibility::Unknown;
  PlanState state = PlanState::Draft;
  bool closure_complete = false;
  bool service_withheld = false;
  std::uint64_t topology_digest = 0;
  std::uint64_t policy_digest = 0;
  std::uint64_t plan_digest = 0;

  /// Recompute the canonical digest over every meaning-bearing field.
  std::uint64_t compute_digest() const noexcept;
  bool digest_valid() const noexcept { return plan_digest != 0 && plan_digest == compute_digest(); }
  void seal() noexcept { plan_digest = compute_digest(); }

  std::size_t restored_count() const noexcept { return restores.size(); }
  std::size_t unresolved_count() const noexcept { return unresolved.size(); }
  std::uint64_t total_cost() const noexcept;

  /// Canonical byte encoding used for digests, durable records and cross-process comparison.
  std::vector<std::uint8_t> encode() const;
  static Result<ReconstructionPlan> decode(const std::vector<std::uint8_t>& bytes, const Limits& limits);

  /// Deterministic total order used as the final tie-break of the planner objective.
  friend bool operator<(const ReconstructionPlan& a, const ReconstructionPlan& b) noexcept;
};

/// Acknowledgement state of one applied step. Acknowledgement is not verified effect.
enum class AckState : std::uint8_t {
  Unknown = 0,
  Applied = 1,      ///< The runtime issued the effect and the peer acknowledged it.
  Verified = 2,     ///< Independent verification evidence confirmed the effect.
  Failed = 3,       ///< The effect was refused or reported failed.
  Unverified = 4,   ///< The effect was issued but no verification evidence exists.
};

SFF_API const char* to_string(AckState state) noexcept;

struct SFF_API ApplyStepResult {
  DependentRef dependent;
  SwitchKey replacement;
  AckState state = AckState::Unknown;
  AttemptSeq attempt;
  EvidenceId verification;
  std::string detail;
};

/// Receipt for an apply attempt. Distinguishes proposal, acknowledgement and verified effect.
struct SFF_API ApplyReceipt {
  PlanId plan;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  std::vector<ApplyStepResult> steps;
  std::size_t applied = 0;
  std::size_t verified = 0;
  std::size_t failed = 0;
  std::size_t unverified = 0;
  bool complete = false;
  Code outcome = Code::Unknown;

  bool fully_verified() const noexcept { return complete && failed == 0 && unverified == 0 && verified == applied; }
};

/// Decision about restoring service for one dependent under current generations.
struct SFF_API RestoreDecision {
  DependentRef dependent;
  Code outcome = Code::Unknown;
  Code reason = Code::Unknown;
  bool may_restore = false;
  bool effect_verified = false;
  GenerationVector bound;
  PlanId plan;
  std::vector<GrantId> grants;
  std::vector<SwitchKey> blocking_generations;
  Explanation explanation;
  std::uint64_t digest() const noexcept;
};

}  // namespace sff

#endif  // SFF_PLAN_PLAN_HPP
