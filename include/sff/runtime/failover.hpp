// Switch Failover Fabric - failover pipeline value types.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_RUNTIME_FAILOVER_HPP
#define SFF_RUNTIME_FAILOVER_HPP

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
#include "sff/plan/plan.hpp"
#include "sff/export.hpp"

namespace sff {

/// A caller request to treat one switch generation as failed.
///
/// The declaration is not itself authority: it is an input that the runtime turns into an
/// evidence record, adjudicates against policy, and only then acts on.
struct SFF_API FailureDeclaration {
  SwitchKey subject;
  EvidenceSource source = EvidenceSource::Unknown;
  TimestampNs observed_at_ns = 0;
  std::uint64_t valid_for_ns = 0;
  std::string reason;

  Status validate() const;
};

/// Outcome of a completed failover: the fence that was committed and the closure it covered.
struct SFF_API FailoverOutcome {
  SwitchKey failed;
  FailureRecord failure;
  FenceId fence;
  FenceScopeState fence_scope = FenceScopeState::Open;
  DependencyClosure closure;
  std::size_t grants_fenced = 0;
  std::size_t dependents_affected = 0;
  bool deferred = false;      ///< Already fenced; the declaration was recorded but not re-applied.
  Code outcome = Code::Unknown;
  Explanation explanation;
  std::uint64_t digest() const noexcept;
};

/// Request to turn a plan into forwarding effect.
struct SFF_API ApplyRequest {
  PlanId plan;
  PlanAction action = PlanAction::RebindReplacement;
  EvidenceId acknowledgement;   ///< Optional external acknowledgement evidence.
  std::string detail;
};

/// Result of reconciling durable state with a fresh process incarnation.
struct SFF_API RestartReport {
  bool recovered = false;
  bool clean_previous_shutdown = false;
  bool torn_tail_truncated = false;
  std::size_t records_replayed = 0;
  std::size_t corrupt_records = 0;
  std::size_t torn_records = 0;
  std::size_t unsupported_records = 0;
  CoordinatorEpoch previous_epoch;
  CoordinatorEpoch current_epoch;
  BootIncarnation previous_boot;
  BootIncarnation current_boot;
  std::size_t failures_restored = 0;
  std::size_t fences_restored = 0;
  /// Grants found in durable lineage and forced out of the Active state. This release never
  /// persists grants: a restored grant can never be Active, so authority is re-established by
  /// reinstalling the authoritative topology instead. The counter exists so that a deployment
  /// which does persist grant lineage still reports it truthfully; zero is the expected value here.
  std::size_t grants_invalidated = 0;
  std::size_t grants_fenced = 0;
  std::size_t plans_restored = 0;
  std::size_t sessions_invalidated = 0;
  bool dynamic_evidence_restored = false;  ///< Always false. Present so the claim is explicit.
  std::vector<std::string> notes;
  Status status;

  std::uint64_t digest() const noexcept;
};

}  // namespace sff

#endif  // SFF_RUNTIME_FAILOVER_HPP
