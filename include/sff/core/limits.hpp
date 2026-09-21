// Switch Failover Fabric - bounded resource limits.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_LIMITS_HPP
#define SFF_CORE_LIMITS_HPP

#include <cstddef>
#include <cstdint>

#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Hard ceilings. Values above these are refused outright, regardless of what a caller asks for.
/// Every one of them exists so that a hostile or mistaken configuration cannot drive an
/// unbounded allocation or an unbounded traversal.
inline constexpr std::size_t kHardMaxDocumentBytes = std::size_t{256} << 20;   // 256 MiB
inline constexpr std::size_t kHardMaxFramePayload = std::size_t{16} << 20;     // 16 MiB
inline constexpr std::size_t kHardMaxElements = std::size_t{64} << 20;         // 64 Mi elements
inline constexpr std::size_t kHardMaxJournalRecords = std::size_t{64} << 20;
inline constexpr std::size_t kHardMaxEventRecords = std::size_t{1} << 20;
inline constexpr std::size_t kHardMaxSessions = std::size_t{1} << 20;
inline constexpr std::size_t kHardMaxQueueDepth = std::size_t{1} << 20;
inline constexpr std::size_t kHardMaxExplanationTerms = 4096;
inline constexpr std::size_t kHardMaxRetainedAttempts = 4096;

/// Runtime policy limits. All collections the runtime materialises are bounded by this structure.
struct SFF_API Limits {
  /// Topology materialisation bounds.
  std::size_t max_switches = 200000;
  std::size_t max_links = 2000000;
  std::size_t max_paths = 2000000;
  std::size_t max_ports = 4000000;
  std::size_t max_failure_domains = 100000;

  /// Dependency-closure traversal bounds. Exceeding either produces an explicit
  /// PartialClosure outcome; dependents are never silently dropped.
  std::size_t max_closure_nodes = 2000000;
  std::size_t max_closure_edges = 8000000;

  /// Planning bounds.
  std::size_t max_plan_steps = 1000000;
  /// Total assignment-search nodes the planner may visit across every connected component. When
  /// it runs out the plan reports SearchLimitReached instead of an optimality or infeasibility
  /// claim, so a hostile instance degrades the strength of the answer, never its truthfulness.
  std::size_t max_candidates_evaluated = 200000;
  std::size_t max_unresolved_dependents = 1000000;
  std::size_t max_explanation_terms = 64;
  std::size_t max_retained_attempts = 64;

  /// Authority bookkeeping bounds.
  std::size_t max_authority_grants = 4000000;
  std::size_t max_fences = 1000000;

  /// Evidence and history bounds.
  std::size_t max_evidence_records = 200000;
  std::size_t max_event_records = 65536;
  std::size_t max_journal_records = 1000000;

  /// Session / transport bounds.
  std::size_t max_sessions = 4096;
  std::size_t max_session_queue = 256;
  std::size_t max_frame_payload = std::size_t{1} << 20;  // 1 MiB
  std::size_t max_document_bytes = std::size_t{64} << 20;

  /// Freshness windows, in nanoseconds.
  std::uint64_t freshness_window_ns = 30ull * 1000ull * 1000ull * 1000ull;  // 30 s
  std::uint64_t fence_horizon_ns = 24ull * 3600ull * 1000ull * 1000ull * 1000ull;

  static Limits defaults() noexcept { return Limits{}; }

  /// True when every field is inside the hard ceiling and internally consistent.
  Status validate() const;
};

/// Deterministic refusal when a requested size exceeds a bound.
SFF_API Status refuse_exhausted(const char* what, std::size_t requested, std::size_t limit);

}  // namespace sff

#endif  // SFF_CORE_LIMITS_HPP
