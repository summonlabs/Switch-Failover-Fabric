// Switch Failover Fabric - bounded resource limit validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/core/limits.hpp"

#include <string>

namespace sff {
namespace {

Status require_positive(std::size_t value, const char* name) {
  if (value == 0) return Status::failure(Code::Invalid, std::string("limit must be positive: ") + name);
  return Status::success();
}

Status require_within(std::size_t value, std::size_t ceiling, const char* name) {
  if (value > ceiling) {
    return Status::failure(Code::Invalid, std::string("limit exceeds hard ceiling: ") + name);
  }
  return Status::success();
}

}  // namespace

Status Limits::validate() const {
  const struct {
    std::size_t value;
    std::size_t ceiling;
    const char* name;
  } bounded[] = {
      {max_switches, kHardMaxElements, "max_switches"},
      {max_links, kHardMaxElements, "max_links"},
      {max_paths, kHardMaxElements, "max_paths"},
      {max_ports, kHardMaxElements, "max_ports"},
      {max_failure_domains, kHardMaxElements, "max_failure_domains"},
      {max_closure_nodes, kHardMaxElements, "max_closure_nodes"},
      {max_closure_edges, kHardMaxElements, "max_closure_edges"},
      {max_plan_steps, kHardMaxElements, "max_plan_steps"},
      {max_candidates_evaluated, kHardMaxElements, "max_candidates_evaluated"},
      {max_unresolved_dependents, kHardMaxElements, "max_unresolved_dependents"},
      {max_explanation_terms, kHardMaxExplanationTerms, "max_explanation_terms"},
      {max_retained_attempts, kHardMaxRetainedAttempts, "max_retained_attempts"},
      {max_authority_grants, kHardMaxElements, "max_authority_grants"},
      {max_fences, kHardMaxElements, "max_fences"},
      {max_evidence_records, kHardMaxElements, "max_evidence_records"},
      {max_event_records, kHardMaxEventRecords, "max_event_records"},
      {max_journal_records, kHardMaxJournalRecords, "max_journal_records"},
      {max_sessions, kHardMaxSessions, "max_sessions"},
      {max_session_queue, kHardMaxQueueDepth, "max_session_queue"},
      {max_frame_payload, kHardMaxFramePayload, "max_frame_payload"},
      {max_document_bytes, kHardMaxDocumentBytes, "max_document_bytes"},
  };

  for (const auto& entry : bounded) {
    Status s = require_positive(entry.value, entry.name);
    if (!s.ok()) return s;
    s = require_within(entry.value, entry.ceiling, entry.name);
    if (!s.ok()) return s;
  }

  if (freshness_window_ns == 0) {
    return Status::failure(Code::Invalid, "freshness_window_ns must be positive");
  }
  if (fence_horizon_ns == 0) {
    return Status::failure(Code::Invalid, "fence_horizon_ns must be positive");
  }
  if (max_document_bytes < max_frame_payload) {
    return Status::failure(Code::Invalid, "max_document_bytes must be at least max_frame_payload");
  }
  return Status::success();
}

Status refuse_exhausted(const char* what, std::size_t requested, std::size_t limit) {
  std::string message(what == nullptr ? "resource" : what);
  message += ": requested ";
  message += std::to_string(requested);
  message += " exceeds limit ";
  message += std::to_string(limit);
  return Status::failure(Code::Exhausted, message);
}

}  // namespace sff
