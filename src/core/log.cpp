// Switch Failover Fabric - bounded structured event log.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/core/log.hpp"

#include <algorithm>

namespace sff {

const char* to_string(EventKind kind) noexcept {
  switch (kind) {
    case EventKind::Unknown: return "UNKNOWN";
    case EventKind::RuntimeBooted: return "RUNTIME_BOOTED";
    case EventKind::RuntimeShutdown: return "RUNTIME_SHUTDOWN";
    case EventKind::EpochAdvanced: return "EPOCH_ADVANCED";
    case EventKind::TopologyInstalled: return "TOPOLOGY_INSTALLED";
    case EventKind::EvidenceAdmitted: return "EVIDENCE_ADMITTED";
    case EventKind::EvidenceRejected: return "EVIDENCE_REJECTED";
    case EventKind::FailureDeclared: return "FAILURE_DECLARED";
    case EventKind::FenceCommitted: return "FENCE_COMMITTED";
    case EventKind::AuthorityGranted: return "AUTHORITY_GRANTED";
    case EventKind::AuthorityRevoked: return "AUTHORITY_REVOKED";
    case EventKind::PlanProposed: return "PLAN_PROPOSED";
    case EventKind::PlanValidated: return "PLAN_VALIDATED";
    case EventKind::PlanRejected: return "PLAN_REJECTED";
    case EventKind::PlanCommitted: return "PLAN_COMMITTED";
    case EventKind::ApplyAttempted: return "APPLY_ATTEMPTED";
    case EventKind::ApplyAcknowledged: return "APPLY_ACKNOWLEDGED";
    case EventKind::ApplyVerified: return "APPLY_VERIFIED";
    case EventKind::RestoreDecided: return "RESTORE_DECIDED";
    case EventKind::RestartReconciled: return "RESTART_RECONCILED";
    case EventKind::SessionOpened: return "SESSION_OPENED";
    case EventKind::SessionClosed: return "SESSION_CLOSED";
    case EventKind::Refused: return "REFUSED";
  }
  return "UNRECOGNISED_EVENT_KIND";
}

EventLog::EventLog(std::size_t capacity, const Clock* clock)
    : capacity_(capacity == 0 ? 1 : capacity), clock_(clock) {}

void EventLog::append(EventKind kind, Code code, std::string_view text, std::uint64_t subject,
                      std::uint64_t generation) {
  EventRecord record;
  record.at_ns = clock_ != nullptr ? clock_->now_ns() : 0;
  record.kind = kind;
  record.code = code;
  record.subject = subject;
  record.generation = generation;
  record.text = bounded_message(text);

  std::lock_guard<std::mutex> guard(mutex_);
  record.seq = next_seq_;
  next_seq_ = next_seq_ + 1;
  records_.push_back(std::move(record));
  while (records_.size() > capacity_) {
    records_.pop_front();
    dropped_ = dropped_ + 1;
  }
}

std::vector<EventRecord> EventLog::tail(std::size_t count) const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<EventRecord> result;
  const std::size_t take = std::min(count, records_.size());
  result.reserve(take);
  const auto begin = records_.end() - static_cast<std::ptrdiff_t>(take);
  for (auto it = begin; it != records_.end(); ++it) result.push_back(*it);
  return result;
}

std::size_t EventLog::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return records_.size();
}

std::size_t EventLog::capacity() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return capacity_;
}

std::uint64_t EventLog::first_seq() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return records_.empty() ? 0 : records_.front().seq;
}

std::uint64_t EventLog::last_seq() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return records_.empty() ? 0 : records_.back().seq;
}

std::uint64_t EventLog::dropped() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return dropped_;
}

void EventLog::clear() {
  std::lock_guard<std::mutex> guard(mutex_);
  records_.clear();
}

void EventLog::set_capacity(std::size_t capacity) {
  std::lock_guard<std::mutex> guard(mutex_);
  capacity_ = capacity == 0 ? 1 : capacity;
  while (records_.size() > capacity_) {
    records_.pop_front();
    dropped_ = dropped_ + 1;
  }
}

}  // namespace sff
