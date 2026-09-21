// Switch Failover Fabric - bounded structured event log.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_LOG_HPP
#define SFF_CORE_LOG_HPP

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Externally meaningful lifecycle events. The numbering is durable: values are never reused.
enum class EventKind : std::uint16_t {
  Unknown = 0,
  RuntimeBooted = 1,
  RuntimeShutdown = 2,
  EpochAdvanced = 3,
  TopologyInstalled = 4,
  EvidenceAdmitted = 5,
  EvidenceRejected = 6,
  FailureDeclared = 7,
  FenceCommitted = 8,
  AuthorityGranted = 9,
  AuthorityRevoked = 10,
  PlanProposed = 11,
  PlanValidated = 12,
  PlanRejected = 13,
  PlanCommitted = 14,
  ApplyAttempted = 15,
  ApplyAcknowledged = 16,
  ApplyVerified = 17,
  RestoreDecided = 18,
  RestartReconciled = 19,
  SessionOpened = 20,
  SessionClosed = 21,
  Refused = 22,
};

SFF_API const char* to_string(EventKind kind) noexcept;

/// A single bounded log record.
struct SFF_API EventRecord {
  std::uint64_t seq = 0;
  TimestampNs at_ns = 0;
  EventKind kind = EventKind::Unknown;
  Code code = Code::Ok;
  std::uint64_t subject = 0;   ///< Caller-supplied subject identity (switch id, plan id, ...).
  std::uint64_t generation = 0;///< Generation qualifying the subject, when applicable.
  std::string text;            ///< Bounded by kMaxMessageBytes.
};

/// Bounded, append-only, thread-safe event log.
///
/// The log is deliberately *not* part of the durable recovery state: it is an observation
/// channel, not authority. Retention is bounded, and eviction is reported through first_seq().
class SFF_API EventLog {
 public:
  explicit EventLog(std::size_t capacity = 4096, const Clock* clock = nullptr);

  void append(EventKind kind, Code code, std::string_view text = {}, std::uint64_t subject = 0,
              std::uint64_t generation = 0);

  /// Snapshot of up to count most recent records, oldest first.
  std::vector<EventRecord> tail(std::size_t count) const;

  std::size_t size() const;
  std::size_t capacity() const;
  std::uint64_t first_seq() const;  ///< Sequence of the oldest retained record, 0 when empty.
  std::uint64_t last_seq() const;   ///< Sequence of the newest record, 0 when empty.
  std::uint64_t dropped() const;    ///< Number of records evicted by the retention bound.

  void clear();
  void set_capacity(std::size_t capacity);

 private:
  mutable std::mutex mutex_;
  std::deque<EventRecord> records_;
  std::size_t capacity_;
  const Clock* clock_;
  std::uint64_t next_seq_ = 1;
  std::uint64_t dropped_ = 0;
};

}  // namespace sff

#endif  // SFF_CORE_LOG_HPP
