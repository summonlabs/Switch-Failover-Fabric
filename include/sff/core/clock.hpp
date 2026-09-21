// Switch Failover Fabric - time sources.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_CLOCK_HPP
#define SFF_CORE_CLOCK_HPP

#include <atomic>
#include <cstdint>
#include <memory>

#include "sff/export.hpp"

namespace sff {

/// Nanoseconds on an arbitrary but strictly monotonic axis.
using TimestampNs = std::uint64_t;

inline constexpr TimestampNs kNanosPerSecond = 1000000000ull;

/// Time source abstraction. Every freshness decision in this runtime is made against a Clock,
/// so the whole freshness model is deterministic under test.
class SFF_API Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock();

  /// Monotonically non-decreasing reading. Implementations must never move backwards.
  virtual TimestampNs now_ns() const noexcept = 0;
};

/// Wall-clock-relative monotonic reading, seeded from the system steady clock.
class SFF_API SystemClock final : public Clock {
 public:
  SystemClock() noexcept;
  TimestampNs now_ns() const noexcept override;

 private:
  TimestampNs origin_ = 0;
};

/// Deterministic clock driven explicitly by tests and simulators.
class SFF_API ManualClock final : public Clock {
 public:
  explicit ManualClock(TimestampNs start = 1000) noexcept : now_(start) {}
  TimestampNs now_ns() const noexcept override { return now_.load(std::memory_order_relaxed); }
  void advance(TimestampNs delta) noexcept { now_.fetch_add(delta, std::memory_order_relaxed); }
  void set(TimestampNs value) noexcept { now_.store(value, std::memory_order_relaxed); }

 private:
  std::atomic<TimestampNs> now_;
};

}  // namespace sff

#endif  // SFF_CORE_CLOCK_HPP
