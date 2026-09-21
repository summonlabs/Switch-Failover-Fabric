// Switch Failover Fabric - time sources.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/core/clock.hpp"

#include <chrono>

namespace sff {

Clock::~Clock() = default;

SystemClock::SystemClock() noexcept {
  const auto start = std::chrono::steady_clock::now();
  // Record a private origin so that the reported axis is monotonic and independent of wall time.
  origin_ = static_cast<TimestampNs>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(start.time_since_epoch()).count());
}

TimestampNs SystemClock::now_ns() const noexcept {
  const auto now = static_cast<TimestampNs>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
  // Never move backwards, even if the underlying steady clock is coarser than a nanosecond tick.
  return now >= origin_ ? now - origin_ : 0;
}

}  // namespace sff
