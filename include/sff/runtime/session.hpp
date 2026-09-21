// Switch Failover Fabric - session authority.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_RUNTIME_SESSION_HPP
#define SFF_RUNTIME_SESSION_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// What a request must present in order to act.
///
/// Session identity alone is not authority: the epoch and boot incarnation under which the
/// session was established must still be current, and the request sequence must advance
/// monotonically. A replayed or regressed sequence is refused.
struct SFF_API SessionBinding {
  SessionId session;
  CoordinatorEpoch epoch;
  std::uint64_t boot_digest = 0;
  std::uint64_t request_seq = 0;
};

struct SFF_API SessionRecord {
  SessionId id;
  std::string principal;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  TimestampNs opened_at_ns = 0;
  std::uint64_t last_request_seq = 0;
  bool closed = false;
};

/// Bounded session table.
///
/// Sessions are dynamic state and are never restored from durable storage: a restart invalidates
/// every session that existed before it.
class SFF_API SessionRegistry {
 public:
  explicit SessionRegistry(Limits limits = Limits::defaults());

  Result<SessionRecord> open(std::string_view principal, CoordinatorEpoch epoch,
                             const BootIncarnation& boot, TimestampNs now_ns);

  Status close(SessionId id);

  /// Validate a binding and consume its sequence number.
  Status authorise(const SessionBinding& binding, CoordinatorEpoch current_epoch,
                   std::uint64_t current_boot_digest);

  std::size_t size() const;
  std::size_t replay_rejections() const;
  std::vector<SessionRecord> all() const;
  std::size_t close_all();
  bool contains(SessionId id) const;

 private:
  mutable std::mutex mutex_;
  Limits limits_;
  std::map<SessionId, SessionRecord> sessions_;
  std::uint64_t next_session_ = 1;
  std::uint64_t replay_rejections_ = 0;
};

}  // namespace sff

#endif  // SFF_RUNTIME_SESSION_HPP
