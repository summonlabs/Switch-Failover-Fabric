// Switch Failover Fabric - session authority.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/runtime/session.hpp"

#include <algorithm>

namespace sff {

SessionRegistry::SessionRegistry(Limits limits) : limits_(limits) {}

Result<SessionRecord> SessionRegistry::open(std::string_view principal, CoordinatorEpoch epoch,
                                            const BootIncarnation& boot, TimestampNs now_ns) {
  if (!epoch.valid() || !boot.valid()) {
    return Status::failure(Code::Unauthorized,
                           "a session requires a current epoch and boot incarnation");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  if (sessions_.size() >= limits_.max_sessions) {
    return refuse_exhausted("max_sessions", sessions_.size() + 1, limits_.max_sessions);
  }
  SessionRecord record;
  record.id = SessionId(next_session_);
  next_session_ += 1;
  record.principal = bounded_message(principal);
  record.epoch = epoch;
  record.boot = boot;
  record.opened_at_ns = now_ns;
  const SessionId id = record.id;
  sessions_.emplace(id, std::move(record));
  return sessions_.at(id);
}

Status SessionRegistry::close(SessionId id) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = sessions_.find(id);
  if (position == sessions_.end()) {
    return Status::failure(Code::NotFound, "session identity is unknown");
  }
  position->second.closed = true;
  return Status::success();
}

Status SessionRegistry::authorise(const SessionBinding& binding, CoordinatorEpoch current_epoch,
                                  std::uint64_t current_boot_digest) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = sessions_.find(binding.session);
  if (position == sessions_.end()) {
    replay_rejections_ += 1;
    return Status::failure(Code::Unauthorized, "session identity is unknown to this incarnation");
  }
  SessionRecord& record = position->second;
  if (record.closed) {
    return Status::failure(Code::Closed, "session is closed");
  }
  if (current_boot_digest == 0) {
    return Status::failure(Code::Unauthorized, "this incarnation has no established boot identity");
  }
  if (binding.epoch != current_epoch || record.epoch != current_epoch) {
    return Status::failure(Code::Stale, "request was issued under a different coordinator epoch");
  }
  if (binding.boot_digest != current_boot_digest) {
    return Status::failure(Code::Stale,
                           "request was issued under a different process incarnation");
  }
  if (binding.request_seq <= record.last_request_seq) {
    replay_rejections_ += 1;
    return Status::failure(Code::Replay, "request sequence did not advance");
  }
  record.last_request_seq = binding.request_seq;
  return Status::success();
}

std::size_t SessionRegistry::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return sessions_.size();
}

std::size_t SessionRegistry::replay_rejections() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return replay_rejections_;
}

std::vector<SessionRecord> SessionRegistry::all() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<SessionRecord> result;
  result.reserve(sessions_.size());
  for (const auto& entry : sessions_) result.push_back(entry.second);
  return result;
}

std::size_t SessionRegistry::close_all() {
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t closed = 0;
  for (auto& entry : sessions_) {
    if (!entry.second.closed) {
      entry.second.closed = true;
      closed += 1;
    }
  }
  return closed;
}

bool SessionRegistry::contains(SessionId id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return sessions_.find(id) != sessions_.end();
}

}  // namespace sff
