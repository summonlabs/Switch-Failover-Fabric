// Switch Failover Fabric - dependency authority, fencing and revocation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/authority.hpp"

#include <algorithm>
#include <set>

namespace sff {

const char* to_string(GrantState state) noexcept {
  switch (state) {
    case GrantState::Unknown: return "UNKNOWN";
    case GrantState::Active: return "ACTIVE";
    case GrantState::Stale: return "STALE";
    case GrantState::Revoked: return "REVOKED";
    case GrantState::Expired: return "EXPIRED";
    case GrantState::Fenced: return "FENCED";
  }
  return "UNRECOGNISED_GRANT_STATE";
}

const char* to_string(RevocationCause cause) noexcept {
  switch (cause) {
    case RevocationCause::Unknown: return "UNKNOWN";
    case RevocationCause::Superseded: return "SUPERSEDED";
    case RevocationCause::Fence: return "FENCE";
    case RevocationCause::Restart: return "RESTART";
    case RevocationCause::Expiry: return "EXPIRY";
    case RevocationCause::OperatorRevocation: return "OPERATOR_REVOCATION";
    case RevocationCause::RevalidationFailed: return "REVALIDATION_FAILED";
    case RevocationCause::Shutdown: return "SHUTDOWN";
  }
  return "UNRECOGNISED_REVOCATION_CAUSE";
}

const char* to_string(FenceScopeState state) noexcept {
  switch (state) {
    case FenceScopeState::Open: return "OPEN";
    case FenceScopeState::Partial: return "PARTIAL";
    case FenceScopeState::Committed: return "COMMITTED";
  }
  return "UNRECOGNISED_FENCE_SCOPE";
}

std::uint64_t AuthorityGrant::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.authority-grant.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_dependent(dependent);
  digest.absorb_u64(bound.digest());
  digest.absorb_u64(epoch.raw());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_u64(attempt.raw());
  digest.absorb_u64(granted_at_ns);
  digest.absorb_u64(expires_at_ns);
  digest.absorb_byte(static_cast<std::uint8_t>(state));
  digest.absorb_byte(static_cast<std::uint8_t>(cause));
  digest.absorb_string(detail);
  return digest.hi;
}

bool AuthorityGrant::active_at(TimestampNs now_ns) const noexcept {
  // A grant confers authority only inside its own validity window: not before it was minted and
  // not after the window elapses. An instant outside that window is never affirmative.
  return state == GrantState::Active && expires_at_ns != 0 && now_ns >= granted_at_ns &&
         now_ns <= expires_at_ns;
}

std::uint64_t FenceRecord::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.fence-record.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_key(subject);
  digest.absorb_u64(epoch.raw());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_u64(created_at_ns);
  digest.absorb_byte(static_cast<std::uint8_t>(scope_state));
  digest.absorb_u64(closure_digest);
  digest.absorb_u64(closure_members);
  digest.absorb_u64(fenced_grants);
  digest.absorb_u64(omitted_dependents);
  digest.absorb_string(reason);
  return digest.hi;
}

std::uint64_t AuthorityQuery::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.authority-query.v1");
  digest.absorb_dependent(dependent);
  digest.absorb_byte(has_authority ? 1 : 0);
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  digest.absorb_byte(static_cast<std::uint8_t>(reason));
  digest.absorb_u64(bound.digest());
  for (const auto& id : active_grants) digest.absorb_u64(id.raw());
  for (const auto& id : withdrawn_grants) digest.absorb_u64(id.raw());
  for (const auto& key : fenced_generations) digest.absorb_key(key);
  for (const auto& key : unproven_generations) digest.absorb_key(key);
  return digest.hi;
}

// ---------------------------------------------------------------------------------------------
// AuthorityRegistry
// ---------------------------------------------------------------------------------------------

AuthorityRegistry::AuthorityRegistry(Limits limits) : limits_(limits) {}

Result<GrantId> AuthorityRegistry::grant(const DependentRef& dependent, const GenerationVector& bound,
                                         CoordinatorEpoch epoch, const BootIncarnation& boot,
                                         TimestampNs now_ns, std::uint64_t ttl_ns,
                                         std::string_view detail) {
  if (!dependent.valid()) {
    return Status::failure(Code::Invalid, "grant subject is not a valid dependent reference");
  }
  if (bound.empty()) {
    return Status::failure(Code::Invalid, "grant binds no generation");
  }
  if (!epoch.valid() || !boot.valid()) {
    return Status::failure(Code::Unauthorized, "grant requires a current epoch and boot incarnation");
  }
  if (ttl_ns == 0) {
    return Status::failure(Code::Invalid, "grant requires a non-zero validity window");
  }

  std::lock_guard<std::mutex> guard(mutex_);

  for (const auto& key : bound.keys()) {
    if (fences_.find(key) != fences_.end()) {
      return Status::failure(Code::Fenced,
                             "grant would bind a fenced generation: " + key.to_string());
    }
  }
  if (grants_.size() >= limits_.max_authority_grants) {
    return refuse_exhausted("max_authority_grants", grants_.size() + 1, limits_.max_authority_grants);
  }

  attempt_ += 1;
  AuthorityGrant record;
  record.id = GrantId(next_grant_);
  next_grant_ += 1;
  record.dependent = dependent;
  record.bound = bound;
  record.epoch = epoch;
  record.boot = boot;
  record.attempt = AttemptSeq(attempt_);
  record.granted_at_ns = now_ns;
  const std::uint64_t expires = now_ns + ttl_ns;
  record.expires_at_ns = expires < now_ns ? UINT64_MAX : expires;
  record.state = GrantState::Active;
  record.detail = bounded_message(detail);

  const GrantId id = record.id;
  grants_.emplace(id, std::move(record));
  by_dependent_[dependent].push_back(id);
  return id;
}

Status AuthorityRegistry::revoke(GrantId id, RevocationCause cause, std::string_view detail) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = grants_.find(id);
  if (position == grants_.end()) {
    return Status::failure(Code::NotFound, "grant identity is unknown");
  }
  if (position->second.state != GrantState::Active) return Status::success();
  position->second.state = GrantState::Revoked;
  position->second.cause = cause;
  position->second.detail = bounded_message(detail);
  return Status::success();
}

std::size_t AuthorityRegistry::fence_generations(const GenerationVector& generations,
                                                 TimestampNs now_ns) {
  (void)now_ns;
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t revoked = 0;
  for (auto& entry : grants_) {
    AuthorityGrant& record = entry.second;
    if (record.state != GrantState::Active) continue;
    if (!record.bound.intersects(generations)) continue;
    record.state = GrantState::Fenced;
    record.cause = RevocationCause::Fence;
    record.detail = "a bound switch generation was fenced";
    revoked += 1;
  }
  return revoked;
}

std::size_t AuthorityRegistry::revoke_dependent(const DependentRef& dependent,
                                                RevocationCause cause, std::string_view detail) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto index = by_dependent_.find(dependent);
  if (index == by_dependent_.end()) return 0;
  std::size_t revoked = 0;
  for (const GrantId id : index->second) {
    const auto position = grants_.find(id);
    if (position == grants_.end()) continue;
    if (position->second.state != GrantState::Active) continue;
    position->second.state = GrantState::Revoked;
    position->second.cause = cause;
    position->second.detail = bounded_message(detail);
    revoked += 1;
  }
  return revoked;
}

std::size_t AuthorityRegistry::invalidate_pre_restart(CoordinatorEpoch new_epoch,
                                                      const BootIncarnation& new_boot,
                                                      TimestampNs now_ns) {
  (void)new_epoch;
  (void)new_boot;
  (void)now_ns;
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t invalidated = 0;
  for (auto& entry : grants_) {
    AuthorityGrant& record = entry.second;
    if (record.state != GrantState::Active) continue;
    record.state = GrantState::Stale;
    record.cause = RevocationCause::Restart;
    record.detail = "minted before the current process incarnation";
    invalidated += 1;
  }
  return invalidated;
}

std::size_t AuthorityRegistry::expire_due(TimestampNs now_ns) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t expired = 0;
  for (auto& entry : grants_) {
    AuthorityGrant& record = entry.second;
    if (record.state != GrantState::Active) continue;
    if (now_ns <= record.expires_at_ns) continue;
    record.state = GrantState::Expired;
    record.cause = RevocationCause::Expiry;
    record.detail = "validity window elapsed";
    expired += 1;
  }
  return expired;
}

std::size_t AuthorityRegistry::withdraw_all(RevocationCause cause, std::string_view detail) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t withdrawn = 0;
  for (auto& entry : grants_) {
    AuthorityGrant& record = entry.second;
    if (record.state == GrantState::Revoked || record.state == GrantState::Fenced) continue;
    // The resulting state must describe what actually happened. Claiming Fenced without a durable
    // fence record would make the registry contradict its own fence table and would present a
    // process restart as a generation fence.
    switch (cause) {
      case RevocationCause::Fence:
        record.state = GrantState::Fenced;
        break;
      case RevocationCause::Restart:
        record.state = GrantState::Stale;
        break;
      default:
        record.state = GrantState::Revoked;
        break;
    }
    record.cause = cause;
    record.detail = bounded_message(detail);
    withdrawn += 1;
  }
  return withdrawn;
}

Result<FenceId> AuthorityRegistry::commit_fence(FenceRecord record) {
  if (!record.subject.valid()) {
    return Status::failure(Code::Invalid, "fence subject is not generation-qualified");
  }
  if (record.reason.empty()) {
    return Status::failure(Code::Invalid, "fence requires a recorded reason");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  if (fences_.find(record.subject) != fences_.end()) {
    return Status::failure(Code::AlreadyExists,
                           "generation is already fenced: " + record.subject.to_string());
  }
  if (fences_.size() >= limits_.max_fences) {
    return refuse_exhausted("max_fences", fences_.size() + 1, limits_.max_fences);
  }
  record.id = FenceId(next_fence_);
  next_fence_ += 1;
  record.reason = bounded_message(record.reason);
  const FenceId id = record.id;
  fences_.emplace(record.subject, std::move(record));
  return id;
}

bool AuthorityRegistry::is_fenced(const SwitchKey& key) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return fences_.find(key) != fences_.end();
}

bool AuthorityRegistry::identity_has_any_fence(SwitchId id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  for (const auto& entry : fences_) {
    if (entry.first.id() == id) return true;
  }
  return false;
}

std::vector<FenceRecord> AuthorityRegistry::fences() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<FenceRecord> result;
  result.reserve(fences_.size());
  for (const auto& entry : fences_) result.push_back(entry.second);
  return result;
}

std::size_t AuthorityRegistry::fence_count() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return fences_.size();
}

AuthorityQuery AuthorityRegistry::query(const DependentRef& dependent, TimestampNs now_ns) const {
  std::lock_guard<std::mutex> guard(mutex_);
  AuthorityQuery result;
  result.dependent = dependent;

  const auto index = by_dependent_.find(dependent);
  if (index == by_dependent_.end() || index->second.empty()) {
    result.outcome = Code::NotFound;
    result.reason = Code::NotFound;
    result.rationale = "no forwarding authority was ever granted for this dependent";
    return result;
  }

  std::set<SwitchKey> historical_fenced;
  std::vector<SwitchKey> blocking;
  GenerationVector bound;
  bool saw_restart = false;
  bool saw_expiry = false;
  bool saw_revocation = false;
  bool saw_stale = false;

  for (const GrantId id : index->second) {
    const auto position = grants_.find(id);
    if (position == grants_.end()) continue;
    const AuthorityGrant& record = position->second;
    if (record.active_at(now_ns)) {
      result.active_grants.push_back(id);
      bound = bound.united(record.bound);
      continue;
    }
    result.withdrawn_grants.push_back(id);
    switch (record.state) {
      case GrantState::Fenced:
        for (const auto& key : record.bound.keys()) historical_fenced.insert(key);
        break;
      case GrantState::Stale:
        saw_stale = true;
        break;
      case GrantState::Expired:
        saw_expiry = true;
        break;
      case GrantState::Active:
        // Still nominally Active but outside its validity window: the caller must be able to tell
        // a lapsed window from an operator revocation without driving expire_due() first.
        saw_expiry = true;
        break;
      default:
        saw_revocation = true;
        break;
    }
    if (record.cause == RevocationCause::Restart) saw_restart = true;
  }

  // Only the generations an ACTIVE grant is bound to can take authority away. A fence that was
  // applied to a superseded grant is history: it is reported, but it must never re-deny authority
  // that was legitimately re-established on a different generation after the fence.
  for (const auto& key : bound.keys()) {
    if (fences_.find(key) != fences_.end()) blocking.push_back(key);
  }

  result.bound = bound;
  result.fenced_generations.assign(historical_fenced.begin(), historical_fenced.end());
  for (const auto& key : blocking) {
    if (std::find(result.fenced_generations.begin(), result.fenced_generations.end(), key) ==
        result.fenced_generations.end()) {
      result.fenced_generations.push_back(key);
    }
  }
  std::sort(result.fenced_generations.begin(), result.fenced_generations.end());
  result.has_authority = !result.active_grants.empty() && blocking.empty();

  if (result.has_authority) {
    result.outcome = Code::Ok;
    result.reason = Code::Ok;
    result.rationale = "an active grant covers every bound generation";
    return result;
  }
  if (!blocking.empty()) {
    result.outcome = Code::Fenced;
    result.reason = Code::Fenced;
    result.rationale = "an active grant is bound to a generation that is now fenced";
    return result;
  }
  if (result.active_grants.empty() && !historical_fenced.empty()) {
    result.outcome = Code::Fenced;
    result.reason = Code::Fenced;
    result.rationale = "every grant for this dependent was fenced";
    return result;
  }
  if (!result.active_grants.empty()) {
    result.outcome = Code::Unknown;
    result.reason = Code::Unknown;
    result.rationale = "active grants exist but confer no authority";
    return result;
  }
  if (saw_restart || saw_stale) {
    result.outcome = Code::Stale;
    result.reason = Code::Stale;
    result.rationale = "authority was minted before the current process incarnation";
    return result;
  }
  if (saw_expiry) {
    result.outcome = Code::Expired;
    result.reason = Code::Expired;
    result.rationale = "the grant validity window elapsed";
    return result;
  }
  if (saw_revocation) {
    result.outcome = Code::Denied;
    result.reason = Code::Denied;
    result.rationale = "authority was withdrawn";
    return result;
  }
  result.outcome = Code::Unknown;
  result.reason = Code::Unknown;
  result.rationale = "authority state could not be resolved";
  return result;
}

std::vector<AuthorityGrant> AuthorityRegistry::grants_for(const DependentRef& dependent) const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<AuthorityGrant> result;
  const auto index = by_dependent_.find(dependent);
  if (index == by_dependent_.end()) return result;
  result.reserve(index->second.size());
  for (const GrantId id : index->second) {
    const auto position = grants_.find(id);
    if (position != grants_.end()) result.push_back(position->second);
  }
  return result;
}

std::size_t AuthorityRegistry::active_grant_count() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::size_t count = 0;
  for (const auto& entry : grants_) {
    if (entry.second.state == GrantState::Active) count += 1;
  }
  return count;
}

std::size_t AuthorityRegistry::total_grant_count() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return grants_.size();
}

Status AuthorityRegistry::restore_grant(const AuthorityGrant& value) {
  if (!value.id.valid() || !value.dependent.valid()) {
    return Status::failure(Code::Invalid, "durable grant record is malformed");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  AuthorityGrant record = value;
  // Persistence is not liveness: a restored grant is never Active. It must be revalidated and
  // re-minted under the current epoch and boot incarnation.
  record.state = GrantState::Stale;
  record.cause = RevocationCause::Restart;
  record.detail = "restored from durable lineage; revalidation required";
  grants_[record.id] = record;
  auto& index = by_dependent_[record.dependent];
  if (std::find(index.begin(), index.end(), record.id) == index.end()) {
    index.push_back(record.id);
  }
  if (record.id.raw() >= next_grant_) next_grant_ = record.id.raw() + 1;
  if (record.attempt.raw() > attempt_) attempt_ = record.attempt.raw();
  return Status::success();
}

Status AuthorityRegistry::restore_fence(const FenceRecord& value) {
  if (!value.subject.valid()) {
    return Status::failure(Code::Invalid, "durable fence record is malformed");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  fences_[value.subject] = value;
  if (value.id.raw() >= next_fence_) next_fence_ = value.id.raw() + 1;
  return Status::success();
}

std::vector<AuthorityGrant> AuthorityRegistry::all_grants() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<AuthorityGrant> result;
  result.reserve(grants_.size());
  for (const auto& entry : grants_) result.push_back(entry.second);
  return result;
}

AttemptSeq AuthorityRegistry::last_attempt() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return AttemptSeq(attempt_);
}

}  // namespace sff
