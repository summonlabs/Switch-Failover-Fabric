// Switch Failover Fabric - dependency authority, fencing and revocation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_AUTHORITY_HPP
#define SFF_MODEL_AUTHORITY_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"
#include "sff/export.hpp"

namespace sff {

enum class GrantState : std::uint8_t {
  Unknown = 0,
  Active = 1,   ///< Affirmative forwarding authority under the bound generations.
  Stale = 2,    ///< Revalidation required after a process/epoch boundary.
  Revoked = 3,  ///< Explicitly withdrawn.
  Expired = 4,  ///< Validity window elapsed.
  Fenced = 5,   ///< Withdrawn because a bound generation was fenced.
};

SFF_API const char* to_string(GrantState state) noexcept;

enum class RevocationCause : std::uint8_t {
  Unknown = 0,
  Superseded = 1,
  Fence = 2,
  Restart = 3,
  Expiry = 4,
  OperatorRevocation = 5,
  RevalidationFailed = 6,
  Shutdown = 7,
};

SFF_API const char* to_string(RevocationCause cause) noexcept;

/// A grant of forwarding authority to one dependent resource, bound to exact generations.
struct SFF_API AuthorityGrant {
  GrantId id;
  DependentRef dependent;
  GenerationVector bound;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  AttemptSeq attempt;
  TimestampNs granted_at_ns = 0;
  TimestampNs expires_at_ns = 0;
  GrantState state = GrantState::Active;
  RevocationCause cause = RevocationCause::Unknown;
  std::string detail;

  std::uint64_t digest() const noexcept;
  bool active_at(TimestampNs now_ns) const noexcept;
};

enum class FenceScopeState : std::uint8_t {
  Open = 0,
  Partial = 1,    ///< Closure was truncated by a bound; obligations are explicit but incomplete.
  Committed = 2,
};

SFF_API const char* to_string(FenceScopeState state) noexcept;

/// A committed fence over one switch generation.
///
/// A fence is durable lineage and is never silently removed. Recovery of the generation allows
/// new grants; it does not restore old ones.
struct SFF_API FenceRecord {
  FenceId id;
  SwitchKey subject;
  CoordinatorEpoch epoch;
  BootIncarnation boot;
  TimestampNs created_at_ns = 0;
  FenceScopeState scope_state = FenceScopeState::Open;
  std::uint64_t closure_digest = 0;
  std::size_t closure_members = 0;
  std::size_t fenced_grants = 0;
  std::size_t omitted_dependents = 0;
  std::string reason;

  std::uint64_t digest() const noexcept;
};

/// Outcome of an authority query over one dependent resource.
///
/// has_authority is true exactly when at least one Active, unexpired grant exists and none of the
/// generations that grant is bound to is fenced. A fence applied to a superseded grant is history:
/// it is listed in fenced_generations for audit, but it never re-denies authority that was
/// legitimately re-established on a different generation afterwards.
struct SFF_API AuthorityQuery {
  DependentRef dependent;
  bool has_authority = false;
  Code outcome = Code::Unknown;
  Code reason = Code::Unknown;
  GenerationVector bound;
  std::vector<GrantId> active_grants;
  std::vector<GrantId> withdrawn_grants;
  std::vector<SwitchKey> fenced_generations;
  std::vector<SwitchKey> unproven_generations;
  std::string rationale;
  std::uint64_t digest() const noexcept;
};

/// Registry of grants and fences.
///
/// The registry owns only authority bookkeeping. Whether a bound generation is currently
/// usable is decided by the runtime from evidence; the registry contributes fence state and
/// grant lifecycle, which is exactly the part that must survive restart.
class SFF_API AuthorityRegistry {
 public:
  explicit AuthorityRegistry(Limits limits = Limits::defaults());

  /// Mint a grant. Refuses when the dependent is invalid, the generation vector is empty or
  /// contains an invalid key, the time-to-live is zero, or any bound generation is fenced.
  Result<GrantId> grant(const DependentRef& dependent,
                        const GenerationVector& bound,
                        CoordinatorEpoch epoch,
                        const BootIncarnation& boot,
                        TimestampNs now_ns,
                        std::uint64_t ttl_ns,
                        std::string_view detail = {});

  Status revoke(GrantId id, RevocationCause cause, std::string_view detail = {});

  /// Revoke every grant bound to any of the supplied generations. Returns the number revoked.
  std::size_t fence_generations(const GenerationVector& generations, TimestampNs now_ns);

  /// Revoke every grant for a dependent. Returns the number revoked.
  std::size_t revoke_dependent(const DependentRef& dependent, RevocationCause cause,
                               std::string_view detail = {});

  /// Mark every grant minted before the boundary as Stale. Called exactly once per process boot.
  std::size_t invalidate_pre_restart(CoordinatorEpoch new_epoch, const BootIncarnation& new_boot,
                                     TimestampNs now_ns);

  /// Expire grants whose validity window has elapsed. Returns the number expired.
  std::size_t expire_due(TimestampNs now_ns);

  /// Withdraw every grant that is not already withdrawn, whatever its state. Used by the
  /// fence-on-restart policy, which refuses to carry even stale authority across a process
  /// boundary.
  std::size_t withdraw_all(RevocationCause cause, std::string_view detail);

  /// Commit a fence. Returns AlreadyExists when the exact generation is already fenced.
  Result<FenceId> commit_fence(FenceRecord record);
  bool is_fenced(const SwitchKey& key) const;
  bool identity_has_any_fence(SwitchId id) const;
  std::vector<FenceRecord> fences() const;
  std::size_t fence_count() const;

  /// Full authority picture for one dependent. Never claims authority without an Active grant
  /// whose bound generations are all unfenced.
  AuthorityQuery query(const DependentRef& dependent, TimestampNs now_ns) const;

  std::vector<AuthorityGrant> grants_for(const DependentRef& dependent) const;
  std::size_t active_grant_count() const;
  std::size_t total_grant_count() const;

  /// Restore durable state during recovery. Bypasses freshness checks by design: what is
  /// restored is lineage, and every restored grant is forced to Stale.
  Status restore_grant(const AuthorityGrant& grant);
  Status restore_fence(const FenceRecord& fence);

  /// Every grant, canonical order. Used to build durable checkpoints.
  std::vector<AuthorityGrant> all_grants() const;

  const Limits& limits() const noexcept { return limits_; }
  AttemptSeq last_attempt() const;

 private:
  mutable std::mutex mutex_;
  Limits limits_;
  std::map<GrantId, AuthorityGrant> grants_;
  std::map<DependentRef, std::vector<GrantId>> by_dependent_;
  std::map<SwitchKey, FenceRecord> fences_;
  std::uint64_t next_grant_ = 1;
  std::uint64_t next_fence_ = 1;
  std::uint64_t attempt_ = 0;
};

}  // namespace sff

#endif  // SFF_MODEL_AUTHORITY_HPP
