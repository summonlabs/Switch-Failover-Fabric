// Switch Failover Fabric - dependency authority, fencing and revocation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC ONLY. Every fixture is a synthetic, deterministic construction labelled SYNTHETIC;
// time is supplied explicitly, never read from a clock.
//
// The proposition under test: authority is granted per dependent and bound to exact generations,
// fencing one generation revokes exactly the grants bound to it, and no amount of persistence or
// acknowledgement is ever mistaken for live, verified authority.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "sff/model/authority.hpp"

#include "test_support.hpp"

namespace {

using sff::AttemptSeq;
using sff::AuthorityGrant;
using sff::AuthorityQuery;
using sff::AuthorityRegistry;
using sff::BootIncarnation;
using sff::Code;
using sff::CoordinatorEpoch;
using sff::DependentRef;
using sff::FenceId;
using sff::FenceRecord;
using sff::FenceScopeState;
using sff::GenerationVector;
using sff::GrantId;
using sff::GrantState;
using sff::Limits;
using sff::Result;
using sff::RevocationCause;
using sff::Status;
using sff::SwitchGeneration;
using sff::SwitchId;
using sff::SwitchKey;
using sff::TimestampNs;

constexpr TimestampNs kNow = 1000 * sff::kNanosPerSecond;
constexpr std::uint64_t kTtl = 60 * sff::kNanosPerSecond;

SwitchKey key(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

CoordinatorEpoch epoch() { return CoordinatorEpoch(1); }
CoordinatorEpoch next_epoch() { return CoordinatorEpoch(2); }
BootIncarnation boot() { return BootIncarnation::from_parts(4242, 1, 0x1111, 0x2222); }
BootIncarnation next_boot() { return BootIncarnation::from_parts(4242, 2, 0x3333, 0x4444); }

GenerationVector one(const SwitchKey& sw) { return GenerationVector::canonicalise({sw}); }
GenerationVector two(const SwitchKey& first, const SwitchKey& second) {
  return GenerationVector::canonicalise({first, second});
}

FenceRecord synth_fence(const SwitchKey& subject, const char* reason) {
  FenceRecord fence;
  fence.subject = subject;
  fence.epoch = epoch();
  fence.boot = boot();
  fence.created_at_ns = kNow;
  fence.scope_state = FenceScopeState::Committed;
  fence.reason = reason;
  return fence;
}

GrantId must_grant(AuthorityRegistry& registry, const DependentRef& dependent,
                   const GenerationVector& bound, TimestampNs now_ns, std::uint64_t ttl_ns,
                   const char* what) {
  const Result<GrantId> result =
      registry.grant(dependent, bound, epoch(), boot(), now_ns, ttl_ns, "SYNTHETIC grant");
  CHECK(result.ok());
  if (!result.ok()) {
    std::printf("  grant refused for %s: %s\n", what, result.status().to_string().c_str());
  }
  return result.value_or(GrantId{});
}

FenceId must_fence(AuthorityRegistry& registry, const SwitchKey& subject, const char* reason) {
  const Result<FenceId> result = registry.commit_fence(synth_fence(subject, reason));
  CHECK(result.ok());
  if (!result.ok()) {
    std::printf("  fence refused for %s: %s\n", reason, result.status().to_string().c_str());
  }
  return result.value_or(FenceId{});
}

/// Order-independent digest of a grant set, used to prove a refusal changed nothing.
std::uint64_t grants_digest(const std::vector<AuthorityGrant>& grants) {
  std::uint64_t folded = 0x9e3779b97f4a7c15ull;
  for (const auto& grant : grants) folded = sff::mix64(folded ^ grant.digest());
  return folded;
}

// --- minting ------------------------------------------------------------------------------------

SFF_TEST(grant_refusals_are_explicit_and_attempts_advance_only_on_success) {
  AuthorityRegistry registry;
  const DependentRef dependent = DependentRef::service(1);
  const SwitchKey live = key(1, 1);
  const SwitchKey doomed = key(2, 1);
  const AttemptSeq before = registry.last_attempt();

  const Result<GrantId> empty_bound =
      registry.grant(dependent, GenerationVector{}, epoch(), boot(), kNow, kTtl, "SYNTHETIC");
  CHECK(!empty_bound.ok());
  if (!empty_bound.ok()) CHECK(empty_bound.status().code() == Code::Invalid);

  const Result<GrantId> invalid_dependent =
      registry.grant(DependentRef{}, one(live), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
  CHECK(!invalid_dependent.ok());
  if (!invalid_dependent.ok()) CHECK(invalid_dependent.status().code() == Code::Invalid);

  const Result<GrantId> zero_ttl =
      registry.grant(dependent, one(live), epoch(), boot(), kNow, 0, "SYNTHETIC");
  CHECK(!zero_ttl.ok());
  if (!zero_ttl.ok()) CHECK(zero_ttl.status().code() == Code::Invalid);

  const Result<GrantId> no_epoch =
      registry.grant(dependent, one(live), CoordinatorEpoch(0), boot(), kNow, kTtl, "SYNTHETIC");
  CHECK(!no_epoch.ok());
  if (!no_epoch.ok()) CHECK(no_epoch.status().code() == Code::Unauthorized);

  const Result<GrantId> no_boot =
      registry.grant(dependent, one(live), epoch(), BootIncarnation{}, kNow, kTtl, "SYNTHETIC");
  CHECK(!no_boot.ok());
  if (!no_boot.ok()) CHECK(no_boot.status().code() == Code::Unauthorized);

  // A refused grant mints nothing and does not consume an attempt.
  CHECK_EQ(registry.total_grant_count(), std::size_t{0});
  CHECK_EQ(registry.active_grant_count(), std::size_t{0});
  CHECK(registry.last_attempt() == before);

  // A generation that is already fenced can never be bound.
  must_fence(registry, doomed, "SYNTHETIC fence before grant");
  const Result<GrantId> fenced =
      registry.grant(dependent, one(doomed), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
  CHECK(!fenced.ok());
  if (!fenced.ok()) CHECK(fenced.status().code() == Code::Fenced);
  CHECK(registry.last_attempt() == before);

  // Successful grants advance the attempt sequence monotonically and mint fresh identities.
  const GrantId first = must_grant(registry, DependentRef::service(1), one(live), kNow, kTtl, "first");
  const AttemptSeq after_first = registry.last_attempt();
  CHECK(after_first.raw() > before.raw());
  const GrantId second =
      must_grant(registry, DependentRef::service(2), one(key(3, 1)), kNow, kTtl, "second");
  const AttemptSeq after_second = registry.last_attempt();
  CHECK(after_second.raw() > after_first.raw());
  const GrantId third =
      must_grant(registry, DependentRef::service(3), one(key(4, 1)), kNow, kTtl, "third");
  CHECK(registry.last_attempt().raw() > after_second.raw());
  CHECK(second.raw() > first.raw());
  CHECK(third.raw() > second.raw());
  CHECK_EQ(registry.total_grant_count(), std::size_t{3});
  CHECK_EQ(registry.active_grant_count(), std::size_t{3});

  const std::vector<AuthorityGrant> recorded = registry.grants_for(DependentRef::service(1));
  CHECK_EQ(recorded.size(), std::size_t{1});
  if (!recorded.empty()) {
    CHECK(recorded.front().attempt == after_first);
    CHECK(recorded.front().state == GrantState::Active);
    CHECK(recorded.front().bound.contains(live));
  }
}

SFF_TEST(query_grants_authority_only_for_an_active_unexpired_unfenced_grant) {
  AuthorityRegistry registry;
  const DependentRef covered = DependentRef::service(10);
  const DependentRef never_granted = DependentRef::service(11);
  const SwitchKey bound = key(1, 1);

  const GrantId grant = must_grant(registry, covered, one(bound), kNow, kTtl, "covered");
  const AuthorityQuery active = registry.query(covered, kNow);
  CHECK(active.outcome == Code::Ok);
  CHECK(active.has_authority);
  CHECK_EQ(active.active_grants.size(), std::size_t{1});
  CHECK(active.active_grants.front() == grant);
  CHECK(active.withdrawn_grants.empty());
  CHECK(active.bound.contains(bound));
  CHECK(active.fenced_generations.empty());

  // The validity window is inclusive at its boundary.
  CHECK(registry.query(covered, kNow + kTtl).has_authority);
  CHECK_EQ(registry.expire_due(kNow + kTtl), std::size_t{0});
  CHECK(registry.query(covered, kNow + kTtl).outcome == Code::Ok);

  // Past the boundary the grant is elapsed, and the query says exactly that.
  CHECK_EQ(registry.expire_due(kNow + kTtl + 1), std::size_t{1});
  const AuthorityQuery elapsed = registry.query(covered, kNow + kTtl + 1);
  CHECK(elapsed.outcome == Code::Expired);
  CHECK(!elapsed.has_authority);
  CHECK_EQ(elapsed.active_grants.size(), std::size_t{0});
  CHECK_EQ(elapsed.withdrawn_grants.size(), std::size_t{1});

  // Ordinary absence: no grant was ever minted for this dependent.
  const AuthorityQuery absent = registry.query(never_granted, kNow);
  CHECK(absent.outcome == Code::NotFound);
  CHECK(absent.outcome != Code::Ok);
  CHECK(!absent.has_authority);
  CHECK(absent.active_grants.empty());
  CHECK(absent.withdrawn_grants.empty());
  CHECK(absent.fenced_generations.empty());
  CHECK(!absent.rationale.empty());
}

// --- fencing ------------------------------------------------------------------------------------

SFF_TEST(fencing_one_generation_revokes_exactly_the_grants_bound_to_it) {
  AuthorityRegistry registry;
  const DependentRef only_a = DependentRef::service(20);
  const DependentRef only_b = DependentRef::service(21);
  const DependentRef both = DependentRef::service(22);
  const SwitchKey a = key(1, 1);
  const SwitchKey b = key(2, 1);

  must_grant(registry, only_a, one(a), kNow, kTtl, "only a");
  must_grant(registry, only_b, one(b), kNow, kTtl, "only b");
  must_grant(registry, both, two(a, b), kNow, kTtl, "both");
  CHECK_EQ(registry.active_grant_count(), std::size_t{3});

  CHECK_EQ(registry.fence_generations(one(a), kNow), std::size_t{2});

  const AuthorityQuery fenced_a = registry.query(only_a, kNow);
  CHECK(fenced_a.outcome == Code::Fenced);
  CHECK(!fenced_a.has_authority);
  CHECK_EQ(fenced_a.active_grants.size(), std::size_t{0});
  CHECK_EQ(fenced_a.fenced_generations.size(), std::size_t{1});

  const AuthorityQuery fenced_both = registry.query(both, kNow);
  CHECK(fenced_both.outcome == Code::Fenced);
  CHECK(!fenced_both.has_authority);

  const AuthorityQuery untouched = registry.query(only_b, kNow);
  CHECK(untouched.outcome == Code::Ok);
  CHECK(untouched.has_authority);
  CHECK_EQ(untouched.active_grants.size(), std::size_t{1});
  CHECK(untouched.fenced_generations.empty());

  const std::vector<AuthorityGrant> revoked = registry.grants_for(only_a);
  CHECK_EQ(revoked.size(), std::size_t{1});
  if (!revoked.empty()) {
    CHECK(revoked.front().state == GrantState::Fenced);
    CHECK(revoked.front().cause == RevocationCause::Fence);
  }
  CHECK_EQ(registry.active_grant_count(), std::size_t{1});

  // Sweeping again revokes nothing further, and an empty scope is never a blanket revocation.
  CHECK_EQ(registry.fence_generations(one(a), kNow), std::size_t{0});
  CHECK_EQ(registry.fence_generations(GenerationVector{}, kNow), std::size_t{0});
  CHECK_EQ(registry.fence_generations(one(key(90, 1)), kNow), std::size_t{0});
  CHECK(registry.query(only_b, kNow).has_authority);

  // The committed fence is itself binding: query() never reports authority while an Active grant
  // is bound to a generation this registry has fenced, even before any sweep revokes that grant.
  {
    AuthorityRegistry late;
    const DependentRef dependent = DependentRef::service(23);
    const SwitchKey subject = key(3, 1);
    must_grant(late, dependent, one(subject), kNow, kTtl, "granted before the fence");
    CHECK(late.query(dependent, kNow).has_authority);
    must_fence(late, subject, "SYNTHETIC fence committed after the grant");
    const AuthorityQuery after_fence = late.query(dependent, kNow);
    CHECK(!after_fence.has_authority);
    CHECK(after_fence.outcome == Code::Fenced);
    CHECK_EQ(after_fence.fenced_generations.size(), std::size_t{1});
    CHECK(late.is_fenced(subject));
    // A different dependent bound only to an unfenced generation keeps its authority.
    const DependentRef other = DependentRef::service(24);
    must_grant(late, other, one(key(4, 1)), kNow, kTtl, "unrelated dependent");
    CHECK(late.query(other, kNow).has_authority);
  }
}

SFF_TEST(authority_follows_generations_and_never_a_matching_identity) {
  AuthorityRegistry registry;
  const SwitchKey old_generation = key(5, 1);
  const SwitchKey new_generation = key(5, 2);
  CHECK(old_generation.same_identity(new_generation));
  CHECK(old_generation != new_generation);

  must_fence(registry, old_generation, "SYNTHETIC generation one replaced");
  CHECK(registry.is_fenced(old_generation));
  CHECK(!registry.is_fenced(new_generation));
  CHECK(registry.identity_has_any_fence(SwitchId(5)));

  // The fenced generation can never be re-granted, however often it is asked for.
  const DependentRef dependent = DependentRef::service(30);
  for (int attempt = 0; attempt < 3; ++attempt) {
    const Result<GrantId> refused =
        registry.grant(dependent, one(old_generation), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK(refused.status().code() == Code::Fenced);
  }
  CHECK_EQ(registry.total_grant_count(), std::size_t{0});

  // A vector mixing a fenced generation with a live one is refused as a whole.
  const Result<GrantId> mixed = registry.grant(dependent, two(old_generation, new_generation), epoch(),
                                              boot(), kNow, kTtl, "SYNTHETIC");
  CHECK(!mixed.ok());
  if (!mixed.ok()) CHECK(mixed.status().code() == Code::Fenced);

  // The newer generation of the same identity is grantable, and doing so does not un-fence the old.
  const GrantId granted = must_grant(registry, dependent, one(new_generation), kNow, kTtl, "newer");
  const AuthorityQuery query = registry.query(dependent, kNow);
  CHECK(query.outcome == Code::Ok);
  CHECK(query.has_authority);
  CHECK(query.bound.contains(new_generation));
  CHECK(!query.bound.contains(old_generation));
  CHECK(registry.is_fenced(old_generation));
  CHECK_EQ(registry.fence_count(), std::size_t{1});
  CHECK(granted.valid());
}

SFF_TEST(commit_fence_refuses_a_second_fence_for_the_same_generation) {
  AuthorityRegistry registry;
  const SwitchKey subject = key(6, 1);

  FenceRecord first = synth_fence(subject, "SYNTHETIC first fence");
  first.closure_digest = 0xABCDEF01u;
  first.closure_members = 7;
  first.fenced_grants = 2;
  first.omitted_dependents = 1;
  const Result<FenceId> committed = registry.commit_fence(first);
  CHECK(committed.ok());
  const FenceId stored_id = committed.value_or(FenceId{});
  CHECK(stored_id.valid());

  FenceRecord second = synth_fence(subject, "SYNTHETIC second fence for the same generation");
  second.created_at_ns = kNow + 5000;
  second.closure_digest = 0xFFFFFFFFu;
  second.scope_state = FenceScopeState::Partial;
  const Result<FenceId> again = registry.commit_fence(second);
  CHECK(!again.ok());
  if (!again.ok()) CHECK(again.status().code() == Code::AlreadyExists);

  CHECK_EQ(registry.fence_count(), std::size_t{1});
  const std::vector<FenceRecord> fences = registry.fences();
  CHECK_EQ(fences.size(), std::size_t{1});
  if (!fences.empty()) {
    FenceRecord expected = first;
    expected.id = stored_id;
    CHECK_EQ(fences.front().digest(), expected.digest());
    CHECK(fences.front().reason == std::string("SYNTHETIC first fence"));
    CHECK_EQ(fences.front().created_at_ns, first.created_at_ns);
    CHECK_EQ(fences.front().closure_digest, first.closure_digest);
    CHECK(fences.front().scope_state == FenceScopeState::Committed);
    CHECK(fences.front().id == stored_id);
  }

  // Malformed fences are refused outright and change nothing.
  FenceRecord unqualified = first;
  unqualified.subject = key(6, 0);
  CHECK(registry.commit_fence(unqualified).status().code() == Code::Invalid);
  FenceRecord anonymous = synth_fence(key(7, 1), "SYNTHETIC placeholder");
  anonymous.reason.clear();
  CHECK(registry.commit_fence(anonymous).status().code() == Code::Invalid);
  CHECK_EQ(registry.fence_count(), std::size_t{1});

  // A different generation of the same identity is a different fence.
  must_fence(registry, key(6, 2), "SYNTHETIC next generation");
  CHECK_EQ(registry.fence_count(), std::size_t{2});
  CHECK(registry.is_fenced(key(6, 2)));
}

// --- restart ------------------------------------------------------------------------------------

SFF_TEST(pre_restart_invalidation_turns_every_active_grant_stale) {
  AuthorityRegistry registry;
  const DependentRef a = DependentRef::service(40);
  const DependentRef b = DependentRef::service(41);
  const SwitchKey bound = key(8, 1);
  must_grant(registry, a, one(bound), kNow, kTtl, "a");
  must_grant(registry, b, one(key(9, 1)), kNow, kTtl, "b");
  CHECK_EQ(registry.active_grant_count(), std::size_t{2});

  CHECK_EQ(registry.invalidate_pre_restart(next_epoch(), next_boot(), kNow), std::size_t{2});
  CHECK_EQ(registry.active_grant_count(), std::size_t{0});

  const AuthorityQuery stale = registry.query(a, kNow);
  CHECK(stale.outcome == Code::Stale);
  CHECK(stale.outcome != Code::Ok);
  CHECK(!stale.has_authority);
  CHECK_EQ(stale.withdrawn_grants.size(), std::size_t{1});
  const std::vector<AuthorityGrant> grants = registry.grants_for(a);
  CHECK_EQ(grants.size(), std::size_t{1});
  if (!grants.empty()) {
    CHECK(grants.front().state == GrantState::Stale);
    CHECK(grants.front().cause == RevocationCause::Restart);
  }
  CHECK(registry.query(b, kNow).outcome == Code::Stale);

  // The boundary is crossed once: repeating it invalidates nothing more.
  CHECK_EQ(registry.invalidate_pre_restart(next_epoch(), next_boot(), kNow), std::size_t{0});

  // A grant minted after the restart is live authority, and the abandoned one stays stale.
  must_grant(registry, a, one(bound), kNow, kTtl, "after restart");
  const AuthorityQuery refreshed = registry.query(a, kNow);
  CHECK(refreshed.outcome == Code::Ok);
  CHECK(refreshed.has_authority);
  CHECK_EQ(refreshed.active_grants.size(), std::size_t{1});
  CHECK_EQ(refreshed.withdrawn_grants.size(), std::size_t{1});
  CHECK_EQ(registry.grants_for(a).size(), std::size_t{2});
}

SFF_TEST(a_restored_grant_is_stale_however_active_the_durable_record_looked) {
  AuthorityRegistry registry;
  const DependentRef dependent = DependentRef::service(50);
  const SwitchKey bound = key(10, 1);

  AuthorityGrant durable;
  durable.id = GrantId(77);
  durable.dependent = dependent;
  durable.bound = one(bound);
  durable.epoch = epoch();
  durable.boot = boot();
  durable.attempt = AttemptSeq(9);
  durable.granted_at_ns = kNow;
  durable.expires_at_ns = kNow + 100 * kTtl;
  durable.state = GrantState::Active;
  durable.detail = "SYNTHETIC durable grant recorded before the restart";

  const Status restored = registry.restore_grant(durable);
  CHECK(restored.ok());
  const std::vector<AuthorityGrant> grants = registry.grants_for(dependent);
  CHECK_EQ(grants.size(), std::size_t{1});
  if (!grants.empty()) {
    // The durable record said Active and its window is wide open; persistence is still not liveness.
    CHECK(grants.front().state == GrantState::Stale);
    CHECK(grants.front().cause == RevocationCause::Restart);
  }
  const AuthorityQuery query = registry.query(dependent, kNow);
  CHECK(query.outcome == Code::Stale);
  CHECK(!query.has_authority);
  CHECK_EQ(registry.active_grant_count(), std::size_t{0});

  // Restoring does not rewind the attempt lineage, and a later grant never reuses a used identity.
  CHECK(registry.last_attempt().raw() >= 9);
  const GrantId fresh = must_grant(registry, dependent, one(bound), kNow, kTtl, "after restore");
  CHECK(fresh.raw() > 77);
  CHECK(registry.query(dependent, kNow).has_authority);

  // Malformed durable grants are refused rather than half-restored.
  AuthorityGrant anonymous = durable;
  anonymous.id = GrantId(0);
  CHECK(registry.restore_grant(anonymous).code() == Code::Invalid);
  AuthorityGrant unbound = durable;
  unbound.dependent = DependentRef{};
  CHECK(registry.restore_grant(unbound).code() == Code::Invalid);
  CHECK_EQ(registry.grants_for(dependent).size(), std::size_t{2});

  // Restored fences are durable lineage, and grants bound to them are refused.
  FenceRecord fence = synth_fence(key(11, 1), "SYNTHETIC restored fence");
  fence.id = FenceId(5);
  CHECK(registry.restore_fence(fence).ok());
  CHECK(registry.is_fenced(key(11, 1)));
  CHECK(registry.restore_fence(FenceRecord{}).code() == Code::Invalid);
  CHECK(registry.grant(dependent, one(key(11, 1)), epoch(), boot(), kNow, kTtl, "SYNTHETIC")
            .status()
            .code() == Code::Fenced);
}

// --- expiry and withdrawal ----------------------------------------------------------------------

SFF_TEST(expire_due_moves_elapsed_grants_to_expired) {
  AuthorityRegistry registry;
  const DependentRef short_lived = DependentRef::service(60);
  const DependentRef long_lived = DependentRef::service(61);
  must_grant(registry, short_lived, one(key(12, 1)), kNow, 100 * sff::kNanosPerSecond, "short");
  must_grant(registry, long_lived, one(key(13, 1)), kNow, 10000 * sff::kNanosPerSecond, "long");
  CHECK_EQ(registry.active_grant_count(), std::size_t{2});

  // Exactly at the boundary nothing has elapsed yet.
  const TimestampNs boundary = kNow + 100 * sff::kNanosPerSecond;
  CHECK_EQ(registry.expire_due(boundary), std::size_t{0});
  CHECK(registry.query(short_lived, boundary).has_authority);

  CHECK_EQ(registry.expire_due(boundary + 1), std::size_t{1});
  const AuthorityQuery elapsed = registry.query(short_lived, boundary + 1);
  CHECK(elapsed.outcome == Code::Expired);
  CHECK(!elapsed.has_authority);
  CHECK_EQ(elapsed.withdrawn_grants.size(), std::size_t{1});
  const std::vector<AuthorityGrant> grants = registry.grants_for(short_lived);
  CHECK_EQ(grants.size(), std::size_t{1});
  if (!grants.empty()) {
    CHECK(grants.front().state == GrantState::Expired);
    CHECK(grants.front().cause == RevocationCause::Expiry);
  }
  CHECK(registry.query(long_lived, boundary + 1).outcome == Code::Ok);
  CHECK(registry.query(long_lived, boundary + 1).has_authority);
  CHECK_EQ(registry.active_grant_count(), std::size_t{1});
  CHECK_EQ(registry.expire_due(boundary + 1), std::size_t{0});
}

SFF_TEST(withdraw_all_removes_every_grant_and_is_not_a_durable_fence) {
  AuthorityRegistry registry;
  const std::vector<DependentRef> dependents = {DependentRef::service(70), DependentRef::service(71),
                                                DependentRef::service(72)};
  must_grant(registry, dependents[0], one(key(14, 1)), kNow, kTtl, "first");
  must_grant(registry, dependents[1], one(key(15, 1)), kNow, kTtl, "second");
  must_grant(registry, dependents[2], one(key(16, 1)), kNow, kTtl, "third");
  CHECK_EQ(registry.active_grant_count(), std::size_t{3});

  CHECK_EQ(registry.withdraw_all(RevocationCause::Shutdown, "SYNTHETIC shutdown"), std::size_t{3});
  CHECK_EQ(registry.active_grant_count(), std::size_t{0});
  for (const auto& dependent : dependents) {
    const AuthorityQuery query = registry.query(dependent, kNow);
    CHECK(!query.has_authority);
    CHECK(query.outcome != Code::Ok);
    CHECK(sff::is_fail_closed(query.outcome));
    CHECK_EQ(query.active_grants.size(), std::size_t{0});
    CHECK_EQ(query.withdrawn_grants.size(), std::size_t{1});
  }
  CHECK_EQ(registry.withdraw_all(RevocationCause::Shutdown, "SYNTHETIC shutdown again"),
           std::size_t{0});

  // Withdrawal is bookkeeping, not lineage: nothing was fenced, so authority can be re-minted.
  CHECK(!registry.is_fenced(key(14, 1)));
  const GrantId again = must_grant(registry, dependents[0], one(key(14, 1)), kNow, kTtl, "re-granted");
  CHECK(registry.query(dependents[0], kNow).has_authority);

  // An explicit per-grant revocation is reported, and an unknown grant is ordinary absence.
  CHECK(registry.revoke(again, RevocationCause::OperatorRevocation, "SYNTHETIC revocation").ok());
  const AuthorityQuery revoked = registry.query(dependents[0], kNow);
  CHECK(!revoked.has_authority);
  CHECK(revoked.outcome != Code::Ok);
  CHECK(registry.revoke(GrantId(0xFFFF), RevocationCause::OperatorRevocation, "SYNTHETIC")
            .code() == Code::NotFound);
}

// --- bounds -------------------------------------------------------------------------------------

SFF_TEST(authority_and_fence_bounds_refuse_deterministically) {
  Limits grant_limits = Limits::defaults();
  grant_limits.max_authority_grants = 3;
  const SwitchKey live = key(20, 1);
  {
    AuthorityRegistry registry(grant_limits);
    must_grant(registry, DependentRef::service(80), one(live), kNow, kTtl, "one");
    must_grant(registry, DependentRef::service(81), one(key(21, 1)), kNow, kTtl, "two");
    must_grant(registry, DependentRef::service(82), one(key(22, 1)), kNow, kTtl, "three");
    CHECK_EQ(registry.total_grant_count(), std::size_t{3});

    const std::uint64_t before = grants_digest(registry.all_grants());
    const Result<GrantId> refused =
        registry.grant(DependentRef::service(83), one(key(23, 1)), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
    CHECK(!refused.ok());
    if (!refused.ok()) CHECK(refused.status().code() == Code::Exhausted);
    // Repeated attempts are refused identically and disturb nothing already granted.
    const Result<GrantId> repeated =
        registry.grant(DependentRef::service(83), one(key(23, 1)), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
    CHECK(!repeated.ok());
    if (!repeated.ok()) CHECK(repeated.status().code() == Code::Exhausted);
    CHECK_EQ(registry.total_grant_count(), std::size_t{3});
    CHECK_EQ(grants_digest(registry.all_grants()), before);
    CHECK(registry.query(DependentRef::service(80), kNow).has_authority);

    // Precedence is deterministic: a fenced generation is reported as fenced even at the bound.
    must_fence(registry, key(24, 1), "SYNTHETIC");
    const Result<GrantId> fenced =
        registry.grant(DependentRef::service(84), one(key(24, 1)), epoch(), boot(), kNow, kTtl, "SYNTHETIC");
    CHECK(!fenced.ok());
    if (!fenced.ok()) CHECK(fenced.status().code() == Code::Fenced);
  }

  Limits fence_limits = Limits::defaults();
  fence_limits.max_fences = 2;
  AuthorityRegistry fences(fence_limits);
  const SwitchKey first = key(30, 1);
  const SwitchKey second = key(31, 1);
  const SwitchKey third = key(32, 1);
  must_fence(fences, first, "SYNTHETIC first");
  must_fence(fences, second, "SYNTHETIC second");
  CHECK_EQ(fences.fence_count(), std::size_t{2});

  const Result<FenceId> refused = fences.commit_fence(synth_fence(third, "SYNTHETIC third"));
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK(refused.status().code() == Code::Exhausted);
  CHECK_EQ(fences.fence_count(), std::size_t{2});
  CHECK(!fences.is_fenced(third));
  // A duplicate of an existing fence is refused as a duplicate, not as exhaustion.
  const Result<FenceId> duplicate = fences.commit_fence(synth_fence(first, "SYNTHETIC duplicate"));
  CHECK(!duplicate.ok());
  if (!duplicate.ok()) CHECK(duplicate.status().code() == Code::AlreadyExists);
  CHECK_EQ(fences.fence_count(), std::size_t{2});
  CHECK(fences.is_fenced(first));
  CHECK(fences.is_fenced(second));
}

}  // namespace

SFF_MAIN()
