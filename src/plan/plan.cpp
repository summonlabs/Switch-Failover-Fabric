// Switch Failover Fabric - reconstruction plans and effect accounting.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/plan/plan.hpp"

#include <algorithm>
#include <cstdint>

#include "sff/codec/bytes.hpp"

namespace sff {
namespace {

/// Format tag written at the head of every encoded plan. Bumping it invalidates old documents
/// rather than allowing them to be misread.
constexpr std::uint8_t kPlanFormatTag = 1;

void write_key(ByteWriter& writer, const SwitchKey& key) {
  writer.u64(key.id().raw());
  writer.u64(key.generation().raw());
}

SwitchKey read_key(ByteReader& reader) {
  const SwitchId id(reader.u64());
  const SwitchGeneration generation(reader.u64());
  return SwitchKey(id, generation);
}

void write_dependent(ByteWriter& writer, const DependentRef& dependent) {
  writer.u8(static_cast<std::uint8_t>(dependent.kind()));
  writer.u64(dependent.id());
}

DependentRef read_dependent(ByteReader& reader) {
  const std::uint8_t kind = reader.u8();
  const std::uint64_t id = reader.u64();
  if (!reader.ok()) return DependentRef{};
  if (!is_valid_dependent_kind(kind)) {
    reader.fail(Code::Invalid, "dependent kind is not defined");
    return DependentRef{};
  }
  return DependentRef(static_cast<DependentKind>(kind), id);
}

constexpr std::size_t kDependentBytes = 9;
constexpr std::size_t kKeyBytes = 16;
constexpr std::size_t kU64Bytes = 8;

std::size_t total_hops(const ReconstructionPlan& plan) noexcept {
  std::size_t total = 0;
  for (const auto& step : plan.restores) {
    if (total > SIZE_MAX - step.hops.size()) return SIZE_MAX;
    total += step.hops.size();
  }
  return total;
}

/// Comparison helper implementing the object-independent total order of the planner objective.
bool sequence_less(const ReconstructionPlan& a, const ReconstructionPlan& b) noexcept {
  const std::size_t shared = std::min(a.restores.size(), b.restores.size());
  for (std::size_t index = 0; index < shared; ++index) {
    const RestoreStep& left = a.restores[index];
    const RestoreStep& right = b.restores[index];
    if (left.dependent != right.dependent) return left.dependent < right.dependent;
    if (left.covers_failed != right.covers_failed) return left.covers_failed < right.covers_failed;
    if (left.action != right.action) {
      return static_cast<std::uint8_t>(left.action) < static_cast<std::uint8_t>(right.action);
    }
    if (left.replacement != right.replacement) return left.replacement < right.replacement;
    if (left.hops != right.hops) return left.hops < right.hops;
    if (left.links != right.links) return left.links < right.links;
    if (left.cost != right.cost) return left.cost < right.cost;
    if (left.evidence != right.evidence) return left.evidence < right.evidence;
  }
  return a.restores.size() < b.restores.size();
}

}  // namespace

std::uint64_t ReconstructionCandidate::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.reconstruction-candidate.v1");
  digest.absorb_dependent(dependent);
  digest.absorb_key(covers_failed);
  digest.absorb_u64(static_cast<std::uint64_t>(hops.size()));
  for (const auto& hop : hops) digest.absorb_key(hop);
  digest.absorb_u64(static_cast<std::uint64_t>(links.size()));
  for (const auto& link : links) digest.absorb_u64(link.raw());
  digest.absorb_u64(cost);
  digest.absorb_u64(capabilities);
  digest.absorb_u64(evidence.raw());
  digest.absorb_byte(static_cast<std::uint8_t>(source));
  return digest.hi;
}

Status ReconstructionCandidate::validate() const {
  if (!dependent.valid()) {
    return Status::failure(Code::Invalid, "reconstruction alternative names no dependent");
  }
  if (!covers_failed.valid()) {
    return Status::failure(Code::Invalid,
                           "reconstruction alternative is not bound to a failed generation");
  }
  if (hops.empty()) {
    return Status::failure(Code::Invalid, "reconstruction alternative supplies no hops");
  }
  for (const auto& hop : hops) {
    if (!hop.valid()) {
      return Status::failure(Code::Invalid,
                             "reconstruction alternative contains an unqualified generation");
    }
  }
  if (cost == 0) {
    return Status::failure(Code::Invalid, "reconstruction alternative has a zero cost");
  }
  return validate_capability_mask(capabilities);
}

const char* to_string(UnresolvedReason reason) noexcept {
  switch (reason) {
    case UnresolvedReason::Unknown: return "UNKNOWN";
    case UnresolvedReason::NoCandidateSupplied: return "NO_CANDIDATE_SUPPLIED";
    case UnresolvedReason::CandidateGenerationStale: return "CANDIDATE_GENERATION_STALE";
    case UnresolvedReason::CapabilityInsufficient: return "CAPABILITY_INSUFFICIENT";
    case UnresolvedReason::BehindFence: return "BEHIND_FENCE";
    case UnresolvedReason::CapacityExhausted: return "CAPACITY_EXHAUSTED";
    case UnresolvedReason::FailureDomainConflict: return "FAILURE_DOMAIN_CONFLICT";
    case UnresolvedReason::Withheld: return "WITHHELD";
    case UnresolvedReason::ClosureTruncated: return "CLOSURE_TRUNCATED";
    case UnresolvedReason::SearchLimitReached: return "SEARCH_LIMIT_REACHED";
    case UnresolvedReason::ContradictoryEvidence: return "CONTRADICTORY_EVIDENCE";
    case UnresolvedReason::HopNotInTopology: return "HOP_NOT_IN_TOPOLOGY";
    case UnresolvedReason::NonAuthoritativeOrigin: return "NON_AUTHORITATIVE_ORIGIN";
  }
  return "UNRECOGNISED_UNRESOLVED_REASON";
}

bool is_proven_negative(UnresolvedReason reason) noexcept {
  switch (reason) {
    case UnresolvedReason::NoCandidateSupplied:
    case UnresolvedReason::CandidateGenerationStale:
    case UnresolvedReason::CapabilityInsufficient:
    case UnresolvedReason::BehindFence:
    case UnresolvedReason::CapacityExhausted:
    case UnresolvedReason::FailureDomainConflict:
    case UnresolvedReason::Withheld:
    case UnresolvedReason::ContradictoryEvidence:
    case UnresolvedReason::HopNotInTopology:
    case UnresolvedReason::NonAuthoritativeOrigin:
      return true;
    default:
      // ClosureTruncated and SearchLimitReached are explicitly NOT proofs of absence.
      return false;
  }
}

std::uint64_t UnresolvedDependent::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.unresolved-dependent.v2");
  digest.absorb_dependent(dependent);
  digest.absorb_key(covers_failed);
  digest.absorb_byte(static_cast<std::uint8_t>(reason));
  digest.absorb_string(detail);
  return digest.hi;
}

const char* to_string(PlanAction action) noexcept {
  switch (action) {
    case PlanAction::Unknown: return "UNKNOWN";
    case PlanAction::RebindReplacement: return "REBIND_REPLACEMENT";
  }
  return "UNRECOGNISED_PLAN_ACTION";
}

std::uint64_t FenceStep::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.fence-step.v1");
  digest.absorb_key(failed);
  digest.absorb_u64(closure_digest);
  digest.absorb_byte(static_cast<std::uint8_t>(closure_state));
  digest.absorb_u64(closure_members);
  digest.absorb_u64(omitted_dependents);
  return digest.hi;
}

std::uint64_t RestoreStep::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.restore-step.v2");
  digest.absorb_dependent(dependent);
  digest.absorb_key(covers_failed);
  digest.absorb_byte(static_cast<std::uint8_t>(action));
  digest.absorb_key(replacement);
  digest.absorb_u64(static_cast<std::uint64_t>(hops.size()));
  for (const auto& hop : hops) digest.absorb_key(hop);
  digest.absorb_u64(static_cast<std::uint64_t>(links.size()));
  for (const auto& link : links) digest.absorb_u64(link.raw());
  digest.absorb_u64(cost);
  digest.absorb_u64(evidence.raw());
  return digest.hi;
}

const char* to_string(PlanFeasibility feasibility) noexcept {
  switch (feasibility) {
    case PlanFeasibility::Unknown: return "UNKNOWN";
    case PlanFeasibility::ProvenFeasible: return "PROVEN_FEASIBLE";
    case PlanFeasibility::ProvenInfeasible: return "PROVEN_INFEASIBLE";
    case PlanFeasibility::Indeterminate: return "INDETERMINATE";
    case PlanFeasibility::SearchLimitReached: return "SEARCH_LIMIT_REACHED";
    case PlanFeasibility::NothingToRestore: return "NOTHING_TO_RESTORE";
  }
  return "UNRECOGNISED_FEASIBILITY";
}

const char* to_string(PlanState state) noexcept {
  switch (state) {
    case PlanState::Draft: return "DRAFT";
    case PlanState::Validated: return "VALIDATED";
    case PlanState::Rejected: return "REJECTED";
    case PlanState::Committed: return "COMMITTED";
    case PlanState::Applying: return "APPLYING";
    case PlanState::Applied: return "APPLIED";
    case PlanState::PartiallyApplied: return "PARTIALLY_APPLIED";
    case PlanState::Failed: return "FAILED";
    case PlanState::Superseded: return "SUPERSEDED";
  }
  return "UNRECOGNISED_PLAN_STATE";
}

const char* to_string(AckState state) noexcept {
  switch (state) {
    case AckState::Unknown: return "UNKNOWN";
    case AckState::Applied: return "APPLIED";
    case AckState::Verified: return "VERIFIED";
    case AckState::Failed: return "FAILED";
    case AckState::Unverified: return "UNVERIFIED";
  }
  return "UNRECOGNISED_ACK_STATE";
}

std::uint64_t ReconstructionPlan::compute_digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.reconstruction-plan.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_u64(epoch.raw());
  digest.absorb_u64(boot.process_id());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_u64(boot.nonce_hi());
  digest.absorb_u64(boot.nonce_lo());
  digest.absorb_u64(failed_generations.digest());
  digest.absorb_u64(static_cast<std::uint64_t>(fences.size()));
  for (const auto& step : fences) digest.absorb_u64(step.digest());
  digest.absorb_u64(static_cast<std::uint64_t>(restores.size()));
  for (const auto& step : restores) digest.absorb_u64(step.digest());
  digest.absorb_u64(static_cast<std::uint64_t>(unresolved.size()));
  for (const auto& entry : unresolved) digest.absorb_u64(entry.digest());
  digest.absorb_byte(static_cast<std::uint8_t>(feasibility));
  digest.absorb_byte(static_cast<std::uint8_t>(state));
  digest.absorb_byte(closure_complete ? 1 : 0);
  digest.absorb_byte(service_withheld ? 1 : 0);
  digest.absorb_u64(topology_digest);
  digest.absorb_u64(policy_digest);
  return digest.hi;
}

std::uint64_t ReconstructionPlan::total_cost() const noexcept {
  std::uint64_t total = 0;
  for (const auto& step : restores) {
    if (total > UINT64_MAX - step.cost) return UINT64_MAX;
    total += step.cost;
  }
  return total;
}

bool operator<(const ReconstructionPlan& a, const ReconstructionPlan& b) noexcept {
  // "a < b" means a is strictly preferred under the planner's total objective.
  if (a.unresolved.size() != b.unresolved.size()) return a.unresolved.size() < b.unresolved.size();
  const std::uint64_t cost_a = a.total_cost();
  const std::uint64_t cost_b = b.total_cost();
  if (cost_a != cost_b) return cost_a < cost_b;
  const std::size_t hops_a = total_hops(a);
  const std::size_t hops_b = total_hops(b);
  if (hops_a != hops_b) return hops_a < hops_b;
  return sequence_less(a, b);
}

std::vector<std::uint8_t> ReconstructionPlan::encode() const {
  ByteWriter writer;
  writer.set_limit(std::size_t{8} << 20);
  writer.u8(kPlanFormatTag);
  writer.u64(id.raw());
  writer.u64(epoch.raw());
  writer.u64(boot.process_id());
  writer.u64(boot.boot_ordinal());
  writer.u64(boot.nonce_hi());
  writer.u64(boot.nonce_lo());

  writer.u32(static_cast<std::uint32_t>(failed_generations.size()));
  for (const auto& key : failed_generations.keys()) write_key(writer, key);

  writer.u32(static_cast<std::uint32_t>(fences.size()));
  for (const auto& step : fences) {
    write_key(writer, step.failed);
    writer.u64(step.closure_digest);
    writer.u8(static_cast<std::uint8_t>(step.closure_state));
    writer.u64(step.closure_members);
    writer.u64(step.omitted_dependents);
  }

  writer.u32(static_cast<std::uint32_t>(restores.size()));
  for (const auto& step : restores) {
    write_dependent(writer, step.dependent);
    write_key(writer, step.covers_failed);
    writer.u8(static_cast<std::uint8_t>(step.action));
    write_key(writer, step.replacement);
    writer.u32(static_cast<std::uint32_t>(step.hops.size()));
    for (const auto& hop : step.hops) write_key(writer, hop);
    writer.u32(static_cast<std::uint32_t>(step.links.size()));
    for (const auto& link : step.links) writer.u64(link.raw());
    writer.u32(step.cost);
    writer.u64(step.evidence.raw());
  }

  writer.u32(static_cast<std::uint32_t>(unresolved.size()));
  for (const auto& entry : unresolved) {
    write_dependent(writer, entry.dependent);
    write_key(writer, entry.covers_failed);
    writer.u8(static_cast<std::uint8_t>(entry.reason));
    writer.string(entry.detail);
  }

  writer.u8(static_cast<std::uint8_t>(feasibility));
  writer.u8(static_cast<std::uint8_t>(state));
  writer.boolean(closure_complete);
  writer.boolean(service_withheld);
  writer.u64(topology_digest);
  writer.u64(policy_digest);
  return writer.bytes();
}

Result<ReconstructionPlan> ReconstructionPlan::decode(const std::vector<std::uint8_t>& bytes,
                                                      const Limits& limits) {
  ByteReader reader(bytes);
  reader.set_element_limit(limits.max_plan_steps);
  const std::uint8_t tag = reader.u8();
  if (!reader.ok()) return reader.status();
  if (tag != kPlanFormatTag) {
    return Status::failure(Code::VersionMismatch, "reconstruction plan format tag is unsupported");
  }

  ReconstructionPlan plan;
  plan.id = PlanId(reader.u64());
  plan.epoch = CoordinatorEpoch(reader.u64());
  {
    // Argument evaluation order is unspecified in C++, so the four words are read into named
    // locals in sequence rather than passed directly to from_parts.
    const std::uint64_t process_id = reader.u64();
    const std::uint64_t boot_ordinal = reader.u64();
    const std::uint64_t nonce_hi = reader.u64();
    const std::uint64_t nonce_lo = reader.u64();
    plan.boot = BootIncarnation::from_parts(process_id, boot_ordinal, nonce_hi, nonce_lo);
  }

  const std::size_t failed_count = reader.list_count(kKeyBytes);
  plan.failed_generations = GenerationVector{};
  {
    std::vector<SwitchKey> keys;
    keys.reserve(failed_count);
    for (std::size_t index = 0; index < failed_count; ++index) keys.push_back(read_key(reader));
    plan.failed_generations = GenerationVector::canonicalise(std::move(keys));
  }

  const std::size_t fence_count = reader.list_count(kKeyBytes + 8 + 1 + 8 + 8);
  plan.fences.reserve(fence_count);
  for (std::size_t index = 0; index < fence_count; ++index) {
    FenceStep step;
    step.failed = read_key(reader);
    step.closure_digest = reader.u64();
    const std::uint8_t closure_state = reader.u8();
    step.closure_members = reader.u64();
    step.omitted_dependents = reader.u64();
    if (!reader.ok()) return reader.status();
    if (closure_state > static_cast<std::uint8_t>(ClosureState::Truncated)) {
      return Status::failure(Code::Invalid, "plan fence step has an undefined closure state");
    }
    step.closure_state = static_cast<ClosureState>(closure_state);
    plan.fences.push_back(std::move(step));
  }

  const std::size_t restore_count = reader.list_count(kDependentBytes + kKeyBytes + 1 + kKeyBytes + 4);
  plan.restores.reserve(restore_count);
  for (std::size_t index = 0; index < restore_count; ++index) {
    RestoreStep step;
    step.dependent = read_dependent(reader);
    step.covers_failed = read_key(reader);
    const std::uint8_t action = reader.u8();
    step.replacement = read_key(reader);
    if (!reader.ok()) return reader.status();
    if (action > static_cast<std::uint8_t>(PlanAction::RebindReplacement)) {
      return Status::failure(Code::Invalid, "plan restore step has an undefined action");
    }
    step.action = static_cast<PlanAction>(action);
    const std::size_t hops = reader.list_count(kKeyBytes);
    step.hops.reserve(hops);
    for (std::size_t hop = 0; hop < hops; ++hop) step.hops.push_back(read_key(reader));
    const std::size_t links = reader.list_count(kU64Bytes);
    step.links.reserve(links);
    for (std::size_t link = 0; link < links; ++link) step.links.push_back(LinkId(reader.u64()));
    step.cost = reader.u32();
    step.evidence = EvidenceId(reader.u64());
    if (!reader.ok()) return reader.status();
    if (step.hops.size() > limits.max_plan_steps || step.links.size() > limits.max_plan_steps) {
      return Status::failure(Code::Exhausted, "plan restore step exceeds the planning bound");
    }
    plan.restores.push_back(std::move(step));
  }

  const std::size_t unresolved_count = reader.list_count(kDependentBytes + kKeyBytes + 1);
  plan.unresolved.reserve(unresolved_count);
  for (std::size_t index = 0; index < unresolved_count; ++index) {
    UnresolvedDependent entry;
    entry.dependent = read_dependent(reader);
    entry.covers_failed = read_key(reader);
    const std::uint8_t reason = reader.u8();
    entry.detail = reader.string();
    if (!reader.ok()) return reader.status();
    if (reason > static_cast<std::uint8_t>(UnresolvedReason::NonAuthoritativeOrigin)) {
      return Status::failure(Code::Invalid, "plan unresolved entry has an undefined reason");
    }
    entry.reason = static_cast<UnresolvedReason>(reason);
    plan.unresolved.push_back(std::move(entry));
  }

  const std::uint8_t feasibility = reader.u8();
  const std::uint8_t state = reader.u8();
  plan.closure_complete = reader.boolean();
  plan.service_withheld = reader.boolean();
  plan.topology_digest = reader.u64();
  plan.policy_digest = reader.u64();
  if (!reader.ok()) return reader.status();
  if (feasibility > static_cast<std::uint8_t>(PlanFeasibility::NothingToRestore)) {
    return Status::failure(Code::Invalid, "plan has an undefined feasibility value");
  }
  if (state > static_cast<std::uint8_t>(PlanState::Superseded)) {
    return Status::failure(Code::Invalid, "plan has an undefined state value");
  }
  plan.feasibility = static_cast<PlanFeasibility>(feasibility);
  plan.state = static_cast<PlanState>(state);

  Status end = reader.require_end();
  if (!end.ok()) return end;

  plan.seal();
  if (plan.failed_generations.empty() && plan.fences.empty() && plan.restores.empty() &&
      plan.unresolved.empty() && !plan.id.valid()) {
    return Status::failure(Code::Invalid, "decoded plan is empty");
  }
  return plan;
}

std::uint64_t RestoreDecision::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.restore-decision.v1");
  digest.absorb_dependent(dependent);
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  digest.absorb_byte(static_cast<std::uint8_t>(reason));
  digest.absorb_byte(may_restore ? 1 : 0);
  digest.absorb_byte(effect_verified ? 1 : 0);
  digest.absorb_u64(bound.digest());
  digest.absorb_u64(plan.raw());
  for (const auto& id : grants) digest.absorb_u64(id.raw());
  for (const auto& key : blocking_generations) digest.absorb_key(key);
  digest.absorb_u64(explanation.digest());
  return digest.hi;
}

}  // namespace sff
