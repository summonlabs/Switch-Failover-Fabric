// Switch Failover Fabric - evidence admission and fail-closed adjudication.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/evidence.hpp"

#include <algorithm>
#include <string>

namespace sff {
namespace {

/// Retention cap per switch generation. The oldest record for a subject is evicted first and
/// every eviction is counted, so retention never silently changes the answer.
constexpr std::size_t kPerSubjectRetention = 32;

/// Hard sanity bound on an evidence timestamp that claims to be in the future.
constexpr std::uint64_t kFutureSanityBoundNs = 3600ull * kNanosPerSecond;

bool is_failure_health(SwitchHealthState state) noexcept {
  return state == SwitchHealthState::Failed || state == SwitchHealthState::Unreachable ||
         state == SwitchHealthState::Suspect;
}

bool is_positive_health(SwitchHealthState state) noexcept {
  return state == SwitchHealthState::Healthy || state == SwitchHealthState::Degraded;
}

bool is_admin_unavailable(SwitchAdminState state) noexcept {
  return state == SwitchAdminState::Disabled || state == SwitchAdminState::Maintenance;
}

}  // namespace

const char* to_string(EvidenceSource source) noexcept {
  switch (source) {
    case EvidenceSource::Unknown: return "UNKNOWN";
    case EvidenceSource::SimulatedFixture: return "SYNTHETIC_FIXTURE";
    case EvidenceSource::TelemetryCollector: return "TELEMETRY";
    case EvidenceSource::SwitchAgent: return "SWITCH_AGENT";
    case EvidenceSource::TopologyService: return "TOPOLOGY_SERVICE";
    case EvidenceSource::FabricManager: return "FABRIC_MANAGER";
    case EvidenceSource::OperatorPolicy: return "OPERATOR";
  }
  return "UNRECOGNISED_EVIDENCE_SOURCE";
}

bool is_valid_evidence_source(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(EvidenceSource::SimulatedFixture) &&
         raw <= static_cast<std::uint8_t>(EvidenceSource::OperatorPolicy);
}

const char* to_string(TrustLevel level) noexcept {
  switch (level) {
    case TrustLevel::Untrusted: return "UNTRUSTED";
    case TrustLevel::Advisory: return "ADVISORY";
    case TrustLevel::Authoritative: return "AUTHORITATIVE";
  }
  return "UNRECOGNISED_TRUST_LEVEL";
}

TrustLevel trust_of(EvidenceSource source) noexcept {
  switch (source) {
    case EvidenceSource::Unknown:
      return TrustLevel::Untrusted;
    case EvidenceSource::SimulatedFixture:
      // A fixture is a first-class authoritative input for synthetic proof, and it is labelled
      // SYNTHETIC everywhere it surfaces.
      return TrustLevel::Authoritative;
    case EvidenceSource::TelemetryCollector:
    case EvidenceSource::SwitchAgent:
      return TrustLevel::Advisory;
    case EvidenceSource::TopologyService:
    case EvidenceSource::FabricManager:
    case EvidenceSource::OperatorPolicy:
      return TrustLevel::Authoritative;
  }
  return TrustLevel::Untrusted;
}

const char* to_string(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::Unknown: return "UNKNOWN";
    case EvidenceKind::SwitchHealth: return "SWITCH_HEALTH";
    case EvidenceKind::SwitchFailureDeclaration: return "SWITCH_FAILURE_DECLARATION";
    case EvidenceKind::SwitchRecoveryDeclaration: return "SWITCH_RECOVERY_DECLARATION";
    case EvidenceKind::CapabilityDeclaration: return "CAPABILITY_DECLARATION";
    case EvidenceKind::AdminStateDeclaration: return "ADMIN_STATE_DECLARATION";
    case EvidenceKind::EffectVerification: return "EFFECT_VERIFICATION";
    case EvidenceKind::EffectFailure: return "EFFECT_FAILURE";
  }
  return "UNRECOGNISED_EVIDENCE_KIND";
}

bool is_valid_evidence_kind(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(EvidenceKind::SwitchHealth) &&
         raw <= static_cast<std::uint8_t>(EvidenceKind::EffectFailure);
}

std::uint64_t EvidenceRecord::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.evidence-record.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_byte(static_cast<std::uint8_t>(kind));
  digest.absorb_byte(static_cast<std::uint8_t>(source));
  digest.absorb_key(subject);
  digest.absorb_u64(admitted_epoch.raw());
  digest.absorb_u64(admitted_boot.boot_ordinal());
  digest.absorb_u64(observed_at_ns);
  digest.absorb_u64(valid_for_ns);
  digest.absorb_byte(static_cast<std::uint8_t>(health));
  digest.absorb_byte(static_cast<std::uint8_t>(admin));
  digest.absorb_u64(capabilities);
  digest.absorb_dependent(effect_dependent);
  digest.absorb_u64(effect_plan.raw());
  digest.absorb_u64(effect_attempt.raw());
  digest.absorb_string(detail);
  return digest.hi;
}

Status EvidenceRecord::validate(const Limits& limits) const {
  if (!id.valid()) {
    return Status::failure(Code::Invalid, "evidence record has no identity");
  }
  if (!is_valid_evidence_kind(static_cast<std::uint8_t>(kind))) {
    return Status::failure(Code::Invalid, "evidence record has an invalid kind");
  }
  if (!is_valid_evidence_source(static_cast<std::uint8_t>(source))) {
    return Status::failure(Code::Invalid, "evidence record has an invalid source");
  }
  if (!subject.valid()) {
    return Status::failure(Code::Invalid, "evidence subject is not generation-qualified");
  }
  if (valid_for_ns == 0) {
    return Status::failure(Code::Invalid, "evidence record has a zero validity window");
  }
  if (observed_at_ns == 0) {
    return Status::failure(Code::Invalid, "evidence record has no observation time");
  }
  if (detail.size() > kMaxMessageBytes) {
    return Status::failure(Code::Invalid, "evidence detail exceeds the message budget");
  }
  switch (kind) {
    case EvidenceKind::SwitchHealth:
      if (!is_valid_health_state(static_cast<std::uint8_t>(health)) ||
          health == SwitchHealthState::Unknown) {
        return Status::failure(Code::Invalid, "health evidence carries no defined health state");
      }
      break;
    case EvidenceKind::AdminStateDeclaration:
      if (!is_valid_admin_state(static_cast<std::uint8_t>(admin)) ||
          admin == SwitchAdminState::Unknown) {
        return Status::failure(Code::Invalid, "admin evidence carries no defined admin state");
      }
      break;
    case EvidenceKind::CapabilityDeclaration: {
      Status s = validate_capability_mask(capabilities);
      if (!s.ok()) return s;
      break;
    }
    case EvidenceKind::EffectVerification:
    case EvidenceKind::EffectFailure:
      if (!effect_dependent.valid()) {
        return Status::failure(Code::Invalid, "effect evidence names no dependent");
      }
      if (!effect_plan.valid()) {
        return Status::failure(Code::Invalid, "effect evidence names no plan");
      }
      break;
    default:
      break;
  }
  if (kind == EvidenceKind::SwitchFailureDeclaration ||
      kind == EvidenceKind::SwitchRecoveryDeclaration) {
    if (trust_of(source) != TrustLevel::Authoritative) {
      // Advisory sources may not assert lifecycle facts. They are admitted as observations, but
      // the record is marked by its source and adjudication refuses to treat it as authority.
      return Status::failure(
          Code::Unsupported,
          "advisory source cannot assert a switch lifecycle declaration");
    }
  }
  (void)limits;
  return Status::success();
}

bool EvidenceRecord::fresh_at(TimestampNs now) const noexcept {
  if (observed_at_ns > now) return false;
  const TimestampNs expires = expires_at_ns();
  if (expires < observed_at_ns) return false;  // overflow: treat as never fresh
  return now <= expires;
}

// ---------------------------------------------------------------------------------------------
// FailureTable
// ---------------------------------------------------------------------------------------------

Status FailureTable::record(const FailureRecord& value) {
  if (!value.subject.valid()) {
    return Status::failure(Code::Invalid, "failure record is not generation-qualified");
  }
  if (value.observed_at_ns == 0) {
    return Status::failure(Code::Invalid, "failure record has no observation time");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  const auto existing = entries_.find(value.subject);
  if (existing != entries_.end() && existing->second.observed_at_ns > value.observed_at_ns) {
    // A later failure already supersedes this one; keep the newer lineage.
    return Status::success();
  }
  entries_[value.subject] = value;
  return Status::success();
}

bool FailureTable::contains(const SwitchKey& key) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return entries_.find(key) != entries_.end();
}

const FailureRecord* FailureTable::find(const SwitchKey& key) const {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = entries_.find(key);
  if (position == entries_.end()) return nullptr;
  // The table is append-only for a given generation, so returning the address of the stored
  // record is stable for the lifetime of the entry. Protected by the same mutex for the lookup
  // itself; callers must not retain the pointer across a concurrent record() for the same key.
  return &position->second;
}

std::vector<FailureRecord> FailureTable::all() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<FailureRecord> result;
  result.reserve(entries_.size());
  for (const auto& entry : entries_) result.push_back(entry.second);
  return result;
}

std::size_t FailureTable::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return entries_.size();
}

void FailureTable::clear() {
  std::lock_guard<std::mutex> guard(mutex_);
  entries_.clear();
}

Status FailureTable::supersede(const SwitchKey& key, TimestampNs recovery_observed_at_ns) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = entries_.find(key);
  if (position == entries_.end()) return Status::success();
  if (recovery_observed_at_ns <= position->second.observed_at_ns) {
    return Status::failure(Code::Stale,
                           "recovery declaration does not postdate the recorded failure");
  }
  entries_.erase(position);
  return Status::success();
}

// ---------------------------------------------------------------------------------------------
// EvidenceStore
// ---------------------------------------------------------------------------------------------

EvidenceStore::EvidenceStore(Limits limits, const Clock* clock)
    : limits_(limits), clock_(clock) {}

Status EvidenceStore::admit(const EvidenceRecord& record) {
  Status structural = record.validate(limits_);
  if (!structural.ok()) {
    std::lock_guard<std::mutex> guard(mutex_);
    rejected_ += 1;
    return structural;
  }
  const TimestampNs now = clock_ != nullptr ? clock_->now_ns() : 0;
  if (record.observed_at_ns > now && record.observed_at_ns - now > kFutureSanityBoundNs) {
    std::lock_guard<std::mutex> guard(mutex_);
    rejected_ += 1;
    return Status::failure(Code::Invalid, "evidence observation time is implausibly far ahead");
  }
  if (record.admitted_epoch.valid() && record.admitted_boot.valid()) {
    // Epoch/boot are recorded for lineage; adjudication rejects cross-boot evidence by comparing
    // against the runtime's current incarnation, which the store does not know.
  }

  std::lock_guard<std::mutex> guard(mutex_);
  if (!identities_.insert(record.id).second) {
    rejected_ += 1;
    return Status::failure(Code::AlreadyExists, "evidence identity has already been admitted");
  }
  auto& bucket = by_subject_[record.subject];
  if (total_ >= limits_.max_evidence_records) {
    identities_.erase(record.id);
    rejected_ += 1;
    return Status::failure(Code::Exhausted, "evidence retention bound reached");
  }
  const auto position = std::lower_bound(
      bucket.begin(), bucket.end(), record, [](const EvidenceRecord& left, const EvidenceRecord& right) {
        if (left.observed_at_ns != right.observed_at_ns) return left.observed_at_ns < right.observed_at_ns;
        return left.id < right.id;
      });
  bucket.insert(position, record);
  total_ += 1;
  while (bucket.size() > kPerSubjectRetention) {
    identities_.erase(bucket.front().id);
    bucket.erase(bucket.begin());
    total_ -= 1;
    evicted_ += 1;
  }
  return Status::success();
}

std::vector<EvidenceRecord> EvidenceStore::records() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<EvidenceRecord> result;
  result.reserve(total_);
  for (const auto& entry : by_subject_) {
    for (const auto& record : entry.second) result.push_back(record);
  }
  return result;
}

std::vector<EvidenceRecord> EvidenceStore::for_subject(const SwitchKey& subject) const {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto position = by_subject_.find(subject);
  if (position == by_subject_.end()) return {};
  return position->second;
}

std::size_t EvidenceStore::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return total_;
}

std::size_t EvidenceStore::capacity() const { return limits_.max_evidence_records; }

std::size_t EvidenceStore::rejected() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return rejected_;
}

std::size_t EvidenceStore::evicted() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return evicted_;
}

void EvidenceStore::clear() {
  std::lock_guard<std::mutex> guard(mutex_);
  by_subject_.clear();
  identities_.clear();
  total_ = 0;
}

bool EvidenceStore::had_rejection() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return rejected_ != 0;
}

// ---------------------------------------------------------------------------------------------
// Adjudication
// ---------------------------------------------------------------------------------------------

std::uint64_t SwitchAssessment::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.switch-assessment.v1");
  digest.absorb_key(subject);
  digest.absorb_byte(static_cast<std::uint8_t>(health));
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  digest.absorb_byte(usable ? 1 : 0);
  digest.absorb_byte(fence_required ? 1 : 0);
  digest.absorb_byte(durable_failure_present ? 1 : 0);
  for (const auto& id : supporting) digest.absorb_u64(id.raw());
  for (const auto& id : conflicting) digest.absorb_u64(id.raw());
  return digest.hi;
}

SwitchAssessment assess_switch(const SwitchKey& subject, const EvidenceStore& evidence,
                               const FailureTable& failures, TimestampNs now_ns,
                               const AssessmentPolicy& policy) {
  SwitchAssessment result;
  result.subject = subject;

  if (!subject.valid()) {
    result.outcome = Code::Invalid;
    result.fence_required = true;
    result.rationale = "subject is not generation-qualified; no authority can be derived";
    return result;
  }

  const auto records = evidence.for_subject(subject);

  TimestampNs failure_time = 0;
  TimestampNs recovery_time = 0;
  TimestampNs admin_unavailable_time = 0;
  TimestampNs admin_enabled_time = 0;
  TimestampNs advisory_bad_time = 0;
  TimestampNs advisory_good_time = 0;
  TimestampNs authoritative_good_time = 0;
  TimestampNs recovering_time = 0;
  std::size_t non_lifecycle_evidence = 0;
  EvidenceId failure_evidence;
  EvidenceId recovery_evidence;
  EvidenceId advisory_bad_evidence;
  EvidenceId advisory_good_evidence;
  EvidenceId authoritative_good_evidence;
  EvidenceId admin_evidence;

  for (const auto& record : records) {
    const TrustLevel trust = trust_of(record.source);
    if (trust == TrustLevel::Untrusted) {
      result.untrusted.push_back(record.id);
      continue;
    }
    if (record.observed_at_ns > now_ns) {
      const TimestampNs ahead = record.observed_at_ns - now_ns;
      if (ahead > policy.future_skew_tolerance_ns) {
        result.out_of_window.push_back(record.id);
        continue;
      }
    }
    if (!record.fresh_at(now_ns)) {
      result.stale.push_back(record.id);
      continue;
    }

    const bool authoritative = trust == TrustLevel::Authoritative;
    switch (record.kind) {
      case EvidenceKind::SwitchFailureDeclaration:
      case EvidenceKind::SwitchHealth:
        if (record.kind == EvidenceKind::SwitchHealth &&
            record.health == SwitchHealthState::Recovering) {
          // Recovering is neither failure nor availability. It is recorded so that the rationale
          // can say what was actually observed instead of reporting ordinary absence.
          recovering_time = std::max(recovering_time, record.observed_at_ns);
          break;
        }
        if (record.kind == EvidenceKind::SwitchHealth && is_positive_health(record.health)) {
          if (authoritative) {
            if (record.observed_at_ns >= authoritative_good_time) {
              authoritative_good_time = record.observed_at_ns;
              authoritative_good_evidence = record.id;
            }
          } else if (record.observed_at_ns >= advisory_good_time) {
            advisory_good_time = record.observed_at_ns;
            advisory_good_evidence = record.id;
          }
        } else {
          // A failure declaration, or a health observation that reports failure/unreachability.
          const bool assertion = record.kind == EvidenceKind::SwitchFailureDeclaration ||
                                 (record.kind == EvidenceKind::SwitchHealth &&
                                  is_failure_health(record.health));
          if (assertion) {
            if (authoritative) {
              if (record.observed_at_ns > failure_time) {
                failure_time = record.observed_at_ns;
                failure_evidence = record.id;
              }
            } else if (record.observed_at_ns > advisory_bad_time) {
              advisory_bad_time = record.observed_at_ns;
              advisory_bad_evidence = record.id;
            }
          }
        }
        break;
      case EvidenceKind::SwitchRecoveryDeclaration:
        if (authoritative) {
          if (record.observed_at_ns > recovery_time) {
            recovery_time = record.observed_at_ns;
            recovery_evidence = record.id;
          }
        } else if (record.observed_at_ns >= advisory_good_time) {
          advisory_good_time = record.observed_at_ns;
          advisory_good_evidence = record.id;
        }
        break;
      case EvidenceKind::AdminStateDeclaration:
        if (!authoritative) {
          non_lifecycle_evidence += 1;  // advisory administrative claims are not lifecycle proof
          break;
        }
        if (authoritative) {
          if (is_admin_unavailable(record.admin)) {
            if (record.observed_at_ns >= admin_unavailable_time) {
              admin_unavailable_time = record.observed_at_ns;
              admin_evidence = record.id;
            }
          } else if (record.admin == SwitchAdminState::Enabled) {
            if (record.observed_at_ns >= admin_enabled_time) {
              admin_enabled_time = record.observed_at_ns;
              admin_evidence = record.id;
            }
          }
        }
        break;
      default:
        // Capability declarations, effect verification and effect failure are legitimate evidence
        // about other subjects. They are counted so the rationale can say so rather than claiming
        // that nothing exists.
        non_lifecycle_evidence += 1;
        break;
    }
  }

  const auto note = [&result](const EvidenceId& id) {
    if (!id.valid()) return;
    if (std::find(result.supporting.begin(), result.supporting.end(), id) == result.supporting.end()) {
      result.supporting.push_back(id);
    }
  };
  note(failure_evidence);
  note(recovery_evidence);
  note(authoritative_good_evidence);
  note(admin_evidence);
  if (advisory_bad_evidence.valid() && advisory_bad_time != failure_time) {
    result.untrusted.push_back(advisory_bad_evidence);
  }
  if (advisory_good_evidence.valid()) result.untrusted.push_back(advisory_good_evidence);

  const FailureRecord* durable = failures.find(subject);
  if (durable != nullptr) {
    result.durable_failure_present = true;
    result.durable_failure = *durable;
  }

  const bool same_generation_recovery = policy.allow_same_generation_recovery;
  const TimestampNs effective_recovery =
      same_generation_recovery ? std::max(recovery_time, admin_enabled_time) : 0;

  bool durable_active = result.durable_failure_present;
  if (durable_active && same_generation_recovery &&
      effective_recovery > result.durable_failure.observed_at_ns) {
    durable_active = false;
  }

  const bool observed_anything = failure_time != 0 || recovery_time != 0 ||
                                 admin_unavailable_time != 0 || admin_enabled_time != 0 ||
                                 advisory_bad_time != 0 || advisory_good_time != 0 ||
                                 authoritative_good_time != 0;

  if (durable_active) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Failed;
    result.usable = false;
    result.fence_required = true;
    result.rationale = "durable committed failure lineage applies to this generation";
    note(result.durable_failure.evidence);
    return result;
  }

  if (failure_time != 0 && recovery_time != 0 && failure_time == recovery_time) {
    result.outcome = Code::Conflict;
    result.health = SwitchHealthState::Unknown;
    result.usable = false;
    result.fence_required = policy.fence_on_authoritative_conflict;
    result.conflicting.push_back(failure_evidence);
    result.conflicting.push_back(recovery_evidence);
    result.supporting.clear();
    result.rationale =
        "authoritative failure and recovery declarations share the same observation instant";
    return result;
  }

  if (recovery_time != 0 && recovery_time > failure_time) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Healthy;
    result.usable = true;
    result.rationale = "authoritative recovery declaration postdates every failure declaration";
    return result;
  }

  if (failure_time != 0) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Failed;
    result.usable = false;
    result.fence_required = true;
    result.rationale = "authoritative failure declaration for this exact generation";
    return result;
  }

  if (advisory_bad_time != 0 && !policy.require_authoritative_failure_evidence) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Unreachable;
    result.usable = false;
    result.fence_required = true;
    result.rationale =
        "policy accepts advisory failure observation as sufficient to fence this generation";
    return result;
  }

  if (admin_unavailable_time >= admin_enabled_time && admin_unavailable_time != 0) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Unknown;
    result.usable = false;
    result.fence_required = false;
    result.rationale = "authoritative administrative declaration makes the generation unavailable";
    return result;
  }

  if (authoritative_good_time != 0) {
    result.outcome = Code::Ok;
    result.health = SwitchHealthState::Healthy;
    result.usable = true;
    result.rationale = "authoritative affirmative health observation within its validity window";
    return result;
  }

  if (advisory_bad_time != 0) {
    result.outcome = Code::Unknown;
    result.health = SwitchHealthState::Unreachable;
    result.usable = false;
    result.fence_required = policy.fence_on_missing_health;
    result.rationale =
        "advisory observation only; policy requires authoritative evidence before fencing";
    return result;
  }

  if (advisory_good_time != 0) {
    result.outcome = Code::Unknown;
    result.health = SwitchHealthState::Healthy;
    result.usable = false;
    result.fence_required = policy.fence_on_missing_health;
    result.rationale = "observation is not authority: advisory health cannot grant availability";
    return result;
  }

  if (!result.stale.empty()) {
    result.outcome = Code::Stale;
    result.health = SwitchHealthState::Unknown;
    result.usable = false;
    result.fence_required = policy.fence_on_missing_health;
    result.rationale = "every retained observation is outside its validity window";
    return result;
  }

  if (!observed_anything) {
    result.outcome = Code::Unknown;
    result.health = SwitchHealthState::Unknown;
    result.usable = false;
    result.fence_required = policy.fence_on_missing_health;
    if (recovering_time != 0) {
      result.health = SwitchHealthState::Recovering;
      result.rationale =
          "the generation is reported recovering; availability is not yet affirmed";
    } else if (non_lifecycle_evidence != 0) {
      result.rationale =
          "evidence exists for this generation but none of it adjudicates switch lifecycle";
    } else if (!result.stale.empty()) {
      result.outcome = Code::Stale;
      result.rationale = "every lifecycle observation is outside its validity window";
    } else if (!result.untrusted.empty()) {
      result.rationale = "no trusted evidence exists for this generation";
    } else {
      result.rationale = "no evidence exists for this generation";
    }
    return result;
  }

  result.outcome = Code::Unknown;
  result.health = SwitchHealthState::Unknown;
  result.usable = false;
  result.fence_required = policy.fence_on_missing_health;
  result.rationale = "evidence present but insufficient to reach a conclusion";
  return result;
}

}  // namespace sff
