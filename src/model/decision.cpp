// Switch Failover Fabric - decisions, scopes and bounded explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/decision.hpp"

#include <algorithm>

namespace sff {
namespace {

/// Per-term byte budget. Together with the term count limit this bounds an explanation.
constexpr std::size_t kMaxTermBytes = 256;

std::string bounded_term(std::string_view text) {
  if (text.size() <= kMaxTermBytes) return std::string(text);
  return std::string(text.substr(0, kMaxTermBytes));
}

}  // namespace

const char* to_string(DecisionKind kind) noexcept {
  switch (kind) {
    case DecisionKind::Unknown: return "UNKNOWN";
    case DecisionKind::SwitchFailure: return "SWITCH_FAILURE";
    case DecisionKind::FenceCommit: return "FENCE_COMMIT";
    case DecisionKind::ClosureComputation: return "CLOSURE_COMPUTATION";
    case DecisionKind::ReplacementEligibility: return "REPLACEMENT_ELIGIBILITY";
    case DecisionKind::ReconstructionPlan: return "RECONSTRUCTION_PLAN";
    case DecisionKind::PlanValidation: return "PLAN_VALIDATION";
    case DecisionKind::ApplyEffect: return "APPLY_EFFECT";
    case DecisionKind::ServiceRestore: return "SERVICE_RESTORE";
    case DecisionKind::AuthorityQuery: return "AUTHORITY_QUERY";
    case DecisionKind::RestartReconciliation: return "RESTART_RECONCILIATION";
    case DecisionKind::EvidenceAdmission: return "EVIDENCE_ADMISSION";
  }
  return "UNRECOGNISED_DECISION_KIND";
}

const char* to_string(DecisionSubjectKind kind) noexcept {
  switch (kind) {
    case DecisionSubjectKind::None: return "NONE";
    case DecisionSubjectKind::Switch: return "SWITCH";
    case DecisionSubjectKind::Dependent: return "DEPENDENT";
    case DecisionSubjectKind::Plan: return "PLAN";
    case DecisionSubjectKind::Runtime: return "RUNTIME";
  }
  return "UNRECOGNISED_SUBJECT_KIND";
}

DecisionScope DecisionScope::of_switch(const SwitchKey& key, std::string_view label) {
  DecisionScope scope;
  scope.kind = DecisionSubjectKind::Switch;
  scope.subject = key;
  scope.label = bounded_term(label);
  return scope;
}

DecisionScope DecisionScope::of_dependent(const DependentRef& dependent, std::string_view label) {
  DecisionScope scope;
  scope.kind = DecisionSubjectKind::Dependent;
  scope.dependent = dependent;
  scope.label = bounded_term(label);
  return scope;
}

DecisionScope DecisionScope::of_plan(PlanId plan, std::string_view label) {
  DecisionScope scope;
  scope.kind = DecisionSubjectKind::Plan;
  scope.plan = plan;
  scope.label = bounded_term(label);
  return scope;
}

DecisionScope DecisionScope::of_runtime(std::string_view label) {
  DecisionScope scope;
  scope.kind = DecisionSubjectKind::Runtime;
  scope.label = bounded_term(label);
  return scope;
}

bool DecisionScope::valid() const noexcept {
  switch (kind) {
    case DecisionSubjectKind::Switch:
      return subject.valid();
    case DecisionSubjectKind::Dependent:
      return dependent.valid();
    case DecisionSubjectKind::Plan:
      return plan.valid();
    case DecisionSubjectKind::Runtime:
      return true;
    case DecisionSubjectKind::None:
      return false;
  }
  return false;
}

std::uint64_t DecisionScope::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.decision-scope.v1");
  digest.absorb_byte(static_cast<std::uint8_t>(kind));
  digest.absorb_key(subject);
  digest.absorb_dependent(dependent);
  digest.absorb_u64(plan.raw());
  // The descriptive label is deliberately excluded: identity is structural, never textual.
  return digest.hi;
}

std::string DecisionScope::to_string() const {
  switch (kind) {
    case DecisionSubjectKind::Switch: return "switch:" + subject.to_string();
    case DecisionSubjectKind::Dependent: return "dependent:" + dependent.to_string();
    case DecisionSubjectKind::Plan: return "plan:" + std::to_string(plan.raw());
    case DecisionSubjectKind::Runtime: return "runtime";
    case DecisionSubjectKind::None: return "none";
  }
  return "unrecognised";
}

Explanation::Explanation(std::size_t term_limit)
    : limit_(term_limit == 0 ? 1 : term_limit) {}

Explanation& Explanation::add(std::string_view key, std::string_view value) {
  if (terms_.size() >= limit_) {
    truncated_ = true;
    return *this;
  }
  ExplanationTerm term;
  term.key = bounded_term(key);
  term.value = bounded_term(value);
  terms_.push_back(std::move(term));
  return *this;
}

Explanation& Explanation::add_u64(std::string_view key, std::uint64_t value) {
  return add(key, std::to_string(value));
}

Explanation& Explanation::add_bool(std::string_view key, bool value) {
  return add(key, value ? "true" : "false");
}

Explanation& Explanation::add_code(std::string_view key, Code code) {
  return add(key, to_string(code));
}

Explanation& Explanation::add_key(std::string_view key, const SwitchKey& switch_key) {
  return add(key, switch_key.to_string());
}

Explanation& Explanation::add_dependent(std::string_view key, const DependentRef& dependent) {
  return add(key, dependent.to_string());
}

std::string Explanation::canonical() const {
  std::string result;
  for (const auto& term : terms_) {
    result += term.key;
    result += "=";
    result += term.value;
    result += ";";
  }
  if (truncated_) result += "truncated=true;";
  return result;
}

std::uint64_t Explanation::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.explanation.v1");
  for (const auto& term : terms_) {
    digest.absorb_string(term.key);
    digest.absorb_string(term.value);
  }
  digest.absorb_byte(truncated_ ? 1 : 0);
  return digest.hi;
}

std::uint64_t Decision::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.decision.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_byte(static_cast<std::uint8_t>(kind));
  digest.absorb_u64(scope.digest());
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  digest.absorb_byte(static_cast<std::uint8_t>(reason));
  digest.absorb_u64(bound.digest());
  digest.absorb_u64(epoch.raw());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_byte(static_cast<std::uint8_t>(evidence_class));
  digest.absorb_u64(explanation.digest());
  return digest.hi;
}

std::string Decision::to_string() const {
  std::string result;
  result += sff::to_string(kind);
  result += " ";
  result += scope.to_string();
  result += " outcome=";
  result += sff::to_string(outcome);
  result += " reason=";
  result += sff::to_string(reason);
  result += " class=";
  result += sff::to_string(evidence_class);
  return result;
}

DecisionLog::DecisionLog(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

void DecisionLog::append(Decision decision) {
  std::lock_guard<std::mutex> guard(mutex_);
  decision.id = DecisionId(next_id_);
  next_id_ += 1;
  decisions_.push_back(std::move(decision));
  while (decisions_.size() > capacity_) {
    decisions_.pop_front();
    dropped_ += 1;
  }
}

std::vector<Decision> DecisionLog::tail(std::size_t count) const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<Decision> result;
  const std::size_t take = std::min(count, decisions_.size());
  result.reserve(take);
  for (auto it = decisions_.end() - static_cast<std::ptrdiff_t>(take); it != decisions_.end(); ++it) {
    result.push_back(*it);
  }
  return result;
}

std::size_t DecisionLog::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return decisions_.size();
}

std::size_t DecisionLog::capacity() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return capacity_;
}

std::uint64_t DecisionLog::dropped() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return dropped_;
}

std::uint64_t DecisionLog::last_id() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return next_id_ - 1;
}

void DecisionLog::clear() {
  std::lock_guard<std::mutex> guard(mutex_);
  decisions_.clear();
}

}  // namespace sff
