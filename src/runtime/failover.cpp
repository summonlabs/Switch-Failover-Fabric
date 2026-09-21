// Switch Failover Fabric - the failover pipeline.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Ordering contract, enforced here and asserted by the integration suite:
//   1. evidence is admitted;
//   2. the failure becomes durable lineage;
//   3. the bounded dependency closure is computed and reported, truncation included;
//   4. every dependent bound to the failed generation is fenced (authority revoked);
//   5. the fence record itself becomes durable;
//   6. only then may a reconstruction plan be produced, and a plan never preserves authority
//      that depended on a fenced generation;
//   7. applying a plan mints new authority under the current epoch and incarnation, and reports
//      acknowledgement - never verified effect.
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "runtime/coordinator_impl.hpp"
#include "sff/persist/records.hpp"
#include "sff/plan/validator.hpp"

namespace sff {

Status FailureDeclaration::validate() const {
  if (!subject.valid()) {
    return Status::failure(Code::Invalid, "failure declaration subject is not generation-qualified");
  }
  if (!is_valid_evidence_source(static_cast<std::uint8_t>(source))) {
    return Status::failure(Code::Invalid, "failure declaration names an unknown evidence source");
  }
  if (trust_of(source) != TrustLevel::Authoritative) {
    return Status::failure(Code::Unauthorized,
                           "failure declaration requires an authoritative evidence source");
  }
  if (observed_at_ns == 0) {
    return Status::failure(Code::Invalid, "failure declaration has no observation time");
  }
  if (valid_for_ns == 0) {
    return Status::failure(Code::Invalid, "failure declaration has no validity window");
  }
  if (reason.size() > kMaxMessageBytes) {
    return Status::failure(Code::Invalid, "failure declaration reason exceeds the message budget");
  }
  return Status::success();
}

std::uint64_t FailoverOutcome::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.failover-outcome.v1");
  digest.absorb_key(failed);
  digest.absorb_u64(failure.digest());
  digest.absorb_u64(fence.raw());
  digest.absorb_byte(static_cast<std::uint8_t>(fence_scope));
  digest.absorb_u64(closure.digest());
  digest.absorb_u64(grants_fenced);
  digest.absorb_u64(dependents_affected);
  digest.absorb_byte(deferred ? 1 : 0);
  digest.absorb_byte(static_cast<std::uint8_t>(outcome));
  return digest.hi;
}

std::uint64_t RestartReport::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.restart-report.v1");
  digest.absorb_byte(recovered ? 1 : 0);
  digest.absorb_byte(clean_previous_shutdown ? 1 : 0);
  digest.absorb_byte(torn_tail_truncated ? 1 : 0);
  digest.absorb_u64(records_replayed);
  digest.absorb_u64(corrupt_records);
  digest.absorb_u64(torn_records);
  digest.absorb_u64(previous_epoch.raw());
  digest.absorb_u64(current_epoch.raw());
  digest.absorb_u64(previous_boot.boot_ordinal());
  digest.absorb_u64(current_boot.boot_ordinal());
  digest.absorb_u64(failures_restored);
  digest.absorb_u64(fences_restored);
  digest.absorb_u64(grants_invalidated);
  digest.absorb_u64(plans_restored);
  digest.absorb_byte(dynamic_evidence_restored ? 1 : 0);
  return digest.hi;
}

// ---------------------------------------------------------------------------------------------
// Evidence and assessment
// ---------------------------------------------------------------------------------------------

Status Coordinator::admit_evidence(const EvidenceRecord& record) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;

  EvidenceRecord stamped = record;
  if (stamped.id.raw() >= kRuntimeReservedIdBase) {
    return Status::failure(Code::Invalid,
                           "evidence identity is inside the range reserved for runtime-minted ids");
  }
  if (stamped.admitted_boot.valid() && stamped.admitted_boot != impl_->boot) {
    impl_->append_event(EventKind::EvidenceRejected, Code::Stale,
                        "evidence was admitted under a different process incarnation",
                        stamped.subject.id().raw(), stamped.subject.generation().raw());
    return Status::failure(Code::Stale,
                           "evidence carries a process incarnation that is not current");
  }
  if (stamped.admitted_epoch.valid() && stamped.admitted_epoch != impl_->epoch) {
    impl_->append_event(EventKind::EvidenceRejected, Code::Stale,
                        "evidence was admitted under a different coordinator epoch",
                        stamped.subject.id().raw(), stamped.subject.generation().raw());
    return Status::failure(Code::Stale, "evidence carries a coordinator epoch that is not current");
  }
  stamped.admitted_epoch = impl_->epoch;
  stamped.admitted_boot = impl_->boot;

  Status admitted = impl_->evidence.admit(stamped);
  const EventKind kind =
      admitted.ok() ? EventKind::EvidenceAdmitted : EventKind::EvidenceRejected;
  impl_->append_event(kind, admitted.ok() ? Code::Ok : admitted.code(),
                      to_string(stamped.kind), stamped.subject.id().raw(),
                      stamped.subject.generation().raw());
  if (!admitted.ok()) return admitted;

  Explanation explanation;
  explanation.add("evidence", std::to_string(stamped.id.raw()))
      .add("kind", to_string(stamped.kind))
      .add("source", to_string(stamped.source))
      .add_key("subject", stamped.subject);
  (void)impl_->record_decision(DecisionKind::EvidenceAdmission,
                               DecisionScope::of_switch(stamped.subject, "evidence admission"),
                               Code::Ok, Code::Ok, GenerationVector{}, std::move(explanation));
  return Status::success();
}

Result<SwitchAssessment> Coordinator::assess(const SwitchKey& subject) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  SwitchAssessment assessment = assess_switch(subject, impl_->evidence, impl_->failures,
                                              impl_->now(), impl_->policy.assessment);
  Explanation explanation;
  explanation.add_bool("usable", assessment.usable)
      .add_bool("fence_required", assessment.fence_required)
      .add("health", to_string(assessment.health))
      .add("rationale", assessment.rationale)
      .add_u64("supporting", assessment.supporting.size())
      .add_u64("stale", assessment.stale.size())
      .add_u64("conflicting", assessment.conflicting.size());
  (void)impl_->record_decision(
      DecisionKind::SwitchFailure, DecisionScope::of_switch(subject, "switch assessment"),
      assessment.outcome, assessment.fence_required ? Code::Fenced : assessment.outcome,
      GenerationVector{}, std::move(explanation));
  return assessment;
}

Result<SwitchAssessment> Coordinator::assess_identity(SwitchId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->topology_present) {
    return Status::failure(Code::Unsupported, "no topology snapshot is installed");
  }
  const SwitchDescriptor* descriptor = impl_->topology.find_highest_generation(id);
  if (descriptor == nullptr) {
    return Status::failure(Code::NotFound, "the topology declares no switch with that identity");
  }
  return assess_switch(descriptor->key, impl_->evidence, impl_->failures, impl_->now(),
                       impl_->policy.assessment);
}

// ---------------------------------------------------------------------------------------------
// Failure fencing
// ---------------------------------------------------------------------------------------------

Result<FailureRecord> Coordinator::record_failure(const FailureDeclaration& declaration) {
  Status valid = declaration.validate();
  if (!valid.ok()) return valid;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->record_failure_locked(declaration);
}

Result<FailureRecord> Coordinator::Impl::record_failure_locked(
    const FailureDeclaration& declaration) {
  Status valid = declaration.validate();
  if (!valid.ok()) return valid;
  Status running;
  if (!ensure_running(running)) return running;
  if (!topology_present) {
    return Status::failure(Code::Unsupported,
                           "a failure cannot be recorded before a topology is installed");
  }

  EvidenceRecord assertion;
  assertion.id = EvidenceId(kRuntimeReservedIdBase + next_evidence);
  next_evidence += 1;
  assertion.kind = EvidenceKind::SwitchFailureDeclaration;
  assertion.source = declaration.source;
  assertion.subject = declaration.subject;
  assertion.admitted_epoch = epoch;
  assertion.admitted_boot = boot;
  assertion.observed_at_ns = declaration.observed_at_ns;
  assertion.valid_for_ns = declaration.valid_for_ns;
  assertion.health = SwitchHealthState::Failed;
  assertion.detail = declaration.reason;

  Status admitted = evidence_store_ref().admit(assertion);
  if (!admitted.ok()) return admitted;

  const SwitchAssessment assessment =
      assess_switch(declaration.subject, evidence_store_ref(), failures, now(),
                    policy.assessment);
  if (assessment.outcome == Code::Conflict) {
    append_event(EventKind::EvidenceRejected, Code::Conflict,
                 "authoritative failure and recovery evidence contradict each other",
                 declaration.subject.id().raw(), declaration.subject.generation().raw());
    return Status::failure(Code::Conflict,
                           "authoritative evidence about this generation contradicts itself");
  }
  if (!assessment.fence_required) {
    return Status::failure(
        assessment.outcome == Code::Ok ? Code::Denied : assessment.outcome,
        assessment.rationale.empty() ? "failure evidence did not establish a fence obligation"
                                     : assessment.rationale);
  }

  FailureRecord record;
  record.subject = declaration.subject;
  record.evidence = assertion.id;
  record.epoch = epoch;
  record.boot = boot;
  record.observed_at_ns = declaration.observed_at_ns;
  record.recorded_at_ns = now();
  record.reason = declaration.reason;

  Status s = persist_record(RecordKind::FailureCommitted, encode_failure_record(record));
  if (!s.ok()) return s;
  s = failures.record(record);
  if (!s.ok()) return s;

  append_event(EventKind::FailureDeclared, Code::Ok, record.reason,
               record.subject.id().raw(), record.subject.generation().raw());
  return record;
}

Result<FailoverOutcome> Coordinator::declare_failure(const FailureDeclaration& declaration) {
  Status valid = declaration.validate();
  if (!valid.ok()) return valid;

  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;

  Result<FailureRecord> failure = impl_->record_failure_locked(declaration);
  if (!failure.ok()) return failure.status();

  FailoverOutcome outcome;
  outcome.failed = declaration.subject;
  outcome.failure = failure.value();

  GenerationVector roots;
  roots.insert(declaration.subject);
  outcome.closure = impl_->topology.closure(roots, impl_->limits);
  outcome.dependents_affected = outcome.closure.dependents.size();

  outcome.grants_fenced = impl_->authority.fence_generations(roots, impl_->now());

  FenceRecord fence;
  if (impl_->authority.is_fenced(declaration.subject)) {
    outcome.deferred = true;
    const auto existing = impl_->authority.fences();
    for (const auto& candidate : existing) {
      if (candidate.subject == declaration.subject) {
        fence = candidate;
        break;
      }
    }
  } else {
    fence.subject = declaration.subject;
    fence.epoch = impl_->epoch;
    fence.boot = impl_->boot;
    fence.created_at_ns = impl_->now();
    fence.scope_state = outcome.closure.truncated() || !outcome.closure.enumerates_every_root()
                            ? FenceScopeState::Partial
                            : FenceScopeState::Committed;
    fence.closure_digest = outcome.closure.digest();
    fence.closure_members = outcome.closure.members.size();
    fence.fenced_grants = outcome.grants_fenced;
    fence.omitted_dependents = outcome.closure.omitted_frontier;
    fence.reason = declaration.reason.empty()
                       ? std::string("switch generation established unusable")
                       : declaration.reason;
    Result<FenceId> committed = impl_->authority.commit_fence(fence);
    if (!committed.ok()) return committed.status();
    fence.id = committed.value();
    Status s = impl_->persist_record(RecordKind::FenceCommitted, encode_fence_record(fence));
    if (!s.ok()) return s;
  }

  // A committed fence invalidates every outstanding plan that referenced the newly fenced
  // generation. Leaving such a plan in a usable state would let a later apply preserve authority
  // that depended on a failed generation, which is exactly what this runtime must never do.
  std::size_t superseded = 0;
  for (auto& entry : impl_->plans) {
    ReconstructionPlan& plan = entry.second;
    if (plan.state == PlanState::Superseded || plan.state == PlanState::Failed) continue;
    bool touches = false;
    for (const auto& step : plan.restores) {
      if (step.covers_failed == declaration.subject) {
        touches = true;
        break;
      }
      for (const auto& hop : step.hops) {
        if (hop == declaration.subject) {
          touches = true;
          break;
        }
      }
      if (touches) break;
    }
    if (!touches) continue;
    plan.state = PlanState::Superseded;
    plan.seal();
    superseded += 1;
  }

  outcome.fence = fence.id;
  outcome.fence_scope = fence.scope_state;
  outcome.outcome = fence.scope_state == FenceScopeState::Partial ? Code::PartialClosure : Code::Ok;

  Explanation explanation;
  explanation.add_bool("deferred", outcome.deferred)
      .add("closure_state", to_string(outcome.closure.state))
      .add_u64("closure_members", outcome.closure.members.size())
      .add_u64("dependents", outcome.closure.dependents.size())
      .add_u64("omitted_frontier", outcome.closure.omitted_frontier)
      .add_u64("roots_absent", outcome.closure.roots_absent)
      .add_u64("grants_fenced", outcome.grants_fenced)
      .add("reason", fence.reason);
  (void)impl_->record_decision(DecisionKind::FenceCommit,
                               DecisionScope::of_switch(declaration.subject, "switch failure fence"),
                               outcome.outcome, Code::Fenced, roots, std::move(explanation));

  impl_->append_event(EventKind::FenceCommitted, outcome.outcome,
                      outcome.deferred ? "fence already existed" : "fence committed",
                      declaration.subject.id().raw(), declaration.subject.generation().raw());
  if (superseded != 0) {
    impl_->append_event(EventKind::PlanRejected, Code::Fenced,
                        "outstanding plans superseded by a new fence", superseded);
  }
  return outcome;
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

Result<ReconstructionPlan> Coordinator::propose_plan(const GenerationVector& failed) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  if (!impl_->topology_present) {
    return Status::failure(Code::Unsupported, "no topology snapshot is installed");
  }
  if (!impl_->candidates_present) {
    return Status::failure(
        Code::Unsupported,
        "no reconstruction alternatives have been supplied; absence of alternatives is not "
        "evidence that none exist");
  }

  const PlanId plan_id(impl_->next_plan);
  PlanInputs inputs = impl_->make_inputs(plan_id, impl_->now());
  Result<ReconstructionPlan> produced = plan_reconstruction(inputs, failed);
  if (!produced.ok()) return produced.status();
  ReconstructionPlan plan = std::move(produced).value();
  impl_->next_plan += 1;

  ValidationReport report = sff::validate_plan(plan, inputs);
  Explanation explanation;
  explanation.add("feasibility", to_string(plan.feasibility))
      .add_u64("restores", plan.restores.size())
      .add_u64("unresolved", plan.unresolved.size())
      .add_bool("closure_complete", plan.closure_complete)
      .add_bool("valid", report.valid)
      .add_u64("checks", report.checks_performed);
  if (!report.findings.empty()) {
    explanation.add("first_finding", report.findings.front().detail);
  }

  if (!report.valid) {
    plan.state = PlanState::Rejected;
    plan.seal();
    impl_->plans[plan.id] = plan;
    (void)impl_->record_decision(DecisionKind::PlanValidation,
                                 DecisionScope::of_plan(plan.id, "plan rejected"),
                                 Code::Invalid, report.outcome, failed, std::move(explanation));
    impl_->append_event(EventKind::PlanRejected, Code::Invalid, report.to_string(), plan.id.raw());
    return Status::failure(Code::Invalid, "produced plan failed independent validation: " +
                                              report.to_string());
  }

  plan.state = PlanState::Validated;
  plan.seal();

  while (impl_->plans.size() >= impl_->policy.max_retained_plans && !impl_->plans.empty()) {
    auto victim = impl_->plans.begin();
    while (victim != impl_->plans.end() && victim->second.state == PlanState::Applying) ++victim;
    if (victim == impl_->plans.end()) break;
    impl_->plans.erase(victim);
  }
  impl_->plans[plan.id] = plan;

  (void)impl_->record_decision(DecisionKind::ReconstructionPlan,
                               DecisionScope::of_plan(plan.id, "reconstruction plan"),
                               Code::Ok, Code::Ok, failed, std::move(explanation));
  impl_->append_event(EventKind::PlanProposed, Code::Ok, to_string(plan.feasibility), plan.id.raw());
  impl_->append_event(EventKind::PlanValidated, Code::Ok, report.to_string(), plan.id.raw());
  return plan;
}

Result<ValidationReport> Coordinator::validate_plan(const ReconstructionPlan& plan) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->topology_present) {
    return Status::failure(Code::Unsupported, "no topology snapshot is installed");
  }
  PlanInputs inputs = impl_->make_inputs(plan.id, impl_->now());
  ValidationReport report = sff::validate_plan(plan, inputs);
  Explanation explanation;
  explanation.add_bool("valid", report.valid)
      .add_u64("checks", report.checks_performed)
      .add_u64("findings", report.findings.size());
  for (std::size_t index = 0; index < report.findings.size() && index < 8; ++index) {
    explanation.add("finding", report.findings[index].detail);
  }
  (void)impl_->record_decision(DecisionKind::PlanValidation,
                               DecisionScope::of_plan(plan.id, "plan validation"), report.outcome,
                               report.outcome, plan.failed_generations, std::move(explanation));
  return report;
}

// ---------------------------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------------------------

Result<ApplyReceipt> Coordinator::apply_plan(const ReconstructionPlan& request) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  if (!impl_->topology_present) {
    return Status::failure(Code::Unsupported, "no topology snapshot is installed");
  }
  const auto position = impl_->plans.find(request.id);
  if (position == impl_->plans.end()) {
    return Status::failure(Code::NotFound, "plan identity is not retained by this incarnation");
  }
  ReconstructionPlan plan = position->second;

  PlanInputs inputs = impl_->make_inputs(plan.id, impl_->now());
  ValidationReport report = sff::validate_plan(plan, inputs);
  if (!report.valid) {
    plan.state = PlanState::Rejected;
    plan.seal();
    impl_->plans[plan.id] = plan;
    impl_->append_event(EventKind::PlanRejected, Code::Invalid, report.to_string(), plan.id.raw());
    return Status::failure(Code::Invalid, "plan no longer validates against current inputs");
  }
  if (!plan.closure_complete && !impl_->policy.allow_restore_when_closure_truncated) {
    return Status::failure(Code::PartialClosure,
                           "the dependency closure is incomplete; restoration is refused");
  }
  if (plan.feasibility == PlanFeasibility::NothingToRestore) {
    // The failed generation invalidated nothing, so there is no forwarding effect to issue. The
    // plan is applied as a complete no-op and the receipt says exactly that.
    ApplyReceipt empty;
    empty.plan = plan.id;
    empty.epoch = impl_->epoch;
    empty.boot = impl_->boot;
    empty.complete = true;
    empty.outcome = Code::Ok;
    plan.state = PlanState::Applied;
    plan.seal();
    Status s = impl_->persist_record(RecordKind::ApplyCompleted, encode_apply_receipt(empty));
    if (!s.ok()) return s;
    impl_->plans[plan.id] = plan;
    return empty;
  }
  if (plan.feasibility != PlanFeasibility::ProvenFeasible) {
    return Status::failure(Code::Indeterminate,
                           "plan feasibility is not proven; nothing may be applied");
  }

  // Write-ahead: a plan that is about to take effect must survive a crash, together with the
  // fact that its effect may have been partially issued.
  plan.state = PlanState::Applying;
  plan.seal();
  Status s = impl_->persist_record(RecordKind::PlanCommitted, encode_plan_record(plan));
  if (!s.ok()) return s;
  impl_->plans[plan.id] = plan;

  ApplyReceipt receipt;
  receipt.plan = plan.id;
  receipt.epoch = impl_->epoch;
  receipt.boot = impl_->boot;

  for (const auto& step : plan.restores) {
    ApplyStepResult result;
    result.dependent = step.dependent;
    result.replacement = step.replacement;

    bool admissible = true;
    std::string refusal;
    for (const auto& hop : step.hops) {
      if (impl_->authority.is_fenced(hop)) {
        admissible = false;
        refusal = "replacement generation is fenced: " + hop.to_string();
        break;
      }
      if (impl_->topology.find_switch(hop) == nullptr) {
        admissible = false;
        refusal = "replacement generation is not in the current topology: " + hop.to_string();
        break;
      }
      const SwitchAssessment assessment =
          assess_switch(hop, impl_->evidence, impl_->failures, impl_->now(),
                        impl_->policy.assessment);
      if (assessment.fence_required) {
        admissible = false;
        refusal = "replacement generation carries a fence obligation: " + hop.to_string();
        break;
      }
    }

    if (!admissible) {
      result.state = AckState::Failed;
      result.detail = refusal;
      receipt.failed += 1;
    } else {
      GenerationVector bound;
      for (const auto& hop : step.hops) bound.insert(hop);
      if (bound.empty()) {
        result.state = AckState::Failed;
        result.detail = "restore step binds no generation";
        receipt.failed += 1;
      } else {
        Result<GrantId> granted =
            impl_->authority.grant(step.dependent, bound, impl_->epoch, impl_->boot,
                                   impl_->now(), impl_->policy.grant_ttl_ns,
                                   "reconstruction applied under plan " +
                                       std::to_string(plan.id.raw()));
        if (!granted.ok()) {
          result.state = AckState::Failed;
          result.detail = granted.status().to_string();
          receipt.failed += 1;
        } else {
          result.attempt = impl_->authority.last_attempt();
          result.state = AckState::Applied;
          result.detail = "authority grant minted under the current epoch and incarnation";
          receipt.applied += 1;
        }
      }
    }
    impl_->apply_steps[{result.dependent, result.replacement}] = result;
    receipt.steps.push_back(std::move(result));
    (void)impl_->record_decision(
        DecisionKind::ApplyEffect,
        DecisionScope::of_dependent(receipt.steps.back().dependent, "apply effect"),
        receipt.steps.back().state == AckState::Applied ? Code::Ok : Code::Denied,
        receipt.steps.back().state == AckState::Applied ? Code::Ok : Code::Denied,
        GenerationVector{}, Explanation{});
  }

  receipt.unverified = receipt.applied;
  receipt.complete = receipt.failed == 0 && receipt.applied == plan.restores.size();
  receipt.outcome = receipt.complete ? Code::Unverified : Code::PartialClosure;

  plan.state = receipt.complete ? PlanState::Applied
                                : (receipt.applied == 0 ? PlanState::Failed
                                                        : PlanState::PartiallyApplied);
  plan.seal();
  s = impl_->persist_record(RecordKind::ApplyCompleted, encode_apply_receipt(receipt));
  if (!s.ok()) return s;
  s = impl_->persist_record(RecordKind::PlanCommitted, encode_plan_record(plan));
  if (!s.ok()) return s;
  impl_->plans[plan.id] = plan;

  Explanation explanation;
  explanation.add_u64("applied", receipt.applied)
      .add_u64("failed", receipt.failed)
      .add_u64("verified", receipt.verified)
      .add_bool("complete", receipt.complete);
  (void)impl_->record_decision(DecisionKind::ApplyEffect,
                               DecisionScope::of_plan(plan.id, "apply plan"), receipt.outcome,
                               Code::Unverified, plan.failed_generations, std::move(explanation));
  impl_->append_event(EventKind::ApplyAttempted, receipt.outcome, "plan applied", plan.id.raw());
  impl_->append_event(EventKind::ApplyAcknowledged, Code::Ok,
                      "acknowledgement is not verified effect", plan.id.raw());
  return receipt;
}

Status Coordinator::record_effect_verification(const EvidenceRecord& verification) {
  if (verification.kind != EvidenceKind::EffectVerification &&
      verification.kind != EvidenceKind::EffectFailure) {
    return Status::failure(Code::Invalid, "record carries no effect verification");
  }
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;

  if (verification.id.raw() >= kRuntimeReservedIdBase) {
    return Status::failure(Code::Invalid,
                           "verification identity is inside the range reserved for runtime-minted ids");
  }
  EvidenceRecord record = verification;
  record.admitted_epoch = impl_->epoch;
  record.admitted_boot = impl_->boot;
  Status admitted = impl_->evidence.admit(record);
  if (!admitted.ok()) return admitted;
  impl_->append_event(EventKind::ApplyVerified, Code::Ok, "independent verification admitted",
                      record.id.raw());

  const auto plan = impl_->plans.find(record.effect_plan);
  if (plan == impl_->plans.end()) {
    return Status::failure(Code::NotFound, "verification names a plan that is not retained");
  }
  bool matched = false;
  for (const auto& step : plan->second.restores) {
    if (step.dependent != record.effect_dependent) continue;
    auto applied = impl_->apply_steps.find({step.dependent, step.replacement});
    if (applied == impl_->apply_steps.end()) continue;
    applied->second.verification = record.id;
    applied->second.state = record.kind == EvidenceKind::EffectVerification ? AckState::Verified
                                                                           : AckState::Failed;
    applied->second.detail = record.detail;
    matched = true;
  }
  if (!matched) {
    return Status::failure(Code::NotFound,
                           "verification names a dependent that the plan did not restore");
  }
  return Status::success();
}

// ---------------------------------------------------------------------------------------------
// Restoration
// ---------------------------------------------------------------------------------------------

Result<RestoreDecision> Coordinator::evaluate_restore(const DependentRef& dependent) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!dependent.valid()) {
    return Status::failure(Code::Invalid, "restore query names an invalid dependent");
  }

  const TimestampNs now_ns = impl_->now();
  AuthorityQuery query = impl_->authority.query(dependent, now_ns);

  RestoreDecision decision;
  decision.dependent = dependent;
  decision.bound = query.bound;
  decision.grants = query.active_grants;

  for (const auto& key : query.bound.keys()) {
    const SwitchAssessment assessment =
        assess_switch(key, impl_->evidence, impl_->failures, now_ns, impl_->policy.assessment);
    if (impl_->authority.is_fenced(key) || assessment.fence_required) {
      decision.blocking_generations.push_back(key);
    }
  }

  PlanId latest_plan;
  ApplyStepResult latest_step;
  bool have_step = false;
  for (const auto& entry : impl_->apply_steps) {
    if (entry.first.first != dependent) continue;
    if (!have_step) {
      latest_step = entry.second;
      have_step = true;
      continue;
    }
    latest_step = entry.second;
  }
  for (const auto& entry : impl_->plans) {
    for (const auto& step : entry.second.restores) {
      if (step.dependent == dependent) latest_plan = entry.first;
    }
  }
  decision.plan = latest_plan;

  Explanation explanation;
  explanation.add_u64("active_grants", query.active_grants.size())
      .add_u64("withdrawn_grants", query.withdrawn_grants.size())
      .add_u64("blocking_generations", decision.blocking_generations.size())
      .add_bool("apply_recorded", have_step)
      .add("apply_state", have_step ? to_string(latest_step.state) : "NONE")
      .add("authority_reason", query.rationale);

  if (!decision.blocking_generations.empty()) {
    decision.outcome = Code::Fenced;
    decision.reason = Code::Fenced;
    decision.may_restore = false;
    explanation.add("refusal", "a bound generation is fenced or carries a fence obligation");
  } else if (!query.has_authority) {
    decision.outcome = query.outcome;
    decision.reason = query.reason;
    decision.may_restore = false;
    explanation.add("refusal", "no active forwarding authority covers this dependent");
  } else if (!have_step) {
    decision.outcome = Code::Unverified;
    decision.reason = Code::Unverified;
    decision.may_restore = false;
    explanation.add("refusal", "no reconstruction has been applied for this dependent");
  } else if (latest_step.state == AckState::Failed) {
    decision.outcome = Code::Denied;
    decision.reason = Code::Denied;
    decision.may_restore = false;
    explanation.add("refusal", "the recorded reconstruction attempt failed");
  } else if (latest_step.state == AckState::Verified) {
    decision.outcome = Code::Ok;
    decision.reason = Code::Ok;
    decision.may_restore = true;
    decision.effect_verified = true;
  } else if (impl_->policy.allow_acknowledgement_restore) {
    decision.outcome = Code::Unverified;
    decision.reason = Code::Unverified;
    decision.may_restore = true;
    decision.effect_verified = false;
    explanation.add("refusal", "policy permits restoration on acknowledgement alone");
  } else {
    decision.outcome = Code::Unverified;
    decision.reason = Code::Unverified;
    decision.may_restore = false;
    explanation.add("refusal",
                    "forwarding effect has not been independently verified under this incarnation");
  }

  decision.explanation = std::move(explanation);
  (void)impl_->record_decision(DecisionKind::ServiceRestore,
                               DecisionScope::of_dependent(dependent, "service restore"),
                               decision.outcome, decision.reason, decision.bound,
                               decision.explanation);
  impl_->append_event(EventKind::RestoreDecided, decision.outcome, decision.reason == Code::Ok
                                                                          ? "restore permitted"
                                                                          : "restore refused",
                      dependent.id());
  return decision;
}

Result<AuthorityQuery> Coordinator::query_authority(const DependentRef& dependent) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!dependent.valid()) {
    return Status::failure(Code::Invalid, "authority query names an invalid dependent");
  }
  const TimestampNs now_ns = impl_->now();
  AuthorityQuery query = impl_->authority.query(dependent, now_ns);
  for (const auto& key : query.bound.keys()) {
    const SwitchAssessment assessment =
        assess_switch(key, impl_->evidence, impl_->failures, now_ns, impl_->policy.assessment);
    if (!assessment.usable) query.unproven_generations.push_back(key);
  }

  Explanation explanation;
  explanation.add_bool("has_authority", query.has_authority)
      .add("authority_reason", query.rationale)
      .add_u64("active_grants", query.active_grants.size())
      .add_u64("unproven_generations", query.unproven_generations.size())
      .add_u64("fenced_generations", query.fenced_generations.size());
  (void)impl_->record_decision(DecisionKind::AuthorityQuery,
                               DecisionScope::of_dependent(dependent, "authority query"),
                               query.outcome, query.reason, query.bound, std::move(explanation));
  return query;
}

}  // namespace sff
