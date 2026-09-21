// Switch Failover Fabric - evidence admission and fail-closed adjudication.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC ONLY. Every fixture is labelled SYNTHETIC and driven by a ManualClock, so no result
// here depends on wall-clock time.
//
// The proposition under test: adjudication is fail-closed. Absence of evidence is never health,
// observation is never authority, a stale or out-of-window record is an explicit outcome rather
// than ordinary absence, and a durable failure survives the loss of every dynamic record.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "sff/model/evidence.hpp"

#include "test_support.hpp"

namespace {

using sff::AssessmentPolicy;
using sff::BootIncarnation;
using sff::Code;
using sff::CoordinatorEpoch;
using sff::EvidenceId;
using sff::EvidenceKind;
using sff::EvidenceRecord;
using sff::EvidenceSource;
using sff::EvidenceStore;
using sff::FailureRecord;
using sff::FailureTable;
using sff::Limits;
using sff::ManualClock;
using sff::Status;
using sff::SwitchAdminState;
using sff::SwitchAssessment;
using sff::SwitchGeneration;
using sff::SwitchHealthState;
using sff::SwitchId;
using sff::SwitchKey;
using sff::TimestampNs;

constexpr TimestampNs kSecond = sff::kNanosPerSecond;

SwitchKey key(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

BootIncarnation synth_boot() { return BootIncarnation::from_parts(4242, 1, 0x5A5A5A5A, 0x12345678); }

/// A structurally valid synthetic record. Callers mutate exactly one field to probe one refusal.
EvidenceRecord synth_record(EvidenceId id, EvidenceKind kind, EvidenceSource source, const SwitchKey& subject,
                            TimestampNs observed_at_ns, std::uint64_t valid_for_ns) {
  EvidenceRecord record;
  record.id = id;
  record.kind = kind;
  record.source = source;
  record.subject = subject;
  record.admitted_epoch = CoordinatorEpoch(1);
  record.admitted_boot = synth_boot();
  record.observed_at_ns = observed_at_ns;
  record.valid_for_ns = valid_for_ns;
  record.detail = "SYNTHETIC evidence record";
  return record;
}

EvidenceRecord synth_health(EvidenceId id, EvidenceSource source, const SwitchKey& subject,
                            SwitchHealthState health, TimestampNs observed_at_ns, std::uint64_t valid_for_ns) {
  EvidenceRecord record = synth_record(id, EvidenceKind::SwitchHealth, source, subject, observed_at_ns, valid_for_ns);
  record.health = health;
  return record;
}

EvidenceRecord synth_lifecycle(EvidenceId id, EvidenceKind kind, EvidenceSource source, const SwitchKey& subject,
                               TimestampNs observed_at_ns, std::uint64_t valid_for_ns) {
  return synth_record(id, kind, source, subject, observed_at_ns, valid_for_ns);
}

Status admit_or_report(EvidenceStore& store, const EvidenceRecord& record, const char* what) {
  const Status status = store.admit(record);
  if (!status.ok()) std::printf("  refused %s: %s\n", what, status.to_string().c_str());
  return status;
}

AssessmentPolicy awaiting_authority_policy() {
  AssessmentPolicy policy;
  policy.require_authoritative_failure_evidence = false;
  return policy;
}

// --- absence and observation --------------------------------------------------------------------

SFF_TEST(no_evidence_is_unknown_and_never_healthy) {
  ManualClock clock(1 * kSecond);
  EvidenceStore store(Limits::defaults(), &clock);
  FailureTable failures;
  const SwitchKey subject = key(1, 1);

  const SwitchAssessment bare =
      sff::assess_switch(subject, store, failures, clock.now_ns(), AssessmentPolicy{});
  CHECK(bare.outcome == Code::Unknown);
  CHECK(bare.outcome != Code::Ok);
  CHECK(!bare.usable);
  CHECK(bare.health == SwitchHealthState::Unknown);
  CHECK(bare.health != SwitchHealthState::Healthy);
  CHECK(!bare.durable_failure_present);
  CHECK(!bare.fence_required);
  CHECK(bare.supporting.empty());
  CHECK(bare.conflicting.empty());
  CHECK(bare.stale.empty());
  CHECK(!sff::is_success(bare.outcome));
  CHECK(sff::is_fail_closed(bare.outcome));
  CHECK(!bare.rationale.empty());
  CHECK_EQ(store.size(), std::size_t{0});

  // An unqualified subject cannot even be adjudicated, and it is fenced rather than assumed well.
  const SwitchAssessment unqualified =
      sff::assess_switch(key(1, 0), store, failures, clock.now_ns(), AssessmentPolicy{});
  CHECK(unqualified.outcome == Code::Invalid);
  CHECK(!unqualified.usable);
  CHECK(unqualified.fence_required);
}

SFF_TEST(advisory_observation_is_not_authority) {
  ManualClock clock(1 * kSecond);
  const SwitchKey healthy = key(1, 1);
  const SwitchKey failing = key(2, 1);

  EvidenceStore store(Limits::defaults(), &clock);
  FailureTable failures;

  EvidenceRecord good = synth_health(EvidenceId(1), EvidenceSource::TelemetryCollector, healthy,
                                     SwitchHealthState::Healthy, 1 * kSecond, 3600 * kSecond);
  EvidenceRecord bad = synth_health(EvidenceId(2), EvidenceSource::SwitchAgent, failing,
                                    SwitchHealthState::Unreachable, 1 * kSecond, 3600 * kSecond);
  CHECK(admit_or_report(store, good, "advisory healthy").ok());
  CHECK(admit_or_report(store, bad, "advisory failing").ok());

  const SwitchAssessment observed_healthy =
      sff::assess_switch(healthy, store, failures, clock.now_ns(), AssessmentPolicy{});
  CHECK(observed_healthy.outcome == Code::Unknown);
  CHECK(!observed_healthy.usable);
  // The observation is retained as an observation, and it is explicitly not authority.
  CHECK(observed_healthy.health == SwitchHealthState::Healthy);
  CHECK(!sff::is_success(observed_healthy.outcome));
  CHECK(observed_healthy.supporting.empty());
  CHECK(!observed_healthy.untrusted.empty());

  // Default policy: an advisory failure is not sufficient to fence.
  const AssessmentPolicy strict{};
  const SwitchAssessment strict_failing =
      sff::assess_switch(failing, store, failures, clock.now_ns(), strict);
  CHECK(strict_failing.outcome == Code::Unknown);
  CHECK(!strict_failing.usable);
  CHECK(!strict_failing.fence_required);
  CHECK(strict_failing.supporting.empty());

  // Policy may accept the advisory observation as a basis to fence; it still never grants authority.
  const SwitchAssessment lenient_failing =
      sff::assess_switch(failing, store, failures, clock.now_ns(), awaiting_authority_policy());
  CHECK(lenient_failing.outcome == Code::Ok);
  CHECK(!lenient_failing.usable);
  CHECK(lenient_failing.fence_required);
  // Even when policy accepts the observation as a basis to fence, it is reported as an advisory
  // observation: no authoritative support is claimed for it.
  CHECK(lenient_failing.supporting.empty());
  CHECK_EQ(lenient_failing.untrusted.size(), std::size_t{1});
  CHECK(lenient_failing.untrusted.front() == EvidenceId(2));
}

// --- authoritative lifecycle --------------------------------------------------------------------

SFF_TEST(authoritative_failure_and_recovery_are_ordered_strictly) {
  ManualClock clock(1 * kSecond);
  const SwitchKey subject = key(3, 1);

  {
    // A failure declaration with no recovery: fenced, not usable, and Ok because it resolved.
    EvidenceStore store(Limits::defaults(), &clock);
    FailureTable failures;
    const EvidenceRecord failure =
        synth_lifecycle(EvidenceId(10), EvidenceKind::SwitchFailureDeclaration,
                        EvidenceSource::FabricManager, subject, 1 * kSecond, 3600 * kSecond);
    CHECK(admit_or_report(store, failure, "authoritative failure").ok());
    const SwitchAssessment assessment =
        sff::assess_switch(subject, store, failures, clock.now_ns(), AssessmentPolicy{});
    CHECK(assessment.outcome == Code::Ok);
    CHECK(assessment.fence_required);
    CHECK(!assessment.usable);
    CHECK(assessment.health == SwitchHealthState::Failed);
    CHECK_EQ(assessment.supporting.size(), std::size_t{1});
    CHECK(assessment.supporting.front() == EvidenceId(10));
  }

  {
    // A strict recovery declaration: usable again, same generation.
    EvidenceStore store(Limits::defaults(), &clock);
    FailureTable failures;
    CHECK(store.admit(synth_lifecycle(EvidenceId(11), EvidenceKind::SwitchFailureDeclaration,
                                      EvidenceSource::OperatorPolicy, subject, 1 * kSecond, 3600 * kSecond))
              .ok());
    CHECK(store.admit(synth_lifecycle(EvidenceId(12), EvidenceKind::SwitchRecoveryDeclaration,
                                      EvidenceSource::OperatorPolicy, subject, 2 * kSecond, 3600 * kSecond))
              .ok());
    const SwitchAssessment assessment =
        sff::assess_switch(subject, store, failures, 2 * kSecond, AssessmentPolicy{});
    CHECK(assessment.outcome == Code::Ok);
    CHECK(assessment.usable);
    CHECK(!assessment.fence_required);
    CHECK(assessment.health == SwitchHealthState::Healthy);
  }

  {
    // The same instant: an explicit conflict, never Ok and never usable.
    EvidenceStore store(Limits::defaults(), &clock);
    FailureTable failures;
    CHECK(store.admit(synth_lifecycle(EvidenceId(13), EvidenceKind::SwitchFailureDeclaration,
                                      EvidenceSource::FabricManager, subject, 3 * kSecond, 3600 * kSecond))
              .ok());
    CHECK(store.admit(synth_lifecycle(EvidenceId(14), EvidenceKind::SwitchRecoveryDeclaration,
                                      EvidenceSource::FabricManager, subject, 3 * kSecond, 3600 * kSecond))
              .ok());
    const SwitchAssessment assessment =
        sff::assess_switch(subject, store, failures, 3 * kSecond, AssessmentPolicy{});
    CHECK(assessment.outcome == Code::Conflict);
    CHECK(assessment.outcome != Code::Ok);
    CHECK(!assessment.usable);
    CHECK(assessment.fence_required);
    CHECK(assessment.health == SwitchHealthState::Unknown);
    CHECK(assessment.supporting.empty());
    CHECK_EQ(assessment.conflicting.size(), std::size_t{2});
    CHECK(sff::is_fail_closed(assessment.outcome));

    AssessmentPolicy unfenced_conflict{};
    unfenced_conflict.fence_on_authoritative_conflict = false;
    const SwitchAssessment recorded_but_unfenced =
        sff::assess_switch(subject, store, failures, 3 * kSecond, unfenced_conflict);
    CHECK(recorded_but_unfenced.outcome == Code::Conflict);
    CHECK(!recorded_but_unfenced.usable);

    // An earlier recovery declaration does not un-fail a later failure.
    EvidenceStore later_store(Limits::defaults(), &clock);
    CHECK(later_store
              .admit(synth_lifecycle(EvidenceId(15), EvidenceKind::SwitchRecoveryDeclaration,
                                     EvidenceSource::FabricManager, subject, 4 * kSecond, 3600 * kSecond))
              .ok());
    CHECK(later_store
              .admit(synth_lifecycle(EvidenceId(16), EvidenceKind::SwitchFailureDeclaration,
                                     EvidenceSource::FabricManager, subject, 5 * kSecond, 3600 * kSecond))
              .ok());
    const SwitchAssessment ordered =
        sff::assess_switch(subject, later_store, failures, 5 * kSecond, AssessmentPolicy{});
    CHECK(ordered.outcome == Code::Ok);
    CHECK(ordered.fence_required);
    CHECK(!ordered.usable);
    CHECK(ordered.health == SwitchHealthState::Failed);
  }
}

SFF_TEST(stale_evidence_is_an_explicit_outcome) {
  ManualClock clock(3 * kSecond);
  FailureTable failures;

  {
    EvidenceStore store(Limits::defaults(), &clock);
    CHECK(store.admit(synth_lifecycle(EvidenceId(20), EvidenceKind::SwitchFailureDeclaration,
                                      EvidenceSource::FabricManager, key(4, 1), 1 * kSecond, 1 * kSecond))
              .ok());
    const SwitchAssessment assessment =
        sff::assess_switch(key(4, 1), store, failures, 3 * kSecond, AssessmentPolicy{});
    CHECK(assessment.outcome == Code::Stale);
    CHECK(assessment.outcome != Code::Ok);
    CHECK(!assessment.usable);
    CHECK_EQ(assessment.stale.size(), std::size_t{1});
    CHECK(assessment.stale.front() == EvidenceId(20));
    // The record is still accounted for: it was not silently discarded as if it never existed.
    CHECK(assessment.supporting.empty());
    CHECK(sff::is_fail_closed(assessment.outcome));
  }

  {
    EvidenceStore store(Limits::defaults(), &clock);
    CHECK(store.admit(synth_health(EvidenceId(21), EvidenceSource::FabricManager, key(5, 1),
                                   SwitchHealthState::Healthy, 1 * kSecond, 1 * kSecond))
              .ok());
    const SwitchAssessment assessment =
        sff::assess_switch(key(5, 1), store, failures, 3 * kSecond, AssessmentPolicy{});
    CHECK(assessment.outcome == Code::Stale);
    CHECK(!assessment.usable);
    CHECK_EQ(assessment.stale.size(), std::size_t{1});
  }
}

SFF_TEST(evidence_outside_the_time_window_is_ignored_rather_than_trusted) {
  ManualClock clock(1 * kSecond);
  const SwitchKey subject = key(6, 1);
  EvidenceStore store(Limits::defaults(), &clock);
  FailureTable failures;

  // Implausibly far ahead: the store refuses it outright.
  const EvidenceRecord implausible =
      synth_lifecycle(EvidenceId(30), EvidenceKind::SwitchFailureDeclaration,
                      EvidenceSource::FabricManager, subject, 1 * kSecond + 2 * 3600 * kSecond, 3600 * kSecond);
  const Status refused = store.admit(implausible);
  CHECK(!refused.ok());
  CHECK(refused.code() == Code::Invalid);
  CHECK_EQ(store.size(), std::size_t{0});
  CHECK_EQ(store.rejected(), std::size_t{1});
  CHECK(store.had_rejection());

  // Inside the store's sanity bound but beyond the adjudication skew tolerance: retained, ignored.
  const EvidenceRecord ahead =
      synth_lifecycle(EvidenceId(31), EvidenceKind::SwitchFailureDeclaration,
                      EvidenceSource::FabricManager, subject, 1 * kSecond + 500 * kSecond, 100 * kSecond);
  CHECK(admit_or_report(store, ahead, "ahead of the assessment instant").ok());
  CHECK_EQ(store.size(), std::size_t{1});

  const SwitchAssessment ignored =
      sff::assess_switch(subject, store, failures, 1 * kSecond, AssessmentPolicy{});
  CHECK(ignored.outcome == Code::Unknown);
  CHECK(!ignored.usable);
  CHECK(!ignored.fence_required);
  CHECK_EQ(ignored.out_of_window.size(), std::size_t{1});
  CHECK(ignored.out_of_window.front() == EvidenceId(31));
  CHECK(ignored.supporting.empty());

  // Widening the tolerance does not make a future record fresh: it becomes explicitly stale.
  AssessmentPolicy tolerant{};
  tolerant.future_skew_tolerance_ns = 1000 * kSecond;
  const SwitchAssessment tolerated =
      sff::assess_switch(subject, store, failures, 1 * kSecond, tolerant);
  CHECK(tolerated.outcome == Code::Stale);
  CHECK(!tolerated.usable);
  CHECK(tolerated.supporting.empty());
  CHECK_EQ(tolerated.stale.size(), std::size_t{1});

  // Once the observation instant has actually arrived, the same record is authoritative, and a
  // failure declaration is required to fence.
  const SwitchAssessment arrived =
      sff::assess_switch(subject, store, failures, 1 * kSecond + 500 * kSecond, AssessmentPolicy{});
  CHECK(arrived.outcome == Code::Ok);
  CHECK(arrived.fence_required);
  CHECK(!arrived.usable);
  CHECK_EQ(arrived.supporting.size(), std::size_t{1});
  CHECK_EQ(arrived.out_of_window.size(), std::size_t{0});
}

// --- per-record validation ----------------------------------------------------------------------

SFF_TEST(evidence_records_are_validated_field_by_field) {
  const Limits limits = Limits::defaults();
  const SwitchKey subject = key(1, 1);
  const EvidenceRecord baseline = synth_health(EvidenceId(40), EvidenceSource::TelemetryCollector, subject,
                                               SwitchHealthState::Healthy, 1 * kSecond, 1 * kSecond);
  CHECK(baseline.validate(limits).ok());

  struct Case {
    const char* what;
    EvidenceRecord record;
    Code expected;
  };

  std::vector<Case> cases;
  {
    EvidenceRecord record = baseline;
    record.id = EvidenceId(0);
    cases.push_back(Case{"no identity", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.kind = EvidenceKind::Unknown;
    cases.push_back(Case{"unknown kind", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.kind = static_cast<EvidenceKind>(99);
    cases.push_back(Case{"undefined kind", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.source = EvidenceSource::Unknown;
    cases.push_back(Case{"unknown source", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.source = static_cast<EvidenceSource>(99);
    cases.push_back(Case{"undefined source", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.subject = key(0, 1);
    cases.push_back(Case{"subject without an identity", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.subject = key(1, 0);
    cases.push_back(Case{"subject without a generation", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.valid_for_ns = 0;
    cases.push_back(Case{"zero validity window", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.observed_at_ns = 0;
    cases.push_back(Case{"no observation time", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.health = SwitchHealthState::Unknown;
    cases.push_back(Case{"health evidence with no health state", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.health = static_cast<SwitchHealthState>(99);
    cases.push_back(Case{"undefined health state", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.kind = EvidenceKind::AdminStateDeclaration;
    record.admin = SwitchAdminState::Unknown;
    cases.push_back(Case{"admin evidence with no admin state", record, Code::Invalid});
  }
  {
    EvidenceRecord record = baseline;
    record.kind = EvidenceKind::EffectVerification;
    cases.push_back(Case{"effect evidence without a dependent", record, Code::Invalid});
  }
  {
    // An advisory source may not assert a lifecycle fact, however it is adjudicated later.
    EvidenceRecord record =
        synth_lifecycle(EvidenceId(41), EvidenceKind::SwitchFailureDeclaration,
                        EvidenceSource::SwitchAgent, subject, 1 * kSecond, 1 * kSecond);
    cases.push_back(Case{"advisory lifecycle declaration", record, Code::Unsupported});
  }

  ManualClock clock(1 * kSecond);
  EvidenceStore store(Limits::defaults(), &clock);
  std::size_t expected_rejections = 0;
  for (const auto& entry : cases) {
    const Status status = entry.record.validate(limits);
    CHECK(!status.ok());
    if (!status.ok()) {
      CHECK(status.code() == entry.expected);
      if (status.code() != entry.expected) {
        std::printf("  %s: expected %s, got %s\n", entry.what, sff::to_string(entry.expected),
                    status.to_string().c_str());
      }
    }
    const Status admitted = store.admit(entry.record);
    CHECK(!admitted.ok());
    CHECK(admitted.code() == entry.expected);
    expected_rejections += 1;
    CHECK_EQ(store.rejected(), expected_rejections);
    CHECK_EQ(store.size(), std::size_t{0});
  }

  // Positive control: a fixture-sourced lifecycle declaration is authoritative and admissible.
  const EvidenceRecord fixture =
      synth_lifecycle(EvidenceId(42), EvidenceKind::SwitchFailureDeclaration,
                      EvidenceSource::SimulatedFixture, subject, 1 * kSecond, 1 * kSecond);
  CHECK(fixture.validate(limits).ok());
  CHECK(store.admit(fixture).ok());
  CHECK_EQ(store.size(), std::size_t{1});
  CHECK_EQ(store.for_subject(subject).size(), std::size_t{1});
}

// --- generation qualification -------------------------------------------------------------------

SFF_TEST(a_different_generation_is_a_different_authority_subject) {
  ManualClock clock(1 * kSecond);
  EvidenceStore store(Limits::defaults(), &clock);
  FailureTable failures;
  const SwitchKey generation_one = key(7, 1);
  const SwitchKey generation_two = key(7, 2);
  CHECK(generation_one.same_identity(generation_two));
  CHECK(generation_one != generation_two);

  const EvidenceRecord failure =
      synth_lifecycle(EvidenceId(50), EvidenceKind::SwitchFailureDeclaration,
                      EvidenceSource::FabricManager, generation_two, 1 * kSecond, 3600 * kSecond);
  CHECK(admit_or_report(store, failure, "generation two failure").ok());
  CHECK(store.for_subject(generation_one).empty());
  CHECK_EQ(store.for_subject(generation_two).size(), std::size_t{1});

  const SwitchAssessment untouched =
      sff::assess_switch(generation_one, store, failures, 1 * kSecond, AssessmentPolicy{});
  CHECK(untouched.outcome == Code::Unknown);
  CHECK(!untouched.usable);
  CHECK(!untouched.fence_required);
  CHECK(untouched.supporting.empty());
  CHECK(untouched.stale.empty());
  CHECK(untouched.out_of_window.empty());

  const SwitchAssessment failed =
      sff::assess_switch(generation_two, store, failures, 1 * kSecond, AssessmentPolicy{});
  CHECK(failed.outcome == Code::Ok);
  CHECK(failed.fence_required);
  CHECK(!failed.usable);

  // Durable lineage is generation-qualified in exactly the same way.
  FailureRecord record;
  record.subject = generation_two;
  record.evidence = EvidenceId(51);
  record.epoch = CoordinatorEpoch(1);
  record.boot = synth_boot();
  record.observed_at_ns = 1 * kSecond;
  record.recorded_at_ns = 1 * kSecond;
  record.reason = "SYNTHETIC durable failure for generation two";
  CHECK(failures.record(record).ok());
  const SwitchAssessment still_untouched =
      sff::assess_switch(generation_one, store, failures, 2 * kSecond, AssessmentPolicy{});
  CHECK(still_untouched.outcome == Code::Unknown);
  CHECK(!still_untouched.durable_failure_present);
  CHECK(!still_untouched.fence_required);
}

// --- durability ---------------------------------------------------------------------------------

SFF_TEST(durable_failure_lineage_survives_the_loss_of_every_dynamic_record) {
  ManualClock clock(1 * kSecond);
  EvidenceStore store(Limits::defaults(), &clock);
  FailureTable failures;
  const SwitchKey subject = key(5, 1);

  FailureRecord committed;
  committed.subject = subject;
  committed.evidence = EvidenceId(900);
  committed.epoch = CoordinatorEpoch(1);
  committed.boot = synth_boot();
  committed.observed_at_ns = 1 * kSecond;
  committed.recorded_at_ns = 1 * kSecond;
  committed.reason = "SYNTHETIC committed failure lineage";
  CHECK(failures.record(committed).ok());
  CHECK(failures.contains(subject));
  CHECK_EQ(failures.size(), std::size_t{1});
  CHECK(failures.find(subject) != nullptr);

  CHECK(store.admit(synth_lifecycle(EvidenceId(901), EvidenceKind::SwitchFailureDeclaration,
                                    EvidenceSource::FabricManager, subject, 1 * kSecond, 3600 * kSecond))
            .ok());
  const SwitchAssessment before_restart =
      sff::assess_switch(subject, store, failures, 1 * kSecond, AssessmentPolicy{});
  CHECK(before_restart.outcome == Code::Ok);
  CHECK(before_restart.fence_required);
  CHECK(!before_restart.usable);
  CHECK(before_restart.durable_failure_present);

  // Restart: every dynamic record is gone, the lineage is not.
  store.clear();
  CHECK_EQ(store.size(), std::size_t{0});
  const SwitchAssessment after_restart =
      sff::assess_switch(subject, store, failures, 2 * kSecond, AssessmentPolicy{});
  CHECK(after_restart.outcome == Code::Ok);
  CHECK(after_restart.durable_failure_present);
  CHECK(after_restart.fence_required);
  CHECK(!after_restart.usable);
  CHECK(after_restart.health == SwitchHealthState::Failed);
  CHECK(after_restart.durable_failure.evidence == EvidenceId(900));
  CHECK_EQ(after_restart.supporting.size(), std::size_t{1});
  CHECK(after_restart.supporting.front() == EvidenceId(900));
  CHECK(failures.contains(subject));

  // A strictly later authoritative recovery declaration makes the generation usable again, and it
  // still does not erase the durable lineage.
  CHECK(store.admit(synth_lifecycle(EvidenceId(902), EvidenceKind::SwitchRecoveryDeclaration,
                                    EvidenceSource::FabricManager, subject, 3 * kSecond, 3600 * kSecond))
            .ok());
  const SwitchAssessment recovered =
      sff::assess_switch(subject, store, failures, 3 * kSecond, AssessmentPolicy{});
  CHECK(recovered.outcome == Code::Ok);
  CHECK(recovered.usable);
  CHECK(recovered.durable_failure_present);
  CHECK(failures.contains(subject));

  // Only a strictly later supersede removes the lineage; equal or earlier is refused.
  CHECK(failures.supersede(subject, 1 * kSecond).code() == Code::Stale);
  CHECK(failures.contains(subject));
  CHECK(failures.supersede(subject, 1 * kSecond - 1).code() == Code::Stale);
  CHECK(failures.contains(subject));
  CHECK(failures.supersede(subject, 1 * kSecond + 1).ok());
  CHECK(!failures.contains(subject));
  CHECK_EQ(failures.size(), std::size_t{0});

  // With the lineage superseded and no evidence left, the generation is simply unknown again -
  // never silently healthy, and no longer fenced.
  store.clear();
  const SwitchAssessment after_supersede =
      sff::assess_switch(subject, store, failures, 4 * kSecond, AssessmentPolicy{});
  CHECK(after_supersede.outcome == Code::Unknown);
  CHECK(!after_supersede.durable_failure_present);
  CHECK(!after_supersede.usable);
  CHECK(!after_supersede.fence_required);
}

SFF_TEST(failure_table_keeps_the_newest_lineage_and_refuses_a_non_posterior_recovery) {
  FailureTable failures;
  const SwitchKey subject = key(9, 1);

  FailureRecord first;
  first.subject = subject;
  first.evidence = EvidenceId(60);
  first.epoch = CoordinatorEpoch(1);
  first.boot = synth_boot();
  first.observed_at_ns = 5 * kSecond;
  first.recorded_at_ns = 5 * kSecond;
  first.reason = "SYNTHETIC first failure";
  CHECK(failures.record(first).ok());
  CHECK_EQ(failures.size(), std::size_t{1});

  // A late-arriving older declaration cannot un-fail the switch.
  FailureRecord stale_arrival = first;
  stale_arrival.observed_at_ns = 4 * kSecond;
  stale_arrival.evidence = EvidenceId(61);
  CHECK(failures.record(stale_arrival).ok());
  CHECK(failures.find(subject) != nullptr);
  if (failures.find(subject) != nullptr) {
    CHECK_EQ(failures.find(subject)->observed_at_ns, 5 * kSecond);
    CHECK(failures.find(subject)->evidence == EvidenceId(60));
  }

  // A newer declaration replaces it.
  FailureRecord newest = first;
  newest.observed_at_ns = 6 * kSecond;
  newest.evidence = EvidenceId(62);
  CHECK(failures.record(newest).ok());
  if (failures.find(subject) != nullptr) {
    CHECK_EQ(failures.find(subject)->observed_at_ns, 6 * kSecond);
  }

  CHECK(failures.supersede(subject, 6 * kSecond).code() == Code::Stale);
  CHECK(failures.supersede(subject, 5 * kSecond).code() == Code::Stale);
  CHECK(failures.contains(subject));
  CHECK(failures.supersede(subject, 6 * kSecond + 1).ok());
  CHECK(!failures.contains(subject));
  CHECK_EQ(failures.all().size(), std::size_t{0});

  // Superseding something that was never recorded is a no-op, not a fabricated success of recovery.
  CHECK(failures.supersede(key(77, 1), 1 * kSecond).ok());
  CHECK_EQ(failures.size(), std::size_t{0});

  // Malformed lineage is refused rather than admitted.
  FailureRecord unqualified = first;
  unqualified.subject = key(9, 0);
  CHECK(failures.record(unqualified).code() == Code::Invalid);
  FailureRecord undated = first;
  undated.observed_at_ns = 0;
  CHECK(failures.record(undated).code() == Code::Invalid);
  CHECK_EQ(failures.size(), std::size_t{0});
}

// --- bounded retention --------------------------------------------------------------------------

SFF_TEST(evidence_store_retention_is_bounded_and_duplicates_are_refused) {
  ManualClock clock(1 * kSecond);
  const SwitchKey subject = key(8, 1);
  constexpr std::size_t kAdmissions = 40;

  EvidenceStore store(Limits::defaults(), &clock);
  for (std::size_t i = 0; i < kAdmissions; ++i) {
    const EvidenceRecord record =
        synth_health(EvidenceId(i + 1), EvidenceSource::SimulatedFixture, subject,
                     SwitchHealthState::Healthy, 1 * kSecond + i * kSecond, 3600 * kSecond);
    CHECK(store.admit(record).ok());
  }
  CHECK_EQ(store.size(), store.for_subject(subject).size());
  CHECK(store.evicted() > 0);
  CHECK(store.size() < kAdmissions);
  CHECK_EQ(store.size() + store.evicted(), kAdmissions);
  CHECK_EQ(store.rejected(), std::size_t{0});
  CHECK(!store.had_rejection());
  CHECK_EQ(store.records().size(), store.size());

  const std::vector<EvidenceRecord> retained = store.for_subject(subject);
  CHECK(!retained.empty());
  // The oldest was evicted, the newest retained, and canonical order is preserved.
  CHECK(retained.front().id != EvidenceId(1));
  CHECK(retained.back().id == EvidenceId(kAdmissions));
  CHECK(std::is_sorted(retained.begin(), retained.end(),
                       [](const EvidenceRecord& left, const EvidenceRecord& right) {
                         if (left.observed_at_ns != right.observed_at_ns) {
                           return left.observed_at_ns < right.observed_at_ns;
                         }
                         return left.id < right.id;
                       }));
  for (std::size_t i = 0; i + 1 < retained.size(); ++i) {
    CHECK_LT(retained[i].observed_at_ns, retained[i + 1].observed_at_ns);
  }

  // Hard ceiling: refusal is deterministic and nothing already admitted is disturbed.
  Limits capped = Limits::defaults();
  capped.max_evidence_records = 5;
  EvidenceStore small(capped, &clock);
  CHECK_EQ(small.capacity(), std::size_t{5});
  for (std::size_t i = 0; i < 5; ++i) {
    CHECK(small.admit(synth_health(EvidenceId(100 + i), EvidenceSource::SimulatedFixture, key(100 + i, 1),
                                   SwitchHealthState::Healthy, 1 * kSecond, 3600 * kSecond))
              .ok());
  }
  CHECK_EQ(small.size(), std::size_t{5});
  const EvidenceRecord over =
      synth_health(EvidenceId(200), EvidenceSource::SimulatedFixture, key(999, 1),
                   SwitchHealthState::Healthy, 1 * kSecond, 3600 * kSecond);
  const Status refused = small.admit(over);
  CHECK(!refused.ok());
  CHECK(refused.code() == Code::Exhausted);
  CHECK_EQ(small.rejected(), std::size_t{1});
  CHECK(small.had_rejection());
  CHECK_EQ(small.size(), std::size_t{5});
  CHECK_EQ(small.evicted(), std::size_t{0});
  CHECK(small.for_subject(key(999, 1)).empty());
  CHECK_EQ(small.for_subject(key(100, 1)).size(), std::size_t{1});
  CHECK_EQ(small.for_subject(key(104, 1)).size(), std::size_t{1});

  // A duplicate evidence identity is refused rather than stored twice.
  EvidenceStore duplicate_store(Limits::defaults(), &clock);
  const EvidenceRecord once = synth_health(EvidenceId(300), EvidenceSource::SimulatedFixture, subject,
                                           SwitchHealthState::Healthy, 1 * kSecond, 3600 * kSecond);
  CHECK(duplicate_store.admit(once).ok());
  EvidenceRecord twice = once;
  twice.health = SwitchHealthState::Degraded;  // same identity, contradictory content
  const Status duplicate = duplicate_store.admit(twice);
  CHECK(!duplicate.ok());
  CHECK(duplicate.code() == Code::AlreadyExists);
  CHECK_EQ(duplicate_store.size(), std::size_t{1});
  CHECK_EQ(duplicate_store.for_subject(subject).size(), std::size_t{1});
  CHECK(duplicate_store.for_subject(subject).front().health == SwitchHealthState::Healthy);
}

}  // namespace

SFF_MAIN()
