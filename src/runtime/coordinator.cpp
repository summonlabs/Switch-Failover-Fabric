// Switch Failover Fabric - the coordinator runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/runtime/coordinator.hpp"

#include <algorithm>
#include <string>

#include "runtime/coordinator_impl.hpp"
#include "sff/codec/bytes.hpp"
#include "sff/codec/integrity.hpp"
#include "sff/persist/records.hpp"

namespace sff {
namespace {

std::uint64_t boot_digest_of(const BootIncarnation& boot) noexcept {
  Digest128 digest;
  digest.absorb_string("sff.boot-incarnation.v1");
  digest.absorb_u64(boot.process_id());
  digest.absorb_u64(boot.boot_ordinal());
  digest.absorb_u64(boot.nonce_hi());
  digest.absorb_u64(boot.nonce_lo());
  return digest.hi;
}

}  // namespace

Coordinator::Coordinator(const CoordinatorConfig& config, const Clock* clock)
    : impl_(std::make_unique<Impl>(config, clock)) {}

Coordinator::~Coordinator() {
  if (impl_) {
    if (impl_->store) {
      Status ignored = impl_->store->close();
      (void)ignored;
    }
  }
}

Decision& Coordinator::Impl::record_decision(DecisionKind kind, DecisionScope scope, Code outcome,
                                              Code reason,
                                GenerationVector bound, Explanation explanation) {
  Decision decision;
  decision.kind = kind;
  decision.scope = std::move(scope);
  decision.outcome = outcome;
  decision.reason = reason;
  decision.bound = std::move(bound);
  decision.epoch = epoch;
  decision.boot = boot;
  decision.evidence_class = config.evidence_class;
  decision.explanation = std::move(explanation);
  decision.recorded_at_ns = now();
  decisions.append(std::move(decision));
  return decisions.tail(1).front();
}

PlanInputs Coordinator::Impl::make_inputs(PlanId plan_id, TimestampNs now_ns) const {
  PlanInputs inputs;
  inputs.topology = &topology;
  inputs.candidates = &candidates;
  inputs.evidence = &evidence;
  inputs.failures = &failures;
  inputs.authority = &authority;
  inputs.clock = clock;
  inputs.limits = limits;
  inputs.assessment = policy.assessment;
  inputs.planning = policy.planning;
  inputs.epoch = epoch;
  inputs.boot = boot;
  inputs.plan_id = plan_id;
  inputs.now_ns = now_ns;
  return inputs;
}

Status Coordinator::Impl::persist_record(RecordKind kind, const std::vector<std::uint8_t>& payload) {
  if (!store) return Status::success();
  return store->append(kind, payload);
}

Result<std::unique_ptr<Coordinator>> Coordinator::open(const CoordinatorConfig& config,
                                                       const Clock* clock) {
  Status limit_status = config.limits.validate();
  if (!limit_status.ok()) return limit_status;
  Status policy_status = config.policy.validate();
  if (!policy_status.ok()) return policy_status;

  std::unique_ptr<Coordinator> coordinator(new Coordinator(config, clock));
  Impl& impl = *coordinator->impl_;
  impl.limits = config.limits;
  impl.policy = config.policy;

  CoordinatorEpoch previous_epoch;
  BootIncarnation previous_boot;
  std::uint64_t previous_boot_ordinal = 0;

  if (config.enable_durability) {
    if (config.durable_root.empty()) {
      return Status::failure(Code::Invalid, "durability was requested without a durable root");
    }
    StoreOptions options;
    options.root = config.durable_root;
    options.limits = config.limits;
    options.mode = OpenMode::OpenOrCreate;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    if (!store.ok()) return store.status();
    impl.store = std::move(store).value();

    const ReplayReport& opening = impl.store->open_report();
    if (!opening.status.ok()) {
      return Status::failure(opening.status.code(),
                             "durable lineage could not be replayed without corruption");
    }

    RestartReport report;
    // Nothing was recovered from a brand-new journal, so claiming recovery would be false.
    report.recovered = !opening.records.empty();
    report.clean_previous_shutdown = opening.clean_shutdown;
    report.torn_tail_truncated = opening.truncated_tail;
    report.records_replayed = opening.records.size();
    report.corrupt_records = opening.corrupt_records;
    report.torn_records = opening.torn_records;
    report.unsupported_records = opening.unsupported_records;

    std::size_t grants_restored = 0;
    for (const auto& record : opening.records) {
      switch (record.header.kind) {
        case RecordKind::StreamHeader: {
          ByteReader reader(record.payload);
          reader.u8();
          reader.u16();
          const std::uint64_t boot_ordinal = reader.u64();
          const std::uint64_t process_id = reader.u64();
          const std::uint64_t epoch_raw = reader.u64();
          const std::uint64_t nonce_hi = reader.u64();
          const std::uint64_t nonce_lo = reader.u64();
          if (reader.ok()) {
            previous_epoch = CoordinatorEpoch(epoch_raw);
            previous_boot = BootIncarnation::from_parts(process_id, boot_ordinal, nonce_hi, nonce_lo);
            previous_boot_ordinal = boot_ordinal;
          }
          break;
        }
        case RecordKind::FailureCommitted: {
          Result<FailureRecord> decoded = decode_failure_record(record.payload);
          if (decoded.ok()) {
            Status s = impl.failures.record(decoded.value());
            if (s.ok()) report.failures_restored += 1;
          }
          break;
        }
        case RecordKind::FenceCommitted: {
          Result<FenceRecord> decoded = decode_fence_record(record.payload);
          if (decoded.ok()) {
            Status s = impl.authority.restore_fence(decoded.value());
            if (s.ok()) report.fences_restored += 1;
          }
          break;
        }
        case RecordKind::GrantMinted: {
          Result<AuthorityGrant> decoded = decode_grant_record(record.payload);
          if (decoded.ok()) {
            Status s = impl.authority.restore_grant(decoded.value());
            if (s.ok()) grants_restored += 1;
          }
          break;
        }
        case RecordKind::PlanCommitted: {
          Result<ReconstructionPlan> decoded =
              decode_plan_record(record.payload, config.limits);
          if (decoded.ok()) {
            // Later records for the same plan supersede earlier ones; only the final restored
            // state decides whether the plan was genuinely in flight when the process ended.
            ReconstructionPlan plan = std::move(decoded).value();
            const PlanId plan_id = plan.id;
            const bool first_seen = impl.plans.find(plan_id) == impl.plans.end();
            impl.plans[plan_id] = std::move(plan);
            if (first_seen) report.plans_restored += 1;
          }
          break;
        }
        case RecordKind::ApplyCompleted: {
          Result<ApplyReceipt> decoded = decode_apply_receipt(record.payload);
          if (decoded.ok()) {
            for (const auto& step : decoded.value().steps) {
              impl.apply_steps[{step.dependent, step.replacement}] = step;
            }
          }
          break;
        }
        default:
          break;
      }
    }

    // A note is emitted only for plans whose FINAL restored state is still Applying, which is the
    // honest statement that no apply completion record exists for them.
    for (const auto& entry : impl.plans) {
      if (entry.second.state != PlanState::Applying) continue;
      report.notes.push_back("plan " + std::to_string(entry.first.raw()) +
                             " was in flight when the process ended; its effect is ambiguous and "
                             "no apply completion record exists");
    }

    if (previous_boot_ordinal != 0) {
      // A restart always advances the epoch and mints a fresh incarnation.
      impl.epoch = CoordinatorEpoch(previous_epoch.raw() + 1);
      impl.boot = BootIncarnation::for_current_process(previous_boot_ordinal + 1);
    } else {
      impl.epoch = CoordinatorEpoch(1);
      impl.boot = BootIncarnation::for_current_process(
          config.boot_ordinal == 0 ? 1 : config.boot_ordinal);
    }
    report.previous_epoch = previous_epoch;
    report.previous_boot = previous_boot;
    report.current_epoch = impl.epoch;
    report.current_boot = impl.boot;

    // Persistence is not liveness. Every grant restored above is already Stale; this call is the
    // single, explicit statement of that fact and is idempotent.
    const std::size_t invalidated =
        impl.authority.invalidate_pre_restart(impl.epoch, impl.boot, impl.now());
    report.grants_invalidated = grants_restored + invalidated;
    if (impl.policy.fence_on_restart) {
      report.grants_fenced =
          impl.authority.withdraw_all(RevocationCause::Restart,
                                      "fence-on-restart policy refuses stale authority");
    }
    report.dynamic_evidence_restored = false;
    report.notes.push_back(
        "dynamic liveness, telemetry freshness, active leases and in-flight authority were not "
        "restored");
    report.notes.push_back(
        "the installed topology and the supplied candidate table are inputs, not durable state; "
        "the authoritative source must reinstall them");
    report.status = Status::success();
    impl.restart = report;
  } else {
    impl.epoch = CoordinatorEpoch(1);
    impl.boot = BootIncarnation::for_current_process(config.boot_ordinal == 0 ? 1
                                                                             : config.boot_ordinal);
    impl.restart.recovered = false;
    impl.restart.current_epoch = impl.epoch;
    impl.restart.current_boot = impl.boot;
    impl.restart.dynamic_evidence_restored = false;
    impl.restart.status = Status::success();
  }

  impl.boot_digest = boot_digest_of(impl.boot);

  if (impl.store) {
    Status s = impl.persist_record(RecordKind::StreamHeader,
                                   encode_stream_header(kRecordFormatVersion,
                                                        impl.boot.boot_ordinal(),
                                                        impl.boot.process_id(), impl.epoch.raw(),
                                                        impl.boot.nonce_hi(), impl.boot.nonce_lo()));
    if (!s.ok()) return s;
    if (impl.epoch.raw() > 1) {
      s = impl.persist_record(RecordKind::EpochAdvance, encode_u64_payload(impl.epoch.raw()));
      if (!s.ok()) return s;
    }
  }

  impl.append_event(EventKind::RuntimeBooted, Code::Ok,
                    std::string("epoch=") + std::to_string(impl.epoch.raw()) + " boot=" +
                        std::to_string(impl.boot.boot_ordinal()));
  if (impl.restart.recovered) {
    impl.append_event(EventKind::RestartReconciled, impl.restart.status.code(),
                      "durable lineage reconciled; dynamic authority was not restored");
  }
  return coordinator;
}

// ---------------------------------------------------------------------------------------------
// Runtime identity
// ---------------------------------------------------------------------------------------------

CoordinatorEpoch Coordinator::epoch() const { return impl_->epoch; }

BootIncarnation Coordinator::boot() const { return impl_->boot; }

std::uint64_t Coordinator::boot_digest() const { return impl_->boot_digest; }

EvidenceClass Coordinator::evidence_class() const { return impl_->config.evidence_class; }

const Limits& Coordinator::limits() const { return impl_->limits; }

Policy Coordinator::policy() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->policy;
}

bool Coordinator::stopped() const { return impl_->stopped.load(std::memory_order_acquire); }

// ---------------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------------

Status Coordinator::install_topology(TopologySnapshot topology) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  if (topology.empty()) {
    return Status::failure(Code::Invalid, "an empty topology snapshot is not installable");
  }
  std::vector<std::uint8_t> payload;
  {
    ByteWriter writer;
    writer.u8(1);
    writer.u64(topology.version().raw());
    writer.u64(topology.digest());
    writer.u64(topology.switches().size());
    writer.u64(topology.links().size());
    writer.u64(topology.paths().size());
    payload = writer.bytes();
  }
  Status s = impl_->persist_record(RecordKind::TopologyInstalled, payload);
  if (!s.ok()) return s;
  impl_->topology = std::move(topology);
  impl_->topology_present = true;

  // An authoritative topology declaration is also the statement that the declared paths and links
  // are forwarding. Authority is therefore established for each of them, bound to the exact
  // generations they traverse, so that a later generation failure has something real to fence.
  std::size_t granted = 0;
  for (const auto& path : impl_->topology.paths()) {
    GenerationVector bound;
    for (const auto& hop : path.hops) bound.insert(hop);
    if (bound.empty()) continue;
    Result<GrantId> established = impl_->authority.grant(
        DependentRef::path(path.id), bound, impl_->epoch, impl_->boot, impl_->now(),
        impl_->policy.grant_ttl_ns, "established by topology declaration");
    if (established.ok()) granted += 1;
  }
  for (const auto& link : impl_->topology.links()) {
    GenerationVector bound;
    bound.insert(link.a.sw);
    bound.insert(link.b.sw);
    if (bound.empty()) continue;
    Result<GrantId> established = impl_->authority.grant(
        DependentRef::link(link.id), bound, impl_->epoch, impl_->boot, impl_->now(),
        impl_->policy.grant_ttl_ns, "established by topology declaration");
    if (established.ok()) granted += 1;
  }

  impl_->append_event(EventKind::TopologyInstalled, Code::Ok,
                      "topology snapshot installed for this incarnation",
                      impl_->topology.version().raw());
  impl_->append_event(EventKind::AuthorityGranted, Code::Ok,
                      "authority established for declared dependents", granted);
  return Status::success();
}

Status Coordinator::establish_authority(const DependentRef& dependent, const GenerationVector& bound,
                                        std::string_view detail) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  Result<GrantId> established = impl_->authority.grant(dependent, bound, impl_->epoch, impl_->boot,
                                                       impl_->now(), impl_->policy.grant_ttl_ns,
                                                       detail);
  if (!established.ok()) {
    impl_->append_event(EventKind::AuthorityRevoked, established.status().code(),
                        established.status().message(), dependent.id());
    return established.status();
  }
  impl_->append_event(EventKind::AuthorityGranted, Code::Ok, "authority established",
                      dependent.id());
  return Status::success();
}

Status Coordinator::withdraw_authority(const DependentRef& dependent, RevocationCause cause,
                                       std::string_view detail) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  const std::size_t revoked = impl_->authority.revoke_dependent(dependent, cause, detail);
  impl_->append_event(EventKind::AuthorityRevoked, Code::Ok, "authority withdrawn", revoked);
  return Status::success();
}

Status Coordinator::install_candidates(CandidateTable candidates) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  impl_->candidates = std::move(candidates);
  impl_->candidates_present = true;
  impl_->append_event(EventKind::TopologyInstalled, Code::Ok,
                      "reconstruction candidate table installed", impl_->candidates.digest());
  return Status::success();
}

Status Coordinator::install_policy(const Policy& policy) {
  Status valid = policy.validate();
  if (!valid.ok()) return valid;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  Status s = impl_->persist_record(RecordKind::PolicyInstalled, policy.encode());
  if (!s.ok()) return s;
  impl_->policy = policy;
  impl_->append_event(EventKind::TopologyInstalled, Code::Ok, "policy installed", policy.digest());
  return Status::success();
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

Result<SessionRecord> Coordinator::open_session(std::string_view principal) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status running;
  if (!impl_->ensure_running(running)) return running;
  Result<SessionRecord> opened =
      impl_->sessions.open(principal, impl_->epoch, impl_->boot, impl_->now());
  if (!opened.ok()) return opened;
  impl_->append_event(EventKind::SessionOpened, Code::Ok, "session established",
                      opened.value().id.raw());
  return opened;
}

Status Coordinator::close_session(SessionId id) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status s = impl_->sessions.close(id);
  if (!s.ok()) return s;
  impl_->append_event(EventKind::SessionClosed, Code::Ok, "session closed", id.raw());
  return Status::success();
}

Status Coordinator::authorise(const SessionBinding& binding) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->sessions.authorise(binding, impl_->epoch, impl_->boot_digest);
}

std::size_t Coordinator::session_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->sessions.size();
}

// ---------------------------------------------------------------------------------------------
// Queries and borrowed views
// ---------------------------------------------------------------------------------------------

std::vector<EventRecord> Coordinator::events(std::size_t count) const {
  return impl_->events.tail(count);
}

std::vector<Decision> Coordinator::decisions(std::size_t count) const {
  return impl_->decisions.tail(count);
}

Result<RestartReport> Coordinator::restart_report() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->restart;
}

Result<ReconstructionPlan> Coordinator::plan_by_id(PlanId id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto position = impl_->plans.find(id);
  if (position == impl_->plans.end()) {
    return Status::failure(Code::NotFound, "no plan with that identity is retained");
  }
  return position->second;
}

std::vector<ReconstructionPlan> Coordinator::plans() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<ReconstructionPlan> result;
  result.reserve(impl_->plans.size());
  for (const auto& entry : impl_->plans) result.push_back(entry.second);
  return result;
}

const TopologySnapshot* Coordinator::topology() const { return impl_->topology_present ? &impl_->topology : nullptr; }

const FailureTable* Coordinator::failures() const { return &impl_->failures; }

const EvidenceStore* Coordinator::evidence() const { return &impl_->evidence; }

const AuthorityRegistry* Coordinator::authority() const { return &impl_->authority; }

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

Status Coordinator::shutdown() {
  bool expected = false;
  if (!impl_->stopped.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    return Status::success();
  }
  const std::size_t closed = impl_->sessions.close_all();
  impl_->append_event(EventKind::RuntimeShutdown, Code::Ok, "runtime shutting down");

  Status s = Status::success();
  if (impl_->store) {
    s = impl_->persist_record(RecordKind::ShutdownClean, encode_u64_payload(impl_->epoch.raw()));
    if (s.ok()) s = impl_->store->sync();
    Status closed_status = impl_->store->close();
    if (s.ok()) s = closed_status;
    if (!s.ok()) {
      impl_->append_event(EventKind::RuntimeShutdown, s.code(), s.message());
    }
  }
  if (closed != 0) {
    impl_->append_event(EventKind::SessionClosed, Code::Ok, "sessions invalidated at shutdown",
                        closed);
  }
  return s;
}

}  // namespace sff
