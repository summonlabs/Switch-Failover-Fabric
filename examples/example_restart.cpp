// Switch Failover Fabric - example: the restart contract with durable storage.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This program commits a failure and a fence into a durable store, shuts the runtime down, opens a
// fresh runtime over the same store and prints what a restart is allowed to carry across the
// process boundary:
//
//   survives - committed failure lineage and committed fences: a switch that was declared failed
//              with authoritative evidence stays failed until an authoritative recovery says
//              otherwise, and a fence is never silently removed;
//   does not - dynamic liveness, telemetry freshness, in-flight authority and the installed
//              topology. Every restored grant is forced to Stale, and no evidence is restored.
//
// The topology and the reconstruction alternatives are INPUTS, not durable state: the authoritative
// source must reinstall them after a restart, which is why the reopened runtime reports that it has
// no topology until one is installed.
//
// Honest scope statement: this example performs an IN-PROCESS incarnation change with two
// sequential Coordinator instances. The real cross-process proof - two independent operating
// system processes over real sockets and real files - lives in the test suite. Nothing here claims
// to be that proof.
#include "sff/sff.hpp"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace sff;

constexpr TimestampNs kStartNs = 1000000000ull;
constexpr TimestampNs kSecondIncarnationNs = 2000000000ull;
constexpr std::uint64_t kWindowNs = 30ull * kNanosPerSecond;

int g_refusals = 0;

int refuse(const char* step, const Status& status) {
  g_refusals += 1;
  std::cout << "REFUSED step=" << step << " code=" << to_string(status.code()) << " detail=\""
            << status.message() << "\"\n";
  std::cout << "example_restart_status=refused exit=1\n";
  return 1;
}

struct Fixture {
  TopologySnapshot topology;
  CandidateTable candidates;
  SwitchKey failed;
  SwitchKey cover;
};

bool build_fixture(Fixture& out, std::string& error) {
  const SwitchKey failed(SwitchId(1), SwitchGeneration(1));
  const SwitchKey cover(SwitchId(2), SwitchGeneration(1));
  const CapabilityMask caps = capability_bit(Capability::Layer2) | capability_bit(Capability::Layer3);

  std::vector<SwitchDescriptor> switches;
  {
    SwitchDescriptor descriptor;
    descriptor.key = failed;
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(10);
    descriptor.capabilities = caps;
    descriptor.port_count = 16;
    descriptor.capacity_score = 4;
    descriptor.label = "synthetic-leaf";
    switches.push_back(descriptor);

    descriptor.key = cover;
    descriptor.role = SwitchRole::Spine;
    descriptor.failure_domain = FailureDomainId(20);
    descriptor.port_count = 32;
    descriptor.capacity_score = 8;
    descriptor.label = "synthetic-spine";
    switches.push_back(descriptor);
  }

  std::vector<LinkDescriptor> links;
  {
    LinkDescriptor link;
    link.id = LinkId(1);
    link.a.sw = failed;
    link.a.index = 1;
    link.b.sw = cover;
    link.b.index = 1;
    link.cost = 1;
    links.push_back(link);
  }

  std::vector<PathDescriptor> paths;
  {
    PathDescriptor path;
    path.id = PathId(1);
    path.source = NodeId(1);
    path.destination = NodeId(9);
    path.hops.push_back(failed);
    path.hops.push_back(cover);
    path.links.push_back(LinkId(1));
    path.cost = 2;
    path.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(path);
  }

  std::vector<DependencyEdge> edges;
  {
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::service(5));
    edge.to = ClosureNode::of_dependent(DependentRef::path(PathId(1)));
    edges.push_back(edge);
  }

  std::vector<ReconstructionCandidate> supplied;
  {
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::link(LinkId(1));
    candidate.covers_failed = failed;
    candidate.hops.push_back(cover);
    candidate.cost = 1;
    candidate.capabilities = caps;
    candidate.evidence = EvidenceId(11);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::path(PathId(1));
    candidate.covers_failed = failed;
    candidate.hops.push_back(cover);
    candidate.cost = 3;
    candidate.capabilities = capability_bit(Capability::Layer3);
    candidate.evidence = EvidenceId(12);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(5);
    candidate.covers_failed = failed;
    candidate.hops.push_back(cover);
    candidate.cost = 2;
    candidate.capabilities = capability_bit(Capability::Layer3);
    candidate.evidence = EvidenceId(13);
    candidate.source = EvidenceSource::SimulatedFixture;
    supplied.push_back(candidate);
  }

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                              std::move(paths), std::move(edges), Limits::defaults());
  if (!topology.ok()) {
    error = topology.status().to_string();
    return false;
  }
  Result<CandidateTable> table = CandidateTable::build(std::move(supplied), Limits::defaults());
  if (!table.ok()) {
    error = table.status().to_string();
    return false;
  }
  out.topology = std::move(topology).value();
  out.candidates = std::move(table).value();
  out.failed = failed;
  out.cover = cover;
  return true;
}

Result<std::unique_ptr<Coordinator>> open_durable(const std::filesystem::path& root,
                                                  const Limits& limits, const Clock* clock) {
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = Policy{};  // fail-closed defaults; fence_on_restart stays off
  config.evidence_class = EvidenceClass::Synthetic;
  config.durable_root = root;
  config.enable_durability = true;
  return Coordinator::open(config, clock);
}

std::filesystem::path default_root() {
  std::random_device device;
  const std::uint64_t nonce =
      (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  return std::filesystem::temp_directory_path() /
         ("sff-example-restart-" + std::to_string(nonce));
}

/// Removes the durable store root on every exit path when this program created it. A directory
/// supplied by the caller is never deleted: it belongs to the caller.
class ScopedRoot {
 public:
  ScopedRoot(std::filesystem::path path, bool owned, bool keep)
      : path_(std::move(path)), owned_(owned), keep_(keep) {}

  ~ScopedRoot() {
    if (!owned_) {
      std::cout << "durable_root_kept=caller_supplied\n";
      return;
    }
    if (keep_) {
      std::cout << "durable_root_kept=--keep\n";
      return;
    }
    std::error_code removed;
    std::filesystem::remove_all(path_, removed);
    std::cout << "durable_root_removed=" << (removed ? "false" : "true") << "\n";
  }

  ScopedRoot(const ScopedRoot&) = delete;
  ScopedRoot& operator=(const ScopedRoot&) = delete;

 private:
  std::filesystem::path path_;
  bool owned_ = false;
  bool keep_ = false;
};

void print_usage() {
  std::cerr << "usage: example_restart [DIRECTORY] [--keep]\n"
            << "  DIRECTORY is the durable store root. When it is omitted a temporary directory\n"
            << "  is created and removed again unless --keep is passed.\n";
}

}  // namespace

int main(int argc, char** argv) {
  bool keep = false;
  std::filesystem::path root;
  bool caller_supplied_root = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--keep") {
      keep = true;
    } else if (!argument.empty() && argument[0] == '-') {
      print_usage();
      std::cerr << "example_restart: unknown option " << argument << "\n";
      return 2;
    } else if (root.empty()) {
      root = std::filesystem::path(argument);
      caller_supplied_root = true;
    } else {
      print_usage();
      std::cerr << "example_restart: at most one directory may be supplied\n";
      return 2;
    }
  }
  const bool created_root = !caller_supplied_root;
  if (created_root) root = default_root();
  ScopedRoot scoped_root(root, created_root, keep);

  const Limits limits = Limits::defaults();
  Fixture fixture;
  std::string error;
  if (!build_fixture(fixture, error)) {
    std::cout << "REFUSED fixture code=Invalid detail=\"" << error << "\"\n";
    return 1;
  }

  std::cout << "synthetic=true durable_root=\"" << root.string() << "\"\n";
  std::cout << "in_process_incarnation_change=true multiprocess_proof=test_suite\n";

  std::size_t active_grants_before = 0;
  std::vector<AuthorityGrant> active_before;
  CoordinatorEpoch first_epoch;
  std::uint64_t first_boot_ordinal = 0;

  // -------------------------------------------------------------------------------------------
  // Incarnation 1: commit a failure, observe the fence, apply a reconstruction, shut down.
  // -------------------------------------------------------------------------------------------
  {
    ManualClock clock(kStartNs);
    Result<std::unique_ptr<Coordinator>> opened = open_durable(root, limits, &clock);
    if (!opened.ok()) return refuse("incarnation_1_open", opened.status());
    std::unique_ptr<Coordinator> runtime = std::move(opened).value();
    first_epoch = runtime->epoch();
    first_boot_ordinal = runtime->boot().boot_ordinal();

    Status step = runtime->install_topology(fixture.topology);
    if (!step.ok()) return refuse("incarnation_1_install_topology", step);
    step = runtime->install_candidates(fixture.candidates);
    if (!step.ok()) return refuse("incarnation_1_install_candidates", step);

    FailureDeclaration declaration;
    declaration.subject = fixture.failed;
    declaration.source = EvidenceSource::SimulatedFixture;
    declaration.observed_at_ns = clock.now_ns();
    declaration.valid_for_ns = kWindowNs;
    declaration.reason = "synthetic fixture: generation declared unusable before the restart";
    Result<FailoverOutcome> failover = runtime->declare_failure(declaration);
    if (!failover.ok()) return refuse("incarnation_1_declare_failure", failover.status());
    std::cout << "incarnation_1_epoch=" << first_epoch.raw()
              << " boot_ordinal=" << first_boot_ordinal << "\n";
    std::cout << "incarnation_1_fence=" << failover.value().fence.raw()
              << " grants_fenced=" << failover.value().grants_fenced
              << " closure_dependents=" << failover.value().closure.dependents.size() << "\n";

    GenerationVector failed_set;
    failed_set.insert(fixture.failed);
    Result<ReconstructionPlan> proposed = runtime->propose_plan(failed_set);
    if (!proposed.ok()) return refuse("incarnation_1_propose_plan", proposed.status());
    Result<ApplyReceipt> applied = runtime->apply_plan(proposed.value());
    if (!applied.ok()) return refuse("incarnation_1_apply_plan", applied.status());
    std::cout << "incarnation_1_applied=" << applied.value().applied
              << " verified=" << applied.value().verified
              << " outcome=" << to_string(applied.value().outcome) << "\n";

    for (const AuthorityGrant& grant : runtime->authority()->all_grants()) {
      if (grant.state != GrantState::Active) continue;
      active_before.push_back(grant);
    }
    active_grants_before = active_before.size();
    std::cout << "incarnation_1_active_grants=" << active_grants_before << "\n";

    const Status shutdown = runtime->shutdown();
    if (!shutdown.ok()) return refuse("incarnation_1_shutdown", shutdown);
    std::cout << "incarnation_1_clean_shutdown=true\n";
  }

  // -------------------------------------------------------------------------------------------
  // The grant lifecycle gap, stated explicitly.
  //
  // This build's coordinator writes durable records for the failure, the fence, the plan and the
  // apply receipt, but it never writes GrantMinted or GrantWithdrawn records. Grant lifecycle
  // therefore does not survive a restart at all, which is fail-closed (nothing usable comes back)
  // but it leaves the "every restored grant is forced to Stale" contract unexercised. To exercise
  // the documented contract this example plants GrantMinted records for the grants that were
  // active before the shutdown, using the public durable record codec, and says so.
  // -------------------------------------------------------------------------------------------
  if (!active_before.empty()) {
    StoreOptions options;
    options.root = root;
    options.limits = limits;
    options.mode = OpenMode::OpenExisting;
    options.durable_writes = true;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(options);
    if (!store.ok()) return refuse("plant_open", store.status());
    std::unique_ptr<DurableStore> durable = std::move(store).value();
    // The shutdown marker was the last record until this point; the planted records follow it, so
    // the next restart legitimately reports clean_previous_shutdown=false.
    std::cout << "pre_plant_clean_shutdown="
              << (durable->open_report().clean_shutdown ? "true" : "false") << "\n";
    std::cout << "planted_records_follow_the_shutdown_marker=true\n";
    for (const AuthorityGrant& grant : active_before) {
      const Status appended =
          durable->append(RecordKind::GrantMinted, encode_grant_record(grant));
      if (!appended.ok()) return refuse("plant_grant", appended);
    }
    const Status closed = durable->close();
    if (!closed.ok()) return refuse("plant_close", closed);
    std::cout << "planted_grant_records=" << active_before.size()
              << " planted_because=this_build_never_persists_grant_lifecycle\n";
  }

  // -------------------------------------------------------------------------------------------
  // Incarnation 2: reopen over the same durable root and reconcile.
  // -------------------------------------------------------------------------------------------
  int exit_code = 0;
  {
    ManualClock clock(kSecondIncarnationNs);
    Result<std::unique_ptr<Coordinator>> opened = open_durable(root, limits, &clock);
    if (!opened.ok()) return refuse("incarnation_2_open", opened.status());
    std::unique_ptr<Coordinator> runtime = std::move(opened).value();

    Result<RestartReport> report_result = runtime->restart_report();
    if (!report_result.ok()) return refuse("incarnation_2_report", report_result.status());
    const RestartReport& report = report_result.value();

    std::cout << "restart_recovered=" << (report.recovered ? "true" : "false")
              << " clean_previous_shutdown=" << (report.clean_previous_shutdown ? "true" : "false")
              << " records_replayed=" << report.records_replayed
              << " torn_tail_truncated=" << (report.torn_tail_truncated ? "true" : "false") << "\n";
    std::cout << "restart_previous_epoch=" << report.previous_epoch.raw()
              << " current_epoch=" << report.current_epoch.raw()
              << " previous_boot_ordinal=" << report.previous_boot.boot_ordinal()
              << " current_boot_ordinal=" << report.current_boot.boot_ordinal() << "\n";
    std::cout << "restart_failures_restored=" << report.failures_restored
              << " fences_restored=" << report.fences_restored
              << " plans_restored=" << report.plans_restored
              << " grants_invalidated=" << report.grants_invalidated << "\n";
    std::cout << "restart_dynamic_evidence_restored="
              << (report.dynamic_evidence_restored ? "true" : "false") << "\n";
    for (const std::string& note : report.notes) {
      std::cout << "restart_note=\"" << note << "\"\n";
    }

    // The failure lineage survived, bound to the exact generation.
    const bool failure_survived = runtime->failures()->contains(fixture.failed);
    const FailureRecord* lineage = runtime->failures()->find(fixture.failed);
    std::cout << "failure_lineage_survived=" << (failure_survived ? "true" : "false") << "\n";
    if (lineage != nullptr) {
      std::cout << "failure_lineage_subject=" << lineage->subject.to_string()
                << " observed_at_ns=" << lineage->observed_at_ns << " reason=\""
                << lineage->reason << "\"\n";
    }

    // The fence survived and still applies to the exact generation.
    const bool fence_survived = runtime->authority()->is_fenced(fixture.failed);
    std::cout << "fence_survived=" << (fence_survived ? "true" : "false")
              << " fences=" << runtime->authority()->fence_count() << "\n";

    // Every restored grant is Stale, and no pre-restart authority is Active.
    const std::vector<AuthorityGrant> grants = runtime->authority()->all_grants();
    std::size_t stale = 0;
    std::size_t active = 0;
    for (const AuthorityGrant& grant : grants) {
      if (grant.state == GrantState::Stale) stale += 1;
      if (grant.state == GrantState::Active) active += 1;
    }
    std::cout << "restored_grants=" << grants.size() << " stale=" << stale
              << " active=" << active
              << " active_grant_count=" << runtime->authority()->active_grant_count() << "\n";

    // The installed topology is an input, not durable state: it must be reinstalled.
    std::cout << "topology_reinstalled_required="
              << (runtime->topology() == nullptr ? "true" : "false") << "\n";

    // A dependent that was covered before the restart has no usable authority now.
    const Result<AuthorityQuery> query = runtime->query_authority(DependentRef::service(5));
    if (query.ok()) {
      std::cout << "post_restart_authority dependent=" << query.value().dependent.to_string()
                << " has_authority=" << (query.value().has_authority ? "true" : "false")
                << " outcome=" << to_string(query.value().outcome) << "\n";
    }

    const Status shutdown = runtime->shutdown();
    if (!shutdown.ok()) return refuse("incarnation_2_shutdown", shutdown);

    const bool contract_held = failure_survived && fence_survived && active == 0 &&
                               !report.dynamic_evidence_restored && stale == grants.size() &&
                               report.current_epoch.raw() > report.previous_epoch.raw();
    std::cout << "incarnation_2_epoch=" << runtime->epoch().raw() << "\n";
    if (!contract_held) {
      std::cout << "REFUSED restart_contract code=Conflict detail=\"the restart contract did not "
                   "hold for one of: lineage, fence, staleness, epoch advance\"\n";
      g_refusals += 1;
      exit_code = 1;
    }
  }

  std::cout << "example_restart_summary synthetic=true in_process=true active_grants_before="
            << active_grants_before << " refusals=" << g_refusals
            << " result=" << (exit_code == 0 ? "ok" : "refused") << "\n";
  return exit_code;
}
