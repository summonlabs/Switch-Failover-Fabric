// Switch Failover Fabric - sffctl: deterministic command line driver.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every command operates on a SYNTHETIC in-process fixture topology: there is no hardware, no
// discovery and no live fabric here. The driver exists so that the product proposition can be
// asserted from a script:
//
//   given authoritative evidence that a switch GENERATION has failed, which dependent authority
//   must be fenced, which supplied replacement resources are eligible, and when may service be
//   restored under current generations?
//
// Output discipline: every command prints machine-readable one-line "key=value" summaries, never
// claims success when the underlying Status was not Ok, and exits 0 only on success. A malformed
// command prints the usage line to stderr and exits 2. A corrupt journal exits 3.
#include "sff/sff.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace sff;

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

constexpr int kExitOk = 0;
constexpr int kExitRefused = 1;
constexpr int kExitUsage = 2;
constexpr int kExitCorruptJournal = 3;

/// Every freshness decision in this driver is made against a deterministic clock, so two runs of
/// the same command produce identical output.
constexpr TimestampNs kClockStartNs = 1000000000ull;
constexpr std::uint64_t kEvidenceWindowNs = 30ull * kNanosPerSecond;

std::string quoted_text(std::string_view text) { return "\"" + std::string(text) + "\""; }

std::string hex64(std::uint64_t value) {
  static const char* digits = "0123456789abcdef";
  std::string result = "0x";
  for (int shift = 60; shift >= 0; shift -= 4) {
    result.push_back(digits[(value >> shift) & 0xfu]);
  }
  return result;
}

int refuse(std::string_view summary_key, Code code, std::string_view detail) {
  std::cout << summary_key << "=refused\n";
  std::cout << "refusal_code=" << to_string(code) << "\n";
  std::cout << "refusal_detail=" << quoted_text(detail) << "\n";
  std::cout << "sffctl_status=refused\n";
  std::cout << "exit=" << kExitRefused << "\n";
  return kExitRefused;
}

int refuse_status(std::string_view summary_key, const Status& status) {
  return refuse(summary_key, status.code(), status.message());
}

void print_usage(std::ostream& out) {
  out << "usage: sffctl <command> [options]\n"
      << "  sffctl demo  [--seed N] [--paths N] [--durable DIR]\n"
      << "  sffctl replay --log DIR\n"
      << "  sffctl plan  --seed N [--paths N] [--max-closure N]\n"
      << "  sffctl serve --port N [--root DIR]\n"
      << "  sffctl query --port N --dependent KIND:ID\n"
      << "  sffctl stop  --port N\n"
      << "  sffctl selftest\n"
      << "  KIND is one of PORT, LINK, PATH, SERVICE. All fixtures are SYNTHETIC.\n";
}

// ---------------------------------------------------------------------------------------------
// Strict hand-rolled argument handling: no third-party parser, no abbreviations, no defaults for
// required values.
// ---------------------------------------------------------------------------------------------

class CommandLine {
 public:
  explicit CommandLine(int argc, char** argv) {
    for (int index = 0; index < argc; ++index) args_.emplace_back(argv[index]);
  }

  std::size_t size() const { return args_.size(); }
  const std::string& at(std::size_t index) const { return args_[index]; }

  /// Parse "--name value" pairs starting at first_option_index. Every token must be a known
  /// option followed by exactly one value; repetition is refused rather than silently resolved.
  bool parse(std::size_t first_option_index, const std::vector<std::string>& allowed,
             std::string& error) {
    for (std::size_t index = first_option_index; index < args_.size(); ++index) {
      const std::string& token = args_[index];
      if (token.size() < 3 || token.rfind("--", 0) != 0) {
        error = "expected an option beginning with '--', found " + quoted_text(token);
        return false;
      }
      const std::string name = token.substr(2);
      bool known = false;
      for (const auto& candidate : allowed) {
        if (candidate == name) {
          known = true;
          break;
        }
      }
      if (!known) {
        error = "unknown option " + quoted_text(token);
        return false;
      }
      if (index + 1 >= args_.size()) {
        error = "option " + quoted_text(token) + " requires a value";
        return false;
      }
      if (options_.find(name) != options_.end()) {
        error = "option " + quoted_text(token) + " was supplied more than once";
        return false;
      }
      options_.emplace(name, args_[index + 1]);
      index += 1;
    }
    return true;
  }

  bool has(std::string_view name) const { return options_.find(std::string(name)) != options_.end(); }

  std::string value(std::string_view name) const {
    const auto position = options_.find(std::string(name));
    return position == options_.end() ? std::string() : position->second;
  }

 private:
  std::vector<std::string> args_;
  std::map<std::string, std::string> options_;
};

/// Strict unsigned decimal parse: no sign, no whitespace, no trailing characters, no overflow.
bool parse_u64(std::string_view text, std::uint64_t& out) {
  if (text.empty()) return false;
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') return false;
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (UINT64_MAX - digit) / 10ull) return false;
    value = value * 10ull + digit;
  }
  out = value;
  return true;
}

bool parse_port(std::string_view text, std::uint16_t& out) {
  std::uint64_t value = 0;
  if (!parse_u64(text, value)) return false;
  if (value > 65535ull) return false;
  out = static_cast<std::uint16_t>(value);
  return true;
}

bool parse_size(std::string_view text, std::size_t& out) {
  std::uint64_t value = 0;
  if (!parse_u64(text, value)) return false;
  if (value > static_cast<std::uint64_t>(SIZE_MAX)) return false;
  out = static_cast<std::size_t>(value);
  return true;
}

bool equals_ascii_upper(std::string_view text, std::string_view upper) {
  if (text.size() != upper.size()) return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    char character = text[index];
    if (character >= 'a' && character <= 'z') {
      character = static_cast<char>(character - 'a' + 'A');
    }
    if (character != upper[index]) return false;
  }
  return true;
}

bool parse_dependent(std::string_view text, DependentRef& out) {
  const std::size_t separator = text.find(':');
  if (separator == std::string_view::npos) return false;
  const std::string_view kind_text = text.substr(0, separator);
  const std::string_view id_text = text.substr(separator + 1);
  std::uint64_t id = 0;
  if (!parse_u64(id_text, id) || id == 0) return false;
  if (equals_ascii_upper(kind_text, "PORT")) {
    out = DependentRef::port(id);
  } else if (equals_ascii_upper(kind_text, "LINK")) {
    out = DependentRef::link(LinkId(id));
  } else if (equals_ascii_upper(kind_text, "PATH")) {
    out = DependentRef::path(PathId(id));
  } else if (equals_ascii_upper(kind_text, "SERVICE")) {
    out = DependentRef::service(id);
  } else {
    return false;
  }
  return out.valid();
}

// ---------------------------------------------------------------------------------------------
// SYNTHETIC fixture
// ---------------------------------------------------------------------------------------------

struct Fixture {
  TopologySnapshot topology;
  CandidateTable candidates;
  GenerationVector failed;
  SwitchKey failed_switch;
  SwitchKey newer_generation;
  SwitchKey survivor;
  SwitchKey replacement;
  DependentRef demo_dependent;
  std::size_t declared_switches = 0;
  std::size_t declared_links = 0;
  std::size_t declared_paths = 0;
  std::size_t declared_candidates = 0;
  std::size_t declared_edges = 0;
};

/// Build the synthetic instance. Input vectors are emitted in a seed-dependent order on purpose:
/// canonicalisation must remove every trace of construction order, and callers assert that by
/// comparing digests across seeds.
bool build_fixture(std::size_t path_count, std::uint64_t seed, const Limits& limits, Fixture& out,
                   std::string& error) {
  if (path_count == 0) path_count = 1;
  if (path_count > 64) {
    error = "the synthetic fixture supports at most 64 paths";
    return false;
  }

  std::mt19937_64 rng(seed == 0 ? 0x9e3779b97f4a7c15ull : seed);

  const SwitchKey failed(SwitchId(1), SwitchGeneration(1));
  const SwitchKey newer(SwitchId(1), SwitchGeneration(2));
  const SwitchKey spine_b(SwitchId(2), SwitchGeneration(1));
  const SwitchKey spine_c(SwitchId(3), SwitchGeneration(1));

  const CapabilityMask base_caps = capability_bit(Capability::Layer2) |
                                   capability_bit(Capability::Layer3) |
                                   capability_bit(Capability::Ecmp);
  const CapabilityMask rich_caps = base_caps | capability_bit(Capability::Vxlan);

  std::vector<SwitchDescriptor> switches;
  {
    SwitchDescriptor descriptor;
    descriptor.key = failed;
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = FailureDomainId(100);
    descriptor.capabilities = base_caps;
    descriptor.port_count = 24;
    descriptor.max_radix = 24;
    descriptor.capacity_score = 6;
    descriptor.label = "synthetic-leaf-a";
    switches.push_back(descriptor);

    descriptor.key = newer;
    descriptor.capacity_score = 2;
    descriptor.label = "synthetic-leaf-a-generation-2";
    switches.push_back(descriptor);

    descriptor.key = spine_b;
    descriptor.role = SwitchRole::Spine;
    descriptor.failure_domain = FailureDomainId(200);
    descriptor.port_count = 32;
    descriptor.max_radix = 32;
    descriptor.capacity_score = 64;
    descriptor.label = "synthetic-spine-b";
    switches.push_back(descriptor);

    descriptor.key = spine_c;
    descriptor.failure_domain = FailureDomainId(300);
    descriptor.capabilities = rich_caps;
    descriptor.label = "synthetic-spine-c";
    switches.push_back(descriptor);
  }

  std::vector<LinkDescriptor> links;
  {
    LinkDescriptor link;
    link.id = LinkId(1);
    link.a.sw = failed;
    link.a.index = 1;
    link.b.sw = spine_b;
    link.b.index = 1;
    link.cost = 1;
    link.bandwidth_gbps = 400;
    link.latency_ns = 900;
    links.push_back(link);

    link.id = LinkId(2);
    link.a.sw = failed;
    link.a.index = 2;
    link.b.sw = spine_c;
    link.b.index = 1;
    link.latency_ns = 950;
    links.push_back(link);

    link.id = LinkId(3);
    link.a.sw = spine_b;
    link.a.index = 2;
    link.b.sw = spine_c;
    link.b.index = 2;
    link.cost = 2;
    link.latency_ns = 800;
    links.push_back(link);
  }

  std::vector<PathDescriptor> paths;
  for (std::size_t index = 0; index < path_count; ++index) {
    const bool even = (index % 2) == 0;
    PathDescriptor path;
    path.id = PathId(100 + index);
    path.source = NodeId(1);
    path.destination = NodeId(9);
    path.hops.push_back(failed);
    path.hops.push_back(even ? spine_b : spine_c);
    path.links.push_back(even ? LinkId(1) : LinkId(2));
    path.cost = 2u + static_cast<std::uint32_t>(index % 3);
    path.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(path);
  }
  {
    // A path that does not traverse the failing generation. It proves the closure is scoped.
    PathDescriptor path;
    path.id = PathId(900);
    path.source = NodeId(2);
    path.destination = NodeId(9);
    path.hops.push_back(spine_b);
    path.hops.push_back(spine_c);
    path.links.push_back(LinkId(3));
    path.cost = 3;
    path.required_capabilities = capability_bit(Capability::Layer3);
    paths.push_back(path);
  }

  std::vector<DependencyEdge> edges;
  for (std::size_t index = 0; index < path_count; ++index) {
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::service(500 + index));
    edge.to = ClosureNode::of_dependent(DependentRef::path(PathId(100 + index)));
    edges.push_back(edge);
  }
  {
    DependencyEdge edge;
    edge.from = ClosureNode::of_dependent(DependentRef::port(700));
    edge.to = ClosureNode::of_dependent(DependentRef::link(LinkId(3)));
    edges.push_back(edge);
    edge.from = ClosureNode::of_dependent(DependentRef::port(701));
    edge.to = ClosureNode::of_dependent(DependentRef::path(PathId(900)));
    edges.push_back(edge);
  }

  const CapabilityMask l3 = capability_bit(Capability::Layer3);
  std::vector<ReconstructionCandidate> candidates;
  {
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::link(LinkId(1));
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine_b);
    candidate.cost = 1;
    candidate.capabilities = base_caps;
    candidate.evidence = EvidenceId(2001);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::link(LinkId(2));
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine_c);
    candidate.cost = 1;
    candidate.capabilities = base_caps;
    candidate.evidence = EvidenceId(2002);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);
  }
  for (std::size_t index = 0; index < path_count; ++index) {
    const bool even = (index % 2) == 0;
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::path(PathId(100 + index));
    candidate.covers_failed = failed;
    candidate.hops.push_back(even ? spine_b : spine_c);
    candidate.cost = 4u + static_cast<std::uint32_t>(index % 2);
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(2100 + index);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(500 + index);
    candidate.covers_failed = failed;
    candidate.hops.push_back(even ? spine_b : spine_c);
    candidate.cost = 3;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(2200 + index);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);
  }
  {
    // Three deliberately ineligible alternatives for the demo dependent. Each one is a distinct,
    // explicitly named reason rather than a silent omission.
    ReconstructionCandidate candidate;
    candidate.dependent = DependentRef::service(500);
    candidate.covers_failed = failed;
    candidate.hops.push_back(failed);  // reuses the failed generation
    candidate.cost = 1;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(2300);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(500);
    candidate.covers_failed = failed;
    candidate.hops.push_back(newer);  // same identity, different generation, same failure domain
    candidate.cost = 1;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(2301);
    candidate.source = EvidenceSource::SimulatedFixture;
    candidates.push_back(candidate);

    candidate = ReconstructionCandidate{};
    candidate.dependent = DependentRef::service(500);
    candidate.covers_failed = failed;
    candidate.hops.push_back(spine_b);
    candidate.cost = 2;
    candidate.capabilities = l3;
    candidate.evidence = EvidenceId(2302);
    candidate.source = EvidenceSource::TelemetryCollector;  // advisory origin is not authority
    candidates.push_back(candidate);
  }

  out.declared_switches = switches.size();
  out.declared_links = links.size();
  out.declared_paths = paths.size();
  out.declared_candidates = candidates.size();
  out.declared_edges = edges.size();

  std::shuffle(switches.begin(), switches.end(), rng);
  std::shuffle(links.begin(), links.end(), rng);
  std::shuffle(paths.begin(), paths.end(), rng);
  std::shuffle(edges.begin(), edges.end(), rng);
  std::shuffle(candidates.begin(), candidates.end(), rng);

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                              std::move(paths), std::move(edges), limits);
  if (!topology.ok()) {
    error = "synthetic topology was refused: " + topology.status().to_string();
    return false;
  }
  Result<CandidateTable> table = CandidateTable::build(std::move(candidates), limits);
  if (!table.ok()) {
    error = "synthetic candidate table was refused: " + table.status().to_string();
    return false;
  }

  out.topology = std::move(topology).value();
  out.candidates = std::move(table).value();
  out.failed_switch = failed;
  out.newer_generation = newer;
  out.survivor = spine_b;
  out.replacement = spine_c;
  out.demo_dependent = DependentRef::service(500);
  out.failed.insert(failed);
  return true;
}

std::string switches_to_string(const std::vector<SwitchKey>& keys) {
  std::string result;
  for (const auto& key : keys) {
    if (!result.empty()) result += ",";
    result += key.to_string();
  }
  return result;
}

// ---------------------------------------------------------------------------------------------
// demo
// ---------------------------------------------------------------------------------------------

std::unique_ptr<Coordinator> open_coordinator(const std::filesystem::path& durable_root,
                                              const Limits& limits, ManualClock& clock,
                                              std::string& error) {
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = Policy{};
  config.evidence_class = EvidenceClass::Synthetic;
  config.event_capacity = 4096;
  config.decision_capacity = 1024;
  if (!durable_root.empty()) {
    config.durable_root = durable_root;
    config.enable_durability = true;
  }
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  if (!opened.ok()) {
    error = opened.status().to_string();
    return nullptr;
  }
  return std::move(opened).value();
}

int run_demo(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {"seed", "paths", "durable"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }

  std::uint64_t seed = 1;
  if (command_line.has("seed") && !parse_u64(command_line.value("seed"), seed)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --seed requires an unsigned decimal value\n";
    return kExitUsage;
  }
  std::size_t path_count = 2;
  if (command_line.has("paths") && !parse_size(command_line.value("paths"), path_count)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --paths requires an unsigned decimal value\n";
    return kExitUsage;
  }
  const std::filesystem::path durable_root =
      command_line.has("durable") ? std::filesystem::path(command_line.value("durable"))
                                  : std::filesystem::path();

  const Limits limits = Limits::defaults();
  Fixture fixture;
  if (!build_fixture(path_count, seed, limits, fixture, error)) {
    return refuse("demo_fixture", Code::Invalid, error);
  }

  // Order independence is a claim, so it is asserted rather than assumed: the same instance is
  // built from a differently ordered input stream and the canonical digests must agree.
  Fixture shuffled;
  if (!build_fixture(path_count, seed ^ 0x5deece66dull, limits, shuffled, error)) {
    return refuse("demo_fixture", Code::Invalid, error);
  }
  const bool order_invariant = fixture.topology.digest() == shuffled.topology.digest() &&
                               fixture.candidates.digest() == shuffled.candidates.digest();

  std::cout << "sffctl_command=demo\n";
  std::cout << "synthetic=true\n";
  std::cout << "evidence_class=SYNTHETIC\n";
  std::cout << "seed=" << seed << "\n";
  std::cout << "fixture_switches=" << fixture.topology.switches().size() << "\n";
  std::cout << "fixture_links=" << fixture.topology.links().size() << "\n";
  std::cout << "fixture_paths=" << fixture.topology.paths().size() << "\n";
  std::cout << "fixture_dependency_edges=" << fixture.topology.dependency_edges().size() << "\n";
  std::cout << "fixture_candidates=" << fixture.candidates.size() << "\n";
  std::cout << "topology_digest=" << hex64(fixture.topology.digest()) << "\n";
  std::cout << "candidate_table_digest=" << hex64(fixture.candidates.digest()) << "\n";
  std::cout << "input_order_invariant=" << (order_invariant ? "true" : "false") << "\n";
  if (!order_invariant) {
    return refuse("demo_order", Code::Conflict,
                  "canonical digests differed between input orderings");
  }
  if (!durable_root.empty()) {
    std::cout << "durable_root=" << quoted_text(durable_root.string()) << "\n";
  }

  ManualClock clock(kClockStartNs);
  std::unique_ptr<Coordinator> coordinator = open_coordinator(durable_root, limits, clock, error);
  if (coordinator == nullptr) return refuse("demo_open", Code::Invalid, error);

  Status installed = coordinator->install_topology(fixture.topology);
  if (!installed.ok()) return refuse_status("demo_install_topology", installed);
  Status candidates = coordinator->install_candidates(fixture.candidates);
  if (!candidates.ok()) return refuse_status("demo_install_candidates", candidates);

  // --- declare the generation failed ---------------------------------------------------------
  FailureDeclaration declaration;
  declaration.subject = fixture.failed_switch;
  declaration.source = EvidenceSource::SimulatedFixture;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = kEvidenceWindowNs;
  declaration.reason = "synthetic fixture: switch generation declared unusable";

  Result<FailoverOutcome> failover = coordinator->declare_failure(declaration);
  if (!failover.ok()) return refuse_status("demo_declare_failure", failover.status());
  const FailoverOutcome outcome = failover.value();

  std::cout << "failed_switch=" << outcome.failed.to_string() << "\n";
  std::cout << "failover_outcome=" << to_string(outcome.outcome) << "\n";
  std::cout << "failure_evidence=" << outcome.failure.evidence.raw() << "\n";
  std::cout << "failure_reason=" << quoted_text(outcome.failure.reason) << "\n";

  // --- (a) bounded dependency closure --------------------------------------------------------
  std::cout << "closure_state=" << to_string(outcome.closure.state) << "\n";
  std::cout << "closure_members=" << outcome.closure.members.size() << "\n";
  std::cout << "closure_dependents=" << outcome.closure.dependents.size() << "\n";
  std::cout << "closure_edges_examined=" << outcome.closure.edges_examined << "\n";
  std::cout << "closure_omitted_frontier=" << outcome.closure.omitted_frontier << "\n";
  std::cout << "closure_roots_absent=" << outcome.closure.roots_absent << "\n";
  std::cout << "closure_truncated=" << (outcome.closure.truncated() ? "true" : "false") << "\n";
  std::cout << "closure_enumerates_every_root="
            << (outcome.closure.enumerates_every_root() ? "true" : "false") << "\n";
  std::cout << "closure_digest=" << hex64(outcome.closure.digest()) << "\n";

  // --- (b) fenced authority ------------------------------------------------------------------
  std::cout << "fence_id=" << outcome.fence.raw() << "\n";
  std::cout << "fence_scope=" << to_string(outcome.fence_scope) << "\n";
  std::cout << "fence_grants_fenced=" << outcome.grants_fenced << "\n";
  std::cout << "fence_deferred=" << (outcome.deferred ? "true" : "false") << "\n";

  std::size_t fenced_dependents = 0;
  for (const DependentRef& dependent : outcome.closure.dependents) {
    const std::vector<AuthorityGrant> grants = coordinator->authority()->grants_for(dependent);
    std::string states;
    bool any_fenced = false;
    for (const AuthorityGrant& grant : grants) {
      if (!states.empty()) states += ",";
      states += to_string(grant.state);
      if (grant.state == GrantState::Fenced) any_fenced = true;
    }
    if (states.empty()) states = "NONE";
    std::cout << "closure_dependent=" << dependent.to_string() << " grants=" << grants.size()
              << " grant_states=" << states << "\n";
    if (any_fenced) {
      fenced_dependents += 1;
      std::cout << "fenced_dependent=" << dependent.to_string() << "\n";
    }
  }
  std::cout << "fenced_dependent_count=" << fenced_dependents << "\n";

  // The failure is bound to the exact generation: the newer generation of the same switch
  // identity is not fenced, and must not be treated as the failed subject.
  std::cout << "fenced_identity_generation_1="
            << (coordinator->authority()->is_fenced(fixture.failed_switch) ? "true" : "false")
            << "\n";
  std::cout << "fenced_identity_generation_2="
            << (coordinator->authority()->is_fenced(fixture.newer_generation) ? "true" : "false")
            << "\n";
  Result<SwitchAssessment> identity_assessment = coordinator->assess_identity(SwitchId(1));
  if (identity_assessment.ok()) {
    std::cout << "assess_identity_1_subject="
              << identity_assessment.value().subject.to_string() << "\n";
    std::cout << "assess_identity_1_usable="
              << (identity_assessment.value().usable ? "true" : "false") << "\n";
  }

  // --- (c) reconstruction plan ----------------------------------------------------------------
  Result<ReconstructionPlan> proposed = coordinator->propose_plan(fixture.failed);
  if (!proposed.ok()) return refuse_status("demo_propose_plan", proposed.status());
  const ReconstructionPlan plan = proposed.value();

  Result<ValidationReport> validation = coordinator->validate_plan(plan);
  if (!validation.ok()) return refuse_status("demo_validate_plan", validation.status());

  std::cout << "plan_id=" << plan.id.raw() << "\n";
  std::cout << "plan_feasibility=" << to_string(plan.feasibility) << "\n";
  std::cout << "plan_state=" << to_string(plan.state) << "\n";
  std::cout << "plan_closure_complete=" << (plan.closure_complete ? "true" : "false") << "\n";
  std::cout << "plan_restores=" << plan.restores.size() << "\n";
  std::cout << "plan_unresolved=" << plan.unresolved.size() << "\n";
  std::cout << "plan_total_cost=" << plan.total_cost() << "\n";
  std::size_t total_hops = 0;
  for (const RestoreStep& step : plan.restores) total_hops += step.hops.size();
  std::cout << "plan_total_hops=" << total_hops << "\n";
  std::cout << "plan_digest=" << hex64(plan.compute_digest()) << "\n";
  std::cout << "plan_digest_valid=" << (plan.digest_valid() ? "true" : "false") << "\n";
  std::cout << "validation_valid=" << (validation.value().valid ? "true" : "false") << "\n";
  std::cout << "validation_checks=" << validation.value().checks_performed << "\n";
  std::cout << "validation_findings=" << validation.value().findings.size() << "\n";
  for (std::size_t index = 0; index < plan.restores.size(); ++index) {
    const RestoreStep& step = plan.restores[index];
    std::cout << "plan_step=" << (index + 1) << " dependent=" << step.dependent.to_string()
              << " replacement=" << step.replacement.to_string() << " cost=" << step.cost
              << " hops=" << step.hops.size() << "\n";
  }
  for (const UnresolvedDependent& entry : plan.unresolved) {
    std::cout << "plan_unresolved_entry=" << entry.dependent.to_string()
              << " reason=" << to_string(entry.reason) << "\n";
  }

  // The restore decision before anything was applied: no authority exists for this dependent yet,
  // so the runtime reports ordinary absence rather than a permissive default.
  Result<RestoreDecision> before_apply = coordinator->evaluate_restore(fixture.demo_dependent);
  if (!before_apply.ok()) return refuse_status("demo_restore_before_apply", before_apply.status());
  std::cout << "restore_dependent=" << fixture.demo_dependent.to_string() << "\n";
  std::cout << "restore_before_apply_outcome=" << to_string(before_apply.value().outcome) << "\n";
  std::cout << "restore_before_apply_may_restore="
            << (before_apply.value().may_restore ? "true" : "false") << "\n";

  // --- (d) apply receipt ----------------------------------------------------------------------
  Result<ApplyReceipt> applied = coordinator->apply_plan(plan);
  if (!applied.ok()) return refuse_status("demo_apply_plan", applied.status());
  const ApplyReceipt receipt = applied.value();

  std::cout << "apply_plan_id=" << receipt.plan.raw() << "\n";
  std::cout << "apply_applied=" << receipt.applied << "\n";
  std::cout << "apply_failed=" << receipt.failed << "\n";
  std::cout << "apply_verified=" << receipt.verified << "\n";
  std::cout << "apply_unverified=" << receipt.unverified << "\n";
  std::cout << "apply_complete=" << (receipt.complete ? "true" : "false") << "\n";
  std::cout << "apply_outcome=" << to_string(receipt.outcome) << "\n";
  std::cout << "apply_fully_verified=" << (receipt.fully_verified() ? "true" : "false") << "\n";
  std::cout << "acknowledgement_is_not_verified_effect=true\n";

  AttemptSeq demo_attempt;
  SwitchKey demo_replacement;
  for (const ApplyStepResult& step : receipt.steps) {
    if (step.dependent != fixture.demo_dependent) continue;
    demo_attempt = step.attempt;
    demo_replacement = step.replacement;
  }

  Result<RestoreDecision> after_apply = coordinator->evaluate_restore(fixture.demo_dependent);
  if (!after_apply.ok()) return refuse_status("demo_restore_after_apply", after_apply.status());
  std::cout << "restore_after_apply_outcome=" << to_string(after_apply.value().outcome) << "\n";
  std::cout << "restore_after_apply_may_restore="
            << (after_apply.value().may_restore ? "true" : "false") << "\n";
  std::cout << "restore_after_apply_effect_verified="
            << (after_apply.value().effect_verified ? "true" : "false") << "\n";

  // --- (e) independent verification evidence ---------------------------------------------------
  EvidenceRecord verification;
  verification.id = EvidenceId(9000);
  verification.kind = EvidenceKind::EffectVerification;
  verification.source = EvidenceSource::SimulatedFixture;
  verification.subject = demo_replacement;
  verification.observed_at_ns = clock.now_ns();
  verification.valid_for_ns = kEvidenceWindowNs;
  verification.effect_dependent = fixture.demo_dependent;
  verification.effect_plan = plan.id;
  verification.effect_attempt = demo_attempt;
  verification.detail = "synthetic independent verification of the reconstructed forwarding path";

  Status recorded = coordinator->record_effect_verification(verification);
  if (!recorded.ok()) return refuse_status("demo_record_verification", recorded);

  Result<RestoreDecision> after_verification =
      coordinator->evaluate_restore(fixture.demo_dependent);
  if (!after_verification.ok()) {
    return refuse_status("demo_restore_after_verification", after_verification.status());
  }
  std::cout << "verification_evidence=" << verification.id.raw() << "\n";
  std::cout << "verification_attempt=" << demo_attempt.raw() << "\n";
  std::cout << "restore_after_verification_outcome="
            << to_string(after_verification.value().outcome) << "\n";
  std::cout << "restore_after_verification_may_restore="
            << (after_verification.value().may_restore ? "true" : "false") << "\n";
  std::cout << "restore_after_verification_effect_verified="
            << (after_verification.value().effect_verified ? "true" : "false") << "\n";
  std::cout << "restore_transition="
            << to_string(after_apply.value().outcome) << "->"
            << to_string(after_verification.value().outcome) << "\n";
  std::cout << "blocking_generations="
            << switches_to_string(after_verification.value().blocking_generations) << "\n";

  // The dependent that was never affected must remain unaffected: the fence is scoped by the
  // dependency closure, not by switch identity or by everything in the snapshot.
  Result<AuthorityQuery> unaffected = coordinator->query_authority(DependentRef::port(700));
  if (unaffected.ok()) {
    std::cout << "unaffected_dependent=" << unaffected.value().dependent.to_string()
              << " has_authority=" << (unaffected.value().has_authority ? "true" : "false")
              << " outcome=" << to_string(unaffected.value().outcome) << "\n";
  }

  Status shutdown = coordinator->shutdown();
  if (!shutdown.ok()) return refuse_status("demo_shutdown", shutdown);
  std::cout << "durable_shutdown=" << to_string(shutdown.code()) << "\n";
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

// ---------------------------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------------------------

int run_plan(CommandLine& command_line) {
  std::string error;
  if (command_line.size() < 3) {
    print_usage(std::cerr);
    std::cerr << "sffctl: plan requires --seed N\n";
    return kExitUsage;
  }
  if (!command_line.parse(2, {"seed", "paths", "max-closure"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }
  if (!command_line.has("seed")) {
    print_usage(std::cerr);
    std::cerr << "sffctl: plan requires --seed N\n";
    return kExitUsage;
  }
  std::uint64_t seed = 0;
  if (!parse_u64(command_line.value("seed"), seed)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --seed requires an unsigned decimal value\n";
    return kExitUsage;
  }
  std::size_t path_count = 4;
  if (command_line.has("paths") && !parse_size(command_line.value("paths"), path_count)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --paths requires an unsigned decimal value\n";
    return kExitUsage;
  }
  Limits limits = Limits::defaults();
  if (command_line.has("max-closure")) {
    std::size_t max_closure = 0;
    if (!parse_size(command_line.value("max-closure"), max_closure) || max_closure == 0) {
      print_usage(std::cerr);
      std::cerr << "sffctl: --max-closure requires a positive unsigned decimal value\n";
      return kExitUsage;
    }
    limits.max_closure_nodes = max_closure;
    limits.max_closure_edges = max_closure;
  }

  // The snapshot itself is built under the default bounds: the declared closure bound is a
  // planning input, and a fixture whose own structure exceeded it could never be constructed.
  Fixture fixture;
  if (!build_fixture(path_count, seed, Limits::defaults(), fixture, error)) {
    return refuse("plan_fixture", Code::Invalid, error);
  }

  ManualClock clock(kClockStartNs);
  std::unique_ptr<Coordinator> coordinator = open_coordinator(std::filesystem::path(), limits, clock,
                                                             error);
  if (coordinator == nullptr) return refuse("plan_open", Code::Invalid, error);

  Status installed = coordinator->install_topology(fixture.topology);
  if (!installed.ok()) return refuse_status("plan_install_topology", installed);
  Status candidates = coordinator->install_candidates(fixture.candidates);
  if (!candidates.ok()) return refuse_status("plan_install_candidates", candidates);

  FailureDeclaration declaration;
  declaration.subject = fixture.failed_switch;
  declaration.source = EvidenceSource::SimulatedFixture;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = kEvidenceWindowNs;
  declaration.reason = "synthetic fixture: switch generation declared unusable";
  Result<FailoverOutcome> failover = coordinator->declare_failure(declaration);
  if (!failover.ok()) return refuse_status("plan_declare_failure", failover.status());

  std::cout << "sffctl_command=plan\n";
  std::cout << "synthetic=true\n";
  std::cout << "seed=" << seed << "\n";
  std::cout << "paths=" << path_count << "\n";
  std::cout << "max_closure_nodes=" << limits.max_closure_nodes << "\n";
  std::cout << "topology_digest=" << hex64(fixture.topology.digest()) << "\n";
  std::cout << "candidate_table_digest=" << hex64(fixture.candidates.digest()) << "\n";
  std::cout << "closure_state=" << to_string(failover.value().closure.state) << "\n";
  std::cout << "closure_truncated="
            << (failover.value().closure.truncated() ? "true" : "false") << "\n";
  std::cout << "closure_dependents=" << failover.value().closure.dependents.size() << "\n";

  Result<ReconstructionPlan> proposed = coordinator->propose_plan(fixture.failed);
  if (!proposed.ok()) return refuse_status("plan_propose", proposed.status());
  const ReconstructionPlan plan = proposed.value();

  std::size_t total_hops = 0;
  for (const RestoreStep& step : plan.restores) total_hops += step.hops.size();

  std::cout << "plan_id=" << plan.id.raw() << "\n";
  std::cout << "plan_digest=" << hex64(plan.compute_digest()) << "\n";
  std::cout << "objective_unresolved=" << plan.unresolved_count() << "\n";
  std::cout << "objective_total_cost=" << plan.total_cost() << "\n";
  std::cout << "objective_total_hops=" << total_hops << "\n";
  std::cout << "feasibility=" << to_string(plan.feasibility) << "\n";
  std::cout << "plan_state=" << to_string(plan.state) << "\n";
  std::cout << "plan_closure_complete=" << (plan.closure_complete ? "true" : "false") << "\n";
  std::cout << "plan_restores=" << plan.restores.size() << "\n";
  for (const UnresolvedDependent& entry : plan.unresolved) {
    std::cout << "plan_unresolved_entry=" << entry.dependent.to_string()
              << " reason=" << to_string(entry.reason)
              << " proven=" << (is_proven_negative(entry.reason) ? "true" : "false") << "\n";
  }

  Status shutdown = coordinator->shutdown();
  if (!shutdown.ok()) return refuse_status("plan_shutdown", shutdown);
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

// ---------------------------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------------------------

/// Decode a StreamHeader payload: format(1) reserved(2) boot_ordinal(8) pid(8) epoch(8) nonce(16).
void decode_stream_header(const std::vector<std::uint8_t>& payload, CoordinatorEpoch& epoch,
                          BootIncarnation& boot) {
  ByteReader reader(payload);
  (void)reader.u8();
  (void)reader.u16();
  const std::uint64_t boot_ordinal = reader.u64();
  const std::uint64_t process_id = reader.u64();
  const std::uint64_t epoch_raw = reader.u64();
  const std::uint64_t nonce_hi = reader.u64();
  const std::uint64_t nonce_lo = reader.u64();
  if (!reader.ok()) return;
  epoch = CoordinatorEpoch(epoch_raw);
  boot = BootIncarnation::from_parts(process_id, boot_ordinal, nonce_hi, nonce_lo);
}

int run_replay(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {"log"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }
  if (!command_line.has("log")) {
    print_usage(std::cerr);
    std::cerr << "sffctl: replay requires --log DIR\n";
    return kExitUsage;
  }
  const std::filesystem::path root(command_line.value("log"));

  std::cout << "sffctl_command=replay\n";
  std::cout << "synthetic=false\n";
  std::cout << "journal_root=" << quoted_text(root.string()) << "\n";

  // Phase 1: a scan of the journal as it exists on disk. OpenExisting refuses a missing journal
  // instead of creating an empty one, and an integrity failure on a complete record refuses the
  // open rather than being repaired or skipped.
  StoreOptions options;
  options.root = root;
  options.limits = Limits::defaults();
  options.mode = OpenMode::OpenExisting;
  options.durable_writes = true;
  Result<std::unique_ptr<DurableStore>> scanned = DurableStore::open(options);
  if (!scanned.ok()) {
    const Code code = scanned.status().code();
    if (code == Code::Corrupt || code == Code::Unsupported || code == Code::VersionMismatch) {
      std::cout << "journal_corrupt=true\n";
      std::cout << "journal_code=" << to_string(code) << "\n";
      std::cout << "journal_detail=" << quoted_text(scanned.status().message()) << "\n";
      std::cout << "sffctl_status=refused\n";
      std::cout << "exit=" << kExitCorruptJournal << "\n";
      return kExitCorruptJournal;
    }
    return refuse_status("replay_open", scanned.status());
  }

  std::unique_ptr<DurableStore> store = std::move(scanned).value();
  const ReplayReport& scan = store->open_report();
  CoordinatorEpoch previous_epoch;
  BootIncarnation previous_boot;
  std::map<std::string, std::size_t> kind_counts;
  for (const Record& record : scan.records) {
    kind_counts[to_string(record.header.kind)] += 1;
    if (record.header.kind == RecordKind::StreamHeader) {
      decode_stream_header(record.payload, previous_epoch, previous_boot);
    }
  }

  std::cout << "scan_records=" << scan.records.size() << "\n";
  std::cout << "scan_corrupt_records=" << scan.corrupt_records << "\n";
  std::cout << "scan_torn_records=" << scan.torn_records << "\n";
  std::cout << "scan_unsupported_records=" << scan.unsupported_records << "\n";
  std::cout << "scan_torn_tail=" << (scan.truncated_tail ? "true" : "false") << "\n";
  std::cout << "scan_torn_bytes_recovered=" << scan.recovered_bytes << "\n";
  std::cout << "scan_clean_previous_shutdown=" << (scan.clean_shutdown ? "true" : "false") << "\n";
  std::cout << "scan_last_sequence=" << scan.last_sequence << "\n";
  if (previous_boot.valid()) {
    std::cout << "scan_previous_epoch=" << previous_epoch.raw() << "\n";
    std::cout << "scan_previous_boot_ordinal=" << previous_boot.boot_ordinal() << "\n";
  }
  for (const auto& entry : kind_counts) {
    std::cout << "scan_record_kind_" << entry.first << "=" << entry.second << "\n";
  }
  const Status closed = store->close();
  if (!closed.ok()) return refuse_status("replay_close", closed);

  // Phase 2: the authoritative restart reconciliation, which is the coordinator's own report.
  const Limits limits = Limits::defaults();
  ManualClock clock(kClockStartNs);
  CoordinatorConfig config;
  config.limits = limits;
  config.policy = Policy{};
  config.evidence_class = EvidenceClass::Synthetic;
  config.durable_root = root;
  config.enable_durability = true;
  Result<std::unique_ptr<Coordinator>> opened = Coordinator::open(config, &clock);
  if (!opened.ok()) {
    const Code code = opened.status().code();
    if (code == Code::Corrupt || code == Code::Unsupported || code == Code::VersionMismatch) {
      std::cout << "journal_corrupt=true\n";
      std::cout << "journal_code=" << to_string(code) << "\n";
      std::cout << "journal_detail=" << quoted_text(opened.status().message()) << "\n";
      std::cout << "sffctl_status=refused\n";
      std::cout << "exit=" << kExitCorruptJournal << "\n";
      return kExitCorruptJournal;
    }
    return refuse_status("replay_restart", opened.status());
  }
  std::unique_ptr<Coordinator> coordinator = std::move(opened).value();

  Result<RestartReport> report_result = coordinator->restart_report();
  if (!report_result.ok()) return refuse_status("replay_report", report_result.status());
  const RestartReport& report = report_result.value();

  std::cout << "restart_recovered=" << (report.recovered ? "true" : "false") << "\n";
  std::cout << "restart_clean_previous_shutdown="
            << (report.clean_previous_shutdown ? "true" : "false") << "\n";
  std::cout << "restart_records_replayed=" << report.records_replayed << "\n";
  std::cout << "restart_corrupt_records=" << report.corrupt_records << "\n";
  std::cout << "restart_torn_records=" << report.torn_records << "\n";
  std::cout << "restart_torn_tail_truncated=" << (report.torn_tail_truncated ? "true" : "false")
            << "\n";
  std::cout << "restart_previous_epoch=" << report.previous_epoch.raw() << "\n";
  std::cout << "restart_current_epoch=" << report.current_epoch.raw() << "\n";
  std::cout << "restart_previous_boot_ordinal=" << report.previous_boot.boot_ordinal() << "\n";
  std::cout << "restart_current_boot_ordinal=" << report.current_boot.boot_ordinal() << "\n";
  std::cout << "restart_failures_restored=" << report.failures_restored << "\n";
  std::cout << "restart_fences_restored=" << report.fences_restored << "\n";
  std::cout << "restart_plans_restored=" << report.plans_restored << "\n";
  std::cout << "restart_grants_invalidated=" << report.grants_invalidated << "\n";
  std::cout << "restart_grants_fenced=" << report.grants_fenced << "\n";
  std::cout << "restart_sessions_invalidated=" << report.sessions_invalidated << "\n";
  std::cout << "restart_dynamic_evidence_restored="
            << (report.dynamic_evidence_restored ? "true" : "false") << "\n";
  std::cout << "restart_status=" << to_string(report.status.code()) << "\n";
  for (const std::string& note : report.notes) {
    std::cout << "restart_note=" << quoted_text(note) << "\n";
  }
  std::cout << "no_dynamic_evidence_restored="
            << (report.dynamic_evidence_restored ? "false" : "true") << "\n";

  const FailureTable* failures = coordinator->failures();
  std::cout << "restored_failure_lineage=" << (failures != nullptr ? failures->size() : 0) << "\n";
  if (failures != nullptr) {
    for (const FailureRecord& record : failures->all()) {
      std::cout << "restored_failure=" << record.subject.to_string()
                << " observed_at_ns=" << record.observed_at_ns << "\n";
    }
  }
  for (const ReconstructionPlan& plan : coordinator->plans()) {
    std::cout << "restored_plan=" << plan.id.raw() << " state=" << to_string(plan.state)
              << " restores=" << plan.restores.size()
              << " feasibility=" << to_string(plan.feasibility) << "\n";
  }
  const AuthorityRegistry* authority = coordinator->authority();
  if (authority != nullptr) {
    std::cout << "restored_fences=" << authority->fence_count() << "\n";
    std::cout << "restored_active_grants=" << authority->active_grant_count() << "\n";
    for (const FenceRecord& fence : authority->fences()) {
      std::cout << "restored_fence=" << fence.subject.to_string()
                << " scope=" << to_string(fence.scope_state)
                << " closure_members=" << fence.closure_members << "\n";
    }
  }

  Status shutdown = coordinator->shutdown();
  if (!shutdown.ok()) return refuse_status("replay_shutdown", shutdown);
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

// ---------------------------------------------------------------------------------------------
// serve / stop
// ---------------------------------------------------------------------------------------------

class ServerRuntime {
 public:
  void request_stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stop_requested_ = true;
    }
    cv_.notify_all();
  }

  void wait_for_stop() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return stop_requested_; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  bool stop_requested_ = false;
};

int run_serve(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {"port", "root"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }
  if (!command_line.has("port")) {
    print_usage(std::cerr);
    std::cerr << "sffctl: serve requires --port N (0 selects an ephemeral port)\n";
    return kExitUsage;
  }
  std::uint16_t port = 0;
  if (!parse_port(command_line.value("port"), port)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --port requires an unsigned decimal value in [0,65535]\n";
    return kExitUsage;
  }
  const std::filesystem::path durable_root =
      command_line.has("root") ? std::filesystem::path(command_line.value("root"))
                               : std::filesystem::path();

  const Limits limits = Limits::defaults();
  Fixture fixture;
  if (!build_fixture(2, 1, limits, fixture, error)) {
    return refuse("serve_fixture", Code::Invalid, error);
  }

  ManualClock clock(kClockStartNs);
  std::unique_ptr<Coordinator> coordinator = open_coordinator(durable_root, limits, clock, error);
  if (coordinator == nullptr) return refuse("serve_open", Code::Invalid, error);

  Status installed = coordinator->install_topology(fixture.topology);
  if (!installed.ok()) return refuse_status("serve_install_topology", installed);
  Status candidates = coordinator->install_candidates(fixture.candidates);
  if (!candidates.ok()) return refuse_status("serve_install_candidates", candidates);

  FailureDeclaration declaration;
  declaration.subject = fixture.failed_switch;
  declaration.source = EvidenceSource::SimulatedFixture;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = kEvidenceWindowNs;
  declaration.reason = "synthetic fixture: switch generation declared unusable";
  Result<FailoverOutcome> failover = coordinator->declare_failure(declaration);
  if (!failover.ok()) return refuse_status("serve_declare_failure", failover.status());

  ServerRuntime runtime;
  const Limits server_limits = limits;
  const bool durability_enabled = !durable_root.empty();
  const FrameServer::Handler handler =
      [&coordinator, &runtime, server_limits,
       durability_enabled](const Frame& request, Frame& response) -> Status {
    switch (request.header.type) {
      case MessageType::Hello: {
        HelloResponse hello;
        hello.format_version = kFrameFormatVersion;
        hello.max_payload = static_cast<std::uint32_t>(server_limits.max_frame_payload);
        Result<HelloRequest> decoded = decode_hello_request(request.payload);
        if (!decoded.ok()) return decoded.status();
        if (decoded.value().format_version != kFrameFormatVersion) {
          hello.outcome = Code::VersionMismatch;
        } else {
          Result<SessionRecord> session = coordinator->open_session(decoded.value().principal);
          if (!session.ok()) {
            hello.outcome = session.status().code();
          } else {
            hello.session = session.value().id;
            hello.epoch = coordinator->epoch();
            hello.boot_digest = coordinator->boot_digest();
            hello.outcome = Code::Ok;
          }
        }
        response.header.type = MessageType::HelloAck;
        response.payload = encode_hello_response(hello);
        return Status::success();
      }
      case MessageType::Goodbye: {
        // The stop path is a protocol message, never a timer: the driver shuts down promptly
        // when a peer asks it to, and it never guesses at a deadline.
        response.header.type = MessageType::Goodbye;
        response.payload.clear();
        runtime.request_stop();
        return Status::success();
      }
      default:
        break;
    }

    // Every other request must present the session, epoch and boot incarnation that are current,
    // and a request sequence that advances. Session identity alone is not authority.
    const Status authorised = coordinator->authorise(request.header.binding());
    if (!authorised.ok()) return authorised;

    switch (request.header.type) {
      case MessageType::QueryAuthority: {
        Result<AuthorityQueryRequest> decoded = decode_authority_query(request.payload);
        if (!decoded.ok()) return decoded.status();
        Result<AuthorityQuery> query = coordinator->query_authority(decoded.value().dependent);
        if (!query.ok()) return query.status();
        AuthorityQueryResponse answer;
        answer.outcome = query.value().outcome;
        answer.reason = query.value().reason;
        answer.has_authority = query.value().has_authority;
        answer.active_grants = query.value().active_grants.size();
        answer.withdrawn_grants = query.value().withdrawn_grants.size();
        answer.fenced_generations = query.value().fenced_generations.size();
        answer.digest = query.value().digest();
        response.header.type = MessageType::AuthorityResult;
        response.payload = encode_authority_response(answer);
        return Status::success();
      }
      case MessageType::QueryRestore: {
        Result<RestoreQueryRequest> decoded = decode_restore_query(request.payload);
        if (!decoded.ok()) return decoded.status();
        Result<RestoreDecision> decision = coordinator->evaluate_restore(decoded.value().dependent);
        if (!decision.ok()) return decision.status();
        RestoreQueryResponse answer;
        answer.outcome = decision.value().outcome;
        answer.reason = decision.value().reason;
        answer.may_restore = decision.value().may_restore;
        answer.effect_verified = decision.value().effect_verified;
        answer.blocking_generations = decision.value().blocking_generations.size();
        response.header.type = MessageType::RestoreResult;
        response.payload = encode_restore_response(answer);
        return Status::success();
      }
      case MessageType::SnapshotRequest: {
        SnapshotResponse snapshot;
        snapshot.outcome = Code::Ok;
        snapshot.epoch = coordinator->epoch().raw();
        snapshot.boot_ordinal = coordinator->boot().boot_ordinal();
        const TopologySnapshot* topology = coordinator->topology();
        snapshot.switches = topology != nullptr ? topology->switches().size() : 0;
        snapshot.fences = coordinator->authority()->fence_count();
        snapshot.failures = coordinator->failures()->size();
        snapshot.active_grants = coordinator->authority()->active_grant_count();
        snapshot.retained_events = coordinator->events(static_cast<std::size_t>(-1)).size();
        snapshot.durability_enabled = durability_enabled;
        response.header.type = MessageType::SnapshotResult;
        response.payload = encode_snapshot_response(snapshot);
        return Status::success();
      }
      default:
        return Status::failure(Code::Unsupported,
                               "this synthetic driver does not implement that message type");
    }
  };

  ServerOptions server_options;
  server_options.bind_address = "127.0.0.1";
  server_options.port = port;
  server_options.limits = limits;
  server_options.max_connections = 16;
  server_options.worker_threads = 2;
  server_options.accept_backlog = 16;

  Result<std::unique_ptr<FrameServer>> started = FrameServer::start(server_options, handler);
  if (!started.ok()) return refuse_status("serve_start", started.status());
  std::unique_ptr<FrameServer> server = std::move(started).value();

  std::cout << "sffctl_command=serve\n";
  std::cout << "synthetic=true\n";
  std::cout << "serve_bound_address=" << server->bound_address() << "\n";
  std::cout << "serve_port=" << server->port() << "\n";
  std::cout << "serve_ephemeral_port=" << (port == 0 ? "true" : "false") << "\n";
  std::cout << "serve_durability=" << (durability_enabled ? "true" : "false") << "\n";
  std::cout << "serve_stop_path=goodbye-frame\n";
  std::cout << "serve_ready=true\n";
  std::cout.flush();

  runtime.wait_for_stop();

  Status stopped = server->stop();
  if (!stopped.ok()) return refuse_status("serve_stop", stopped);
  std::cout << "serve_connections=" << server->connections_served() << "\n";
  std::cout << "serve_frames_processed=" << server->frames_processed() << "\n";
  std::cout << "serve_frames_rejected=" << server->frames_rejected() << "\n";
  std::cout << "serve_stopped=true\n";

  Status shutdown = coordinator->shutdown();
  if (!shutdown.ok()) return refuse_status("serve_shutdown", shutdown);
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

int run_stop(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {"port"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }
  if (!command_line.has("port")) {
    print_usage(std::cerr);
    std::cerr << "sffctl: stop requires --port N\n";
    return kExitUsage;
  }
  std::uint16_t port = 0;
  if (!parse_port(command_line.value("port"), port) || port == 0) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --port requires an unsigned decimal value in [1,65535]\n";
    return kExitUsage;
  }

  std::cout << "sffctl_command=stop\n";
  std::cout << "stop_port=" << port << "\n";

  Result<std::unique_ptr<FrameClient>> connected =
      FrameClient::connect("127.0.0.1", port, Limits::defaults());
  if (!connected.ok()) return refuse_status("stop_connect", connected.status());
  std::unique_ptr<FrameClient> client = std::move(connected).value();

  Status handshake = client->handshake("sffctl-stop");
  if (!handshake.ok()) return refuse_status("stop_handshake", handshake);

  // The stop request may be answered, or the server may close the connection while it stops.
  // Either way the request itself is what stops the server, so a lost acknowledgement is not a
  // refusal - it is reported as what it is.
  Result<Frame> reply = client->call(MessageType::Goodbye, {});
  if (reply.ok() && reply.value().header.type == MessageType::Goodbye) {
    std::cout << "stop_response=Goodbye\n";
  } else if (reply.ok()) {
    std::cout << "stop_response=" << to_string(reply.value().header.type) << "\n";
  } else {
    std::cout << "stop_response_code=" << to_string(reply.status().code()) << "\n";
  }
  std::cout << "stop_sent=true\n";
  Status closed = client->close();
  if (!closed.ok()) return refuse_status("stop_close", closed);
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

// ---------------------------------------------------------------------------------------------
// query
// ---------------------------------------------------------------------------------------------

int run_query(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {"port", "dependent"}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }
  if (!command_line.has("port") || !command_line.has("dependent")) {
    print_usage(std::cerr);
    std::cerr << "sffctl: query requires --port N and --dependent KIND:ID\n";
    return kExitUsage;
  }
  std::uint16_t port = 0;
  if (!parse_port(command_line.value("port"), port) || port == 0) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --port requires an unsigned decimal value in [1,65535]\n";
    return kExitUsage;
  }
  DependentRef dependent;
  if (!parse_dependent(command_line.value("dependent"), dependent)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: --dependent requires KIND:ID with KIND in {PORT,LINK,PATH,SERVICE}\n";
    return kExitUsage;
  }

  std::cout << "sffctl_command=query\n";
  std::cout << "query_port=" << port << "\n";
  std::cout << "query_dependent=" << dependent.to_string() << "\n";

  Result<std::unique_ptr<FrameClient>> connected =
      FrameClient::connect("127.0.0.1", port, Limits::defaults());
  if (!connected.ok()) return refuse_status("query_connect", connected.status());
  std::unique_ptr<FrameClient> client = std::move(connected).value();

  Status handshake = client->handshake("sffctl-query");
  if (!handshake.ok()) return refuse_status("query_handshake", handshake);
  std::cout << "query_session=" << client->session().raw() << "\n";
  std::cout << "query_epoch=" << client->epoch().raw() << "\n";

  AuthorityQueryRequest request;
  request.dependent = dependent;
  Result<Frame> reply =
      client->call(MessageType::QueryAuthority, encode_authority_query(request));
  if (!reply.ok()) return refuse_status("query_call", reply.status());
  const Frame& frame = reply.value();
  if (frame.header.type == MessageType::Error) {
    Result<std::pair<Code, std::string>> decoded = decode_error_payload(frame.payload);
    if (!decoded.ok()) return refuse_status("query_error_payload", decoded.status());
    return refuse("query_answered", decoded.value().first, decoded.value().second);
  }
  if (frame.header.type != MessageType::AuthorityResult) {
    return refuse("query_answered", Code::Invalid, "unexpected response message type");
  }
  Result<AuthorityQueryResponse> answer = decode_authority_response(frame.payload);
  if (!answer.ok()) return refuse_status("query_decode", answer.status());

  std::cout << "query_outcome=" << to_string(answer.value().outcome) << "\n";
  std::cout << "query_reason=" << to_string(answer.value().reason) << "\n";
  std::cout << "query_has_authority=" << (answer.value().has_authority ? "true" : "false") << "\n";
  std::cout << "query_active_grants=" << answer.value().active_grants << "\n";
  std::cout << "query_withdrawn_grants=" << answer.value().withdrawn_grants << "\n";
  std::cout << "query_fenced_generations=" << answer.value().fenced_generations << "\n";
  std::cout << "query_digest=" << hex64(answer.value().digest) << "\n";

  Status closed = client->close();
  if (!closed.ok()) return refuse_status("query_close", closed);
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

// ---------------------------------------------------------------------------------------------
// selftest
// ---------------------------------------------------------------------------------------------

struct SelfCheck {
  std::size_t checks = 0;
  std::size_t failures = 0;

  void check(bool condition, std::string_view name) {
    checks += 1;
    if (!condition) failures += 1;
    std::cout << "selftest_check=" << name << " result=" << (condition ? "PASS" : "FAIL") << "\n";
  }
};

std::filesystem::path make_scratch_root(std::string_view tag) {
  std::random_device device;
  const std::uint64_t nonce =
      (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  std::filesystem::path root = std::filesystem::temp_directory_path() /
                               ("sffctl-" + std::string(tag) + "-" + std::to_string(nonce));
  std::error_code code;
  std::filesystem::remove_all(root, code);
  return root;
}

int run_selftest(CommandLine& command_line) {
  std::string error;
  if (!command_line.parse(2, {}, error)) {
    print_usage(std::cerr);
    std::cerr << "sffctl: " << error << "\n";
    return kExitUsage;
  }

  std::cout << "sffctl_command=selftest\n";
  std::cout << "synthetic=true\n";
  SelfCheck check;

  const Limits limits = Limits::defaults();
  Fixture fixture;
  check.check(build_fixture(2, 7, limits, fixture, error), "fixture_builds");
  Fixture reordered;
  check.check(build_fixture(2, 0xabcdefull, limits, reordered, error), "fixture_builds_reordered");
  check.check(fixture.topology.digest() == reordered.topology.digest(),
              "topology_digest_is_order_independent");
  check.check(fixture.candidates.digest() == reordered.candidates.digest(),
              "candidate_digest_is_order_independent");

  // Matching identity is not matching generation.
  const SwitchKey generation_zero(fixture.failed_switch.id(), SwitchGeneration(0));
  check.check(!generation_zero.valid(), "generation_zero_is_never_valid");
  const SwitchKey other_generation = fixture.newer_generation;
  check.check(other_generation.id() == fixture.failed_switch.id() &&
                  other_generation != fixture.failed_switch,
              "identity_match_is_not_generation_match");

  // The full pipeline on a fresh in-process coordinator.
  ManualClock clock(kClockStartNs);
  std::unique_ptr<Coordinator> coordinator =
      open_coordinator(std::filesystem::path(), limits, clock, error);
  check.check(coordinator != nullptr, "coordinator_opens");
  if (coordinator == nullptr) {
    std::cout << "selftest_failures=" << check.failures << "\n";
    return kExitRefused;
  }

  check.check(coordinator->install_topology(fixture.topology).ok(), "topology_installs");
  check.check(coordinator->install_candidates(fixture.candidates).ok(), "candidates_install");

  const std::size_t grants_before = coordinator->authority()->active_grant_count();
  check.check(grants_before > 0, "topology_declaration_establishes_authority");

  FailureDeclaration declaration;
  declaration.subject = fixture.failed_switch;
  declaration.source = EvidenceSource::SimulatedFixture;
  declaration.observed_at_ns = clock.now_ns();
  declaration.valid_for_ns = kEvidenceWindowNs;
  declaration.reason = "synthetic fixture: switch generation declared unusable";

  // An advisory source may not assert a lifecycle declaration.
  FailureDeclaration advisory = declaration;
  advisory.source = EvidenceSource::TelemetryCollector;
  check.check(coordinator->declare_failure(advisory).status().code() == Code::Unauthorized,
              "advisory_observation_cannot_declare_failure");

  Result<FailoverOutcome> failover = coordinator->declare_failure(declaration);
  check.check(failover.ok(), "failure_is_declared");
  if (!failover.ok()) {
    std::cout << "selftest_failures=" << check.failures << "\n";
    return kExitRefused;
  }
  check.check(failover.value().closure.complete(), "closure_is_complete_for_the_fixture");
  check.check(failover.value().closure.dependents.size() > 0, "closure_has_dependents");
  check.check(failover.value().grants_fenced > 0, "authority_bound_to_the_generation_is_fenced");
  check.check(coordinator->authority()->is_fenced(fixture.failed_switch),
              "fence_applies_to_the_exact_generation");
  check.check(!coordinator->authority()->is_fenced(fixture.newer_generation),
              "fence_does_not_leak_to_another_generation_of_the_same_identity");

  Result<ReconstructionPlan> proposed = coordinator->propose_plan(fixture.failed);
  check.check(proposed.ok(), "plan_is_proposed");
  if (!proposed.ok()) {
    std::cout << "selftest_failures=" << check.failures << "\n";
    return kExitRefused;
  }
  const ReconstructionPlan plan = proposed.value();
  check.check(plan.feasibility == PlanFeasibility::ProvenFeasible, "plan_is_proven_feasible");
  check.check(plan.digest_valid(), "plan_digest_is_valid");
  check.check(plan.unresolved.empty(), "plan_has_no_unresolved_dependents");

  Result<ValidationReport> validated = coordinator->validate_plan(plan);
  check.check(validated.ok() && validated.value().valid, "plan_revalidates_independently");

  Result<ApplyReceipt> receipt = coordinator->apply_plan(plan);
  check.check(receipt.ok(), "plan_applies");
  if (!receipt.ok()) {
    std::cout << "selftest_failures=" << check.failures << "\n";
    return kExitRefused;
  }
  check.check(receipt.value().applied == plan.restores.size(), "every_step_was_acknowledged");
  check.check(receipt.value().verified == 0, "acknowledgement_is_not_verification");
  check.check(receipt.value().unverified == receipt.value().applied, "applied_steps_are_unverified");
  check.check(receipt.value().outcome == Code::Unverified, "apply_outcome_is_unverified");
  check.check(!receipt.value().fully_verified(), "receipt_is_not_fully_verified");

  Result<RestoreDecision> before = coordinator->evaluate_restore(fixture.demo_dependent);
  check.check(before.ok() && !before.value().may_restore,
              "restore_is_refused_before_independent_verification");
  check.check(before.ok() && before.value().outcome == Code::Unverified,
              "unverified_effect_is_an_explicit_outcome");

  AttemptSeq attempt;
  SwitchKey replacement;
  for (const ApplyStepResult& step : receipt.value().steps) {
    if (step.dependent != fixture.demo_dependent) continue;
    attempt = step.attempt;
    replacement = step.replacement;
  }
  check.check(replacement.valid() && attempt.valid(), "demo_step_carries_attempt_and_replacement");

  EvidenceRecord verification;
  verification.id = EvidenceId(9000);
  verification.kind = EvidenceKind::EffectVerification;
  verification.source = EvidenceSource::SimulatedFixture;
  verification.subject = replacement;
  verification.observed_at_ns = clock.now_ns();
  verification.valid_for_ns = kEvidenceWindowNs;
  verification.effect_dependent = fixture.demo_dependent;
  verification.effect_plan = plan.id;
  verification.effect_attempt = attempt;
  verification.detail = "synthetic independent verification";
  check.check(coordinator->record_effect_verification(verification).ok(),
              "verification_evidence_is_admitted");

  Result<RestoreDecision> after = coordinator->evaluate_restore(fixture.demo_dependent);
  check.check(after.ok() && after.value().may_restore,
              "restore_is_permitted_after_verification");
  check.check(after.ok() && after.value().effect_verified, "restore_decision_records_verified_effect");
  check.check(after.ok() && after.value().outcome == Code::Ok, "restore_outcome_is_affirmative");

  Result<AuthorityQuery> unknown_dependent =
      coordinator->query_authority(DependentRef::service(4242));
  check.check(unknown_dependent.ok() && !unknown_dependent.value().has_authority,
              "absent_authority_is_not_invented");
  check.check(unknown_dependent.ok() && unknown_dependent.value().outcome == Code::NotFound,
              "absent_authority_reports_not_found");

  check.check(coordinator->shutdown().ok(), "coordinator_shuts_down");

  // Durability: lineage survives, liveness does not.
  const std::filesystem::path scratch = make_scratch_root("selftest");
  {
    ManualClock first_clock(kClockStartNs);
    std::unique_ptr<Coordinator> first = open_coordinator(scratch, limits, first_clock, error);
    check.check(first != nullptr, "durable_coordinator_opens");
    if (first != nullptr) {
      (void)first->install_topology(fixture.topology);
      (void)first->install_candidates(fixture.candidates);
      FailureDeclaration durable_declaration = declaration;
      durable_declaration.observed_at_ns = first_clock.now_ns();
      Result<FailoverOutcome> durable_failure = first->declare_failure(durable_declaration);
      check.check(durable_failure.ok(), "durable_failure_is_committed");
      check.check(first->shutdown().ok(), "durable_coordinator_shuts_down_cleanly");
    }
    ManualClock second_clock(kClockStartNs);
    std::unique_ptr<Coordinator> second = open_coordinator(scratch, limits, second_clock, error);
    check.check(second != nullptr, "durable_coordinator_reopens");
    if (second != nullptr) {
      Result<RestartReport> report = second->restart_report();
      check.check(report.ok() && report.value().failures_restored >= 1,
                  "restart_restores_failure_lineage");
      check.check(report.ok() && report.value().fences_restored >= 1,
                  "restart_restores_fence_lineage");
      check.check(report.ok() && !report.value().dynamic_evidence_restored,
                  "restart_restores_no_dynamic_evidence");
      check.check(report.ok() && report.value().current_epoch.raw() >
                                     report.value().previous_epoch.raw(),
                  "restart_advances_the_epoch");
      check.check(second->authority()->is_fenced(fixture.failed_switch),
                  "fence_survives_the_process_boundary");
      check.check(second->authority()->active_grant_count() == 0,
                  "no_pre_restart_authority_is_active");
      check.check(second->failures()->contains(fixture.failed_switch),
                  "failure_lineage_survives_the_process_boundary");
      check.check(second->shutdown().ok(), "durable_coordinator_shuts_down_again");
    }
  }
  std::error_code removed;
  std::filesystem::remove_all(scratch, removed);
  check.check(!removed, "scratch_directory_was_removed");

  // Record integrity: a complete-looking record with a bad integrity check is never replayed.
  FailureRecord record;
  record.subject = fixture.failed_switch;
  record.evidence = EvidenceId(1);
  record.epoch = CoordinatorEpoch(1);
  record.boot = BootIncarnation::from_parts(1, 1, 2, 3);
  record.observed_at_ns = 100;
  record.recorded_at_ns = 200;
  record.reason = "synthetic";
  Record durable;
  durable.header.seq = 1;
  durable.header.kind = RecordKind::FailureCommitted;
  durable.payload = encode_failure_record(record);
  Result<std::vector<std::uint8_t>> encoded = encode_record(durable, limits);
  check.check(encoded.ok(), "record_encodes");
  if (encoded.ok()) {
    const DecodeResult whole = decode_record(encoded.value().data(), encoded.value().size(), limits);
    check.check(whole.complete(), "record_decodes");
    std::vector<std::uint8_t> corrupted = encoded.value();
    corrupted.back() = static_cast<std::uint8_t>(corrupted.back() ^ 0xffu);
    const DecodeResult damaged = decode_record(corrupted.data(), corrupted.size(), limits);
    check.check(!damaged.complete(), "corrupted_record_is_refused");
    const DecodeResult prefix = decode_record(encoded.value().data(), 4, limits);
    check.check(prefix.disposition == DecodeDisposition::TornTail,
                "genuine_prefix_is_a_torn_tail");
  }

  // The outcome taxonomy is explicit: only Ok is affirmative and no epistemic code is mapped
  // onto success.
  check.check(is_success(Code::Ok), "only_ok_is_success");
  check.check(!is_success(Code::Unknown) && !is_success(Code::Stale) &&
                  !is_success(Code::Conflict) && !is_success(Code::Invalid) &&
                  !is_success(Code::Unsupported) && !is_success(Code::Unverified),
              "epistemic_outcomes_are_never_success");
  check.check(is_fail_closed(Code::Unknown) && is_fail_closed(Code::Stale) &&
                  is_fail_closed(Code::Fenced),
              "fail_closed_covers_unknown_stale_and_fenced");
  check.check(is_indeterminate(Code::Indeterminate) && is_indeterminate(Code::SearchLimitReached),
              "indeterminate_is_not_a_negative_conclusion");

  std::cout << "selftest_checks=" << check.checks << "\n";
  std::cout << "selftest_failures=" << check.failures << "\n";
  if (check.failures != 0) {
    std::cout << "sffctl_status=refused\n";
    std::cout << "exit=" << kExitRefused << "\n";
    return kExitRefused;
  }
  std::cout << "sffctl_status=ok\n";
  std::cout << "exit=" << kExitOk << "\n";
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  CommandLine command_line(argc, argv);
  if (command_line.size() < 2) {
    print_usage(std::cerr);
    std::cerr << "sffctl: a command is required\n";
    return kExitUsage;
  }

  const std::string command = command_line.at(1);
  try {
    if (command == "demo") return run_demo(command_line);
    if (command == "replay") return run_replay(command_line);
    if (command == "plan") return run_plan(command_line);
    if (command == "serve") return run_serve(command_line);
    if (command == "query") return run_query(command_line);
    if (command == "stop") return run_stop(command_line);
    if (command == "selftest") return run_selftest(command_line);
  } catch (const std::exception& error) {
    std::cerr << "sffctl: " << error.what() << "\n";
    return kExitRefused;
  }
  print_usage(std::cerr);
  std::cerr << "sffctl: unknown command " << quoted_text(command) << "\n";
  return kExitUsage;
}
