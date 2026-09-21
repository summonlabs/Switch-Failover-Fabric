// Switch Failover Fabric - dependency closure over generation-qualified topologies.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SYNTHETIC ONLY. Every fixture in this file is a synthetic, deterministic construction whose
// labels begin with SYNTHETIC; nothing here is a claim about a real fabric.
//
// The product-defining computation under test: given authoritative evidence that a switch
// GENERATION has failed, which dependents must be fenced? The closure must be exact (every
// dependent, once each), order- and duplication-independent, and it must never present a short
// answer as a complete one.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "sff/model/topology.hpp"

#include "test_support.hpp"

namespace {

using sff::ClosureNode;
using sff::ClosureState;
using sff::Code;
using sff::DependencyClosure;
using sff::DependencyEdge;
using sff::DependentRef;
using sff::GenerationVector;
using sff::Limits;
using sff::LinkDescriptor;
using sff::LinkId;
using sff::NodeId;
using sff::PathDescriptor;
using sff::PathId;
using sff::PortRef;
using sff::Result;
using sff::SwitchDescriptor;
using sff::SwitchGeneration;
using sff::SwitchId;
using sff::SwitchKey;
using sff::TopologySnapshot;
using sff::TopologyVersion;

constexpr std::uint64_t kSynthSwitchId = 1;

SwitchKey key(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

sff::CapabilityMask synth_capabilities() {
  return sff::capability_bit(sff::Capability::Layer2) | sff::capability_bit(sff::Capability::Layer3) |
         sff::capability_bit(sff::Capability::Ecmp);
}

/// A synthetic switch generation. The label is descriptive only and is never used for matching.
SwitchDescriptor synth_switch(std::uint64_t id, std::uint64_t generation, const char* label) {
  SwitchDescriptor descriptor;
  descriptor.key = key(id, generation);
  descriptor.role = sff::SwitchRole::Leaf;
  descriptor.admin = sff::SwitchAdminState::Enabled;
  descriptor.failure_domain = sff::FailureDomainId(7);
  descriptor.capabilities = synth_capabilities();
  descriptor.port_count = 64;
  descriptor.max_radix = 64;
  descriptor.capacity_score = 100;
  descriptor.label = label;
  return descriptor;
}

DependentRef synth_path_dep(std::uint64_t id) { return DependentRef::path(PathId(id)); }
DependentRef synth_link_dep(std::uint64_t id) { return DependentRef::link(LinkId(id)); }
DependentRef synth_port_dep(std::uint64_t id) { return DependentRef::port(id); }
DependentRef synth_service_dep(std::uint64_t id) { return DependentRef::service(id); }

DependencyEdge depends_on(const ClosureNode& from, const ClosureNode& to) {
  DependencyEdge edge;
  edge.from = from;
  edge.to = to;
  return edge;
}

DependencyEdge dep_on_switch(const DependentRef& dependent, const SwitchKey& sw) {
  return depends_on(ClosureNode::of_dependent(dependent), ClosureNode::of_switch(sw));
}

DependencyEdge dep_on_dep(const DependentRef& from, const DependentRef& to) {
  return depends_on(ClosureNode::of_dependent(from), ClosureNode::of_dependent(to));
}

Result<TopologySnapshot> build_topology(std::vector<SwitchDescriptor> switches,
                                       std::vector<LinkDescriptor> links = {},
                                       std::vector<PathDescriptor> paths = {},
                                       std::vector<DependencyEdge> edges = {},
                                       Limits limits = Limits::defaults()) {
  return TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                                 std::move(paths), std::move(edges), limits);
}

/// Build that reports a refusal as a check failure, so a fixture defect is never mistaken for a
/// traversal defect.
TopologySnapshot must_build(Result<TopologySnapshot> result, const char* what) {
  CHECK(result.ok());
  if (!result.ok()) {
    std::printf("  fixture refused: %s -> %s\n", what, result.status().to_string().c_str());
  }
  return std::move(result).value();
}

void expect_invalid(const Result<TopologySnapshot>& result, const char* what) {
  CHECK(!result.ok());
  if (result.ok()) {
    std::printf("  expected refusal, got a snapshot: %s\n", what);
    return;
  }
  CHECK(result.status().code() == Code::Invalid);
}

bool contains_node(const std::vector<ClosureNode>& members, const ClosureNode& node) {
  return std::binary_search(members.begin(), members.end(), node);
}

bool contains_dependent(const std::vector<DependentRef>& dependents, const DependentRef& dependent) {
  return std::binary_search(dependents.begin(), dependents.end(), dependent);
}

/// Canonical order means strictly increasing, which also proves uniqueness.
bool strictly_ordered_unique(const std::vector<ClosureNode>& values) {
  for (std::size_t i = 1; i < values.size(); ++i) {
    if (!(values[i - 1] < values[i])) return false;
  }
  return true;
}

bool strictly_ordered_unique(const std::vector<DependentRef>& values) {
  for (std::size_t i = 1; i < values.size(); ++i) {
    if (!(values[i - 1] < values[i])) return false;
  }
  return true;
}

std::size_t count_node(const std::vector<ClosureNode>& values, const ClosureNode& node) {
  return static_cast<std::size_t>(std::count(values.begin(), values.end(), node));
}

GenerationVector roots_of(std::vector<SwitchKey> keys) {
  return GenerationVector::canonicalise(std::move(keys));
}

// --- fan-out ------------------------------------------------------------------------------------

SFF_TEST(closure_fan_out_enumerates_every_dependent_exactly_once) {
  const SwitchKey sw = key(kSynthSwitchId, 1);
  constexpr std::size_t kFanOut = 64;

  std::vector<DependencyEdge> edges;
  std::vector<DependentRef> expected;
  for (std::size_t i = 0; i < kFanOut; ++i) {
    const DependentRef dependent = synth_service_dep(1000 + i);
    edges.push_back(dep_on_switch(dependent, sw));
    expected.push_back(dependent);
  }

  // One path descriptor whose hop contributes a derived edge as well as an explicit one.
  PathDescriptor path;
  path.id = PathId(1);
  path.source = NodeId(1);
  path.destination = NodeId(2);
  path.hops = {sw};
  path.cost = 1;
  edges.push_back(dep_on_switch(DependentRef::path(path.id), sw));
  expected.push_back(DependentRef::path(path.id));
  std::sort(expected.begin(), expected.end());

  const TopologySnapshot snapshot =
      must_build(build_topology({synth_switch(kSynthSwitchId, 1, "SYNTHETIC-fanout")}, {}, {path}, edges),
                 "fan-out");
  CHECK_EQ(snapshot.stats().dependency_edges, std::size_t{65});
  CHECK_EQ(snapshot.stats().nodes, std::size_t{66});
  CHECK(!snapshot.empty());

  const DependencyClosure closure = snapshot.closure(roots_of({sw}), Limits::defaults());
  CHECK(closure.state == ClosureState::Complete);
  CHECK(closure.complete());
  CHECK(!closure.truncated());
  CHECK(closure.enumerates_every_root());
  CHECK_EQ(closure.roots_absent, std::size_t{0});
  CHECK_EQ(closure.members.size(), std::size_t{66});
  CHECK_EQ(closure.dependents.size(), std::size_t{65});
  CHECK_EQ(closure.edges_examined, std::size_t{65});
  CHECK(contains_node(closure.members, ClosureNode::of_switch(sw)));
  CHECK(strictly_ordered_unique(closure.members));
  CHECK(strictly_ordered_unique(closure.dependents));
  // Exact set equality: every dependent of the failed generation, once each, and nothing else.
  CHECK(closure.dependents == expected);

  const DependencyClosure repeat = snapshot.closure(roots_of({sw}), Limits::defaults());
  CHECK_EQ(repeat.digest(), closure.digest());
}

// --- fan-in -------------------------------------------------------------------------------------

SFF_TEST(closure_fan_in_union_is_exact_and_duplicate_free) {
  const SwitchKey a = key(1, 1);
  const SwitchKey b = key(1, 2);
  const SwitchKey c = key(2, 1);
  const DependentRef d1 = synth_port_dep(1);     // depends on A and B
  const DependentRef d2 = synth_link_dep(2);     // depends on B and C
  const DependentRef d3 = synth_path_dep(3);     // depends on A
  const DependentRef d4 = synth_service_dep(4);  // depends on C

  const std::vector<DependencyEdge> edges = {
      dep_on_switch(d1, a), dep_on_switch(d1, b), dep_on_switch(d2, b),
      dep_on_switch(d2, c), dep_on_switch(d3, a), dep_on_switch(d4, c),
  };
  const TopologySnapshot snapshot = must_build(
      build_topology({synth_switch(1, 1, "SYNTHETIC-fanin-a"), synth_switch(1, 2, "SYNTHETIC-fanin-b"),
                      synth_switch(2, 1, "SYNTHETIC-fanin-c")},
                     {}, {}, edges),
      "fan-in");
  CHECK_EQ(snapshot.stats().nodes, std::size_t{7});
  CHECK_EQ(snapshot.stats().dependency_edges, std::size_t{6});

  const DependencyClosure only_a = snapshot.closure(roots_of({a}), Limits::defaults());
  const DependencyClosure only_b = snapshot.closure(roots_of({b}), Limits::defaults());
  const DependencyClosure ab = snapshot.closure(roots_of({a, b}), Limits::defaults());
  const DependencyClosure abc = snapshot.closure(roots_of({c, b, a}), Limits::defaults());

  CHECK(only_a.complete());
  CHECK_EQ(only_a.dependents.size(), std::size_t{2});
  CHECK(contains_dependent(only_a.dependents, d1));
  CHECK(contains_dependent(only_a.dependents, d3));
  CHECK(!contains_dependent(only_a.dependents, d2));
  CHECK(!contains_dependent(only_a.dependents, d4));

  CHECK(only_b.complete());
  CHECK_EQ(only_b.dependents.size(), std::size_t{2});

  // The union over two failed generations is exactly the union of the two individual closures:
  // overlap is enumerated once, never twice.
  std::vector<DependentRef> unioned = only_a.dependents;
  unioned.insert(unioned.end(), only_b.dependents.begin(), only_b.dependents.end());
  std::sort(unioned.begin(), unioned.end());
  unioned.erase(std::unique(unioned.begin(), unioned.end()), unioned.end());
  CHECK(unioned == ab.dependents);
  CHECK_EQ(ab.dependents.size(), std::size_t{3});
  CHECK(strictly_ordered_unique(ab.dependents));
  CHECK_EQ(count_node(ab.members, ClosureNode::of_dependent(d1)), std::size_t{1});

  // Canonical order is (kind, id): port < link < path < service.
  const std::vector<DependentRef> expected = {d1, d2, d3, d4};
  CHECK(abc.dependents == expected);
  CHECK(abc.complete());
  CHECK_EQ(abc.members.size(), std::size_t{7});
  CHECK_EQ(abc.roots_absent, std::size_t{0});
  // Root presentation order does not change the answer.
  CHECK_EQ(abc.digest(), snapshot.closure(roots_of({a, b, c}), Limits::defaults()).digest());
}

// --- cycles -------------------------------------------------------------------------------------

SFF_TEST(closure_terminates_on_cycles_and_self_reference) {
  const SwitchKey sw = key(1, 1);
  const DependentRef p1 = synth_path_dep(1);
  const DependentRef p2 = synth_path_dep(2);
  const DependentRef p3 = synth_path_dep(3);

  // p1 and p2 depend on each other; p1 also depends on the switch; the switch depends on itself;
  // p3 depends only on itself.
  const std::vector<DependencyEdge> edges = {
      dep_on_dep(p1, p2), dep_on_dep(p2, p1), dep_on_switch(p1, sw),
      depends_on(ClosureNode::of_switch(sw), ClosureNode::of_switch(sw)), dep_on_dep(p3, p3),
  };
  const TopologySnapshot snapshot =
      must_build(build_topology({synth_switch(1, 1, "SYNTHETIC-cycle")}, {}, {}, edges), "cycle");

  const DependencyClosure closure = snapshot.closure(roots_of({sw}), Limits::defaults());
  CHECK(closure.complete());
  CHECK(!closure.truncated());
  CHECK_EQ(closure.members.size(), std::size_t{3});
  CHECK_EQ(closure.dependents.size(), std::size_t{2});
  CHECK(contains_node(closure.members, ClosureNode::of_switch(sw)));
  CHECK(contains_dependent(closure.dependents, p1));
  CHECK(contains_dependent(closure.dependents, p2));
  CHECK(!contains_dependent(closure.dependents, p3));
  CHECK(strictly_ordered_unique(closure.members));
  CHECK(strictly_ordered_unique(closure.dependents));
  // Each member appears exactly once even though the cycle revisits it.
  CHECK_EQ(count_node(closure.members, ClosureNode::of_switch(sw)), std::size_t{1});
  CHECK_EQ(count_node(closure.members, ClosureNode::of_dependent(p1)), std::size_t{1});
  CHECK_EQ(count_node(closure.members, ClosureNode::of_dependent(p2)), std::size_t{1});

  const DependencyClosure from_nodes =
      snapshot.closure_from({ClosureNode::of_switch(sw), ClosureNode::of_dependent(p3)},
                            Limits::defaults());
  CHECK_EQ(from_nodes.members.size(), std::size_t{4});
  CHECK_EQ(count_node(from_nodes.members, ClosureNode::of_dependent(p3)), std::size_t{1});
  CHECK_EQ(from_nodes.dependents.size(), std::size_t{3});

  // Direct adjacency is canonical and contains the self reference exactly once.
  const std::vector<ClosureNode> direct = snapshot.direct_dependents(ClosureNode::of_switch(sw));
  CHECK_EQ(direct.size(), std::size_t{2});
  CHECK(strictly_ordered_unique(direct));
  CHECK(contains_node(direct, ClosureNode::of_switch(sw)));
  CHECK(contains_node(direct, ClosureNode::of_dependent(p1)));
}

// --- duplication and ordering -------------------------------------------------------------------

SFF_TEST(duplicate_edges_are_counted_and_do_not_change_the_canonical_digest) {
  const SwitchKey s = key(1, 1);
  const SwitchKey t = key(2, 1);

  LinkDescriptor link;
  link.id = LinkId(1);
  link.a.sw = s;
  link.a.index = 1;
  link.b.sw = t;
  link.b.index = 1;
  link.cost = 1;
  link.bandwidth_gbps = 100;
  link.latency_ns = 10;

  PathDescriptor path;
  path.id = PathId(1);
  path.source = NodeId(1);
  path.destination = NodeId(2);
  path.hops = {s, t};
  path.links = {LinkId(1)};
  path.cost = 1;

  const std::vector<SwitchDescriptor> switches = {synth_switch(1, 1, "SYNTHETIC-dup-s"),
                                                  synth_switch(2, 1, "SYNTHETIC-dup-t")};
  std::vector<DependencyEdge> base_edges;
  for (std::size_t i = 0; i < 3; ++i) {
    base_edges.push_back(dep_on_switch(synth_service_dep(10 + i), s));
  }

  constexpr std::size_t kRepeats = 5;
  constexpr std::size_t kDerivedCopies = 3;
  std::vector<DependencyEdge> duplicated;
  for (const auto& edge : base_edges) {
    for (std::size_t repeat = 0; repeat < kRepeats; ++repeat) duplicated.push_back(edge);
  }
  // A copy of an edge the snapshot derives from the path descriptor is also a duplicate, so every
  // one of these copies is dropped rather than added.
  for (std::size_t repeat = 0; repeat < kDerivedCopies; ++repeat) {
    duplicated.push_back(dep_on_switch(DependentRef::path(path.id), s));
  }

  const TopologySnapshot noisy =
      must_build(build_topology(switches, {link}, {path}, duplicated), "duplicated edges");
  const TopologySnapshot clean =
      must_build(build_topology(switches, {link}, {path}, base_edges), "de-duplicated edges");

  CHECK(noisy.stats().duplicate_edges_dropped > 0);
  CHECK_EQ(clean.stats().duplicate_edges_dropped, std::size_t{0});
  const std::size_t expected_duplicates =
      base_edges.size() * (kRepeats - 1) + kDerivedCopies;
  CHECK_EQ(noisy.stats().duplicate_edges_dropped, expected_duplicates);
  CHECK_EQ(noisy.stats().dependency_edges, clean.stats().dependency_edges);
  CHECK(noisy.dependency_edges() == clean.dependency_edges());
  CHECK_EQ(noisy.stats().nodes, clean.stats().nodes);
  CHECK_EQ(noisy.digest(), clean.digest());

  const DependencyClosure noisy_closure = noisy.closure(roots_of({s}), Limits::defaults());
  const DependencyClosure clean_closure = clean.closure(roots_of({s}), Limits::defaults());
  CHECK_EQ(noisy_closure.digest(), clean_closure.digest());
  CHECK_EQ(noisy_closure.dependents.size(), clean_closure.dependents.size());
  CHECK(strictly_ordered_unique(clean_closure.dependents));

  // Input order is irrelevant to the canonical digest.
  std::vector<SwitchDescriptor> reversed_switches = switches;
  std::reverse(reversed_switches.begin(), reversed_switches.end());
  std::vector<DependencyEdge> reversed_edges = base_edges;
  std::reverse(reversed_edges.begin(), reversed_edges.end());
  const TopologySnapshot reversed =
      must_build(build_topology(reversed_switches, {link}, {path}, reversed_edges), "reversed order");
  CHECK_EQ(reversed.digest(), clean.digest());
  CHECK_EQ(reversed.closure(roots_of({t, s}), Limits::defaults()).digest(),
           clean.closure(roots_of({s, t}), Limits::defaults()).digest());
}

SFF_TEST(contradictory_declarations_conflict_and_identical_ones_are_counted) {
  const SwitchDescriptor base = synth_switch(3, 7, "SYNTHETIC-dup-switch");
  const SwitchDescriptor identical = synth_switch(3, 7, "SYNTHETIC-dup-switch");
  const TopologySnapshot deduplicated = must_build(
      build_topology({base, identical, identical, identical, identical}), "identical duplicates");
  CHECK_EQ(deduplicated.switches().size(), std::size_t{1});
  CHECK_EQ(deduplicated.stats().switches, std::size_t{1});
  CHECK_EQ(deduplicated.stats().duplicate_switches_dropped, std::size_t{4});

  // Same generation-qualified key, different content: the snapshot cannot pick a winner.
  const SwitchDescriptor different_label = synth_switch(3, 7, "SYNTHETIC-contradictory-label");
  const Result<TopologySnapshot> conflict_a = build_topology({base, different_label});
  CHECK(!conflict_a.ok());
  if (!conflict_a.ok()) CHECK(conflict_a.status().code() == Code::Conflict);

  SwitchDescriptor different_capacity = synth_switch(3, 7, "SYNTHETIC-dup-switch");
  different_capacity.capacity_score = 5;
  const Result<TopologySnapshot> conflict_b = build_topology({base, different_capacity});
  CHECK(!conflict_b.ok());
  if (!conflict_b.ok()) CHECK(conflict_b.status().code() == Code::Conflict);

  // The same rule applies to derived structure: one path identity, two different contents.
  PathDescriptor path_a;
  path_a.id = PathId(1);
  path_a.source = NodeId(1);
  path_a.destination = NodeId(2);
  path_a.hops = {base.key};
  path_a.cost = 1;
  PathDescriptor path_b = path_a;
  path_b.cost = 9;
  const Result<TopologySnapshot> conflict_c =
      build_topology({base, identical}, {}, {path_a, path_b});
  CHECK(!conflict_c.ok());
  if (!conflict_c.ok()) CHECK(conflict_c.status().code() == Code::Conflict);

  const TopologySnapshot path_dedup = must_build(build_topology({base}, {}, {path_a, path_a}, {}),
                                                "identical path duplicates");
  CHECK_EQ(path_dedup.paths().size(), std::size_t{1});
  CHECK_EQ(path_dedup.stats().duplicate_paths_dropped, std::size_t{1});
}

// --- structural rejection -----------------------------------------------------------------------

SFF_TEST(structurally_invalid_topologies_are_refused_as_invalid) {
  const SwitchKey s = key(1, 1);
  const SwitchKey absent = key(9, 9);  // fully qualified, but not declared in the snapshot.

  // A link naming a switch generation the snapshot does not contain.
  LinkDescriptor unknown_endpoint;
  unknown_endpoint.id = LinkId(1);
  unknown_endpoint.a.sw = absent;
  unknown_endpoint.a.index = 1;
  unknown_endpoint.b.sw = s;
  unknown_endpoint.b.index = 1;
  unknown_endpoint.cost = 1;
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {unknown_endpoint}),
                 "link with an unknown endpoint generation");

  // A link that is not fully generation-qualified, and one that is a self loop or free of cost.
  LinkDescriptor unqualified = unknown_endpoint;
  unqualified.a.sw = key(1, 0);
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {unqualified}),
                 "link with an unqualified endpoint generation");

  LinkDescriptor self_loop;
  self_loop.id = LinkId(2);
  self_loop.a.sw = s;
  self_loop.a.index = 1;
  self_loop.b.sw = s;
  self_loop.b.index = 1;
  self_loop.cost = 1;
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {self_loop}),
                 "link self loop");

  LinkDescriptor zero_cost = self_loop;
  zero_cost.a.index = 2;
  zero_cost.b.index = 3;
  zero_cost.cost = 0;
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {zero_cost}),
                 "link with zero cost");

  // A path with no hops at all.
  PathDescriptor empty_hops;
  empty_hops.id = PathId(1);
  empty_hops.source = NodeId(1);
  empty_hops.destination = NodeId(2);
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {empty_hops}),
                 "path with an empty hop list");

  // A path referencing a switch generation the snapshot does not contain.
  PathDescriptor unknown_hop;
  unknown_hop.id = PathId(2);
  unknown_hop.source = NodeId(1);
  unknown_hop.destination = NodeId(2);
  unknown_hop.hops = {s, absent};
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {unknown_hop}),
                 "path hop with an unknown generation");

  // A path referencing a link the snapshot does not contain, and an unknown path identity.
  PathDescriptor unknown_link;
  unknown_link.id = PathId(3);
  unknown_link.source = NodeId(1);
  unknown_link.destination = NodeId(2);
  unknown_link.hops = {s};
  unknown_link.links = {LinkId(77)};
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {unknown_link}),
                 "path link with an unknown identity");

  PathDescriptor no_identity;
  no_identity.source = NodeId(1);
  no_identity.destination = NodeId(2);
  no_identity.hops = {s};
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {no_identity}),
                 "path without an identity");

  // Dependency edges whose endpoints are not fully qualified.
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {},
                                {depends_on(ClosureNode{}, ClosureNode::of_switch(s))}),
                 "edge with an unqualified source");
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {},
                                {depends_on(ClosureNode::of_switch(s),
                                            ClosureNode::of_dependent(DependentRef{}))}),
                 "edge with an unqualified target");
  expect_invalid(build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {},
                                {depends_on(ClosureNode::of_switch(key(1, 0)),
                                            ClosureNode::of_switch(s))}),
                 "edge with an unqualified generation");

  // An unqualified generation (SwitchGeneration 0) is never a topology member.
  expect_invalid(build_topology({synth_switch(1, 0, "SYNTHETIC-invalid")}), "generation 0");
  SwitchDescriptor no_identity_switch = synth_switch(1, 1, "SYNTHETIC-invalid");
  no_identity_switch.key = key(0, 1);
  expect_invalid(build_topology({no_identity_switch}), "switch identity 0");
  SwitchDescriptor zero_ports = synth_switch(1, 1, "SYNTHETIC-invalid");
  zero_ports.port_count = 0;
  expect_invalid(build_topology({zero_ports}), "switch with zero ports");

  // Version 0 is not a version.
  const Result<TopologySnapshot> no_version = TopologySnapshot::build(
      TopologyVersion(0), {synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {}, {}, Limits::defaults());
  expect_invalid(no_version, "version 0");

  // Positive control: the same fixture without the offending element builds.
  const TopologySnapshot good = must_build(
      build_topology({synth_switch(1, 1, "SYNTHETIC-invalid")}, {}, {}, {dep_on_switch(synth_port_dep(1), s)}),
      "control");
  CHECK(good.find_switch(s) != nullptr);
  CHECK(good.find_switch(absent) == nullptr);
  CHECK(good.find_link(LinkId(1)) == nullptr);
  CHECK(good.find_path(PathId(1)) == nullptr);
}

// --- bounds -------------------------------------------------------------------------------------

SFF_TEST(a_bounded_closure_reports_truncation_and_never_a_short_complete_answer) {
  const SwitchKey sw = key(1, 1);
  constexpr std::size_t kDependents = 32;

  std::vector<DependencyEdge> edges;
  for (std::size_t i = 0; i < kDependents; ++i) {
    edges.push_back(dep_on_switch(synth_service_dep(100 + i), sw));
  }
  const TopologySnapshot snapshot =
      must_build(build_topology({synth_switch(1, 1, "SYNTHETIC-bound")}, {}, {}, edges), "bound");

  Limits small = Limits::defaults();
  small.max_closure_nodes = 5;
  const DependencyClosure bounded = snapshot.closure(roots_of({sw}), small);
  CHECK(bounded.truncated());
  CHECK(bounded.state == ClosureState::Truncated);
  CHECK(!bounded.complete());
  CHECK(bounded.omitted_frontier > 0);
  CHECK(bounded.members.size() <= 5);
  CHECK(bounded.dependents.size() < kDependents);
  CHECK(bounded.enumerates_every_root());
  CHECK(bounded.digest() != snapshot.closure(roots_of({sw}), Limits::defaults()).digest());

  Limits edge_bound = Limits::defaults();
  edge_bound.max_closure_edges = 3;
  const DependencyClosure edge_limited = snapshot.closure(roots_of({sw}), edge_bound);
  CHECK(edge_limited.truncated());
  CHECK(edge_limited.state != ClosureState::Complete);
  CHECK(edge_limited.edges_examined <= 3);
  CHECK(edge_limited.dependents.size() < kDependents);

  // The snapshot's own bound is a ceiling: a caller cannot widen it back out.
  Limits narrow_snapshot = Limits::defaults();
  narrow_snapshot.max_closure_nodes = 8;
  const Result<TopologySnapshot> refused = build_topology(
      {synth_switch(1, 1, "SYNTHETIC-bound")}, {}, {}, edges, narrow_snapshot);
  CHECK(!refused.ok());
  if (!refused.ok()) CHECK(refused.status().code() == Code::Exhausted);

  Limits edge_ceiling = Limits::defaults();
  edge_ceiling.max_closure_edges = 4;
  const Result<TopologySnapshot> refused_edges =
      build_topology({synth_switch(1, 1, "SYNTHETIC-bound")}, {}, {}, edges, edge_ceiling);
  CHECK(!refused_edges.ok());
  if (!refused_edges.ok()) CHECK(refused_edges.status().code() == Code::Exhausted);

  // Unbounded, the same snapshot yields the exact answer, and it says so.
  const DependencyClosure full = snapshot.closure(roots_of({sw}), Limits::defaults());
  CHECK(full.complete());
  CHECK(!full.truncated());
  CHECK_EQ(full.dependents.size(), kDependents);
  CHECK_EQ(full.members.size(), kDependents + 1);
}

SFF_TEST(absent_roots_are_reported_and_never_reported_as_ordinary_absence) {
  const SwitchKey present = key(1, 1);
  const SwitchKey absent = key(42, 3);  // fully qualified, absent from the snapshot.

  const TopologySnapshot snapshot =
      must_build(build_topology({synth_switch(1, 1, "SYNTHETIC-absent")}, {}, {},
                                {dep_on_switch(synth_service_dep(1), present),
                                 dep_on_switch(synth_service_dep(2), present)}),
                 "absent root");

  const DependencyClosure absent_root = snapshot.closure(roots_of({absent}), Limits::defaults());
  CHECK_EQ(absent_root.roots_absent, std::size_t{1});
  CHECK(!absent_root.enumerates_every_root());
  CHECK(absent_root.dependents.empty());
  // Same snapshot, a generation it does contain: genuinely no dependents exist.
  const TopologySnapshot lone =
      must_build(build_topology({synth_switch(7, 1, "SYNTHETIC-lone")}), "lone switch");
  const DependencyClosure no_dependents = lone.closure(roots_of({key(7, 1)}), Limits::defaults());
  CHECK_EQ(no_dependents.roots_absent, std::size_t{0});
  CHECK(no_dependents.enumerates_every_root());
  CHECK(no_dependents.state == ClosureState::Empty);
  CHECK(no_dependents.dependents.empty());
  // Both are "no dependents enumerated", but only one is a completeness statement.
  CHECK(no_dependents.enumerates_every_root() != absent_root.enumerates_every_root());
  CHECK(no_dependents.digest() != absent_root.digest());

  // Mixed roots: the present root is still resolved exactly, and the absence is still reported.
  const DependencyClosure mixed = snapshot.closure(roots_of({present, absent}), Limits::defaults());
  CHECK_EQ(mixed.roots_absent, std::size_t{1});
  CHECK(!mixed.enumerates_every_root());
  CHECK_EQ(mixed.dependents.size(), std::size_t{2});
  CHECK(mixed.complete());
  CHECK_EQ(count_node(mixed.members, ClosureNode::of_switch(absent)), std::size_t{1});

  // An absent root is never silently dropped: it stays visible as a member and as an omission.
  CHECK(contains_node(absent_root.members, ClosureNode::of_switch(absent)));
  CHECK_EQ(absent_root.members.size(), std::size_t{1});
}

// --- canonical order and scale ------------------------------------------------------------------

SFF_TEST(canonical_order_and_root_presentation_order_are_irrelevant) {
  const SwitchKey a = key(3, 1);
  const SwitchKey b = key(1, 1);
  const SwitchKey c = key(2, 1);
  const std::vector<DependencyEdge> edges = {
      dep_on_switch(synth_service_dep(5), a), dep_on_switch(synth_link_dep(1), a),
      dep_on_switch(synth_service_dep(6), b), dep_on_switch(synth_port_dep(2), c),
      dep_on_switch(synth_path_dep(9), c),    dep_on_dep(synth_service_dep(5), synth_path_dep(9)),
  };
  const TopologySnapshot snapshot = must_build(
      build_topology({synth_switch(3, 1, "SYNTHETIC-order-a"), synth_switch(1, 1, "SYNTHETIC-order-b"),
                      synth_switch(2, 1, "SYNTHETIC-order-c")},
                     {}, {}, edges),
      "order");

  const DependencyClosure canonical = snapshot.closure(roots_of({a, b, c}), Limits::defaults());
  CHECK(canonical.complete());
  CHECK(strictly_ordered_unique(canonical.members));
  CHECK(strictly_ordered_unique(canonical.dependents));
  CHECK(canonical.members.front().is_switch());
  CHECK(canonical.members.back().is_dependent());

  // The same root set built by insertion in a different order is the same root set.
  GenerationVector reordered;
  CHECK(reordered.insert(c));
  CHECK(reordered.insert(a));
  CHECK(!reordered.insert(c));
  CHECK(reordered.insert(b));
  CHECK(reordered == roots_of({a, b, c}));
  CHECK_EQ(snapshot.closure(reordered, Limits::defaults()).digest(), canonical.digest());

  // Raw duplicates in the supplied root sequence are canonicalised away.
  CHECK_EQ(GenerationVector::canonicalise({a, a, b, b, c, c}).size(), std::size_t{3});
  CHECK_EQ(snapshot.closure(GenerationVector::canonicalise({c, c, b, a, b}), Limits::defaults()).digest(),
           canonical.digest());

  // Two independently built but identical snapshots canonicalise to the same digest.
  const TopologySnapshot copy = must_build(
      build_topology({synth_switch(3, 1, "SYNTHETIC-order-a"), synth_switch(1, 1, "SYNTHETIC-order-b"),
                      synth_switch(2, 1, "SYNTHETIC-order-c")},
                     {}, {}, edges),
      "order copy");
  CHECK_EQ(copy.digest(), snapshot.digest());
}

SFF_TEST(scale_star_and_chain_closures_are_exact) {
  const SwitchKey star = key(1, 1);
  const SwitchKey chain = key(2, 1);
  constexpr std::size_t kScale = 4000;

  // A star: every service dependent of the first switch. A chain: p[i] depends on p[i + 1], and
  // the last path depends on the second switch, so the closure has to walk the whole chain.
  std::vector<DependencyEdge> edges;
  edges.reserve(2 * kScale);
  for (std::size_t i = 0; i < kScale; ++i) {
    edges.push_back(dep_on_switch(synth_service_dep(1 + i), star));
  }
  for (std::size_t i = 0; i < kScale; ++i) {
    if (i + 1 < kScale) {
      edges.push_back(dep_on_dep(synth_path_dep(1 + i), synth_path_dep(2 + i)));
    } else {
      edges.push_back(dep_on_switch(synth_path_dep(1 + i), chain));
    }
  }

  const TopologySnapshot snapshot = must_build(
      build_topology({synth_switch(1, 1, "SYNTHETIC-scale-star"), synth_switch(2, 1, "SYNTHETIC-scale-chain")},
                     {}, {}, edges),
      "scale");
  CHECK_EQ(snapshot.stats().nodes, 2 * kScale + 2);
  CHECK_EQ(snapshot.stats().dependency_edges, 2 * kScale);

  const DependencyClosure star_closure = snapshot.closure(roots_of({star}), Limits::defaults());
  CHECK(star_closure.complete());
  CHECK(!star_closure.truncated());
  CHECK(star_closure.enumerates_every_root());
  CHECK_EQ(star_closure.members.size(), kScale + 1);
  CHECK_EQ(star_closure.dependents.size(), kScale);
  CHECK_EQ(star_closure.edges_examined, kScale);
  CHECK(strictly_ordered_unique(star_closure.members));
  CHECK(contains_dependent(star_closure.dependents, synth_service_dep(1)));
  CHECK(contains_dependent(star_closure.dependents, synth_service_dep(kScale)));

  const DependencyClosure chain_closure = snapshot.closure(roots_of({chain}), Limits::defaults());
  CHECK(chain_closure.complete());
  CHECK_EQ(chain_closure.members.size(), kScale + 1);
  CHECK_EQ(chain_closure.dependents.size(), kScale);
  CHECK(strictly_ordered_unique(chain_closure.members));
  CHECK(contains_dependent(chain_closure.dependents, synth_path_dep(1)));
  CHECK(contains_dependent(chain_closure.dependents, synth_path_dep(kScale)));

  const DependencyClosure both = snapshot.closure(roots_of({star, chain}), Limits::defaults());
  CHECK(both.complete());
  CHECK_EQ(both.members.size(), 2 * kScale + 2);
  CHECK_EQ(both.dependents.size(), 2 * kScale);
  CHECK(strictly_ordered_unique(both.members));
  CHECK(strictly_ordered_unique(both.dependents));
}

}  // namespace

SFF_MAIN()
