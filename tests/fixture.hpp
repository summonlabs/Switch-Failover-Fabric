// Switch Failover Fabric - deterministic synthetic fixtures.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Everything produced here is SYNTHETIC. No physical switch, NIC, RDMA device or multi-node
// fabric is exercised by these fixtures, and no result derived from them may be reported as
// physical-hardware evidence.
#ifndef SFF_TESTS_FIXTURE_HPP
#define SFF_TESTS_FIXTURE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "sff/sff.hpp"

namespace sfftest {

// Test fixtures read far more clearly with the domain types unqualified.
using namespace sff;

inline SwitchId sid(std::uint64_t value) { return SwitchId(value); }
inline SwitchGeneration gen(std::uint64_t value) { return SwitchGeneration(value); }
inline SwitchKey skey(std::uint64_t id, std::uint64_t generation) {
  return SwitchKey(SwitchId(id), SwitchGeneration(generation));
}

/// Shape of the synthetic two-tier fabric.
struct FabricSpec {
  std::size_t leaves = 2;
  std::size_t spines = 2;
  std::size_t replacement_spines = 2;
  std::size_t paths_per_leaf = 4;
  std::uint32_t capacity_score = 1000;
  std::uint32_t link_cost = 1;
  std::uint32_t candidate_cost = 5;
  CapabilityMask leaf_capabilities = kAllCapabilities;
  CapabilityMask spine_capabilities = kAllCapabilities;
  std::uint64_t generation = 1;
};

/// A fully materialised synthetic instance.
struct Fabric {
  TopologySnapshot topology;
  CandidateTable candidates;
  std::vector<SwitchKey> leaf_keys;
  std::vector<SwitchKey> spine_keys;
  std::vector<SwitchKey> replacement_keys;
  std::vector<PathId> path_ids;
};

inline Result<Fabric> build_fabric(const FabricSpec& spec, const Limits& limits) {
  if (spec.spines == 0 || spec.leaves == 0 || spec.replacement_spines == 0) {
    return Status::failure(Code::Invalid, "fixture requires at least one leaf, spine and replacement");
  }
  Fabric fabric;
  std::vector<SwitchDescriptor> switches;
  std::vector<LinkDescriptor> links;
  std::vector<PathDescriptor> paths;
  std::vector<DependencyEdge> edges;
  std::vector<ReconstructionCandidate> candidates;

  const auto make_switch = [&](std::uint64_t id, FailureDomainId domain, CapabilityMask caps) {
    SwitchDescriptor descriptor;
    descriptor.key = skey(id, spec.generation);
    descriptor.role = SwitchRole::Leaf;
    descriptor.admin = SwitchAdminState::Enabled;
    descriptor.failure_domain = domain;
    descriptor.capabilities = caps;
    descriptor.port_count = 64;
    descriptor.max_radix = 64;
    descriptor.capacity_score = spec.capacity_score;
    descriptor.label = "synthetic-" + std::to_string(id);
    switches.push_back(descriptor);
    return descriptor.key;
  };

  for (std::size_t index = 0; index < spec.leaves; ++index) {
    const std::uint64_t id = 1000 + index;
    fabric.leaf_keys.push_back(make_switch(id, FailureDomainId(100 + index), spec.leaf_capabilities));
  }
  for (std::size_t index = 0; index < spec.spines; ++index) {
    const std::uint64_t id = 2000 + index;
    fabric.spine_keys.push_back(make_switch(id, FailureDomainId(200 + index), spec.spine_capabilities));
  }
  for (std::size_t index = 0; index < spec.replacement_spines; ++index) {
    const std::uint64_t id = 3000 + index;
    fabric.replacement_keys.push_back(
        make_switch(id, FailureDomainId(300 + index), spec.spine_capabilities));
  }

  LinkId next_link(1);
  for (const auto& leaf : fabric.leaf_keys) {
    for (const auto& spine : fabric.spine_keys) {
      LinkDescriptor link;
      link.id = next_link;
      next_link = next_link.next();
      link.a = PortRef{leaf, 1};
      link.b = PortRef{spine, 1};
      link.cost = spec.link_cost;
      link.bandwidth_gbps = 400;
      links.push_back(link);
    }
    for (const auto& spine : fabric.replacement_keys) {
      LinkDescriptor link;
      link.id = next_link;
      next_link = next_link.next();
      link.a = PortRef{leaf, 2};
      link.b = PortRef{spine, 1};
      link.cost = spec.link_cost;
      link.bandwidth_gbps = 400;
      links.push_back(link);
    }
  }

  LinkId candidate_link = next_link;
  PathId next_path(1);
  for (std::size_t leaf_index = 0; leaf_index < fabric.leaf_keys.size(); ++leaf_index) {
    const SwitchKey& leaf = fabric.leaf_keys[leaf_index];
    for (std::size_t path_index = 0; path_index < spec.paths_per_leaf; ++path_index) {
      const std::size_t spine_index = path_index % fabric.spine_keys.size();
      const SwitchKey& spine = fabric.spine_keys[spine_index];
      PathDescriptor path;
      path.id = next_path;
      next_path = next_path.next();
      path.source = NodeId(9000 + leaf_index);
      path.destination = NodeId(9500 + leaf_index);
      path.hops = {leaf, spine};
      path.cost = static_cast<std::uint32_t>(2 * spec.link_cost);
      path.required_capabilities = capability_bit(Capability::Layer3);
      paths.push_back(path);
      fabric.path_ids.push_back(path.id);

      const SwitchKey& replacement =
          fabric.replacement_keys[path_index % fabric.replacement_keys.size()];
      ReconstructionCandidate candidate;
      candidate.dependent = DependentRef::path(path.id);
      candidate.covers_failed = spine;
      candidate.hops = {leaf, replacement};
      LinkDescriptor alt;
      alt.id = candidate_link;
      candidate_link = candidate_link.next();
      alt.a = PortRef{leaf, 2};
      alt.b = PortRef{replacement, 1};
      alt.cost = spec.link_cost;
      links.push_back(alt);
      candidate.links = {alt.id};
      candidate.cost = spec.candidate_cost;
      candidate.capabilities = spec.spine_capabilities;
      candidate.evidence = EvidenceId(7000 + path.id.raw());
      candidate.source = EvidenceSource::SimulatedFixture;
      candidates.push_back(candidate);
    }
  }

  Result<TopologySnapshot> topology =
      TopologySnapshot::build(TopologyVersion(1), std::move(switches), std::move(links),
                              std::move(paths), std::move(edges), limits);
  if (!topology.ok()) return topology.status();
  fabric.topology = std::move(topology).value();

  Result<CandidateTable> table = CandidateTable::build(std::move(candidates), limits);
  if (!table.ok()) return table.status();
  fabric.candidates = std::move(table).value();
  return fabric;
}

/// Convenience: a candidate table with exactly one alternative per (dependent, failed generation).
inline Result<Fabric> build_fabric(const FabricSpec& spec) {
  return build_fabric(spec, Limits::defaults());
}

}  // namespace sfftest

#endif  // SFF_TESTS_FIXTURE_HPP
