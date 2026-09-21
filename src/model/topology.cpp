// Switch Failover Fabric - generation-qualified topology and bounded dependency closure.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/model/topology.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>

namespace sff {
namespace {

constexpr std::size_t kMinElementBytes = 16;

template <class T>
void sort_and_dedupe(std::vector<T>& values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

void absorb_switch_key(Digest128& digest, const SwitchKey& key) noexcept {
  digest.absorb_u64(key.id().raw());
  digest.absorb_u64(key.generation().raw());
}

}  // namespace

std::uint64_t PortRef::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.port-ref.v1");
  absorb_switch_key(digest, sw);
  digest.absorb_u64(index);
  return digest.hi;
}

std::uint64_t LinkDescriptor::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.link-descriptor.v1");
  digest.absorb_u64(id.raw());
  absorb_switch_key(digest, a.sw);
  digest.absorb_u64(a.index);
  absorb_switch_key(digest, b.sw);
  digest.absorb_u64(b.index);
  digest.absorb_u64(cost);
  digest.absorb_u64(bandwidth_gbps);
  digest.absorb_u64(latency_ns);
  return digest.hi;
}

Status LinkDescriptor::validate() const {
  if (!valid()) {
    return Status::failure(Code::Invalid, "link descriptor is not fully generation-qualified");
  }
  if (a == b) {
    return Status::failure(Code::Invalid, "link descriptor is a self loop");
  }
  if (cost == 0) {
    return Status::failure(Code::Invalid, "link descriptor has a zero cost");
  }
  return Status::success();
}

std::uint64_t PathDescriptor::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.path-descriptor.v1");
  digest.absorb_u64(id.raw());
  digest.absorb_u64(source.raw());
  digest.absorb_u64(destination.raw());
  digest.absorb_u64(static_cast<std::uint64_t>(hops.size()));
  for (const auto& hop : hops) absorb_switch_key(digest, hop);
  digest.absorb_u64(static_cast<std::uint64_t>(links.size()));
  for (const auto& link : links) digest.absorb_u64(link.raw());
  digest.absorb_u64(cost);
  digest.absorb_u64(required_capabilities);
  return digest.hi;
}

Status PathDescriptor::validate() const {
  if (!id.valid()) {
    return Status::failure(Code::Invalid, "path descriptor has no identity");
  }
  if (hops.empty()) {
    return Status::failure(Code::Invalid, "path descriptor has no hops");
  }
  for (const auto& hop : hops) {
    if (!hop.valid()) {
      return Status::failure(Code::Invalid, "path descriptor has an unqualified hop generation");
    }
  }
  Status s = validate_capability_mask(required_capabilities);
  if (!s.ok()) return s;
  return Status::success();
}

std::string ClosureNode::to_string() const {
  if (kind_ == Kind::Switch) return switch_.to_string();
  return dependent_.to_string();
}

const char* to_string(ClosureState state) noexcept {
  switch (state) {
    case ClosureState::Empty: return "EMPTY";
    case ClosureState::Complete: return "COMPLETE";
    case ClosureState::Truncated: return "TRUNCATED";
  }
  return "UNRECOGNISED_CLOSURE_STATE";
}

std::uint64_t DependencyClosure::digest() const noexcept {
  Digest128 digest;
  digest.absorb_string("sff.dependency-closure.v1");
  digest.absorb_u64(roots.digest());
  digest.absorb_u64(static_cast<std::uint64_t>(members.size()));
  for (const auto& member : members) {
    digest.absorb_byte(static_cast<std::uint8_t>(member.kind()));
    if (member.is_switch()) {
      absorb_switch_key(digest, member.switch_key());
    } else {
      digest.absorb_byte(static_cast<std::uint8_t>(member.dependent().kind()));
      digest.absorb_u64(member.dependent().id());
    }
  }
  digest.absorb_byte(static_cast<std::uint8_t>(state));
  digest.absorb_u64(omitted_frontier);
  digest.absorb_u64(roots_absent);
  return digest.hi;
}

// ---------------------------------------------------------------------------------------------
// TopologySnapshot
// ---------------------------------------------------------------------------------------------

Result<TopologySnapshot> TopologySnapshot::build(TopologyVersion version,
                                                 std::vector<SwitchDescriptor> switches,
                                                 std::vector<LinkDescriptor> links,
                                                 std::vector<PathDescriptor> paths,
                                                 std::vector<DependencyEdge> explicit_edges,
                                                 const Limits& limits) {
  Status limit_status = limits.validate();
  if (!limit_status.ok()) return limit_status;
  if (!version.valid()) {
    return Status::failure(Code::Invalid, "topology version is not set");
  }
  if (switches.size() > limits.max_switches) {
    return refuse_exhausted("max_switches", switches.size(), limits.max_switches);
  }
  if (links.size() > limits.max_links) {
    return refuse_exhausted("max_links", links.size(), limits.max_links);
  }
  if (paths.size() > limits.max_paths) {
    return refuse_exhausted("max_paths", paths.size(), limits.max_paths);
  }
  if (explicit_edges.size() > limits.max_closure_edges) {
    return refuse_exhausted("max_closure_edges", explicit_edges.size(), limits.max_closure_edges);
  }

  TopologySnapshot result;
  result.version_ = version;
  result.limits_ = limits;

  // --- switches ---------------------------------------------------------------------------
  std::sort(switches.begin(), switches.end(),
            [](const SwitchDescriptor& a, const SwitchDescriptor& b) { return a.key < b.key; });
  for (const auto& descriptor : switches) {
    Status s = descriptor.validate();
    if (!s.ok()) return s;
    if (!result.switches_.empty() && result.switches_.back().key == descriptor.key) {
      if (result.switches_.back().digest() == descriptor.digest()) {
        result.stats_.duplicate_switches_dropped += 1;
        continue;
      }
      return Status::failure(Code::Conflict,
                             "contradictory declarations for the same switch generation: " +
                                 descriptor.key.to_string());
    }
    result.switches_.push_back(descriptor);
  }
  result.stats_.switches = result.switches_.size();

  const auto switch_known = [&result](const SwitchKey& key) {
    const auto position =
        std::lower_bound(result.switches_.begin(), result.switches_.end(), key,
                         [](const SwitchDescriptor& descriptor, const SwitchKey& probe) {
                           return descriptor.key < probe;
                         });
    return position != result.switches_.end() && position->key == key;
  };

  // --- links ------------------------------------------------------------------------------
  std::sort(links.begin(), links.end(),
            [](const LinkDescriptor& a, const LinkDescriptor& b) { return a.id < b.id; });
  for (const auto& descriptor : links) {
    Status s = descriptor.validate();
    if (!s.ok()) return s;
    if (!switch_known(descriptor.a.sw) || !switch_known(descriptor.b.sw)) {
      return Status::failure(Code::Invalid,
                             "link references a switch generation the snapshot does not contain");
    }
    if (!result.links_.empty() && result.links_.back().id == descriptor.id) {
      if (result.links_.back().digest() == descriptor.digest()) {
        result.stats_.duplicate_links_dropped += 1;
        continue;
      }
      return Status::failure(Code::Conflict,
                             "contradictory declarations for the same link identity");
    }
    result.links_.push_back(descriptor);
  }
  result.stats_.links = result.links_.size();

  const auto link_known = [&result](const LinkId& id) {
    const auto position =
        std::lower_bound(result.links_.begin(), result.links_.end(), id,
                         [](const LinkDescriptor& descriptor, const LinkId& probe) {
                           return descriptor.id < probe;
                         });
    return position != result.links_.end() && position->id == id;
  };

  // --- paths ------------------------------------------------------------------------------
  std::sort(paths.begin(), paths.end(),
            [](const PathDescriptor& a, const PathDescriptor& b) { return a.id < b.id; });
  for (auto& descriptor : paths) {
    Status s = descriptor.validate();
    if (!s.ok()) return s;
    const std::size_t before = descriptor.hops.size();
    sort_and_dedupe(descriptor.hops);
    result.stats_.duplicate_hops_removed += before - descriptor.hops.size();
    for (const auto& hop : descriptor.hops) {
      if (!switch_known(hop)) {
        return Status::failure(Code::Invalid,
                               "path references a switch generation the snapshot does not contain");
      }
    }
    sort_and_dedupe(descriptor.links);
    for (const auto& link : descriptor.links) {
      if (!link_known(link)) {
        return Status::failure(Code::Invalid,
                               "path references a link the snapshot does not contain");
      }
    }
    if (!result.paths_.empty() && result.paths_.back().id == descriptor.id) {
      if (result.paths_.back().digest() == descriptor.digest()) {
        result.stats_.duplicate_paths_dropped += 1;
        continue;
      }
      return Status::failure(Code::Conflict,
                             "contradictory declarations for the same path identity");
    }
    result.paths_.push_back(descriptor);
  }
  result.stats_.paths = result.paths_.size();

  // --- dependency edges -------------------------------------------------------------------
  std::vector<DependencyEdge> edges;
  edges.reserve(explicit_edges.size() + result.paths_.size() * 2 + result.links_.size() * 3);
  // Derived edges. The snapshot only derives relations it can prove from supplied structure:
  // a link depends on both of its endpoint switch generations, and a path depends on its hops
  // and its links. Port-level and service-level dependents are supplied explicitly by the caller
  // through explicit_edges, because this runtime does not own port or service discovery.
  for (const auto& link : result.links_) {
    const ClosureNode link_node = ClosureNode::of_dependent(DependentRef::link(link.id));
    edges.push_back(DependencyEdge{link_node, ClosureNode::of_switch(link.a.sw)});
    edges.push_back(DependencyEdge{link_node, ClosureNode::of_switch(link.b.sw)});
  }
  for (const auto& path : result.paths_) {
    const ClosureNode path_node = ClosureNode::of_dependent(DependentRef::path(path.id));
    for (const auto& hop : path.hops) {
      edges.push_back(DependencyEdge{path_node, ClosureNode::of_switch(hop)});
    }
    for (const auto& link : path.links) {
      edges.push_back(DependencyEdge{path_node, ClosureNode::of_dependent(DependentRef::link(link))});
    }
  }
  for (const auto& edge : explicit_edges) {
    if (!edge.from.valid() || !edge.to.valid()) {
      return Status::failure(Code::Invalid, "dependency edge endpoint is not fully qualified");
    }
    edges.push_back(edge);
  }
  const std::size_t edges_before = edges.size();
  sort_and_dedupe(edges);
  result.stats_.duplicate_edges_dropped = edges_before - edges.size();
  result.edges_ = std::move(edges);
  result.stats_.dependency_edges = result.edges_.size();

  // --- node table -------------------------------------------------------------------------
  std::vector<ClosureNode> nodes;
  nodes.reserve(result.switches_.size() + result.paths_.size() + result.links_.size() +
                result.stats_.dependency_edges * 2);
  for (const auto& descriptor : result.switches_) nodes.push_back(ClosureNode::of_switch(descriptor.key));
  for (const auto& path : result.paths_) {
    nodes.push_back(ClosureNode::of_dependent(DependentRef::path(path.id)));
  }
  for (const auto& link : result.links_) {
    nodes.push_back(ClosureNode::of_dependent(DependentRef::link(link.id)));
  }
  for (const auto& edge : result.edges_) {
    nodes.push_back(edge.from);
    nodes.push_back(edge.to);
  }
  sort_and_dedupe(nodes);
  if (nodes.size() > limits.max_closure_nodes) {
    return refuse_exhausted("max_closure_nodes", nodes.size(), limits.max_closure_nodes);
  }
  result.nodes_ = std::move(nodes);
  result.stats_.nodes = result.nodes_.size();

  // --- reverse adjacency ------------------------------------------------------------------
  result.reverse_adjacency_.assign(result.nodes_.size(), {});
  for (const auto& edge : result.edges_) {
    const auto from_index = result.index_of(edge.from);
    const auto to_index = result.index_of(edge.to);
    if (from_index == result.nodes_.size() || to_index == result.nodes_.size()) {
      return Status::failure(Code::Invalid, "dependency edge references an unknown node");
    }
    result.reverse_adjacency_[to_index].push_back(edge.from);
  }
  for (auto& adjacency : result.reverse_adjacency_) sort_and_dedupe(adjacency);

  // --- canonical digest -------------------------------------------------------------------
  Digest128 digest;
  digest.absorb_string("sff.topology.v1");
  digest.absorb_u64(version.raw());
  for (const auto& descriptor : result.switches_) digest.absorb_u64(descriptor.digest());
  for (const auto& descriptor : result.links_) digest.absorb_u64(descriptor.digest());
  for (const auto& descriptor : result.paths_) digest.absorb_u64(descriptor.digest());
  for (const auto& edge : result.edges_) {
    digest.absorb_byte(static_cast<std::uint8_t>(edge.from.kind()));
    if (edge.from.is_switch()) {
      absorb_switch_key(digest, edge.from.switch_key());
    } else {
      digest.absorb_byte(static_cast<std::uint8_t>(edge.from.dependent().kind()));
      digest.absorb_u64(edge.from.dependent().id());
    }
    digest.absorb_byte(static_cast<std::uint8_t>(edge.to.kind()));
    if (edge.to.is_switch()) {
      absorb_switch_key(digest, edge.to.switch_key());
    } else {
      digest.absorb_byte(static_cast<std::uint8_t>(edge.to.dependent().kind()));
      digest.absorb_u64(edge.to.dependent().id());
    }
  }
  result.digest_ = digest.hi;
  return result;
}

std::size_t TopologySnapshot::index_of(const ClosureNode& node) const noexcept {
  const auto position = std::lower_bound(nodes_.begin(), nodes_.end(), node);
  if (position == nodes_.end() || *position != node) return nodes_.size();
  return static_cast<std::size_t>(position - nodes_.begin());
}

const SwitchDescriptor* TopologySnapshot::find_switch(const SwitchKey& key) const noexcept {
  const auto position =
      std::lower_bound(switches_.begin(), switches_.end(), key,
                       [](const SwitchDescriptor& descriptor, const SwitchKey& probe) {
                         return descriptor.key < probe;
                       });
  if (position == switches_.end() || position->key != key) return nullptr;
  return &(*position);
}

const SwitchDescriptor* TopologySnapshot::find_highest_generation(SwitchId id) const noexcept {
  if (!id.valid()) return nullptr;
  const SwitchKey probe(id, SwitchGeneration(1));
  auto position = std::lower_bound(
      switches_.begin(), switches_.end(), probe,
      [](const SwitchDescriptor& descriptor, const SwitchKey& key) { return descriptor.key < key; });
  const SwitchDescriptor* best = nullptr;
  while (position != switches_.end() && position->key.id() == id) {
    best = &(*position);
    ++position;
  }
  return best;
}

const LinkDescriptor* TopologySnapshot::find_link(LinkId id) const noexcept {
  const auto position = std::lower_bound(links_.begin(), links_.end(), id,
                                         [](const LinkDescriptor& descriptor, const LinkId& probe) {
                                           return descriptor.id < probe;
                                         });
  if (position == links_.end() || position->id != id) return nullptr;
  return &(*position);
}

const PathDescriptor* TopologySnapshot::find_path(PathId id) const noexcept {
  const auto position = std::lower_bound(paths_.begin(), paths_.end(), id,
                                         [](const PathDescriptor& descriptor, const PathId& probe) {
                                           return descriptor.id < probe;
                                         });
  if (position == paths_.end() || position->id != id) return nullptr;
  return &(*position);
}

const std::vector<ClosureNode>& TopologySnapshot::direct_dependents(
    const ClosureNode& node) const noexcept {
  static const std::vector<ClosureNode> kEmpty;
  const std::size_t index = index_of(node);
  if (index == nodes_.size()) return kEmpty;
  return reverse_adjacency_[index];
}

DependencyClosure TopologySnapshot::closure(const GenerationVector& roots,
                                            const Limits& limits) const {
  std::vector<ClosureNode> seed;
  seed.reserve(roots.size());
  for (const auto& key : roots.keys()) seed.push_back(ClosureNode::of_switch(key));
  DependencyClosure result = closure_from(seed, limits);
  result.roots = roots;
  return result;
}

DependencyClosure TopologySnapshot::closure_from(const std::vector<ClosureNode>& roots,
                                                 const Limits& limits) const {
  DependencyClosure result;
  const std::size_t node_budget = std::min(limits.max_closure_nodes, limits_.max_closure_nodes);
  const std::size_t edge_budget = std::min(limits.max_closure_edges, limits_.max_closure_edges);

  std::vector<ClosureNode> unique_roots = roots;
  sort_and_dedupe(unique_roots);

  std::vector<std::uint8_t> visited(nodes_.size(), 0);
  std::vector<std::size_t> queue;
  queue.reserve(std::min(node_budget, nodes_.size()));

  for (const auto& root : unique_roots) {
    const std::size_t index = index_of(root);
    if (index == nodes_.size()) {
      result.roots_absent += 1;
      result.members.push_back(root);
      continue;
    }
    if (visited[index] != 0) continue;
    visited[index] = 1;
    result.members.push_back(root);
    queue.push_back(index);
  }

  std::size_t head = 0;
  bool truncated = false;
  while (head < queue.size()) {
    if (result.members.size() >= node_budget) {
      truncated = true;
      break;
    }
    if (result.edges_examined >= edge_budget) {
      truncated = true;
      break;
    }
    const std::size_t index = queue[head];
    ++head;
    for (const auto& dependent : reverse_adjacency_[index]) {
      if (result.edges_examined >= edge_budget) {
        truncated = true;
        break;
      }
      result.edges_examined += 1;
      const std::size_t dependent_index = index_of(dependent);
      if (dependent_index == nodes_.size()) continue;
      if (visited[dependent_index] != 0) continue;
      if (result.members.size() >= node_budget) {
        truncated = true;
        break;
      }
      visited[dependent_index] = 1;
      result.members.push_back(dependent);
      queue.push_back(dependent_index);
    }
    if (truncated) break;
  }

  if (truncated) {
    result.state = ClosureState::Truncated;
    // Report exactly how much was discovered but not expanded. Nodes behind the frontier were
    // never discovered at all, which is why the frontier count is the honest lower bound.
    for (std::size_t index = head; index < queue.size(); ++index) {
      result.omitted_frontier += 1;
      result.omitted_edges += reverse_adjacency_[queue[index]].size();
    }
  }

  sort_and_dedupe(result.members);
  for (const auto& member : result.members) {
    if (member.is_dependent()) result.dependents.push_back(member.dependent());
  }
  sort_and_dedupe(result.dependents);

  if (result.state != ClosureState::Truncated) {
    result.state = result.dependents.empty() ? ClosureState::Empty : ClosureState::Complete;
  }
  return result;
}

}  // namespace sff
