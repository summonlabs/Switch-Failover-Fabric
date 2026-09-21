// Switch Failover Fabric - generation-qualified topology and bounded dependency closure.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_MODEL_TOPOLOGY_HPP
#define SFF_MODEL_TOPOLOGY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"
#include "sff/model/switch.hpp"
#include "sff/export.hpp"

namespace sff {

/// A switch port, qualified by the generation of the switch that owns it.
struct SFF_API PortRef {
  SwitchKey sw;
  std::uint32_t index = 0;

  bool valid() const noexcept { return sw.valid(); }
  std::uint64_t digest() const noexcept;

  friend bool operator==(const PortRef& a, const PortRef& b) noexcept {
    return a.sw == b.sw && a.index == b.index;
  }
  friend bool operator!=(const PortRef& a, const PortRef& b) noexcept { return !(a == b); }
  friend bool operator<(const PortRef& a, const PortRef& b) noexcept {
    if (a.sw != b.sw) return a.sw < b.sw;
    return a.index < b.index;
  }
};

/// A bidirectional link between two generation-qualified switch ports.
struct SFF_API LinkDescriptor {
  LinkId id;
  PortRef a;
  PortRef b;
  std::uint32_t cost = 1;
  std::uint32_t bandwidth_gbps = 0;
  std::uint32_t latency_ns = 0;

  bool valid() const noexcept { return id.valid() && a.valid() && b.valid(); }
  std::uint64_t digest() const noexcept;
  Status validate() const;
};

/// A forwarding path over a sequence of generation-qualified switch hops.
struct SFF_API PathDescriptor {
  PathId id;
  NodeId source;
  NodeId destination;
  std::vector<SwitchKey> hops;
  std::vector<LinkId> links;
  std::uint32_t cost = 0;
  CapabilityMask required_capabilities = 0;

  bool valid() const noexcept { return id.valid(); }
  std::uint64_t digest() const noexcept;
  Status validate() const;
};

/// A node in the dependency graph: either a generation-qualified switch or a dependent resource.
class SFF_API ClosureNode {
 public:
  enum class Kind : std::uint8_t { Switch = 0, Dependent = 1 };

  constexpr ClosureNode() noexcept = default;

  static constexpr ClosureNode of_switch(const SwitchKey& key) noexcept {
    ClosureNode node;
    node.kind_ = Kind::Switch;
    node.switch_ = key;
    return node;
  }
  static constexpr ClosureNode of_dependent(const DependentRef& dependent) noexcept {
    ClosureNode node;
    node.kind_ = Kind::Dependent;
    node.dependent_ = dependent;
    return node;
  }

  constexpr Kind kind() const noexcept { return kind_; }
  constexpr bool is_switch() const noexcept { return kind_ == Kind::Switch; }
  constexpr bool is_dependent() const noexcept { return kind_ == Kind::Dependent; }
  constexpr SwitchKey switch_key() const noexcept { return switch_; }
  constexpr DependentRef dependent() const noexcept { return dependent_; }
  constexpr bool valid() const noexcept {
    return kind_ == Kind::Switch ? switch_.valid() : dependent_.valid();
  }

  std::string to_string() const;

  friend constexpr bool operator==(const ClosureNode& a, const ClosureNode& b) noexcept {
    if (a.kind_ != b.kind_) return false;
    return a.kind_ == Kind::Switch ? a.switch_ == b.switch_ : a.dependent_ == b.dependent_;
  }
  friend constexpr bool operator!=(const ClosureNode& a, const ClosureNode& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const ClosureNode& a, const ClosureNode& b) noexcept {
    if (a.kind_ != b.kind_) return static_cast<std::uint8_t>(a.kind_) < static_cast<std::uint8_t>(b.kind_);
    if (a.kind_ == Kind::Switch) return a.switch_ < b.switch_;
    return a.dependent_ < b.dependent_;
  }

 private:
  Kind kind_ = Kind::Switch;
  SwitchKey switch_{};
  DependentRef dependent_{};
};

/// Directed dependency edge: the source node depends on the target node.
///
/// The edge direction is the one authority flows in reverse: fencing the target must
/// invalidate the source.
struct SFF_API DependencyEdge {
  ClosureNode from;
  ClosureNode to;

  friend bool operator==(const DependencyEdge& a, const DependencyEdge& b) noexcept {
    return a.from == b.from && a.to == b.to;
  }
  friend bool operator<(const DependencyEdge& a, const DependencyEdge& b) noexcept {
    if (a.from != b.from) return a.from < b.from;
    return a.to < b.to;
  }
};

/// Completeness of a dependency closure.
enum class ClosureState : std::uint8_t {
  Empty = 0,      ///< No dependents exist for the requested roots.
  Complete = 1,   ///< Every reachable dependent was enumerated.
  Truncated = 2,  ///< A declared bound stopped traversal; the closure is explicitly partial.
};

SFF_API const char* to_string(ClosureState state) noexcept;

/// The result of a bounded reverse-dependency traversal.
///
/// A truncated closure is never reported as complete: consumers must treat restoration as
/// unavailable for the affected scope and must surface the omission counts.
struct SFF_API DependencyClosure {
  GenerationVector roots;
  std::vector<ClosureNode> members;      ///< Canonical order, roots included when reached.
  std::vector<DependentRef> dependents;  ///< Canonical order, dependent members only.
  ClosureState state = ClosureState::Empty;
  std::size_t edges_examined = 0;
  std::size_t omitted_frontier = 0;      ///< Discovered but not expanded when a bound was hit.
  std::size_t omitted_edges = 0;         ///< Adjacency entries not examined when a bound was hit.
  std::size_t roots_absent = 0;          ///< Roots the snapshot does not contain at all.

  /// A closure is usable as a completeness statement only when it is Complete and every root
  /// was present in the snapshot. A root that is absent means the snapshot cannot enumerate its
  /// dependents, which is reported rather than treated as "no dependents".
  bool enumerates_every_root() const noexcept { return roots_absent == 0; }

  bool truncated() const noexcept { return state == ClosureState::Truncated; }
  bool complete() const noexcept { return state == ClosureState::Complete; }
  std::uint64_t digest() const noexcept;
};

/// Statistics recorded while canonicalising a topology. Reported so callers can see exactly
/// what was deduplicated rather than having it happen invisibly.
struct SFF_API TopologyBuildStats {
  std::size_t switches = 0;
  std::size_t links = 0;
  std::size_t paths = 0;
  std::size_t dependency_edges = 0;
  std::size_t nodes = 0;
  std::size_t duplicate_switches_dropped = 0;
  std::size_t duplicate_links_dropped = 0;
  std::size_t duplicate_paths_dropped = 0;
  std::size_t duplicate_edges_dropped = 0;
  std::size_t duplicate_hops_removed = 0;
};

/// Immutable, canonicalised topology snapshot.
///
/// Every reference inside the snapshot is generation-qualified. Construction validates
/// structure, rejects contradictory declarations of the same generation, and builds the reverse
/// dependency index once so closure computation is linear in the reachable subgraph.
class SFF_API TopologySnapshot {
 public:
  TopologySnapshot() = default;

  static Result<TopologySnapshot> build(TopologyVersion version,
                                        std::vector<SwitchDescriptor> switches,
                                        std::vector<LinkDescriptor> links,
                                        std::vector<PathDescriptor> paths,
                                        std::vector<DependencyEdge> explicit_edges,
                                        const Limits& limits);

  TopologyVersion version() const noexcept { return version_; }
  const std::vector<SwitchDescriptor>& switches() const noexcept { return switches_; }
  const std::vector<LinkDescriptor>& links() const noexcept { return links_; }
  const std::vector<PathDescriptor>& paths() const noexcept { return paths_; }
  const std::vector<DependencyEdge>& dependency_edges() const noexcept { return edges_; }
  const std::vector<ClosureNode>& nodes() const noexcept { return nodes_; }
  const TopologyBuildStats& stats() const noexcept { return stats_; }
  const Limits& limits() const noexcept { return limits_; }
  std::uint64_t digest() const noexcept { return digest_; }
  bool empty() const noexcept { return switches_.empty(); }

  /// Exact generation match. Returns nullptr when the generation is not present.
  const SwitchDescriptor* find_switch(const SwitchKey& key) const noexcept;

  /// Highest generation known for an identity. Deliberately named: this is a lookup over
  /// declared topology, not a statement that the returned generation is alive.
  const SwitchDescriptor* find_highest_generation(SwitchId id) const noexcept;

  const LinkDescriptor* find_link(LinkId id) const noexcept;
  const PathDescriptor* find_path(PathId id) const noexcept;

  /// Direct dependents of a node in canonical order.
  const std::vector<ClosureNode>& direct_dependents(const ClosureNode& node) const noexcept;

  /// Bounded transitive closure over reverse dependency edges. Cycles terminate.
  DependencyClosure closure(const GenerationVector& roots, const Limits& limits) const;

  /// Bounded transitive closure starting from explicit nodes.
  DependencyClosure closure_from(const std::vector<ClosureNode>& roots, const Limits& limits) const;

 private:
  std::size_t index_of(const ClosureNode& node) const noexcept;

  TopologyVersion version_{};
  std::vector<SwitchDescriptor> switches_;
  std::vector<LinkDescriptor> links_;
  std::vector<PathDescriptor> paths_;
  std::vector<DependencyEdge> edges_;
  std::vector<ClosureNode> nodes_;
  std::vector<std::vector<ClosureNode>> reverse_adjacency_;
  TopologyBuildStats stats_{};
  Limits limits_{};
  std::uint64_t digest_ = 0;
};

}  // namespace sff

#endif  // SFF_MODEL_TOPOLOGY_HPP
