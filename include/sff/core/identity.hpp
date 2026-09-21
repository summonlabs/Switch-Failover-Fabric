// Switch Failover Fabric - strongly typed identities and generation-qualified keys.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_IDENTITY_HPP
#define SFF_CORE_IDENTITY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Strongly typed 64-bit identifier.
///
/// Identifiers of different domains are different types: a PathId can never be passed where a
/// LinkId is expected, and no implicit conversion to or from the raw integer exists.
template <class Tag>
class StrongId {
 public:
  using value_type = std::uint64_t;
  using tag_type = Tag;

  constexpr StrongId() noexcept = default;
  explicit constexpr StrongId(std::uint64_t raw) noexcept : raw_(raw) {}

  constexpr std::uint64_t raw() const noexcept { return raw_; }
  constexpr bool valid() const noexcept { return raw_ != 0; }

  /// Monotonic successor. The maximum value has NO successor: next() returns an invalid id,
  /// which callers must treat as sequence exhaustion. Returning the maximum again would silently
  /// hand out a replayed identity, and wrapping would be worse still.
  constexpr StrongId next() const noexcept {
    return raw_ == UINT64_MAX ? StrongId() : StrongId(raw_ + 1);
  }

  friend constexpr bool operator==(StrongId a, StrongId b) noexcept { return a.raw_ == b.raw_; }
  friend constexpr bool operator!=(StrongId a, StrongId b) noexcept { return a.raw_ != b.raw_; }
  friend constexpr bool operator<(StrongId a, StrongId b) noexcept { return a.raw_ < b.raw_; }
  friend constexpr bool operator>(StrongId a, StrongId b) noexcept { return a.raw_ > b.raw_; }
  friend constexpr bool operator<=(StrongId a, StrongId b) noexcept { return a.raw_ <= b.raw_; }
  friend constexpr bool operator>=(StrongId a, StrongId b) noexcept { return a.raw_ >= b.raw_; }

 private:
  std::uint64_t raw_ = 0;
};

struct SwitchIdTag {};
struct LinkIdTag {};
struct PathIdTag {};
struct NodeIdTag {};
struct FenceIdTag {};
struct GrantIdTag {};
struct PlanIdTag {};
struct DecisionIdTag {};
struct EvidenceIdTag {};
struct SessionIdTag {};
struct AttemptTag {};
struct EpochTag {};
struct FailureDomainTag {};
struct TopologyVersionTag {};
struct SwitchGenerationTag {};
struct PathGenerationTag {};

using SwitchId = StrongId<SwitchIdTag>;
using LinkId = StrongId<LinkIdTag>;
using PathId = StrongId<PathIdTag>;
using NodeId = StrongId<NodeIdTag>;
using FenceId = StrongId<FenceIdTag>;
using GrantId = StrongId<GrantIdTag>;
using PlanId = StrongId<PlanIdTag>;
using DecisionId = StrongId<DecisionIdTag>;
using EvidenceId = StrongId<EvidenceIdTag>;
using SessionId = StrongId<SessionIdTag>;
using AttemptSeq = StrongId<AttemptTag>;
using CoordinatorEpoch = StrongId<EpochTag>;
using FailureDomainId = StrongId<FailureDomainTag>;
using TopologyVersion = StrongId<TopologyVersionTag>;

/// Generation counter for a switch configuration/incarnation.
///
/// Generation 0 is reserved and means "no generation asserted". It never matches a concrete
/// generation, so identity equality can never be mistaken for generation equality.
using SwitchGeneration = StrongId<SwitchGenerationTag>;

/// Generation-qualified switch identity.
///
/// This type - not SwitchId - is what every authority-bearing relation is keyed on. Two
/// SwitchKeys with equal id but different generation are different authority subjects.
class SFF_API SwitchKey {
 public:
  constexpr SwitchKey() noexcept = default;
  constexpr SwitchKey(SwitchId id, SwitchGeneration generation) noexcept
      : id_(id), generation_(generation) {}

  constexpr SwitchId id() const noexcept { return id_; }
  constexpr SwitchGeneration generation() const noexcept { return generation_; }

  /// A key is valid only when it carries both a switch identity and a concrete generation.
  constexpr bool valid() const noexcept { return id_.valid() && generation_.valid(); }
  constexpr bool same_identity(const SwitchKey& other) const noexcept { return id_ == other.id_; }

  std::string to_string() const;

  friend constexpr bool operator==(const SwitchKey& a, const SwitchKey& b) noexcept {
    return a.id_ == b.id_ && a.generation_ == b.generation_;
  }
  friend constexpr bool operator!=(const SwitchKey& a, const SwitchKey& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const SwitchKey& a, const SwitchKey& b) noexcept {
    if (a.id_ != b.id_) return a.id_ < b.id_;
    return a.generation_ < b.generation_;
  }
  friend constexpr bool operator>(const SwitchKey& a, const SwitchKey& b) noexcept { return b < a; }
  friend constexpr bool operator<=(const SwitchKey& a, const SwitchKey& b) noexcept { return !(b < a); }
  friend constexpr bool operator>=(const SwitchKey& a, const SwitchKey& b) noexcept { return !(a < b); }

 private:
  SwitchId id_{};
  SwitchGeneration generation_{};
};

/// Process-incarnation boundary. A new process boot always produces a distinct incarnation,
/// so authority minted before a restart can never be mistaken for authority after it.
class SFF_API BootIncarnation {
 public:
  constexpr BootIncarnation() noexcept = default;
  constexpr BootIncarnation(std::uint64_t process_id, std::uint64_t boot_ordinal,
                            std::uint64_t nonce_hi, std::uint64_t nonce_lo) noexcept
      : process_id_(process_id), boot_ordinal_(boot_ordinal), nonce_hi_(nonce_hi), nonce_lo_(nonce_lo) {}

  /// Produce a fresh incarnation for this process.
  static BootIncarnation for_current_process(std::uint64_t boot_ordinal) noexcept;

  /// Deterministic construction for tests, fixtures and durable replay.
  static constexpr BootIncarnation from_parts(std::uint64_t process_id, std::uint64_t boot_ordinal,
                                              std::uint64_t nonce_hi, std::uint64_t nonce_lo) noexcept {
    return BootIncarnation(process_id, boot_ordinal, nonce_hi, nonce_lo);
  }

  constexpr std::uint64_t process_id() const noexcept { return process_id_; }
  constexpr std::uint64_t boot_ordinal() const noexcept { return boot_ordinal_; }
  constexpr std::uint64_t nonce_hi() const noexcept { return nonce_hi_; }
  constexpr std::uint64_t nonce_lo() const noexcept { return nonce_lo_; }

  constexpr bool valid() const noexcept { return boot_ordinal_ != 0; }

  std::string to_string() const;

  friend constexpr bool operator==(const BootIncarnation& a, const BootIncarnation& b) noexcept {
    return a.process_id_ == b.process_id_ && a.boot_ordinal_ == b.boot_ordinal_ &&
           a.nonce_hi_ == b.nonce_hi_ && a.nonce_lo_ == b.nonce_lo_;
  }
  friend constexpr bool operator!=(const BootIncarnation& a, const BootIncarnation& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const BootIncarnation& a, const BootIncarnation& b) noexcept {
    if (a.boot_ordinal_ != b.boot_ordinal_) return a.boot_ordinal_ < b.boot_ordinal_;
    if (a.process_id_ != b.process_id_) return a.process_id_ < b.process_id_;
    if (a.nonce_hi_ != b.nonce_hi_) return a.nonce_hi_ < b.nonce_hi_;
    return a.nonce_lo_ < b.nonce_lo_;
  }

 private:
  std::uint64_t process_id_ = 0;
  std::uint64_t boot_ordinal_ = 0;
  std::uint64_t nonce_hi_ = 0;
  std::uint64_t nonce_lo_ = 0;
};

/// Kind of dependent resource whose forwarding authority can be invalidated by a switch failure.
enum class DependentKind : std::uint8_t {
  Unknown = 0,
  Port = 1,
  Link = 2,
  Path = 3,
  Service = 4,
};

SFF_API const char* to_string(DependentKind kind) noexcept;
SFF_API bool is_valid_dependent_kind(std::uint8_t raw) noexcept;

/// A dependent resource reference. Kinds occupy disjoint identifier spaces, so the pair is the
/// identity; the canonical order is (kind, id).
class SFF_API DependentRef {
 public:
  constexpr DependentRef() noexcept = default;
  constexpr DependentRef(DependentKind kind, std::uint64_t id) noexcept : kind_(kind), id_(id) {}

  static constexpr DependentRef port(std::uint64_t id) noexcept { return DependentRef(DependentKind::Port, id); }
  static constexpr DependentRef link(LinkId id) noexcept {
    return DependentRef(DependentKind::Link, id.raw());
  }
  static constexpr DependentRef path(PathId id) noexcept {
    return DependentRef(DependentKind::Path, id.raw());
  }
  static constexpr DependentRef service(std::uint64_t id) noexcept {
    return DependentRef(DependentKind::Service, id);
  }

  constexpr DependentKind kind() const noexcept { return kind_; }
  constexpr std::uint64_t id() const noexcept { return id_; }
  constexpr bool valid() const noexcept { return kind_ != DependentKind::Unknown && id_ != 0; }

  std::string to_string() const;

  friend constexpr bool operator==(const DependentRef& a, const DependentRef& b) noexcept {
    return a.kind_ == b.kind_ && a.id_ == b.id_;
  }
  friend constexpr bool operator!=(const DependentRef& a, const DependentRef& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const DependentRef& a, const DependentRef& b) noexcept {
    if (a.kind_ != b.kind_) return static_cast<std::uint8_t>(a.kind_) < static_cast<std::uint8_t>(b.kind_);
    return a.id_ < b.id_;
  }

 private:
  DependentKind kind_ = DependentKind::Unknown;
  std::uint64_t id_ = 0;
};

/// Lower bound of the identifier range the runtime reserves for identities it mints itself
/// (evidence records for failures it establishes, and similar internal assertions).
///
/// Caller-supplied identities must lie strictly below this base, so an external record can never
/// collide with a runtime-minted one. The boundary is enforced at every admission point.
inline constexpr std::uint64_t kRuntimeReservedIdBase = 0x8000000000000000ull;

/// Stable mixing function used for canonical digests. Not a cryptographic hash.
SFF_API std::uint64_t mix64(std::uint64_t value) noexcept;

/// Deterministic 128-bit digest accumulator (two independent FNV-1a style lanes).
struct SFF_API Digest128 {
  std::uint64_t hi = 0xcbf29ce484222325ull;
  std::uint64_t lo = 0x9e3779b97f4a7c15ull;

  void absorb_byte(std::uint8_t byte) noexcept;
  void absorb_u64(std::uint64_t value) noexcept;
  void absorb_bytes(const void* data, std::size_t size) noexcept;
  void absorb_string(std::string_view text) noexcept;
  void absorb_key(const SwitchKey& key) noexcept;
  void absorb_dependent(const DependentRef& dependent) noexcept;

  std::string to_hex() const;
};

}  // namespace sff

#endif  // SFF_CORE_IDENTITY_HPP
