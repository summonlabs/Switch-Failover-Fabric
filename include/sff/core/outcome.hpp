// Switch Failover Fabric - outcome codes, status values and result plumbing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_OUTCOME_HPP
#define SFF_CORE_OUTCOME_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "sff/export.hpp"

namespace sff {

/// Maximum number of bytes retained from any single human-readable message.
/// Explanations are bounded so adversarial input cannot grow retained state without limit.
inline constexpr std::size_t kMaxMessageBytes = 512;

/// Explicit outcome taxonomy.
///
/// Only Ok is an affirmative result. Every other code is a first-class, externally visible
/// outcome: Unknown is never coerced into ordinary absence, Stale is never treated as current,
/// and Indeterminate is never reported as ProvenInfeasible.
enum class Code : std::uint16_t {
  Ok = 0,

  // --- epistemic outcomes required by the boundary ---
  Unknown = 1,             ///< No sufficient basis to decide. Never affirmative.
  Stale = 2,               ///< Evidence or authority existed but is outside its validity window.
  Conflict = 3,            ///< Two or more authoritative inputs contradict each other.
  Invalid = 4,             ///< Structurally or semantically malformed input.
  Unsupported = 5,         ///< Well-formed request for a capability outside this runtime's boundary.
  Indeterminate = 6,       ///< Analysis did not terminate within bound; no conclusion either way.
  SearchLimitReached = 7,  ///< A declared bound stopped the analysis; results are partial and marked.
  ProvenInfeasible = 8,    ///< A valid certificate proves no admissible solution exists.

  // --- authority outcomes ---
  Denied = 9,              ///< Refused by policy.
  Unauthorized = 10,       ///< Caller/session lacks established authority for the operation.
  Fenced = 11,             ///< Subject is fenced by a committed fence record.
  Interrupted = 12,        ///< Work was cut short (process boundary, shutdown, restart).
  Ambiguous = 13,          ///< Durable state cannot distinguish committed from uncommitted effect.

  // --- structural outcomes ---
  NotFound = 14,
  AlreadyExists = 15,
  Exhausted = 16,          ///< A bounded resource was exhausted; refusal is deterministic.
  Busy = 17,
  Closed = 18,

  // --- durability / wire outcomes ---
  Corrupt = 19,
  Truncated = 20,
  Replay = 21,
  VersionMismatch = 22,
  IoError = 23,
  DeadlineExceeded = 24,   ///< A bounded transport/protocol budget expired. Not a test watchdog.
  Unverified = 25,         ///< Effect was applied but no verification evidence exists.
  PartialClosure = 26,     ///< Dependency closure was cut by a declared bound; never silently omitted.
  Expired = 27,            ///< A validity window elapsed; the subject is no longer current.
};

SFF_API const char* to_string(Code code) noexcept;

/// True only for the single affirmative outcome.
SFF_API bool is_success(Code code) noexcept;

/// True when the code means "no affirmative authority may be derived".
SFF_API bool is_fail_closed(Code code) noexcept;

/// True when the code expresses absence of conclusion rather than a negative conclusion.
SFF_API bool is_indeterminate(Code code) noexcept;

/// A bounded, copyable explanation of an outcome.
class SFF_API Status {
 public:
  Status() noexcept = default;

  /// Factory for the affirmative status. Named success() rather than ok() so that the static
  /// factory and the querying member function cannot collide.
  static Status success() noexcept { return Status{}; }
  static Status failure(Code code, std::string_view message = {}, std::uint32_t detail = 0);

  Code code() const noexcept { return code_; }
  std::uint32_t detail() const noexcept { return detail_; }
  const std::string& message() const noexcept { return message_; }
  bool ok() const noexcept { return code_ == Code::Ok; }
  explicit operator bool() const noexcept { return ok(); }

  /// Deterministic canonical text, bounded by kMaxMessageBytes.
  std::string to_string() const;

 private:
  Code code_ = Code::Ok;
  std::uint32_t detail_ = 0;
  std::string message_;
};

/// Result carrier. A Result never silently discards a non-Ok status.
template <class T>
class Result {
 public:
  Result(T value) : status_(), value_(std::move(value)) {}
  Result(Status status) : status_(std::move(status)) {}

  /// A failed result that still carries a value.
  ///
  /// Used where a partial result is genuinely meaningful - a replay report records what was
  /// recovered before the failure. The result is still not ok(), so a caller that only checks
  /// ok() cannot mistake a failed scan for a successful one.
  Result(Status status, T value) : status_(std::move(status)), value_(std::move(value)) {}

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Status& status() const noexcept { return status_; }

  T& value() & noexcept { return value_; }
  const T& value() const& noexcept { return value_; }
  T&& value() && noexcept { return std::move(value_); }

  T value_or(T fallback) const { return ok() ? value_ : std::move(fallback); }

 private:
  Status status_;
  T value_{};
};

template <>
class Result<void> {
 public:
  Result() = default;
  Result(Status status) : status_(std::move(status)) {}

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Status& status() const noexcept { return status_; }

 private:
  Status status_;
};

/// Truncate an untrusted string to the bounded message budget.
SFF_API std::string bounded_message(std::string_view text);

}  // namespace sff

#endif  // SFF_CORE_OUTCOME_HPP
