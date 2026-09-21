// Switch Failover Fabric - checked arithmetic.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CORE_CHECKED_HPP
#define SFF_CORE_CHECKED_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace sff {

/// Saturating-free checked addition. Returns nullopt on overflow or underflow.
template <class T>
constexpr std::optional<T> checked_add(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "checked_add requires an integral type");
  if constexpr (std::is_unsigned_v<T>) {
    if (b > static_cast<T>(std::numeric_limits<T>::max() - a)) return std::nullopt;
  } else {
    if (b > 0 && a > static_cast<T>(std::numeric_limits<T>::max() - b)) return std::nullopt;
    if (b < 0 && a < static_cast<T>(std::numeric_limits<T>::min() - b)) return std::nullopt;
  }
  return static_cast<T>(a + b);
}

/// Checked subtraction. Returns nullopt on overflow or underflow.
template <class T>
constexpr std::optional<T> checked_sub(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "checked_sub requires an integral type");
  if constexpr (std::is_unsigned_v<T>) {
    if (b > a) return std::nullopt;
  } else {
    if (b < 0 && a > static_cast<T>(std::numeric_limits<T>::max() + b)) return std::nullopt;
    if (b > 0 && a < static_cast<T>(std::numeric_limits<T>::min() + b)) return std::nullopt;
  }
  return static_cast<T>(a - b);
}

/// Checked multiplication. Returns nullopt on overflow.
template <class T>
constexpr std::optional<T> checked_mul(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "checked_mul requires an integral type");
  if (a == 0 || b == 0) return static_cast<T>(0);
  if constexpr (std::is_unsigned_v<T>) {
    if (a > static_cast<T>(std::numeric_limits<T>::max() / b)) return std::nullopt;
  } else {
    constexpr T kMax = std::numeric_limits<T>::max();
    constexpr T kMin = std::numeric_limits<T>::min();
    if (a > 0) {
      if (b > 0) {
        if (a > kMax / b) return std::nullopt;
      } else {
        if (b < kMin / a) return std::nullopt;
      }
    } else {
      if (b > 0) {
        if (a < kMin / b) return std::nullopt;
      } else {
        if (a < kMax / b) return std::nullopt;
      }
    }
  }
  return static_cast<T>(a * b);
}

/// Round a size up to a multiple of an alignment, refusing overflow.
constexpr std::optional<std::size_t> checked_align_up(std::size_t value, std::size_t alignment) noexcept {
  if (alignment == 0) return std::nullopt;
  const auto remainder = value % alignment;
  if (remainder == 0) return value;
  const auto delta = alignment - remainder;
  return checked_add(value, delta);
}

/// Narrowing helper: convert a 64-bit value to size_t only when it round-trips.
constexpr std::optional<std::size_t> narrow_size(std::uint64_t value) noexcept {
  if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return std::nullopt;
  return static_cast<std::size_t>(value);
}

}  // namespace sff

#endif  // SFF_CORE_CHECKED_HPP
