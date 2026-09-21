// Switch Failover Fabric - strongly typed identities.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/core/identity.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <random>

#if defined(_WIN32)
#  include <process.h>
#else
#  include <unistd.h>
#endif

namespace sff {
namespace {

constexpr std::uint64_t kFnvPrimeHi = 0x00000100000001b3ull;
constexpr std::uint64_t kFnvPrimeLo = 0xc2b2ae3d27d4eb4full;

std::uint64_t current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(::_getpid());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

}  // namespace

std::string SwitchKey::to_string() const {
  if (!valid()) {
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "switch(%llu)@gen(%llu)",
                  static_cast<unsigned long long>(id_.raw()),
                  static_cast<unsigned long long>(generation_.raw()));
    return std::string(buffer);
  }
  char buffer[48];
  std::snprintf(buffer, sizeof(buffer), "switch(%llu)@gen(%llu)",
                static_cast<unsigned long long>(id_.raw()),
                static_cast<unsigned long long>(generation_.raw()));
  return std::string(buffer);
}

BootIncarnation BootIncarnation::for_current_process(std::uint64_t boot_ordinal) noexcept {
  std::random_device device;
  std::uint64_t hi = (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  std::uint64_t lo = (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  const auto steady = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
  hi ^= steady;
  lo = mix64(lo ^ steady ^ static_cast<std::uint64_t>(current_process_id()));
  if (hi == 0 && lo == 0) lo = 1;  // never produce an all-zero nonce
  return BootIncarnation(current_process_id(), boot_ordinal, hi, lo);
}

std::string BootIncarnation::to_string() const {
  char buffer[96];
  std::snprintf(buffer, sizeof(buffer), "boot(%llu)pid(%llu)nonce(%016llx%016llx)",
                static_cast<unsigned long long>(boot_ordinal_),
                static_cast<unsigned long long>(process_id_),
                static_cast<unsigned long long>(nonce_hi_),
                static_cast<unsigned long long>(nonce_lo_));
  return std::string(buffer);
}

const char* to_string(DependentKind kind) noexcept {
  switch (kind) {
    case DependentKind::Unknown:
      return "UNKNOWN";
    case DependentKind::Port:
      return "PORT";
    case DependentKind::Link:
      return "LINK";
    case DependentKind::Path:
      return "PATH";
    case DependentKind::Service:
      return "SERVICE";
  }
  return "UNRECOGNISED_DEPENDENT_KIND";
}

bool is_valid_dependent_kind(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(DependentKind::Port) &&
         raw <= static_cast<std::uint8_t>(DependentKind::Service);
}

std::string DependentRef::to_string() const {
  std::string result(sff::to_string(kind_));
  result += "(";
  result += std::to_string(id_);
  result += ")";
  return result;
}

std::uint64_t mix64(std::uint64_t value) noexcept {
  std::uint64_t z = value + 0x9e3779b97f4a7c15ull;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

void Digest128::absorb_byte(std::uint8_t byte) noexcept {
  hi = (hi ^ static_cast<std::uint64_t>(byte)) * kFnvPrimeHi;
  lo = (lo ^ (static_cast<std::uint64_t>(byte) + 0x9e3779b97f4a7c15ull)) * kFnvPrimeLo;
}

void Digest128::absorb_u64(std::uint64_t value) noexcept {
  for (int index = 0; index < 8; ++index) {
    absorb_byte(static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu));
  }
}

void Digest128::absorb_bytes(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  for (std::size_t index = 0; index < size; ++index) absorb_byte(bytes[index]);
}

void Digest128::absorb_string(std::string_view text) noexcept {
  absorb_u64(static_cast<std::uint64_t>(text.size()));
  absorb_bytes(text.data(), text.size());
}

void Digest128::absorb_key(const SwitchKey& key) noexcept {
  absorb_u64(key.id().raw());
  absorb_u64(key.generation().raw());
}

void Digest128::absorb_dependent(const DependentRef& dependent) noexcept {
  absorb_byte(static_cast<std::uint8_t>(dependent.kind()));
  absorb_u64(dependent.id());
}

std::string Digest128::to_hex() const {
  static const char* digits = "0123456789abcdef";
  std::string result;
  result.reserve(32);
  const std::uint64_t parts[2] = {hi, lo};
  for (const std::uint64_t part : parts) {
    for (int shift = 60; shift >= 0; shift -= 4) {
      result.push_back(digits[(part >> shift) & 0xfu]);
    }
  }
  return result;
}

}  // namespace sff
