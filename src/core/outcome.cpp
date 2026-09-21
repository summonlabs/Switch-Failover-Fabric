// Switch Failover Fabric - outcome codes and status plumbing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/core/outcome.hpp"

#include <algorithm>

namespace sff {
namespace {

constexpr const char* kCodeNames[] = {
    "OK",             "UNKNOWN",       "STALE",         "CONFLICT",
    "INVALID",        "UNSUPPORTED",   "INDETERMINATE", "SEARCH_LIMIT_REACHED",
    "PROVEN_INFEASIBLE", "DENIED",     "UNAUTHORIZED",  "FENCED",
    "INTERRUPTED",    "AMBIGUOUS",     "NOT_FOUND",     "ALREADY_EXISTS",
    "EXHAUSTED",      "BUSY",          "CLOSED",        "CORRUPT",
    "TRUNCATED",      "REPLAY",        "VERSION_MISMATCH", "IO_ERROR",
    "DEADLINE_EXCEEDED", "UNVERIFIED", "PARTIAL_CLOSURE", "EXPIRED",
};

constexpr std::size_t kCodeCount = sizeof(kCodeNames) / sizeof(kCodeNames[0]);

}  // namespace

const char* to_string(Code code) noexcept {
  const auto index = static_cast<std::size_t>(code);
  if (index >= kCodeCount) return "UNRECOGNISED_CODE";
  return kCodeNames[index];
}

bool is_success(Code code) noexcept { return code == Code::Ok; }

bool is_fail_closed(Code code) noexcept {
  switch (code) {
    case Code::Ok:
      return false;
    case Code::ProvenInfeasible:
      // A proven negative is a conclusion, not an absence of one, but it still confers no
      // authority. It is fail-closed for authority purposes.
      return true;
    default:
      return true;
  }
}

bool is_indeterminate(Code code) noexcept {
  switch (code) {
    case Code::Unknown:
    case Code::Indeterminate:
    case Code::SearchLimitReached:
    case Code::Ambiguous:
    case Code::Interrupted:
    case Code::Busy:
    case Code::DeadlineExceeded:
      return true;
    default:
      return false;
  }
}

std::string bounded_message(std::string_view text) {
  if (text.size() <= kMaxMessageBytes) return std::string(text);
  std::string result(text.substr(0, kMaxMessageBytes));
  return result;
}

Status Status::failure(Code code, std::string_view message, std::uint32_t detail) {
  Status status;
  status.code_ = code == Code::Ok ? Code::Invalid : code;
  status.detail_ = detail;
  status.message_ = bounded_message(message);
  return status;
}

std::string Status::to_string() const {
  std::string result(sff::to_string(code_));
  if (detail_ != 0) {
    result += ":";
    result += std::to_string(detail_);
  }
  if (!message_.empty()) {
    result += " ";
    result += message_;
  }
  return result;
}

}  // namespace sff
