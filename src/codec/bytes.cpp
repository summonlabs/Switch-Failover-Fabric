// Switch Failover Fabric - canonical, total, bounded binary codec.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/codec/bytes.hpp"

#include <algorithm>

namespace sff {
namespace {

void store_le(std::uint8_t* out, std::uint64_t value, std::size_t width) noexcept {
  for (std::size_t index = 0; index < width; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xffu);
  }
}

std::uint64_t load_le(const std::uint8_t* in, std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < width; ++index) {
    value |= static_cast<std::uint64_t>(in[index]) << (8 * index);
  }
  return value;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// ByteWriter
// ---------------------------------------------------------------------------------------------

ByteWriter::ByteWriter(std::size_t reserve) {
  const std::size_t bounded = std::min(reserve, limit_);
  try {
    bytes_.reserve(bounded);
  } catch (...) {
    failed_ = true;
    failure_ = Status::failure(Code::Exhausted, "writer reserve failed");
  }
}

std::uint32_t ByteWriter::checked_count(std::size_t count) noexcept {
  return count > 0xffffffffull ? 0xffffffffu : static_cast<std::uint32_t>(count);
}

Status ByteWriter::raw(const void* data, std::size_t size) {
  if (failed_) return failure_;
  if (size > limit_ || bytes_.size() > limit_ - size) {
    failed_ = true;
    failure_ = Status::failure(Code::Exhausted, "canonical document exceeds the writer limit");
    return failure_;
  }
  if (size != 0) {
    if (data == nullptr) {
      failed_ = true;
      failure_ = Status::failure(Code::Invalid, "null data with non-zero size");
      return failure_;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    bytes_.insert(bytes_.end(), bytes, bytes + size);
  }
  return Status::success();
}

Status ByteWriter::u8(std::uint8_t value) { return raw(&value, 1); }

Status ByteWriter::u16(std::uint16_t value) {
  std::uint8_t buffer[2];
  store_le(buffer, value, 2);
  return raw(buffer, 2);
}

Status ByteWriter::u32(std::uint32_t value) {
  std::uint8_t buffer[4];
  store_le(buffer, value, 4);
  return raw(buffer, 4);
}

Status ByteWriter::u64(std::uint64_t value) {
  std::uint8_t buffer[8];
  store_le(buffer, value, 8);
  return raw(buffer, 8);
}

Status ByteWriter::boolean(bool value) { return u8(value ? 1u : 0u); }

Status ByteWriter::blob(std::span<const std::uint8_t> data) {
  Status status = u32(checked_count(data.size()));
  if (!status.ok()) return status;
  return raw(data.data(), data.size());
}

Status ByteWriter::string(std::string_view text) {
  Status status = u32(checked_count(text.size()));
  if (!status.ok()) return status;
  return raw(text.data(), text.size());
}

// ---------------------------------------------------------------------------------------------
// ByteReader
// ---------------------------------------------------------------------------------------------

ByteReader::ByteReader(const void* data, std::size_t size) noexcept
    : data_(static_cast<const std::uint8_t*>(data)), size_(data == nullptr ? 0 : size) {}

void ByteReader::fail(Code code, std::string_view message) {
  // Sticky to the first failure: later reads never overwrite the original diagnosis.
  if (!failure_.ok()) return;
  failure_ = Status::failure(code, message);
}

bool ByteReader::ensure(std::size_t count) {
  if (!failure_.ok()) return false;
  if (count > remaining()) {
    fail(Code::Truncated, "read past the end of the canonical document");
    return false;
  }
  return true;
}

std::uint8_t ByteReader::u8() {
  if (!ensure(1)) return 0;
  const std::uint8_t value = data_[offset_];
  offset_ += 1;
  return value;
}

std::uint16_t ByteReader::u16() {
  if (!ensure(2)) return 0;
  const std::uint16_t value = static_cast<std::uint16_t>(load_le(data_ + offset_, 2));
  offset_ += 2;
  return value;
}

std::uint32_t ByteReader::u32() {
  if (!ensure(4)) return 0;
  const std::uint32_t value = static_cast<std::uint32_t>(load_le(data_ + offset_, 4));
  offset_ += 4;
  return value;
}

std::uint64_t ByteReader::u64() {
  if (!ensure(8)) return 0;
  const std::uint64_t value = load_le(data_ + offset_, 8);
  offset_ += 8;
  return value;
}

bool ByteReader::boolean() {
  const std::uint8_t raw_value = u8();
  if (!failure_.ok()) return false;
  if (raw_value > 1) {
    fail(Code::Invalid, "boolean field is not 0 or 1");
    return false;
  }
  return raw_value == 1;
}

std::vector<std::uint8_t> ByteReader::blob() {
  const std::uint32_t length = u32();
  if (!failure_.ok()) return {};
  if (static_cast<std::size_t>(length) > element_limit_) {
    fail(Code::Exhausted, "declared blob length exceeds the element limit");
    return {};
  }
  if (!ensure(length)) return {};
  std::vector<std::uint8_t> result(data_ + offset_, data_ + offset_ + length);
  offset_ += length;
  return result;
}

std::string ByteReader::string() {
  const std::uint32_t length = u32();
  if (!failure_.ok()) return {};
  if (static_cast<std::size_t>(length) > element_limit_) {
    fail(Code::Exhausted, "declared string length exceeds the element limit");
    return {};
  }
  if (!ensure(length)) return {};
  std::string result(reinterpret_cast<const char*>(data_ + offset_), length);
  offset_ += length;
  return result;
}

std::size_t ByteReader::list_count(std::size_t minimum_element_bytes) {
  const std::uint32_t declared = u32();
  if (!failure_.ok()) return 0;
  const auto count = static_cast<std::size_t>(declared);
  if (count > element_limit_) {
    fail(Code::Exhausted, "declared element count exceeds the element limit");
    return 0;
  }
  if (minimum_element_bytes != 0) {
    const std::size_t affordable = remaining() / minimum_element_bytes;
    if (count > affordable) {
      fail(Code::Truncated, "declared element count does not fit in the remaining bytes");
      return 0;
    }
  }
  return count;
}

Status ByteReader::require_end() {
  if (!failure_.ok()) return failure_;
  if (offset_ != size_) {
    fail(Code::Invalid, "trailing bytes after the canonical document");
    return failure_;
  }
  return Status::success();
}

}  // namespace sff
