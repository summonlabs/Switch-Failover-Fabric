// Switch Failover Fabric - canonical, total, bounded binary codec.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_CODEC_BYTES_HPP
#define SFF_CODEC_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/outcome.hpp"
#include "sff/export.hpp"

namespace sff {

/// Canonical little-endian, fixed-width encoding.
///
/// Every value written by ByteWriter is decoded by exactly one ByteReader method, and the
/// encoding is fully specified: no padding, no alignment, no platform-dependent widths. Two
/// runs over the same logical value always produce byte-identical output, which is what makes
/// digests and durable records comparable across processes and restarts.
class SFF_API ByteWriter {
 public:
  ByteWriter() = default;
  explicit ByteWriter(std::size_t reserve);

  /// Upper bound on the produced document. Exceeding it fails closed with Code::Exhausted.
  void set_limit(std::size_t limit) noexcept { limit_ = limit; }
  std::size_t limit() const noexcept { return limit_; }

  Status u8(std::uint8_t value);
  Status u16(std::uint16_t value);
  Status u32(std::uint32_t value);
  Status u64(std::uint64_t value);
  Status boolean(bool value);
  Status raw(const void* data, std::size_t size);
  Status blob(std::span<const std::uint8_t> data);
  Status string(std::string_view text);

  /// Length-prefixed vector of a trivially canonically-encodable element type.
  template <class Fn>
  Status list(std::size_t count, Fn&& write_element) {
    Status s = u32(checked_count(count));
    if (!s.ok()) return s;
    for (std::size_t i = 0; i < count; ++i) {
      s = write_element(*this, i);
      if (!s.ok()) return s;
    }
    return Status::ok();
  }

  const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
  std::vector<std::uint8_t> take() && noexcept { return std::move(bytes_); }
  std::size_t size() const noexcept { return bytes_.size(); }
  void clear() noexcept { bytes_.clear(); }
  bool overflowed() const noexcept { return failed_; }
  const Status& status() const noexcept { return failure_; }

 private:
  static std::uint32_t checked_count(std::size_t count) noexcept;

  std::vector<std::uint8_t> bytes_;
  std::size_t limit_ = std::size_t{1} << 30;
  bool failed_ = false;
  Status failure_;
};

/// Total, sticky-failure decoder.
///
/// Once any read fails, the reader stays failed: every subsequent read returns a zero value and
/// the original failure status is preserved. Decoding is therefore total - there is no input for
/// which the decoder reads out of bounds or reports a value it did not fully validate.
class SFF_API ByteReader {
 public:
  ByteReader(const void* data, std::size_t size) noexcept;
  explicit ByteReader(const std::vector<std::uint8_t>& data) noexcept
      : ByteReader(data.data(), data.size()) {}

  /// Maximum number of elements any length-prefixed collection may declare.
  void set_element_limit(std::size_t limit) noexcept { element_limit_ = limit; }
  std::size_t element_limit() const noexcept { return element_limit_; }

  std::uint8_t u8();
  std::uint16_t u16();
  std::uint32_t u32();
  std::uint64_t u64();
  bool boolean();
  std::vector<std::uint8_t> blob();
  std::string string();

  /// Read a length prefix and check it against both the declared collection bound and the
  /// number of bytes still available. Returns the declared count, or 0 with a sticky failure.
  std::size_t list_count(std::size_t minimum_element_bytes = 1);

  bool ok() const noexcept { return failure_.ok(); }
  const Status& status() const noexcept { return failure_; }
  std::size_t remaining() const noexcept { return size_ - offset_; }
  std::size_t offset() const noexcept { return offset_; }
  bool at_end() const noexcept { return offset_ == size_; }

  /// Fail explicitly when bytes remain. Trailing bytes are never silently ignored.
  Status require_end();

  void fail(Code code, std::string_view message = {});

 private:
  /// Bounds check that preserves the first failure. Returns false once the reader has failed.
  bool ensure(std::size_t count);

  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t offset_ = 0;
  std::size_t element_limit_ = std::size_t{1} << 24;
  Status failure_;
};

}  // namespace sff

#endif  // SFF_CODEC_BYTES_HPP
