// Switch Failover Fabric - transactional durable store.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_PERSIST_STORE_HPP
#define SFF_PERSIST_STORE_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/persist/records.hpp"
#include "sff/export.hpp"

namespace sff {

enum class OpenMode : std::uint8_t {
  CreateNew = 0,  ///< Fail with AlreadyExists when the journal is present.
  OpenExisting = 1,
  OpenOrCreate = 2,
};

SFF_API const char* to_string(OpenMode mode) noexcept;

struct SFF_API StoreOptions {
  std::filesystem::path root;   ///< Directory holding journal and snapshot.
  Limits limits = Limits::defaults();
  OpenMode mode = OpenMode::OpenOrCreate;
  bool durable_writes = true;   ///< Flush and, where supported, sync after each commit.
};

/// Outcome of scanning a journal.
struct SFF_API ReplayReport {
  std::vector<Record> records;
  std::size_t corrupt_records = 0;
  std::size_t torn_records = 0;
  std::size_t unsupported_records = 0;
  std::size_t recovered_bytes = 0;  ///< Bytes dropped from a genuine torn tail.
  bool truncated_tail = false;
  bool clean_shutdown = false;
  std::uint64_t last_sequence = 0;
  Status status;
};

/// Append-only journal plus a transactionally replaced snapshot.
///
/// Ordering guarantee: on every commit the payload bytes reach the file before the record is
/// considered published; a snapshot is written to a staging file, flushed, and then atomically
/// renamed over the live snapshot. A crash can therefore lose the newest record or keep the old
/// snapshot, but it can never expose a partially written record or a half-replaced snapshot.
class SFF_API DurableStore {
 public:
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  ~DurableStore();

  static Result<std::unique_ptr<DurableStore>> open(const StoreOptions& options);

  /// Append one record and publish it. Sequence numbers are assigned internally and are
  /// strictly increasing; nothing else may write to the journal.
  Status append(RecordKind kind, const std::vector<std::uint8_t>& payload, std::uint32_t flags = 0);

  /// Flush buffered bytes to the operating system.
  Status flush();

  /// Flush and, where the platform supports it, force to stable storage.
  Status sync();

  /// Read every record back. Rejects corruption; recovers only genuine torn tails.
  Result<ReplayReport> replay() const;

  /// Transactional snapshot replacement: staging -> flush -> sync -> atomic rename.
  Status write_snapshot(const std::vector<std::uint8_t>& document);
  Result<std::vector<std::uint8_t>> read_snapshot() const;
  bool has_snapshot() const;

  /// Rewrite the journal with exactly the supplied records, using transactional replacement.
  Status compact(const std::vector<Record>& records);

  /// Physically drop a genuine torn tail so that the journal is byte-exact.
  Status truncate_torn_tail(std::size_t recovered_bytes);

  const std::filesystem::path& root() const noexcept { return options_.root; }
  const std::filesystem::path& journal_path() const noexcept { return journal_path_; }
  const std::filesystem::path& snapshot_path() const noexcept { return snapshot_path_; }
  std::uint64_t next_sequence() const;
  std::uint64_t records_written() const;
  bool closed() const;

  /// Scan performed while opening: what was found, and whether the previous run shut down
  /// cleanly. A genuine torn tail has already been dropped physically at this point; an
  /// integrity failure on a complete record refuses the open instead.
  const ReplayReport& open_report() const noexcept;

  /// Number of bytes dropped from a genuine torn tail while opening.
  std::size_t torn_bytes_recovered() const noexcept;

  Status close();

 private:
  DurableStore() = default;

  StoreOptions options_{};
  std::filesystem::path journal_path_;
  std::filesystem::path snapshot_path_;
  std::unique_ptr<class DurableStoreImpl> impl_;
};

/// Canonical path hardening: refuse paths containing traversal or parent references, and
/// resolve the result to an absolute normalised form.
SFF_API Result<std::filesystem::path> sanitise_path(const std::filesystem::path& path);

}  // namespace sff

#endif  // SFF_PERSIST_STORE_HPP
