// Switch Failover Fabric - transactional durable store.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/persist/store.hpp"

#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "sff/codec/integrity.hpp"

#if defined(_WIN32)
#  include <io.h>
#  include <windows.h>
#else
#  include <unistd.h>
#endif

namespace sff {
namespace {

constexpr const char* kJournalName = "sff.journal";
constexpr const char* kSnapshotName = "sff.snapshot";
constexpr const char* kSnapshotStagingName = "sff.snapshot.staging";
constexpr const char* kJournalStagingName = "sff.journal.staging";

Status io_failure(const char* what) {
  return Status::failure(Code::IoError, what);
}

bool force_to_stable_storage(std::FILE* file) {
  if (file == nullptr) return false;
  if (std::fflush(file) != 0) return false;
#if defined(_WIN32)
  return ::_commit(::_fileno(file)) == 0;
#else
  return ::fsync(::fileno(file)) == 0;
#endif
}

bool read_whole_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out,
                     std::size_t limit) {
  std::error_code code;
  if (!std::filesystem::exists(path, code)) return false;
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) return false;
  std::fseek(file, 0, SEEK_END);
  const long length = std::ftell(file);
  if (length < 0 || static_cast<std::size_t>(length) > limit) {
    std::fclose(file);
    return false;
  }
  std::fseek(file, 0, SEEK_SET);
  out.assign(static_cast<std::size_t>(length), 0);
  const std::size_t read = out.empty() ? 0 : std::fread(out.data(), 1, out.size(), file);
  std::fclose(file);
  return read == out.size();
}

bool atomic_replace(const std::filesystem::path& from, const std::filesystem::path& to) {
#if defined(_WIN32)
  return ::MoveFileExW(from.wstring().c_str(), to.wstring().c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
  std::error_code code;
  std::filesystem::rename(from, to, code);
  return !code;
#endif
}

}  // namespace

const char* to_string(OpenMode mode) noexcept {
  switch (mode) {
    case OpenMode::CreateNew: return "CREATE_NEW";
    case OpenMode::OpenExisting: return "OPEN_EXISTING";
    case OpenMode::OpenOrCreate: return "OPEN_OR_CREATE";
  }
  return "UNRECOGNISED_OPEN_MODE";
}

Result<std::filesystem::path> sanitise_path(const std::filesystem::path& path) {
  if (path.empty()) {
    return Status::failure(Code::Invalid, "path is empty");
  }
  for (const auto& component : path) {
    if (component == "..") {
      return Status::failure(Code::Invalid, "path contains a parent directory reference");
    }
  }
  std::error_code code;
  std::filesystem::path absolute = std::filesystem::absolute(path, code);
  if (code) {
    return Status::failure(Code::Invalid, "path could not be resolved to an absolute location");
  }
  return absolute.lexically_normal();
}

class DurableStoreImpl {
 public:
  std::FILE* file = nullptr;
  bool open = false;
  std::uint64_t next_sequence = 1;
  std::uint64_t records_written = 0;
  ReplayReport open_report;
};

DurableStore::~DurableStore() {
  if (impl_ && impl_->open) {
    std::fclose(impl_->file);
    impl_->file = nullptr;
    impl_->open = false;
  }
}

Result<std::unique_ptr<DurableStore>> DurableStore::open(const StoreOptions& options) {
  Status limit_status = options.limits.validate();
  if (!limit_status.ok()) return limit_status;

  Result<std::filesystem::path> root = sanitise_path(options.root);
  if (!root.ok()) return root.status();

  std::unique_ptr<DurableStore> store(new DurableStore());
  store->options_ = options;
  store->options_.root = root.value();
  store->journal_path_ = root.value() / kJournalName;
  store->snapshot_path_ = root.value() / kSnapshotName;
  store->impl_ = std::make_unique<DurableStoreImpl>();

  std::error_code code;
  const bool directory_exists = std::filesystem::is_directory(store->options_.root, code);
  const bool journal_exists = std::filesystem::exists(store->journal_path_, code);

  if (options.mode == OpenMode::CreateNew && journal_exists) {
    return Status::failure(Code::AlreadyExists, "journal already exists");
  }
  if (options.mode == OpenMode::OpenExisting && !journal_exists) {
    return Status::failure(Code::NotFound, "journal does not exist");
  }
  if (!directory_exists) {
    std::filesystem::create_directories(store->options_.root, code);
    if (code) return io_failure("durable root directory could not be created");
  }

  if (journal_exists) {
    Result<ReplayReport> report = store->replay();
    store->impl_->open_report = report.value();
    if (!report.ok()) {
      // An integrity failure on a complete record is never repaired or skipped.
      return Status::failure(report.value().status.code(),
                             "journal contains a record that failed its integrity check");
    }
    if (report.value().truncated_tail) {
      Status truncated = store->truncate_torn_tail(report.value().recovered_bytes);
      if (!truncated.ok()) return truncated;
    }
    store->impl_->next_sequence = report.value().last_sequence + 1;
  }

  const char* mode = journal_exists ? "r+b" : "w+b";
  store->impl_->file = std::fopen(store->journal_path_.string().c_str(), mode);
  if (store->impl_->file == nullptr) {
    return io_failure("journal could not be opened");
  }
  std::fseek(store->impl_->file, 0, SEEK_END);
  store->impl_->open = true;
  return store;
}

Status DurableStore::append(RecordKind kind, const std::vector<std::uint8_t>& payload,
                            std::uint32_t flags) {
  if (!impl_ || !impl_->open) {
    return Status::failure(Code::Closed, "durable store is closed");
  }
  if (impl_->records_written >= options_.limits.max_journal_records) {
    return refuse_exhausted("max_journal_records", impl_->records_written + 1,
                            options_.limits.max_journal_records);
  }
  if (!is_valid_record_kind(static_cast<std::uint16_t>(kind))) {
    return Status::failure(Code::Invalid, "record kind cannot be persisted");
  }

  Record record;
  record.header.magic = kRecordMagic;
  record.header.format_version = kRecordFormatVersion;
  record.header.kind = kind;
  record.header.flags = flags;
  record.header.seq = impl_->next_sequence;
  record.payload = payload;

  Result<std::vector<std::uint8_t>> encoded = encode_record(record, options_.limits);
  if (!encoded.ok()) return encoded.status();

  std::fseek(impl_->file, 0, SEEK_END);
  const std::size_t written =
      std::fwrite(encoded.value().data(), 1, encoded.value().size(), impl_->file);
  if (written != encoded.value().size()) {
    return io_failure("record could not be written in full");
  }
  if (options_.durable_writes) {
    if (!force_to_stable_storage(impl_->file)) {
      return io_failure("record could not be forced to stable storage");
    }
  } else if (std::fflush(impl_->file) != 0) {
    return io_failure("record could not be flushed");
  }
  impl_->next_sequence += 1;
  impl_->records_written += 1;
  return Status::success();
}

Status DurableStore::flush() {
  if (!impl_ || !impl_->open) return Status::failure(Code::Closed, "durable store is closed");
  if (std::fflush(impl_->file) != 0) return io_failure("flush failed");
  return Status::success();
}

Status DurableStore::sync() {
  if (!impl_ || !impl_->open) return Status::failure(Code::Closed, "durable store is closed");
  if (!force_to_stable_storage(impl_->file)) return io_failure("sync failed");
  return Status::success();
}

Result<ReplayReport> DurableStore::replay() const {
  ReplayReport report;
  std::error_code code;
  if (!std::filesystem::exists(journal_path_, code)) {
    report.status = Status::success();
    return report;
  }
  if (impl_ && impl_->open && std::fflush(impl_->file) != 0) {
    return io_failure("journal could not be flushed before replay");
  }

  std::FILE* file = std::fopen(journal_path_.string().c_str(), "rb");
  if (file == nullptr) return io_failure("journal could not be opened for replay");

  // Streaming reader: one record is materialised at a time, so replay cost and memory are O(1) per
  // record regardless of journal size. A fixed-size window is fundamentally wrong here - a record
  // that straddles the window edge is complete in the file but looks torn in the window, and
  // recovering that "torn tail" would physically delete valid durable bytes.
  std::vector<std::uint8_t> record_bytes;
  std::uint64_t expected_sequence = 0;
  bool first = true;
  bool done = false;
  Status failure = Status::success();

  while (!done) {
    std::uint8_t header[kRecordHeaderBytes];
    const std::size_t header_read = std::fread(header, 1, kRecordHeaderBytes, file);
    if (header_read == 0) break;  // clean end of file

    if (header_read < kRecordHeaderBytes) {
      // Only a genuine prefix of a record header may be recovered; anything else is corruption.
      DecodeResult probe = decode_record(header, header_read, options_.limits);
      if (probe.disposition == DecodeDisposition::TornTail) {
        report.truncated_tail = true;
        report.torn_records += 1;
        report.recovered_bytes = header_read;
      } else {
        report.corrupt_records += 1;
        failure = probe.status.ok()
                      ? Status::failure(Code::Corrupt, "truncated record header is not a valid prefix")
                      : probe.status;
      }
      done = true;
      break;
    }

    // The header alone is enough to validate magic, version, kind, declared length and the header
    // integrity check, and to learn how many bytes a whole record needs.
    DecodeResult probe = decode_record(header, kRecordHeaderBytes, options_.limits);
    if (probe.disposition == DecodeDisposition::Corrupt ||
        probe.disposition == DecodeDisposition::Unsupported) {
      if (probe.disposition == DecodeDisposition::Corrupt) {
        report.corrupt_records += 1;
      } else {
        report.unsupported_records += 1;
      }
      failure = probe.status;
      done = true;
      break;
    }

    const std::size_t payload_len = static_cast<std::size_t>(probe.record.header.payload_len);
    const std::size_t total = kRecordHeaderBytes + payload_len + 4;
    record_bytes.assign(total, 0);
    std::memcpy(record_bytes.data(), header, kRecordHeaderBytes);
    const std::size_t body_read =
        std::fread(record_bytes.data() + kRecordHeaderBytes, 1, payload_len + 4, file);
    if (body_read < payload_len + 4) {
      // The writer stopped part way through a record whose header was already durable: a genuine
      // torn tail, recovered exactly by its real length.
      report.truncated_tail = true;
      report.torn_records += 1;
      report.recovered_bytes = kRecordHeaderBytes + body_read;
      done = true;
      break;
    }

    DecodeResult decoded = decode_record(record_bytes.data(), total, options_.limits);
    if (decoded.disposition != DecodeDisposition::Complete) {
      if (decoded.disposition == DecodeDisposition::Unsupported) {
        report.unsupported_records += 1;
      } else {
        report.corrupt_records += 1;
      }
      failure = decoded.status;
      done = true;
      break;
    }

    const std::uint64_t sequence = decoded.record.header.seq;
    if (first) {
      // A compacted journal may legitimately start at any sequence; continuity is anchored on the
      // first record actually present, and every later record must follow it with no gap and no
      // regression.
      expected_sequence = sequence;
      first = false;
    }
    if (sequence != expected_sequence) {
      report.corrupt_records += 1;
      failure = Status::failure(sequence < expected_sequence ? Code::Replay : Code::Corrupt,
                                sequence < expected_sequence
                                    ? "journal sequence number regressed"
                                    : "journal sequence number is not contiguous");
      done = true;
      break;
    }
    expected_sequence += 1;
    report.last_sequence = sequence;
    report.clean_shutdown = decoded.record.header.kind == RecordKind::ShutdownClean;
    if (report.records.size() >= options_.limits.max_journal_records) {
      failure = refuse_exhausted("max_journal_records", report.records.size() + 1,
                                 options_.limits.max_journal_records);
      done = true;
      break;
    }
    report.records.push_back(std::move(decoded.record));
  }

  std::fclose(file);
  report.status = failure;
  if (report.truncated_tail && report.corrupt_records == 0 && failure.ok()) {
    report.status = Status::success();
  } else if (!failure.ok()) {
    report.status = failure;
  }
  // The Result status mirrors the report status: a corrupt or unsupported scan must never appear
  // as a successful Result. The full report travels with it so the caller still sees how much was
  // recovered before the failure.
  return Result<ReplayReport>(report.status, report);
}

Status DurableStore::write_snapshot(const std::vector<std::uint8_t>& document) {
  if (!impl_ || !impl_->open) return Status::failure(Code::Closed, "durable store is closed");
  if (document.size() > options_.limits.max_document_bytes) {
    return refuse_exhausted("max_document_bytes", document.size(), options_.limits.max_document_bytes);
  }
  const std::filesystem::path staging = options_.root / kSnapshotStagingName;
  std::FILE* file = std::fopen(staging.string().c_str(), "wb");
  if (file == nullptr) return io_failure("snapshot staging file could not be created");
  const std::uint32_t crc = crc32_ieee(document);
  std::uint8_t crc_bytes[4] = {static_cast<std::uint8_t>(crc & 0xffu),
                               static_cast<std::uint8_t>((crc >> 8) & 0xffu),
                               static_cast<std::uint8_t>((crc >> 16) & 0xffu),
                               static_cast<std::uint8_t>((crc >> 24) & 0xffu)};
  bool ok = document.empty() || std::fwrite(document.data(), 1, document.size(), file) == document.size();
  ok = ok && std::fwrite(crc_bytes, 1, sizeof(crc_bytes), file) == sizeof(crc_bytes);
  ok = ok && force_to_stable_storage(file);
  std::fclose(file);
  if (!ok) {
    std::error_code code;
    std::filesystem::remove(staging, code);
    return io_failure("snapshot staging file could not be written in full");
  }
  if (!atomic_replace(staging, snapshot_path_)) {
    std::error_code code;
    std::filesystem::remove(staging, code);
    return io_failure("snapshot could not be published atomically");
  }
  return Status::success();
}

Result<std::vector<std::uint8_t>> DurableStore::read_snapshot() const {
  std::vector<std::uint8_t> raw;
  if (!read_whole_file(snapshot_path_, raw, options_.limits.max_document_bytes + 4)) {
    std::error_code code;
    if (!std::filesystem::exists(snapshot_path_, code)) {
      return Status::failure(Code::NotFound, "snapshot does not exist");
    }
    return Status::failure(Code::Corrupt, "snapshot could not be read or exceeds the document bound");
  }
  if (raw.size() < 4) {
    return Status::failure(Code::Truncated, "snapshot is shorter than its integrity trailer");
  }
  const std::size_t document_size = raw.size() - 4;
  const std::uint32_t stored = static_cast<std::uint32_t>(raw[document_size]) |
                               (static_cast<std::uint32_t>(raw[document_size + 1]) << 8) |
                               (static_cast<std::uint32_t>(raw[document_size + 2]) << 16) |
                               (static_cast<std::uint32_t>(raw[document_size + 3]) << 24);
  std::vector<std::uint8_t> document(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(document_size));
  if (crc32_ieee(document) != stored) {
    return Status::failure(Code::Corrupt, "snapshot integrity check failed");
  }
  return document;
}

bool DurableStore::has_snapshot() const {
  std::error_code code;
  return std::filesystem::exists(snapshot_path_, code);
}

Status DurableStore::compact(const std::vector<Record>& records) {
  if (!impl_ || !impl_->open) return Status::failure(Code::Closed, "durable store is closed");
  if (records.size() > options_.limits.max_journal_records) {
    return refuse_exhausted("max_journal_records", records.size(), options_.limits.max_journal_records);
  }
  const std::filesystem::path staging = options_.root / kJournalStagingName;
  std::FILE* file = std::fopen(staging.string().c_str(), "wb");
  if (file == nullptr) return io_failure("journal staging file could not be created");
  bool ok = true;
  for (const auto& record : records) {
    Result<std::vector<std::uint8_t>> encoded = encode_record(record, options_.limits);
    if (!encoded.ok()) {
      ok = false;
      break;
    }
    ok = std::fwrite(encoded.value().data(), 1, encoded.value().size(), file) == encoded.value().size();
    if (!ok) break;
  }
  ok = ok && force_to_stable_storage(file);
  std::fclose(file);
  if (!ok) {
    std::error_code code;
    std::filesystem::remove(staging, code);
    return io_failure("journal compaction could not be written in full");
  }
  if (std::fflush(impl_->file) != 0) return io_failure("journal could not be flushed before compaction");
  std::fclose(impl_->file);
  impl_->file = nullptr;
  impl_->open = false;
  if (!atomic_replace(staging, journal_path_)) {
    std::error_code code;
    std::filesystem::remove(staging, code);
    return io_failure("journal could not be replaced atomically");
  }
  impl_->file = std::fopen(journal_path_.string().c_str(), "r+b");
  if (impl_->file == nullptr) return io_failure("journal could not be reopened after compaction");
  std::fseek(impl_->file, 0, SEEK_END);
  impl_->open = true;
  impl_->next_sequence = records.empty() ? 1 : records.back().header.seq + 1;
  impl_->records_written = records.size();
  return Status::success();
}

Status DurableStore::truncate_torn_tail(std::size_t recovered_bytes) {
  if (!impl_) return Status::failure(Code::Closed, "durable store is closed");
  std::error_code code;
  const std::uintmax_t size = std::filesystem::file_size(journal_path_, code);
  if (code) return io_failure("journal size could not be determined");
  if (static_cast<std::uintmax_t>(recovered_bytes) > size) {
    return Status::failure(Code::Invalid, "torn tail is larger than the journal");
  }
  const std::uintmax_t target = size - static_cast<std::uintmax_t>(recovered_bytes);
  if (impl_->open && std::fflush(impl_->file) != 0) return io_failure("flush before truncation failed");
#if defined(_WIN32)
  if (impl_->open) {
    if (::_chsize_s(::_fileno(impl_->file), static_cast<__int64>(target)) != 0) {
      return io_failure("journal could not be truncated");
    }
  }
#else
  if (impl_->open) {
    if (::ftruncate(::fileno(impl_->file), static_cast<off_t>(target)) != 0) {
      return io_failure("journal could not be truncated");
    }
  }
#endif
  if (!impl_->open) {
    std::filesystem::resize_file(journal_path_, target, code);
    if (code) return io_failure("journal could not be truncated");
  } else {
    std::fseek(impl_->file, 0, SEEK_END);
  }
  return Status::success();
}

std::uint64_t DurableStore::next_sequence() const {
  return impl_ ? impl_->next_sequence : 0;
}

std::uint64_t DurableStore::records_written() const {
  return impl_ ? impl_->records_written : 0;
}

bool DurableStore::closed() const { return impl_ == nullptr || !impl_->open; }

const ReplayReport& DurableStore::open_report() const noexcept {
  static const ReplayReport kEmpty;
  return impl_ ? impl_->open_report : kEmpty;
}

std::size_t DurableStore::torn_bytes_recovered() const noexcept {
  return impl_ ? impl_->open_report.recovered_bytes : 0;
}

Status DurableStore::close() {
  if (!impl_ || !impl_->open) return Status::success();
  const bool ok = force_to_stable_storage(impl_->file);
  std::fclose(impl_->file);
  impl_->file = nullptr;
  impl_->open = false;
  if (!ok) return io_failure("journal could not be synced while closing");
  return Status::success();
}

}  // namespace sff
