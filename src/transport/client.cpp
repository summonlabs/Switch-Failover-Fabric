// Switch Failover Fabric - blocking framed TCP client.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// One request is outstanding at a time: handshake() and call() are serialised, so a response can
// never be attributed to the wrong request. Sequences are handed out from a monotonic counter
// that saturates instead of wrapping, and the final value is refused a second time, so a replayed
// request sequence is impossible by construction.
//
// close() releases a blocked read by shutting the socket down; the handle itself is closed by
// whichever thread is inside the operation (or immediately when nobody is), so a handle is never
// closed while a read is in flight on it and is never closed twice.

// frame.hpp declares FrameHeader::binding() returning SessionBinding without including
// sff/runtime/session.hpp; the declaring header must come first (public headers are frozen).
#include "sff/runtime/session.hpp"

#include "sff/transport/client.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sff/core/limits.hpp"
#include "transport/socket.hpp"

namespace sff {

struct FrameClient::Impl {
  transport::GuardedSocket guard;
  Limits limits = Limits::defaults();
  bool handshaken = false;
  SessionId session;
  CoordinatorEpoch epoch;
  std::uint64_t boot_digest = 0;
  std::uint64_t next_seq = 1;
  bool sequence_exhausted = false;

  std::mutex io_mutex;     ///< serialises handshake()/call()
  std::mutex state_mutex;  ///< guards the adopted authority and the sequence counter

  FrameStreamDecoder decoder;
  std::vector<std::uint8_t> chunk;

  std::optional<std::uint64_t> take_sequence();
  Result<Frame> round_trip(const Frame& request);
};

std::optional<std::uint64_t> FrameClient::Impl::take_sequence() {
  std::lock_guard<std::mutex> lock(state_mutex);
  if (sequence_exhausted) return std::nullopt;
  const std::uint64_t sequence = next_seq;
  if (next_seq == UINT64_MAX) {
    // The last representable sequence is handed out once and then the space is closed.
    sequence_exhausted = true;
  } else {
    ++next_seq;
  }
  return sequence;
}

Result<Frame> FrameClient::Impl::round_trip(const Frame& request) {
  const auto encoded = encode_frame(request, limits);
  if (!encoded.ok()) return Result<Frame>(encoded.status());

  {
    transport::GuardedSocketUse use(guard);
    if (!use.usable()) {
      return Result<Frame>(Status::failure(Code::Closed, "client is not connected"));
    }
    const Status sent =
        transport::send_all(*use.socket(), encoded.value().data(), encoded.value().size());
    if (!sent.ok()) {
      guard.request_close();
      return Result<Frame>(sent);
    }
  }

  for (;;) {
    FrameDecodeResult decoded = decoder.next();
    if (decoded.disposition == FrameDisposition::Complete) {
      return Result<Frame>(std::move(decoded.frame));
    }
    if (decoded.disposition != FrameDisposition::Incomplete) {
      // A desynchronised stream is never resynchronised: the connection is dropped.
      guard.request_close();
      return Result<Frame>(decoded.status);
    }

    std::size_t received = 0;
    Status read;
    {
      transport::GuardedSocketUse use(guard);
      if (!use.usable()) {
        return Result<Frame>(Status::failure(Code::Closed, "client is not connected"));
      }
      read = transport::receive_some(*use.socket(), chunk.data(), chunk.size(), received);
    }
    if (!read.ok()) {
      guard.request_close();
      return Result<Frame>(read);
    }
    if (received == 0) {
      guard.request_close();
      return Result<Frame>(Status::failure(Code::Closed, "peer closed the connection"));
    }
    const Status fed = decoder.feed(chunk.data(), received);
    if (!fed.ok()) {
      guard.request_close();
      return Result<Frame>(fed);
    }
  }
}

FrameClient::FrameClient() : impl_(std::make_unique<Impl>()) {}

FrameClient::~FrameClient() {
  try {
    if (impl_) impl_->guard.request_close();
  } catch (...) {
    // A destructor never propagates.
  }
}

Result<std::unique_ptr<FrameClient>> FrameClient::connect(std::string host, std::uint16_t port,
                                                          Limits limits) {
  using ClientResult = Result<std::unique_ptr<FrameClient>>;

  if (host.empty()) {
    return ClientResult(Status::failure(Code::Invalid, "host must not be empty"));
  }
  if (port == 0) {
    return ClientResult(Status::failure(Code::Invalid, "port 0 cannot be connected to"));
  }
  if (const Status limits_status = limits.validate(); !limits_status.ok()) {
    return ClientResult(limits_status);
  }
  if (const Status ready = transport::ensure_network_ready(); !ready.ok()) {
    return ClientResult(ready);
  }

  auto socket = transport::connect_tcp(host, port);
  if (!socket.ok()) return ClientResult(socket.status());

  try {
    std::unique_ptr<FrameClient> client(new FrameClient());
    Impl& impl = *client->impl_;
    if (const Status adopted = impl.guard.reset(std::move(socket.value())); !adopted.ok()) {
      return ClientResult(adopted);
    }
    impl.limits = limits;
    impl.chunk.assign(transport::transport_chunk_bytes(limits), std::uint8_t{0});
    return ClientResult(std::move(client));
  } catch (const std::bad_alloc&) {
    return ClientResult(Status::failure(Code::Exhausted, "client allocation failed"));
  }
}

Status FrameClient::handshake(std::string_view principal) {
  Impl& impl = *impl_;
  if (principal.empty()) {
    return Status::failure(Code::Invalid, "handshake requires a principal");
  }
  if (!impl.guard.valid()) {
    return Status::failure(Code::Closed, "client is not connected");
  }

  std::lock_guard<std::mutex> io_lock(impl.io_mutex);
  {
    std::lock_guard<std::mutex> state_lock(impl.state_mutex);
    if (impl.handshaken) {
      return Status::failure(Code::AlreadyExists, "handshake already completed");
    }
  }

  HelloRequest hello;
  hello.principal = std::string(principal);
  hello.format_version = kFrameFormatVersion;

  Frame request;
  request.header.type = MessageType::Hello;
  request.header.session = SessionId{};
  request.header.epoch = CoordinatorEpoch{};
  request.header.boot_digest = 0;
  request.payload = encode_hello_request(hello);

  const auto sequence = impl.take_sequence();
  if (!sequence) {
    return Status::failure(Code::Exhausted, "request sequence space exhausted");
  }
  request.header.request_seq = *sequence;

  auto response = impl.round_trip(request);
  if (!response.ok()) return response.status();
  const Frame& frame = response.value();

  if (frame.header.type == MessageType::Error) {
    const auto error = decode_error_payload(frame.payload);
    if (error.ok()) return Status::failure(error.value().first, error.value().second);
    return Status::failure(Code::Invalid, "server answered with an undecodable error frame");
  }
  if (frame.header.type != MessageType::HelloAck) {
    return Status::failure(Code::Invalid, "unexpected handshake response type");
  }

  const auto acknowledged = decode_hello_response(frame.payload);
  if (!acknowledged.ok()) return acknowledged.status();
  const HelloResponse& ack = acknowledged.value();
  if (ack.format_version != static_cast<std::uint32_t>(kFrameFormatVersion)) {
    return Status::failure(Code::VersionMismatch, "server frame format version mismatch");
  }
  if (ack.outcome != Code::Ok) {
    return Status::failure(ack.outcome, "handshake refused by server");
  }
  if (!ack.session.valid() || !ack.epoch.valid()) {
    return Status::failure(Code::Invalid, "handshake accepted without a session authority");
  }

  std::lock_guard<std::mutex> state_lock(impl.state_mutex);
  impl.session = ack.session;
  impl.epoch = ack.epoch;
  impl.boot_digest = ack.boot_digest;
  impl.handshaken = true;
  if (ack.max_payload != 0) {
    // Adopt a server-declared lower bound; never raise our own.
    impl.limits.max_frame_payload =
        std::min<std::size_t>(impl.limits.max_frame_payload,
                              static_cast<std::size_t>(ack.max_payload));
  }
  return Status::success();
}

Result<Frame> FrameClient::call(MessageType type, const std::vector<std::uint8_t>& payload,
                                std::uint32_t flags) {
  Impl& impl = *impl_;
  if (!is_valid_message_type(static_cast<std::uint16_t>(type))) {
    return Result<Frame>(Status::failure(Code::Unsupported, "unassigned message type"));
  }
  if (!impl.guard.valid()) {
    return Result<Frame>(Status::failure(Code::Closed, "client is not connected"));
  }

  std::lock_guard<std::mutex> io_lock(impl.io_mutex);

  Frame request;
  {
    std::lock_guard<std::mutex> state_lock(impl.state_mutex);
    if (!impl.handshaken) {
      return Result<Frame>(Status::failure(Code::Unauthorized, "handshake required before call"));
    }
    if (payload.size() > impl.limits.max_frame_payload) {
      return Result<Frame>(
          refuse_exhausted("frame payload", payload.size(), impl.limits.max_frame_payload));
    }
    request.header.type = type;
    request.header.flags = flags;
    request.header.session = impl.session;
    request.header.epoch = impl.epoch;
    request.header.boot_digest = impl.boot_digest;
  }

  const auto sequence = impl.take_sequence();
  if (!sequence) {
    return Result<Frame>(Status::failure(Code::Exhausted, "request sequence space exhausted"));
  }
  request.header.request_seq = *sequence;
  request.payload = payload;

  return impl.round_trip(request);
}

SessionId FrameClient::session() const {
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->session;
}

CoordinatorEpoch FrameClient::epoch() const {
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->epoch;
}

std::uint64_t FrameClient::boot_digest() const {
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->boot_digest;
}

std::uint64_t FrameClient::next_sequence() const {
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->next_seq;
}

bool FrameClient::connected() const { return impl_->guard.valid(); }

bool FrameClient::handshaken() const {
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->handshaken;
}

Status FrameClient::close() {
  Impl& impl = *impl_;
  impl.guard.request_close();
  {
    std::lock_guard<std::mutex> state_lock(impl.state_mutex);
    impl.handshaken = false;
  }
  return Status::success();
}

}  // namespace sff
