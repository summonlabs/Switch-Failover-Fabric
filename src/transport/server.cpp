// Switch Failover Fabric - bounded framed TCP server.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Shape: one accept thread plus a fixed worker pool. A connection is queued on accept and is
// served by exactly one worker for its whole lifetime, which is what lets a session issue more
// than one request on one connection. The pool is bounded by options.worker_threads and the live
// connection set by options.max_connections; a connection beyond that bound is accepted and
// immediately closed so the refusal is observable to the peer instead of leaving it in a backlog.
//
// The user handler is always invoked on the worker thread with no internal lock held. Responses
// always carry the request's session/epoch/boot_digest, so a handler can never answer as another
// session by accident.
//
// Shutdown releases blocked work structurally rather than by timing out: the accept thread waits
// on (listener, wakeup socket) and the stopper writes to the wakeup socket; every live connection
// is shut down, which releases any blocked recv() and is what makes a silent peer irrelevant.
// Nothing here waits on a timeout.

// frame.hpp declares FrameHeader::binding() returning SessionBinding without including
// sff/runtime/session.hpp; the declaring header must come first (public headers are frozen).
#include "sff/runtime/session.hpp"

#include "sff/transport/server.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "sff/codec/integrity.hpp"
#include "sff/core/limits.hpp"
#include "transport/socket.hpp"

namespace sff {
namespace {

/// Largest worker pool this build will create, regardless of what a caller requests.
constexpr std::size_t kMaxWorkerThreads = 256;

/// Consecutive accept failures tolerated before the accept loop gives up. Bounded so that a
/// persistently failing listener can never become a spin loop.
constexpr std::size_t kMaxConsecutiveAcceptErrors = 64;

/// One accepted connection and the protocol state that goes with it.
struct Connection {
  explicit Connection(transport::Socket socket) : guard(std::move(socket)) {}

  transport::GuardedSocket guard;
};

}  // namespace

struct FrameServer::Impl {
  ServerOptions options;
  Handler handler;

  transport::Socket listener;
  transport::Socket wake_reader;
  transport::Socket wake_writer;

  std::thread accept_thread;
  std::thread::id accept_thread_id;
  std::vector<std::thread> workers;
  std::vector<std::thread::id> worker_ids;

  mutable std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::shared_ptr<Connection>> queue;
  std::vector<std::shared_ptr<Connection>> live;
  bool stopping = false;
  bool stopped = false;

  std::atomic<std::size_t> connections_served{0};
  std::atomic<std::size_t> frames_processed{0};
  std::atomic<std::size_t> frames_rejected{0};

  std::uint16_t bound_port = 0;
  std::string bound_address;

  void serve(const std::shared_ptr<Connection>& connection);
  void worker_main();
  void accept_main();
  void accept_connection(transport::Socket accepted);
  void mark_stopping();
  Status stop_all();
};

// --- worker ---------------------------------------------------------------------------------

void FrameServer::Impl::serve(const std::shared_ptr<Connection>& connection) {
  connections_served.fetch_add(1, std::memory_order_relaxed);
  FrameStreamDecoder decoder(options.limits);
  std::vector<std::uint8_t> chunk(transport::transport_chunk_bytes(options.limits));

  for (;;) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (stopping) return;
    }

    FrameDecodeResult decoded = decoder.next();
    while (decoded.disposition == FrameDisposition::Incomplete) {
      std::size_t received = 0;
      Status read;
      {
        transport::GuardedSocketUse use(connection->guard);
        if (!use.usable()) return;
        read = transport::receive_some(*use.socket(), chunk.data(), chunk.size(), received);
      }
      if (!read.ok() || received == 0) return;  // peer closed, or was shut down by stop()
      const Status fed = decoder.feed(chunk.data(), received);
      if (!fed.ok()) {
        // The peer pushed the stream past its declared bound; the connection cannot be
        // resynchronised, so it is refused rather than silently resynchronised.
        frames_rejected.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      decoded = decoder.next();
    }
    if (decoded.disposition != FrameDisposition::Complete) {
      frames_rejected.fetch_add(1, std::memory_order_relaxed);
      return;
    }

    frames_processed.fetch_add(1, std::memory_order_relaxed);

    Frame response;
    Status outcome = Status::success();
    bool handler_ok = false;
    try {
      // Outside every internal lock by construction: serve() holds no lock here.
      outcome = handler(decoded.frame, response);
      handler_ok = outcome.ok();
    } catch (const std::exception& error) {
      outcome = Status::failure(Code::Invalid, error.what());
    } catch (...) {
      outcome = Status::failure(Code::Unknown, "handler threw an unrecognised exception");
    }

    if (!handler_ok || !is_valid_message_type(static_cast<std::uint16_t>(response.header.type))) {
      const Code code = handler_ok ? Code::Invalid : outcome.code();
      const std::string_view detail =
          handler_ok ? std::string_view("handler produced no response message type")
                     : std::string_view(outcome.message());
      response = Frame{};
      response.header.type = MessageType::Error;
      response.payload = encode_error_payload(code, detail);
    }

    // The authority binding always comes from the request. A handler cannot make this
    // connection answer as a different session, epoch or boot incarnation.
    response.header.magic = kFrameMagic;
    response.header.format_version = kFrameFormatVersion;
    response.header.session = decoded.frame.header.session;
    response.header.epoch = decoded.frame.header.epoch;
    response.header.boot_digest = decoded.frame.header.boot_digest;
    response.header.request_seq = decoded.frame.header.request_seq;

    auto encoded = encode_frame(response, options.limits);
    if (!encoded.ok()) {
      // The handler produced a response this transport refuses to carry (for example a payload
      // beyond the bound). Answer with a bounded Error frame rather than dropping the connection,
      // so the peer always gets exactly one definite response.
      Frame fallback;
      fallback.header.type = MessageType::Error;
      fallback.header.session = decoded.frame.header.session;
      fallback.header.epoch = decoded.frame.header.epoch;
      fallback.header.boot_digest = decoded.frame.header.boot_digest;
      fallback.header.request_seq = decoded.frame.header.request_seq;
      fallback.payload = encode_error_payload(encoded.status().code(), encoded.status().message());
      encoded = encode_frame(fallback, options.limits);
      if (!encoded.ok()) {
        frames_rejected.fetch_add(1, std::memory_order_relaxed);
        return;
      }
    }
    Status written;
    {
      transport::GuardedSocketUse use(connection->guard);
      if (!use.usable()) return;
      written = transport::send_all(*use.socket(), encoded.value().data(), encoded.value().size());
    }
    if (!written.ok()) return;
  }
}

void FrameServer::Impl::worker_main() {
  try {
    for (;;) {
      std::shared_ptr<Connection> connection;
      {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return stopping || !queue.empty(); });
        if (stopping) return;
        connection = queue.front();
        queue.pop_front();
      }
      serve(connection);
      connection->guard.request_close();
      {
        std::lock_guard<std::mutex> lock(mutex);
        live.erase(std::remove(live.begin(), live.end(), connection), live.end());
      }
    }
  } catch (...) {
    mark_stopping();
  }
}

// --- accept ---------------------------------------------------------------------------------

void FrameServer::Impl::accept_main() {
  try {
    std::size_t consecutive_errors = 0;
    for (;;) {
      {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping) return;
      }
      bool listener_ready = false;
      const Status waited =
          transport::wait_readable_pair(listener, wake_reader, listener_ready);
      {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping) return;
      }
      if (!waited.ok()) {
        mark_stopping();
        return;
      }
      if (!listener_ready) return;  // the wakeup end was signalled

      auto accepted = transport::accept_tcp(listener);
      {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping) return;
      }
      if (!accepted.ok()) {
        if (accepted.status().code() == Code::Closed) {
          mark_stopping();
          return;
        }
        if (++consecutive_errors >= kMaxConsecutiveAcceptErrors) {
          mark_stopping();
          return;
        }
        continue;
      }
      consecutive_errors = 0;
      accept_connection(std::move(accepted.value()));
    }
  } catch (...) {
    mark_stopping();
  }
}

void FrameServer::Impl::accept_connection(transport::Socket accepted) {
  const auto connection = std::make_shared<Connection>(std::move(accepted));
  bool admitted = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (!stopping && live.size() < options.max_connections) {
      live.push_back(connection);
      queue.push_back(connection);
      admitted = true;
    }
  }
  if (!admitted) {
    // Refused: shut the socket down immediately so the peer sees the refusal without waiting.
    frames_rejected.fetch_add(1, std::memory_order_relaxed);
    connection->guard.request_close();
    return;
  }
  cv.notify_one();
}

// --- shutdown -------------------------------------------------------------------------------

void FrameServer::Impl::mark_stopping() {
  {
    std::lock_guard<std::mutex> lock(mutex);
    stopping = true;
  }
  cv.notify_all();
}

Status FrameServer::Impl::stop_all() {
  const std::thread::id self = std::this_thread::get_id();
  bool on_server_thread = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (stopped) return Status::success();
    stopping = true;
    on_server_thread =
        (self == accept_thread_id) ||
        (std::find(worker_ids.begin(), worker_ids.end(), self) != worker_ids.end());
  }
  cv.notify_all();
  transport::wake_socket(wake_writer);

  {
    std::vector<std::shared_ptr<Connection>> snapshot;
    {
      std::lock_guard<std::mutex> lock(mutex);
      snapshot = live;
    }
    // Releases every blocked recv() on a served connection and closes idle ones. This is what
    // makes a silent peer irrelevant to shutdown.
    for (const auto& connection : snapshot) {
      connection->guard.request_close();
    }
  }

  if (on_server_thread) {
    return Status::failure(
        Code::Busy, "stop() was called from a server thread; the stop was signalled but the "
                    "server threads cannot be joined from inside the server");
  }

  if (accept_thread.joinable()) accept_thread.join();
  for (auto& worker : workers) {
    if (worker.joinable()) worker.join();
  }

  listener.close();
  wake_reader.close();
  wake_writer.close();
  {
    std::lock_guard<std::mutex> lock(mutex);
    live.clear();
    queue.clear();
    stopped = true;
  }
  return Status::success();
}

// --- public surface ---------------------------------------------------------------------------

FrameServer::FrameServer() : impl_(std::make_unique<Impl>()) {}

FrameServer::~FrameServer() {
  try {
    (void)stop();
  } catch (...) {
    // A destructor never propagates.
  }
}

Result<std::unique_ptr<FrameServer>> FrameServer::start(const ServerOptions& options,
                                                        Handler handler) {
  using ServerResult = Result<std::unique_ptr<FrameServer>>;

  if (const Status limits_status = options.limits.validate(); !limits_status.ok()) {
    return ServerResult(limits_status);
  }
  if (!handler) {
    return ServerResult(Status::failure(Code::Invalid, "frame server requires a handler"));
  }
  if (options.worker_threads == 0) {
    return ServerResult(Status::failure(Code::Invalid, "worker_threads must be at least 1"));
  }
  if (options.worker_threads > kMaxWorkerThreads) {
    return ServerResult(refuse_exhausted("worker threads", options.worker_threads,
                                         kMaxWorkerThreads));
  }
  if (options.max_connections == 0) {
    return ServerResult(Status::failure(Code::Invalid, "max_connections must be at least 1"));
  }
  if (options.max_connections > kHardMaxSessions) {
    return ServerResult(
        refuse_exhausted("connections", options.max_connections, kHardMaxSessions));
  }
  if (options.accept_backlog == 0) {
    return ServerResult(Status::failure(Code::Invalid, "accept_backlog must be at least 1"));
  }
  if (options.bind_address.empty()) {
    return ServerResult(Status::failure(Code::Invalid, "bind_address must not be empty"));
  }
  if (const Status ready = transport::ensure_network_ready(); !ready.ok()) {
    return ServerResult(ready);
  }

  std::uint16_t bound_port = 0;
  auto listener = transport::listen_tcp(options.bind_address, options.port,
                                        options.accept_backlog, bound_port);
  if (!listener.ok()) return ServerResult(listener.status());

  auto wakeup = transport::make_wakeup_pair();
  if (!wakeup.ok()) return ServerResult(wakeup.status());

  std::unique_ptr<FrameServer> server(new FrameServer());
  Impl& impl = *server->impl_;
  impl.options = options;
  impl.handler = std::move(handler);
  impl.bound_port = bound_port;
  impl.bound_address = options.bind_address;
  impl.listener = std::move(listener.value());
  impl.wake_reader = std::move(wakeup.value().first);
  impl.wake_writer = std::move(wakeup.value().second);

  try {
    impl.workers.reserve(options.worker_threads);
    for (std::size_t index = 0; index < options.worker_threads; ++index) {
      impl.workers.emplace_back([&impl] { impl.worker_main(); });
      std::lock_guard<std::mutex> lock(impl.mutex);
      impl.worker_ids.push_back(impl.workers.back().get_id());
    }
    impl.accept_thread = std::thread([&impl] { impl.accept_main(); });
    std::lock_guard<std::mutex> lock(impl.mutex);
    impl.accept_thread_id = impl.accept_thread.get_id();
  } catch (const std::system_error& error) {
    impl.mark_stopping();
    (void)impl.stop_all();
    return ServerResult(Status::failure(Code::Exhausted, std::string("thread creation failed: ") +
                                                             error.what()));
  }
  return ServerResult(std::move(server));
}

std::uint16_t FrameServer::port() const noexcept { return impl_ ? impl_->bound_port : 0; }

std::string FrameServer::bound_address() const { return impl_ ? impl_->bound_address : std::string(); }

bool FrameServer::running() const {
  if (!impl_) return false;
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return !impl_->stopping;
}

Status FrameServer::stop() { return impl_ ? impl_->stop_all() : Status::success(); }

std::size_t FrameServer::connections_served() const {
  return impl_ ? impl_->connections_served.load(std::memory_order_relaxed) : 0;
}

std::size_t FrameServer::frames_processed() const {
  return impl_ ? impl_->frames_processed.load(std::memory_order_relaxed) : 0;
}

std::size_t FrameServer::frames_rejected() const {
  return impl_ ? impl_->frames_rejected.load(std::memory_order_relaxed) : 0;
}

}  // namespace sff
