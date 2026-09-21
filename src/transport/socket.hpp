// Switch Failover Fabric - private RAII TCP socket layer for the framed transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This header is private to src/transport. It owns every platform-specific detail (Winsock2 on
// Windows, BSD sockets elsewhere) so that frame.cpp stays purely portable and so that the server
// and client never touch a raw handle.
//
// Threading contract: one Socket object owns one handle. Socket::close() is idempotent and never
// races with itself, and GuardedSocket makes it the single, serialised closer so a handle is
// closed exactly once.
//
// Releasing a *blocked* operation from another thread is platform work: shutdown() wakes a blocked
// recv() on POSIX but not on Windows (verified on this toolchain - a blocking recv stays blocked
// after shutdown(SD_BOTH) and only returns once the handle is closed), so Socket::close() performs
// shutdown *and* closes the handle. After the close, GuardedSocket::begin() refuses, so the thread
// that was blocked never issues another operation on that handle and a recycled handle value can
// never be observed: a stale read is impossible by construction, not by timing.

#ifndef SFF_TRANSPORT_SOCKET_HPP
#define SFF_TRANSPORT_SOCKET_HPP

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace sff::transport {

#if defined(_WIN32)
using NativeSocket = std::uintptr_t;
inline constexpr NativeSocket kInvalidSocket = static_cast<NativeSocket>(~static_cast<std::uintptr_t>(0));
#else
using NativeSocket = int;
inline constexpr NativeSocket kInvalidSocket = -1;
#endif

/// Owning handle for one connected or listening TCP socket.
class Socket {
 public:
  Socket() noexcept = default;
  explicit Socket(NativeSocket handle) noexcept : handle_(handle) {}
  ~Socket();

  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  bool valid() const noexcept { return handle_ != kInvalidSocket; }
  NativeSocket native() const noexcept { return handle_; }

  /// Release blocked readers/writers in other threads. The handle stays open and owned here.
  void shutdown() noexcept;

  /// Shut down and close. Idempotent: the second and later calls do nothing.
  void close() noexcept;

 private:
  NativeSocket handle_ = kInvalidSocket;
};

/// One socket shared between a worker that blocks on it and a stopper that must release it.
///
/// A user calls begin()/end() (normally through GuardedSocketUse) around a blocking operation.
/// request_close() from any other thread closes the handle, which is what releases that blocked
/// call on every supported platform, and is idempotent. begin() then refuses, so the released
/// thread returns without touching the handle again.
class GuardedSocket {
 public:
  GuardedSocket() = default;
  explicit GuardedSocket(Socket socket) : socket_(std::move(socket)) {}
  ~GuardedSocket();

  GuardedSocket(const GuardedSocket&) = delete;
  GuardedSocket& operator=(const GuardedSocket&) = delete;

  /// Adopt a fresh handle. Refused (and the handle closed) when a close is already in progress.
  Status reset(Socket socket);

  bool begin();
  void end();

  /// Close the handle, releasing any operation another thread is blocked in. Idempotent, safe
  /// from any thread, and never blocks. The first caller is the only closer.
  void request_close();

  bool closing() const;
  bool valid() const;

  /// Direct access for the owning thread only, between begin() and end().
  Socket* socket();

  /// True while no operation is in flight on this socket.
  bool idle() const;

 private:
  mutable std::mutex mutex_;
  Socket socket_;
  bool closing_ = false;
  int active_ = 0;  ///< Operations in flight; see end().
};

/// RAII form of GuardedSocket::begin()/end().
class GuardedSocketUse {
 public:
  explicit GuardedSocketUse(GuardedSocket& guard) : guard_(&guard), usable_(guard.begin()) {}
  ~GuardedSocketUse() {
    if (guard_ != nullptr) guard_->end();
  }

  GuardedSocketUse(const GuardedSocketUse&) = delete;
  GuardedSocketUse& operator=(const GuardedSocketUse&) = delete;

  bool usable() const noexcept { return usable_; }
  Socket* socket() const noexcept { return usable_ ? guard_->socket() : nullptr; }

 private:
  GuardedSocket* guard_;
  bool usable_;
};

/// Initialise the process network stack exactly once (WSAStartup on Windows; a no-op elsewhere).
Status ensure_network_ready();

/// The payload bound actually enforced: the caller's limit clamped by the hard ceiling.
std::size_t effective_max_frame_payload(const Limits& limits) noexcept;

/// The read chunk used by the server and client: one frame at most, capped for locality.
std::size_t transport_chunk_bytes(const Limits& limits) noexcept;

/// Blocking connect to host:port, trying every resolved address in order.
Result<Socket> connect_tcp(const std::string& host, std::uint16_t port);

/// Bind and listen. port 0 selects an ephemeral port, reported through out_port.
Result<Socket> listen_tcp(const std::string& bind_address, std::uint16_t port, std::size_t backlog,
                          std::uint16_t& out_port);

/// Accept one connection (blocking). A failure is reported, never solved by retrying forever.
Result<Socket> accept_tcp(const Socket& listener);

/// Send every byte or fail. Never partially reports success.
Status send_all(const Socket& socket, const std::uint8_t* data, std::size_t size);

/// Receive at least one byte. received == 0 with an Ok status means the peer closed cleanly.
Status receive_some(const Socket& socket, std::uint8_t* data, std::size_t capacity,
                    std::size_t& received);

/// A connected loopback pair used to wake a thread blocked in wait_readable_pair().
Result<std::pair<Socket, Socket>> make_wakeup_pair();

/// Signal the wakeup pair. Best effort: failure means the pair is already gone.
void wake_socket(const Socket& writer) noexcept;

/// Block until either socket is readable. Returns with a_ready == true when a is readable and
/// a_ready == false when the wakeup end was signalled. No time limit is involved.
Status wait_readable_pair(const Socket& a, const Socket& b, bool& a_ready);

}  // namespace sff::transport

#endif  // SFF_TRANSPORT_SOCKET_HPP
