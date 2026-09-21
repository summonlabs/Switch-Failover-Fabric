// Switch Failover Fabric - private RAII TCP socket layer for the framed transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "transport/socket.hpp"

// The framing constants are needed to size a read chunk. sff/runtime/session.hpp must precede
// sff/transport/frame.hpp: the latter uses SessionBinding without including its declaring header.
#include "sff/runtime/session.hpp"

#include "sff/transport/frame.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#if !defined(_WIN32)
#  include <poll.h>
#endif

#include "sff/core/checked.hpp"

namespace sff::transport {
namespace {

/// Largest single send/recv request; keeps every length inside an int on every platform.
constexpr std::size_t kMaxIoChunk = std::size_t{1} << 20;

/// Read chunk used by the transport: one frame at most, capped for locality.
constexpr std::size_t kMaxChunkBytes = std::size_t{64} << 10;

#if defined(_WIN32)
using IoResult = int;
using SockLen = int;
#else
using IoResult = ssize_t;
using SockLen = socklen_t;
#endif

#if !defined(_WIN32) && defined(MSG_NOSIGNAL)
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

int last_error() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

bool is_interrupted(int error) noexcept {
#if defined(_WIN32)
  return error == WSAEINTR;
#else
  return error == EINTR;
#endif
}

bool is_connection_gone(int error) noexcept {
#if defined(_WIN32)
  return error == WSAECONNRESET || error == WSAECONNABORTED || error == WSAENOTSOCK ||
         error == WSAESHUTDOWN || error == WSAENOTCONN;
#else
  return error == ECONNRESET || error == ENOTCONN || error == EBADF || error == EPIPE ||
         error == ECONNABORTED;
#endif
}

Status socket_failure(Code code, std::string_view what, int error) {
  std::string message(what);
  message += " failed (";
  message += std::to_string(error);
  message += ")";
  return Status::failure(code, message);
}

void shutdown_native(NativeSocket handle) noexcept {
#if defined(_WIN32)
  (void)::shutdown(handle, SD_BOTH);
#else
  (void)::shutdown(handle, SHUT_RDWR);
#endif
}

void close_native(NativeSocket handle) noexcept {
#if defined(_WIN32)
  (void)::closesocket(handle);
#else
  (void)::close(handle);
#endif
}

/// Best-effort latency and robustness settings for a connected stream socket.
void tune_connected_socket(NativeSocket handle) noexcept {
  const int enabled = 1;
#if defined(_WIN32)
  (void)::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&enabled),
                     static_cast<int>(sizeof enabled));
#else
  (void)::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled);
#  if defined(SO_NOSIGPIPE)
  (void)::setsockopt(handle, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof enabled);
#  endif
#endif
}

void free_addresses(addrinfo* addresses) noexcept {
  if (addresses != nullptr) ::freeaddrinfo(addresses);
}

std::uint16_t portable_port(const sockaddr_storage& storage) noexcept {
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    return ntohs(address->sin_port);
  }
  if (storage.ss_family == AF_INET6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(&storage);
    return ntohs(address->sin6_port);
  }
  return 0;
}

int bounded_backlog(std::size_t backlog) noexcept {
  const std::size_t capped =
      std::min<std::size_t>(backlog, static_cast<std::size_t>(INT_MAX));
  return static_cast<int>(capped == 0 ? 1 : capped);
}

}  // namespace

// --- Socket ---------------------------------------------------------------------------------

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = kInvalidSocket;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalidSocket;
  }
  return *this;
}

void Socket::shutdown() noexcept {
  if (handle_ == kInvalidSocket) return;
  shutdown_native(handle_);
}

void Socket::close() noexcept {
  if (handle_ == kInvalidSocket) return;
  const NativeSocket handle = handle_;
  handle_ = kInvalidSocket;
  shutdown_native(handle);
  close_native(handle);
}

// --- GuardedSocket --------------------------------------------------------------------------

GuardedSocket::~GuardedSocket() {
  std::lock_guard<std::mutex> lock(mutex_);
  socket_.close();
}

Status GuardedSocket::reset(Socket socket) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (closing_) {
    socket.close();
    return Status::failure(Code::Closed, "socket is closing");
  }
  if (socket_.valid()) {
    socket.close();
    return Status::failure(Code::AlreadyExists, "socket already holds a handle");
  }
  socket_ = std::move(socket);
  return Status::success();
}

bool GuardedSocket::begin() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (closing_ || !socket_.valid()) return false;
  ++active_;
  return true;
}

void GuardedSocket::end() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (active_ > 0) --active_;
}

void GuardedSocket::request_close() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (closing_) return;
  closing_ = true;
  // Socket::close() shuts the connection down and closes the handle. On POSIX the shutdown is what
  // releases a blocked recv(); on Windows the handle close is. Doing both here, once, under this
  // lock is what makes shutdown deterministic on both and keeps the handle from being closed
  // twice. begin() refuses from now on, so the released thread performs no further I/O on it.
  socket_.close();
}

bool GuardedSocket::closing() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return closing_;
}

bool GuardedSocket::valid() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return !closing_ && socket_.valid();
}

Socket* GuardedSocket::socket() { return &socket_; }

bool GuardedSocket::idle() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return active_ == 0;
}

// --- process-wide network state ---------------------------------------------------------------

Status ensure_network_ready() {
#if defined(_WIN32)
  static std::once_flag once;
  static int startup_error = 0;
  std::call_once(once, []() {
    WSADATA data{};
    startup_error = ::WSAStartup(MAKEWORD(2, 2), &data);
  });
  if (startup_error != 0) {
    return socket_failure(Code::IoError, "WSAStartup", startup_error);
  }
#endif
  return Status::success();
}

std::size_t effective_max_frame_payload(const Limits& limits) noexcept {
  return std::min<std::size_t>(limits.max_frame_payload, kHardMaxFramePayload);
}

std::size_t transport_chunk_bytes(const Limits& limits) noexcept {
  const auto body = checked_add(kFrameHeaderBytes, effective_max_frame_payload(limits));
  const auto frame_bytes =
      body ? checked_add(*body, kFrameTrailerBytes) : std::optional<std::size_t>();
  if (!frame_bytes) return kMaxChunkBytes;
  return std::max<std::size_t>(std::min<std::size_t>(*frame_bytes, kMaxChunkBytes),
                               kFrameHeaderBytes + kFrameTrailerBytes);
}

// --- connection setup -------------------------------------------------------------------------

Result<Socket> connect_tcp(const std::string& host, std::uint16_t port) {
  if (host.empty()) {
    return Result<Socket>(Status::failure(Code::Invalid, "empty host"));
  }
  const std::string service = std::to_string(port);
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* addresses = nullptr;
  const int resolved = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses);
  if (resolved != 0 || addresses == nullptr) {
    free_addresses(addresses);
    return Result<Socket>(Status::failure(Code::NotFound, "host resolution failed"));
  }

  Status failure = Status::failure(Code::NotFound, "no usable address");
  for (addrinfo* candidate = addresses; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      failure = socket_failure(Code::IoError, "socket", last_error());
      continue;
    }
    Socket socket(handle);
    if (::connect(handle, candidate->ai_addr, static_cast<SockLen>(candidate->ai_addrlen)) == 0) {
      tune_connected_socket(handle);
      free_addresses(addresses);
      return Result<Socket>(std::move(socket));
    }
    failure = socket_failure(Code::IoError, "connect", last_error());
    socket.close();
  }
  free_addresses(addresses);
  return Result<Socket>(failure);
}

Result<Socket> listen_tcp(const std::string& bind_address, std::uint16_t port, std::size_t backlog,
                          std::uint16_t& out_port) {
  out_port = 0;
  if (bind_address.empty()) {
    return Result<Socket>(Status::failure(Code::Invalid, "empty bind address"));
  }
  const std::string service = std::to_string(port);
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* addresses = nullptr;
  const int resolved = ::getaddrinfo(bind_address.c_str(), service.c_str(), &hints, &addresses);
  if (resolved != 0 || addresses == nullptr) {
    free_addresses(addresses);
    return Result<Socket>(Status::failure(Code::Invalid, "bind address resolution failed"));
  }

  Status failure = Status::failure(Code::IoError, "bind failed");
  const int backlog_value = bounded_backlog(backlog);
  for (addrinfo* candidate = addresses; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      failure = socket_failure(Code::IoError, "socket", last_error());
      continue;
    }
    Socket socket(handle);
#if !defined(_WIN32)
    const int enabled = 1;
    (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled);
#endif
    if (::bind(handle, candidate->ai_addr, static_cast<SockLen>(candidate->ai_addrlen)) != 0) {
      failure = socket_failure(Code::IoError, "bind", last_error());
      socket.close();
      continue;
    }
    if (::listen(handle, backlog_value) != 0) {
      failure = socket_failure(Code::IoError, "listen", last_error());
      socket.close();
      continue;
    }
    sockaddr_storage storage{};
    SockLen length = static_cast<SockLen>(sizeof storage);
    if (::getsockname(handle, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
      failure = socket_failure(Code::IoError, "getsockname", last_error());
      socket.close();
      continue;
    }
    out_port = portable_port(storage);
    free_addresses(addresses);
    return Result<Socket>(std::move(socket));
  }
  free_addresses(addresses);
  return Result<Socket>(failure);
}

Result<Socket> accept_tcp(const Socket& listener) {
  if (!listener.valid()) {
    return Result<Socket>(Status::failure(Code::Closed, "listener is closed"));
  }
  for (;;) {
    const NativeSocket handle = ::accept(listener.native(), nullptr, nullptr);
    if (handle != kInvalidSocket) {
      tune_connected_socket(handle);
      return Result<Socket>(Socket(handle));
    }
    const int error = last_error();
    if (is_interrupted(error)) continue;
    return Result<Socket>(socket_failure(is_connection_gone(error) ? Code::Closed : Code::IoError,
                                         "accept", error));
  }
}

Status send_all(const Socket& socket, const std::uint8_t* data, std::size_t size) {
  if (!socket.valid()) {
    return Status::failure(Code::Closed, "socket is closed");
  }
  if (size != 0 && data == nullptr) {
    return Status::failure(Code::Invalid, "null send buffer");
  }
  std::size_t sent = 0;
  while (sent < size) {
    const std::size_t remaining = size - sent;
    const int chunk = static_cast<int>(std::min<std::size_t>(remaining, kMaxIoChunk));
#if defined(_WIN32)
    const IoResult written =
        ::send(socket.native(), reinterpret_cast<const char*>(data + sent), chunk, kSendFlags);
#else
    const IoResult written = ::send(socket.native(), data + sent, static_cast<std::size_t>(chunk),
                                    kSendFlags);
#endif
    if (written > 0) {
      sent += static_cast<std::size_t>(written);
      continue;
    }
    if (written == 0) {
      return Status::failure(Code::Closed, "peer closed during send");
    }
    const int error = last_error();
    if (is_interrupted(error)) continue;
    return socket_failure(is_connection_gone(error) ? Code::Closed : Code::IoError, "send", error);
  }
  return Status::success();
}

Status receive_some(const Socket& socket, std::uint8_t* data, std::size_t capacity,
                    std::size_t& received) {
  received = 0;
  if (!socket.valid()) {
    return Status::failure(Code::Closed, "socket is closed");
  }
  if (data == nullptr || capacity == 0) {
    return Status::failure(Code::Invalid, "empty receive buffer");
  }
  for (;;) {
    const int chunk = static_cast<int>(std::min<std::size_t>(capacity, kMaxIoChunk));
#if defined(_WIN32)
    const IoResult read = ::recv(socket.native(), reinterpret_cast<char*>(data), chunk, 0);
#else
    const IoResult read = ::recv(socket.native(), data, static_cast<std::size_t>(chunk), 0);
#endif
    if (read >= 0) {
      // A zero-length read is an orderly close, reported with an Ok status and received == 0.
      received = static_cast<std::size_t>(read);
      return Status::success();
    }
    const int error = last_error();
    if (is_interrupted(error)) continue;
    return socket_failure(is_connection_gone(error) ? Code::Closed : Code::IoError, "recv", error);
  }
}

Result<std::pair<Socket, Socket>> make_wakeup_pair() {
#if defined(_WIN32)
  // Winsock has no socketpair(), so the wakeup channel is a connected loopback TCP pair.
  std::uint16_t port = 0;
  auto listener = listen_tcp("127.0.0.1", 0, 1, port);
  if (!listener.ok()) return Result<std::pair<Socket, Socket>>(listener.status());
  auto writer = connect_tcp("127.0.0.1", port);
  if (!writer.ok()) return Result<std::pair<Socket, Socket>>(writer.status());
  auto reader = accept_tcp(listener.value());
  if (!reader.ok()) return Result<std::pair<Socket, Socket>>(reader.status());
  listener.value().close();
  return Result<std::pair<Socket, Socket>>(
      std::make_pair(std::move(reader.value()), std::move(writer.value())));
#else
  int handles[2] = {-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, handles) != 0) {
    return Result<std::pair<Socket, Socket>>(socket_failure(Code::IoError, "socketpair", errno));
  }
  return Result<std::pair<Socket, Socket>>(
      std::make_pair(Socket(handles[0]), Socket(handles[1])));
#endif
}

void wake_socket(const Socket& writer) noexcept {
  if (!writer.valid()) return;
  const char byte = 1;
  (void)::send(writer.native(), &byte, 1, kSendFlags);
}

Status wait_readable_pair(const Socket& a, const Socket& b, bool& a_ready) {
  a_ready = false;
  if (!a.valid() || !b.valid()) {
    return Status::failure(Code::Closed, "wakeup channel is closed");
  }
#if defined(_WIN32)
  for (;;) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(a.native(), &readable);
    FD_SET(b.native(), &readable);
    const int ready = ::select(0, &readable, nullptr, nullptr, nullptr);
    if (ready > 0) {
      a_ready = FD_ISSET(a.native(), &readable) != 0;
      return Status::success();
    }
    if (ready == 0) continue;
    const int error = last_error();
    if (is_interrupted(error)) continue;
    return socket_failure(Code::IoError, "select", error);
  }
#else
  for (;;) {
    pollfd descriptors[2] = {};
    descriptors[0].fd = a.native();
    descriptors[0].events = POLLIN;
    descriptors[1].fd = b.native();
    descriptors[1].events = POLLIN;
    const int ready = ::poll(descriptors, 2, -1);
    if (ready > 0) {
      const short wake_events = static_cast<short>(POLLIN | POLLHUP | POLLERR);
      if ((descriptors[1].revents & wake_events) != 0) {
        a_ready = false;
        return Status::success();
      }
      if ((descriptors[0].revents & wake_events) != 0) {
        a_ready = true;
        return Status::success();
      }
      continue;
    }
    if (ready == 0) continue;
    if (is_interrupted(errno)) continue;
    return socket_failure(Code::IoError, "poll", errno);
  }
#endif
}

}  // namespace sff::transport
