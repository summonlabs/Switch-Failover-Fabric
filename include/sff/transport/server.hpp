// Switch Failover Fabric - loopback frame server.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_TRANSPORT_SERVER_HPP
#define SFF_TRANSPORT_SERVER_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/transport/frame.hpp"
#include "sff/export.hpp"

namespace sff {

struct SFF_API ServerOptions {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;  ///< 0 selects an ephemeral port; read it back with port().
  Limits limits = Limits::defaults();
  std::size_t max_connections = 64;
  std::size_t worker_threads = 4;
  std::size_t accept_backlog = 32;
};

/// A bounded, framed TCP server.
///
/// Trust boundary: the transport is unauthenticated and unencrypted. It binds to loopback by
/// default and is intended for in-host control and for multiprocess proof. Authentication and
/// encryption are out of scope and are not claimed.
class SFF_API FrameServer {
 public:
  using Handler = std::function<Status(const Frame& request, Frame& response)>;

  FrameServer(const FrameServer&) = delete;
  FrameServer& operator=(const FrameServer&) = delete;
  ~FrameServer();

  static Result<std::unique_ptr<FrameServer>> start(const ServerOptions& options, Handler handler);

  std::uint16_t port() const noexcept;
  std::string bound_address() const;
  bool running() const;

  /// Stop accepting, release every blocked accept and read, drain workers and join them.
  /// Idempotent, and never blocks on a peer that has gone silent.
  Status stop();

  std::size_t connections_served() const;
  std::size_t frames_processed() const;
  std::size_t frames_rejected() const;

 private:
  FrameServer();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace sff

#endif  // SFF_TRANSPORT_SERVER_HPP
