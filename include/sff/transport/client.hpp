// Switch Failover Fabric - loopback frame client.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_TRANSPORT_CLIENT_HPP
#define SFF_TRANSPORT_CLIENT_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "sff/core/limits.hpp"
#include "sff/core/outcome.hpp"
#include "sff/transport/frame.hpp"
#include "sff/export.hpp"

namespace sff {

/// Blocking, strictly sequential frame client.
///
/// One request is outstanding at a time. The client assigns monotonically increasing request
/// sequences and refuses to reuse one, so a server can always detect a replayed request.
class SFF_API FrameClient {
 public:
  FrameClient(const FrameClient&) = delete;
  FrameClient& operator=(const FrameClient&) = delete;
  ~FrameClient();

  static Result<std::unique_ptr<FrameClient>> connect(std::string host, std::uint16_t port,
                                                      Limits limits = Limits::defaults());

  /// Perform the handshake and adopt the returned session authority.
  Status handshake(std::string_view principal);

  Result<Frame> call(MessageType type, const std::vector<std::uint8_t>& payload,
                     std::uint32_t flags = 0);

  SessionId session() const;
  CoordinatorEpoch epoch() const;
  std::uint64_t boot_digest() const;
  std::uint64_t next_sequence() const;
  bool connected() const;
  bool handshaken() const;

  /// Close the socket, releasing any blocked read.
  Status close();

 private:
  FrameClient();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace sff

#endif  // SFF_TRANSPORT_CLIENT_HPP
