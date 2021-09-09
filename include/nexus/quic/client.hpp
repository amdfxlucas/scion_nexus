#pragma once

#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus::quic {

class client_connection;

class client {
  friend class client_connection;
  detail::engine_state state;
 public:
  client() : state(0) {}
  void close() { state.close(); }
};

class client_connection {
  friend class stream;
  detail::connection_state state;
 public:
  client_connection(client& c, const sockaddr* remote_endpoint,
                    const char* remote_hostname)
      : state(c.state, remote_endpoint, remote_hostname) {}
  void open_stream(detail::stream_state& stream, error_code& ec) {
    state.open_stream(stream, ec);
  }
  void close(error_code& ec) { state.close(ec); }
};

} // namespace nexus::quic