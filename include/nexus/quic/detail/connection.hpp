#pragma once

#include <queue>
#include <asio/ip/udp.hpp>
#include <boost/intrusive/list.hpp>
#include <nexus/detail/completion.hpp>
#include <nexus/quic/detail/socket.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/detail/request.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct engine_state;

struct connection_state : public boost::intrusive::list_base_hook<> {
  engine_state& engine;
  lsquic_conn* handle = nullptr;
  connect_request* connect_ = nullptr;
  accept_request* accept_ = nullptr;
  close_request* close_ = nullptr;

  using completion = nexus::detail::completion<void(error_code)>;
  std::unique_ptr<completion> async_connect_;
  std::unique_ptr<completion> async_accept_;

  boost::intrusive::list<stream_state> connecting_streams;
  boost::intrusive::list<stream_state> accepting_streams;
  std::queue<lsquic_stream*> incoming_streams;

  explicit connection_state(engine_state& engine) : engine(engine) {}
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  asio::ip::udp::endpoint remote_endpoint();

  void connect(const asio::ip::udp::endpoint& endpoint,
               const char* hostname, error_code& ec);
  void accept(error_code& ec);
  void close(error_code& ec);
};

} // namespace nexus::quic::detail
