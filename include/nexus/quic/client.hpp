#pragma once

#include <nexus/udp.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>
#ifdef ENABLE_SCION
#include "pan.hpp"
#endif

namespace nexus::quic {

class connection;
class stream;


/// a generic QUIC client that owns a UDP socket and uses it to service client
/// connections
class client {
protected:      
  friend class connection;
  
  udp::endpoint m_remote;
  detail::engine_impl engine;
  detail::socket_impl socket;

  friend class client_helper;


 public:
  /// the polymorphic executor type, boost::asio::any_io_executor
  using executor_type = detail::engine_impl::executor_type;

  /// construct the client, taking ownership of a bound UDP socket
  client(udp::socket&& socket, ssl::context& ctx); // TODO: noexcept

  /// construct the client, taking ownership of a bound UDP socket
  client(udp::socket&& socket, ssl::context& ctx, const settings& s); // TODO: noexcept

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, const udp::endpoint& endpoint,
         ssl::context& ctx);

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, const udp::endpoint& endpoint,
         ssl::context& ctx, const settings& s);

  /// return the associated io executor
  executor_type get_executor() const;

  /// return the socket's locally-bound address/port
  udp::endpoint local_endpoint() const;

  virtual std::string remote_address()const;

  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  void connect(connection& conn,
               const udp::endpoint& endpoint,
               const std::string_view& hostname);

  /// close the socket, along with any related connections
  void close(error_code& ec);
  /// \overload
  void close();

  protected:

    /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex,    ssl::context& ctx, const udp::endpoint& endpoint );

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, ssl::context& ctx, const settings& s,
   const udp::endpoint& endpoint );
};

#ifdef ENABLE_SCION
class scion_client : public client {
  friend class connection;
  Pan::udp::Endpoint m_remote;

 public:
  /// the polymorphic executor type, boost::asio::any_io_executor
  using executor_type = detail::engine_impl::executor_type;

  /// construct the client and bind a UDP socket to the given endpoint
  scion_client(const executor_type& ex, const udp::endpoint& endpoint,
         ssl::context& ctx);

  /// construct the client and bind a UDP socket to the given endpoint
  scion_client(const executor_type& ex, const udp::endpoint& endpoint,
         ssl::context& ctx, const settings& s);


  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  void connect(connection& conn,
               const Pan::udp::Endpoint& endpoint,
               const std::string_view& hostname);

virtual std::string remote_address()const;               

  /// close the socket, along with any related connections
  // void close(error_code& ec);
  /// \overload
  // void close();
};
#endif

} // namespace nexus::quic
