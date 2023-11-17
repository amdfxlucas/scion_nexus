#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/connection_impl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <boost/asio.hpp>
#include <variant>
#include "pan.hpp"
#include <nexus/quic/detail/quic-debug.hpp>

struct lsquic_conn;
struct lsquic_out_spec;

namespace nexus::quic::detail {

struct engine_impl;
struct connection_impl;

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr addr;
  sockaddr_in addr4;
  sockaddr_in6 addr6;
};



 using pan_sock_t = boost::asio::local::datagram_protocol::socket;

using connection_list = boost::intrusive::list<connection_impl>;

inline void list_erase(connection_impl& s, connection_list& from)
{
  from.erase(from.iterator_to(s));
}

inline void list_transfer(connection_impl& s, connection_list& from,
                          connection_list& to)
{
  from.erase(from.iterator_to(s));
  to.push_back(s);
}

struct socket_impl : boost::intrusive::list_base_hook<> {
  engine_impl& engine;
  std::variant<std::monostate,udp::socket,pan_sock_t> socket; 
  asio::signal_set m_signals;

  std::shared_ptr<Pan::udp::ListenConn > m_listen_conn;
  std::shared_ptr<Pan::udp::ListenSockAdapter> m_listen_sock_adapter;
  std::shared_ptr<Pan::udp::Conn> m_conn;
  std::shared_ptr<Pan::udp::ConnSockAdapter> m_conn_adapter;


  /* requirements: close() 
                      async_wait(wait_type, token)   // /usr/local/include/boost/asio/basic_socket.hpp
                     boost::asio::ip::udp::endpoint local_endpoint()
                      native_handle()  // src/socket.cc 
                      cancel()
   */



  ssl::context& ssl;
  udp::endpoint local_addr; // socket's bound address
  /* requirements: data() -> returns asio::basic_endpoint<>::data_type
                    which is boost::asio::detail::sock_addr_type
                    which ultimately is a unix    struct sockaddr{ char sa_data[14]; sa_family_t sa_family;}  
                    (with sa_family_t == unsigned short int )
  */

  boost::circular_buffer<incoming_connection> incoming_connections;
  connection_list accepting_connections;
  connection_list open_connections;
  bool receiving = false;
  std::string m_go_path;
  std::string m_path;

// for scion_client only ?!
  socket_impl( engine_impl& e,ssl::context& s )
  :engine(e),
  ssl(s) ,
  m_signals(get_executor(),SIGINT) ,
  socket(pan_sock_t( e.get_executor()) )
  {
     m_signals.async_wait( std::bind(&socket_impl::cancel_on_signal,
      this, std::placeholders::_1, std::placeholders::_2) );
  }

// for scion_client and scion_acceptor only
  socket_impl( engine_impl& e,ssl::context& s , const udp::endpoint& local )
  :engine(e),
  ssl(s) ,
  m_signals(get_executor(),SIGINT),
  local_addr(local),
  socket(pan_sock_t( e.get_executor()) )
   {
     m_signals.async_wait( std::bind(&socket_impl::cancel_on_signal,
      this, std::placeholders::_1, std::placeholders::_2) );
   }


  socket_impl(engine_impl& engine, udp::socket&& socket, ssl::context& ssl);
  socket_impl(engine_impl& engine, pan_sock_t&& socket, ssl::context& ssl, const udp::endpoint& endpoint );

  socket_impl(engine_impl& engine, const udp::endpoint& endpoint,  bool is_server, ssl::context& ssl);

  ~socket_impl() {
    close();
  }

  void cancel();

  using executor_type = boost::asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint local_endpoint() const { return local_addr; }
  std::string local_address()const ;

  void listen(int backlog);

  void prepare_scion_server( std::function< void (const system::error_code& err )> on_connected
              = [](const system::error_code&  ){ qDebug("server unix domain socket connected") ;} 
              );
  void prepare_scion_client( const Pan::udp::Endpoint& remote,
                            std::function< void (const system::error_code& err )> on_connected =
                             [](const system::error_code&  )
                             {qDebug( "client unix domain socket connected" ); } 
                              );

  void connect(connection_impl& c,
               const udp::endpoint& endpoint,
               const std::string_view& hostname);

  void connect( connection_impl&c ,
                const Pan::udp::Endpoint& endpoint,
                const std::string_view& hostname );

                void connect_impl( connection_impl&c ,
                const sockaddr* endpoint,
                const std::string_view& hostname );

  void cancel_on_signal( const system::error_code&code, int signal );


  void on_connect(connection_impl& c, lsquic_conn* conn);

  void accept(connection_impl& c, accept_operation& op);
  connection_context* on_accept(lsquic_conn* conn);

  template <typename Connection, typename CompletionToken>
  requires requires { std::is_invocable_v<CompletionToken,error_code>; }
  decltype(auto) async_accept(Connection& conn,
                              CompletionToken&& token) {
    auto& c = conn.impl;
    return boost::asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &c] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          accept(c, *op);
          op.release(); // release ownership
        }, token);
  }

  void close();

  void abort_connections(error_code ec);

  void start_recv();
  void on_readable();
  void on_writeable();

  const lsquic_out_spec* send_packets(const lsquic_out_spec* begin,
                                      const lsquic_out_spec* end,
                                      error_code& ec);

  size_t recv_packet(iovec iov, udp::endpoint& peer, sockaddr_union& self,
                     int& ecn, error_code& ec);
};

} // namespace nexus::quic::detail
