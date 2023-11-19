#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/connection_impl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <boost/asio.hpp>
#include <variant>

#ifdef ENABLE_SCION
#include "pan.hpp"
#include <nexus/quic/detail/quic-debug.hpp>
#endif

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
  boost::asio::signal_set m_signals;
#ifdef ENABLE_SCION
  std::shared_ptr<Pan::udp::ListenConn > m_listen_conn;
  std::shared_ptr<Pan::udp::ListenSockAdapter> m_listen_sock_adapter;
  std::shared_ptr<Pan::udp::Conn> m_conn;
  std::shared_ptr<Pan::udp::ConnSockAdapter> m_conn_adapter;

 bool is_server()const { return static_cast<bool>(m_listen_conn); }
  bool is_client()const {    return  static_cast<bool>(m_conn) ;  }
#endif




  ssl::context& ssl;
  udp::endpoint local_addr; // socket's bound address

  boost::circular_buffer<incoming_connection> incoming_connections;
   // no init to capacity -> this is done in listen( int backlog )
  connection_list accepting_connections;
  connection_list open_connections;
  bool receiving = false;
  std::string m_go_path;
  std::string m_path;

// for scion_client and acceptor only
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

#ifdef ENABLE_SCION
  void prepare_scion_server( std::function< void (const boost::system::error_code& err )> on_connected
              = [](const boost::system::error_code&  ){ qDebug("server unix domain socket connected") ;} 
              );
  void prepare_scion_client( const Pan::udp::Endpoint& remote,
                            std::function< void (const boost::system::error_code& err )> on_connected =
                             [](const boost::system::error_code&  )
                             {qDebug( "client unix domain socket connected" ); } 
                              );
  void connect( connection_impl&c ,
                const Pan::udp::Endpoint& endpoint,
                const std::string_view& hostname );

             

#endif                        

  void connect(connection_impl& c,
               const udp::endpoint& endpoint,
               const std::string_view& hostname);


  void cancel_on_signal( const boost::system::error_code&code, int signal );


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

  size_t recv_packet(iovec& iov, udp::endpoint& peer, sockaddr_union& self,
                     int& ecn, error_code& ec);
private:
   void connect_impl( connection_impl&c ,
                const sockaddr* endpoint,
                const std::string_view& hostname );
#ifdef ENABLE_SCION

/* for clients this address is presented to the lsquic engine as its remote peer's address
 for packets which are received through the unix domain socket.
 It is important that this is the same address, that connect_impl was called with
 This is a workaround because the Pan ConnSockAdapter does not add a proxy-header
 containing the real source address of the packet.
 */

inline const static udp::endpoint m_fake 
= udp::endpoint{ boost::asio::ip::address::from_string("127.0.0.1"), 5555};
inline static sockaddr m_fake_endp = *m_fake.data();
#endif
};

} // namespace nexus::quic::detail
