#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/connection_impl.hpp>

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


/*
template<typename T>
class deferred_init {
    alignas(T) std::byte data[sizeof(T)];
    bool init = false;

    auto t() -> T& { return *std::launder(reinterpret_cast<T*>(&data)); }

    template<typename U>
    friend class out;

    auto destroy() -> void         { if (init) { t().~T(); }  init = false; }

public:
    deferred_init() noexcept       { }
   ~deferred_init() noexcept       { destroy(); }
    auto value()    noexcept -> T& { Default.expects(init);  return t(); }

    auto construct(auto&& ...args) -> void { Default.expects(!init);  new (&data) T{CPP2_FORWARD(args)...};  init = true; }
};
*/

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
  udp::socket socket; /* requirements: close() 
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

  socket_impl(engine_impl& engine, udp::socket&& socket,
              ssl::context& ssl);
  socket_impl(engine_impl& engine, const udp::endpoint& endpoint,
              bool is_server, ssl::context& ssl);
  ~socket_impl() {
    close();
  }

  using executor_type = boost::asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint local_endpoint() const { return local_addr; }

  void listen(int backlog);

  void connect(connection_impl& c,
               const udp::endpoint& endpoint,
               const char* hostname);
  void on_connect(connection_impl& c, lsquic_conn* conn);

  void accept(connection_impl& c, accept_operation& op);
  connection_context* on_accept(lsquic_conn* conn);

  template <typename Connection, typename CompletionToken>
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
