#include <nexus/quic/socket.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>
#include <array>
#include <format>
#include <cstring>

#include <netinet/ip.h>
#include <lsquic.h>

#include <cstdlib>
#include <nexus/quic/detail/sockaddr_scion.hpp>
#include <iostream>
// #include <dirent.h>
// #include <sys/types.h>
#include "pan.hpp"
#include "tracing.hpp"
#include <nexus/quic/detail/quic-debug.hpp>

using namespace std;

namespace nexus::quic
{

  template <typename socket_t>
  void prepare_socket(socket_t &sock, bool is_server, error_code &ec)
  {
    if (sock.non_blocking(true, ec); ec)
    {
      return;
    }

    // not supported with unix domain sockets
    if constexpr (!std::is_same_v<socket_t, asio::local::datagram_protocol::socket>)
      if (sock.set_option(receive_ecn{true}, ec); ec)
      {
        return;
      }

    // not supported with unix domain sockets
    if constexpr (!std::is_same_v<socket_t, asio::local::datagram_protocol::socket>)
      if (is_server)
      {
        ec = nexus::detail::set_options(sock, receive_dstaddr{true},
                                        udp::socket::reuse_address{true});
      }
  }

  namespace detail
  {

    static udp::socket bind_socket(const boost::asio::any_io_executor &ex,
                                   const udp::endpoint &endpoint, bool is_server)
    {
      // open the socket
      auto socket = udp::socket{ex, endpoint.protocol()};
      // set socket options before bind(), because the server enables REUSEADDR
      error_code ec;
      prepare_socket(socket, is_server, ec);
      if (ec)
      {
        throw system_error(ec);
      }
      socket.bind(endpoint); // may throw
      return socket;
    }

    void socket_impl::cancel()
    {
      if (auto usock = std::get_if<udp::socket>(&socket))
      {
        usock->cancel();
      }
      else if (auto psock = std::get_if<pan_sock_t>(&socket))
      {
        psock->cancel();
      }

      // SockToPtr()->cancel();
    }

    socket_impl::socket_impl(engine_impl &engine, udp::socket &&sock,
                             ssl::context &ssl)
        : engine(engine),
          socket(std::move(sock)),
          ssl(ssl),
          m_signals(get_executor(), SIGINT)
    //    local_addr( SockToPtr()->local_endpoint())
    {
      if (auto usock = std::get_if<udp::socket>(&socket))
      {
        local_addr = usock->local_endpoint();
      }

      m_signals.async_wait(std::bind(&socket_impl::cancel_on_signal, this, std::placeholders::_1, std::placeholders::_2));
    }

    socket_impl::socket_impl(engine_impl &engine, pan_sock_t &&socket,
                             ssl::context &ssl, const udp::endpoint &endpoint)
        : engine(engine),
          socket(std::move(socket)),
          ssl(ssl),
          m_signals(get_executor(), SIGINT),
          local_addr(endpoint)
    {
      m_signals.async_wait(std::bind(&socket_impl::cancel_on_signal, this, std::placeholders::_1, std::placeholders::_2));
    }

    socket_impl::socket_impl(engine_impl &engine, const udp::endpoint &endpoint,
                             bool is_server, ssl::context &ssl)
        : engine(engine),
          socket(bind_socket(engine.get_executor(), endpoint, is_server)),
          ssl(ssl),
          local_addr(endpoint),
          m_signals(get_executor(), SIGINT)
    {
      // socket.get<udp::socket>.local_end
      m_signals.async_wait(std::bind(&socket_impl::cancel_on_signal, this, std::placeholders::_1, std::placeholders::_2));
    }

    socket_impl::executor_type socket_impl::get_executor() const
    {
      return engine.get_executor();
    }

    void socket_impl::listen(int backlog)
    {
      auto lock = std::unique_lock{engine.mutex};
      incoming_connections.set_capacity(backlog);
      start_recv();
    }

    void socket_impl::cancel_on_signal(const system::error_code &error, int signal)
    {
      if (error)
      {
        std::cerr << "ASIO error: " << error.message() << std::endl;
        return;
      }

      if (signal == SIGINT)
      {
        close();
      }
    }

    std::string socket_impl::local_address() const
    {
      std::string local = local_endpoint().address().to_string() + ":" + std::to_string(local_endpoint().port());
      return local;
    }

    void socket_impl::prepare_scion_client(
        const Pan::udp::Endpoint &remote,
        std::function<void(const system::error_code &err)> on_connected)
    {
      m_conn = std::make_shared<Pan::udp::Conn>();
      // m_conn_adapter = std::make_shared<Pan::udp::ConnSockAdapter>();
      // socket = pan_sock_t( get_executor());

      /* system::error_code eec;
       prepare_socket( std::get<pan_sock_t>(socket) , false, eec );
       if(eec)
       {
         throw std::runtime_error( eec.message() );
       }
     */

      using namespace std::placeholders;
      using asio::local::datagram_protocol;
      srand(time(0));
      auto rnd = rand();
      m_go_path = std::format("/tmp/scion_async_client_go_{}.sock", rnd);
      m_path = std::format("/tmp/scion_async_client_{}.sock", rnd);

      std::cout << "about to dial: " << remote.toString() << std::endl;
      m_conn->dial(local_address().c_str(), remote);

      std::get<pan_sock_t>(socket).open();

      system::error_code eec;
      prepare_socket(std::get<pan_sock_t>(socket), false, eec);
      if (eec)
      {
        throw std::runtime_error(eec.message());
      }

      // std::remove(m_path);
      std::get<pan_sock_t>(socket).bind(datagram_protocol::endpoint(m_path));
      m_conn_adapter = std::make_shared<Pan::udp::ConnSockAdapter>(m_conn->createSockAdapter(m_go_path.c_str(), m_path.c_str()));

      std::cout << "client unix domain fd: " << std::get<pan_sock_t>(socket).native_handle() << std::endl;

      std::get<pan_sock_t>(socket).async_connect(
          datagram_protocol::endpoint(m_go_path),
          on_connected
          // std::bind(&Client::connected, this, _1)
      );

      // ioContext.run();
      //  socket.close();
      //  adapter.close();
      //  std::remove(socketPath);

      /*void connected(const system::error_code& error)
      {
          using namespace std::placeholders;

          if (error) {
              std::cerr << "ASIO error: " << error.message() << std::endl;
              return;
          }

        //  socket.async_send(asio::buffer(buffer), std::bind(&Client::sent, this, _1, _2));
      }
  */
    }

    void socket_impl::prepare_scion_server(std::function<void(const system::error_code &err)> on_connected)
    {
      m_listen_conn = std::make_shared<Pan::udp::ListenConn>();
      srand(time(0));
      int rnd = rand();
      m_go_path = std::format("/tmp/scion_async_server_go_{}.sock", rnd);
      m_path = std::format("/tmp/scion_async_server_{}.sock", rnd);

      m_listen_conn->listen(local_address().c_str());
      std::cout << "ListenConn listening at: " << m_listen_conn->getLocalEndpoint().toString() << std::endl;

      using asio::local::datagram_protocol;
      socket = datagram_protocol::socket(get_executor());

      std::get<pan_sock_t>(socket).open();

      system::error_code eec;
      prepare_socket(std::get<pan_sock_t>(socket), true, eec);
      if (eec)
      {
        throw std::runtime_error(eec.message());
      }

      // std::remove(socketPath);

      std::get<pan_sock_t>(socket).bind(datagram_protocol::endpoint(m_path.c_str()));

      m_listen_sock_adapter = std::make_shared<Pan::udp::ListenSockAdapter>(m_listen_conn->createSockAdapter(m_go_path.c_str(), m_path.c_str()));

      std::cout << "unix domain sock fd: " << std::get<pan_sock_t>(socket).native_handle() << std::endl;

      std::get<pan_sock_t>(socket).async_connect(
          datagram_protocol::endpoint(m_go_path.c_str()),
          // std::bind(&Server::connected, this, std::placeholders::_1)
          on_connected
          // std::bind(&Client::connected, this, _1)

      );

      // m_signals.async_wait(std::bind(&Server::cancel, this, std::placeholders::_1, std::placeholders::_2));

      //        ioContext.run();

      //      socket.close();
      //     adapter.close();
      // std::remove( m_path );
    }

    /* called by scion_client ctor
     */
    void socket_impl::connect(connection_impl &c,
                              const Pan::udp::Endpoint &endpoint,
                              const std::string_view &hostname)
    {
      prepare_scion_client(endpoint);

      [&]()
      {
        sockaddr hash = hashSockaddr(endpoint);
        auto remote = ScionUDPAddr(endpoint.toString());

        addrMapper::instance().insertMapping(hash, remote);

        // auto* ptr_data = std::get<pan_sock_t>(socket).local_endpoint().data();
        // asio::local::datagram_protocol::endpoint remote(m_go_path);

        // udp::endpoint trick2{ endpoint.getIP()};

        //   auto before_fam = ptr_data->sa_family;
        // auto before_dat = ptr_data->sa_data;
        //  ptr_data->sa_family= AF_INET;

        // udp::endpoint trick{ reinterpret_cast<udp::endpoint*>(&remote) };

        connect_impl(c, // remote.data(),
                        // ptr_data,
                     &hash,
                     hostname);

        //       ptr_data->sa_family = before_fam;
      }();

      // connect_impl(c, std::get<pan_sock_t>(socket).local_endpoint().data() ,hostname);
    }

    void socket_impl::connect(connection_impl &c,
                              const udp::endpoint &endpoint,
                              const std::string_view &hostname)
    {
      connect_impl(c, endpoint.data(), hostname);
    }

    void socket_impl::connect_impl(connection_impl &c, const sockaddr *endpoint, const std::string_view &hostname)
    {
      assert(&c.socket == this);
      auto lock = std::unique_lock{engine.mutex};
      auto peer_ctx = this;
      auto cctx = reinterpret_cast<lsquic_conn_ctx_t *>(&c);
      ::lsquic_engine_connect(engine.handle.get(), N_LSQVER,
                              local_addr.data(), endpoint, peer_ctx, cctx,
                              hostname.data(), 0, nullptr, 0, nullptr, 0);
      // note, this assert triggers with some quic versions that don't allow
      // multiple connections on the same address, see lquic's hash_conns_by_addr()
      assert(connection_state::is_open(c.state));
      engine.process(lock);

      std::cout << "errno after connect: " << errno << std::endl;

      start_recv();
    }
    // precondition: connection_impl::state is 'closed'
    void socket_impl::on_connect(connection_impl &c, lsquic_conn_t *conn)
    {
      HANDLER_LOCATION;
      qDebug("invoked");
      connection_state::on_connect(c.state, conn);
      open_connections.push_back(c);
    }

    void socket_impl::accept(connection_impl &c, accept_operation &op)
    {
      auto lock = std::unique_lock{engine.mutex};
      if (!incoming_connections.empty())
      {
        auto incoming = std::move(incoming_connections.front());
        incoming_connections.pop_front();
        open_connections.push_back(c);
        // when we accepted this, we had to return nullptr for the conn ctx
        // because we didn't have this connection_impl yet. update the ctx
        auto ctx = reinterpret_cast<lsquic_conn_ctx_t *>(&c);
        ::lsquic_conn_set_ctx(incoming.handle, ctx);
        connection_state::accept_incoming(c.state, std::move(incoming));
        op.post(error_code{}); // success
        return;
      }
      connection_state::accept(c.state, op);
      accepting_connections.push_back(c);
      engine.process(lock);
    }

    connection_context *socket_impl::on_accept(lsquic_conn_t *conn)
    {
      assert(conn);
      if (accepting_connections.empty())
      {
        // not waiting on accept, try to queue this for later
        if (incoming_connections.full())
        {
          ::lsquic_conn_close(conn);
          return nullptr;
        }
        incoming_connections.push_back({conn, engine.max_streams_per_connection});
        return &incoming_connections.back();
      }
      auto &c = accepting_connections.front();
      list_transfer(c, accepting_connections, open_connections);

      connection_state::on_accept(c.state, conn);
      return &c;
    }

    void socket_impl::abort_connections(error_code ec)
    {
      // close incoming streams that we haven't accepted yet
      while (!incoming_connections.empty())
      {
        auto &incoming = incoming_connections.front();
        ::lsquic_conn_close(incoming.handle); // also closes incoming_streams
        incoming_connections.pop_front();
      }
      // close open connections on this socket
      while (!open_connections.empty())
      {
        auto &c = open_connections.front();
        open_connections.pop_front();
        connection_state::reset(c.state, ec);
      }
      // cancel connections pending accept
      while (!accepting_connections.empty())
      {
        auto &c = accepting_connections.front();
        accepting_connections.pop_front();
        connection_state::reset(c.state, ec);
      }
    }

    void socket_impl::close()
    {
      auto lock = std::unique_lock{engine.mutex};
      abort_connections(make_error_code(connection_error::aborted));
      // send any CONNECTION_CLOSE frames before closing the socket
      engine.process(lock);
      receiving = false;
      //  socket.close();
      // SockToPtr()->close();

      if (auto usock = std::get_if<udp::socket>(&socket))
      {
        usock->close();
      }
      else if (auto psock = std::get_if<pan_sock_t>(&socket))
      {
        psock->close();
      }

      if (m_conn)
      {
        m_conn->close();
      }
      if (m_conn_adapter)
      {
        m_conn_adapter->close();
      }
      if (m_listen_conn)
      {
        m_listen_conn->close();
      }
      if (m_listen_sock_adapter)
      {
        m_listen_sock_adapter->close();
      }

      if (!m_path.empty())
      {
        std::remove(m_path.c_str());
      }
      // if(!m_go_path.empty() ){std::remove(m_go_path);}
    }

    void socket_impl::start_recv()
    {
      if (receiving)
      {
        return;
      }
      receiving = true;

      auto cb = [this](error_code ec)
      {
        receiving = false;
        if (!ec)
        {
          on_readable();
        } // XXX: else fatal? retry?
        else
        {
          std::cout << "start_recv cb: " << ec.message() << " errno: " << errno << std::endl;
        }
      };

      if (auto usock = std::get_if<udp::socket>(&socket))
      {
        usock->async_wait(boost::asio::socket_base::wait_read, cb);
      }
      else if (auto psock = std::get_if<pan_sock_t>(&socket))
      {
        psock->async_wait(boost::asio::socket_base::wait_read, cb);
      }
    }

    void socket_impl::on_readable()
    {
      std::array<unsigned char, 4096> buffer;
      iovec iov;
      iov.iov_base = buffer.data();
      iov.iov_len = buffer.size();

      error_code ec;
      for (;;)
      {
        udp::endpoint peer;
        sockaddr_union self;
        int ecn = 0;

        const auto bytes = recv_packet(iov, peer, self, ecn, ec);
        if (ec)
        {
          if (ec == errc::resource_unavailable_try_again ||
              ec == errc::operation_would_block)
          {
            start_recv();
          } // XXX: else fatal? retry?
          return;
        }

        auto lock = std::unique_lock{engine.mutex};
        const auto peer_ctx = this;
        ::lsquic_engine_packet_in(engine.handle.get(),
                                   buffer.data(),   // this must change to iov.iov_base for scion !!
                                   bytes,
                                  &self.addr,
                                   peer.data(),
                                    peer_ctx, ecn);
        engine.process(lock);
      }
    }

    void socket_impl::on_writeable()
    {
      auto lock = std::scoped_lock{engine.mutex};
      ::lsquic_engine_send_unsent_packets(engine.handle.get());
    }

    auto socket_impl::send_packets(const lsquic_out_spec *begin,
                                   const lsquic_out_spec *end,
                                   error_code &ec)
        -> const lsquic_out_spec *
    {
      msghdr msg{};
      msg.msg_flags = 0;

      // send until we encounter a packet with a different peer_ctx
      auto p = begin;
      for (; p < end && p->peer_ctx == begin->peer_ctx; ++p)
      {
        msg.msg_name = const_cast<void *>(static_cast<const void *>(p->dest_sa));
        if (p->dest_sa->sa_family == AF_INET)
        {
          msg.msg_namelen = sizeof(struct sockaddr_in);
        }
        else
        {
          msg.msg_namelen = sizeof(struct sockaddr_in6);
        }

        msg.msg_iov = p->iov;
        msg.msg_iovlen = p->iovlen;

        constexpr size_t ecn_size = sizeof(int); // TODO: add DSTADDR
        constexpr size_t max_control_size = CMSG_SPACE(ecn_size);
        auto control = std::array<unsigned char, max_control_size>{};
        if (p->ecn)
        {
          msg.msg_control = control.data();
          msg.msg_controllen = control.size();

          cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
          if (p->dest_sa->sa_family == AF_INET)
          {
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
          }
          else
          {
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_TCLASS;
          }
          cmsg->cmsg_len = CMSG_LEN(ecn_size);
          ::memcpy(CMSG_DATA(cmsg), &p->ecn, ecn_size);
          msg.msg_controllen = CMSG_SPACE(ecn_size);
        }
        else
        {
          msg.msg_controllen = 0;
          msg.msg_control = nullptr;
        }

        int err_send;
        if (auto usock = std::get_if<udp::socket>(&socket))
        {
          auto nhandle = usock->native_handle();
          err_send = ::sendmsg(nhandle, &msg, 0);
        }
        else if (auto psock = std::get_if<pan_sock_t>(&socket))
        {
          int nhandle = psock->native_handle();

          // what if iovlen > 1 ?! do i have to concatenate the vectors ?!
          //   msg.msg_iov = p->iov;
          // msg.msg_iovlen = p->iovlen;
          auto endp = psock->local_endpoint();
          msg.msg_name = const_cast<void *>(static_cast<const void *>(endp.data()));

          msg.msg_namelen = endp.size(); // sizeof(struct sockaddr_in);

          if (msg.msg_iovlen > 1)
          {
            std::cout << "msg_iovlen: " << msg.msg_iovlen << " in send_packets()" << std::endl;
          }

          // TODO: add proxy header expected by adapter
          auto scion_remote = addrMapper::instance().lookupHash(*p->dest_sa);

          std::vector<char> buff; // contains original data plus appended header
          auto new_len = msg.msg_iov->iov_len + 32;
          buff.resize(new_len);

          makeProxyHeader(buff.data(), **scion_remote); // might throw bad optional access

          std::memcpy(buff.data() + 32, msg.msg_iov->iov_base, msg.msg_iov->iov_len);

          msg.msg_iov->iov_base = buff.data();
          msg.msg_iov->iov_len = new_len;
          // msg.msg_iovlen = new_len;

          // err_send = ::sendmsg(nhandle, &msg, 0);           // operation not permitted !!

          qDebug(" send: " << new_len << " bytes");
          // auto sock_endp =  asio::local::datagram_protocol::endpoint(m_go_path);
          //  err_send = send(nhandle, msg.msg_iov, msg.msg_iovlen , 0);
          err_send = send(nhandle, buff.data(), new_len, 0);
          // err_send = sendto(nhandle, buff.data(), new_len,0,sock_endp.data(), sock_endp.size() );
        }

        // TODO: send all at once with sendmmsg()
        if (err_send == -1)
        {
          ec.assign(errno, system_category());
          if (ec == errc::resource_unavailable_try_again ||
              ec == errc::operation_would_block)
          {
            // lsquic won't call our send_packets() callback again until we call
            // lsquic_engine_send_unsent_packets()
            // wait for the socket to become writeable again, so we can call that

            auto cb = [this](error_code ec)
            {
              if (!ec)
              {
                on_writeable();
              } // else fatal?
              else
              {
                std::cout << "async_wait_write: " << ec.message() << " errno: " << errno << std::endl;
              }
            };
            if (auto usock = std::get_if<udp::socket>(&socket))
            {
              usock->async_wait(boost::asio::socket_base::wait_write, cb);
            }
            else if (auto psock = std::get_if<pan_sock_t>(&socket))
            {
              psock->async_wait(boost::asio::socket_base::wait_write, cb);
            }

            errno = ec.value(); // lsquic needs to see this errno
          }
          std::cout << "send_packets error " << ec.message() << std::endl;
          break;
        }
      }
      return p;
    }

    constexpr size_t ecn_size = sizeof(int);
#ifdef IP_RECVORIGDSTADDR
    constexpr size_t dstaddr4_size = sizeof(sockaddr_in);
#else
    constexpr size_t dstaddr4_size = sizeof(in_pktinfo)
#endif
    constexpr size_t dstaddr_size = std::max(dstaddr4_size, sizeof(in6_pktinfo));
    constexpr size_t max_control_size = CMSG_SPACE(ecn_size) + CMSG_SPACE(dstaddr_size);

    size_t socket_impl::recv_packet(iovec iov, udp::endpoint &peer,
                                    sockaddr_union &self, int &ecn,
                                    error_code &ec)
    {
      auto msg = msghdr{};

      msg.msg_name = peer.data();
      msg.msg_namelen = peer.size();

      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;

      std::array<unsigned char, max_control_size> control;
      msg.msg_control = control.data();
      msg.msg_controllen = control.size();

      int bytes;
      if (auto usock = std::get_if<udp::socket>(&socket))
      {
        int nhandle = usock->native_handle();
        bytes = ::recvmsg(nhandle, &msg, 0);
      }
      else if (auto psock = std::get_if<pan_sock_t>(&socket))
      {
        int nhandle = psock->native_handle();

        // TODO: remove proxy header
        std::array<char, 4096> buffer;
        // this buffer and the copy-ing can be avoided
        // call recv( iov.base )
        // and adjust afterwards:  iov.base+=32

        bytes = recv(nhandle, buffer.data(), 4096, 0);
        if (bytes > 0)
        {
          qDebug("received " << bytes << " bytes");

          ScionUDPAddr addr = parseProxyHeader(buffer.data(), bytes);

          sockaddr ad = hashSockaddr(addr.toString());

          addrMapper::instance().insertMapping(ad, addr);
          *peer.data() = ad;

          auto payload_len = std::max(bytes - 32, 0);
          iov.iov_len = payload_len;
          std::memcpy(iov.iov_base, buffer.data() + 32, payload_len );

          return payload_len;
        }
      }

      if (bytes == -1)
      {

        ec.assign(errno, system_category());
        qDebug("recv error: " << ec.message());
        return 0;
      }

      if (local_addr.data()->sa_family == AF_INET6)
      {
        ::memcpy(&self.addr6, local_addr.data(), sizeof(sockaddr_in6));
      }
      else
      {
        ::memcpy(&self.addr4, local_addr.data(), sizeof(sockaddr_in));
      }

      for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
      {
        if (cmsg->cmsg_level == IPPROTO_IP)
        {
          if (cmsg->cmsg_type == IP_TOS)
          {
            auto value = reinterpret_cast<const int *>(CMSG_DATA(cmsg));
            ecn = IPTOS_ECN(*value);
#ifdef IP_RECVORIGDSTADDR
          }
          else if (cmsg->cmsg_type == IP_ORIGDSTADDR)
          {
            ::memcpy(&self.storage, CMSG_DATA(cmsg), sizeof(sockaddr_in));
#else
          }
          else if (cmsg->cmsg_type == IP_PKTINFO)
          {
            auto info = reinterpret_cast<const in_pktinfo *>(CMSG_DATA(cmsg));
            self.addr4.sin_addr = info->ipi_addr;
#endif
          }
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6)
        {
          if (cmsg->cmsg_type == IPV6_TCLASS)
          {
            auto value = reinterpret_cast<const int *>(CMSG_DATA(cmsg));
            ecn = IPTOS_ECN(*value);
          }
          else if (cmsg->cmsg_type == IPV6_PKTINFO)
          {
            auto info = reinterpret_cast<const in6_pktinfo *>(CMSG_DATA(cmsg));
            self.addr6.sin6_addr = info->ipi6_addr;
          }
        }
      }
      return bytes;
    }

  } // namespace detail
} // namespace nexus::quic
