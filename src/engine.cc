#include <vector>

#include <lsquic.h>
#include <lsxpack_header.h>

#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/socket.hpp>

namespace nexus::quic::detail {

void engine_deleter::operator()(lsquic_engine* e) const {
  ::lsquic_engine_destroy(e);
}

engine_state::~engine_state()
{
  close();
}

udp::endpoint engine_state::remote_endpoint(connection_state& cstate)
{
  auto remote = udp::endpoint{};
  auto lock = std::scoped_lock{mutex};
  if (cstate.handle) {
    const sockaddr* l = nullptr;
    const sockaddr* r = nullptr;
    lsquic_conn_get_sockaddr(cstate.handle, &l, &r);
    if (r->sa_family == AF_INET6) {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in6));
    } else {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in));
    }
  }
  return remote;
}

void engine_state::connect(connection_state& cstate,
                           const udp::endpoint& endpoint,
                           const char* hostname)
{
  auto lock = std::unique_lock{mutex};
  auto peer_ctx = &cstate.socket;
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(&cstate);
  assert(!cstate.handle);
  ::lsquic_engine_connect(handle.get(), N_LSQVER,
      cstate.socket.local_addr.data(), endpoint.data(), peer_ctx, cctx,
      hostname, 0, nullptr, 0, nullptr, 0);
  assert(cstate.handle); // lsquic_engine_connect() calls on_connect()
  process(lock);
  if (client) { // make sure we're listening
    start_recv(*client);
  }
}

void engine_state::on_connect(connection_state& cstate, lsquic_conn_t* conn)
{
  assert(!cstate.handle);
  cstate.handle = conn;
  cstate.socket.connected.push_back(cstate);
}

void engine_state::on_handshake(connection_state& cstate, int s)
{
  switch (s) {
    case LSQ_HSK_FAIL:
    case LSQ_HSK_RESUMED_FAIL:
      if (!cstate.err) {
        cstate.err = make_error_code(connection_error::handshake_failed);
      }
      break;
  }
}

void engine_state::accept(connection_state& cstate, accept_operation& op)
{
  auto lock = std::unique_lock{mutex};
  if (!cstate.socket.incoming_connections.empty()) {
    cstate.handle = cstate.socket.incoming_connections.front();
    cstate.socket.incoming_connections.pop_front();
    cstate.socket.connected.push_back(cstate);
    auto ctx = reinterpret_cast<lsquic_conn_ctx_t*>(&cstate);
    ::lsquic_conn_set_ctx(cstate.handle, ctx);
    op.post(error_code{}); // success
    return;
  }
  assert(!cstate.accept_);
  cstate.accept_ = &op;
  cstate.socket.accepting_connections.push_back(cstate);
  process(lock);
}

connection_state* engine_state::on_accept(lsquic_conn_t* conn)
{
  const sockaddr* local = nullptr;
  const sockaddr* peer = nullptr;
  int r = ::lsquic_conn_get_sockaddr(conn, &local, &peer);
  if (r != 0) {
    return nullptr;
  }
  // get the peer_ctx from our call to lsquic_engine_packet_in()
  auto peer_ctx = ::lsquic_conn_get_peer_ctx(conn, local);
  assert(peer_ctx);
  auto& socket = *static_cast<socket_state*>(peer_ctx);
  if (socket.accepting_connections.empty()) {
    // not waiting on accept, try to queue this for later
    if (socket.incoming_connections.full()) {
      ::lsquic_conn_close(conn);
    } else {
      socket.incoming_connections.push_back(conn);
    }
    return nullptr;
  }
  auto& cstate = socket.accepting_connections.front();
  socket.accepting_connections.pop_front();
  socket.connected.push_back(cstate);
  assert(cstate.accept_);
  assert(!cstate.handle);
  cstate.handle = conn;
  cstate.accept_->defer(error_code{}); // success
  cstate.accept_ = nullptr;
  return &cstate;
}

bool engine_state::is_open(const connection_state& cstate) const
{
  auto lock = std::scoped_lock{mutex};
  return cstate.handle;
}

void engine_state::close(connection_state& cstate, error_code& ec)
{
  auto lock = std::unique_lock{mutex};
  const auto aborted = make_error_code(connection_error::aborted);
  if (cstate.accept_) {
    assert(cstate.is_linked());
    auto& accepting = cstate.socket.accepting_connections;
    accepting.erase(accepting.iterator_to(cstate));
    auto op = std::exchange(cstate.accept_, nullptr);
    op->defer(aborted);
  }
  if (!cstate.handle) {
    ec = make_error_code(errc::not_connected);
    return;
  }

  cancel(cstate, aborted);

  ::lsquic_conn_close(cstate.handle);
  cstate.handle = nullptr;

  assert(cstate.is_linked());
  auto& connected = cstate.socket.connected;
  connected.erase(connected.iterator_to(cstate));

  process(lock);
}

using stream_ptr = std::unique_ptr<stream_state>;

int engine_state::cancel(connection_state& cstate, error_code ec)
{
  int canceled = 0;
  // close incoming streams that we haven't accepted yet
  while (!cstate.incoming_streams.empty()) {
    // take ownership of the stream and free on scope exit
    auto sstate = stream_ptr{&cstate.incoming_streams.front()};
    cstate.incoming_streams.pop_front();
    ::lsquic_stream_close(sstate->handle);
    sstate->handle = nullptr;
    sstate->conn = nullptr;
  }
  // cancel pending stream connect/accept
  while (!cstate.connecting_streams.empty()) {
    auto sstate = stream_ptr{&cstate.connecting_streams.front()};
    cstate.connecting_streams.pop_front();
    assert(sstate->conn);
    sstate->conn = nullptr;
    assert(!sstate->handle);
    assert(sstate->connect_);
    auto op = std::exchange(sstate->connect_, nullptr);
    op->defer(ec, nullptr);
    canceled++;
  }
  while (!cstate.accepting_streams.empty()) {
    auto sstate = stream_ptr{&cstate.accepting_streams.front()};
    cstate.accepting_streams.pop_front();
    assert(sstate->conn);
    sstate->conn = nullptr;
    assert(!sstate->handle);
    assert(sstate->accept_);
    auto op = std::exchange(sstate->accept_, nullptr);
    op->defer(ec, nullptr);
    canceled++;
  }
  // close connected streams
  while (!cstate.connected_streams.empty()) {
    auto& sstate = cstate.connected_streams.front();
    cstate.connected_streams.pop_front();
    assert(sstate.conn);
    sstate.conn = nullptr;

    assert(sstate.handle);
    ::lsquic_stream_close(sstate.handle);
    sstate.handle = nullptr;

    int count = 0;
    count += stream_cancel_read(sstate, ec);
    count += stream_cancel_write(sstate, ec);
    if (!count) {
      sstate.conn_err = ec;
    }
    canceled += count;
  }
  // cancel closing streams
  while (!cstate.closing_streams.empty()) {
    auto& sstate = cstate.closing_streams.front();
    cstate.closing_streams.pop_front();
    assert(sstate.close_);
    auto op = std::exchange(sstate.close_, nullptr);
    op->defer(ec);
    canceled++;
  }
  return canceled;
}

void engine_state::on_close(connection_state& cstate, lsquic_conn_t* conn)
{
  if (!cstate.handle) {
    return;
  }
  assert(cstate.handle == conn);
  cstate.handle = nullptr;

  assert(cstate.accept_ == nullptr);
  assert(cstate.is_linked());
  auto& connected = cstate.socket.connected;
  connected.erase(connected.iterator_to(cstate));

  // we may already have an error from on_handshake() or on_conncloseframe()
  error_code ec = cstate.err;
  if (!ec) {
    // use lsquic_conn_status() to choose the most relevant error code
    const auto status = ::lsquic_conn_status(conn, nullptr, 0);
    switch (status) {
      case LSCONN_ST_VERNEG_FAILURE:
      case LSCONN_ST_HSK_FAILURE:
        ec = make_error_code(connection_error::handshake_failed);
        break;
      case LSCONN_ST_TIMED_OUT:
        ec = make_error_code(connection_error::timed_out);
        break;
      case LSCONN_ST_PEER_GOING_AWAY:
        ec = make_error_code(connection_error::going_away);
        break;
      case LSCONN_ST_USER_ABORTED:
      case LSCONN_ST_CLOSED:
        ec = make_error_code(connection_error::aborted);
        break;
      case LSCONN_ST_ERROR:
      case LSCONN_ST_RESET:
      default:
        ec = make_error_code(connection_error::reset);
        break;
    }
  }

  const int canceled = cancel(cstate, ec);
  if (canceled) {
    // clear the connection error if we delivered it to the application
    cstate.err = error_code{};
  }
}

void engine_state::on_conncloseframe(connection_state& cstate,
                                     int app_error, uint64_t code)
{
  error_code ec;
  if (app_error == -1) {
    ec = make_error_code(connection_error::reset);
  } else if (app_error) {
    ec.assign(code, application_category());
  } else if ((code & 0xffff'ffff'ffff'ff00) == 0x0100) {
    // CRYPTO_ERROR 0x0100-0x01ff
    ec.assign(code & 0xff, tls_category());
  } else {
    ec.assign(code, transport_category());
  }

  cstate.err = ec;
}

void engine_state::stream_connect(connection_state& cstate,
                                  stream_connect_operation& op)
{
  auto lock = std::unique_lock{mutex};
  if (cstate.err) {
    op.post(std::exchange(cstate.err, {}), nullptr);
    return;
  }
  if (!cstate.handle) {
    op.post(make_error_code(errc::bad_file_descriptor), nullptr);
    return;
  }
  auto sstate = std::make_unique<stream_state>(ex, &cstate);
  sstate->connect_ = &op;
  cstate.connecting_streams.push_back(*sstate.release()); // transfer ownership
  ::lsquic_conn_make_stream(cstate.handle);
  process(lock);
}

stream_state* engine_state::on_stream_connect(connection_state& cstate,
                                              lsquic_stream_t* stream)
{
  assert(!cstate.connecting_streams.empty());
  auto& sstate = cstate.connecting_streams.front();
  cstate.connecting_streams.pop_front();
  cstate.connected_streams.push_back(sstate);
  assert(!sstate.handle);
  sstate.handle = stream;
  auto ec = error_code{}; // success
  assert(sstate.connect_);
  sstate.connect_->defer(ec, &sstate);
  sstate.connect_ = nullptr;
  return &sstate;
}

void engine_state::stream_accept(connection_state& cstate,
                                 stream_accept_operation& op)
{
  auto lock = std::unique_lock{mutex};
  if (cstate.err) {
    op.post(std::exchange(cstate.err, {}), nullptr);
    return;
  }
  if (!cstate.handle) {
    op.post(make_error_code(errc::bad_file_descriptor), nullptr);
    return;
  }
  if (!cstate.incoming_streams.empty()) {
    // take ownership of the first incoming stream
    auto sstate = stream_ptr{&cstate.incoming_streams.front()};
    cstate.incoming_streams.pop_front();
    cstate.connected_streams.push_back(*sstate);
    op.post(error_code{}, std::move(sstate)); // success
    return;
  }
  auto sstate = std::make_unique<stream_state>(ex, &cstate);
  sstate->accept_ = &op;
  cstate.accepting_streams.push_back(*sstate.release()); // transfer ownership
}

stream_state* engine_state::on_stream_accept(connection_state& cstate,
                                             lsquic_stream* stream)
{
  if (cstate.accepting_streams.empty()) {
    // not waiting on accept, queue this for later
    auto sstate = std::make_unique<stream_state>(ex, &cstate);
    cstate.incoming_streams.push_back(*sstate);
    sstate->handle = stream;
    return sstate.release();
  }
  auto& sstate = cstate.accepting_streams.front();
  cstate.accepting_streams.pop_front();
  cstate.connected_streams.push_back(sstate);
  assert(!sstate.handle);
  sstate.handle = stream;
  assert(sstate.accept_);
  sstate.accept_->defer(error_code{}, &sstate); // success
  sstate.accept_ = nullptr;
  return &sstate;
}

stream_state* engine_state::on_new_stream(connection_state& cstate,
                                          lsquic_stream_t* stream)
{
  // XXX: any way to decide between connect/accept without stream id?
  const auto id = ::lsquic_stream_id(stream);
  const int server = !client;
  if ((id & 1) == server) { // self-initiated
    return on_stream_connect(cstate, stream);
  } else { // peer-initiated
    return on_stream_accept(cstate, stream);
  }
}

bool engine_state::is_open(const stream_state& sstate) const
{
  auto lock = std::scoped_lock{mutex};
  return sstate.handle;
}

void engine_state::stream_read(stream_state& sstate, stream_data_operation& op)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    op.post(std::exchange(sstate.conn->err, {}), 0);
    return;
  }
  if (!sstate.handle) {
    op.post(make_error_code(errc::not_connected), 0);
    return;
  }
  if (sstate.in.header || sstate.in.data) { // no concurrent reads
    op.post(make_error_code(stream_error::busy), 0);
    return;
  }
  if (::lsquic_stream_wantread(sstate.handle, 1) == -1) {
    op.post(error_code{errno, system_category()}, 0);
    return;
  }
  sstate.in.data = &op;
  process(lock);
}

void engine_state::stream_read_headers(stream_state& sstate,
                                       stream_header_read_operation& op)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    op.post(std::exchange(sstate.conn->err, {}));
    return;
  }
  if (!sstate.handle) {
    op.post(make_error_code(errc::not_connected));
    return;
  }
  if (sstate.in.header || sstate.in.data) { // no concurrent reads
    op.post(make_error_code(stream_error::busy));
    return;
  }
  if (::lsquic_stream_wantread(sstate.handle, 1) == -1) {
    op.post(error_code{errno, system_category()});
    return;
  }
  sstate.in.header = &op;
  process(lock);
}

struct recv_header_set {
  h3::fields fields;
  int is_push_promise;
  lsxpack_header header;
  std::vector<char> buffer;

  recv_header_set(int is_push_promise) : is_push_promise(is_push_promise) {}
};

void engine_state::on_stream_read(stream_state& sstate)
{
  error_code ec;
  if (sstate.in.header) {
    auto& op = *std::exchange(sstate.in.header, nullptr);
    auto hset = ::lsquic_stream_get_hset(sstate.handle);
    if (!hset) {
      ec = make_error_code(stream_error::eof);
    } else {
      auto headers = std::unique_ptr<recv_header_set>(
          reinterpret_cast<recv_header_set*>(hset)); // take ownership
      op.fields = std::move(headers->fields);
    }
    op.defer(ec);
  } else if (sstate.in.data) {
    auto& op = *std::exchange(sstate.in.data, nullptr);
    auto bytes = ::lsquic_stream_readv(sstate.handle, op.iovs, op.num_iovs);
    if (bytes == -1) {
      bytes = 0;
      ec.assign(errno, system_category());
    } else if (bytes == 0) {
      ec = make_error_code(stream_error::eof);
    }
    op.defer(ec, bytes);
  }
  ::lsquic_stream_wantread(sstate.handle, 0);
}

void engine_state::stream_write(stream_state& sstate, stream_data_operation& op)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    op.post(std::exchange(sstate.conn->err, {}), 0);
    return;
  }
  if (!sstate.handle) {
    op.post(make_error_code(errc::not_connected), 0);
    return;
  }
  if (sstate.out.header || sstate.out.data) { // no concurrent writes
    op.post(make_error_code(stream_error::busy), 0);
    return;
  }
  if (::lsquic_stream_wantwrite(sstate.handle, 1) == -1) {
    op.post(error_code{errno, system_category()}, 0);
    return;
  }
  sstate.out.data = &op;
  process(lock);
}

void engine_state::stream_write_headers(stream_state& sstate,
                                        stream_header_write_operation& op)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    op.post(std::exchange(sstate.conn->err, {}));
    return;
  }
  if (!sstate.handle) {
    op.post(make_error_code(errc::not_connected));
    return;
  }
  if (sstate.out.header || sstate.out.data) { // no concurrent writes
    op.post(make_error_code(stream_error::busy));
    return;
  }
  if (::lsquic_stream_wantwrite(sstate.handle, 1) == -1) {
    op.post(error_code{errno, system_category()});
    return;
  }
  sstate.out.header = &op;
  process(lock);
}

static void do_write_headers(lsquic_stream_t* stream,
                             const h3::fields& fields, error_code& ec)
{
  // stack-allocate a lsxpack_header array
  auto array = reinterpret_cast<lsxpack_header*>(
      ::alloca(fields.size() * sizeof(lsxpack_header)));
  int num_headers = 0;
  for (auto f = fields.begin(); f != fields.end(); ++f, ++num_headers) {
    auto& header = array[num_headers];
    const char* buf = f->data();
    const size_t name_offset = std::distance(buf, f->name().data());
    const size_t name_len = f->name().size();
    const size_t val_offset = std::distance(buf, f->value().data());
    const size_t val_len = f->value().size();
    lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                               val_offset, val_len);
    if (f->never_index()) {
      header.flags = LSXPACK_NEVER_INDEX;
    }
  }
  auto headers = lsquic_http_headers{num_headers, array};
  if (::lsquic_stream_send_headers(stream, &headers, 0) == -1) {
    ec.assign(errno, system_category());
  }
}

void engine_state::on_stream_write(stream_state& sstate)
{
  error_code ec;
  if (sstate.out.header) {
    auto& op = *std::exchange(sstate.out.header, nullptr);
    do_write_headers(sstate.handle, op.fields, ec);
    op.defer(ec);
  } else if (sstate.out.data) {
    auto& op = *std::exchange(sstate.out.data, nullptr);
    auto bytes = ::lsquic_stream_writev(sstate.handle, op.iovs, op.num_iovs);
    if (bytes == -1) {
      bytes = 0;
      ec.assign(errno, system_category());
    }
    op.defer(ec, bytes);
  }
  ::lsquic_stream_wantwrite(sstate.handle, 0);
}

void engine_state::stream_flush(stream_state& sstate, error_code& ec)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    ec = std::exchange(sstate.conn->err, {});
    return;
  }
  if (!sstate.handle) {
    ec = make_error_code(errc::not_connected);
    return;
  }
  if (::lsquic_stream_flush(sstate.handle) == -1) {
    ec.assign(errno, system_category());
    return;
  }
  process(lock);
}

void engine_state::stream_shutdown(stream_state& sstate,
                                   int how, error_code& ec)
{
  const bool shutdown_read = (how == 0 || how == 2);
  const bool shutdown_write = (how == 1 || how == 2);
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.conn->err) {
    ec = std::exchange(sstate.conn->err, {});
    return;
  }
  if (!sstate.handle) {
    ec = make_error_code(errc::bad_file_descriptor);
    return;
  }
  if (::lsquic_stream_shutdown(sstate.handle, how) == -1) {
    ec.assign(errno, system_category());
    return;
  }
  auto ecanceled = make_error_code(stream_error::aborted);
  if (shutdown_read) {
    stream_cancel_read(sstate, ecanceled);
  }
  if (shutdown_write) {
    stream_cancel_write(sstate, ecanceled);
  }
  process(lock);
}

bool engine_state::try_stream_reset(stream_state& sstate)
{
  assert(sstate.conn);
  auto ec = make_error_code(stream_error::aborted);
  if (sstate.accept_) {
    sstate.accept_->defer(ec, nullptr);
    sstate.accept_ = nullptr;
    auto& accepting = sstate.conn->accepting_streams;
    accepting.erase(accepting.iterator_to(sstate));
  }
  if (sstate.connect_) {
    sstate.connect_->defer(ec, nullptr);
    sstate.connect_ = nullptr;
    auto& connecting = sstate.conn->connecting_streams;
    connecting.erase(connecting.iterator_to(sstate));
  }
  if (!sstate.handle) { // not connected
    return false;
  }
  ::lsquic_stream_close(sstate.handle);
  sstate.handle = nullptr;

  assert(sstate.conn);
  auto& connected = sstate.conn->connected_streams;
  connected.erase(connected.iterator_to(sstate));

  stream_cancel_read(sstate, ec);
  stream_cancel_write(sstate, ec);
  return true;
}

void engine_state::stream_reset(stream_state& sstate)
{
  auto lock = std::unique_lock{mutex};
  assert(sstate.conn);
  if (sstate.close_) {
    auto& closing = sstate.conn->closing_streams;
    closing.erase(closing.iterator_to(sstate));
    sstate.close_->defer(make_error_code(stream_error::aborted));
    sstate.close_ = nullptr;
  }
  try_stream_reset(sstate);
  sstate.conn = nullptr;
  process(lock);
}

void engine_state::stream_close(stream_state& sstate,
                                stream_close_operation& op)
{
  auto lock = std::unique_lock{mutex};
  if (sstate.close_) { // already waiting on close
    op.post(make_error_code(stream_error::busy));
    return;
  }
  if (!try_stream_reset(sstate)) {
    op.post(error_code{});
    return;
  }
  assert(sstate.conn);
  sstate.conn->closing_streams.push_back(sstate);
  assert(!sstate.close_);
  sstate.close_ = &op;
  process(lock);
}

int engine_state::stream_cancel_read(stream_state& sstate, error_code ec)
{
  int canceled = 0;
  if (sstate.in.header) {
    sstate.in.header->defer(ec);
    sstate.in.header = nullptr;
    canceled++;
  }
  if (sstate.in.data) {
    sstate.in.data->defer(ec, 0);
    sstate.in.data = nullptr;
    canceled++;
  }
  return canceled;
}

int engine_state::stream_cancel_write(stream_state& sstate, error_code ec)
{
  int canceled = 0;
  if (sstate.out.header) {
    sstate.out.header->defer(ec);
    sstate.out.header = nullptr;
    canceled++;
  }
  if (sstate.out.data) {
    sstate.out.data->defer(ec, 0);
    sstate.out.data = nullptr;
    canceled++;
  }
  return canceled;
}

void engine_state::on_stream_close(stream_state& sstate)
{
  assert(sstate.conn);
  if (sstate.close_) {
    auto& closing = sstate.conn->closing_streams;
    closing.erase(closing.iterator_to(sstate));
    auto op = std::exchange(sstate.close_, nullptr);
    op->defer(error_code{});
  }
  if (!sstate.handle) {
    return; // already closed
  }
  sstate.handle = nullptr;

  auto& connected = sstate.conn->connected_streams;
  connected.erase(connected.iterator_to(sstate));

  auto ec = make_error_code(stream_error::reset);
  if (sstate.conn->err) {
    ec = sstate.conn->err;
  }
  sstate.conn = nullptr;

  int canceled = 0;
  canceled += stream_cancel_read(sstate, ec);
  canceled += stream_cancel_write(sstate, ec);
  if (!canceled) {
    sstate.conn_err = ec;
  }
}

void engine_state::close()
{
  auto lock = std::unique_lock{mutex};
  ::lsquic_engine_cooldown(handle.get());
  process(lock);
}

void engine_state::listen(socket_state& socket, int backlog)
{
  auto lock = std::unique_lock{mutex};
  socket.incoming_connections.set_capacity(backlog);
  start_recv(socket);
}

void engine_state::close(socket_state& socket)
{
  auto lock = std::unique_lock{mutex};
  // close incoming streams that we haven't accepted yet
  while (!socket.incoming_connections.empty()) {
    auto conn = socket.incoming_connections.front();
    socket.incoming_connections.pop_front();
    ::lsquic_conn_close(conn);
  }
  const auto ecanceled = make_error_code(connection_error::aborted);
  // close connections on this socket
  while (!socket.connected.empty()) {
    auto& cstate = socket.connected.front();
    socket.connected.pop_front();

    ::lsquic_conn_close(cstate.handle);
    cstate.handle = nullptr;

    cancel(cstate, ecanceled);
  }
  process(lock);
  // cancel connections pending accept
  while (!socket.accepting_connections.empty()) {
    auto& cstate = socket.accepting_connections.front();
    socket.accepting_connections.pop_front();
    assert(cstate.accept_);
    cstate.accept_->defer(ecanceled);
    cstate.accept_ = nullptr;
  }
  // XXX: cancel the async_wait for read, but don't close until ~socket_state()
  socket.receiving = false;
  socket.socket.cancel();
}

void engine_state::process(std::unique_lock<std::mutex>& lock)
{
  ::lsquic_engine_process_conns(handle.get());
  reschedule(lock);
}

void engine_state::reschedule(std::unique_lock<std::mutex>& lock)
{
  int micros = 0;
  if (!::lsquic_engine_earliest_adv_tick(handle.get(), &micros)) {
    // no connections to process. servers should keep listening for packets,
    // but clients can stop reading
    if (client && client->receiving) {
      client->receiving = false;
      client->socket.cancel();
    }
    timer.cancel();
    return;
  }
  if (micros <= 0) {
    process(lock);
    return;
  }
  const auto dur = std::chrono::microseconds{micros};
  timer.expires_after(dur);
  timer.async_wait([this] (error_code ec) {
        if (!ec) {
          on_timer();
        }
      });
}

void engine_state::on_timer()
{
  auto lock = std::unique_lock{mutex};
  process(lock);
}

void engine_state::start_recv(socket_state& socket)
{
  if (socket.receiving) {
    return;
  }
  socket.receiving = true;
  socket.socket.async_wait(udp::socket::wait_read,
      [this, &socket] (error_code ec) {
        socket.receiving = false;
        if (!ec) {
          on_readable(socket);
        } // XXX: else fatal? retry?
      });
}

void engine_state::on_readable(socket_state& socket)
{
  std::array<unsigned char, 4096> buffer;
  iovec iov;
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();

  error_code ec;
  for (;;) {
    udp::endpoint peer;
    sockaddr_union self;
    int ecn = 0;

    const auto bytes = socket.recv_packet(iov, peer, self, ecn, ec);
    if (ec) {
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        start_recv(socket);
      } // XXX: else fatal? retry?
      return;
    }

    auto lock = std::unique_lock{mutex};
    ::lsquic_engine_packet_in(handle.get(), buffer.data(), bytes,
                              &self.addr, peer.data(), &socket, ecn);
    process(lock);
  }
}

void engine_state::on_writeable(socket_state&)
{
  auto lock = std::scoped_lock{mutex};
  ::lsquic_engine_send_unsent_packets(handle.get());
}

int engine_state::send_packets(const lsquic_out_spec* specs, unsigned n_specs)
{
  auto p = specs;
  const auto end = std::next(p, n_specs);
  while (p < end) {
    socket_state& socket = *static_cast<socket_state*>(p->peer_ctx);
    error_code ec;
    p = socket.send_packets(p, end, ec);
    if (ec) {
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        // lsquic won't call our send_packets() callback again until we call
        // lsquic_engine_send_unsent_packets()
        // wait for the socket to become writeable again, so we can call that
        socket.socket.async_wait(udp::socket::wait_write,
            [this, &socket] (error_code ec) {
              if (!ec) {
                on_writeable(socket);
              } // else fatal?
            });
        errno = ec.value(); // lsquic needs to see this errno
      }
      break;
    }
  }
  return std::distance(specs, p);
}


// stream api
static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  auto estate = static_cast<engine_state*>(ectx);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  // outgoing connections will have a context set by lsquic_engine_connect()
  if (!cctx) {
    auto cstate = estate->on_accept(conn);
    return reinterpret_cast<lsquic_conn_ctx_t*>(cstate);
  }
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  estate->on_connect(*cstate, conn);
  return cctx;
}

static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
{
  auto estate = static_cast<engine_state*>(ectx);
  if (stream == nullptr) {
    return nullptr; // connection went away?
  }
  auto conn = ::lsquic_stream_conn(stream);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  auto sstate = estate->on_new_stream(*cstate, stream);
  return reinterpret_cast<lsquic_stream_ctx_t*>(sstate);
}

static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  assert(sstate->conn);
  sstate->conn->socket.engine.on_stream_read(*sstate);
}

static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  assert(sstate->conn);
  sstate->conn->socket.engine.on_stream_write(*sstate);
}

static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  if (sstate && sstate->conn) {
    sstate->conn->socket.engine.on_stream_close(*sstate);
  }
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  cstate->socket.engine.on_close(*cstate, conn);
}

static void on_hsk_done(lsquic_conn_t* conn, lsquic_hsk_status s)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  cstate->socket.engine.on_handshake(*cstate, s);
}

void on_conncloseframe_received(lsquic_conn_t* conn,
                                int app_error, uint64_t code,
                                const char* reason, int reason_len)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  cstate->socket.engine.on_conncloseframe(*cstate, app_error, code);
}

static constexpr lsquic_stream_if make_stream_api()
{
  lsquic_stream_if api = {};
  api.on_new_conn = on_new_conn;
  api.on_conn_closed = on_conn_closed;
  api.on_new_stream = on_new_stream;
  api.on_read = on_read;
  api.on_write = on_write;
  api.on_close = on_close;
  api.on_hsk_done = on_hsk_done;
  api.on_conncloseframe_received = on_conncloseframe_received;
  return api;
}


// header set api
static void* header_set_create(void* ctx, lsquic_stream_t* stream,
                               int is_push_promise)
{
  // TODO: store this in stream_state to avoid allocation?
  return new recv_header_set(is_push_promise);
}

static lsxpack_header* header_set_prepare(void* hset, lsxpack_header* hdr,
                                          size_t space)
{
  auto headers = reinterpret_cast<recv_header_set*>(hset);
  auto& header = headers->header;
  auto& buf = headers->buffer;
  buf.resize(space);
  if (hdr) { // existing header, just update the pointer and capacity
    header.buf = buf.data();
    header.val_len = space;
  } else { // initialize the entire header
    lsxpack_header_prepare_decode(&header, buf.data(), 0, space);
  }
  return &header;
}

static int header_set_process(void* hset, lsxpack_header* hdr)
{
  if (hdr) {
    auto headers = reinterpret_cast<recv_header_set*>(hset);
    auto name = std::string_view{hdr->buf + hdr->name_offset, hdr->name_len};
    auto value = std::string_view{hdr->buf + hdr->val_offset, hdr->val_len};
    const bool never_index = hdr->flags & LSXPACK_NEVER_INDEX;
    auto f = headers->fields.insert(name, value, never_index);
  }
  return 0;
}

static void header_set_discard(void* hset)
{
  delete reinterpret_cast<recv_header_set*>(hset);
}

static constexpr lsquic_hset_if make_header_api()
{
  lsquic_hset_if api = {};
  api.hsi_create_header_set  = header_set_create;
  api.hsi_prepare_decode = header_set_prepare;
  api.hsi_process_header = header_set_process;
  api.hsi_discard_header_set = header_set_discard;
  return api;
}

static int api_send_packets(void* ectx, const lsquic_out_spec *specs,
                            unsigned n_specs)
{
  auto estate = static_cast<engine_state*>(ectx);
  return estate->send_packets(specs, n_specs);
}

ssl_ctx_st* api_peer_ssl_ctx(void* peer_ctx, const sockaddr* local)
{
  auto& socket = *static_cast<socket_state*>(peer_ctx);
  return socket.ssl.native_handle();
}

engine_state::engine_state(const asio::any_io_executor& ex,
                           socket_state* client, const settings* s,
                           unsigned flags)
  : ex(ex), timer(ex), client(client)
{
  lsquic_engine_api api = {};
  api.ea_packets_out = api_send_packets;
  api.ea_packets_out_ctx = this;
  static const lsquic_stream_if stream_api = make_stream_api();
  api.ea_stream_if = &stream_api;
  api.ea_stream_if_ctx = this;
  api.ea_get_ssl_ctx = api_peer_ssl_ctx;
  if (flags & LSENG_HTTP) {
    static const lsquic_hset_if header_api = make_header_api();
    api.ea_hsi_if = &header_api;
    api.ea_hsi_ctx = this;
  }

  // apply and validate the settings
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, flags);
  if (s) {
    write_settings(*s, es);
  }
  es.es_versions = (1 << LSQVER_I001); // RFC version only
  char errbuf[256];
  int r = ::lsquic_engine_check_settings(&es, flags, errbuf, sizeof(errbuf));
  if (r == -1) {
    throw bad_setting(errbuf);
  }
  es.es_delay_onclose = 1;
  api.ea_settings = &es;

  handle.reset(::lsquic_engine_new(flags, &api));
}

} // namespace nexus::quic::detail
