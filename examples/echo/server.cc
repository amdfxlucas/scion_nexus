#include <charconv>
#include <iostream>
#include <optional>
#include <boost/asio.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <openssl/ssl.h>
#include <nexus/global_init.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/quic/server.hpp>
#include <nexus/quic/settings.hpp>
#include <nexus/quic/stream.hpp>
#include <ranges>
#include <iterator>

// echo server that accepts connections and their streams, writing back
// anything it reads on each stream

namespace {

struct configuration {
  const char* hostname;
  const char* portstr;
  std::string cert;
  std::string scion;
  std::string key;
  std::optional<uint32_t> max_streams;
};

configuration parse_args(int argc, char** argv)
{
  if (argc < 5) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> <certificate> <private key> <scion> [max-streams]\n";
    ::exit(EXIT_FAILURE);
  }
  configuration config;
  config.hostname = argv[1];
  config.portstr = argv[2];
  config.cert = argv[3];
  config.key = argv[4];
  config.scion = argv[5];
  if (argc > 6) { // parse max-streams
    const auto begin = argv[6];
    const auto end = begin + strlen(begin);
    uint32_t value;
    const auto result = std::from_chars(begin, end, value);
    if (auto ec = make_error_code(result.ec); ec) {
      std::cerr << "failed to parse max-streams \"" << argv[5]
          << "\": " << ec.message() << '\n';
      ::exit(EXIT_FAILURE);
    }
    config.max_streams = value;
  }
  return config;
}

using boost::asio::ip::udp;
using nexus::error_code;
using nexus::system_error;

int alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* arg)
{
  const unsigned char alpn[] = {4,'e','c','h','o'};
  int r = ::SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                                  const_cast<unsigned char*>(in), inlen,
                                  alpn, sizeof(alpn));
   if (r == OPENSSL_NPN_NEGOTIATED) {
    std::cerr << "alpn negotiation successfull !" << std::endl;
    return SSL_TLSEXT_ERR_OK;
  } else {
    std::cerr << "alpn negotiation failed!" << std::endl;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

template <typename T>
using ref_counter = boost::intrusive_ref_counter<T, boost::thread_unsafe_counter>;

struct echo_connection : ref_counter<echo_connection> {
  nexus::quic::connection conn;

  explicit echo_connection(nexus::quic::acceptor* acceptor)
      : conn(*acceptor) {}
  ~echo_connection() {
    std::cerr << "connection closed\n";
  }
};
using connection_ptr = boost::intrusive_ptr<echo_connection>;

struct echo_stream {
  connection_ptr conn;
  nexus::quic::stream stream;
  std::array<char, 1024> buffer;

  explicit echo_stream(connection_ptr conn)
      : conn(std::move(conn)), stream(this->conn->conn) {}
};

void on_stream_write(std::unique_ptr<echo_stream> s,
                     error_code ec, size_t bytes);

void on_stream_read(std::unique_ptr<echo_stream> s,
                    error_code ec, size_t bytes_read)
{
  auto& stream = s->stream;
  if (ec == nexus::quic::stream_error::eof) {
    // done reading and all writes were submitted, wait for the acks and shut
    // down gracefully
    stream.async_close([s=std::move(s)] (error_code ec) {
        if (ec) {
          std::cerr << "stream close failed with " << ec.message() << '\n';
        } else {
          std::cerr << "stream closed\n";
        }
      });
    return;
  }
  if (ec) {
    std::cerr << "read failed with " << ec.message() << '\n';
    return;
  }
  // echo the buffer back to the client
  auto& data = s->buffer;
  boost::asio::async_write(stream, boost::asio::buffer(data.data(), bytes_read),
    [s=std::move(s)] (error_code ec, size_t bytes_written) mutable {

     // std::cout <<"wrote: \"" ;
      std::ranges::copy(  s->buffer|std::ranges::views::take(bytes_written) ,
      std::ostream_iterator<char>(std::cout, "") );
    //  std::cout << "\""<< std::endl;

      on_stream_write(std::move(s), ec, bytes_written);
    });
}

void on_stream_write(std::unique_ptr<echo_stream> s,
                     error_code ec, size_t bytes_written)
{
  if (ec) {
    std::cerr << "write failed with " << ec.message() << '\n';
    return;
  }
  // read the next buffer from the client
  auto& stream = s->stream;
  auto& data = s->buffer;
  stream.async_read_some( boost::asio::buffer(data.data(),bytes_written ), // boost::asio::buffer(data),
    [s=std::move(s)] (error_code ec, size_t bytes_read) mutable {

  //    std::cout <<"read: \"" ;
      std::ranges::copy(  s->buffer|std::ranges::views::take(bytes_read) ,
      std::ostream_iterator<char>(std::cout, "") );
  //    std::cout << "\""<< std::endl;

      on_stream_read(std::move(s), ec, bytes_read);
    });
}

void accept_streams(connection_ptr c)
{
  auto s = std::make_unique<echo_stream>(c);
  auto& stream = s->stream;
  auto& conn = c->conn;
  conn.async_accept(stream,
    [c=std::move(c), s=std::move(s)] (error_code ec) mutable {
      if (ec) {
        std::cerr << "stream accept failed with " << ec.message() << '\n';
        return;
      }
      std::cout << "server about to accept stream" << std::endl;
      // start next accept
      accept_streams(std::move(c));
      // start reading from stream
      std::cerr << "new stream\n";
      auto& stream = s->stream;
      auto& data = s->buffer;
      stream.async_read_some(boost::asio::buffer(data),
        [s=std::move(s)] (error_code ec, size_t bytes) mutable {
          on_stream_read(std::move(s), ec, bytes);
        });
    });
}

void accept_connections(nexus::quic::server& server,
                        nexus::quic::acceptor* acceptor)
{
  auto conn = connection_ptr{new echo_connection(acceptor)};
  auto& c = conn->conn;
  acceptor->async_accept(c,
    [&server, acceptor, conn=std::move(conn)] (error_code ec) {
      if (ec) {
        std::cerr << "accept failed with " << ec.message()
            << ", shutting down\n";
        server.close();
        return;
      }
      std::cout << "start next accept ..." << std::endl;
      // start next accept
      accept_connections(server, acceptor);
      std::cerr << "new connection\n";
      // start accepting streams on the connection
      accept_streams(std::move(conn));
    });
}

} // anonymous namespace

int main(int argc, char** argv)
{
  const auto cfg = parse_args(argc, argv);

  auto context = boost::asio::io_context{};
  boost::asio::any_io_executor ex = context.get_executor();
  const auto endpoint = [&] {
      auto resolver = udp::resolver{ex};
      return resolver.resolve(cfg.hostname, cfg.portstr)->endpoint();
    }();

    std::cout <<"server listening on: " <<
   endpoint.address().to_string() +" : " << cfg.portstr <<std::endl;

  auto ssl = boost::asio::ssl::context{boost::asio::ssl::context::tlsv13};
  ::SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_alpn_select_cb(ssl.native_handle(), alpn_select_cb, nullptr);

  if(!cfg.cert.empty())
    ssl.use_certificate_chain_file(cfg.cert);
  if(!cfg.key.empty() )
    ssl.use_private_key_file(cfg.key, boost::asio::ssl::context::file_format::pem);
  
  if(cfg.cert.empty() && cfg.key.empty() )
  {  ssl.set_verify_mode( boost::asio::ssl::verify_none );
  std::cerr << "ssl verification disabled because no cert and key were specified" << std::endl;
  }

  ssl.set_verify_callback([](
                              bool preverified,              // True if the certificate passed pre-verification.
                              asio::ssl::verify_context &ctx // The peer certificate and other context.
                          )
                          {
  std::cout << "client cert successfully verified!" << std::endl;
   return true; });

  auto global = nexus::global::init_server();
  auto settings = nexus::quic::default_server_settings();
  if (cfg.max_streams) {
    settings.max_streams_per_connection = *cfg.max_streams;
  }
  auto server = nexus::quic::server{ex, settings};
  std::shared_ptr<nexus::quic::acceptor> acceptor;
  if(cfg.scion=="false")
  { acceptor = std::make_shared<nexus::quic::acceptor>(server, endpoint, ssl );
  }
  else
  {
  acceptor =std::dynamic_pointer_cast<nexus::quic::acceptor>(
   std::make_shared<nexus::quic::scion_acceptor>(server, endpoint, ssl )
   );
  }
  acceptor->listen(16);

  accept_connections(server, acceptor.get() );
  context.run();
  return 0;
}
