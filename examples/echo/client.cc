#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <nexus/global_init.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/quic/stream.hpp>
#include <nexus/quic/detail/scion-utils.h>

// echo client takes one or more input files, writes each file in parallel
// to a different stream and reads back their echos for display to stdout.
// because the streams are multiplexed, the output from multiple files will be
// mixed together; however, running against a server with max-streams=1 will
// display their output in sequential order

namespace {

struct configuration {
  std::string_view hostname;
  std::string_view scion;
  const char* portstr;
  char** files_begin;
  char** files_end;
};

configuration parse_args(int argc, char** argv)
{
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> <scion> [filenames...]\n";
    ::exit(EXIT_FAILURE);
  }
  configuration config;
  config.hostname = argv[1];
  config.portstr = argv[2];
  config.scion = argv[3];
  config.files_begin = std::next(argv, 4);
  config.files_end = std::next(argv, argc);
  return config;
}

using boost::asio::ip::udp;
using nexus::error_code;
using nexus::system_error;

using buffer_type = std::array<char, 256>;

template <typename T>
using ref_counter = boost::intrusive_ref_counter<T, boost::thread_unsafe_counter>;

struct echo_connection : ref_counter<echo_connection> {
  nexus::quic::client* client;
  nexus::quic::connection conn;

  echo_connection(nexus::quic::client* client)
  : client(client),
  conn(*client)
   {}

  echo_connection( nexus::quic::client* client,
                  const udp::endpoint& endpoint,
                  const std::string_view& hostname)
      : client(client),
       conn(*client, endpoint, hostname)
  {}

  echo_connection( nexus::quic::client* client,
                  const Pan::udp::Endpoint& endpoint,
                 const std::string_view& hostname)
      : client(client),
       conn(*client, endpoint, hostname)
  {}

  ~echo_connection() {
    client->close();
  }
};

using connection_ptr = boost::intrusive_ptr<echo_connection>;

struct echo_stream : ref_counter<echo_stream> {
  connection_ptr conn;
  nexus::quic::stream stream;
  std::ifstream input;
  std::ostream& output;
  buffer_type readbuf;
  buffer_type writebuf;
  echo_stream(connection_ptr _conn, const char* filename, std::ostream& output)
      : conn(std::move(_conn)),
       stream(this->conn->conn),
        input(filename), output(output)
  {
    std::cout << "echo stream constructed for file: " << filename << std::endl;
  }
};
using stream_ptr = boost::intrusive_ptr<echo_stream>;

void write_file(stream_ptr stream)
{
  // read from input
  auto& data = stream->writebuf;
  stream->input.read(data.data(), data.size());
  const auto bytes = stream->input.gcount();

  // write to stream
  auto& s = stream->stream;
  boost::asio::async_write(s, boost::asio::buffer(data.data(), bytes),
                              boost::asio::transfer_at_least(1),
    [stream=std::move(stream)] (error_code ec, size_t bytes_written ) {
   
      if (ec) {
        std::cerr << "async_write failed with " << ec.message() 
        << " bytes: " << bytes_written  << '\n';
      } else if (!stream->input) { // no more input, done writing
        std::cout << "<< No more input ! >>" << std::endl;
        stream->stream.shutdown(1); // close stream for writing

      } else {
        write_file(std::move(stream));
      }
    });
}

void read_file(stream_ptr stream)
{
  // read back the echo
  auto& data = stream->readbuf;
  auto& s = stream->stream;
  s.async_read_some(boost::asio::buffer(data),
                //  boost::asio::transfer_at_least(1),
    [stream=std::move(stream)] (error_code ec, size_t bytes_read) {
      if (ec)
      {
        if (ec != nexus::quic::stream_error::eof) {
          // should we shutdown(0) the stream for read here ?!
          std::cerr << "async_read_some returned " << ec.message() << '\n';
        }
        return;
      }
     
      // write the output bytes then start reading more
      auto& data = stream->readbuf;
      stream->output<< "stream read: " << bytes_read << std::endl;
      stream->output.write(data.data(), bytes_read);
      stream->output<< std::endl;
      read_file(std::move(stream));
    });
}

} // anonymous namespace


int main(int argc, char** argv)
{
  const auto cfg = parse_args(argc, argv);

  auto context = boost::asio::io_context{};
  auto ex = context.get_executor();

  
  Pan::udp::Endpoint scion_remote;
  boost::asio::ip::udp::endpoint endpoint;

  if(cfg.scion=="true")
  {
    std::string full_address { cfg.hostname.data()};
    full_address.append(":");
    full_address.append( cfg.portstr );

    auto add = Pan::udp::resolveUDPAddr( full_address.data() );
    scion_remote = add;
    
  }


  
  if(cfg.scion == "false" )
  {   endpoint = [&] {
      auto resolver = udp::resolver{ex};
      return resolver.resolve(cfg.hostname, cfg.portstr)->endpoint();
    }();
  }

  std::cout <<"client connecting to: " << cfg.hostname << " : " << cfg.portstr <<std::endl;

  auto ssl = boost::asio::ssl::context{boost::asio::ssl::context::tlsv13};
  ::SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  const unsigned char alpn[] = {4,'e','c','h','o'};
  ::SSL_CTX_set_alpn_protos(ssl.native_handle(), alpn, sizeof(alpn));

  // ssl.set_verify_mode( boost::asio::ssl::verify_none );
  boost::system::error_code ec;
  ssl.load_verify_file(   "certs/rootCA.crt",    ec);
  if(ec) throw std::runtime_error("CA file not found");

  auto global = nexus::global::init_client();
  #ifdef LSQUIC_LOG
  global.log_to_stderr( LSQUIC_LOG_LVL );
  #endif

  std::shared_ptr<nexus::quic::client> client;
  connection_ptr conn;
  if( cfg.scion == "false")
  { client = std::make_shared< nexus::quic::client>(ex, udp::endpoint{endpoint.protocol(), 0}, ssl);
   conn = connection_ptr{new echo_connection(client.get(), endpoint, cfg.hostname)};
   }
  else
  {
    client = std::dynamic_pointer_cast<nexus::quic::client>(
       std::make_shared< nexus::quic::scion_client>(ex, udp::endpoint{endpoint.protocol(), 0}, ssl )
       );

       conn = connection_ptr{new echo_connection(client.get(), scion_remote, cfg.hostname)};
  }
 

  // connect a stream for each input file
  for (auto f = cfg.files_begin; f != cfg.files_end; ++f) {
    auto s = stream_ptr{new echo_stream(conn, *f, std::cout)};
    auto& stream = s->stream;
    conn->conn.async_connect(stream,    
     [s=std::move(s)] (error_code ec) {
        if (ec) {
          std::cerr << "async_connect stream failed with " 
          << ec.message() << '\n';
          return;
        }
        write_file(s);
        read_file(std::move(s));
        std::cout << "async connect returned! "<< std::endl;
      });
  }
  conn.reset(); // let the connection close once all streams are done

  context.run();
  return 0;
}
