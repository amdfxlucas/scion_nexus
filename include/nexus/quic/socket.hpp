#pragma once

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>

namespace nexus::quic {

// enable the socket options necessary for a quic client or server
template<typename socket_t>
inline void prepare_socket( socket_t& sock, bool is_server, error_code& ec);

} // namespace nexus::quic
