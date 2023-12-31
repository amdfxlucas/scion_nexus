#pragma once

#include <chrono>
#include <string_view>
#include <nexus/error_code.hpp>
#include <nexus/ssl.hpp>

namespace nexus::test {

void self_sign_certificate(ssl::context& ctx,
                           std::string_view country,
                           std::string_view organization,
                           std::string_view common_name,
                           std::chrono::seconds duration,
                           error_code& ec);

void self_sign_certificate(ssl::context& ctx,
                           std::string_view country,
                           std::string_view organization,
                           std::string_view common_name,
                           std::chrono::seconds duration);

ssl::context init_client_context(const char* alpn);
ssl::context init_server_context(const char* alpn);

} // namespace nexus::test
