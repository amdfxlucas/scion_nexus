add_executable(nexus_echo_client client.cc)
target_link_libraries(nexus_echo_client nexus address-sanitizer)

add_executable(nexus_echo_server server.cc)
target_link_libraries(nexus_echo_server nexus address-sanitizer)

#if(CMAKE_BUILD_TYPE MATCHES Debug)
# target_compile_definitions( nexus_echo_server PRIVATE BOOST_ASIO_ENABLE_HANDLER_TRACKING )
# target_compile_definitions( nexus_echo_client PRIVATE BOOST_ASIO_ENABLE_HANDLER_TRACKING )
#endif()
