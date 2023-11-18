#set(MYVAR cachedValue CACHE STRING "someval")
option(ENABLE_LSQUIC_LOGGING "enable lsquic engine logging" OFF )
option(LSQUIC_LOGLEVEL "lsquic engine loglevel:  debug(default), info, notice, warning, error, alert, emerg, and crit" debug )



add_executable(nexus_echo_client client.cc)
target_link_libraries(nexus_echo_client nexus address-sanitizer)

add_executable(nexus_echo_server server.cc)
target_link_libraries(nexus_echo_server nexus address-sanitizer)

#if(CMAKE_BUILD_TYPE MATCHES Debug)
# target_compile_definitions( nexus_echo_server PRIVATE BOOST_ASIO_ENABLE_HANDLER_TRACKING )
# target_compile_definitions( nexus_echo_client PRIVATE BOOST_ASIO_ENABLE_HANDLER_TRACKING )
#endif()

if(ENABLE_LSQUIC_LOGGING)
target_compile_definitions( nexus_echo_server PRIVATE LSQUIC_LOG )
target_compile_definitions( nexus_echo_client PRIVATE LSQUIC_LOG )

target_compile_definitions( nexus_echo_server PRIVATE LSQUIC_LOG_LVL=${LSQUIC_LOGLEVEL} )
target_compile_definitions( nexus_echo_client PRIVATE LSQUIC_LOG_LVL=${LSQUIC_LOGLEVEL} )
endif()