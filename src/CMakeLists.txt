#find_package(Boost COMPONENTS thread system)

#find_package(sha3)




set(CMAKE_CXX_STANDARD 23 )

set(nexus-srcs
	client.cc
	connection.cc
	connection_state.cc
	engine.cc
	error.cc
	global.cc
	server.cc
	settings.cc
	socket.cc
	tracing.hpp	
	stream.cc
	stream_state.cc)

add_library(nexus ${nexus-srcs})

#if(CMAKE_BUILD_TYPE MATCHES Debug)
#	target_compile_definitions( nexus PUBLIC BOOST_ASIO_ENABLE_HANDLER_TRACKING )
#endif()

set(NEXUS_DEPS	nexus-headers lsquic  )

if(ENABLE_SCION)	
list(APPEND NEXUS_DEPS pancpp pan::pan )
if(ENABLE_SCION_IPv6)
list(APPEND NEXUS_DEPS sha3)
endif()
endif()

target_link_libraries(nexus PUBLIC ${NEXUS_DEPS}
${Boost_LIBRARIES}
Boost::system
Boost::thread

)

#target_include_directories( nexus PRIVATE /usr/local/include )

install(TARGETS nexus LIBRARY DESTINATION lib)
