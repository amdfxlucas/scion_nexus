#find_package(Boost COMPONENTS thread system)

find_package(sha3)


include(FindPackageHandleStandardArgs)

find_library(pan_LIBRARY 
NAMES pan pan_c libpan libpand pand
   HINTS "${PROJECT_SOURCE_DIR}/dependency/pan-bindings"
	)
find_path( pan_INCLUDE_DIR NAMES pan.h
HINTS "${PROJECT_SOURCE_DIR}/dependency/pan-bindings/include"
)

find_package_handle_standard_args(pan REQUIRED_VARS pan_LIBRARY pan_INCLUDE_DIR)

if ( pan_FOUND)
  mark_as_advanced( pan_INCLUDE_DIR)
  mark_as_advanced( pan_LIBRARY)
endif()

if ( pan_FOUND AND NOT TARGET pan::pan)
  add_library(pan::pan IMPORTED STATIC )
  set_property(TARGET pan::pan PROPERTY IMPORTED_LOCATION ${pan_LIBRARY})
  target_include_directories( pan::pan INTERFACE ${pan_INCLUDE_DIR})
endif()

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

set(NEXUS_DEPS
	nexus-headers lsquic pancpp pan::pan )
if(ENABLE_SCION_IPv6)
list(APPEND NEXUS_DEPS sha3)
endif()

target_link_libraries(nexus PUBLIC ${NEXUS_DEPS}
${Boost_LIBRARIES}
Boost::system
Boost::thread

)

#target_include_directories( nexus PRIVATE /usr/local/include )

install(TARGETS nexus LIBRARY DESTINATION lib)
