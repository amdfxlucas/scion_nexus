cmake_minimum_required (VERSION 3.5.1)
project(nexus)
find_package(Boost COMPONENTS thread system)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_CXX_STANDARD 17 )
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_SCION "enable support for SCION next generation internet protocol" FALSE )

if( ENABLE_SCION )
add_compile_definitions(ENABLE_SCION)

list(APPEND CMAKE_PREFIX_PATH "dependency/pan-bindings"  )
find_package(pancpp)
#find_package(pan)
 # cannot find a way to re-export imported targets :( can u ?


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

# scionlab doesnt support IPv6 anyway
option(ENABLE_SCION_IPv6 "support scion addresses with IPv6 host part" FALSE)
if( ENABLE_SCION_IPv6)
list(APPEND CMAKE_PREFIX_PATH "dependency/sha3" )
add_compile_definitions(ENABLE_SCION_IPv6)
find_package(sha3 HINTS "dependency/sha3" )
endif()
endif()

add_subdirectory(dependency)

add_library(address-sanitizer INTERFACE)
target_compile_options(address-sanitizer INTERFACE "-fsanitize=address,undefined")
target_link_libraries(address-sanitizer INTERFACE "-fsanitize=address,undefined")

add_library(thread-sanitizer INTERFACE)
target_compile_options(thread-sanitizer INTERFACE "-fsanitize=thread")
target_link_libraries(thread-sanitizer INTERFACE "-fsanitize=thread")

#if(CMAKE_BUILD_TYPE MATCHES Debug)
#	add_compile_definitions( BOOST_ASIO_ENABLE_HANDLER_TRACKING )
#    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -DBOOST_ASIO_ENABLE_HANDLER_TRACKING )
#endif()


add_library(nexus-headers INTERFACE)

set(NEXUS_HEADER_INCLUDE_DIRS include ${BOOST_LIBRARY_INCLUDES} )


if( ENABLE_SCION )
list(APPEND NEXUS_HEADER_INCLUDE_DIRS dependency/pan-binding/include  )
target_link_libraries(nexus-headers INTERFACE  pancpp )
endif()

target_include_directories(nexus-headers INTERFACE  ${NEXUS_HEADER_INCLUDE_DIRS} )

install(DIRECTORY include/nexus DESTINATION include)


set(CMAKE_CXX_STANDARD 23 )
add_subdirectory(examples)


add_subdirectory(src)

enable_testing()
add_subdirectory(test)
