cmake_minimum_required (VERSION 3.5.1)
project(nexus)
find_package(Boost COMPONENTS thread system)

list(APPEND CMAKE_PREFIX_PATH "dependency/pan-bindings" "dependency/sha3" )
find_package(pancpp)
#find_package(pan)
 # cannot find a way to re-export imported targets :( can u ?

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_CXX_STANDARD 17 )
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# scionlab doesnt support IPv6 anyway
option(ENABLE_SCION_IPv6 "support scion addresses with IPv6 host part" FALSE)
if( ENABLE_SCION_IPv6)
add_compile_definitions(ENABLE_SCION_IPv6)
find_package(sha3 HINTS "dependency/sha3" )
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
target_include_directories(nexus-headers INTERFACE include ${BOOST_LIBRARY_INCLUDES} dependency/pan-binding/include  )
target_link_libraries(nexus-headers INTERFACE  pancpp )
install(DIRECTORY include/nexus DESTINATION include)


set(CMAKE_CXX_STANDARD 23 )
add_subdirectory(examples)


add_subdirectory(src)

enable_testing()
add_subdirectory(test)
