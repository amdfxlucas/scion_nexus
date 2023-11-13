cmake_minimum_required (VERSION 3.5.1)
project(nexus)
find_package(Boost COMPONENTS thread system)

list(APPEND CMAKE_PREFIX_PATH /usr/local/lib/cmake/pan )
find_package(pancpp)
#find_package(pan)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(CMAKE_CXX_STANDARD 17 )
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(dependency)

add_library(address-sanitizer INTERFACE)
target_compile_options(address-sanitizer INTERFACE "-fsanitize=address,undefined")
target_link_libraries(address-sanitizer INTERFACE "-fsanitize=address,undefined")

add_library(thread-sanitizer INTERFACE)
target_compile_options(thread-sanitizer INTERFACE "-fsanitize=thread")
target_link_libraries(thread-sanitizer INTERFACE "-fsanitize=thread")


add_library(nexus-headers INTERFACE)
target_include_directories(nexus-headers INTERFACE include ${BOOST_LIBRARY_INCLUDES} dependency/pan-binding/include  )
target_link_libraries(nexus-headers INTERFACE  pancpp  ) #Boost::asio
install(DIRECTORY include/nexus DESTINATION include)

add_subdirectory(examples)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)
