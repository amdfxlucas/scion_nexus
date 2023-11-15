set(CMAKE_CXX_STANDARD 23 )
add_subdirectory(echo)

add_executable(h3cli h3cli.cc)
target_link_libraries(h3cli nexus address-sanitizer)
