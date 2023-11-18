
cmake_minimum_required(VERSION 3.16)

project( sha3 VERSION 1.0 )

add_subdirectory( SHA-3 )

add_subdirectory( KeccakTests )

set(CMAKE_CXX_STANDARD 23)


