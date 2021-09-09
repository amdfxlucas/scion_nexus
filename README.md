# Nexus HTTP/3

Nexus is a C++ library for the QUIC and HTTP/3 protocols.

## Dependencies

* LiteSpeed QUIC (lsquic)
* BoringSSL
* liburing
* zlib
* googletest for tests

BoringSSL, lsquic, and googletest are included as git submodules, which must be initialized before building:

	~/nexus $ git submodule update --init --recursive

The liburing and zlib dependencies must be installed manually. For example, on Fedora:

	~/nexus $ sudo dnf install liburing-devel zlib-devel

## Building

Nexus uses the CMake build system. Start by creating a build directory:

	~/nexus $ mkdir build && cd build

Then invoke `cmake` to generate the build scripts:

	~/nexus/build $ cmake ..

Then build the library and its dependencies:

	~/nexus/build $ cmake --build .

You can run unit tests with `ctest`:

	~/nexus/build $ ctest

You can install nexus and its dependencies with:

	~/nexus/build $ cmake --build . --target install