cmake_minimum_required(VERSION 3.16)

project(pan-bindings VERSION 1.0 )
set( PACKAGE_NAME "pan")

set(GO_BINARY "go1.19" CACHE PATH "Path to go binary")
set(BUILD_CPP ON CACHE BOOL "Build the C++ bindings")
set(BUILD_EXAMPLES ON CACHE BOOL "Build the examples")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")


add_subdirectory(go)

if (BUILD_CPP)
    add_subdirectory(cpp)
endif()

if (BUILD_EXAMPLES AND BUILD_CPP)
    add_subdirectory(examples/cpp)
endif()


#message(status ${PACKAGE_NAME})
#set( CONFIG_INPUT ${PACKAGE_NAME}Config.cmake.in)
#set( CONFIG_FILE ${PACKAGE_NAME}Config.cmake )
#set( VERSION_FILE ${PACKAGE_NAME}ConfigVersion.cmake )

#include(CMakePackageConfigHelpers)
#configure_package_config_file(
#    ${CONFIG_INPUT}
#    ${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_FILE}
#    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pan
#    # PATH_VARS TARGET_EXPORT_NAME
#)

#install(FILES
#          "${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_FILE}"
#          "${CMAKE_CURRENT_BINARY_DIR}/${VERSION_FILE}"
#        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pan
#)