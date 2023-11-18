cmake_minimum_required(VERSION 3.16)


add_library(pan_cpp
    go_handle.cpp
    pan.cpp
)
set_property(TARGET pan_cpp PROPERTY CXX_STANDARD 17)
set_target_properties(pan_cpp PROPERTIES OUTPUT_NAME pancpp)
set_target_properties(pan_cpp PROPERTIES DEBUG_POSTFIX "d")
target_link_libraries(pan_cpp PUBLIC pan_c)
#target_include_directories(pan_cpp PUBLIC "${CMAKE_SOURCE_DIR}/include")

set(PUBLIC_HEADERS
    "${CMAKE_SOURCE_DIR}/include/pan.hpp"
    "${CMAKE_SOURCE_DIR}/include/go_handle.hpp"
)
set_target_properties(pan_cpp PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
set_target_properties(pan_cpp PROPERTIES VERSION "1.0.0")
set_target_properties(pan_cpp PROPERTIES SOVERSION "1")

install(TARGETS pan_cpp
EXPORT pancppTargets
    ARCHIVE
    LIBRARY
    PUBLIC_HEADER DESTINATION include/pan
)



#target_sources( fun PRIVATE ${SOURCES} PUBLIC FILE_SET HEADERS 
#BASE_DIRS ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/conf
#FILES ${HEADERS}
#)
            #target_include_directories(fun PUBLIC ${PROJECT_SOURCE_DIR}/src )
# target_include_directories(fun PUBLIC  
# $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>  
# $<INSTALL_INTERFACE:/usr/local/include/neo/fun>  # <prefix>/include/mylib) 
# )

#set_target_properties(fun PROPERTIES PUBLIC_HEADER ${HEADERS})
#include(GNUInstallDirs)
#install(TARGETS neo-fun FILE_SET HEADERS)
#install(TARGETS neo-fun      PUBLIC_HEADER      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/neo-fun )

#install(TARGETS fun
#        EXPORT funTargets
#        FILE_SET HEADERS DESTINATION include/neo/fun
#        # for executables and dll on Win
#        RUNTIME DESTINATION bin
#        # shared libraries
#        LIBRARY DESTINATION lib/neo/fun
#        # for static libraries
#        ARCHIVE DESTINATION lib/neo/fun
#        INCLUDES DESTINATION include/neo/fun
#        PUBLIC_HEADER DESTINATION include )

        install(EXPORT pancppTargets
        FILE pancppTargets.cmake
        NAMESPACE pancpp::
        DESTINATION lib/cmake/pan )
    
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        "pancppConfigVersion.cmake"
        VERSION ${pan_cpp_VERSION}
        COMPATIBILITY AnyNewerVersion)
    
    install(FILES "pancppConfig.cmake" "${CMAKE_CURRENT_BINARY_DIR}/pancppConfigVersion.cmake"
        DESTINATION lib/cmake/pan)        