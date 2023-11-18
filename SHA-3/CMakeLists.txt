
set( sha3_headers 
 Endian.h 
 Rotation.h
  HashFunction.h 
  Keccak.h
   CommandParser.h
    ParserCommon.h 
    RAII_Wrapper.h 
    Hex.h
     stdafx.h
      Base64.h
)

set( sha3_sources 
 HashFunction.cpp 
  Keccak.cpp 
   CommandParser.cpp
    Base64.cpp
)

add_library( sha3 STATIC ${sha3_headers} ${sha3_sources} )



set_target_properties(sha3 PROPERTIES PUBLIC_HEADER "${sha3_headers}")
set_target_properties(sha3 PROPERTIES VERSION "1.0.0")
set_target_properties(sha3 PROPERTIES SOVERSION "1")

install(TARGETS sha3
EXPORT sha3Targets
    ARCHIVE
    LIBRARY
    PUBLIC_HEADER DESTINATION include/sha3
)

        install(EXPORT sha3Targets
        FILE sha3Targets.cmake
        NAMESPACE pancpp::
        DESTINATION lib/cmake/sha3 )
    
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        "sha3ConfigVersion.cmake"
        VERSION ${sha3_VERSION}
        COMPATIBILITY AnyNewerVersion)
    
    install(FILES "sha3Config.cmake" "${CMAKE_CURRENT_BINARY_DIR}/sha3ConfigVersion.cmake"
        DESTINATION lib/cmake/sha3)        