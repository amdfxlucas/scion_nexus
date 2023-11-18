

find_package( Boost COMPONENTS unit_test_framework REQUIRED )

set(sources 
KeccakTests.cpp )
add_executable( sha3_test ${sources} )
target_link_libraries( sha3_test 
sha3 
Boost::unit_test_framework
 #${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
 )