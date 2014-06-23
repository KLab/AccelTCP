include_directories(${gtest_SOURCE_DIR}/include)
set(test_sources
	test_acceltcp.cc
)
add_executable(acceltcp_unittest ${test_sources})
target_link_libraries(acceltcp_unittest gtest_main)
