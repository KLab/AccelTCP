include_directories(${gtest_SOURCE_DIR}/include ..)
set(test_sources
	test_acceltcp.cc
	test_evsock.cc
	test_http_handler.cc
	test_http_parser.cc
	../acceltcp.c
	../evsock.c
	../http_handler.c
	../http_parser.c
)
add_executable(acceltcp_unittest ${test_sources})
target_link_libraries(acceltcp_unittest gtest_main)
target_link_libraries(acceltcp_unittest ev)
target_link_libraries(acceltcp_unittest ssl)
target_link_libraries(acceltcp_unittest crypto)
