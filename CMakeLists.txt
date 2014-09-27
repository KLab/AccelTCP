project(acceltcp)
cmake_minimum_required(VERSION 2.6.2)
include_directories(/usr/local/include /usr/include)
link_directories(/usr/local/lib /usr/lib)

set(acceltcp_srcs acceltcp_main.c acceltcp.c evsock.c http_handler.c http_parser.c)
add_executable(acceltcp ${acceltcp_srcs})
target_link_libraries(acceltcp ev)
target_link_libraries(acceltcp ssl)
target_link_libraries(acceltcp crypto)

add_subdirectory(gtest-1.7.0)
add_subdirectory(test)
