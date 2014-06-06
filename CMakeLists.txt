project(acceltcp)
cmake_minimum_required(VERSION 2.6.2)
include_directories(~/include /usr/local/include /usr/include)

set(acceltcp_srcs acceltcp.c evsock.c http_handler.c http_parser.c)
add_executable(acceltcp ${acceltcp_srcs})
target_link_libraries(acceltcp ev)
target_link_libraries(acceltcp ssl)
target_link_libraries(acceltcp crypto)
