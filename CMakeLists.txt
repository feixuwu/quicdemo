cmake_minimum_required(VERSION 3.10)
project(echo_server)

set(CMAKE_CXX_STANDARD 17)

find_package(gflags COMPONENTS static)
find_package(mvfst REQUIRED)

add_executable(echo_server main.cpp 
    server.cpp
    client.cpp)

include_directories(${mvfst_INCLUDE_DIRS})
target_link_libraries(echo_server ${mvfst_LIBRARIES})
