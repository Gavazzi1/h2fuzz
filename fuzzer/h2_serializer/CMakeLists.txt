#cmake_minimum_required(VERSION 3.17)
#project(h2srlz)

#set(CMAKE_CXX_STANDARD 11)

add_subdirectory(src/hpacker)
add_subdirectory(test)
add_library(h2srlz src/frames/common/utils.cpp)
target_link_libraries(h2srlz hpack)