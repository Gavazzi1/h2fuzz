#cmake_minimum_required(VERSION 3.17)
#project(h2srlz)

#set(CMAKE_CXX_STANDARD 11)

add_library(hpack HPacker.h HPacker.cpp HPackTable.h HPackTable.cpp StaticTable.h hpack_huffman_table.h)