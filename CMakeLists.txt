cmake_minimum_required(VERSION 3.0)

#项目名称
project(CPPTEA)

#设置使用C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#生成可执行的文件
aux_source_directory(. DIR_TOOT_SRCS)
add_executable(CPPTEA ${DIR_TOOT_SRCS})
