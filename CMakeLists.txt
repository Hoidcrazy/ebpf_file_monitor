# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 设置BPF工具链路径
set(BPFTOOL_PATH ${CMAKE_BINARY_DIR}/bpftool/bin/bpftool)
set(LIBBPF_PATH ${CMAKE_BINARY_DIR}/libbpf/lib/libbpf.a)

# 添加子目录
add_subdirectory(external)
add_subdirectory(src/ebpf)
add_subdirectory(src/user)
add_subdirectory(tests)

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)