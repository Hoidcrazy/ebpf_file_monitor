cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor LANGUAGES C CXX)


# 设置 C 和 C++ 编译器为 Clang
# set(CMAKE_C_COMPILER clang)
# set(CMAKE_CXX_COMPILER clang++)

# 设置编译选项
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/usr/include")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/include")

# 为 eBPF 编译设置目标平台和优化
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target bpf -O2")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -target bpf -O2")

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 添加子目录
add_subdirectory(external/libbpf)
add_subdirectory(src/ebpf)
add_subdirectory(src/user)
add_subdirectory(tests)

# 移除无效的 PARENT_SCOPE 设置