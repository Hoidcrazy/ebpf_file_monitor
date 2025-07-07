cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor VERSION 1.0.0 LANGUAGES C CXX)

# 设置编译选项
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

# 设置输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 查找依赖包
find_package(Threads REQUIRED)

# 添加libbpf编译目标
add_subdirectory(external/libbpf)

# 设置bpftool路径变量
set(BPFTOOL ${CMAKE_BINARY_DIR}/external/libbpf/tools/bpftool/bpftool CACHE INTERNAL "Path to bpftool")

# 添加eBPF程序和用户态程序
add_subdirectory(src/ebpf)
add_subdirectory(src/user)

# 安装目标
install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/ DESTINATION bin)
install(DIRECTORY ${CMAKE_BINARY_DIR}/lib/ DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)