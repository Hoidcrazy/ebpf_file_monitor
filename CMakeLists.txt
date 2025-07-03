## 顶层CMakeLists.txt

cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}build/bin)

# 增加子目录：ebpf 内核程序和用户态程序
add_subdirectory(src/ebpf)
add_subdirectory(src/user)

# 让用户程序等 file_monitor.bpf.o 编译完
add_dependencies(user_program file_monitor_bpf_target)
