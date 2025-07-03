## 顶层CMakeLists.txt

cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}build/bin)

# 不添加 external/libbpf 子目录，改为手动设置 include 和 lib 路径
# add_subdirectory(external/libbpf)  # 删除或注释掉

# 增加子目录：ebpf 内核程序和用户态程序
add_subdirectory(src/ebpf)
add_subdirectory(src/user)
