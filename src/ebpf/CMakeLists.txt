## src/ebpf/CMakeLists.txt

cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor_bpf C)

# 包含内核头或自定义头
include_directories(${CMAKE_SOURCE_DIR}/include)

# 设置 BPF 编译器与参数
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -Wall -target bpf -m64")

# BPF 源文件（可扩展多个）
set(BPF_SOURCES
    file_monitor.bpf.c
    fd_map.bpf.c
)

# 编译所有 bpf 对象
# 创建 OBJECT 库，用于编译 BPF 程序（CO-RE）
add_library(file_monitor_bpf_obj OBJECT ${BPF_SOURCES})

# 添加头文件目录（内核 headers、libbpf headers、自定义头）
target_include_directories(file_monitor_bpf_obj PRIVATE
    ${CMAKE_SOURCE_DIR}/external/libbpf/include
    ${CMAKE_SOURCE_DIR}/external/libbpf/src
    ${CMAKE_SOURCE_DIR}/src/ebpf
    ${CMAKE_SOURCE_DIR}/include
)

# 定义复制生成的 BPF 对象文件的自定义命令（绕过 OBJECT 库不支持 POST_BUILD）
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:file_monitor_bpf_obj> ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
    DEPENDS file_monitor_bpf_obj
)

# 创建一个虚拟 target 依赖上面复制动作，方便用户态程序依赖
add_custom_target(file_monitor_bpf_target
    DEPENDS ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
)

# 设置一个变量，方便顶层 CMakeLists.txt 和用户态依赖此 target
set(BPF_TARGET file_monitor_bpf_target CACHE INTERNAL "BPF target to depend on")
