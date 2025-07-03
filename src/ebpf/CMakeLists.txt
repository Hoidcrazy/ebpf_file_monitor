cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor_bpf)

find_package(Clang REQUIRED)
find_package(LibBPF REQUIRED)

set(CMAKE_C_FLAGS "-g -O2 -Wall -Werror")
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --target=bpf")

# 编译 BPF 程序生成 .o 对象
add_library(file_monitor_bpf OBJECT file_monitor.bpf.c)
# 指定 BPF 对象为 CO-RE 模式，LIBBPF 会处理 BTF
target_include_directories(file_monitor_bpf PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(file_monitor_bpf bpf)

# 将 BPF 对象复制到用户态可加载位置
add_custom_command(TARGET file_monitor_bpf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:file_monitor_bpf> ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
)
