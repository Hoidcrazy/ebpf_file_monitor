## src/ebpf/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor_bpf)

# 编译外部 libbpf
add_subdirectory(
    ${CMAKE_SOURCE_DIR}/external/libbpf
    ${CMAKE_BINARY_DIR}/libbpf-build
)

# clang编译bpf程序的flags
set(CMAKE_C_FLAGS "-g -O2 -Wall -Werror --target=bpf")

# 编译 file_monitor.bpf.c 为 CO-RE 兼容的 BPF 对象文件
add_library(file_monitor_bpf OBJECT file_monitor.bpf.c)

# 该 BPF 对象启用 CO-RE（Compile Once – Run Everywhere）模式，
# libbpf 会利用内核中的 BTF（BPF Type Format）信息，
# 实现 BPF 程序跨内核版本的兼容加载和运行
target_include_directories(file_monitor_bpf PRIVATE
    ${CMAKE_SOURCE_DIR}/external/libbpf/include
    ${CMAKE_SOURCE_DIR}/external/libbpf/src
    ${CMAKE_SOURCE_DIR}/src/ebpf
)

# 编译后把 .o 复制到 bin 目录方便加载
add_custom_command(TARGET file_monitor_bpf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:file_monitor_bpf> ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
)

# 拷贝 .o 文件到 bin 目录
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:file_monitor_bpf> ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
    DEPENDS file_monitor_bpf
)

# 创建构建目标
add_custom_target(file_monitor_bpf_target
    DEPENDS ${CMAKE_BINARY_DIR}/bin/file_monitor.bpf.o
)
