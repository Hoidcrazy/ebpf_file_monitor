# src/ebpf/CMakeLists.txt
# 查找Clang
find_program(CLANG_PATH clang REQUIRED)
find_program(BPFTOOL_PATH bpftool REQUIRED)
# find_program(PAHOLE_PATH pahole REQUIRED)

# 设置eBPF编译选项
set(EBPF_FLAGS
    -O2 -g -Wall
    -target bpf
    -D__TARGET_ARCH_x86
    # 禁止 Clang 自带的 std headers
    -nostdinc
    -I${CMAKE_SOURCE_DIR}/include
    # 添加 libbpf 的源代码路径
    -I${CMAKE_SOURCE_DIR}/external/libbpf/src
    # 移除非UAPI路径：
    # -I${CMAKE_SOURCE_DIR}/external/libbpf/include
    # 仅保留UAPI路径（内核兼容）：
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include/uapi
    # 添加 glibc 的系统头文件路径,以支持标准库函数
    -I/usr/include/x86_64-linux-gnu
)


# 编译eBPF程序
add_custom_command(
    OUTPUT file_monitor.bpf.o
    COMMAND ${CLANG_PATH} ${EBPF_FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.bpf.o
    DEPENDS file_monitor.bpf.c
    COMMENT "编译 eBPF 程序"
)

# 生成Skeleton头文件
add_custom_command(
    OUTPUT file_monitor.skel.h
    COMMAND ${BPFTOOL_PATH} gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.bpf.o > ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.skel.h
    DEPENDS file_monitor.bpf.o
    COMMENT "生成 eBPF Skeleton"
)

# 添加自定义目标
add_custom_target(ebpf ALL DEPENDS file_monitor.skel.h)

# 设置包含目录变量 - 不再使用 PARENT_SCOPE
set(EBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "eBPF include directories")