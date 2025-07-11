cmake_minimum_required(VERSION 3.16)

# 设置 eBPF 包含路径
set(EBPF_INCLUDES
    "${KERNEL_HEADERS_DIR}/arch/x86/include"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/generated"
    "${KERNEL_HEADERS_DIR}/include"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/uapi"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/generated/uapi"
    "${PROJECT_SOURCE_DIR}/include"     # vmlinux.h 位置
    "${LIBBPF_BUILD_DIR}/include"
)

# 生成包含标志列表 - 每个选项单独列出
set(EBPF_INCLUDE_FLAGS_LIST "")
foreach(include_dir IN LISTS EBPF_INCLUDES)
    list(APPEND EBPF_INCLUDE_FLAGS_LIST "-I${include_dir}")
endforeach()

# 设置 eBPF 编译标志 - 每个选项单独列出
set(EBPF_CFLAGS
    ${EBPF_INCLUDE_FLAGS_LIST}  # 包含路径列表
    "-O2"                       # 优化级别单独列出
    "-g"                        # 调试信息单独列出
    "--target=bpf"              # BPF 目标
    "-D__TARGET_ARCH_x86"       # 目标架构
    "-mcpu=v3"                  # CPU 特性
)

# 创建 eBPF 输出目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/ebpf)

# 添加 eBPF 目标
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
    DEPENDS file_monitor.bpf.c vmlinux_h_dep  # 依赖 vmlinux.h
    COMMENT "Compiling eBPF program: file_monitor.bpf.c"
    VERBATIM
    COMMAND_EXPAND_LISTS  # 关键修复：展开列表为单独参数
)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/fd_map.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
    DEPENDS fd_map.bpf.c
    COMMENT "Compiling eBPF program: fd_map.bpf.c"
    VERBATIM
    COMMAND_EXPAND_LISTS  # 关键修复：展开列表为单独参数
)

# 生成带 BTF 的对象文件
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    DEPENDS file_monitor.bpf.c
    COMMENT "Generating BTF-enabled eBPF object"
    VERBATIM
    COMMAND_EXPAND_LISTS  # 关键修复：展开列表为单独参数
)

# 生成 skeleton 头文件
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.skel.h
    COMMAND ${BPFTOOL} gen skeleton ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o > ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.skel.h
    DEPENDS ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    COMMENT "Generating BPF skeleton from BTF object"
    VERBATIM
)

# 创建 eBPF 目标
add_custom_target(ebpf_programs ALL
    DEPENDS 
        ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
        ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
        ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
        ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.skel.h
)

# 安装规则
install(FILES 
    ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
    ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
    ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    DESTINATION bin/ebpf
)

# 添加自定义目标验证 BTF
add_custom_target(verify_btf
    COMMAND ${LLVM_OBJDUMP} -S ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o | grep BTF
    COMMENT "Verifying BTF support in eBPF object"
    DEPENDS ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
)