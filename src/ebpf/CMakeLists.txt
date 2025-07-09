cmake_minimum_required(VERSION 3.16)

# 设置 eBPF 包含路径
set(EBPF_INCLUDES
    "${KERNEL_HEADERS_DIR}/arch/x86/include"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/generated"
    "${KERNEL_HEADERS_DIR}/include"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/uapi"
    "${KERNEL_HEADERS_DIR}/arch/x86/include/generated/uapi"
    "${KERNEL_HEADERS_DIR}/include/uapi"
    "${KERNEL_HEADERS_DIR}/include/generated/uapi"
    "${PROJECT_SOURCE_DIR}/include"
    "${LIBBPF_BUILD_DIR}/include"
)

# 生成包含标志
set(EBPF_INCLUDE_FLAGS "")
foreach(include_dir IN LISTS EBPF_INCLUDES)
    set(EBPF_INCLUDE_FLAGS "${EBPF_INCLUDE_FLAGS}-I${include_dir} ")
endforeach()

# 设置 eBPF 编译标志
set(EBPF_CFLAGS
    "${EBPF_INCLUDE_FLAGS}"
    "-O2 -g"
    "--target=bpf"
    "-D__TARGET_ARCH_x86"
    "-mcpu=v3"
)

# 添加 Clang 12 的特定优化
list(APPEND EBPF_CFLAGS
    "-Xclang -disable-llvm-passes"
    "-Xclang -debug-info-kind=limited"
)

# 创建 eBPF 输出目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/ebpf)

# 添加 eBPF 目标
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.bpf.o
    DEPENDS file_monitor.bpf.c
    COMMENT "Compiling eBPF program: file_monitor.bpf.c"
    VERBATIM
)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/fd_map.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/fd_map.bpf.o
    DEPENDS fd_map.bpf.c
    COMMENT "Compiling eBPF program: fd_map.bpf.c"
    VERBATIM
)

# 生成带 BTF 的对象文件
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    COMMAND ${CLANG} ${EBPF_CFLAGS} -g -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o
    DEPENDS file_monitor.bpf.c
    COMMENT "Generating BTF-enabled eBPF object"
    VERBATIM
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