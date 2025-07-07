# src/ebpf/CMakeLists.txt
# 编译eBPF内核程序

# 查找Clang
find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(LLVM_STRIP_EXECUTABLE llvm-strip REQUIRED)

# 设置BPF编译标志
set(BPF_FLAGS
    -target bpf
    -g
    -O2
    -Wall
    -Werror
    -D__TARGET_ARCH_x86
)

# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external/libbpf/include
)

# 添加eBPF源文件
set(EBPF_SOURCES
    file_monitor.bpf.c
    fd_map.bpf.c
)

# 为每个eBPF源文件创建编译目标
foreach(src ${EBPF_SOURCES})
    get_filename_component(name ${src} NAME_WE)
    
    # 编译.o文件
    add_custom_command(
        OUTPUT ${name}.bpf.o
        COMMAND ${CLANG_EXECUTABLE} ${BPF_FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${src} -o ${name}.bpf.o
        DEPENDS ${src}
        COMMENT "Compiling eBPF program: ${src}"
    )
    
    # 生成skeleton头文件
    add_custom_command(
        OUTPUT ${name}.skel.h
        COMMAND ${BPFTOOL_PATH} gen skeleton ${name}.bpf.o > ${name}.skel.h
        DEPENDS ${name}.bpf.o bpftool_build
        COMMENT "Generating skeleton for ${name}"
    )
    
    # 添加到目标
    list(APPEND EBPF_OBJECTS ${name}.bpf.o)
    list(APPEND EBPF_SKELETONS ${name}.skel.h)
endforeach()

# 创建自定义目标
add_custom_target(ebpf_programs ALL
    DEPENDS ${EBPF_OBJECTS} ${EBPF_SKELETONS}
)

# 安装eBPF程序
install(FILES ${EBPF_OBJECTS} DESTINATION ebpf)