# 查找必要的工具
find_program(CLANG_PATH clang REQUIRED)
find_program(LLVM_STRIP_PATH llvm-strip REQUIRED)

# 设置eBPF编译标志
set(EBPF_CFLAGS
    -O2 -g -Wall
    -target bpf
    -D__TARGET_ARCH_x86
    -I${CMAKE_SOURCE_DIR}/include
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include/uapi
    -I${CMAKE_SOURCE_DIR}/external/libbpf/src
    -I${CMAKE_BINARY_DIR}/external/libbpf
    -fno-stack-protector
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
    -Wno-unknown-warning-option
)

# 添加BTF支持（CO-RE）
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(EBPF_CFLAGS ${EBPF_CFLAGS} -D__x86_64__)
endif()

# 定义eBPF源文件
set(EBPF_SOURCES
    file_monitor.bpf.c
    fd_map.bpf.c
)

# 为每个eBPF源文件创建目标
foreach(SOURCE_FILE ${EBPF_SOURCES})
    get_filename_component(TARGET_NAME ${SOURCE_FILE} NAME_WE)
    
    add_custom_command(
        OUTPUT ${TARGET_NAME}.bpf.o
        COMMAND ${CLANG_PATH} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${TARGET_NAME}.bpf.o
        DEPENDS ${SOURCE_FILE} ${CMAKE_SOURCE_DIR}/include/event_structs.h
        COMMENT "Compiling eBPF program: ${SOURCE_FILE}"
    )
    
    add_custom_target(${TARGET_NAME}_bpf_obj DEPENDS ${TARGET_NAME}.bpf.o)
    
    add_custom_command(
        OUTPUT ${TARGET_NAME}.skel.h
        COMMAND ${BPFTOOL} gen skeleton ${TARGET_NAME}.bpf.o > ${TARGET_NAME}.skel.h
        DEPENDS ${TARGET_NAME}.bpf.o bpftool
        COMMENT "Generating skeleton for ${TARGET_NAME}"
    )
    
    add_custom_target(${TARGET_NAME}_skel DEPENDS ${TARGET_NAME}.skel.h)
    
    add_custom_target(${TARGET_NAME}_bpf ALL
        DEPENDS 
            ${TARGET_NAME}_bpf_obj
            ${TARGET_NAME}_skel
    )
    
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.bpf.o
        ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.skel.h
        DESTINATION bin/ebpf
    )
endforeach()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src/ebpf
    ${CMAKE_SOURCE_DIR}/external/libbpf/include
    ${CMAKE_BINARY_DIR}/external/libbpf
)