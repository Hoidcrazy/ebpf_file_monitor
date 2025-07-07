# 确保bpftool已构建
if(NOT TARGET bpftool)
    message(FATAL_ERROR "bpftool target not found")
endif()

# 使用生成器表达式获取bpftool路径
set(BPFTOOL_PATH $<TARGET_FILE:bpftool>)

# 设置eBPF编译标志
set(EBPF_CFLAGS
    -O2 -g -Wall
    -target bpf
    -D__TARGET_ARCH_x86
    -I${CMAKE_SOURCE_DIR}/include
    -I${CMAKE_SOURCE_DIR}/external/libbpf/src
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include/uapi
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
    
    # 编译eBPF对象
    add_custom_command(
        OUTPUT ${TARGET_NAME}.bpf.o
        COMMAND ${CLANG} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${TARGET_NAME}.bpf.o
        DEPENDS ${SOURCE_FILE} ${CMAKE_SOURCE_DIR}/include/event_structs.h
        COMMENT "Compiling eBPF program: ${SOURCE_FILE}"
    )
    
    # 生成skeleton头文件 - 使用项目编译的bpftool
    add_custom_command(
        OUTPUT ${TARGET_NAME}.skel.h
        COMMAND ${BPFTOOL_PATH} gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.bpf.o > ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.skel.h
        DEPENDS ${TARGET_NAME}.bpf.o bpftool
        COMMENT "Generating skeleton for ${TARGET_NAME}"
    )
    
    # 创建自定义目标
    add_custom_target(${TARGET_NAME}_bpf ALL
        DEPENDS 
            ${TARGET_NAME}.bpf.o
            ${TARGET_NAME}.skel.h
    )
    
    # 设置目标属性
    set_target_properties(${TARGET_NAME}_bpf PROPERTIES
        OUTPUT_NAME "${TARGET_NAME}"
        FOLDER "eBPF Programs"
    )
    
    # 安装生成的文件
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.bpf.o
        ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.skel.h
        DESTINATION bin/ebpf
    )
endforeach()

# 添加公共头文件路径
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src/ebpf  # 生成的skeleton头文件位置
)