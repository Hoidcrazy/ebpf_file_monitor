# src/ebpf/CMakeLists.txt

# 确保bpftool已构建
if(NOT TARGET bpftool)
    message(FATAL_ERROR "bpftool target not found. Please make sure libbpf submodule is initialized.")
endif()

# 获取bpftool路径
get_target_property(BPFTOOL_PATH bpftool LOCATION)
message(STATUS "Using bpftool: ${BPFTOOL_PATH}")

# 查找必要的工具
find_program(CLANG_PATH clang REQUIRED)
find_program(LLVM_STRIP_PATH llvm-strip REQUIRED)

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

# 添加内核版本相关宏定义
if(KERNEL_VERSION)
    set(EBPF_CFLAGS ${EBPF_CFLAGS} -DKERNEL_VERSION=${KERNEL_VERSION})
endif()

# 定义eBPF源文件
set(EBPF_SOURCES
    file_monitor.bpf.c
    fd_map.bpf.c
)

# 创建目录用于存放生成的文件
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)

# 为每个eBPF源文件创建目标
foreach(SOURCE_FILE ${EBPF_SOURCES})
    get_filename_component(TARGET_NAME ${SOURCE_FILE} NAME_WE)
    set(OBJ_FILE ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.bpf.o)
    set(SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/${TARGET_NAME}.skel.h)
    
    # 编译eBPF对象
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_PATH} ${EBPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${OBJ_FILE}
        DEPENDS ${SOURCE_FILE} ${CMAKE_SOURCE_DIR}/include/event_structs.h
        COMMENT "Compiling eBPF program: ${SOURCE_FILE}"
    )
    
    # 生成skeleton头文件
    add_custom_command(
        OUTPUT ${SKEL_FILE}
        COMMAND ${BPFTOOL_PATH} gen skeleton ${OBJ_FILE} > ${SKEL_FILE}
        DEPENDS ${OBJ_FILE} bpftool
        COMMENT "Generating skeleton for ${TARGET_NAME}"
    )
    
    # 可选：精简BPF对象文件
    add_custom_command(
        OUTPUT ${OBJ_FILE}.stripped
        COMMAND ${LLVM_STRIP_PATH} -g ${OBJ_FILE} -o ${OBJ_FILE}.stripped
        DEPENDS ${OBJ_FILE}
        COMMENT "Stripping debug info from ${TARGET_NAME}.bpf.o"
    )
    
    # 创建主目标
    add_custom_target(${TARGET_NAME}_bpf ALL
        DEPENDS 
            ${OBJ_FILE}
            ${SKEL_FILE}
            ${OBJ_FILE}.stripped
    )
    
    # 将生成的文件添加到目标属性
    set_source_files_properties(${SKEL_FILE} PROPERTIES GENERATED TRUE)
    
    # 添加公共头文件路径
    include_directories(
        ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    
    # 打印状态信息
    message(STATUS "Added eBPF target: ${TARGET_NAME}_bpf")
endforeach()

# 创建安装规则
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.bpf.o
    ${CMAKE_CURRENT_BINARY_DIR}/fd_map.bpf.o
    ${CMAKE_CURRENT_BINARY_DIR}/generated/file_monitor.skel.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/fd_map.skel.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/ebpf
)

# 添加自定义目标来显示构建信息
add_custom_target(ebpf_info
    COMMAND ${CMAKE_COMMAND} -E echo "======================================"
    COMMAND ${CMAKE_COMMAND} -E echo "eBPF Build Configuration"
    COMMAND ${CMAKE_COMMAND} -E echo "--------------------------------------"
    COMMAND ${CMAKE_COMMAND} -E echo "Clang: ${CLANG_PATH}"
    COMMAND ${CMAKE_COMMAND} -E echo "llvm-strip: ${LLVM_STRIP_PATH}"
    COMMAND ${CMAKE_COMMAND} -E echo "bpftool: ${BPFTOOL_PATH}"
    COMMAND ${CMAKE_COMMAND} -E echo "Compiler flags: ${EBPF_CFLAGS}"
    COMMAND ${CMAKE_COMMAND} -E echo "Generated skeletons: ${CMAKE_CURRENT_BINARY_DIR}/generated"
    COMMAND ${CMAKE_COMMAND} -E echo "======================================"
    COMMENT "eBPF build information"
)

# 添加依赖，确保在构建用户态程序前完成eBPF构建
add_dependencies(ebpf_info ${EBPF_SOURCES})

# 设置输出目录
set_target_properties(${EBPF_SOURCES} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/ebpf
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/ebpf
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/ebpf
)