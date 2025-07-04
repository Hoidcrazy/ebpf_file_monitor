# eBPF 内核程序 CMake 构建文件
# 编译 eBPF 程序并生成 skeleton 头文件

# 设置 eBPF 源文件
set(EBPF_SOURCES
    file_monitor.bpf.c
    fd_map.bpf.c
)

# 设置编译选项
set(CLANG_FLAGS 
    -target bpf 
    -Wall 
    -Wextra 
    -O2 
    -g 
    -D__TARGET_ARCH_x86_64
    -I${CMAKE_SOURCE_DIR}/include
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include
    -I${CMAKE_SOURCE_DIR}/external/libbpf/include/uapi
)

# 创建自定义目标来编译 eBPF 程序
add_custom_target(file_monitor_bpf ALL)

# 编译每个 eBPF 源文件
foreach(EBPF_SOURCE ${EBPF_SOURCES})
    get_filename_component(EBPF_NAME ${EBPF_SOURCE} NAME_WE)
    
    # 设置输出文件路径
    set(EBPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/${EBPF_NAME}.o)
    
    # 编译 eBPF 程序
    add_custom_command(
        OUTPUT ${EBPF_OBJECT}
        COMMAND ${CLANG_EXEC} ${CLANG_FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${EBPF_SOURCE} -o ${EBPF_OBJECT}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${EBPF_SOURCE}
        COMMENT "编译 eBPF 程序: ${EBPF_SOURCE}"
        VERBATIM
    )
    
    # 添加依赖
    add_dependencies(file_monitor_bpf ${EBPF_OBJECT})
    
    # 添加到目标列表
    set_property(TARGET file_monitor_bpf APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_OBJECT})
endforeach()

# 生成主要的 eBPF 对象文件
set(MAIN_EBPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.bpf.o)
add_custom_command(
    OUTPUT ${MAIN_EBPF_OBJECT}
    COMMAND ${CLANG_EXEC} ${CLANG_FLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c -o ${MAIN_EBPF_OBJECT}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/file_monitor.bpf.c
    COMMENT "编译主 eBPF 程序: file_monitor.bpf.c"
    VERBATIM
)

# 使用 llvm-strip 优化 eBPF 对象文件
set(STRIPPED_EBPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.bpf.stripped.o)
add_custom_command(
    OUTPUT ${STRIPPED_EBPF_OBJECT}
    COMMAND ${LLVM_STRIP_EXEC} -g ${MAIN_EBPF_OBJECT} -o ${STRIPPED_EBPF_OBJECT}
    DEPENDS ${MAIN_EBPF_OBJECT}
    COMMENT "优化 eBPF 对象文件"
    VERBATIM
)

# 生成 skeleton 头文件（如果支持）
find_program(BPFTOOL_EXEC bpftool)
if(BPFTOOL_EXEC)
    set(SKELETON_HEADER ${CMAKE_CURRENT_BINARY_DIR}/file_monitor.skel.h)
    add_custom_command(
        OUTPUT ${SKELETON_HEADER}
        COMMAND ${BPFTOOL_EXEC} gen skeleton ${STRIPPED_EBPF_OBJECT} > ${SKELETON_HEADER}
        DEPENDS ${STRIPPED_EBPF_OBJECT}
        COMMENT "生成 eBPF skeleton 头文件"
        VERBATIM
    )
    
    add_dependencies(file_monitor_bpf ${SKELETON_HEADER})
    
    # 安装 skeleton 头文件
    install(FILES ${SKELETON_HEADER}
            DESTINATION include
            COMPONENT development)
    
    message(STATUS "将生成 eBPF skeleton 头文件")
else()
    message(WARNING "未找到 bpftool，跳过 skeleton 头文件生成")
endif()

# 将最终的 eBPF 对象文件添加到目标
add_dependencies(file_monitor_bpf ${STRIPPED_EBPF_OBJECT})

# 安装 eBPF 对象文件
install(FILES ${STRIPPED_EBPF_OBJECT}
        DESTINATION share/ebpf_file_monitor
        RENAME file_monitor.bpf.o
        COMPONENT runtime)

# 清理文件
set_property(TARGET file_monitor_bpf APPEND PROPERTY 
             ADDITIONAL_MAKE_CLEAN_FILES 
             ${MAIN_EBPF_OBJECT} 
             ${STRIPPED_EBPF_OBJECT})

if(BPFTOOL_EXEC)
    set_property(TARGET file_monitor_bpf APPEND PROPERTY 
                 ADDITIONAL_MAKE_CLEAN_FILES 
                 ${SKELETON_HEADER})
endif()

# 添加验证目标
add_custom_target(verify_ebpf
    COMMAND ${LLVM_STRIP_EXEC} --version
    COMMAND ${CLANG_EXEC} --version
    COMMAND echo "eBPF 编译工具验证通过"
    COMMENT "验证 eBPF 编译工具"
    VERBATIM
)

# 打印构建信息
message(STATUS "eBPF 程序构建配置:")
message(STATUS "  源文件: ${EBPF_SOURCES}")
message(STATUS "  Clang: ${CLANG_EXEC}")
message(STATUS "  LLVM Strip: ${LLVM_STRIP_EXEC}")
message(STATUS "  BPFTool: ${BPFTOOL_EXEC}")
message(STATUS "  编译选项: ${CLANG_FLAGS}")