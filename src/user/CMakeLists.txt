# 用户态程序 CMake 构建文件
# 编译 C++ 用户态逻辑，包括事件处理、日志记录、数据欺骗等功能

# 设置源文件
set(USER_SOURCES
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 设置头文件
set(USER_HEADERS
    ${CMAKE_SOURCE_DIR}/include/common.h
    ${CMAKE_SOURCE_DIR}/include/logger.h
    ${CMAKE_SOURCE_DIR}/include/event_structs.h
    ${CMAKE_SOURCE_DIR}/include/bpf_loader.h
)

# 创建可执行文件
add_executable(ebpf_file_monitor ${USER_SOURCES} ${USER_HEADERS})

# 链接 libbpf 静态库
target_link_libraries(ebpf_file_monitor ${LIBBPF_STATIC_LIB})

# 设置 libbpf 包含目录
target_include_directories(ebpf_file_monitor PRIVATE 
    ${LIBBPF_INCLUDE_DIR}
    ${LIBBPF_INCLUDE_DIR}/uapi
)

# 链接系统库
target_link_libraries(ebpf_file_monitor
    pthread      # 多线程支持
    elf          # ELF 文件处理
    z            # 压缩库
    cap          # 权限管理库
)

# 设置编译选项
target_compile_options(ebpf_file_monitor PRIVATE
    -Wall
    -Wextra
    -std=c++17
    -fPIC
)

# 设置链接选项
target_link_options(ebpf_file_monitor PRIVATE
    -static-libgcc
    -static-libstdc++
)

# 添加依赖关系：确保 eBPF 程序先编译
add_dependencies(ebpf_file_monitor file_monitor_bpf)

# 设置安装目标
install(TARGETS ebpf_file_monitor
        RUNTIME DESTINATION bin
        COMPONENT runtime)

# 设置调试信息
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(ebpf_file_monitor PRIVATE DEBUG=1)
    target_compile_options(ebpf_file_monitor PRIVATE -g -O0)
else()
    target_compile_options(ebpf_file_monitor PRIVATE -O2)
endif()

# 打印构建信息
message(STATUS "用户态程序构建配置:")
message(STATUS "  源文件: ${USER_SOURCES}")
message(STATUS "  编译器: ${CMAKE_CXX_COMPILER}")
message(STATUS "  C++ 标准: ${CMAKE_CXX_STANDARD}")
message(STATUS "  构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "  libbpf 库: ${LIBBPF_STATIC_LIB}")