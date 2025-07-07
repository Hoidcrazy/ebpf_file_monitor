# 设置用户态程序源文件
set(USER_SOURCES
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 创建用户态可执行文件
add_executable(file_monitor ${USER_SOURCES})

# 链接依赖库 - 使用项目编译的libbpf
target_link_libraries(file_monitor
    PRIVATE
        bpf-static  # 项目内编译的libbpf静态库
        ${LIBELF_LIBRARIES}
        ${ZLIB_LIBRARIES}
        Threads::Threads
)

# 包含目录
target_include_directories(file_monitor
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/external/libbpf/include
        ${CMAKE_SOURCE_DIR}/external/libbpf/include/uapi
        ${CMAKE_BINARY_DIR}/src/ebpf  # 生成的skeleton头文件位置
)

# 添加对libbpf的依赖
add_dependencies(file_monitor bpf-static)

# 安装目标
install(TARGETS file_monitor DESTINATION bin)