# src/user/CMakeLists.txt
# 编译用户态程序

# 添加可执行文件
add_executable(file_monitor
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 包含目录
target_include_directories(file_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external/libbpf/include
    ${CMAKE_BINARY_DIR}/src/ebpf  # 包含生成的skeleton头文件
)

# 链接库
target_link_libraries(file_monitor
    ${LIBBPF_PATH}
    elf
    z
)

# 添加依赖
add_dependencies(file_monitor ebpf_programs libbpf bpftool_build)

# 安装可执行文件
install(TARGETS file_monitor DESTINATION bin)