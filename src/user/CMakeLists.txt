# src/user/CMakeLists.txt
# 添加用户态程序
add_executable(ebpf_file_monitor
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 包含eBPF生成的头文件
target_include_directories(ebpf_file_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src/ebpf  # 直接使用路径
)

# 链接依赖库
# target_link_libraries(ebpf_file_monitor PRIVATE libbpf)
target_link_libraries(ebpf_file_monitor PRIVATE
    libbpf
    z
    elf
    pthread
)

# 确保ebpf目标先构建
add_dependencies(ebpf_file_monitor ebpf)