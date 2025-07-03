cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor_user)

# 包含头文件目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 寻找 libbpf 和 BPF 库
find_package(PkgConfig REQUIRED)
pkg_search_module(LIBBPF libbpf)

# 可执行文件
add_executable(ebpf_file_monitor
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 链接 libbpf 和 libelf
target_link_libraries(ebpf_file_monitor
    ${LIBBPF_LIBRARIES}
    elf
    pthread
)

# 设置编译选项
target_compile_options(ebpf_file_monitor PRIVATE
    -g -O2
)

add_dependencies(user_binary_target file_monitor_bpf_target)