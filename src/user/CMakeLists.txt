## src/user/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor_user)

# 包含头文件目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/external/libbpf/include)

# 寻找 libbpf 和 BPF 库
find_package(PkgConfig REQUIRED)
pkg_search_module(LIBBPF libbpf)

# # 查找 libbpf 静态库
# add_library(libbpf STATIC IMPORTED)
# set_target_properties(libbpf PROPERTIES
#     IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/external/libbpf/src/libbpf.a
#     INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/external/libbpf/include
# )

# 编译用户态程序
add_executable(ebpf_file_monitor
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 链接 libbpf 和 libelf + 其他依赖
target_link_libraries(ebpf_file_monitor
    ${LIBBPF_LIBRARIES}
    elf
    pthread
)

# 设置编译选项
target_compile_options(ebpf_file_monitor PRIVATE
    -g -O2
)

# 构建依赖 eBPF 对象
add_dependencies(ebpf_file_monitor file_monitor_bpf_target)