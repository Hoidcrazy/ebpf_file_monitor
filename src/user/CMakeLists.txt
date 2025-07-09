cmake_minimum_required(VERSION 3.16)

# 添加用户态可执行文件
add_executable(file_monitor
    main.cpp
    logger.cpp
    bpf_loader.cpp
    skeleton_wrapper.cpp
)

# 设置版本信息
target_compile_definitions(file_monitor PRIVATE 
    PROJECT_VERSION=\"${PROJECT_VERSION}\"
    KERNEL_VERSION=\"${KERNEL_RELEASE}\"
)

# 查找依赖库
find_library(LIBELF elf REQUIRED)
find_library(ZLIB z REQUIRED)
find_library(RT rt REQUIRED)

# 链接依赖库
target_link_libraries(file_monitor
    PRIVATE
        libbpf
        ${LIBELF}
        ${ZLIB}
        ${RT}
        pthread
)

# 包含目录
target_include_directories(file_monitor
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${LIBBPF_BUILD_DIR}/include
        ${CMAKE_BINARY_DIR}/bin/ebpf  # 包含 eBPF 生成的 skel.h
)

# 设置编译选项
target_compile_definitions(file_monitor
    PRIVATE
        _GNU_SOURCE
        __USE_GNU
)

# Clang 12 特定警告抑制
if(CLANG_EXECUTABLE MATCHES "clang-12")
    target_compile_options(file_monitor PRIVATE
        "-Wno-deprecated-declarations"
        "-Wno-ignored-attributes"
    )
endif()

# 安装目标
install(TARGETS file_monitor RUNTIME DESTINATION bin)