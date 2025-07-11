cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor LANGUAGES C CXX)

# 添加vmlinux.h
set(VMLINUX_H_PATH ${PROJECT_SOURCE_DIR}/include/vmlinux.h)
if(NOT EXISTS ${VMLINUX_H_PATH})
    message(FATAL_ERROR "vmlinux.h not found at ${VMLINUX_H_PATH}. Please generate it with: bpftool btf dump file /path/to/vmlinux format c > ${VMLINUX_H_PATH}")
else()
    message(STATUS "Using vmlinux.h at: ${VMLINUX_H_PATH}")
endif()

# 添加 vmlinux.h 作为所有 eBPF 目标的依赖
add_custom_target(vmlinux_h_dep DEPENDS ${VMLINUX_H_PATH})

# 项目版本和基本配置
set(PROJECT_VERSION "1.0.0")
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 设置输出目录在 build/bin 下
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
message(STATUS "All build outputs will be in: ${CMAKE_BINARY_DIR}/bin")

# 检测麒麟系统
execute_process(
    COMMAND grep -q "kylin" /etc/os-release
    RESULT_VARIABLE IS_KYLIN
)
if(IS_KYLIN EQUAL 0)
    set(KYLIN_OS TRUE)
    message(STATUS "Detected Kylin OS, applying compatibility fixes")
    add_definitions(-DKYLIN_OS)
endif()

# 查找 Clang 12
find_program(CLANG_EXECUTABLE clang-12
    PATHS /usr/bin /usr/local/bin
    REQUIRED
)
find_program(CLANGPP_EXECUTABLE clang++-12
    PATHS /usr/bin /usr/local/bin
    REQUIRED
)
find_program(LLC_EXECUTABLE llc-12
    PATHS /usr/bin /usr/local/bin
    REQUIRED
)
find_program(LLVM_OBJDUMP_EXECUTABLE llvm-objdump-12
    PATHS /usr/bin /usr/local/bin
    REQUIRED
)

message(STATUS "Using Clang: ${CLANG_EXECUTABLE}")
message(STATUS "Using LLC: ${LLC_EXECUTABLE}")
message(STATUS "Using llvm-objdump: ${LLVM_OBJDUMP_EXECUTABLE}")

# 设置环境变量
set(CLANG ${CLANG_EXECUTABLE} CACHE STRING "Clang compiler" FORCE)
set(LLC ${LLC_EXECUTABLE} CACHE STRING "LLVM static compiler" FORCE)
set(LLVM_OBJDUMP ${LLVM_OBJDUMP_EXECUTABLE} CACHE STRING "LLVM object dump tool" FORCE)

# 查找 bpftool
find_program(BPFTOOL bpftool
    PATHS /usr/sbin /usr/local/sbin /sbin
    REQUIRED
)
message(STATUS "Using bpftool: ${BPFTOOL}")

# 获取内核版本
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_RELEASE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "Building for kernel: ${KERNEL_RELEASE}")

# 设置内核头文件路径
set(KERNEL_HEADERS_DIR "/lib/modules/${KERNEL_RELEASE}/build")
message(STATUS "Kernel headers path: ${KERNEL_HEADERS_DIR}")

# 检查内核头文件目录
if(NOT EXISTS ${KERNEL_HEADERS_DIR})
    message(FATAL_ERROR "Kernel headers not found at ${KERNEL_HEADERS_DIR}. "
        "Please install with: sudo yum install kernel-devel-${KERNEL_RELEASE}")
endif()

# 设置 libbpf 路径
set(LIBBPF_SOURCE_DIR ${PROJECT_SOURCE_DIR}/external/libbpf/src)
set(LIBBPF_BUILD_DIR ${CMAKE_BINARY_DIR}/libbpf)

# 添加 libbpf 子项目
add_subdirectory(external/libbpf ${LIBBPF_BUILD_DIR})

# 添加项目子目录
add_subdirectory(src/ebpf)
add_subdirectory(src/user)
add_subdirectory(tests)

# 安装目标 - 安装到系统目录
install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/ DESTINATION bin)
install(DIRECTORY scripts/ DESTINATION scripts)

# 打印构建摘要
message(STATUS "==========================================")
message(STATUS "Build Configuration Summary")
message(STATUS "  Project:       ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Clang:         ${CLANG_EXECUTABLE}")
message(STATUS "  Kernel:        ${KERNEL_RELEASE}")
message(STATUS "  BPF Tool:      ${BPFTOOL}")
message(STATUS "  Output Dir:    ${CMAKE_BINARY_DIR}/bin")
message(STATUS "==========================================")