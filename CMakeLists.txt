# 📘 ebpf_file_monitor 项目顶层 CMake 构建文件
# 基于 eBPF 的文件操作生命周期追踪与数据欺骗系统

cmake_minimum_required(VERSION 3.16)
project(ebpf_file_monitor VERSION 1.0.0 LANGUAGES C CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")

# 调试模式额外选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DDEBUG")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DDEBUG")
endif()

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 设置 libbpf 静态库路径
set(LIBBPF_DIR ${CMAKE_SOURCE_DIR}/external/libbpf)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_DIR}/include)
set(LIBBPF_LIB_DIR ${LIBBPF_DIR}/lib)

# 检查 libbpf 静态库是否存在
if(NOT EXISTS ${LIBBPF_DIR})
    message(FATAL_ERROR "libbpf 目录不存在: ${LIBBPF_DIR}")
endif()

if(NOT EXISTS ${LIBBPF_INCLUDE_DIR})
    message(FATAL_ERROR "libbpf 头文件目录不存在: ${LIBBPF_INCLUDE_DIR}")
endif()

# 查找 libbpf 静态库文件
find_library(LIBBPF_STATIC_LIB
    NAMES libbpf.a bpf
    PATHS ${LIBBPF_LIB_DIR} ${LIBBPF_DIR}/src ${LIBBPF_DIR}
    NO_DEFAULT_PATH
)

if(NOT LIBBPF_STATIC_LIB)
    message(FATAL_ERROR "未找到 libbpf 静态库文件，请检查路径: ${LIBBPF_LIB_DIR}")
endif()

message(STATUS "找到 libbpf 静态库: ${LIBBPF_STATIC_LIB}")

# 添加 libbpf 包含目录
include_directories(${LIBBPF_INCLUDE_DIR})
include_directories(${LIBBPF_INCLUDE_DIR}/uapi)

# 检查必要的工具
find_program(CLANG_EXEC clang)
find_program(LLVM_STRIP_EXEC llvm-strip)

if(NOT CLANG_EXEC)
    message(FATAL_ERROR "未找到 clang 编译器，请安装 clang/llvm")
endif()

if(NOT LLVM_STRIP_EXEC)
    message(FATAL_ERROR "未找到 llvm-strip 工具，请安装 llvm 工具链")
endif()

# 创建日志目录
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/log)

# 添加子目录
add_subdirectory(src/ebpf)
add_subdirectory(src/user)
add_subdirectory(tests)

# 安装目标
install(TARGETS ebpf_file_monitor
        RUNTIME DESTINATION bin)

# 打印构建信息
message(STATUS "==========================================")
message(STATUS "项目: ebpf_file_monitor")
message(STATUS "版本: ${PROJECT_VERSION}")
message(STATUS "构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ 标准: ${CMAKE_CXX_STANDARD}")
message(STATUS "C 标准: ${CMAKE_C_STANDARD}")
message(STATUS "Clang 路径: ${CLANG_EXEC}")
message(STATUS "LLVM Strip 路径: ${LLVM_STRIP_EXEC}")
message(STATUS "libbpf 静态库: ${LIBBPF_STATIC_LIB}")
message(STATUS "libbpf 头文件: ${LIBBPF_INCLUDE_DIR}")
message(STATUS "==========================================")