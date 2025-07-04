# 测试模块 CMake 构建文件
# 编译测试程序和测试用例

# 设置测试源文件
set(TEST_SOURCES
    test_basic.cpp
)

# 创建测试可执行文件
add_executable(test_basic test_basic.cpp)

# 链接必要的库
target_link_libraries(test_basic
    pthread
)

# 设置编译选项
target_compile_options(test_basic PRIVATE
    -Wall
    -Wextra
    -std=c++17
    -O2
)

# 设置包含目录
target_include_directories(test_basic PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 设置调试信息
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(test_basic PRIVATE DEBUG=1)
    target_compile_options(test_basic PRIVATE -g -O0)
endif()

# 创建测试数据文件
set(TEST_DATA_FILE ${CMAKE_CURRENT_SOURCE_DIR}/test_docs/test_content.txt)
add_custom_command(
    OUTPUT ${TEST_DATA_FILE}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/test_docs
    COMMAND ${CMAKE_COMMAND} -E echo "这是一段初始测试文件。" > ${TEST_DATA_FILE}
    COMMENT "创建测试数据文件"
)

# 添加自定义目标来创建测试数据
add_custom_target(test_data ALL
    DEPENDS ${TEST_DATA_FILE}
)

# 创建日志目录
add_custom_target(test_log_dir ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/log
    COMMENT "创建测试日志目录"
)

# 添加测试依赖
add_dependencies(test_basic test_data test_log_dir)

# 设置安装目标
install(TARGETS test_basic
        RUNTIME DESTINATION bin
        COMPONENT testing)

# 安装测试数据
install(FILES ${TEST_DATA_FILE}
        DESTINATION share/ebpf_file_monitor/test_docs
        COMPONENT testing)

# 创建测试脚本
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh.in
    ${CMAKE_CURRENT_BINARY_DIR}/run_test.sh
    @ONLY
)

# 添加权限
add_custom_command(
    TARGET test_basic POST_BUILD
    COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/run_test.sh
)

# 打印测试构建信息
message(STATUS "测试模块构建配置:")
message(STATUS "  测试程序: test_basic")
message(STATUS "  测试数据: ${TEST_DATA_FILE}")
message(STATUS "  日志目录: ${CMAKE_CURRENT_SOURCE_DIR}/log")