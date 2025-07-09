cmake_minimum_required(VERSION 3.16)

# 添加测试可执行文件
add_executable(test_basic
    test_basic.cpp
)

# 包含目录
target_include_directories(test_basic
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

# 复制测试文件到 build/bin/test_docs
add_custom_command(
    TARGET test_basic POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/test_docs
        ${CMAKE_BINARY_DIR}/bin/test_docs
    COMMENT "Copying test documents to build/bin"
)

# 添加测试
enable_testing()
add_test(NAME BasicFileMonitorTest 
    COMMAND ${CMAKE_BINARY_DIR}/bin/test_basic
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)