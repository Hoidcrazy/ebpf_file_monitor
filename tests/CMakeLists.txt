# tests/CMakeLists.txt
# 编译测试程序

# 添加测试程序
add_executable(test_basic test_basic.cpp)

# 设置测试目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tests/log)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tests/test_docs)

# 创建测试文件
file(WRITE ${CMAKE_BINARY_DIR}/tests/test_docs/test_content.txt 
    "这是一段初始测试文件。")

# 添加测试
add_test(NAME file_monitor_test
    COMMAND ${CMAKE_BINARY_DIR}/bin/test_basic
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)