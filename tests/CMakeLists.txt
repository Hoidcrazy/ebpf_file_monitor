# 添加测试程序
add_executable(test_basic test_basic.cpp)

# 链接libbpf
target_link_libraries(test_basic PRIVATE libbpf)

# 复制测试文件和创建日志目录
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test_docs)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/log)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_docs/test_content.txt 
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test_docs)

# 添加自定义目标确保目录存在
add_custom_command(TARGET test_basic PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/test_docs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/log
)

# 设置测试属性
add_test(NAME BasicFileMonitorTest
    COMMAND sudo $<TARGET_FILE:test_basic>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})