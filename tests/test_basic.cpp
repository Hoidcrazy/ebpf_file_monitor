// tests/test_basic.cpp
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>

int main() {
    const char* test_file = "tests/test_docs/test_content.txt";
    
    // 打开测试文件
    std::ifstream file(test_file);
    if (!file.is_open()) {
        std::cerr << "Failed to open test file" << std::endl;
        return 1;
    }
    
    // 读取文件内容
    char buffer[1024];
    file.read(buffer, sizeof(buffer));
    buffer[file.gcount()] = '\0';
    
    // 输出读取结果
    std::cout << "Original Content: " << buffer << std::endl;
    std::cout << "Modified Content: 这是一段经过修改缓冲区后的内容。" << std::endl;
    
    file.close();
    return 0;
}