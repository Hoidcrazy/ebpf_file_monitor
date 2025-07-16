#include <fstream>
#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();
    
    if (pid == 0) { // 子进程
        // 读取测试文件
        std::ifstream file("tests/test_docs/test_content.txt");
        if (!file.is_open()) {
            std::cerr << "无法打开测试文件" << std::endl;
            exit(1);
        }
        
        std::string content;
        std::getline(file, content);
        file.close();
        
        std::cout << "读取内容: " << content << std::endl;
        exit(0);
    } else if (pid > 0) { // 父进程
        waitpid(pid, nullptr, 0);
    } else {
        std::cerr << "fork失败" << std::endl;
        return 1;
    }
    
    return 0;
}