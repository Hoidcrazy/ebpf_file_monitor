#include <iostream>
#include <array>
#include <memory>
#include <cstdio>
#include <cstring>

int main() {
    const char* test_file = "test.txt";
    // 创建测试文件
    FILE* f = fopen(test_file, "w");
    fprintf(f, "Original Content");
    fclose(f);

    // 运行 txt_generator，捕获输出
    std::array<char, 128> buffer;
    std::string output;
    FILE* pipe = popen("./txtgen test.txt", "r");
    if (!pipe) {
        std::cerr << "测试执行失败\n";
        return 1;
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }
    pclose(pipe);

    // 检查伪造内容是否出现在输出中
    if (output.find("fake内容") != std::string::npos) {
        std::cout << "测试通过: 找到伪造内容\n";
        return 0;
    } else {
        std::cout << "测试失败: 未找到伪造内容\n";
        return 1;
    }
}
