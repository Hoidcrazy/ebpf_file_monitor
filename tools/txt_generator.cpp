#include <iostream>
#include <fstream>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0] << " <文件路径>\n";
        return 1;
    }
    std::string path = argv[1];
    std::ifstream infile(path);
    if (!infile.is_open()) {
        std::cerr << "无法打开文件: " << path << "\n";
        return 1;
    }
    char buffer[128];
    while (infile.read(buffer, sizeof(buffer)-1) || infile.gcount() > 0) {
        std::streamsize bytes = infile.gcount();
        buffer[bytes] = '\0';
        std::cout << buffer;
    }
    infile.close();
    return 0;
}
