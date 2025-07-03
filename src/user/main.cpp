#include <iostream>
#include <cstring>
#include <unistd.h>
#include "logger.h"
#include "bpf_loader.h"

// 判断文件名是否以 .txt 结尾
bool is_txt_file(const char* path) {
    size_t len = strlen(path);
    if (len < 4) return false;
    return strcmp(path + len - 4, ".txt") == 0;
}

// 主函数
int main(int argc, char** argv) {
    std::cout << "[*] eBPF 文件监控程序启动\n";
    BPFLoader loader;
    if (!loader.init_bpf()) {
        Logger::log(LogLevel::ERROR, "无法初始化 BPF");
        return 1;
    }

    // 事件处理回调
    loader.run([](const event_t& evt) {
        std::string path(evt.path);
        // 打印事件信息
        switch (evt.op) {
            case EV_OPEN:
                Logger::log(LogLevel::INFO, 
                    "[OPEN] PID: %u, FD: %u, Path: %s", evt.pid, evt.fd, path.c_str());
                break;
            case EV_READ:
                Logger::log(LogLevel::INFO, 
                    "[READ] PID: %u, FD: %u, Size: %u, Path: %s", evt.pid, evt.fd, evt.size, path.c_str());
                // 仅对 .txt 文件进行内容欺骗
                if (is_txt_file(path.c_str())) {
                    // 打开目标进程的 /proc/mem
                    char mem_path[64];
                    snprintf(mem_path, sizeof(mem_path), "/proc/%u/mem", evt.pid);
                    int fd = ::open(mem_path, O_RDWR);
                    if (fd < 0) {
                        Logger::log(LogLevel::ERROR, "无法打开 %s: %s", mem_path, strerror(errno));
                    } else {
                        // 伪造内容
                        const char fake_data[] = "这是一段fake内容。";
                        size_t fake_len = sizeof(fake_data);
                        // 写入内存缓冲区
                        if (lseek(fd, evt.buf, SEEK_SET) == -1) {
                            Logger::log(LogLevel::ERROR, "lseek 失败: %s", strerror(errno));
                        } else {
                            ssize_t bytes = write(fd, fake_data, std::min<size_t>(fake_len, evt.size));
                            if (bytes < 0) {
                                Logger::log(LogLevel::ERROR, "写入 /proc/mem 失败: %s", strerror(errno));
                            } else {
                                Logger::log(LogLevel::INFO, "已篡改 PID=%u 缓冲区内容", evt.pid);
                            }
                        }
                        close(fd);
                    }
                }
                break;
            case EV_WRITE:
                Logger::log(LogLevel::INFO, 
                    "[WRITE] PID: %u, FD: %u, Size: %u, Path: %s", evt.pid, evt.fd, evt.size, path.c_str());
                break;
            case EV_CLOSE:
                Logger::log(LogLevel::INFO, 
                    "[CLOSE] PID: %u, FD: %u, Path: %s", evt.pid, evt.fd, path.c_str());
                break;
        }
    });

    return 0;
}
