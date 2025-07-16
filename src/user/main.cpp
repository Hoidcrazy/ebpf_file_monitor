// src/user/main.cpp
#include "user/bpf_loader.h"
#include "user/logger.h"
#include <iostream>
#include <cstring>
#include <csignal>

volatile bool running = true;

void signalHandler(int signum) {
    std::cout << "接收到信号 " << signum << ", 退出程序..." << std::endl;
    running = false;
}

int main() {
    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // 初始化日志
    Logger::getInstance().init("tests/log");
    
    // 加载并启动eBPF监控
    BPFLoader loader;
    if (!loader.load()) {
        std::cerr << "加载eBPF程序失败" << std::endl;
        return 1;
    }
    
    if (!loader.attach()) {
        std::cerr << "附加eBPF程序失败" << std::endl;
        return 1;
    }
    
    std::cout << "文件监控系统已启动，按Ctrl+C退出..." << std::endl;
    
    // 事件处理回调
    auto eventHandler = [&](const struct event& e) {
        // 记录原始事件
        Logger::getInstance().logEvent(e);
        
        // 如果是.txt文件的读取操作，篡改内容
        if (e.type == EVENT_READ && IS_TXT_FILE(e.filename)) {
            const char* modifiedContent = "这是一段经过修改缓冲区后的内容。";
            size_t contentSize = strlen(modifiedContent) + 1;
            
            // 篡改内存
            if (BPFLoader::modifyProcessMemory(e.pid, e.buffer_addr, 
                                             modifiedContent, contentSize)) {
                // 创建篡改事件
                struct event modified = e;
                modified.type = EVENT_MODIFIED;
                strncpy(modified.data, modifiedContent, MAX_BUFFER_SIZE);
                modified.size = contentSize;
                
                // 记录篡改事件
                Logger::getInstance().logEvent(modified);
            }
        }
    };
    
    // 开始事件轮询
    loader.pollEvents(eventHandler);
    
    std::cout << "程序已退出" << std::endl;
    return 0;
}