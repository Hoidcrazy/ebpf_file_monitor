// src/user/main.cpp
#include "bpf_loader.h"
#include "logger.h"
#include <iostream>
#include <csignal>

volatile sig_atomic_t stop;

void signal_handler(int signo) {
    stop = 1;
}

int main() {
    // 初始化日志和BPF加载器
    Logger logger("file_monitor.log");
    BPFLoader loader;
    
    // 加载BPF程序
    if (!loader.load_bpf_program("src/ebpf/file_monitor.bpf.o")) {
        std::cerr << "Failed to load BPF program" << std::endl;
        return 1;
    }
    
    // 注册事件回调
    loader.set_open_callback([&](const open_event& evt) {
        logger.log_event("OPEN", evt.pid, evt.fd, evt.filename);
        std::cout << "OPEN | PID: " << evt.pid << " | FD: " << evt.fd 
                  << " | File: " << evt.filename << std::endl;
    });
    
    // 类似注册read/write/close回调...
    
    // 安装信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 启动事件循环
    loader.attach_probes();
    loader.start_event_loop(logger);
    
    std::cout << "Monitoring stopped" << std::endl;
    return 0;
}