// src/user/logger.cpp
#include "user/logger.h"
#include "user/event_structs_user.h"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

void Logger::init(const std::string& logDir) {
    this->logDir = logDir;
    fs::create_directories(logDir);
    
    // 创建带时间戳的日志文件
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << "file_monitor_" 
        << std::put_time(&tm, "%Y%m%d_%H%M%S") 
        << ".log";
        
    std::string logPath = (fs::path(logDir) / oss.str()).string();
    logFile.open(logPath, std::ios::out);
    
    if (!logFile.is_open()) {
        std::cerr << "无法打开日志文件: " << logPath << std::endl;
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::logEvent(const struct event& e) {
    // 获取当前时间
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    
    // 事件类型字符串
    const char* eventType = "";
    switch (e.type) {
        case EVENT_OPEN: eventType = "OPEN"; break;
        case EVENT_READ: eventType = "READ"; break;
        case EVENT_WRITE: eventType = "WRITE"; break;
        case EVENT_CLOSE: eventType = "CLOSE"; break;
        case EVENT_MODIFIED: eventType = "MODIFIED"; break;
        default: eventType = "UNKNOWN";
    }
    
    // 格式化日志
    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
        << "PID: " << e.pid << ", "
        << "FD: " << e.fd << ", "
        << "Event: " << eventType << ", "
        << "File: " << e.filename;
    
    if (e.type == EVENT_READ || e.type == EVENT_WRITE || e.type == EVENT_MODIFIED) {
        oss << ", Size: " << e.size;
    }
    
    if (e.type == EVENT_MODIFIED) {
        oss << ", Content: \"" << e.data << "\"";
    }
    
    // 输出到控制台和日志文件
    std::cout << oss.str() << std::endl;
    if (logFile.is_open()) {
        logFile << oss.str() << std::endl;
    }
}