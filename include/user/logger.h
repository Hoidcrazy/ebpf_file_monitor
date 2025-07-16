#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>

class Logger {
public:
    // 获取单例实例
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }
    
    // 初始化日志文件
    void init(const std::string& logDir);
    
    // 记录事件
    void logEvent(const struct event& e);
    
private:
    Logger() = default;
    ~Logger();
    
    std::ofstream logFile; // 日志文件流
    std::string logDir;    // 日志目录
};