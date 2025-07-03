#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <mutex>

// 日志级别枚举
enum class LogLevel {
    INFO,
    WARN,
    ERROR
};

// 日志类（线程安全单例）
class Logger {
public:
    static void log(LogLevel level, const std::string &msg);

private:
    static std::mutex log_mutex;
};

#endif // LOGGER_H
