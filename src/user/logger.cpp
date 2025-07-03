#include "logger.h"

std::mutex Logger::log_mutex;

void Logger::log(LogLevel level, const std::string &msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    const char* level_str = "";
    switch(level) {
        case LogLevel::INFO:  level_str = "[INFO] ";  break;
        case LogLevel::WARN:  level_str = "[WARN] ";  break;
        case LogLevel::ERROR: level_str = "[ERROR] "; break;
    }
    std::cout << level_str << msg << std::endl;
}
