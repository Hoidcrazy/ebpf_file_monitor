// src/user/logger.cpp
#include "logger.h"
#include <ctime>
#include <iomanip>

Logger::Logger(const std::string& filename) 
    : log_filename(LOG_DIR + filename) {
    log_file = fopen(log_filename.c_str(), "a");
    if (!log_file) {
        perror("fopen failed");
        exit(EXIT_FAILURE);
    }
    log("========== Logging Started ==========");
}

Logger::~Logger() {
    if (log_file) {
        log("========== Logging Stopped ==========");
        fclose(log_file);
    }
}

void Logger::log(const std::string& message) {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " | " << message;
    
    fprintf(log_file, "%s\n", oss.str().c_str());
    fflush(log_file);
}

void Logger::log_event(const char* event_type, pid_t pid, int fd, 
                      const char* path, size_t size) {
    std::ostringstream oss;
    oss << event_type << " | PID: " << pid 
        << " | FD: " << fd << " | Path: " << path;
    if (size > 0) oss << " | Size: " << size;
    log(oss.str());
}