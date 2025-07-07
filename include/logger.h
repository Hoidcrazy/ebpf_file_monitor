// include/logger.h
#pragma once
#include <string>

class Logger {
public:
    Logger(const std::string& filename);
    ~Logger();
    
    void log(const std::string& message);
    void log_event(const char* event_type, pid_t pid, int fd, 
                   const char* path, size_t size = 0);

private:
    std::string log_filename;
    FILE* log_file;
};