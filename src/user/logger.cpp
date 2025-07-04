/**
 * @file logger.cpp
 * @brief 日志模块实现 - 提供多级别、多目标的日志记录功能
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件实现了日志系统的核心功能，支持控制台和文件输出，
 * 支持颜色输出、时间戳、多级别过滤等功能
 */

 #include "logger.h"
 #include <mutex>
 #include <fstream>
 #include <iostream>
 #include <sstream>
 #include <iomanip>
 #include <chrono>
 #include <ctime>
 
 // ANSI 颜色代码
 #define ANSI_COLOR_RED     "\x1b[31m"
 #define ANSI_COLOR_GREEN   "\x1b[32m"
 #define ANSI_COLOR_YELLOW  "\x1b[33m"
 #define ANSI_COLOR_BLUE    "\x1b[34m"
 #define ANSI_COLOR_MAGENTA "\x1b[35m"
 #define ANSI_COLOR_CYAN    "\x1b[36m"
 #define ANSI_COLOR_WHITE   "\x1b[37m"
 #define ANSI_COLOR_RESET   "\x1b[0m"
 
 // 日志系统内部结构体
 struct logger_handle {
     log_config_t config;                // 日志配置
     std::ofstream log_file;             // 日志文件流
     std::mutex log_mutex;               // 日志互斥锁
     bool is_initialized;                // 是否已初始化
     uint64_t log_count;                 // 日志计数器
     std::chrono::high_resolution_clock::time_point start_time;  // 启动时间
     
     logger_handle() : is_initialized(false), log_count(0) {
         start_time = std::chrono::high_resolution_clock::now();
     }
 };
 
 // 全局日志句柄
 logger_handle_t* g_logger = nullptr;
 
 /**
  * @brief 获取当前时间字符串
  * @param enable_microseconds 是否包含微秒
  * @return std::string 时间字符串
  */
 std::string get_current_time_string(bool enable_microseconds = true) {
     auto now = std::chrono::high_resolution_clock::now();
     auto time_t = std::chrono::high_resolution_clock::to_time_t(now);
     auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
         now.time_since_epoch()) % 1000000;
     
     std::stringstream ss;
     ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
     
     if (enable_microseconds) {
         ss << "." << std::setfill('0') << std::setw(6) << microseconds.count();
     }
     
     return ss.str();
 }
 
 /**
  * @brief 日志级别转字符串
  * @param level 日志级别
  * @return const char* 级别字符串
  */
 const char* logger_level_to_string(log_level_t level) {
     switch (level) {
         case LOG_LEVEL_DEBUG: return "DEBUG";
         case LOG_LEVEL_INFO:  return "INFO";
         case LOG_LEVEL_WARN:  return "WARN";
         case LOG_LEVEL_ERROR: return "ERROR";
         case LOG_LEVEL_FATAL: return "FATAL";
         default: return "UNKNOWN";
     }
 }
 
 /**
  * @brief 获取日志级别对应的颜色代码
  * @param level 日志级别
  * @return const char* ANSI 颜色代码
  */
 const char* logger_level_to_color(log_level_t level) {
     switch (level) {
         case LOG_LEVEL_DEBUG: return ANSI_COLOR_CYAN;
         case LOG_LEVEL_INFO:  return ANSI_COLOR_GREEN;
         case LOG_LEVEL_WARN:  return ANSI_COLOR_YELLOW;
         case LOG_LEVEL_ERROR: return ANSI_COLOR_RED;
         case LOG_LEVEL_FATAL: return ANSI_COLOR_MAGENTA;
         default: return ANSI_COLOR_WHITE;
     }
 }
 
 /**
  * @brief 创建默认日志配置
  * @return log_config_t 默认配置
  */
 log_config_t logger_create_default_config(void) {
     log_config_t config = {};
     
     config.min_level = LOG_LEVEL_INFO;
     config.target = LOG_TARGET_CONSOLE;
     config.enable_timestamp = 1;
     config.enable_colors = 1;
     config.auto_flush = 1;
     
     // 默认日志文件路径
     SAFE_STRCPY(config.log_file_path, "ebpf_monitor.log", sizeof(config.log_file_path));
     
     return config;
 }
 
 /**
  * @brief 初始化日志系统
  * @param config 日志配置
  * @return logger_handle_t* 日志句柄，失败返回NULL
  */
 logger_handle_t* logger_init(const log_config_t* config) {
     if (!config) {
         ERROR_PRINT("日志配置为空");
         return nullptr;
     }
     
     // 创建日志句柄
     logger_handle_t* logger = new logger_handle_t();
     if (!logger) {
         ERROR_PRINT("分配日志句柄内存失败");
         return nullptr;
     }
     
     // 拷贝配置
     logger->config = *config;
     
     // 如果需要文件输出，打开日志文件
     if (config->target == LOG_TARGET_FILE || config->target == LOG_TARGET_BOTH) {
         logger->log_file.open(config->log_file_path, std::ios::app);
         if (!logger->log_file.is_open()) {
             ERROR_PRINT("无法打开日志文件: %s", config->log_file_path);
             delete logger;
             return nullptr;
         }
     }
     
     logger->is_initialized = true;
     
     // 写入启动日志
     logger_info(logger, "日志系统已启动 - 级别: %s, 目标: %s", 
                 logger_level_to_string(config->min_level),
                 (config->target == LOG_TARGET_CONSOLE) ? "控制台" :
                 (config->target == LOG_TARGET_FILE) ? "文件" : "控制台+文件");
     
     return logger;
 }
 
 /**
  * @brief 销毁日志系统
  * @param logger 日志句柄
  */
 void logger_destroy(logger_handle_t* logger) {
     if (!logger) return;
     
     if (logger->is_initialized) {
         logger_info(logger, "日志系统关闭 - 总日志数: %lu", logger->log_count);
         logger_flush(logger);
     }
     
     if (logger->log_file.is_open()) {
         logger->log_file.close();
     }
     
     delete logger;
 }
 
 /**
  * @brief 记录日志的内部实现
  * @param logger 日志句柄
  * @param level 日志级别
  * @param format 格式化字符串
  * @param args 参数列表
  */
 void logger_log_internal(logger_handle_t* logger, log_level_t level, 
                         const char* format, va_list args) {
     if (!logger || !logger->is_initialized) return;
     
     // 检查日志级别
     if (level < logger->config.min_level) return;
     
     // 加锁保护
     std::lock_guard<std::mutex> lock(logger->log_mutex);
     
     // 格式化消息
     char message[1024];
     vsnprintf(message, sizeof(message), format, args);
     
     // 构建完整日志行
     std::stringstream log_line;
     
     // 添加时间戳
     if (logger->config.enable_timestamp) {
         log_line << "[" << get_current_time_string() << "] ";
     }
     
     // 添加日志级别
     log_line << "[" << logger_level_to_string(level) << "] ";
     
     // 添加消息内容
     log_line << message;
     
     std::string log_str = log_line.str();
     
     // 输出到控制台
     if (logger->config.target == LOG_TARGET_CONSOLE || 
         logger->config.target == LOG_TARGET_BOTH) {
         
         if (logger->config.enable_colors) {
             std::cout << logger_level_to_color(level) << log_str 
                       << ANSI_COLOR_RESET << std::endl;
         } else {
             std::cout << log_str << std::endl;
         }
         
         if (logger->config.auto_flush) {
             std::cout.flush();
         }
     }
     
     // 输出到文件
     if (logger->config.target == LOG_TARGET_FILE || 
         logger->config.target == LOG_TARGET_BOTH) {
         
         if (logger->log_file.is_open()) {
             logger->log_file << log_str << std::endl;
             
             if (logger->config.auto_flush) {
                 logger->log_file.flush();
             }
         }
     }
     
     // 更新计数器
     logger->log_count++;
 }
 
 /**
  * @brief 记录日志
  * @param logger 日志句柄
  * @param level 日志级别
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_log(logger_handle_t* logger, log_level_t level, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, level, format, args);
     va_end(args);
 }
 
 /**
  * @brief 记录调试日志
  * @param logger 日志句柄
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_debug(logger_handle_t* logger, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, LOG_LEVEL_DEBUG, format, args);
     va_end(args);
 }
 
 /**
  * @brief 记录信息日志
  * @param logger 日志句柄
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_info(logger_handle_t* logger, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, LOG_LEVEL_INFO, format, args);
     va_end(args);
 }
 
 /**
  * @brief 记录警告日志
  * @param logger 日志句柄
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_warn(logger_handle_t* logger, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, LOG_LEVEL_WARN, format, args);
     va_end(args);
 }
 
 /**
  * @brief 记录错误日志
  * @param logger 日志句柄
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_error(logger_handle_t* logger, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, LOG_LEVEL_ERROR, format, args);
     va_end(args);
 }
 
 /**
  * @brief 记录致命错误日志
  * @param logger 日志句柄
  * @param format 格式化字符串
  * @param ... 参数列表
  */
 void logger_fatal(logger_handle_t* logger, const char* format, ...) {
     va_list args;
     va_start(args, format);
     logger_log_internal(logger, LOG_LEVEL_FATAL, format, args);
     va_end(args);
 }
 
 /**
  * @brief 刷新日志缓冲区
  * @param logger 日志句柄
  */
 void logger_flush(logger_handle_t* logger) {
     if (!logger || !logger->is_initialized) return;
     
     std::lock_guard<std::mutex> lock(logger->log_mutex);
     
     if (logger->config.target == LOG_TARGET_CONSOLE || 
         logger->config.target == LOG_TARGET_BOTH) {
         std::cout.flush();
     }
     
     if (logger->config.target == LOG_TARGET_FILE || 
         logger->config.target == LOG_TARGET_BOTH) {
         if (logger->log_file.is_open()) {
             logger->log_file.flush();
         }
     }
 }
 
 /**
  * @brief 设置日志级别
  * @param logger 日志句柄
  * @param level 新的日志级别
  */
 void logger_set_level(logger_handle_t* logger, log_level_t level) {
     if (!logger || !logger->is_initialized) return;
     
     std::lock_guard<std::mutex> lock(logger->log_mutex);
     logger->config.min_level = level;
     
     logger_info(logger, "日志级别已更改为: %s", logger_level_to_string(level));
 }
 
 /**
  * @brief 获取当前日志级别
  * @param logger 日志句柄
  * @return log_level_t 当前日志级别
  */
 log_level_t logger_get_level(logger_handle_t* logger) {
     if (!logger || !logger->is_initialized) return LOG_LEVEL_INFO;
     
     std::lock_guard<std::mutex> lock(logger->log_mutex);
     return logger->config.min_level;
 }