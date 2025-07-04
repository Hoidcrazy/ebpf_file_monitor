#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <mutex>

// 日志级别枚举
enum class LogLevel {
    INFO,
    WARN,
    ERROR/**
    * @file logger.h
    * @brief 日志接口定义 - 提供统一的日志记录功能
    * @author ebpf_file_monitor
    * @version 1.0.0
    * 
    * 该文件定义了日志系统的接口，支持多级别日志记录、文件输出等功能
    */
   
   #ifndef LOGGER_H
   #define LOGGER_H
   
   #include "common.h"
   #include <stdarg.h>
   
   #ifdef __cplusplus
   extern "C" {
   #endif
   
   // 日志级别定义
   typedef enum {
       LOG_LEVEL_DEBUG = 0,    // 调试级别
       LOG_LEVEL_INFO = 1,     // 信息级别
       LOG_LEVEL_WARN = 2,     // 警告级别
       LOG_LEVEL_ERROR = 3,    // 错误级别
       LOG_LEVEL_FATAL = 4     // 致命错误级别
   } log_level_t;
   
   // 日志输出目标
   typedef enum {
       LOG_TARGET_CONSOLE = 1,     // 控制台输出
       LOG_TARGET_FILE = 2,        // 文件输出
       LOG_TARGET_BOTH = 3         // 同时输出到控制台和文件
   } log_target_t;
   
   // 日志配置结构体
   typedef struct {
       log_level_t min_level;      // 最低日志级别
       log_target_t target;        // 输出目标
       char log_file_path[MAX_PATH_LEN];  // 日志文件路径
       int enable_timestamp;       // 是否启用时间戳
       int enable_colors;          // 是否启用颜色输出
       int auto_flush;             // 是否自动刷新
   } log_config_t;
   
   // 日志系统句柄
   typedef struct logger_handle logger_handle_t;
   
   /**
    * @brief 初始化日志系统
    * @param config 日志配置
    * @return logger_handle_t* 日志句柄，失败返回NULL
    */
   logger_handle_t* logger_init(const log_config_t* config);
   
   /**
    * @brief 销毁日志系统
    * @param logger 日志句柄
    */
   void logger_destroy(logger_handle_t* logger);
   
   /**
    * @brief 记录日志
    * @param logger 日志句柄
    * @param level 日志级别
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_log(logger_handle_t* logger, log_level_t level, const char* format, ...);
   
   /**
    * @brief 记录调试日志
    * @param logger 日志句柄
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_debug(logger_handle_t* logger, const char* format, ...);
   
   /**
    * @brief 记录信息日志
    * @param logger 日志句柄
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_info(logger_handle_t* logger, const char* format, ...);
   
   /**
    * @brief 记录警告日志
    * @param logger 日志句柄
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_warn(logger_handle_t* logger, const char* format, ...);
   
   /**
    * @brief 记录错误日志
    * @param logger 日志句柄
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_error(logger_handle_t* logger, const char* format, ...);
   
   /**
    * @brief 记录致命错误日志
    * @param logger 日志句柄
    * @param format 格式化字符串
    * @param ... 参数列表
    */
   void logger_fatal(logger_handle_t* logger, const char* format, ...);
   
   /**
    * @brief 刷新日志缓冲区
    * @param logger 日志句柄
    */
   void logger_flush(logger_handle_t* logger);
   
   /**
    * @brief 设置日志级别
    * @param logger 日志句柄
    * @param level 新的日志级别
    */
   void logger_set_level(logger_handle_t* logger, log_level_t level);
   
   /**
    * @brief 获取当前日志级别
    * @param logger 日志句柄
    * @return log_level_t 当前日志级别
    */
   log_level_t logger_get_level(logger_handle_t* logger);
   
   /**
    * @brief 创建默认日志配置
    * @return log_config_t 默认配置
    */
   log_config_t logger_create_default_config(void);
   
   /**
    * @brief 日志级别转字符串
    * @param level 日志级别
    * @return const char* 级别字符串
    */
   const char* logger_level_to_string(log_level_t level);
   
   /**
    * @brief 获取日志级别对应的颜色代码
    * @param level 日志级别
    * @return const char* ANSI 颜色代码
    */
   const char* logger_level_to_color(log_level_t level);
   
   // 便捷宏定义（需要全局 logger 实例）
   extern logger_handle_t* g_logger;
   
   #define LOG_DEBUG(fmt, ...) \
       do { \
           if (g_logger) logger_debug(g_logger, fmt, ##__VA_ARGS__); \
       } while(0)
   
   #define LOG_INFO(fmt, ...) \
       do { \
           if (g_logger) logger_info(g_logger, fmt, ##__VA_ARGS__); \
       } while(0)
   
   #define LOG_WARN(fmt, ...) \
       do { \
           if (g_logger) logger_warn(g_logger, fmt, ##__VA_ARGS__); \
       } while(0)
   
   #define LOG_ERROR(fmt, ...) \
       do { \
           if (g_logger) logger_error(g_logger, fmt, ##__VA_ARGS__); \
       } while(0)
   
   #define LOG_FATAL(fmt, ...) \
       do { \
           if (g_logger) logger_fatal(g_logger, fmt, ##__VA_ARGS__); \
       } while(0)
   
   #ifdef __cplusplus
   }
   #endif
   
   #endif // LOGGER_H
};

// 日志类（线程安全单例）
class Logger {
public:
    static void log(LogLevel level, const std::string &msg);

private:
    static std::mutex log_mutex;
};

#endif // LOGGER_H
