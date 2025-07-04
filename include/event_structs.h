/**
 * @file event_structs.h
 * @brief 内核向用户态传递的事件结构体定义
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件定义了 eBPF 内核程序向用户态传递的各种事件结构体
 */

 #ifndef EVENT_STRUCTS_H
 #define EVENT_STRUCTS_H
 
 #include "common.h"
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 // 文件操作事件基础结构体
 typedef struct {
     __u64 timestamp;                    // 事件时间戳（纳秒）
     __u32 pid;                          // 进程ID
     __u32 tid;                          // 线程ID
     __u32 uid;                          // 用户ID
     __u32 gid;                          // 组ID
     char comm[MAX_COMM_LEN];           // 进程名
     file_operation_type_t op_type;      // 操作类型
     int fd;                             // 文件描述符
     char filepath[MAX_PATH_LEN];        // 文件路径
     int ret_code;                       // 系统调用返回码
 } __attribute__((packed)) file_event_base_t;
 
 // 文件打开事件
 typedef struct {
     file_event_base_t base;             // 基础事件信息
     int flags;                          // 打开标志
     mode_t mode;                        // 文件模式
     __u64 inode;                        // 文件 inode 号
     __u64 device;                       // 设备号
 } __attribute__((packed)) file_open_event_t;
 
 // 文件读取事件
 typedef struct {
     file_event_base_t base;             // 基础事件信息
     __u64 buffer_addr;                  // 用户态缓冲区地址
     size_t count;                       // 请求读取的字节数
     ssize_t bytes_read;                 // 实际读取的字节数
     __u64 file_offset;                  // 文件偏移量
 } __attribute__((packed)) file_read_event_t;
 
 // 文件写入事件
 typedef struct {
     file_event_base_t base;             // 基础事件信息
     __u64 buffer_addr;                  // 用户态缓冲区地址
     size_t count;                       // 请求写入的字节数
     ssize_t bytes_written;              // 实际写入的字节数
     __u64 file_offset;                  // 文件偏移量
 } __attribute__((packed)) file_write_event_t;
 
 // 文件关闭事件
 typedef struct {
     file_event_base_t base;             // 基础事件信息
     __u64 total_bytes_read;             // 总读取字节数
     __u64 total_bytes_written;          // 总写入字节数
     __u64 file_lifetime;                // 文件生命周期（毫秒）
 } __attribute__((packed)) file_close_event_t;
 
 // 通用事件联合体
 typedef union {
     file_event_base_t base;             // 基础事件
     file_open_event_t open;             // 打开事件
     file_read_event_t read;             // 读取事件
     file_write_event_t write;           // 写入事件
     file_close_event_t close;           // 关闭事件
 } __attribute__((packed)) file_event_t;
 
 // 事件统计信息
 typedef struct {
     __u64 total_events;                 // 总事件数
     __u64 open_events;                  // 打开事件数
     __u64 read_events;                  // 读取事件数
     __u64 write_events;                 // 写入事件数
     __u64 close_events;                 // 关闭事件数
     __u64 txt_files_modified;           // 被修改的txt文件数
     __u64 data_spoofed_bytes;           // 数据欺骗字节数
     __u64 last_event_time;              // 最后事件时间
 } __attribute__((packed)) event_stats_t;
 
 // 文件描述符映射项（用于 BPF 哈希表）
 typedef struct {
     int fd;                             // 文件描述符
     __u32 pid;                          // 进程ID
 } __attribute__((packed)) fd_key_t;
 
 // 文件信息（存储在 BPF 哈希表中）
 typedef struct {
     char filepath[MAX_PATH_LEN];        // 文件路径
     __u64 open_time;                    // 打开时间
     __u64 total_read_bytes;             // 总读取字节数
     __u64 total_write_bytes;            // 总写入字节数
     __u32 read_count;                   // 读取次数
     __u32 write_count;                  // 写入次数
     int flags;                          // 打开标志
     mode_t mode;                        // 文件模式
 } __attribute__((packed)) file_info_t;
 
 // 进程信息统计
 typedef struct {
     __u32 pid;                          // 进程ID
     char comm[MAX_COMM_LEN];           // 进程名
     __u64 files_opened;                 // 打开的文件数
     __u64 bytes_read;                   // 读取字节数
     __u64 bytes_written;                // 写入字节数
     __u64 last_activity;                // 最后活动时间
 } __attribute__((packed)) process_stats_t;
 
 // 系统调用信息
 typedef struct {
     const char* name;                   // 系统调用名称
     __u64 count;                        // 调用次数
     __u64 total_time;                   // 总耗时（纳秒）
     __u64 min_time;                     // 最小耗时
     __u64 max_time;                     // 最大耗时
     __u64 avg_time;                     // 平均耗时
 } __attribute__((packed)) syscall_stats_t;
 
 // 缓冲区修改通知事件
 typedef struct {
     __u64 timestamp;                    // 修改时间戳
     __u32 pid;                          // 目标进程ID
     __u64 buffer_addr;                  // 缓冲区地址
     size_t original_size;               // 原始大小
     size_t modified_size;               // 修改后大小
     char filepath[MAX_PATH_LEN];        // 文件路径
     char original_content[64];          // 原始内容（前64字节）
     char modified_content[64];          // 修改后内容（前64字节）
 } __attribute__((packed)) buffer_modify_event_t;
 
 // 错误事件
 typedef struct {
     __u64 timestamp;                    // 错误时间戳
     __u32 pid;                          // 进程ID
     char comm[MAX_COMM_LEN];           // 进程名
     file_operation_type_t op_type;      // 操作类型
     int error_code;                     // 错误码
     char error_msg[128];                // 错误信息
     char filepath[MAX_PATH_LEN];        // 相关文件路径
 } __attribute__((packed)) error_event_t;
 
 // 辅助函数：获取事件类型字符串
 static inline const char* get_event_type_string(file_operation_type_t type) {
     switch (type) {
         case FILE_OP_OPEN: return "OPEN";
         case FILE_OP_READ: return "READ";
         case FILE_OP_WRITE: return "WRITE";
         case FILE_OP_CLOSE: return "CLOSE";
         default: return "UNKNOWN";
     }
 }
 
 // 辅助函数：获取打开标志字符串
 static inline void get_open_flags_string(int flags, char* buffer, size_t size) {
     if (!buffer || size == 0) return;
     
     buffer[0] = '\0';
     
     if (flags & O_RDONLY) strncat(buffer, "O_RDONLY|", size - strlen(buffer) - 1);
     if (flags & O_WRONLY) strncat(buffer, "O_WRONLY|", size - strlen(buffer) - 1);
     if (flags & O_RDWR) strncat(buffer, "O_RDWR|", size - strlen(buffer) - 1);
     if (flags & O_CREAT) strncat(buffer, "O_CREAT|", size - strlen(buffer) - 1);
     if (flags & O_EXCL) strncat(buffer, "O_EXCL|", size - strlen(buffer) - 1);
     if (flags & O_TRUNC) strncat(buffer, "O_TRUNC|", size - strlen(buffer) - 1);
     if (flags & O_APPEND) strncat(buffer, "O_APPEND|", size - strlen(buffer) - 1);
     if (flags & O_NONBLOCK) strncat(buffer, "O_NONBLOCK|", size - strlen(buffer) - 1);
     if (flags & O_SYNC) strncat(buffer, "O_SYNC|", size - strlen(buffer) - 1);
     
     // 移除最后的 '|'
     size_t len = strlen(buffer);
     if (len > 0 && buffer[len - 1] == '|') {
         buffer[len - 1] = '\0';
     }
     
     if (strlen(buffer) == 0) {
         strncpy(buffer, "NONE", size - 1);
         buffer[size - 1] = '\0';
     }
 }
 
 // 辅助函数：格式化时间戳
 static inline void format_timestamp(__u64 timestamp, char* buffer, size_t size) {
     if (!buffer || size == 0) return;
     
     time_t sec = timestamp / 1000000000ULL;
     long nsec = timestamp % 1000000000ULL;
     
     struct tm* tm_info = localtime(&sec);
     snprintf(buffer, size, "%02d:%02d:%02d.%09ld",
              tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, nsec);
 }
 
 // 辅助函数：格式化文件大小
 static inline void format_file_size(__u64 size, char* buffer, size_t buf_size) {
     if (!buffer || buf_size == 0) return;
     
     const char* units[] = {"B", "KB", "MB", "GB", "TB"};
     double size_f = (double)size;
     int unit_idx = 0;
     
     while (size_f >= 1024.0 && unit_idx < 4) {
         size_f /= 1024.0;
         unit_idx++;
     }
     
     if (unit_idx == 0) {
         snprintf(buffer, buf_size, "%lu %s", size, units[unit_idx]);
     } else {
         snprintf(buffer, buf_size, "%.2f %s", size_f, units[unit_idx]);
     }
 }
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif // EVENT_STRUCTS_H