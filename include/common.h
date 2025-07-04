/**
 * @file common.h
 * @brief 通用定义文件 - 包含项目中使用的常量、工具宏等
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件定义了项目中用到的通用常量、宏定义、以及一些工具函数
 */

 #ifndef COMMON_H
 #define COMMON_H
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <errno.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <time.h>
 
 // 系统相关定义
 #define MAX_PATH_LEN 256        // 最大路径长度
 #define MAX_COMM_LEN 16         // 最大进程名长度
 #define MAX_BUFFER_SIZE 1024    // 最大缓冲区大小
 #define MAX_EVENT_SIZE 512      // 最大事件大小
 
 // 文件操作类型定义
 typedef enum {
     FILE_OP_OPEN = 1,           // 文件打开操作
     FILE_OP_READ = 2,           // 文件读取操作
     FILE_OP_WRITE = 3,          // 文件写入操作
     FILE_OP_CLOSE = 4           // 文件关闭操作
 } file_operation_type_t;
 
 // 错误码定义
 #define SUCCESS 0               // 成功
 #define ERROR_GENERIC -1        // 通用错误
 #define ERROR_NO_MEMORY -2      // 内存不足
 #define ERROR_INVALID_PARAM -3  // 参数无效
 #define ERROR_FILE_NOT_FOUND -4 // 文件未找到
 #define ERROR_PERMISSION -5     // 权限不足
 
 // 调试宏定义
 #ifdef DEBUG
 #define DEBUG_PRINT(fmt, ...) \
     do { \
         printf("[DEBUG] %s:%d:%s(): " fmt "\n", \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
     } while(0)
 #else
 #define DEBUG_PRINT(fmt, ...) do {} while(0)
 #endif
 
 // 错误处理宏
 #define ERROR_PRINT(fmt, ...) \
     do { \
         fprintf(stderr, "[ERROR] %s:%d:%s(): " fmt "\n", \
                 __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
     } while(0)
 
 // 信息打印宏
 #define INFO_PRINT(fmt, ...) \
     do { \
         printf("[INFO] " fmt "\n", ##__VA_ARGS__); \
     } while(0)
 
 // 警告打印宏
 #define WARN_PRINT(fmt, ...) \
     do { \
         printf("[WARN] " fmt "\n", ##__VA_ARGS__); \
     } while(0)
 
 // 内存分配检查宏
 #define SAFE_MALLOC(ptr, size) \
     do { \
         ptr = malloc(size); \
         if (!ptr) { \
             ERROR_PRINT("内存分配失败: %zu bytes", size); \
             return ERROR_NO_MEMORY; \
         } \
         memset(ptr, 0, size); \
     } while(0)
 
 // 安全字符串拷贝宏
 #define SAFE_STRCPY(dst, src, size) \
     do { \
         strncpy(dst, src, size - 1); \
         dst[size - 1] = '\0'; \
     } while(0)
 
 // 时间戳获取宏
 #define GET_TIMESTAMP() \
     ({ \
         time_t now = time(NULL); \
         now; \
     })
 
 // 获取当前时间字符串
 static inline void get_current_time_str(char* buffer, size_t size) {
     time_t now = time(NULL);
     struct tm* tm_info = localtime(&now);
     strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
 }
 
 // 检查文件是否为.txt后缀
 static inline int is_txt_file(const char* filename) {
     if (!filename) return 0;
     
     size_t len = strlen(filename);
     if (len < 4) return 0;
     
     return (strcmp(filename + len - 4, ".txt") == 0);
 }
 
 // 获取文件名（去掉路径）
 static inline const char* get_filename(const char* path) {
     if (!path) return NULL;
     
     const char* filename = strrchr(path, '/');
     return filename ? filename + 1 : path;
 }
 
 // 检查文件是否存在
 static inline int file_exists(const char* path) {
     if (!path) return 0;
     return access(path, F_OK) == 0;
 }
 
 // 创建目录（如果不存在）
 static inline int create_directory(const char* path) {
     if (!path) return ERROR_INVALID_PARAM;
     
     struct stat st = {0};
     if (stat(path, &st) == -1) {
         if (mkdir(path, 0755) == -1) {
             ERROR_PRINT("创建目录失败: %s", path);
             return ERROR_GENERIC;
         }
     }
     return SUCCESS;
 }
 
 // 系统调用错误处理
 #define HANDLE_SYSCALL_ERROR(call, error_msg) \
     do { \
         if ((call) == -1) { \
             ERROR_PRINT("%s: %s", error_msg, strerror(errno)); \
             return ERROR_GENERIC; \
         } \
     } while(0)
 
 // 数据欺骗相关常量
 #define FAKE_CONTENT "这是一段经过修改缓冲区后的内容。"
 #define FAKE_CONTENT_LEN (sizeof(FAKE_CONTENT) - 1)
 
 // BPF 相关常量
 #define BPF_MAP_MAX_ENTRIES 1024    // BPF 哈希表最大条目数
 #define BPF_RING_BUFFER_SIZE 256    // Ring buffer 大小 (KB)
 #define BPF_PERF_BUFFER_SIZE 64     // Perf buffer 大小 (KB)
 
 // 内核版本检查
 struct kernel_version {
     int major;
     int minor;
     int patch;
 };
 
 // 获取内核版本
 static inline int get_kernel_version(struct kernel_version* version) {
     if (!version) return ERROR_INVALID_PARAM;
     
     FILE* fp = fopen("/proc/version", "r");
     if (!fp) {
         ERROR_PRINT("无法读取内核版本");
         return ERROR_GENERIC;
     }
     
     char line[256];
     if (fgets(line, sizeof(line), fp) == NULL) {
         fclose(fp);
         return ERROR_GENERIC;
     }
     fclose(fp);
     
     // 解析版本号 "Linux version 5.4.0-..."
     if (sscanf(line, "Linux version %d.%d.%d", 
                &version->major, &version->minor, &version->patch) != 3) {
         ERROR_PRINT("内核版本解析失败");
         return ERROR_GENERIC;
     }
     
     return SUCCESS;
 }
 
 // 检查是否支持 ring buffer (内核版本 >= 5.8)
 static inline int supports_ring_buffer(void) {
     struct kernel_version version;
     if (get_kernel_version(&version) != SUCCESS) {
         return 0;
     }
     
     return (version.major > 5 || (version.major == 5 && version.minor >= 8));
 }
 
 #endif // COMMON_H