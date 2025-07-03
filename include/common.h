#ifndef COMMON_H
#define COMMON_H

// 最大文件路径长度
#define MAX_PATH_LEN 256

// 日志打印宏
#define LOG_INFO(fmt, ...)    printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    printf("[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   printf("[ERROR] " fmt "\n", ##__VA_ARGS__)

#endif // COMMON_H
