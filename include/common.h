// include/common.h
#pragma once

// 通用常量和宏定义
#define MAX_PATH_LEN 256
#define MAX_BUFFER_LEN 4096
#define MAX_MSG_LEN 512
#define LOG_DIR "tests/log/"

// 文件后缀检查宏
#define IS_TXT_FILE(path) \
    (strlen(path) > 4 && strcmp(path + strlen(path) - 4, ".txt") == 0)

// 错误处理宏
#define CHECK_ERR(condition, msg, ...) \
    if (condition) { \
        fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    }