// include/common.h
#pragma once

#include <stdint.h>

// 通用常量定义
#define MAX_PATH_LEN 128
#define MAX_BUFFER_SIZE 512
#define MAX_EVENT_SIZE 256

// 文件后缀检查宏
#define IS_TXT_FILE(path) (strstr(path, ".txt") != NULL)

// 系统调用类型枚举
enum syscall_type {
    SYSCALL_OPEN,
    SYSCALL_READ,
    SYSCALL_WRITE,
    SYSCALL_CLOSE
};

// 事件类型枚举
enum event_type {
    EVENT_OPEN,
    EVENT_READ,
    EVENT_WRITE,
    EVENT_CLOSE,
    EVENT_MODIFIED
};