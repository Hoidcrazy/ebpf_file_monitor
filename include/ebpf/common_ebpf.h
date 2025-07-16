// include/ebpf/common_ebpf.h
#pragma once

// 定义兼容 eBPF 的基本类型
typedef unsigned char       u8;
typedef signed char         s8;
typedef unsigned short      u16;
typedef signed short        s16;
typedef unsigned int        u32;
typedef signed int          s32;
typedef unsigned long long  u64;
typedef signed long long    s64;

// 通用常量定义
#define MAX_PATH_LEN 128
#define MAX_BUFFER_SIZE 512
#define MAX_EVENT_SIZE 256

// 文件后缀检查宏
#define IS_TXT_FILE(path) (strstr(path, ".txt") != NULL)

// 系统调用类型枚引
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