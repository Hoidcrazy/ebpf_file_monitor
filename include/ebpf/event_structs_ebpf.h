// include/ebpf/event_structs_ebpf.h
#pragma once

#include "common_ebpf.h"

// 内核向用户态传递的事件结构
struct event {
    enum event_type type;   // 事件类型
    u32 pid;                // 进程ID
    u32 fd;                 // 文件描述符
    u64 buffer_addr;        // 用户空间缓冲区地址
    u64 size;               // 读写大小
    char filename[MAX_PATH_LEN]; // 文件路径
    char data[MAX_BUFFER_SIZE];  // 新增字段
};