// include/event_structs.h
#pragma once

#include "common_user.h"

// 内核向用户态传递的事件结构
struct event {
    enum event_type type;   // 事件类型
    uint32_t pid;           // 进程ID
    uint32_t fd;            // 文件描述符
    uint64_t buffer_addr;   // 用户空间缓冲区地址
    uint64_t size;          // 读写大小
    char filename[MAX_PATH_LEN]; // 文件路径
    char data[MAX_BUFFER_SIZE];  // 新增字段
};