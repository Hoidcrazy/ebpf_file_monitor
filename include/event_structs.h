// include/event_structs.h
#pragma once

# include <common.h>

// 内核到用户态传递的事件结构体
struct open_event {
    int pid;
    int fd;
    char filename[MAX_PATH_LEN];
};

struct rw_event {
    int pid;
    int fd;
    unsigned long buf_addr;  // 用户空间缓冲区地址
    size_t size;             // 读写大小
};

struct close_event {
    int pid;
    int fd;
};