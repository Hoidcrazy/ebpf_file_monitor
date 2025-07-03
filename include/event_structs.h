#ifndef EVENT_STRUCTS_H
#define EVENT_STRUCTS_H

#include <linux/types.h>

#define MAX_PATH_LEN 256

// 事件类型
enum event_type {
    EV_OPEN = 0,
    EV_READ = 1,
    EV_WRITE = 2,
    EV_CLOSE = 3
};

// 从内核传递到用户态的事件结构体
struct event_t {
    __u32 pid;                  // 进程ID
    __u32 fd;                   // 文件描述符
    __u32 size;                 // 读取或写入长度
    __u64 buf;                  // 用户态缓冲区地址
    char path[MAX_PATH_LEN];    // 文件路径
    __u8 op;                    // 事件类型（0=open,1=read,2=write,3=close）
};

#endif // EVENT_STRUCTS_H
