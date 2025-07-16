// src/ebpf/fd_map.bpf.c
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "ebpf/event_structs_ebpf.h"

// 文件描述符到路径的映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);       // fd
    __type(value, char[MAX_PATH_LEN]);
} fd_path_map SEC(".maps");

// 事件映射表（Perf/Ring Buffer）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 获取文件路径的辅助函数
static void get_file_path(struct file *file, char *path) {
    struct path *f_path = &file->f_path;
    char *d_path = d_path(f_path, path, MAX_PATH_LEN);
    
    if (IS_ERR(d_path)) {
        bpf_probe_read_str(path, MAX_PATH_LEN, "<unknown>");
    } else {
        // 复制到用户提供的缓冲区
        bpf_probe_read_str(path, MAX_PATH_LEN, d_path);
    }
}