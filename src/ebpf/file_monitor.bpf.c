// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>
#include <linux/version.h>
#include <bpf_helpers.h>
#include "event_structs.h"

#define MAX_PATH_LEN 256

// FD 映射表：key = (pid << 32) | fd, value = 路径字符串
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char[MAX_PATH_LEN]);
} fd_map SEC(".maps");

// 事件输出 map：perf ring / perf event
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// 临时存储 open 参数，key 为 pid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char[MAX_PATH_LEN]);
} open_args_map SEC(".maps");

// Helper: 获取当前 pid 和 tid 组成的 key
static __inline __u64 get_pid_key() {
    __u64 pid = bpf_get_current_pid_tgid();
    return pid >> 32; // 仅使用 PID 部分
}

// kprobe: open 系统调用入口
SEC("kprobe/__x64_sys_openat")
int probe_do_sys_openat(struct pt_regs *ctx) {
    __u64 pid = get_pid_key();
    const char __user *fname = (const char *) PT_REGS_PARM2(ctx);
    char path[MAX_PATH_LEN] = {};
    // 从用户空间读取文件路径
    bpf_probe_read_user_str(path, sizeof(path), fname);
    // 存储到临时 map
    bpf_map_update_elem(&open_args_map, &pid, path, BPF_ANY);
    return 0;
}

// kretprobe: open 系统调用返回
SEC("kretprobe/__x64_sys_openat")
int probe_ret_sys_openat(struct pt_regs *ctx) {
    __s64 ret_fd = PT_REGS_RC(ctx);
    if (ret_fd < 0) {
        // 打开失败，不处理
        return 0;
    }
    __u64 pid = get_pid_key();
    // 从临时 map 获取路径
    char *path = bpf_map_lookup_elem(&open_args_map, &pid);
    if (!path) {
        return 0;
    }
    // 构建 map key = (pid << 32) | fd
    __u64 key = (pid << 32) | (__u32)ret_fd;
    // 存入 fd_map
    bpf_map_update_elem(&fd_map, &key, path, BPF_ANY);
    // 发送 OPEN 事件到用户态
    struct event_t evt = {};
    evt.pid = pid;
    evt.fd = ret_fd;
    evt.size = 0;
    evt.buf = 0;
    evt.op = EV_OPEN;
    __builtin_memcpy(evt.path, path, MAX_PATH_LEN);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    // 删除临时 map 元素
    bpf_map_delete_elem(&open_args_map, &pid);
    return 0;
}

// kprobe: read 系统调用入口
SEC("kprobe/__x64_sys_read")
int probe_do_sys_read(struct pt_regs *ctx) {
    __u32 fd = (int)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);
    __u64 pid = get_pid_key();
    __u64 key = (pid << 32) | (__u32)fd;
    // 从 fd_map 查找文件路径
    char *path = bpf_map_lookup_elem(&fd_map, &key);
    if (!path) {
        return 0; // 未监控的文件
    }
    // 构造并发送 READ 事件
    struct event_t evt = {};
    evt.pid = pid;
    evt.fd = fd;
    evt.size = count;
    evt.buf = (u64)buf;
    evt.op = EV_READ;
    __builtin_memcpy(evt.path, path, MAX_PATH_LEN);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// kprobe: write 系统调用入口
SEC("kprobe/__x64_sys_write")
int probe_do_sys_write(struct pt_regs *ctx) {
    __u32 fd = (int)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);
    __u64 pid = get_pid_key();
    __u64 key = (pid << 32) | (__u32)fd;
    char *path = bpf_map_lookup_elem(&fd_map, &key);
    if (!path) {
        return 0;
    }
    // 构造并发送 WRITE 事件
    struct event_t evt = {};
    evt.pid = pid;
    evt.fd = fd;
    evt.size = count;
    evt.buf = (u64)buf;
    evt.op = EV_WRITE;
    __builtin_memcpy(evt.path, path, MAX_PATH_LEN);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// kprobe: close 系统调用入口
SEC("kprobe/__x64_sys_close")
int probe_do_sys_close(struct pt_regs *ctx) {
    __u32 fd = (int)PT_REGS_PARM1(ctx);
    __u64 pid = get_pid_key();
    __u64 key = (pid << 32) | (__u32)fd;
    // 从 fd_map 取出路径用于日志
    char *path = bpf_map_lookup_elem(&fd_map, &key);
    if (path) {
        // 构造并发送 CLOSE 事件
        struct event_t evt = {};
        evt.pid = pid;
        evt.fd = fd;
        evt.size = 0;
        evt.buf = 0;
        evt.op = EV_CLOSE;
        __builtin_memcpy(evt.path, path, MAX_PATH_LEN);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        // 删除映射
        bpf_map_delete_elem(&fd_map, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
