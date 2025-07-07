// src/ebpf/file_monitor.bpf.c
#include "fd_map.bpf.c"

// 定义系统调用入口点
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(__x64_sys_openat, int dfd, const char __user *filename, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 获取文件指针
    struct file *file;
    bpf_probe_read(&file, sizeof(file), PT_REGS_RC(ctx));
    
    // 存储fd到路径的映射
    char path[MAX_PATH_LEN];
    get_file_path(file, path);
    
    u32 fd = PT_REGS_RC(ctx);
    bpf_map_update_elem(&fd_path_map, &fd, path, BPF_ANY);
    
    // 发送open事件
    struct open_event evt = {
        .pid = pid,
        .fd = fd,
    };
    bpf_probe_read_str(evt.filename, MAX_PATH_LEN, path);
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    
    return 0;
}

SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(__x64_sys_read, int ret) {
    if (ret <= 0) return 0;  // 忽略错误
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    // 查找文件路径
    char *path = bpf_map_lookup_elem(&fd_path_map, &fd);
    if (!path) return 0;
    
    // 发送read事件
    struct rw_event evt = {
        .pid = pid,
        .fd = fd,
        .buf_addr = (unsigned long)buf,
        .size = count,
    };
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    
    return 0;
}

// 类似地实现write和close的hook
SEC("kretprobe/__x64_sys_write")
int BPF_KRETPROBE(__x64_sys_write, int ret) { /* 类似read的实现 */ }

SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(__x64_sys_close, int fd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 发送close事件
    struct close_event evt = {.pid = pid, .fd = fd};
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    
    // 从映射表中删除
    bpf_map_delete_elem(&fd_path_map, &fd);
    return 0;
}

char _license[] SEC("license") = "GPL";