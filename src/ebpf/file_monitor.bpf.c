// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include "common.h"
// #include "event_structs.h"

// // 解决 bpf_strnlen 函数缺失
// // 自定义字符串长度函数
// static __always_inline int my_strnlen(const char *s, int max_len) {
//     int len = 0;
//     #pragma unroll
//     for (int i = 0; i < max_len; i++) {
//         if (s[i] == '\0') break;
//         len++;
//     }
//     return len;
// }

// // 定义映射表
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10240);
//     __type(key, u32);      // 文件描述符
//     __type(value, char[MAX_PATH_LEN]); // 文件路径
// } fd_map SEC(".maps");

// // 定义 perf_event 输出
// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(key_size, sizeof(u32));
//     __uint(value_size, sizeof(u32));
// } events SEC(".maps");

// // 临时事件缓冲区
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, struct event);
// } tmp_event_heap SEC(".maps");

// // 定义用于存储文件路径的缓冲区
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, char[MAX_PATH_LEN]);
// } file_path_map SEC(".maps");

// // 获取文件路径
// static void get_file_path(struct file *file, char *buf, u32 key) {
//     // 修复1: 正确读取路径结构
//     struct path path;
//     bpf_core_read(&path, sizeof(path), &file->f_path);
    
//     struct dentry *dentry;
//     bpf_core_read(&dentry, sizeof(dentry), &path.dentry);
    
//     // 获取文件名
//     struct qstr qname;
//     bpf_core_read(&qname, sizeof(qname), &dentry->d_name);
//     char name[MAX_PATH_LEN] = {0};
//     bpf_probe_read_kernel_str(name, MAX_PATH_LEN, qname.name);
    
//     // 获取父目录
//     struct dentry *parent;
//     bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
//     char parent_name[MAX_PATH_LEN] = {0};
    
//     // 递归获取完整路径
//     char full_path[MAX_PATH_LEN] = {0};
//     char *ptr = full_path + MAX_PATH_LEN - 1;
//     *ptr = '\0';
    
//     int depth = 0;
//     const int max_depth = 20;  // 防止无限循环
    
//     while (parent != dentry && depth < max_depth) {
//         bpf_core_read(&qname, sizeof(qname), &parent->d_name);
//         int len = bpf_probe_read_kernel_str(parent_name, MAX_PATH_LEN, qname.name);
        
//         // 处理根目录情况
//         if (len == 1 && parent_name[0] == '/') {
//             break;
//         }
        
//         // 添加到路径前面
//         ptr -= len;
//         if (ptr < full_path) break;
//         bpf_probe_read_kernel(ptr, len, parent_name);
        
//         // 添加路径分隔符
//         if (*(ptr + len - 1) != '/') {
//             ptr--;
//             if (ptr < full_path) break;
//             *ptr = '/';
//         }
        
//         dentry = parent;
//         bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
//         depth++;
//     }
    
//     // 添加最终文件名
//     // 修复2: 使用自定义字符串长度函数
//     int name_len = my_strnlen(name, MAX_PATH_LEN);
//     ptr -= name_len;
//     if (ptr >= full_path) {
//         bpf_probe_read_kernel(ptr, name_len, name);
//     }
    
//     // 将路径存入 map
//     bpf_map_update_elem(&file_path_map, &key, full_path, BPF_ANY);
    
//     // bpf_probe_read_kernel_str(buf, MAX_PATH_LEN, ptr);
// }


// // 发送事件到用户态
// static void send_event(void *ctx, enum event_type type, u32 pid, u32 fd, 
//                       u64 buffer_addr, u64 size, u32 key) {
//     // u32 key = 0;
//     // struct event *e = bpf_map_lookup_elem(&tmp_event_heap, &key);
//     u32 map_key = 0;
//     struct event *e = bpf_map_lookup_elem(&tmp_event_heap, &map_key);
//     if (!e)
//         return;

//     __builtin_memset(e, 0, sizeof(*e));  // 用于清空结构体

//     e->type = type;
//     e->pid = pid;
//     e->fd = fd;
//     e->buffer_addr = buffer_addr;
//     e->size = size;

//     // if (filename)
//     //     bpf_probe_read_kernel_str(e->filename, MAX_PATH_LEN, filename);

//     char *path = bpf_map_lookup_elem(&file_path_map, &key);
//     if (path) {
//         bpf_probe_read_kernel_str(e->filename, MAX_PATH_LEN, path);
//     }

//     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
// }

// // sys_openat 钩子修复
// // Hook: openat系统调用
// SEC("kprobe/__x64_sys_openat")
// int BPF_KPROBE(openat) {  // 删除参数定义，BPF_KPROBE 会自动处理 ctx
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     const char *filename = (const char *)PT_REGS_PARM2(ctx);
//     char path[MAX_PATH_LEN];
//     bpf_probe_read_user_str(path, MAX_PATH_LEN, filename);
    
//     u32 key = 0;  // 使用文件描述符作为 key
//     get_file_path(path, key);

//     // 发送打开事件
//     send_event(ctx, EVENT_OPEN, pid, 0, 0, 0, path);
//     return 0;
// }

// // Hook: openat返回
// SEC("kretprobe/__x64_sys_openat")
// int BPF_KRETPROBE(sys_openat_ret, long ret) {
//     if (ret < 0) return 0; // 打开失败
    
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     u32 fd = (u32)ret;
    
//     // 获取文件结构
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     struct files_struct *files = BPF_CORE_READ(task, files);
//     struct file **fd_array = BPF_CORE_READ(files, fdt, fd);
//     struct file *file = fd_array[fd];
    
//     // 获取文件路径
//     // char path[MAX_PATH_LEN];
//     // get_file_path(file, path);
//     u32 key = fd;  // 使用文件描述符作为 key
//     get_file_path(file, key);
    
//     // 更新fd->path映射
//     bpf_map_update_elem(&fd_map, &fd, path, BPF_ANY);
//     send_event(ctx, EVENT_OPEN, pid, fd, 0, 0, key);
    
//     return 0;
// }


// // sys_read 钩子修复
// // Hook: read系统调用
// SEC("kprobe/__x64_sys_read")
// int BPF_KPROBE(read) {  // 删除参数定义，BPF_KPROBE 会自动处理 ctx
//     unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
//     char *buf = (char *)PT_REGS_PARM2(ctx);
//     size_t count = (size_t)PT_REGS_PARM3(ctx);
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
    
//     // 查找文件路径
//     u32 key = fd;  // 使用文件描述符作为 key
//     char *path = bpf_map_lookup_elem(&fd_map, &fd);
//     if (!path) return 0;
    
//     // 发送读取事件
//     // send_event(ctx, EVENT_READ, pid, fd, (u64)buf, count, path);
//     send_event(ctx, EVENT_READ, pid, fd, (u64)buf, count, key);
//     return 0;
// }

// // Hook: close系统调用
// SEC("kprobe/__x64_sys_close")
// int BPF_KPROBE(sys_close, unsigned int fd) {
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
    
//     // 查找文件路径
//     unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);  // 获取 fd
//     u32 key = fd;  // 使用文件描述符作为 key
//     char *path = bpf_map_lookup_elem(&fd_map, &fd);
//     if (!path) return 0;
    
//     // 发送关闭事件
//     send_event(ctx, EVENT_CLOSE, pid, fd, 0, 0, path);
    
//     // 从映射中删除
//     bpf_map_delete_elem(&fd_map, &fd);
//     return 0;
// }

// char _license[] SEC("license") = "GPL";




#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "ebpf/common_ebpf.h"
#include "ebpf/event_structs_ebpf.h"

// 自定义字符串长度函数
static __always_inline int my_strnlen(const char *s, int max_len) {
    int len = 0;
    #pragma unroll
    for (int i = 0; i < max_len; i++) {
        if (s[i] == '\0') break;
        len++;
    }
    return len;
}

// 定义映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);      // 文件描述符
    __type(value, char[MAX_PATH_LEN]); // 文件路径
} fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 临时事件缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} tmp_event_heap SEC(".maps");

// 用于存储文件路径的缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_PATH_LEN]);
} file_path_map SEC(".maps");

// 获取文件路径
static void get_file_path(struct file *file, u32 key) {
    struct path path;
    bpf_core_read(&path, sizeof(path), &file->f_path);
    
    struct dentry *dentry;
    bpf_core_read(&dentry, sizeof(dentry), &path.dentry);
    
    struct qstr qname;
    bpf_core_read(&qname, sizeof(qname), &dentry->d_name);
    char name[MAX_PATH_LEN] = {0};
    bpf_probe_read_kernel_str(name, MAX_PATH_LEN, qname.name);
    
    struct dentry *parent;
    bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
    char parent_name[MAX_PATH_LEN] = {0};
    
    char full_path[MAX_PATH_LEN] = {0};
    char *ptr = full_path + MAX_PATH_LEN - 1;
    *ptr = '\0';
    
    int depth = 0;
    const int max_depth = 20;
    
    while (parent != dentry && depth < max_depth) {
        bpf_core_read(&qname, sizeof(qname), &parent->d_name);
        int len = bpf_probe_read_kernel_str(parent_name, MAX_PATH_LEN, qname.name);
        
        if (len == 1 && parent_name[0] == '/') {
            break;
        }
        
        ptr -= len;
        if (ptr < full_path) break;
        bpf_probe_read_kernel(ptr, len, parent_name);
        
        if (*(ptr + len - 1) != '/') {
            ptr--;
            if (ptr < full_path) break;
            *ptr = '/';
        }
        
        dentry = parent;
        bpf_core_read(&parent, sizeof(parent), &dentry->d_parent);
        depth++;
    }
    
    int name_len = my_strnlen(name, MAX_PATH_LEN);
    ptr -= name_len;
    if (ptr >= full_path) {
        bpf_probe_read_kernel(ptr, name_len, name);
    }
    
    // 将路径存入 map
    bpf_map_update_elem(&file_path_map, &key, full_path, BPF_ANY);
}

// 发送事件到用户态
static void send_event(void *ctx, enum event_type type, u32 pid, u32 fd, 
                       u64 buffer_addr, u64 size, u32 key) {
    u32 map_key = 0;
    struct event *e = bpf_map_lookup_elem(&tmp_event_heap, &map_key);
    if (!e)
        return;

    __builtin_memset(e, 0, sizeof(*e));  // 用于清空结构体

    e->type = type;
    e->pid = pid;
    e->fd = fd;
    e->buffer_addr = buffer_addr;
    e->size = size;

    char *path = bpf_map_lookup_elem(&file_path_map, &key);
    if (path) {
        bpf_probe_read_kernel_str(e->filename, MAX_PATH_LEN, path);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

// sys_openat 钩子修复
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    char path[MAX_PATH_LEN];
    bpf_probe_read_user_str(path, MAX_PATH_LEN, filename);
    
    u32 key = 0;  // 使用文件描述符作为 key
    get_file_path(path, key);
    
    send_event(ctx, EVENT_OPEN, pid, 0, 0, 0, key);
    return 0;
}

// Hook: openat返回
SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(sys_openat_ret, long ret) {
    if (ret < 0) return 0;  // 打开失败
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = (u32)ret;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    struct file **fd_array = BPF_CORE_READ(files, fdt, fd);
    struct file *file = fd_array[fd];
    
    u32 key = fd;  // 使用文件描述符作为 key
    get_file_path(file, key);
    
    char path[MAX_PATH_LEN];  // 确保路径已声明
    get_file_path(file, key); // 获取路径
    
    bpf_map_update_elem(&fd_map, &fd, path, BPF_ANY);
    send_event(ctx, EVENT_OPEN, pid, fd, 0, 0, key);
    
    return 0;
}

// sys_read 钩子修复
SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(read) {
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u32 key = fd;  // 使用文件描述符作为 key
    char *path = bpf_map_lookup_elem(&fd_map, &fd);
    if (!path) return 0;
    
    send_event(ctx, EVENT_READ, pid, fd, (u64)buf, count, key);
    return 0;
}

// Hook: close系统调用
SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(sys_close) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);  // 获取 fd
    u32 key = fd;  // 使用文件描述符作为 key
    char *path = bpf_map_lookup_elem(&fd_map, &fd);
    if (!path) return 0;
    
    send_event(ctx, EVENT_CLOSE, pid, fd, 0, 0, key);
    
    bpf_map_delete_elem(&fd_map, &fd);
    return 0;
}

char _license[] SEC("license") = "GPL";


