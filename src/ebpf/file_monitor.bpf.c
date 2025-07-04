/**
 * @file file_monitor.bpf.c
 * @brief eBPF 内核程序 - 文件操作监控和数据欺骗
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件实现了 eBPF 内核程序，用于 hook 系统调用并监控文件操作
 * 主要功能包括：
 * - hook open/read/write/close 系统调用
 * - 构建 fd → filepath 映射表
 * - 推送事件到用户态
 * - 支持 ring buffer 和 perf buffer 通信
 */

 #include <linux/bpf.h>
 #include <linux/ptrace.h>
 #include <linux/version.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 
 #include "common.h"
 #include "event_structs.h"
 
 // 许可证声明
 char LICENSE[] SEC("license") = "GPL";
 
 // 内核版本检查
 __u32 version SEC("version") = LINUX_VERSION_CODE;
 
 // BPF 映射定义
 
 // fd → 文件信息映射表
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, BPF_MAP_MAX_ENTRIES);
     __type(key, fd_key_t);
     __type(value, file_info_t);
 } fd_map SEC(".maps");
 
 // 事件输出映射 - 支持 ring buffer 和 perf buffer
 struct {
     __uint(type, BPF_MAP_TYPE_RINGBUF);
     __uint(max_entries, BPF_RING_BUFFER_SIZE * 1024);
 } events SEC(".maps");
 
 // 备用的 perf buffer 映射（用于旧内核）
 struct {
     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
     __uint(key_size, sizeof(__u32));
     __uint(value_size, sizeof(__u32));
 } events_perf SEC(".maps");
 
 // 统计信息映射
 struct {
     __uint(type, BPF_MAP_TYPE_ARRAY);
     __uint(max_entries, 1);
     __type(key, __u32);
     __type(value, event_stats_t);
 } stats_map SEC(".maps");
 
 // 配置映射
 struct {
     __uint(type, BPF_MAP_TYPE_ARRAY);
     __uint(max_entries, 1);
     __type(key, __u32);
     __type(value, __u32);  // 配置标志
 } config_map SEC(".maps");
 
 // 辅助函数声明
 static inline int should_trace_file(const char* filepath);
 static inline void update_stats(file_operation_type_t op_type);
 static inline __u64 get_current_timestamp_ns(void);
 static inline int send_event_ringbuf(void* event, size_t size);
 static inline int send_event_perfbuf(void* event, size_t size);
 
 /**
  * @brief 获取当前时间戳（纳秒）
  * @return __u64 时间戳
  */
 static inline __u64 get_current_timestamp_ns(void) {
     return bpf_ktime_get_ns();
 }
 
 /**
  * @brief 检查是否应该追踪该文件
  * @param filepath 文件路径
  * @return int 1表示应该追踪，0表示不追踪
  */
 static inline int should_trace_file(const char* filepath) {
     if (!filepath) return 0;
     
     // 跳过系统目录
     if (bpf_strncmp(filepath, "/proc/", 6) == 0) return 0;
     if (bpf_strncmp(filepath, "/sys/", 5) == 0) return 0;
     if (bpf_strncmp(filepath, "/dev/", 5) == 0) return 0;
     if (bpf_strncmp(filepath, "/tmp/", 5) == 0) return 0;
     
     return 1;
 }
 
 /**
  * @brief 更新统计信息
  * @param op_type 操作类型
  */
 static inline void update_stats(file_operation_type_t op_type) {
     __u32 key = 0;
     event_stats_t* stats = bpf_map_lookup_elem(&stats_map, &key);
     
     if (stats) {
         __sync_fetch_and_add(&stats->total_events, 1);
         stats->last_event_time = get_current_timestamp_ns();
         
         switch (op_type) {
             case FILE_OP_OPEN:
                 __sync_fetch_and_add(&stats->open_events, 1);
                 break;
             case FILE_OP_READ:
                 __sync_fetch_and_add(&stats->read_events, 1);
                 break;
             case FILE_OP_WRITE:
                 __sync_fetch_and_add(&stats->write_events, 1);
                 break;
             case FILE_OP_CLOSE:
                 __sync_fetch_and_add(&stats->close_events, 1);
                 break;
         }
     }
 }
 
 /**
  * @brief 通过 ring buffer 发送事件
  * @param event 事件数据
  * @param size 事件大小
  * @return int 成功返回0，失败返回负数
  */
 static inline int send_event_ringbuf(void* event, size_t size) {
     void* ringbuf_mem = bpf_ringbuf_reserve(&events, size, 0);
     if (!ringbuf_mem) {
         return -1;
     }
     
     bpf_probe_read_kernel(ringbuf_mem, size, event);
     bpf_ringbuf_submit(ringbuf_mem, 0);
     
     return 0;
 }
 
 /**
  * @brief 通过 perf buffer 发送事件
  * @param event 事件数据
  * @param size 事件大小
  * @return int 成功返回0，失败返回负数
  */
 static inline int send_event_perfbuf(void* event, size_t size) {
     return bpf_perf_event_output(bpf_get_current_task(), &events_perf, 
                                 BPF_F_CURRENT_CPU, event, size);
 }
 
 /**
  * @brief 发送事件到用户态
  * @param event 事件数据
  * @param size 事件大小
  * @return int 成功返回0，失败返回负数
  */
 static inline int send_event(void* event, size_t size) {
     // 首先尝试 ring buffer，如果失败则使用 perf buffer
     if (send_event_ringbuf(event, size) == 0) {
         return 0;
     }
     
     return send_event_perfbuf(event, size);
 }
 
 /**
  * @brief 填充事件基础信息
  * @param base 基础事件结构
  * @param op_type 操作类型
  * @param fd 文件描述符
  * @param filepath 文件路径
  * @param ret_code 返回码
  */
 static inline void fill_event_base(file_event_base_t* base, 
                                   file_operation_type_t op_type,
                                   int fd, const char* filepath, int ret_code) {
     if (!base) return;
     
     base->timestamp = get_current_timestamp_ns();
     base->pid = bpf_get_current_pid_tgid() >> 32;
     base->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
     base->uid = bpf_get_current_uid_gid() >> 32;
     base->gid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
     base->op_type = op_type;
     base->fd = fd;
     base->ret_code = ret_code;
     
     // 获取进程名
     bpf_get_current_comm(&base->comm, sizeof(base->comm));
     
     // 复制文件路径
     if (filepath) {
         bpf_probe_read_user_str(base->filepath, sizeof(base->filepath), filepath);
     }
 }
 
 /**
  * @brief hook sys_openat 系统调用入口
  */
 SEC("kprobe/__x64_sys_openat")
 int trace_openat_entry(struct pt_regs* ctx) {
     // 获取参数
     int dfd = (int)PT_REGS_PARM1(ctx);
     const char __user* filename = (const char __user*)PT_REGS_PARM2(ctx);
     int flags = (int)PT_REGS_PARM3(ctx);
     umode_t mode = (umode_t)PT_REGS_PARM4(ctx);
     
     // 读取文件名
     char filepath[MAX_PATH_LEN];
     if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0) {
         return 0;
     }
     
     // 检查是否需要追踪
     if (!should_trace_file(filepath)) {
         return 0;
     }
     
     // 这里只是记录调用，实际的文件描述符要在返回时获取
     return 0;
 }
 
 /**
  * @brief hook sys_openat 系统调用返回
  */
 SEC("kretprobe/__x64_sys_openat")
 int trace_openat_return(struct pt_regs* ctx) {
     long fd = PT_REGS_RC(ctx);
     
     // 检查是否打开成功
     if (fd < 0) {
         return 0;
     }
     
     // 获取文件名（需要从内核结构中获取）
     struct task_struct* task = (struct task_struct*)bpf_get_current_task();
     if (!task) {
         return 0;
     }
     
     // 构造文件打开事件
     file_open_event_t event = {};
     fill_event_base(&event.base, FILE_OP_OPEN, (int)fd, NULL, (int)fd);
     
     // 填充打开相关信息
     event.flags = 0;  // 从上下文中获取
     event.mode = 0;   // 从上下文中获取
     event.inode = 0;  // 从文件结构中获取
     event.device = 0; // 从文件结构中获取
     
     // 创建 fd 映射条目
     fd_key_t key = {
         .fd = (int)fd,
         .pid = event.base.pid
     };
     
     file_info_t info = {};
     bpf_probe_read_kernel_str(info.filepath, sizeof(info.filepath), event.base.filepath);
     info.open_time = event.base.timestamp;
     info.flags = event.flags;
     info.mode = event.mode;
     
     // 更新映射
     bpf_map_update_elem(&fd_map, &key, &info, BPF_ANY);
     
     // 发送事件
     send_event(&event, sizeof(event));
     
     // 更新统计
     update_stats(FILE_OP_OPEN);
     
     return 0;
 }
 
 /**
  * @brief hook sys_read 系统调用入口
  */
 SEC("kprobe/__x64_sys_read")
 int trace_read_entry(struct pt_regs* ctx) {
     unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
     char __user* buf = (char __user*)PT_REGS_PARM2(ctx);
     size_t count = (size_t)PT_REGS_PARM3(ctx);
     
     // 查找文件信息
     __u32 pid = bpf_get_current_pid_tgid() >> 32;
     fd_key_t key = {
         .fd = (int)fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return 0;
     }
     
     // 检查是否需要追踪
     if (!should_trace_file(info->filepath)) {
         return 0;
     }
     
     // 将缓冲区地址存储到临时映射中（用于返回时使用）
     // 这里可以使用 per-CPU 数组或其他机制
     
     return 0;
 }
 
 /**
  * @brief hook sys_read 系统调用返回
  */
 SEC("kretprobe/__x64_sys_read")
 int trace_read_return(struct pt_regs* ctx) {
     long bytes_read = PT_REGS_RC(ctx);
     
     // 检查是否读取成功
     if (bytes_read <= 0) {
         return 0;
     }
     
     // 获取当前进程信息
     __u32 pid = bpf_get_current_pid_tgid() >> 32;
     
     // 这里需要从入口函数中获取参数信息
     // 为了简化，我们假设可以从某种方式获取到 fd 和 buffer 信息
     
     // 构造读取事件
     file_read_event_t event = {};
     fill_event_base(&event.base, FILE_OP_READ, 0, NULL, (int)bytes_read);
     
     event.buffer_addr = 0;      // 从入口函数获取
     event.count = bytes_read;
     event.bytes_read = bytes_read;
     event.file_offset = 0;      // 从文件结构获取
     
     // 发送事件
     send_event(&event, sizeof(event));
     
     // 更新统计
     update_stats(FILE_OP_READ);
     
     return 0;
 }
 
 /**
  * @brief hook sys_write 系统调用入口
  */
 SEC("kprobe/__x64_sys_write")
 int trace_write_entry(struct pt_regs* ctx) {
     unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
     const char __user* buf = (const char __user*)PT_REGS_PARM2(ctx);
     size_t count = (size_t)PT_REGS_PARM3(ctx);
     
     // 查找文件信息
     __u32 pid = bpf_get_current_pid_tgid() >> 32;
     fd_key_t key = {
         .fd = (int)fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return 0;
     }
     
     // 检查是否需要追踪
     if (!should_trace_file(info->filepath)) {
         return 0;
     }
     
     return 0;
 }
 
 /**
  * @brief hook sys_write 系统调用返回
  */
 SEC("kretprobe/__x64_sys_write")
 int trace_write_return(struct pt_regs* ctx) {
     long bytes_written = PT_REGS_RC(ctx);
     
     // 检查是否写入成功
     if (bytes_written <= 0) {
         return 0;
     }
     
     // 构造写入事件
     file_write_event_t event = {};
     fill_event_base(&event.base, FILE_OP_WRITE, 0, NULL, (int)bytes_written);
     
     event.buffer_addr = 0;          // 从入口函数获取
     event.count = bytes_written;
     event.bytes_written = bytes_written;
     event.file_offset = 0;          // 从文件结构获取
     
     // 发送事件
     send_event(&event, sizeof(event));
     
     // 更新统计
     update_stats(FILE_OP_WRITE);
     
     return 0;
 }
 
 /**
  * @brief hook sys_close 系统调用入口
  */
 SEC("kprobe/__x64_sys_close")
 int trace_close_entry(struct pt_regs* ctx) {
     unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
     
     // 查找文件信息
     __u32 pid = bpf_get_current_pid_tgid() >> 32;
     fd_key_t key = {
         .fd = (int)fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return 0;
     }
     
     // 检查是否需要追踪
     if (!should_trace_file(info->filepath)) {
         return 0;
     }
     
     // 构造关闭事件
     file_close_event_t event = {};
     fill_event_base(&event.base, FILE_OP_CLOSE, (int)fd, info->filepath, 0);
     
     // 计算文件生命周期
     __u64 current_time = get_current_timestamp_ns();
     event.file_lifetime = (current_time - info->open_time) / 1000000; // 转换为毫秒
     event.total_bytes_read = info->total_read_bytes;
     event.total_bytes_written = info->total_write_bytes;
     
     // 发送事件
     send_event(&event, sizeof(event));
     
     // 从映射中删除条目
     bpf_map_delete_elem(&fd_map, &key);
     
     // 更新统计
     update_stats(FILE_OP_CLOSE);
     
     return 0;
 }
 
 /**
  * @brief hook sys_close 系统调用返回
  */
 SEC("kretprobe/__x64_sys_close")
 int trace_close_return(struct pt_regs* ctx) {
     long ret = PT_REGS_RC(ctx);
     
     // 检查关闭是否成功
     if (ret != 0) {
         // 关闭失败，但我们在入口时已经处理了事件
         return 0;
     }
     
     return 0;
 }
 
 /**
  * @brief 追踪点：文件打开
  */
 SEC("tracepoint/syscalls/sys_enter_openat")
 int trace_enter_openat(struct trace_event_raw_sys_enter* ctx) {
     // 获取系统调用参数
     int dfd = (int)ctx->args[0];
     const char __user* filename = (const char __user*)ctx->args[1];
     int flags = (int)ctx->args[2];
     umode_t mode = (umode_t)ctx->args[3];
     
     // 读取文件名
     char filepath[MAX_PATH_LEN];
     if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0) {
         return 0;
     }
     
     // 检查是否需要追踪
     if (!should_trace_file(filepath)) {
         return 0;
     }
     
     // 记录打开尝试（实际处理在退出追踪点）
     return 0;
 }
 
 /**
  * @brief 追踪点：文件打开返回
  */
 SEC("tracepoint/syscalls/sys_exit_openat")
 int trace_exit_openat(struct trace_event_raw_sys_exit* ctx) {
     long fd = ctx->ret;
     
     // 检查是否打开成功
     if (fd < 0) {
         return 0;
     }
     
     // 处理文件打开事件（类似于 kretprobe 处理）
     file_open_event_t event = {};
     fill_event_base(&event.base, FILE_OP_OPEN, (int)fd, NULL, (int)fd);
     
     // 发送事件
     send_event(&event, sizeof(event));
     
     // 更新统计
     update_stats(FILE_OP_OPEN);
     
     return 0;
 }
 
 /**
  * @brief 初始化函数（在程序加载时调用）
  */
 SEC("raw_tracepoint/bpf_prog_load")
 int trace_prog_load(struct bpf_raw_tracepoint_args* ctx) {
     // 初始化统计信息
     __u32 key = 0;
     event_stats_t stats = {};
     stats.total_events = 0;
     stats.last_event_time = get_current_timestamp_ns();
     
     bpf_map_update_elem(&stats_map, &key, &stats, BPF_ANY);
     
     return 0;
 }
 
 /**
  * @brief 清理函数（在程序卸载时调用）
  */
 SEC("raw_tracepoint/bpf_prog_free")
 int trace_prog_free(struct bpf_raw_tracepoint_args* ctx) {
     // 清理资源
     return 0;
 }