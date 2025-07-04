/**
 * @file fd_map.bpf.c
 * @brief fd → path 路径映射表管理
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件实现了文件描述符到路径的映射表管理功能，
 * 提供了映射表的增删改查操作
 */

 #include <linux/bpf.h>
 #include <linux/ptrace.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 
 #include "common.h"
 #include "event_structs.h"
 
 // 许可证声明
 char LICENSE[] SEC("license") = "GPL";
 
 // 外部映射声明（在 file_monitor.bpf.c 中定义）
 extern struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, BPF_MAP_MAX_ENTRIES);
     __type(key, fd_key_t);
     __type(value, file_info_t);
 } fd_map SEC(".maps");
 
 // 临时存储映射，用于在系统调用入口和返回之间传递信息
 struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);  // PID
     __type(value, struct {
         int fd;
         char filepath[MAX_PATH_LEN];
         __u64 buffer_addr;
         size_t count;
         int flags;
         umode_t mode;
     });
 } temp_storage SEC(".maps");
 
 // 进程信息映射
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 1024);
     __type(key, __u32);  // PID
     __type(value, process_stats_t);
 } process_map SEC(".maps");
 
 /**
  * @brief 获取或创建文件信息条目
  * @param fd 文件描述符
  * @param pid 进程ID
  * @return file_info_t* 文件信息指针，失败返回NULL
  */
 static inline file_info_t* get_or_create_file_info(int fd, __u32 pid) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (info) {
         return info;
     }
     
     // 创建新的文件信息条目
     file_info_t new_info = {};
     new_info.open_time = bpf_ktime_get_ns();
     
     if (bpf_map_update_elem(&fd_map, &key, &new_info, BPF_NOEXIST) == 0) {
         return bpf_map_lookup_elem(&fd_map, &key);
     }
     
     return NULL;
 }
 
 /**
  * @brief 更新文件信息
  * @param fd 文件描述符
  * @param pid 进程ID
  * @param filepath 文件路径
  * @param flags 打开标志
  * @param mode 文件模式
  * @return int 成功返回0，失败返回负数
  */
 static inline int update_file_info(int fd, __u32 pid, const char* filepath, 
                                   int flags, umode_t mode) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         // 创建新条目
         file_info_t new_info = {};
         new_info.open_time = bpf_ktime_get_ns();
         new_info.flags = flags;
         new_info.mode = mode;
         
         if (filepath) {
             bpf_probe_read_kernel_str(new_info.filepath, sizeof(new_info.filepath), filepath);
         }
         
         return bpf_map_update_elem(&fd_map, &key, &new_info, BPF_ANY);
     } else {
         // 更新现有条目
         info->flags = flags;
         info->mode = mode;
         
         if (filepath) {
             bpf_probe_read_kernel_str(info->filepath, sizeof(info->filepath), filepath);
         }
         
         return bpf_map_update_elem(&fd_map, &key, info, BPF_EXIST);
     }
 }
 
 /**
  * @brief 删除文件信息条目
  * @param fd 文件描述符
  * @param pid 进程ID
  * @return int 成功返回0，失败返回负数
  */
 static inline int delete_file_info(int fd, __u32 pid) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     return bpf_map_delete_elem(&fd_map, &key);
 }
 
 /**
  * @brief 更新文件读取统计
  * @param fd 文件描述符
  * @param pid 进程ID
  * @param bytes_read 读取字节数
  * @return int 成功返回0，失败返回负数
  */
 static inline int update_read_stats(int fd, __u32 pid, size_t bytes_read) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return -1;
     }
     
     info->total_read_bytes += bytes_read;
     info->read_count++;
     
     return bpf_map_update_elem(&fd_map, &key, info, BPF_EXIST);
 }
 
 /**
  * @brief 更新文件写入统计
  * @param fd 文件描述符
  * @param pid 进程ID
  * @param bytes_written 写入字节数
  * @return int 成功返回0，失败返回负数
  */
 static inline int update_write_stats(int fd, __u32 pid, size_t bytes_written) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return -1;
     }
     
     info->total_write_bytes += bytes_written;
     info->write_count++;
     
     return bpf_map_update_elem(&fd_map, &key, info, BPF_EXIST);
 }
 
 /**
  * @brief 获取或创建进程统计信息
  * @param pid 进程ID
  * @return process_stats_t* 进程统计信息指针
  */
 static inline process_stats_t* get_or_create_process_stats(__u32 pid) {
     process_stats_t* stats = bpf_map_lookup_elem(&process_map, &pid);
     if (stats) {
         return stats;
     }
     
     // 创建新的进程统计信息
     process_stats_t new_stats = {};
     new_stats.pid = pid;
     new_stats.last_activity = bpf_ktime_get_ns();
     
     // 获取进程名
     bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
     
     if (bpf_map_update_elem(&process_map, &pid, &new_stats, BPF_NOEXIST) == 0) {
         return bpf_map_lookup_elem(&process_map, &pid);
     }
     
     return NULL;
 }
 
 /**
  * @brief 更新进程统计信息
  * @param pid 进程ID
  * @param op_type 操作类型
  * @param bytes 字节数
  * @return int 成功返回0，失败返回负数
  */
 static inline int update_process_stats(__u32 pid, file_operation_type_t op_type, size_t bytes) {
     process_stats_t* stats = get_or_create_process_stats(pid);
     if (!stats) {
         return -1;
     }
     
     stats->last_activity = bpf_ktime_get_ns();
     
     switch (op_type) {
         case FILE_OP_OPEN:
             stats->files_opened++;
             break;
         case FILE_OP_READ:
             stats->bytes_read += bytes;
             break;
         case FILE_OP_WRITE:
             stats->bytes_written += bytes;
             break;
         case FILE_OP_CLOSE:
             // 不需要特殊处理
             break;
     }
     
     return bpf_map_update_elem(&process_map, &pid, stats, BPF_EXIST);
 }
 
 /**
  * @brief 获取文件路径
  * @param fd 文件描述符
  * @param pid 进程ID
  * @param filepath 输出缓冲区
  * @param size 缓冲区大小
  * @return int 成功返回0，失败返回负数
  */
 static inline int get_file_path(int fd, __u32 pid, char* filepath, size_t size) {
     if (!filepath || size == 0) {
         return -1;
     }
     
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     if (!info) {
         return -1;
     }
     
     bpf_probe_read_kernel_str(filepath, size, info->filepath);
     return 0;
 }
 
 /**
  * @brief 检查文件是否已打开
  * @param fd 文件描述符
  * @param pid 进程ID
  * @return int 1表示已打开，0表示未打开
  */
 static inline int is_file_open(int fd, __u32 pid) {
     fd_key_t key = {
         .fd = fd,
         .pid = pid
     };
     
     file_info_t* info = bpf_map_lookup_elem(&fd_map, &key);
     return info != NULL;
 }
 
 /**
  * @brief 存储临时信息（用于系统调用入口和返回之间传递数据）
  * @param pid 进程ID
  * @param fd 文件描述符
  * @param filepath 文件路径
  * @param buffer_addr 缓冲区地址
  * @param count 字节数
  * @param flags 标志
  * @param mode 模式
  * @return int 成功返回0，失败返回负数
  */
 static inline int store_temp_info(__u32 pid, int fd, const char* filepath, 
                                  __u64 buffer_addr, size_t count, int flags, umode_t mode) {
     struct {
         int fd;
         char filepath[MAX_PATH_LEN];
         __u64 buffer_addr;
         size_t count;
         int flags;
         umode_t mode;
     } temp_info = {};
     
     temp_info.fd = fd;
     temp_info.buffer_addr = buffer_addr;
     temp_info.count = count;
     temp_info.flags = flags;
     temp_info.mode = mode;
     
     if (filepath) {
         bpf_probe_read_user_str(temp_info.filepath, sizeof(temp_info.filepath), filepath);
     }
     
     return bpf_map_update_elem(&temp_storage, &pid, &temp_info, BPF_ANY);
 }
 
 /**
  * @brief 获取临时信息
  * @param pid 进程ID
  * @param fd 文件描述符指针
  * @param filepath 文件路径缓冲区
  * @param buffer_addr 缓冲区地址指针
  * @param count 字节数指针
  * @param flags 标志指针
  * @param mode 模式指针
  * @return int 成功返回0，失败返回负数
  */
 static inline int get_temp_info(__u32 pid, int* fd, char* filepath, 
                                __u64* buffer_addr, size_t* count, int* flags, umode_t* mode) {
     struct {
         int fd;
         char filepath[MAX_PATH_LEN];
         __u64 buffer_addr;
         size_t count;
         int flags;
         umode_t mode;
     }* temp_info = bpf_map_lookup_elem(&temp_storage, &pid);
     
     if (!temp_info) {
         return -1;
     }
     
     if (fd) *fd = temp_info->fd;
     if (buffer_addr) *buffer_addr = temp_info->buffer_addr;
     if (count) *count = temp_info->count;
     if (flags) *flags = temp_info->flags;
     if (mode) *mode = temp_info->mode;
     
     if (filepath) {
         bpf_probe_read_kernel_str(filepath, MAX_PATH_LEN, temp_info->filepath);
     }
     
     return 0;
 }
 
 /**
  * @brief 清理临时信息
  * @param pid 进程ID
  * @return int 成功返回0，失败返回负数
  */
 static inline int clear_temp_info(__u32 pid) {
     return bpf_map_delete_elem(&temp_storage, &pid);
 }
 
 /**
  * @brief 清理进程相关的所有文件描述符
  * @param pid 进程ID
  * @return int 清理的文件描述符数量
  */
 static inline int cleanup_process_files(__u32 pid) {
     int count = 0;
     fd_key_t key = {};
     file_info_t* info;
     
     // 遍历所有文件描述符（这里简化处理）
     for (int fd = 0; fd < 1024; fd++) {
         key.fd = fd;
         key.pid = pid;
         
         info = bpf_map_lookup_elem(&fd_map, &key);
         if (info) {
             bpf_map_delete_elem(&fd_map, &key);
             count++;
         }
     }
     
     return count;
 }
 
 /**
  * @brief 获取映射表大小
  * @return int 映射表中条目数量
  */
 static inline int get_map_size(void) {
     // BPF 不支持直接获取映射大小，这里返回估计值
     return 0;
 }
 
 /**
  * @brief 检查映射表是否需要清理
  * @return int 1表示需要清理，0表示不需要
  */
 static inline int should_cleanup_map(void) {
     // 根据某些条件判断是否需要清理映射表
     // 例如：映射表条目过多、内存使用过高等
     return 0;
 }
 
 /**
  * @brief 执行映射表清理
  * @return int 清理的条目数量
  */
 static inline int cleanup_map(void) {
     int count = 0;
     
     // 清理过期的条目
     // 这里可以实现基于时间的清理策略
     
     return count;
 }