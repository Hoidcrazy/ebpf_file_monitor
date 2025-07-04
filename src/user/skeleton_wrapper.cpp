/**
 * @file skeleton_wrapper.cpp
 * @brief eBPF skeleton 加载器封装实现
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件提供了 eBPF skeleton 的封装接口，用于简化 eBPF 程序的加载和管理
 */

 #include "bpf_loader.h"
 #include <bpf/bpf.h>
 #include <bpf/libbpf.h>
 #include <sys/resource.h>
 #include <unistd.h>
 #include <signal.h>
 
 // 全局变量用于信号处理
 static BpfLoader* g_signal_loader = nullptr;
 
 /**
  * @brief 信号处理函数
  * @param signum 信号编号
  */
 static void signal_handler_wrapper(int signum) {
     if (g_signal_loader) {
         switch (signum) {
             case SIGINT:
             case SIGTERM:
                 g_signal_loader->stop_monitoring();
                 break;
             default:
                 break;
         }
     }
 }
 
 /**
  * @brief 安装信号处理程序
  * @param loader BPF 加载器实例
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int install_signal_handlers(BpfLoader* loader) {
     if (!loader) {
         ERROR_PRINT("BPF 加载器实例为空");
         return ERROR_INVALID_PARAM;
     }
     
     g_signal_loader = loader;
     
     // 安装信号处理程序
     struct sigaction sa;
     sa.sa_handler = signal_handler_wrapper;
     sigemptyset(&sa.sa_mask);
     sa.sa_flags = SA_RESTART;
     
     if (sigaction(SIGINT, &sa, nullptr) == -1) {
         ERROR_PRINT("安装 SIGINT 信号处理程序失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     if (sigaction(SIGTERM, &sa, nullptr) == -1) {
         ERROR_PRINT("安装 SIGTERM 信号处理程序失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief libbpf 日志回调函数
  * @param level 日志级别
  * @param format 格式化字符串
  * @param args 参数列表
  * @return int 返回值
  */
 static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
     // 根据级别选择输出方式
     switch (level) {
         case LIBBPF_DEBUG:
             // 调试信息通常不输出，避免过多日志
             return 0;
             
         case LIBBPF_INFO:
             printf("[LIBBPF INFO] ");
             break;
             
         case LIBBPF_WARN:
             printf("[LIBBPF WARN] ");
             break;
             
         default:
             printf("[LIBBPF] ");
             break;
     }
     
     return vprintf(format, args);
 }
 
 /**
  * @brief 初始化 libbpf 环境
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int initialize_libbpf_environment() {
     // 设置 libbpf 日志回调
     libbpf_set_print(libbpf_print_fn);
     
     // 设置严格模式（可选）
     libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
     
     INFO_PRINT("libbpf 环境初始化完成");
     return SUCCESS;
 }
 
 /**
  * @brief 检查 BPF 系统调用支持
  * @return bool 是否支持
  */
 bool check_bpf_syscall_support() {
     // 尝试创建一个简单的 BPF 映射来测试支持
     int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 1, 0);
     
     if (map_fd >= 0) {
         close(map_fd);
         return true;
     }
     
     return false;
 }
 
 /**
  * @brief 提升进程内存锁定限制
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int increase_memlock_limit() {
     struct rlimit rlim_new = {
         .rlim_cur = RLIM_INFINITY,
         .rlim_max = RLIM_INFINITY,
     };
     
     if (setrlimit(RLIMIT_MEMLOCK, &rlim_new) != 0) {
         ERROR_PRINT("设置内存锁定限制失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     INFO_PRINT("内存锁定限制已设置为无限制");
     return SUCCESS;
 }
 
 /**
  * @brief 检查内核模块加载权限
  * @return bool 是否有权限
  */
 bool check_module_load_permission() {
     // 检查是否有加载内核模块的权限
     // 这通常需要 CAP_SYS_MODULE 权限
     
     // 尝试读取 /proc/modules 来检查权限
     FILE* modules_file = fopen("/proc/modules", "r");
     if (!modules_file) {
         return false;
     }
     
     fclose(modules_file);
     return true;
 }
 
 /**
  * @brief 获取 BPF 程序类型字符串
  * @param prog_type 程序类型
  * @return const char* 类型字符串
  */
 const char* get_bpf_prog_type_string(enum bpf_prog_type prog_type) {
     switch (prog_type) {
         case BPF_PROG_TYPE_SOCKET_FILTER: return "SOCKET_FILTER";
         case BPF_PROG_TYPE_KPROBE: return "KPROBE";
         case BPF_PROG_TYPE_SCHED_CLS: return "SCHED_CLS";
         case BPF_PROG_TYPE_SCHED_ACT: return "SCHED_ACT";
         case BPF_PROG_TYPE_TRACEPOINT: return "TRACEPOINT";
         case BPF_PROG_TYPE_XDP: return "XDP";
         case BPF_PROG_TYPE_PERF_EVENT: return "PERF_EVENT";
         case BPF_PROG_TYPE_CGROUP_SKB: return "CGROUP_SKB";
         case BPF_PROG_TYPE_CGROUP_SOCK: return "CGROUP_SOCK";
         case BPF_PROG_TYPE_LWT_IN: return "LWT_IN";
         case BPF_PROG_TYPE_LWT_OUT: return "LWT_OUT";
         case BPF_PROG_TYPE_LWT_XMIT: return "LWT_XMIT";
         case BPF_PROG_TYPE_SOCK_OPS: return "SOCK_OPS";
         case BPF_PROG_TYPE_SK_SKB: return "SK_SKB";
         case BPF_PROG_TYPE_CGROUP_DEVICE: return "CGROUP_DEVICE";
         case BPF_PROG_TYPE_SK_MSG: return "SK_MSG";
         case BPF_PROG_TYPE_RAW_TRACEPOINT: return "RAW_TRACEPOINT";
         case BPF_PROG_TYPE_CGROUP_SOCK_ADDR: return "CGROUP_SOCK_ADDR";
         case BPF_PROG_TYPE_LWT_SEG6LOCAL: return "LWT_SEG6LOCAL";
         case BPF_PROG_TYPE_LIRC_MODE2: return "LIRC_MODE2";
         case BPF_PROG_TYPE_SK_REUSEPORT: return "SK_REUSEPORT";
         case BPF_PROG_TYPE_FLOW_DISSECTOR: return "FLOW_DISSECTOR";
         case BPF_PROG_TYPE_CGROUP_SYSCTL: return "CGROUP_SYSCTL";
         case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: return "RAW_TRACEPOINT_WRITABLE";
         case BPF_PROG_TYPE_CGROUP_SOCKOPT: return "CGROUP_SOCKOPT";
         case BPF_PROG_TYPE_TRACING: return "TRACING";
         case BPF_PROG_TYPE_STRUCT_OPS: return "STRUCT_OPS";
         case BPF_PROG_TYPE_EXT: return "EXT";
         case BPF_PROG_TYPE_LSM: return "LSM";
         case BPF_PROG_TYPE_SK_LOOKUP: return "SK_LOOKUP";
         case BPF_PROG_TYPE_SYSCALL: return "SYSCALL";
         default: return "UNKNOWN";
     }
 }
 
 /**
  * @brief 获取 BPF 映射类型字符串
  * @param map_type 映射类型
  * @return const char* 类型字符串
  */
 const char* get_bpf_map_type_string(enum bpf_map_type map_type) {
     switch (map_type) {
         case BPF_MAP_TYPE_UNSPEC: return "UNSPEC";
         case BPF_MAP_TYPE_HASH: return "HASH";
         case BPF_MAP_TYPE_ARRAY: return "ARRAY";
         case BPF_MAP_TYPE_PROG_ARRAY: return "PROG_ARRAY";
         case BPF_MAP_TYPE_PERF_EVENT_ARRAY: return "PERF_EVENT_ARRAY";
         case BPF_MAP_TYPE_PERCPU_HASH: return "PERCPU_HASH";
         case BPF_MAP_TYPE_PERCPU_ARRAY: return "PERCPU_ARRAY";
         case BPF_MAP_TYPE_STACK_TRACE: return "STACK_TRACE";
         case BPF_MAP_TYPE_CGROUP_ARRAY: return "CGROUP_ARRAY";
         case BPF_MAP_TYPE_LRU_HASH: return "LRU_HASH";
         case BPF_MAP_TYPE_LRU_PERCPU_HASH: return "LRU_PERCPU_HASH";
         case BPF_MAP_TYPE_LPM_TRIE: return "LPM_TRIE";
         case BPF_MAP_TYPE_ARRAY_OF_MAPS: return "ARRAY_OF_MAPS";
         case BPF_MAP_TYPE_HASH_OF_MAPS: return "HASH_OF_MAPS";
         case BPF_MAP_TYPE_DEVMAP: return "DEVMAP";
         case BPF_MAP_TYPE_SOCKMAP: return "SOCKMAP";
         case BPF_MAP_TYPE_CPUMAP: return "CPUMAP";
         case BPF_MAP_TYPE_XSKMAP: return "XSKMAP";
         case BPF_MAP_TYPE_SOCKHASH: return "SOCKHASH";
         case BPF_MAP_TYPE_CGROUP_STORAGE: return "CGROUP_STORAGE";
         case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: return "REUSEPORT_SOCKARRAY";
         case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: return "PERCPU_CGROUP_STORAGE";
         case BPF_MAP_TYPE_QUEUE: return "QUEUE";
         case BPF_MAP_TYPE_STACK: return "STACK";
         case BPF_MAP_TYPE_SK_STORAGE: return "SK_STORAGE";
         case BPF_MAP_TYPE_DEVMAP_HASH: return "DEVMAP_HASH";
         case BPF_MAP_TYPE_STRUCT_OPS: return "STRUCT_OPS";
         case BPF_MAP_TYPE_RINGBUF: return "RINGBUF";
         case BPF_MAP_TYPE_INODE_STORAGE: return "INODE_STORAGE";
         case BPF_MAP_TYPE_TASK_STORAGE: return "TASK_STORAGE";
         case BPF_MAP_TYPE_BLOOM_FILTER: return "BLOOM_FILTER";
         default: return "UNKNOWN";
     }
 }
 
 /**
  * @brief 打印 BPF 对象信息
  * @param obj BPF 对象
  */
 void print_bpf_object_info(struct bpf_object* obj) {
     if (!obj) {
         ERROR_PRINT("BPF 对象为空");
         return;
     }
     
     const char* obj_name = bpf_object__name(obj);
     INFO_PRINT("BPF 对象信息:");
     INFO_PRINT("  名称: %s", obj_name ? obj_name : "未知");
     
     // 打印程序信息
     struct bpf_program* prog;
     int prog_count = 0;
     
     INFO_PRINT("  程序列表:");
     bpf_object__for_each_program(prog, obj) {
         const char* prog_name = bpf_program__name(prog);
         enum bpf_prog_type prog_type = bpf_program__type(prog);
         
         INFO_PRINT("    [%d] %s (类型: %s)", prog_count++, 
                    prog_name ? prog_name : "未知",
                    get_bpf_prog_type_string(prog_type));
     }
     
     // 打印映射信息
     struct bpf_map* map;
     int map_count = 0;
     
     INFO_PRINT("  映射列表:");
     bpf_object__for_each_map(map, obj) {
         const char* map_name = bpf_map__name(map);
         enum bpf_map_type map_type = bpf_map__type(map);
         __u32 key_size = bpf_map__key_size(map);
         __u32 value_size = bpf_map__value_size(map);
         __u32 max_entries = bpf_map__max_entries(map);
         
         INFO_PRINT("    [%d] %s (类型: %s, 键大小: %u, 值大小: %u, 最大条目: %u)", 
                    map_count++, map_name ? map_name : "未知",
                    get_bpf_map_type_string(map_type),
                    key_size, value_size, max_entries);
     }
     
     INFO_PRINT("  总计: %d 个程序, %d 个映射", prog_count, map_count);
 }
 
 /**
  * @brief 验证 BPF 对象完整性
  * @param obj BPF 对象
  * @return bool 是否完整
  */
 bool verify_bpf_object_integrity(struct bpf_object* obj) {
     if (!obj) {
         ERROR_PRINT("BPF 对象为空");
         return false;
     }
     
     // 检查是否有程序
     struct bpf_program* prog;
     int prog_count = 0;
     
     bpf_object__for_each_program(prog, obj) {
         prog_count++;
         
         // 检查程序是否有效
         if (!bpf_program__name(prog)) {
             ERROR_PRINT("发现无效的 BPF 程序");
             return false;
         }
     }
     
     if (prog_count == 0) {
         ERROR_PRINT("BPF 对象中没有程序");
         return false;
     }
     
     // 检查是否有映射
     struct bpf_map* map;
     int map_count = 0;
     
     bpf_object__for_each_map(map, obj) {
         map_count++;
         
         // 检查映射是否有效
         if (!bpf_map__name(map)) {
             ERROR_PRINT("发现无效的 BPF 映射");
             return false;
         }
     }
     
     INFO_PRINT("BPF 对象完整性验证通过: %d 个程序, %d 个映射", prog_count, map_count);
     return true;
 }
 
 /**
  * @brief 获取系统 BPF 功能信息
  * @param buffer 输出缓冲区
  * @param size 缓冲区大小
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int get_bpf_system_info(char* buffer, size_t size) {
     if (!buffer || size == 0) {
         return ERROR_INVALID_PARAM;
     }
     
     std::stringstream ss;
     
     // 内核版本
     struct kernel_version version;
     if (get_kernel_version(&version) == SUCCESS) {
         ss << "内核版本: " << version.major << "." << version.minor << "." << version.patch << "\n";
     }
     
     // Ring buffer 支持
     ss << "Ring Buffer 支持: " << (supports_ring_buffer() ? "是" : "否") << "\n";
     
     // BPF 系统调用支持
     ss << "BPF 系统调用支持: " << (check_bpf_syscall_support() ? "是" : "否") << "\n";
     
     // 内存锁定限制
     struct rlimit rlim;
     if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0) {
         if (rlim.rlim_cur == RLIM_INFINITY) {
             ss << "内存锁定限制: 无限制\n";
         } else {
             ss << "内存锁定限制: " << rlim.rlim_cur << " 字节\n";
         }
     }
     
     // 权限检查
     ss << "所需权限: " << (check_required_permissions() ? "满足" : "不满足") << "\n";
     
     std::string info = ss.str();
     SAFE_STRCPY(buffer, info.c_str(), size);
     
     return SUCCESS;
 }