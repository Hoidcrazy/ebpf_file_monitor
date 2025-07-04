/**
 * @file main.cpp
 * @brief 主程序入口 - ebpf_file_monitor 用户态程序
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件是 eBPF 文件监控系统的主程序入口，负责初始化系统、
 * 加载 eBPF 程序、处理事件并实现数据欺骗功能
 */

 #include <iostream>
 #include <csignal>
 #include <unistd.h>
 #include <getopt.h>
 #include <sys/resource.h>
 #include <sys/capability.h>
 
 #include "common.h"
 #include "logger.h"
 #include "bpf_loader.h"
 #include "event_structs.h"
 
 // 全局变量
 logger_handle_t* g_logger = nullptr;
 BpfLoader* g_bpf_loader = nullptr;
 std::atomic<bool> g_should_exit{false};
 
 /**
  * @brief 信号处理函数
  * @param signum 信号编号
  */
 void signal_handler(int signum) {
     switch (signum) {
         case SIGINT:
         case SIGTERM:
             INFO_PRINT("收到终止信号 %d，正在关闭程序...", signum);
             g_should_exit.store(true);
             if (g_bpf_loader) {
                 g_bpf_loader->stop_monitoring();
             }
             break;
         case SIGUSR1:
             INFO_PRINT("收到用户信号 1，打印统计信息...");
             if (g_bpf_loader) {
                 event_stats_t stats = g_bpf_loader->get_event_stats();
                 INFO_PRINT("=== 事件统计信息 ===");
                 INFO_PRINT("总事件数: %lu", stats.total_events);
                 INFO_PRINT("打开事件: %lu", stats.open_events);
                 INFO_PRINT("读取事件: %lu", stats.read_events);
                 INFO_PRINT("写入事件: %lu", stats.write_events);
                 INFO_PRINT("关闭事件: %lu", stats.close_events);
                 INFO_PRINT("修改的txt文件: %lu", stats.txt_files_modified);
                 INFO_PRINT("数据欺骗字节数: %lu", stats.data_spoofed_bytes);
             }
             break;
         case SIGUSR2:
             INFO_PRINT("收到用户信号 2，重置统计信息...");
             if (g_bpf_loader) {
                 g_bpf_loader->reset_event_stats();
             }
             break;
         default:
             WARN_PRINT("收到未处理的信号: %d", signum);
             break;
     }
 }
 
 /**
  * @brief 检查运行权限
  * @return bool 是否有足够权限
  */
 bool check_permissions() {
     // 检查是否以 root 身份运行
     if (geteuid() != 0) {
         ERROR_PRINT("程序需要以 root 权限运行");
         return false;
     }
     
     // 检查是否支持 eBPF
     if (!check_ebpf_support()) {
         ERROR_PRINT("当前内核不支持 eBPF 功能");
         return false;
     }
     
     // 检查必要的权限
     if (!check_required_permissions()) {
         ERROR_PRINT("缺少必要的系统权限");
         return false;
     }
     
     return true;
 }
 
 /**
  * @brief 提升资源限制
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int increase_rlimit() {
     struct rlimit rlim_new = {
         .rlim_cur = RLIM_INFINITY,
         .rlim_max = RLIM_INFINITY,
     };
     
     if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
         ERROR_PRINT("设置内存锁定限制失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     INFO_PRINT("已设置内存锁定限制为无限制");
     return SUCCESS;
 }
 
 /**
  * @brief 初始化日志系统
  * @param log_file 日志文件路径
  * @param log_level 日志级别
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int init_logging(const char* log_file, log_level_t log_level) {
     log_config_t config = logger_create_default_config();
     
     // 设置日志级别
     config.min_level = log_level;
     
     // 设置输出目标
     config.target = LOG_TARGET_BOTH;
     config.enable_timestamp = 1;
     config.enable_colors = 1;
     config.auto_flush = 1;
     
     // 设置日志文件路径
     if (log_file) {
         SAFE_STRCPY(config.log_file_path, log_file, sizeof(config.log_file_path));
     } else {
         // 使用默认路径
         SAFE_STRCPY(config.log_file_path, "tests/log/ebpf_monitor.log", 
                    sizeof(config.log_file_path));
     }
     
     // 创建日志目录
     if (create_directory("tests/log") != SUCCESS) {
         ERROR_PRINT("创建日志目录失败");
         return ERROR_GENERIC;
     }
     
     g_logger = logger_init(&config);
     if (!g_logger) {
         ERROR_PRINT("初始化日志系统失败");
         return ERROR_GENERIC;
     }
     
     LOG_INFO("日志系统初始化成功，输出到: %s", config.log_file_path);
     return SUCCESS;
 }
 
 /**
  * @brief 事件处理回调函数
  * @param event 文件事件
  */
 void event_callback(const file_event_t& event) {
     char time_str[64];
     char size_str[32];
     
     format_timestamp(event.base.timestamp, time_str, sizeof(time_str));
     
     switch (event.base.op_type) {
         case FILE_OP_OPEN:
             LOG_INFO("[%s] 进程 %s[%d] 打开文件: %s (fd=%d, flags=0x%x)", 
                     time_str, event.base.comm, event.base.pid, 
                     event.base.filepath, event.base.fd, event.open.flags);
             break;
             
         case FILE_OP_READ:
             format_file_size(event.read.bytes_read, size_str, sizeof(size_str));
             LOG_INFO("[%s] 进程 %s[%d] 读取文件: %s (fd=%d, 大小=%s)", 
                     time_str, event.base.comm, event.base.pid, 
                     event.base.filepath, event.base.fd, size_str);
             
             // 如果是 txt 文件，记录数据欺骗信息
             if (is_txt_file(event.base.filepath)) {
                 LOG_WARN("[数据欺骗] 检测到txt文件读取，将修改缓冲区内容: %s", 
                         get_filename(event.base.filepath));
             }
             break;
             
         case FILE_OP_WRITE:
             format_file_size(event.write.bytes_written, size_str, sizeof(size_str));
             LOG_INFO("[%s] 进程 %s[%d] 写入文件: %s (fd=%d, 大小=%s)", 
                     time_str, event.base.comm, event.base.pid, 
                     event.base.filepath, event.base.fd, size_str);
             break;
             
         case FILE_OP_CLOSE:
             LOG_INFO("[%s] 进程 %s[%d] 关闭文件: %s (fd=%d)", 
                     time_str, event.base.comm, event.base.pid, 
                     event.base.filepath, event.base.fd);
             break;
             
         default:
             LOG_WARN("[%s] 未知操作类型: %d", time_str, event.base.op_type);
             break;
     }
 }
 
 /**
  * @brief 打印帮助信息
  * @param program_name 程序名称
  */
 void print_help(const char* program_name) {
     printf("用法: %s [选项]\n", program_name);
     printf("\n基于 eBPF 的文件操作生命周期追踪与数据欺骗系统\n");
     printf("\n选项:\n");
     printf("  -h, --help              显示此帮助信息\n");
     printf("  -v, --version           显示版本信息\n");
     printf("  -l, --log-file <文件>   指定日志文件路径 (默认: tests/log/ebpf_monitor.log)\n");
     printf("  -L, --log-level <级别>  设置日志级别 (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=FATAL)\n");
     printf("  -d, --disable-spoofing  禁用数据欺骗功能\n");
     printf("  -s, --show-stats        定期显示统计信息\n");
     printf("  -i, --interval <秒>     统计信息显示间隔 (默认: 30秒)\n");
     printf("\n信号处理:\n");
     printf("  SIGINT/SIGTERM          优雅关闭程序\n");
     printf("  SIGUSR1                 打印当前统计信息\n");
     printf("  SIGUSR2                 重置统计信息\n");
     printf("\n示例:\n");
     printf("  %s                                    # 使用默认设置运行\n", program_name);
     printf("  %s -l /var/log/ebpf.log -L 1         # 指定日志文件和级别\n", program_name);
     printf("  %s -d                                 # 禁用数据欺骗\n", program_name);
     printf("  %s -s -i 10                          # 每10秒显示统计信息\n", program_name);
     printf("\n注意: 程序需要以 root 权限运行\n");
 }
 
 /**
  * @brief 打印版本信息
  */
 void print_version() {
     printf("ebpf_file_monitor v1.0.0\n");
     printf("基于 eBPF 的文件操作生命周期追踪与数据欺骗系统\n");
     printf("构建时间: %s %s\n", __DATE__, __TIME__);
     printf("支持的功能:\n");
     printf("  - 文件操作监控 (open/read/write/close)\n");
     printf("  - 数据欺骗 (.txt 文件)\n");
     printf("  - 生命周期追踪\n");
     printf("  - 统计信息收集\n");
     
     // 显示内核版本信息
     char kernel_version[256];
     if (get_kernel_version_string(kernel_version, sizeof(kernel_version)) == SUCCESS) {
         printf("内核版本: %s\n", kernel_version);
     }
     
     // 显示支持的通信方式
     if (supports_ring_buffer()) {
         printf("通信方式: Ring Buffer (推荐)\n");
     } else {
         printf("通信方式: Perf Buffer (兼容模式)\n");
     }
 }
 
 /**
  * @brief 定期显示统计信息的线程函数
  * @param interval 显示间隔（秒）
  */
 void stats_thread_func(int interval) {
     while (!g_should_exit.load()) {
         sleep(interval);
         
         if (g_should_exit.load()) break;
         
         if (g_bpf_loader && g_bpf_loader->is_running()) {
             event_stats_t stats = g_bpf_loader->get_event_stats();
             
             INFO_PRINT("=== 定期统计信息 ===");
             INFO_PRINT("总事件数: %lu, 打开: %lu, 读取: %lu, 写入: %lu, 关闭: %lu",
                       stats.total_events, stats.open_events, stats.read_events,
                       stats.write_events, stats.close_events);
             INFO_PRINT("txt文件修改: %lu, 数据欺骗字节: %lu",
                       stats.txt_files_modified, stats.data_spoofed_bytes);
         }
     }
 }
 
 /**
  * @brief 主函数
  * @param argc 参数个数
  * @param argv 参数数组
  * @return int 退出码
  */
 int main(int argc, char* argv[]) {
     // 默认配置
     const char* log_file = nullptr;
     log_level_t log_level = LOG_LEVEL_INFO;
     bool disable_spoofing = false;
     bool show_stats = false;
     int stats_interval = 30;
     
     // 解析命令行参数
     static struct option long_options[] = {
         {"help", no_argument, 0, 'h'},
         {"version", no_argument, 0, 'v'},
         {"log-file", required_argument, 0, 'l'},
         {"log-level", required_argument, 0, 'L'},
         {"disable-spoofing", no_argument, 0, 'd'},
         {"show-stats", no_argument, 0, 's'},
         {"interval", required_argument, 0, 'i'},
         {0, 0, 0, 0}
     };
     
     int option_index = 0;
     int c;
     
     while ((c = getopt_long(argc, argv, "hvl:L:dsi:", long_options, &option_index)) != -1) {
         switch (c) {
             case 'h':
                 print_help(argv[0]);
                 return 0;
                 
             case 'v':
                 print_version();
                 return 0;
                 
             case 'l':
                 log_file = optarg;
                 break;
                 
             case 'L':
                 log_level = static_cast<log_level_t>(atoi(optarg));
                 if (log_level < LOG_LEVEL_DEBUG || log_level > LOG_LEVEL_FATAL) {
                     ERROR_PRINT("无效的日志级别: %s", optarg);
                     return 1;
                 }
                 break;
                 
             case 'd':
                 disable_spoofing = true;
                 break;
                 
             case 's':
                 show_stats = true;
                 break;
                 
             case 'i':
                 stats_interval = atoi(optarg);
                 if (stats_interval <= 0) {
                     ERROR_PRINT("无效的统计间隔: %s", optarg);
                     return 1;
                 }
                 break;
                 
             case '?':
             default:
                 ERROR_PRINT("无效的选项，使用 -h 查看帮助");
                 return 1;
         }
     }
     
     // 打印启动信息
     INFO_PRINT("=== eBPF 文件监控系统启动 ===");
     INFO_PRINT("程序版本: 1.0.0");
     INFO_PRINT("PID: %d", getpid());
     
     // 检查权限
     if (!check_permissions()) {
         ERROR_PRINT("权限检查失败，请以 root 权限运行");
         return 1;
     }
     
     // 提升资源限制
     if (increase_rlimit() != SUCCESS) {
         ERROR_PRINT("提升资源限制失败");
         return 1;
     }
     
     // 初始化日志系统
     if (init_logging(log_file, log_level) != SUCCESS) {
         ERROR_PRINT("日志系统初始化失败");
         return 1;
     }
     
     // 注册信号处理程序
     signal(SIGINT, signal_handler);
     signal(SIGTERM, signal_handler);
     signal(SIGUSR1, signal_handler);
     signal(SIGUSR2, signal_handler);
     
     // 创建 BPF 加载器
     g_bpf_loader = new BpfLoader(g_logger);
     if (!g_bpf_loader) {
         LOG_ERROR("创建 BPF 加载器失败");
         return 1;
     }
     
     // 设置配置
     g_bpf_loader->set_data_spoofing_enabled(!disable_spoofing);
     g_bpf_loader->set_event_callback(event_callback);
     
     LOG_INFO("数据欺骗功能: %s", disable_spoofing ? "禁用" : "启用");
     LOG_INFO("统计信息显示: %s", show_stats ? "启用" : "禁用");
     if (show_stats) {
         LOG_INFO("统计显示间隔: %d 秒", stats_interval);
     }
     
     // 加载 eBPF 程序
     LOG_INFO("正在加载 eBPF 程序...");
     if (g_bpf_loader->load_bpf_program("src/ebpf/file_monitor.bpf.o") != SUCCESS) {
         LOG_ERROR("加载 eBPF 程序失败");
         delete g_bpf_loader;
         logger_destroy(g_logger);
         return 1;
     }
     
     // 启动监控
     LOG_INFO("正在启动文件监控...");
     if (g_bpf_loader->start_monitoring() != SUCCESS) {
         LOG_ERROR("启动文件监控失败");
         g_bpf_loader->unload_bpf_program();
         delete g_bpf_loader;
         logger_destroy(g_logger);
         return 1;
     }
     
     LOG_INFO("文件监控已启动，按 Ctrl+C 停止程序");
     
     // 启动统计信息显示线程
     std::thread stats_thread;
     if (show_stats) {
         stats_thread = std::thread(stats_thread_func, stats_interval);
     }
     
     // 主循环
     while (!g_should_exit.load()) {
         sleep(1);
         
         // 检查 BPF 加载器状态
         if (!g_bpf_loader->is_running()) {
             LOG_ERROR("BPF 加载器意外停止");
             break;
         }
     }
     
     // 清理资源
     LOG_INFO("正在关闭程序...");
     
     if (stats_thread.joinable()) {
         stats_thread.join();
     }
     
     // 打印最终统计信息
     if (g_bpf_loader->is_running()) {
         event_stats_t final_stats = g_bpf_loader->get_event_stats();
         LOG_INFO("=== 最终统计信息 ===");
         LOG_INFO("总事件数: %lu", final_stats.total_events);
         LOG_INFO("打开事件: %lu", final_stats.open_events);
         LOG_INFO("读取事件: %lu", final_stats.read_events);
         LOG_INFO("写入事件: %lu", final_stats.write_events);
         LOG_INFO("关闭事件: %lu", final_stats.close_events);
         LOG_INFO("修改的txt文件: %lu", final_stats.txt_files_modified);
         LOG_INFO("数据欺骗字节数: %lu", final_stats.data_spoofed_bytes);
     }
     
     g_bpf_loader->stop_monitoring();
     g_bpf_loader->unload_bpf_program();
     delete g_bpf_loader;
     g_bpf_loader = nullptr;
     
     logger_destroy(g_logger);
     g_logger = nullptr;
     
     LOG_INFO("程序已正常退出");
     return 0;
 }