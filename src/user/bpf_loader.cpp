/**
 * @file bpf_loader.cpp
 * @brief BPF 加载器实现 - 负责加载eBPF程序、事件处理和数据欺骗
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件实现了 BPF 加载器的核心功能，包括 eBPF 程序加载、
 * 事件处理、通信机制选择、数据欺骗等功能
 */

 #include "bpf_loader.h"
 #include <bpf/bpf.h>
 #include <bpf/libbpf.h>
 #include <sys/resource.h>
 #include <sys/utsname.h>
 #include <sys/capability.h>
 #include <fcntl.h>
 #include <sys/stat.h>
 #include <sys/ptrace.h>
 #include <sys/wait.h>
 #include <chrono>
 #include <algorithm>
 #include <fstream>
 #include <sstream>
 
 /**
  * @brief 构造函数
  * @param logger 日志句柄
  */
 BpfLoader::BpfLoader(logger_handle_t* logger) 
     : m_logger(logger), m_bpf_obj(nullptr), m_fd_map(nullptr), 
       m_events_map(nullptr), m_ring_buf(nullptr), m_perf_buf(nullptr),
       m_is_running(false), m_should_stop(false), m_data_spoofing_enabled(true),
       m_use_ring_buffer(false) {
     
     // 初始化事件统计
     memset(&m_event_stats, 0, sizeof(m_event_stats));
     
     // 检查是否支持 ring buffer
     m_use_ring_buffer = supports_ring_buffer();
     
     if (m_logger) {
         if (m_use_ring_buffer) {
             logger_info(m_logger, "BPF 加载器初始化 - 使用 Ring Buffer 通信");
         } else {
             logger_info(m_logger, "BPF 加载器初始化 - 使用 Perf Buffer 通信");
         }
     }
 }
 
 /**
  * @brief 析构函数
  */
 BpfLoader::~BpfLoader() {
     if (m_is_running.load()) {
         stop_monitoring();
     }
     
     if (m_bpf_obj) {
         unload_bpf_program();
     }
     
     if (m_logger) {
         logger_info(m_logger, "BPF 加载器已销毁");
     }
 }
 
 /**
  * @brief 检查是否具有必要的权限
  * @return bool 是否具有权限
  */
 bool check_required_permissions() {
     // 检查是否为 root 用户
     if (geteuid() != 0) {
         return false;
     }
     
     // 检查是否有 CAP_SYS_ADMIN 权限
     cap_t caps = cap_get_proc();
     if (caps == nullptr) {
         return false;
     }
     
     cap_flag_value_t cap_val;
     if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_val) != 0) {
         cap_free(caps);
         return false;
     }
     
     cap_free(caps);
     return (cap_val == CAP_SET);
 }
 
 /**
  * @brief 检查内核是否支持 eBPF
  * @return bool 是否支持
  */
 bool check_ebpf_support() {
     // 检查 /sys/kernel/security/bpf 目录是否存在
     struct stat st;
     if (stat("/sys/kernel/security/bpf", &st) != 0) {
         return false;
     }
     
     // 尝试创建一个简单的 BPF 程序来测试支持
     struct bpf_insn insns[] = {
         BPF_MOV64_IMM(BPF_REG_0, 0),
         BPF_EXIT_INSN(),
     };
     
     int prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, insns, 
                                    sizeof(insns) / sizeof(insns[0]), 
                                    "GPL", 0, nullptr, 0);
     
     if (prog_fd >= 0) {
         close(prog_fd);
         return true;
     }
     
     return false;
 }
 
 /**
  * @brief 获取内核版本字符串
  * @param buffer 输出缓冲区
  * @param size 缓冲区大小
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int get_kernel_version_string(char* buffer, size_t size) {
     if (!buffer || size == 0) {
         return ERROR_INVALID_PARAM;
     }
     
     struct utsname uts;
     if (uname(&uts) != 0) {
         return ERROR_GENERIC;
     }
     
     snprintf(buffer, size, "%s %s", uts.sysname, uts.release);
     return SUCCESS;
 }
 
 /**
  * @brief 加载 eBPF 程序
  * @param obj_file eBPF 对象文件路径
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::load_bpf_program(const char* obj_file) {
     if (!obj_file) {
         ERROR_PRINT("eBPF 对象文件路径为空");
         return ERROR_INVALID_PARAM;
     }
     
     if (m_bpf_obj) {
         ERROR_PRINT("eBPF 程序已加载");
         return ERROR_GENERIC;
     }
     
     // 检查文件是否存在
     if (!file_exists(obj_file)) {
         ERROR_PRINT("eBPF 对象文件不存在: %s", obj_file);
         return ERROR_FILE_NOT_FOUND;
     }
     
     if (m_logger) {
         logger_info(m_logger, "开始加载 eBPF 程序: %s", obj_file);
     }
     
     // 打开 BPF 对象文件
     m_bpf_obj = bpf_object__open(obj_file);
     if (libbpf_get_error(m_bpf_obj)) {
         ERROR_PRINT("打开 eBPF 对象文件失败: %s", obj_file);
         return ERROR_GENERIC;
     }
     
     // 加载 BPF 程序
     int ret = bpf_object__load(m_bpf_obj);
     if (ret != 0) {
         ERROR_PRINT("加载 eBPF 程序失败: %s", strerror(-ret));
         bpf_object__close(m_bpf_obj);
         m_bpf_obj = nullptr;
         return ERROR_GENERIC;
     }
     
     // 初始化 BPF 映射
     if (init_bpf_maps() != SUCCESS) {
         ERROR_PRINT("初始化 BPF 映射失败");
         bpf_object__close(m_bpf_obj);
         m_bpf_obj = nullptr;
         return ERROR_GENERIC;
     }
     
     // 附加所有程序
     struct bpf_program* prog;
     bpf_object__for_each_program(prog, m_bpf_obj) {
         struct bpf_link* link = bpf_program__attach(prog);
         if (libbpf_get_error(link)) {
             ERROR_PRINT("附加 BPF 程序失败: %s", bpf_program__name(prog));
             bpf_object__close(m_bpf_obj);
             m_bpf_obj = nullptr;
             return ERROR_GENERIC;
         }
         
         if (m_logger) {
             logger_debug(m_logger, "已附加 BPF 程序: %s", bpf_program__name(prog));
         }
     }
     
     // 初始化通信缓冲区
     if (init_communication_buffer() != SUCCESS) {
         ERROR_PRINT("初始化通信缓冲区失败");
         bpf_object__close(m_bpf_obj);
         m_bpf_obj = nullptr;
         return ERROR_GENERIC;
     }
     
     if (m_logger) {
         logger_info(m_logger, "eBPF 程序加载成功");
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 卸载 eBPF 程序
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::unload_bpf_program() {
     if (!m_bpf_obj) {
         return SUCCESS;
     }
     
     if (m_logger) {
         logger_info(m_logger, "正在卸载 eBPF 程序");
     }
     
     // 清理通信缓冲区
     if (m_ring_buf) {
         ring_buffer__free(m_ring_buf);
         m_ring_buf = nullptr;
     }
     
     if (m_perf_buf) {
         perf_buffer__free(m_perf_buf);
         m_perf_buf = nullptr;
     }
     
     // 关闭 BPF 对象
     bpf_object__close(m_bpf_obj);
     m_bpf_obj = nullptr;
     m_fd_map = nullptr;
     m_events_map = nullptr;
     
     if (m_logger) {
         logger_info(m_logger, "eBPF 程序卸载完成");
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 初始化 BPF 映射
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::init_bpf_maps() {
     if (!m_bpf_obj) {
         ERROR_PRINT("BPF 对象未加载");
         return ERROR_GENERIC;
     }
     
     // 查找 fd 映射表
     m_fd_map = bpf_object__find_map_by_name(m_bpf_obj, "fd_map");
     if (!m_fd_map) {
         ERROR_PRINT("未找到 fd_map 映射");
         return ERROR_GENERIC;
     }
     
     // 查找事件映射表
     m_events_map = bpf_object__find_map_by_name(m_bpf_obj, "events");
     if (!m_events_map) {
         ERROR_PRINT("未找到 events 映射");
         return ERROR_GENERIC;
     }
     
     if (m_logger) {
         logger_debug(m_logger, "BPF 映射初始化成功");
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 初始化通信缓冲区
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::init_communication_buffer() {
     if (!m_events_map) {
         ERROR_PRINT("事件映射未初始化");
         return ERROR_GENERIC;
     }
     
     if (m_use_ring_buffer) {
         // 使用 Ring Buffer
         m_ring_buf = ring_buffer__new(bpf_map__fd(m_events_map), 
                                      ring_buffer_callback, this, nullptr);
         if (!m_ring_buf) {
             ERROR_PRINT("创建 Ring Buffer 失败");
             return ERROR_GENERIC;
         }
         
         if (m_logger) {
             logger_info(m_logger, "Ring Buffer 初始化成功");
         }
     } else {
         // 使用 Perf Buffer
         m_perf_buf = perf_buffer__new(bpf_map__fd(m_events_map), 
                                      BPF_PERF_BUFFER_SIZE,
                                      perf_buffer_callback, 
                                      perf_buffer_lost_callback, 
                                      this, nullptr);
         if (!m_perf_buf) {
             ERROR_PRINT("创建 Perf Buffer 失败");
             return ERROR_GENERIC;
         }
         
         if (m_logger) {
             logger_info(m_logger, "Perf Buffer 初始化成功");
         }
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 启动事件监听
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::start_monitoring() {
     if (m_is_running.load()) {
         WARN_PRINT("事件监听已在运行");
         return SUCCESS;
     }
     
     if (!m_bpf_obj) {
         ERROR_PRINT("eBPF 程序未加载");
         return ERROR_GENERIC;
     }
     
     m_should_stop.store(false);
     m_is_running.store(true);
     
     // 启动轮询线程
     m_polling_thread = std::thread(&BpfLoader::polling_thread_func, this);
     
     if (m_logger) {
         logger_info(m_logger, "事件监听已启动");
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 停止事件监听
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::stop_monitoring() {
     if (!m_is_running.load()) {
         return SUCCESS;
     }
     
     if (m_logger) {
         logger_info(m_logger, "正在停止事件监听");
     }
     
     m_should_stop.store(true);
     
     // 等待轮询线程结束
     if (m_polling_thread.joinable()) {
         m_polling_thread.join();
     }
     
     m_is_running.store(false);
     
     if (m_logger) {
         logger_info(m_logger, "事件监听已停止");
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 轮询线程函数
  */
 void BpfLoader::polling_thread_func() {
     if (m_logger) {
         logger_debug(m_logger, "轮询线程已启动");
     }
     
     while (!m_should_stop.load()) {
         int ret;
         
         if (m_use_ring_buffer && m_ring_buf) {
             // 使用 Ring Buffer 轮询
             ret = ring_buffer__poll(m_ring_buf, 100);  // 100ms 超时
         } else if (m_perf_buf) {
             // 使用 Perf Buffer 轮询
             ret = perf_buffer__poll(m_perf_buf, 100);  // 100ms 超时
         } else {
             ERROR_PRINT("通信缓冲区未初始化");
             break;
         }
         
         if (ret < 0 && ret != -EINTR) {
             ERROR_PRINT("轮询事件失败: %s", strerror(-ret));
             break;
         }
     }
     
     if (m_logger) {
         logger_debug(m_logger, "轮询线程已退出");
     }
 }
 
 /**
  * @brief Ring Buffer 回调函数
  * @param ctx 上下文
  * @param data 数据
  * @param data_size 数据大小
  * @return int 返回值
  */
 int BpfLoader::ring_buffer_callback(void* ctx, void* data, size_t data_size) {
     BpfLoader* loader = static_cast<BpfLoader*>(ctx);
     if (loader) {
         loader->handle_event(data, data_size);
     }
     return 0;
 }
 
 /**
  * @brief Perf Buffer 回调函数
  * @param ctx 上下文
  * @param cpu CPU 编号
  * @param data 数据
  * @param data_size 数据大小
  */
 void BpfLoader::perf_buffer_callback(void* ctx, int cpu, void* data, 
                                     unsigned int data_size) {
     (void)cpu;  // 忽略 CPU 参数
     BpfLoader* loader = static_cast<BpfLoader*>(ctx);
     if (loader) {
         loader->handle_event(data, data_size);
     }
 }
 
 /**
  * @brief Perf Buffer 丢失事件回调函数
  * @param ctx 上下文
  * @param cpu CPU 编号
  * @param lost_cnt 丢失计数
  */
 void BpfLoader::perf_buffer_lost_callback(void* ctx, int cpu, unsigned long long lost_cnt) {
     BpfLoader* loader = static_cast<BpfLoader*>(ctx);
     if (loader && loader->m_logger) {
         logger_warn(loader->m_logger, "CPU %d 丢失了 %llu 个事件", cpu, lost_cnt);
     }
 }
 
 /**
  * @brief 处理单个事件
  * @param data 事件数据
  * @param data_size 数据大小
  */
 void BpfLoader::handle_event(const void* data, size_t data_size) {
     if (!data || data_size < sizeof(file_event_base_t)) {
         if (m_logger) {
             logger_warn(m_logger, "收到无效事件数据，大小: %zu", data_size);
         }
         return;
     }
     
     const file_event_t* event = static_cast<const file_event_t*>(data);
     
     // 更新统计信息
     update_event_stats(event->base.op_type);
     
     // 记录事件日志
     log_event(*event);
     
     // 根据事件类型分发处理
     switch (event->base.op_type) {
         case FILE_OP_OPEN:
             handle_open_event(event->open);
             break;
             
         case FILE_OP_READ:
             handle_read_event(event->read);
             break;
             
         case FILE_OP_WRITE:
             handle_write_event(event->write);
             break;
             
         case FILE_OP_CLOSE:
             handle_close_event(event->close);
             break;
             
         default:
             if (m_logger) {
                 logger_warn(m_logger, "未知事件类型: %d", event->base.op_type);
             }
             break;
     }
     
     // 调用用户回调
     {
         std::lock_guard<std::mutex> lock(m_callback_mutex);
         if (m_event_callback) {
             m_event_callback(*event);
         }
     }
 }
 
 /**
  * @brief 处理文件打开事件
  * @param event 打开事件
  */
 void BpfLoader::handle_open_event(const file_open_event_t& event) {
     // 更新 fd 到路径的映射
     m_fd_to_path[event.base.fd] = std::string(event.base.filepath);
     
     if (m_logger) {
         logger_debug(m_logger, "文件打开: %s (fd=%d, pid=%d)", 
                     event.base.filepath, event.base.fd, event.base.pid);
     }
 }
 
 /**
  * @brief 处理文件读取事件
  * @param event 读取事件
  */
 void BpfLoader::handle_read_event(const file_read_event_t& event) {
     // 如果启用了数据欺骗且是 txt 文件，执行数据欺骗
     if (m_data_spoofing_enabled.load() && 
         is_txt_file(event.base.filepath) && 
         event.bytes_read > 0) {
         
         int ret = perform_data_spoofing(event.base.pid, event.buffer_addr, 
                                        event.bytes_read, event.base.filepath);
         if (ret == SUCCESS) {
             // 更新统计信息
             update_event_stats(FILE_OP_READ, strlen(FAKE_CONTENT));
             
             if (m_logger) {
                 logger_info(m_logger, "已对 txt 文件执行数据欺骗: %s", 
                            get_filename(event.base.filepath));
             }
         }
     }
     
     if (m_logger) {
         logger_debug(m_logger, "文件读取: %s (fd=%d, pid=%d, 大小=%zd)", 
                     event.base.filepath, event.base.fd, event.base.pid, 
                     event.bytes_read);
     }
 }
 
 /**
  * @brief 处理文件写入事件
  * @param event 写入事件
  */
 void BpfLoader::handle_write_event(const file_write_event_t& event) {
     if (m_logger) {
         logger_debug(m_logger, "文件写入: %s (fd=%d, pid=%d, 大小=%zd)", 
                     event.base.filepath, event.base.fd, event.base.pid, 
                     event.bytes_written);
     }
 }
 
 /**
  * @brief 处理文件关闭事件
  * @param event 关闭事件
  */
 void BpfLoader::handle_close_event(const file_close_event_t& event) {
     // 从映射中移除 fd
     auto it = m_fd_to_path.find(event.base.fd);
     if (it != m_fd_to_path.end()) {
         m_fd_to_path.erase(it);
     }
     
     if (m_logger) {
         logger_debug(m_logger, "文件关闭: %s (fd=%d, pid=%d)", 
                     event.base.filepath, event.base.fd, event.base.pid);
     }
 }
 
 /**
  * @brief 执行数据欺骗
  * @param pid 目标进程ID
  * @param buffer_addr 缓冲区地址
  * @param original_size 原始大小
  * @param filepath 文件路径
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::perform_data_spoofing(pid_t pid, uint64_t buffer_addr, 
                                     size_t original_size, const char* filepath) {
     // 准备伪造的内容
     const char* fake_content = FAKE_CONTENT;
     size_t fake_size = strlen(fake_content);
     
     // 确保不超过原始缓冲区大小
     size_t write_size = std::min(fake_size, original_size);
     
     // 修改进程内存
     int ret = modify_process_memory(pid, buffer_addr, fake_content, write_size);
     if (ret != SUCCESS) {
         if (m_logger) {
             logger_error(m_logger, "数据欺骗失败: %s (pid=%d)", filepath, pid);
         }
         return ret;
     }
     
     if (m_logger) {
         logger_info(m_logger, "数据欺骗成功: %s (pid=%d, 大小=%zu)", 
                    get_filename(filepath), pid, write_size);
     }
     
     return SUCCESS;
 }
 
 /**
  * @brief 修改进程内存
  * @param pid 进程ID
  * @param addr 内存地址
  * @param data 新数据
  * @param size 数据大小
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::modify_process_memory(pid_t pid, uint64_t addr, 
                                     const void* data, size_t size) {
     if (!data || size == 0) {
         return ERROR_INVALID_PARAM;
     }
     
     // 打开进程内存文件
     char mem_path[64];
     snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
     
     int fd = open(mem_path, O_WRONLY);
     if (fd == -1) {
         ERROR_PRINT("打开进程内存文件失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     // 定位到目标地址
     if (lseek(fd, addr, SEEK_SET) == -1) {
         ERROR_PRINT("定位内存地址失败: %s", strerror(errno));
         close(fd);
         return ERROR_GENERIC;
     }
     
     // 写入数据
     ssize_t bytes_written = write(fd, data, size);
     if (bytes_written != (ssize_t)size) {
         ERROR_PRINT("写入进程内存失败: %s", strerror(errno));
         close(fd);
         return ERROR_GENERIC;
     }
     
     close(fd);
     return SUCCESS;
 }
 
 /**
  * @brief 读取进程内存
  * @param pid 进程ID
  * @param addr 内存地址
  * @param buffer 输出缓冲区
  * @param size 读取大小
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int BpfLoader::read_process_memory(pid_t pid, uint64_t addr, 
                                   void* buffer, size_t size) {
     if (!buffer || size == 0) {
         return ERROR_INVALID_PARAM;
     }
     
     // 打开进程内存文件
     char mem_path[64];
     snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
     
     int fd = open(mem_path, O_RDONLY);
     if (fd == -1) {
         ERROR_PRINT("打开进程内存文件失败: %s", strerror(errno));
         return ERROR_GENERIC;
     }
     
     // 定位到目标地址
     if (lseek(fd, addr, SEEK_SET) == -1) {
         ERROR_PRINT("定位内存地址失败: %s", strerror(errno));
         close(fd);
         return ERROR_GENERIC;
     }
     
     // 读取数据
     ssize_t bytes_read = read(fd, buffer, size);
     if (bytes_read != (ssize_t)size) {
         ERROR_PRINT("读取进程内存失败: %s", strerror(errno));
         close(fd);
         return ERROR_GENERIC;
     }
     
     close(fd);
     return SUCCESS;
 }
 
 /**
  * @brief 更新事件统计信息
  * @param event_type 事件类型
  * @param bytes_spoofed 欺骗字节数（可选）
  */
 void BpfLoader::update_event_stats(file_operation_type_t event_type, 
                                   size_t bytes_spoofed) {
     std::lock_guard<std::mutex> lock(m_stats_mutex);
     
     m_event_stats.total_events++;
     m_event_stats.last_event_time = GET_TIMESTAMP();
     
     switch (event_type) {
         case FILE_OP_OPEN:
             m_event_stats.open_events++;
             break;
         case FILE_OP_READ:
             m_event_stats.read_events++;
             if (bytes_spoofed > 0) {
                 m_event_stats.txt_files_modified++;
                 m_event_stats.data_spoofed_bytes += bytes_spoofed;
             }
             break;
         case FILE_OP_WRITE:
             m_event_stats.write_events++;
             break;
         case FILE_OP_CLOSE:
             m_event_stats.close_events++;
             break;
         default:
             break;
     }
 }
 
 /**
  * @brief 记录事件日志
  * @param event 事件对象
  */
 void BpfLoader::log_event(const file_event_t& event) {
     if (!m_logger) return;
     
     char buffer[512];
     format_event_info(event, buffer, sizeof(buffer));
     
     logger_debug(m_logger, "%s", buffer);
 }
 
 /**
  * @brief 格式化事件信息
  * @param event 事件对象
  * @param buffer 输出缓冲区
  * @param size 缓冲区大小
  */
 void BpfLoader::format_event_info(const file_event_t& event, char* buffer, size_t size) {
     if (!buffer || size == 0) return;
     
     char time_str[64];
     format_timestamp(event.base.timestamp, time_str, sizeof(time_str));
     
     snprintf(buffer, size, "[%s] %s: %s[%d] %s (fd=%d, ret=%d)",
              time_str, get_event_type_string(event.base.op_type),
              event.base.comm, event.base.pid, event.base.filepath,
              event.base.fd, event.base.ret_code);
 }
 
 /**
  * @brief 检查文件是否应该被监控
  * @param filepath 文件路径
  * @return bool 是否应该监控
  */
 bool BpfLoader::should_monitor_file(const char* filepath) {
     if (!filepath) return false;
     
     // 忽略某些系统文件
     const char* ignore_prefixes[] = {
         "/proc/", "/sys/", "/dev/",
         "/run/", "/tmp/", "/var/tmp/"
     };
     
     for (const char* prefix : ignore_prefixes) {
         if (strncmp(filepath, prefix, strlen(prefix)) == 0) {
             return false;
         }
     }
     
     return true;
 }
 
 /**
  * @brief 获取事件统计信息
  * @return event_stats_t 事件统计结构体
  */
 event_stats_t BpfLoader::get_event_stats() const {
     std::lock_guard<std::mutex> lock(m_stats_mutex);
     return m_event_stats;
 }
 
 /**
  * @brief 重置事件统计信息
  */
 void BpfLoader::reset_event_stats() {
     std::lock_guard<std::mutex> lock(m_stats_mutex);
     memset(&m_event_stats, 0, sizeof(m_event_stats));
     
     if (m_logger) {
         logger_info(m_logger, "事件统计信息已重置");
     }
 }
 
 /**
  * @brief 设置事件回调函数
  * @param callback 回调函数
  */
 void BpfLoader::set_event_callback(std::function<void(const file_event_t&)> callback) {
     std::lock_guard<std::mutex> lock(m_callback_mutex);
     m_event_callback = callback;
 }
 
 /**
  * @brief 设置数据欺骗使能状态
  * @param enabled 是否启用数据欺骗
  */
 void BpfLoader::set_data_spoofing_enabled(bool enabled) {
     m_data_spoofing_enabled.store(enabled);
     
     if (m_logger) {
         logger_info(m_logger, "数据欺骗功能已%s", enabled ? "启用" : "禁用");
     }
 }
 
 /**
  * @brief 获取数据欺骗使能状态
  * @return bool 是否启用数据欺骗
  */
 bool BpfLoader::is_data_spoofing_enabled() const {
     return m_data_spoofing_enabled.load();
 }
 
 /**
  * @brief 检查是否正在运行
  * @return bool 是否正在运行
  */
 bool BpfLoader::is_running() const {
     return m_is_running.load();
 }