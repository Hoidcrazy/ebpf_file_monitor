/**
 * @file bpf_loader.h
 * @brief eBPF 加载器与事件处理类声明
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该文件定义了 eBPF 程序加载器类和事件处理接口
 */

 #ifndef BPF_LOADER_H
 #define BPF_LOADER_H
 
 #include "common.h"
 #include "event_structs.h"
 #include "logger.h"
 #include <memory>
 #include <functional>
 #include <thread>
 #include <atomic>
 #include <mutex>
 #include <unordered_map>
 
 // 前向声明
 struct bpf_object;
 struct bpf_program;
 struct bpf_map;
 struct ring_buffer;
 struct perf_buffer;
 
 /**
  * @class BpfLoader
  * @brief eBPF 程序加载器和事件处理类
  * 
  * 负责加载 eBPF 程序、管理 BPF 映射、处理内核事件，以及实现数据欺骗功能
  */
 class BpfLoader {
 public:
     /**
      * @brief 构造函数
      * @param logger 日志句柄
      */
     explicit BpfLoader(logger_handle_t* logger = nullptr);
     
     /**
      * @brief 析构函数
      */
     ~BpfLoader();
     
     /**
      * @brief 加载 eBPF 程序
      * @param obj_file eBPF 对象文件路径
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int load_bpf_program(const char* obj_file);
     
     /**
      * @brief 卸载 eBPF 程序
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int unload_bpf_program();
     
     /**
      * @brief 启动事件监听
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int start_monitoring();
     
     /**
      * @brief 停止事件监听
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int stop_monitoring();
     
     /**
      * @brief 获取事件统计信息
      * @return event_stats_t 事件统计结构体
      */
     event_stats_t get_event_stats() const;
     
     /**
      * @brief 重置事件统计信息
      */
     void reset_event_stats();
     
     /**
      * @brief 设置事件回调函数
      * @param callback 回调函数
      */
     void set_event_callback(std::function<void(const file_event_t&)> callback);
     
     /**
      * @brief 设置数据欺骗使能状态
      * @param enabled 是否启用数据欺骗
      */
     void set_data_spoofing_enabled(bool enabled);
     
     /**
      * @brief 获取数据欺骗使能状态
      * @return bool 是否启用数据欺骗
      */
     bool is_data_spoofing_enabled() const;
     
     /**
      * @brief 检查是否正在运行
      * @return bool 是否正在运行
      */
     bool is_running() const;
 
 private:
     // 私有成员变量
     logger_handle_t* m_logger;                          // 日志句柄
     struct bpf_object* m_bpf_obj;                       // BPF 对象
     struct bpf_map* m_fd_map;                           // fd 映射表
     struct bpf_map* m_events_map;                       // 事件映射表
     struct ring_buffer* m_ring_buf;                     // Ring buffer
     struct perf_buffer* m_perf_buf;                     // Perf buffer
     
     std::atomic<bool> m_is_running;                     // 是否正在运行
     std::atomic<bool> m_should_stop;                    // 是否应该停止
     std::atomic<bool> m_data_spoofing_enabled;          // 数据欺骗使能
     
     std::thread m_polling_thread;                       // 轮询线程
     std::mutex m_stats_mutex;                           // 统计信息互斥锁
     std::mutex m_callback_mutex;                        // 回调函数互斥锁
     
     event_stats_t m_event_stats;                        // 事件统计信息
     std::function<void(const file_event_t&)> m_event_callback;  // 事件回调
     
     bool m_use_ring_buffer;                             // 是否使用 ring buffer
     std::unordered_map<int, std::string> m_fd_to_path;  // fd 到路径的映射（用户态缓存）
     
     // 私有方法
     
     /**
      * @brief 初始化 BPF 映射
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int init_bpf_maps();
     
     /**
      * @brief 初始化通信缓冲区
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int init_communication_buffer();
     
     /**
      * @brief 轮询线程函数
      */
     void polling_thread_func();
     
     /**
      * @brief 处理单个事件
      * @param data 事件数据
      * @param data_size 数据大小
      */
     void handle_event(const void* data, size_t data_size);
     
     /**
      * @brief 处理文件打开事件
      * @param event 打开事件
      */
     void handle_open_event(const file_open_event_t& event);
     
     /**
      * @brief 处理文件读取事件
      * @param event 读取事件
      */
     void handle_read_event(const file_read_event_t& event);
     
     /**
      * @brief 处理文件写入事件
      * @param event 写入事件
      */
     void handle_write_event(const file_write_event_t& event);
     
     /**
      * @brief 处理文件关闭事件
      * @param event 关闭事件
      */
     void handle_close_event(const file_close_event_t& event);
     
     /**
      * @brief 执行数据欺骗
      * @param pid 目标进程ID
      * @param buffer_addr 缓冲区地址
      * @param original_size 原始大小
      * @param filepath 文件路径
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int perform_data_spoofing(pid_t pid, uint64_t buffer_addr, size_t original_size, 
                              const char* filepath);
     
     /**
      * @brief 修改进程内存
      * @param pid 进程ID
      * @param addr 内存地址
      * @param data 新数据
      * @param size 数据大小
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int modify_process_memory(pid_t pid, uint64_t addr, const void* data, size_t size);
     
     /**
      * @brief 读取进程内存
      * @param pid 进程ID
      * @param addr 内存地址
      * @param buffer 输出缓冲区
      * @param size 读取大小
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int read_process_memory(pid_t pid, uint64_t addr, void* buffer, size_t size);
     
     /**
      * @brief 更新事件统计信息
      * @param event_type 事件类型
      * @param bytes_spoofed 欺骗字节数（可选）
      */
     void update_event_stats(file_operation_type_t event_type, size_t bytes_spoofed = 0);
     
     /**
      * @brief 记录事件日志
      * @param event 事件对象
      */
     void log_event(const file_event_t& event);
     
     /**
      * @brief 格式化事件信息
      * @param event 事件对象
      * @param buffer 输出缓冲区
      * @param size 缓冲区大小
      */
     void format_event_info(const file_event_t& event, char* buffer, size_t size);
     
     /**
      * @brief 检查文件是否应该被监控
      * @param filepath 文件路径
      * @return bool 是否应该监控
      */
     bool should_monitor_file(const char* filepath);
     
     /**
      * @brief 获取进程名称
      * @param pid 进程ID
      * @param comm 输出缓冲区
      * @param size 缓冲区大小
      * @return int 成功返回 SUCCESS，失败返回错误码
      */
     int get_process_name(pid_t pid, char* comm, size_t size);
     
     // 静态回调函数（用于 C 接口）
     static int ring_buffer_callback(void* ctx, void* data, size_t data_size);
     static void perf_buffer_callback(void* ctx, int cpu, void* data, 
                                    unsigned int data_size);
     static void perf_buffer_lost_callback(void* ctx, int cpu, unsigned long long lost_cnt);
     
     // 禁用拷贝构造和赋值操作
     BpfLoader(const BpfLoader&) = delete;
     BpfLoader& operator=(const BpfLoader&) = delete;
 };
 
 /**
  * @brief 获取当前内核版本字符串
  * @param buffer 输出缓冲区
  * @param size 缓冲区大小
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int get_kernel_version_string(char* buffer, size_t size);
 
 /**
  * @brief 检查是否具有必要的权限
  * @return bool 是否具有权限
  */
 bool check_required_permissions();
 
 /**
  * @brief 检查内核是否支持 eBPF
  * @return bool 是否支持
  */
 bool check_ebpf_support();
 
 /**
  * @brief 安装信号处理程序
  * @param loader BPF 加载器实例
  * @return int 成功返回 SUCCESS，失败返回错误码
  */
 int install_signal_handlers(BpfLoader* loader);
 
 #endif // BPF_LOADER_H