// include/user/bpf_loader.h
#pragma once

#include <string>
#include <memory>
#include <functional>
#include "event_structs_user.h"

// 前向声明
struct bpf_object;
struct ring_buffer;
struct perf_buffer;
struct file_monitor_bpf; // eBPF骨架结构

// 事件回调函数类型
using EventCallback = std::function<void(const struct event&)>;

class BPFLoader {
public:
    BPFLoader();
    ~BPFLoader();
    
    // 加载eBPF程序
    bool load();
    
    // 附加eBPF程序到内核
    bool attach();
    
    // 启动事件轮询
    void pollEvents(EventCallback callback);
    
    // 修改进程内存
    static bool modifyProcessMemory(pid_t pid, uint64_t addr, const void* data, size_t size);
    
private:
    // 处理事件回调
    // static int handleEvent(void* ctx, void* data, size_t size);
    // static void handleEvent(void* ctx, int cpu, void* data, unsigned int size);
    // 为 ring_buffer 和 perf_buffer 分别定义回调函数
    static int handleRingBufferEvent(void* ctx, void* data, size_t size);
    static void handlePerfBufferEvent(void* ctx, int cpu, void* data, unsigned int size);

    // 新增的骨架封装函数
    static file_monitor_bpf* open_bpf_object();
    static int load_bpf_object(file_monitor_bpf* obj);
    static int attach_bpf_object(file_monitor_bpf* obj);
    static void destroy_bpf_object(file_monitor_bpf* obj);
    static struct bpf_map* get_map_by_name(file_monitor_bpf* obj, const char* name);
    
    // 根据内核版本选择buffer类型
    void selectBufferType();
    
    // 内核版本检测
    std::tuple<unsigned int, unsigned int, unsigned int> getKernelVersion();
    
    file_monitor_bpf* obj;    // eBPF骨架对象
    ring_buffer* ringBuf;     // Ring Buffer (内核>=5.8)
    perf_buffer* perfBuf;     // Perf Buffer (内核<5.8)
    EventCallback eventCb;    // 用户事件回调
    bool useRingBuffer;       // 是否使用Ring Buffer
};