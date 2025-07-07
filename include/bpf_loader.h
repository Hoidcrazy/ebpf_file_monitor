// include/bpf_loader.h
#pragma once
#include "event_structs.h"
#include <functional>
#include <string>
#include <vector>

class BPFLoader {
public:
    BPFLoader();
    ~BPFLoader();
    
    bool load_bpf_program(const std::string& bpf_obj_path);
    void attach_probes();
    void start_event_loop(Logger& logger);
    void stop_event_loop();

    // 事件回调类型定义
    using OpenCallback = std::function<void(const open_event&)>;
    using ReadCallback = std::function<void(const rw_event&)>;
    using WriteCallback = std::function<void(const rw_event&)>;
    using CloseCallback = std::function<void(const close_event&)>;
    
    // 设置回调函数
    void set_open_callback(OpenCallback cb) { open_cb_ = cb; }
    void set_read_callback(ReadCallback cb) { read_cb_ = cb; }
    void set_write_callback(WriteCallback cb) { write_cb_ = cb; }
    void set_close_callback(CloseCallback cb) { close_cb_ = cb; }

private:
    struct bpf_object* obj_;
    bool running_;
    
    // 事件回调函数
    OpenCallback open_cb_;
    ReadCallback read_cb_;
    WriteCallback write_cb_;
    CloseCallback close_cb_;
    
    // 私有方法
    void handle_open_event(void* data);
    void handle_read_event(void* data);
    void handle_write_event(void* data);
    void handle_close_event(void* data);
};