// src/user/bpf_loader.cpp
#include "bpf_loader.h"
#include <cstring>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <fstream>

void BPFLoader::start_event_loop(Logger& logger) {
    running_ = true;
    
    // 获取ring buffer映射
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj_, "events");
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(rb_map),
        [](void *ctx, void *data, size_t size) -> int {
            auto self = static_cast<BPFLoader*>(ctx);
            // 根据事件类型分发处理
            if (size == sizeof(open_event)) {
                self->handle_open_event(data);
            } else if (size == sizeof(rw_event)) {
                // 区分读写事件
                auto *evt = static_cast<rw_event*>(data);
                if (self->bpf_program_attached("sys_read")) {
                    self->handle_read_event(data);
                } else if (self->bpf_program_attached("sys_write")) {
                    self->handle_write_event(data);
                }
            } else if (size == sizeof(close_event)) {
                self->handle_close_event(data);
            }
            return 0;
        }, this, nullptr);
    
    while (running_) {
        ring_buffer__poll(rb, 100 /* timeout_ms */);
    }
    
    ring_buffer__free(rb);
}

// 数据欺骗核心函数
void modify_process_memory(pid_t pid, unsigned long addr, 
                          const char* new_data, size_t size) {
    // 使用PTRACE写入目标进程内存
    long ret = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    if (ret == -1) return;
    
    waitpid(pid, nullptr, 0);  // 等待进程停止
    
    // 逐页写入修改后的数据
    size_t offset = 0;
    while (offset < size) {
        // 计算当前页剩余空间
        size_t write_size = std::min(size - offset, 
                                   (size_t)sizeof(long));
        
        // 构造iovec结构
        struct iovec local_iov = {
            .iov_base = (void*)(new_data + offset),
            .iov_len = write_size
        };
        struct iovec remote_iov = {
            .iov_base = (void*)(addr + offset),
            .iov_len = write_size
        };
        
        // 执行进程内存写入
        process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        offset += write_size;
    }
    
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

void BPFLoader::handle_read_event(void* data) {
    auto* evt = static_cast<rw_event*>(data);
    if (!read_cb_) return;
    
    read_cb_(*evt);
    
    // 检查是否为.txt文件
    if (IS_TXT_FILE(path)) {
        const char* fake_data = "这是一段经过修改缓冲区后的内容。";
        size_t fake_len = strlen(fake_data) + 1;
        
        // 修改目标进程内存
        modify_process_memory(evt->pid, evt->buf_addr, fake_data, 
                             std::min(fake_len, evt->size));
        
        // 记录欺骗操作
        char msg[MAX_MSG_LEN];
        snprintf(msg, sizeof(msg), 
                "Data Deception Applied | PID: %d | FD: %d | Path: %s",
                evt->pid, evt->fd, path);
        logger.log(msg);
    }
}