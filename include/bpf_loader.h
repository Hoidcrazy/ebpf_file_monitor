#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <bpf/libbpf.h>
#include <unistd.h>
#include <string>
#include <functional>
#include "event_structs.h"

// BPFLoader 类：加载 BPF 程序并处理事件
class BPFLoader {
public:
    BPFLoader();
    ~BPFLoader();

    // 初始化并加载 BPF 程序，返回是否成功
    bool init_bpf();

    // 运行事件监听循环
    void run(std::function<void(const event_t&)> event_cb);

private:
    struct bpf_object *obj = nullptr;
    int ringbuf_map_fd = -1;
    int perf_buffer_map_fd = -1;
    bool use_ringbuf = false;

    // 检查内核版本，决定使用 ring buffer 还是 perf buffer
    bool select_communication_method();

    // perf event 读取回调
    static void handle_perf_event(void *ctx, int cpu, void *data, __u32 size);
};

#endif // BPF_LOADER_H
