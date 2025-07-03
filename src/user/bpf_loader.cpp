#include "bpf_loader.h"
#include <bpf/libbpf.h>
#include <sys/utsname.h>
#include <iostream>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include "event_structs.h"

// 处理 perf 事件回调（目前处理读取同一回调）
void BPFLoader::handle_perf_event(void *ctx, int cpu, void *data, __u32 size) {
    event_t *evt = (event_t *)data;
    // 将事件传递给用户注册的回调
    std::function<void(const event_t&)> *cb = (std::function<void(const event_t&)> *)ctx;
    (*cb)(*evt);
}

BPFLoader::BPFLoader() {}
BPFLoader::~BPFLoader() {
    if (obj) {
        bpf_object__close(obj);
    }
}

bool BPFLoader::select_communication_method() {
    struct utsname u;
    if (uname(&u) < 0) {
        perror("uname");
        return false;
    }
    int major, minor;
    if (sscanf(u.release, "%d.%d", &major, &minor) < 2) {
        // 无法解析版本，默认使用 perf
        use_ringbuf = false;
    } else {
        if (major > 5 || (major == 5 && minor >= 8)) {
            use_ringbuf = true;
        } else {
            use_ringbuf = false;
        }
    }
    return true;
}

bool BPFLoader::init_bpf() {
    // 加载 eBPF skeleton
    struct bpf_object_open_attr attr = {
        .file = "file_monitor.bpf.o",
    };
    obj = bpf_object__open_file(attr.file, NULL);
    if (!obj) {
        std::cerr << "bpf_object__open_file 失败\n";
        return false;
    }
    if (bpf_object__load(obj)) {
        std::cerr << "bpf_object__load 失败\n";
        return false;
    }

    // 获取 map FD
    // 假设 eBPF 程序中有名为 "events" 的 map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        std::cerr << "未找到 events map\n";
        return false;
    }
    int events_fd = bpf_map__fd(map);

    // 检查内核版本并选择通信方式
    if (!select_communication_method()) return false;
    if (use_ringbuf) {
        ringbuf_map_fd = events_fd;
    } else {
        perf_buffer_map_fd = events_fd;
    }
    return true;
}

void BPFLoader::run(std::function<void(const event_t&)> event_cb) {
    // 注册信号处理，以便优雅退出（可选）

    // 创建并开始监听
    if (use_ringbuf) {
        // Ring buffer 方式（Linux 5.8+）
        // 需链接 libbpf_ringbuf 等功能，此处示例简单，假设 perf 方式兼容即可
    }

    // Perf buffer 方式
    int page_cnt = 64;
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sample_cb = BPFLoader::handle_perf_event;
    pb_opts.ctx = &event_cb;

    struct perf_buffer *pb = perf_buffer__new(perf_buffer_map_fd, page_cnt, &pb_opts);
    if (!pb) {
        std::cerr << "perf_buffer__new 失败\n";
        return;
    }

    // 进入循环，等待事件
    while (true) {
        int err = perf_buffer__poll(pb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            std::cerr << "perf_buffer poll 失败\n";
            break;
        }
    }

    perf_buffer__free(pb);
}
