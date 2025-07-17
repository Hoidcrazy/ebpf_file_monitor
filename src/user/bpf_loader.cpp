// src/user/bpf_loader.cpp
#include "user/bpf_loader.h"
#include "file_monitor.skel.h" // 由bpftool生成
#include <cstring>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <filesystem>

BPFLoader::BPFLoader() : obj(nullptr), ringBuf(nullptr), perfBuf(nullptr), useRingBuffer(false) {}

BPFLoader::~BPFLoader() {
    if (ringBuf) ring_buffer__free(ringBuf);
    if (perfBuf) perf_buffer__free(perfBuf);
    if (obj) file_monitor_bpf__destroy(obj);
}

bool BPFLoader::load() {
    // 使用skeleton加载BPF程序
    obj = file_monitor_bpf__open();
    if (!obj) {
        std::cerr << "无法打开BPF程序" << std::endl;
        return false;
    }
    
    // 编译BPF程序
    int err = file_monitor_bpf__load(obj);
    if (err) {
        std::cerr << "无法加载BPF程序: " << err << std::endl;
        return false;
    }
    
    return true;
}

bool BPFLoader::attach() {
    // 附加BPF程序
    int err = file_monitor_bpf__attach(obj);
    if (err) {
        std::cerr << "无法附加BPF程序: " << err << std::endl;
        return false;
    }
    
    // 根据内核版本选择通信机制
    selectBufferType();
    
    return true;
}

std::tuple<unsigned int, unsigned int, unsigned int> BPFLoader::getKernelVersion() {
    struct utsname uts;
    if (uname(&uts) == 0)  {
        perror("uname失败");
        return {0, 0, 0};
    }
    
    unsigned int major = 0, minor = 0, patch = 0;
    sscanf(uts.release, "%u.%u.%u", &major, &minor, &patch);
    // return {major, minor, patch};
    return std::make_tuple(major, minor, patch);
}

// void BPFLoader::selectBufferType() {
//     auto [major, minor, patch] = getKernelVersion();
    
//     // 内核版本 >= 5.8 使用ring buffer
//     if (major > 5 || (major == 5 && minor >= 8)) {
//         std::cout << "检测到内核版本 " << major << "." << minor << "." << patch
//                   << " (>=5.8)，使用 ring buffer" << std::endl;
//         useRingBuffer = true;
//     } else {
//         std::cout << "检测到内核版本 " << major << "." << minor << "." << patch
//                   << " (<5.8)，使用 perf buffer" << std::endl;
//         useRingBuffer = false;
//     }
    
//     // 设置事件回调
//     if (useRingBuffer) {
//         ringBuf = ring_buffer__new(bpf_map__fd(obj->maps.events), 
//                                  handleEvent, this, nullptr);
//         if (!ringBuf) {
//             std::cerr << "无法创建ring buffer" << std::endl;
//         }
//     } else {
//         perfBuf = perf_buffer__new(bpf_map__fd(obj->maps.events), 8, 
//                                  handleEvent, nullptr, this, nullptr);
//         if (!perfBuf) {
//             std::cerr << "无法创建perf buffer" << std::endl;
//         }
//     }
// }

void BPFLoader::selectBufferType() {
    auto [major, minor, patch] = getKernelVersion();

    if (major > 5 || (major == 5 && minor >= 8)) {
        std::cout << "使用 ring buffer (内核 >= 5.8)" << std::endl;
        useRingBuffer = true;

        ringBuf = ring_buffer__new(bpf_map__fd(obj->maps.events),
                                   handleRingBufferEvent,
                                   this, nullptr);
        if (!ringBuf) {
            std::cerr << "无法创建 ring buffer" << std::endl;
        }

    } else {
        std::cout << "使用 perf buffer (内核 < 5.8)" << std::endl;
        useRingBuffer = false;

        perfBuf = perf_buffer__new(bpf_map__fd(obj->maps.events), 8,
                                   handlePerfBufferEvent,
                                   nullptr, this, nullptr);
        if (!perfBuf) {
            std::cerr << "无法创建 perf buffer" << std::endl;
        }
    }
}

void BPFLoader::pollEvents(EventCallback callback) {
    eventCb = callback;
    
    while (true) {
        if (useRingBuffer && ringBuf) {
            ring_buffer__poll(ringBuf, 100 /* timeout ms */);
        } else if (perfBuf) {
            perf_buffer__poll(perfBuf, 100 /* timeout ms */);
        }
    }
}

// int BPFLoader::handleEvent(void *ctx, void *data, size_t size) {
//     BPFLoader* loader = static_cast<BPFLoader*>(ctx);
//     struct event* e = static_cast<struct event*>(data);
    
//     if (loader && loader->eventCb) {
//         loader->eventCb(*e);
//     }
//     return 0;
// }

// void BPFLoader::handleEvent(void *ctx, int cpu, void *data, unsigned int size) {
//     BPFLoader* loader = static_cast<BPFLoader*>(ctx);
//     struct event* e = static_cast<struct event*>(data);

//     if (loader && loader->eventCb) {
//         loader->eventCb(*e);
//     }
// }

int BPFLoader::handleRingBufferEvent(void* ctx, void* data, size_t size) {
    BPFLoader* loader = static_cast<BPFLoader*>(ctx);
    struct event* e = static_cast<struct event*>(data);

    if (loader && loader->eventCb) {
        loader->eventCb(*e);
    }
    return 0; // ring_buffer 要求返回 int
}

void BPFLoader::handlePerfBufferEvent(void* ctx, int cpu, void* data, unsigned int size) {
    BPFLoader* loader = static_cast<BPFLoader*>(ctx);
    struct event* e = static_cast<struct event*>(data);

    if (loader && loader->eventCb) {
        loader->eventCb(*e);
    }
}

bool BPFLoader::modifyProcessMemory(pid_t pid, uint64_t addr, const void* data, size_t size) {
    // 打开进程内存
    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    int memFd = open(memPath, O_RDWR);
    if (memFd < 0) {
        perror("无法打开/proc/pid/mem");
        return false;
    }
    
    // 定位到指定地址
    if (lseek(memFd, addr, SEEK_SET) == (off_t)-1) {
        perror("lseek失败");
        close(memFd);
        return false;
    }
    
    // 写入新内容
    ssize_t written = write(memFd, data, size);
    close(memFd);
    
    if (written != (ssize_t)size) {
        perror("写入内存失败");
        return false;
    }
    
    return true;
}