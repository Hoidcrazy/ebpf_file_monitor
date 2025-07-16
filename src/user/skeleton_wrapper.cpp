#include "user/bpf_loader.h"
#include "file_monitor.skel.h"

// 骨架函数封装
file_monitor_bpf* BPFLoader::open_bpf_object() {
    return file_monitor_bpf__open();
}

int BPFLoader::load_bpf_object(file_monitor_bpf* obj) {
    return file_monitor_bpf__load(obj);
}

int BPFLoader::attach_bpf_object(file_monitor_bpf* obj) {
    return file_monitor_bpf__attach(obj);
}

void BPFLoader::destroy_bpf_object(file_monitor_bpf* obj) {
    file_monitor_bpf__destroy(obj);
}

struct bpf_map* BPFLoader::get_map_by_name(file_monitor_bpf* obj, const char* name) {
    return bpf_object__find_map_by_name(obj->obj, name);
}