// src/user/skeleton_wrapper.cpp
#include "bpf_loader.h"
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <unistd.h>

BPFLoader::BPFLoader() : obj_(nullptr), running_(false) {}

BPFLoader::~BPFLoader() {
    if (obj_) bpf_object__close(obj_);
}

bool BPFLoader::load_bpf_program(const std::string& bpf_obj_path) {
    obj_ = bpf_object__open(bpf_obj_path.c_str());
    if (!obj_) return false;
    
    return bpf_object__load(obj_) == 0;
}

void BPFLoader::attach_probes() {
    // 附加所有自动检测的probe
    bpf_program *prog;
    bpf_object__for_each_program(prog, obj_) {
        bpf_program__attach(prog);
    }
}