#!/bin/bash
# scripts/build.sh

#./scripts/apply_patches.sh

# 确保在项目根目录执行
cd "$(dirname "$0")/.."

# 清理旧构建
if [ "$1" == "clean" ]; then
    rm -rf build
    echo "Clean complete"
    exit 0
fi

# 创建构建目录
mkdir -p build && cd build

# 设置环境变量
export KERNEL_RELEASE=$(uname -r)
export KERNEL_HEADERS="/lib/modules/${KERNEL_RELEASE}/build"

# 检查内核头文件
echo "===== Kernel Header Verification ====="
echo "Kernel Version: ${KERNEL_RELEASE}"
echo "Header Path: ${KERNEL_HEADERS}"

if [ ! -d "${KERNEL_HEADERS}" ]; then
    echo "ERROR: Kernel headers not found"
    echo "Please install with: sudo yum install kernel-devel-${KERNEL_RELEASE}"
    exit 1
fi

# 检查关键头文件
check_header() {
    if [ -f "${KERNEL_HEADERS}/$1" ]; then
        echo "  [OK] $1"
    else
        echo "  [MISSING] $1"
        return 1
    fi
}

echo "Verifying required headers:"
check_header "include/linux/bpf.h" || exit 1
check_header "include/linux/types.h" || exit 1
check_header "include/uapi/linux/bpf.h" || exit 1

# 设置编译器
export CC=clang-12
export CXX=clang++-12

# 使用 CMake 配置项目
echo "===== Configuring Project ====="
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_EBPF_PROGRAMS=ON \
    -DBUILD_USERSPACE=ON

# 编译项目
echo "===== Building Project ====="
make -j$(nproc) VERBOSE=1

# 验证 BTF 支持
echo "===== Verifying BTF Support ====="
llvm-objdump-12 -S ${CMAKE_BINARY_DIR}/bin/ebpf/file_monitor.btf.o | grep BTF
if [ $? -eq 0 ]; then
    echo "BTF support verified"
else
    echo "WARNING: BTF not found in eBPF object"
fi

# 输出构建结果
echo "===== Build Completed ====="
echo "Output files in build/bin:"
ls -lh bin bin/ebpf