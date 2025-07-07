#!/bin/bash
# 一键构建脚本

# 确保在项目根目录
cd "$(dirname "$0")/.."

# 创建构建目录
mkdir -p build && cd build

# 运行CMake配置
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_EBPF_PROGRAMS=ON \
    -DBUILD_USERSPACE=ON

# 编译项目
make -j$(nproc)

echo "Build completed. Output in build/bin/"