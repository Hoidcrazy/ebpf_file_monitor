#!/bin/bash
# scripts/run.sh

# 确保在项目根目录执行
cd "$(dirname "$0")/.."

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 检查是否已构建
if [ ! -f "build/bin/file_monitor" ]; then
    echo "Executable not found. Building first..."
    ./scripts/build.sh
fi

# 创建日志目录
mkdir -p build/bin/log

# 设置环境变量
export KERNEL_HEADERS="/lib/modules/$(uname -r)/build"
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# 运行监控程序
echo "===== Starting eBPF File Monitor ====="
./build/bin/file_monitor