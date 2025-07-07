#!/bin/bash

# 确保在项目根目录执行
cd "$(dirname "$0")/.."

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用root权限运行: sudo $0"
    exit 1
fi

# 设置环境变量
export LD_LIBRARY_PATH=./bin:$LD_LIBRARY_PATH

# 创建日志目录
mkdir -p tests/log

# 运行主程序
./bin/file_monitor

echo "监控已停止"