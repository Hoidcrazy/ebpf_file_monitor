#!/bin/bash

# 检查是否root
if [ "$EUID" -ne 0 ]; then
    echo "请使用root权限运行此脚本"
    exit 1
fi

# 进入构建目录
cd build/bin

# 运行程序
./ebpf_file_monitor