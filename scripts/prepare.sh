#!/bin/bash

# 初始化 Git 子模块
echo "初始化 Git 子模块..."
git submodule update --init --recursive

# 检查系统依赖
echo "检查系统依赖..."
if ! command -v clang &> /dev/null; then
    echo "安装 Clang..."
    sudo apt-get update
    sudo apt-get install -y clang llvm
fi

if ! command -v cmake &> /dev/null; then
    echo "安装 CMake..."
    sudo apt-get install -y cmake
fi

if ! command -v bpftool &> /dev/null; then
    echo "安装 bpftool..."
    sudo apt-get install -y bpftool
fi

echo "准备完成！现在可以运行 ./scripts/build.sh"