#!/bin/bash

# 删除原构建目录
rm -rf build

# 创建构建目录
mkdir -p build
cd build

# 检查是否安装必要工具
command -v cmake >/dev/null 2>&1 || { echo >&2 "需要安装CMake"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo >&2 "需要安装Clang"; exit 1; }
command -v bpftool >/dev/null 2>&1 || { echo >&2 "需要安装bpftool"; exit 1; }

# 设置环境变量（解决可能的路径问题）
export PATH=$PATH:/usr/sbin:/sbin

# 生成并构建项目
cmake .. -DCMAKE_BUILD_TYPE=Release
if [ $? -ne 0 ]; then
    echo "CMake配置失败！"
    exit 1
fi

make -j$(nproc)
if [ $? -ne 0 ]; then
    echo "编译失败！"
    exit 1
fi

# 设置可执行权限
chmod +x ../scripts/run.sh

echo "构建完成！"