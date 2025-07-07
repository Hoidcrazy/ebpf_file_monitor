#!/bin/bash
# 初始化项目并获取子模块

# 确保在项目根目录
cd "$(dirname "$0")"

# 添加libbpf子模块
git submodule add https://github.com/libbpf/libbpf.git external/libbpf

# 添加bpftool子模块
git submodule add https://github.com/libbpf/bpftool.git external/bpftool

# 更新子模块
git submodule update --init --recursive

echo "Project initialized with libbpf and bpftool submodules"