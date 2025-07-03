#!/bin/bash
set -e

# 获取脚本所在目录
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# 创建并进入 build 目录（在项目根目录下）
mkdir -p "$PROJECT_ROOT/build"
cd "$PROJECT_ROOT/build"

# 构建项目
cmake "$PROJECT_ROOT"
make
