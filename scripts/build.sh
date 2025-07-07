#!/bin/bash

# 确保在项目根目录执行
cd "$(dirname "$0")/.."

# 初始化子模块
git submodule update --init --recursive

# 创建构建目录
mkdir -p build
cd build

# 运行CMake配置
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
    -DENABLE_ASAN=OFF \
    -DCMAKE_INSTALL_PREFIX=../install

# 编译项目
make -j$(nproc)

# 安装到本地目录
make install

# 创建bin目录并复制必要文件
mkdir -p ../bin
cp ../install/bin/* ../bin/
cp src/ebpf/*.bpf.o ../bin/
cp src/ebpf/*.skel.h ../bin/

# 复制测试文件
mkdir -p ../tests/test_docs
cp ../tests/test_docs/test_content.txt ../tests/test_docs/

echo "构建完成！可执行文件在 bin/ 目录"
echo "运行: sudo ./scripts/run.sh"