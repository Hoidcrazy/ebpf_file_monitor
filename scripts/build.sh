#!/bin/bash

cd "$(dirname "$0")/.."

# 初始化子模块
git submodule update --init --recursive

# 创建构建目录
mkdir -p build
cd build

# 运行CMake配置
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
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
cp external/libbpf/build/tools/bpftool/bpftool ../bin/

echo "构建完成！可执行文件在 bin/ 目录"
echo "运行: sudo ./scripts/run.sh"