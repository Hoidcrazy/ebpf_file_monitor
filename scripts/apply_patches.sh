# scripts/apply_patches.sh
#!/bin/bash

# 应用 libbpf 补丁
patch -d external/libbpf -p1 < patches/libbpf/kernel_compat.patch

# 添加架构定义
ARCH=$(uname -m)
sed -i "s/__ARCH_PLACEHOLDER__/__${ARCH}__/" external/libbpf/CMakeLists.txt