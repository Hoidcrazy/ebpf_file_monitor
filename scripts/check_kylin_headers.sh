#!/bin/bash
# check_kylin_headers.sh
# 检查麒麟内核头文件位置及关键文件

KERNEL_VER=$(uname -r)
HEADER_DIR="/lib/modules/${KERNEL_VER}/build"

echo "===== Kylin Kernel Header Check ====="
echo "Kernel Version: ${KERNEL_VER}"
echo "Header Path: ${HEADER_DIR}"

# 检查目录是否存在
if [ ! -d "${HEADER_DIR}" ]; then
    echo "[ERROR] Header directory missing!"
    echo "Install with: sudo yum install kernel-devel-${KERNEL_VER}"
    exit 1
fi

# 检查关键文件
REQUIRED_FILES=(
    "include/linux/bpf.h"
    "include/linux/types.h"
    "include/uapi/linux/bpf.h"
    "arch/x86/include/asm/syscall.h"
)

missing=0
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${HEADER_DIR}/${file}" ]; then
        echo "[MISSING] ${file}"
        missing=$((missing+1))
    else
        echo "[OK] ${file}"
    fi
done

# 检查eBPF相关头文件
BPF_HEADERS=($(find ${HEADER_DIR} -name bpf*.h))
if [ ${#BPF_HEADERS[@]} -eq 0 ]; then
    echo "[WARNING] No BPF headers found!"
    missing=$((missing+1))
else
    echo "[OK] Found ${#BPF_HEADERS[@]} BPF headers"
fi

# 最终结果
if [ $missing -gt 0 ]; then
    echo "Found $missing missing headers/features!"
    echo "Try reinstalling: sudo yum reinstall kernel-devel-${KERNEL_VER}"
    exit 1
else
    echo "All required headers are present!"
    exit 0
fi