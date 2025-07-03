#!/bin/bash
# 需 root 权限
if [ "$(id -u)" != "0" ]; then
    echo "请使用 root 权限运行"
    exit 1
fi

# 运行监控程序
$(dirname "$0")/../build/bin/ebpf_file_monitor
