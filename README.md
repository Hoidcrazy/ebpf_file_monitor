# ebpf_file_monitor

一个基于 eBPF 的文件操作监控与数据欺骗项目，支持 Linux 内核 3.1 及以上版本，兼容 CentOS 7、Ubuntu、麒麟等主流 Linux 系统。项目使用 C++ 实现用户态逻辑，C 实现内核态 eBPF 程序，通过 hook 系统调用实时追踪文件生命周期，并可在 `.txt` 文件读取阶段动态篡改数据，欺骗用户程序。

---

## 🎯 项目目标

1. 使用 eBPF hook `open`、`read`、`write`、`close` 函数
2. 实现文件生命周期追踪（打开→读取→写入/关闭），形成控制台信息和日志输出
3. 构建 `fd → filepath` 字典映射，在用户态获取文件路径，保存在日志中
4. 识别 `.txt` 文件，在读取阶段修改缓冲区内容，实现数据欺骗，并输出，相关操作保存在日志中
5. 支持 Linux 内核 3.1 以上，优雅兼容老系统（kprobe + perf buffer）

---

## 🗂️ 项目结构


ebpf_file_monitor/                   # 项目根目录
├── CMakeLists.txt                   # 顶层 CMake 构建文件
├── README.md                        # 项目说明文档（功能/结构/构建说明）
├── include/                         # 公共头文件目录
│   ├── common.h                     # 通用定义、常量、工具宏
│   ├── logger.h                     # 日志接口（用户态）
│   ├── event_types.h                # 内核向用户态传递的事件结构体定义
│   └── bpf_loader.h                 # eBPF 加载器与事件处理类声明
├── src/                             # 源码目录（用户态 + 内核态）
│   ├── user/                        # 用户态程序（C++ 实现）
│   │   ├── main.cpp                 # 主程序入口
│   │   ├── logger.cpp               # 日志模块实现
│   │   ├── bpf_loader.cpp           # 事件处理、buffer选择、数据解析
│   │   ├── skeleton_wrapper.cpp     # eBPF skeleton 加载器封装
│   │   └── CMakeLists.txt           # 构建用户态程序
│   └── ebpf/                        # eBPF 内核程序（C 实现）
│       ├── file_monitor.bpf.c       # hook 系统调用逻辑（open/read/write/close）
│       ├── fd_map.bpf.c             # fd → path 哈希表维护
│       └── CMakeLists.txt           # 编译 .bpf.c 程序并生成 skeleton
├── scripts/                         # 脚本目录
│   ├── build.sh                     # 一键构建脚本（CMake + 编译）
│   └── run.sh                       # 启动程序脚本（需要 root）
├── tools/                           # 辅助工具/测试生成器
│   └── txt_generator.cpp            # 模拟应用程序：打开并读取 .txt 文件
├── tests/                           # 单元测试或集成测试代码
│   └── test_basic.cpp               # 基础功能测试（可选对接 gtest）



## ⚙️ 技术要点

### 系统调用 hook 策略

- 使用 **kprobe/kretprobe** 替代 fentry/fexit，兼容内核 ≥ 3.1
- hook 的函数包括：
  - `do_sys_open` / `sys_openat`（获取路径）
  - `sys_read` / `sys_write`
  - `sys_close`

### 文件生命周期监控

- 在 open 成功返回后：
  - 提取 `fd` 和 `filename`，写入 eBPF 哈希表（fd_map）
- 在 read/write 时：
  - 从哈希表获取对应路径，发送给用户态
- 在 close 时：
  - 删除对应 fd 映射

### 通信机制（用户态 ↔ 内核态）

| 机制           | 内核版本要求 | 状态 | 说明 |
|----------------|---------------|------|------|
| **ring buffer** | ≥ 5.8         | ✅ 推荐 | 高效，libbpf 新接口 |
| **perf buffer** | ≥ 4.4         | ✅ 兼容 | 稳定广泛支持 |
| **map fallback**| ≥ 3.1         | ✅ Linux 3.1 专用 | 用户态轮询读取 map |

📌 项目通过 `BpfLoader` 自动检测内核版本，优先使用 ring buffer，其次 perf buffer，最后回退至 map 轮询通信（用于兼容 3.x 系统）。

### 数据欺骗机制

- 事件中携带 `fd`、`用户缓冲区地址`、`长度`、`文件路径`、`PID`
- 用户态检测到读取 `.txt` 文件时：
  - 拦截事件数据
  - 修改缓冲区内容（替换为 `"这是一段fake内容。"`）
  - 写入原缓冲地址（可使用 `/proc/self/mem`）
- 输出至控制台和日志

> ⚠️ 注意权限需求：需要 root 权限、可能需 CAP_SYS_ADMIN 权限


## 🧱 构建与运行

### 环境依赖

- Linux 内核 ≥ 3.1
- clang / llvm ≥ 10
- cmake ≥ 3.14
- libbpf、bpftool
- g++、make、zlib、pthread
- root 权限执行

### 编译方式

```bash
# 进入项目目录
cd ebpf_file_monitor

# 构建项目
./scripts/build.sh

# 运行监控程序
sudo ./scripts/run.sh
