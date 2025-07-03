# 📘 ebpf_file_monitor

一个基于 **eBPF** 的文件操作生命周期追踪与数据欺骗系统。通过 hook `open`、`read`、`write`、`close` 系统调用，实时监控文件的使用行为，并在读取 `.txt` 文件时动态篡改其内容，实现对用户态程序的“数据欺骗”。

项目采用 C++ 实现用户态逻辑，C 实现 eBPF 内核程序，支持 Linux 4.19 及以上内核版本，兼容 CentOS 7、Ubuntu、麒麟等主流 Linux 发行版。支持 CO-RE（Compile Once, Run Everywhere）与 ring/perf buffer 通信。

---

## 🎯 项目目标

- ✅ 使用 eBPF hook 系统调用 `open` / `read` / `write` / `close`
- ✅ 实现文件的生命周期追踪并输出控制台与日志
- ✅ 构建 `fd → filepath` 映射表
- ✅ 在读取 `.txt` 文件时修改缓冲区内容，欺骗应用程序
- ✅ 支持 Linux 4.19+，优雅兼容低版本（通过 perf buffer）

---

## 🗂️ 项目结构

```
ebpf_file_monitor/                   # 项目根目录
├── CMakeLists.txt                   # 顶层 CMake 构建文件
├── README.md                        # 项目说明文档
├── external/                        # 依赖库
│   ├── libbpf                       
├── include/                         # 公共头文件目录
│   ├── common.h                     # 通用定义（常量、工具宏）
│   ├── logger.h                     # 日志接口定义（用户态）
│   ├── event_structs.h              # 内核向用户态传递的事件结构体定义
│   └── bpf_loader.h                 # eBPF 加载器与事件处理类声明
├── src/                             # 源码目录（用户态 + 内核态）
│   ├── user/                        # 用户态程序（C++ 实现）
│   │   ├── main.cpp                 # 主程序入口
│   │   ├── logger.cpp               # 日志模块实现
│   │   ├── bpf_loader.cpp           # 事件处理、buffer选择、数据解析、通信机制
│   │   ├── skeleton_wrapper.cpp     # eBPF skeleton 加载器封装
│   │   └── CMakeLists.txt           # 用户态逻辑构建
│   └── ebpf/                        # eBPF 内核程序（C 实现）
│       ├── file_monitor.bpf.c       # hook 系统调用逻辑（open/read/write/close）
│       ├── fd_map.bpf.c             # fd → path 路径映射表
│       └── CMakeLists.txt           # 编译 .bpf.c 程序并生成 skeleton
├── scripts/                         # 脚本目录
│   ├── build.sh                     # 一键构建脚本（CMake + 编译）
│   └── run.sh                       # 启动程序脚本（需要 root）
├── tools/                           # 辅助工具/测试生成器
│   └── txt_generator.cpp            # 模拟应用程序：打开并读取 .txt 文件
├── tests/                           # 单元测试或集成测试代码
│   └── test_basic.cpp               # 基础功能测试（可选对接 gtest）（有open/read，修改该缓冲区，并输出显示等功能）

```

---

## ⚙️ 核心技术说明

### 🔩 系统调用 Hook 策略

- 使用 **kprobe/kretprobe** 实现对下列系统调用的 hook：
  - `do_sys_open` / `__x64_sys_openat`
  - `__x64_sys_read` / `__x64_sys_write`
  - `__x64_sys_close`
- 兼容 Linux 4.19+（支持 CO-RE 编译）

---

### 📁 文件生命周期追踪机制

- `open`：
  - 提取 `fd` 与文件路径，存入 BPF 哈希表（fd_map）
- `read` / `write`：
  - 查询哈希表，提取路径、pid、缓冲区等信息
  - 推送事件至用户态
- `close`：
  - 删除对应 fd 的路径映射项

---

### 🔄 用户态 ↔ 内核态通信机制

自动适配内核版本，选择最佳通信方式：

| 通信方式        | 内核版本要求 | 特性          |
|------------------|---------------|---------------|
| **ring buffer**   | ≥ 5.8         | ✅ 推荐：高效低延迟 |
| **perf buffer**   | ≥ 4.4         | ✅ 稳定兼容性广     |

> 项目会在运行时判断内核版本，优先选择 ring buffer，若不支持则自动回退至 perf buffer。

---

### 🎭 数据欺骗实现原理

- eBPF 向用户态推送 `read()` 事件，包括：
  - `fd`、`用户缓冲地址`、`读取长度`、`文件路径`、`PID`
- 用户态收到事件后：
  - 判断文件是否为 `.txt` 后缀
  - 替换为固定伪造内容（如 `"这是一段fake内容。"`)
  - 使用 `/proc/[pid]/mem` 写入原缓冲地址

> ⚠️ 数据修改需 root 权限，推荐运行环境需具备 `CAP_SYS_PTRACE` 权限。

---

## 🧱 构建与运行指南

### ✅ 依赖环境

| 工具组件     | 推荐版本 |
|--------------|----------|
| Linux 内核    | **≥ 4.19**（必须） |
| Clang/LLVM    | **11+**（编译 eBPF） |
| GCC           | **11+**（编译用户态） |
| CMake         | **≥ 3.16** |
| libbpf        | **≥ v0.6**（建议源码集成） |
| 权限          | **root 权限运行程序** |

---

### 🔧 构建步骤

```bash
# 进入项目根目录
cd ebpf_file_monitor

# 构建 eBPF 和用户态程序
./scripts/build.sh

```

## 🚀 运行监控程序

```bash
# 以 root 权限运行主程序
sudo ./scripts/run.sh
```

运行时，终端将实时打印文件打开、读取、关闭的事件日志，包含路径和操作信息。

## 🧪 测试用例

**工具：** txt_generator
用于模拟程序打开并读取 .txt 文件，验证数据欺骗逻辑。

```bash
复制
编辑
# 编译测试程序
g++ tools/txt_generator.cpp -o txtgen

# 执行测试
./txtgen test.txt
```

**预期结果**
- 控制台显示文件打开、读取、关闭的调用日志；
- 读取的 .txt 文件内容被替换为伪造文本；
- 日志中记录数据篡改事件。