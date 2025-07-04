# #!/bin/bash
# # 需 root 权限
# if [ "$(id -u)" != "0" ]; then
#     echo "请使用 root 权限运行"
#     exit 1
# fi

# # 运行监控程序
# $(dirname "$0")/../build/bin/ebpf_file_monitor


#!/bin/bash

# 启动程序脚本 - ebpf_file_monitor
# 以 root 权限运行 eBPF 文件监控系统

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
BUILD_DIR="$PROJECT_ROOT/build"
PROGRAM_PATH="$BUILD_DIR/src/user/ebpf_file_monitor"
EBPF_OBJECT="$BUILD_DIR/src/ebpf/file_monitor.bpf.o"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示此帮助信息"
    echo "  -v, --verbose           详细输出模式"
    echo "  -d, --debug             调试模式"
    echo "  -l, --log-file <文件>   指定日志文件"
    echo "  -L, --log-level <级别>  设置日志级别 (0-4)"
    echo "  --disable-spoofing      禁用数据欺骗功能"
    echo "  --show-stats            显示统计信息"
    echo "  --interval <秒>         统计信息显示间隔"
    echo "  --dry-run              仅检查环境，不运行程序"
    echo ""
    echo "示例:"
    echo "  $0                      # 使用默认设置运行"
    echo "  $0 -v                   # 详细模式运行"
    echo "  $0 -d                   # 调试模式运行"
    echo "  $0 --disable-spoofing   # 禁用数据欺骗"
    echo "  $0 --dry-run            # 仅检查环境"
    echo ""
    echo "注意: 程序需要以 root 权限运行"
}

# 检查权限
check_permissions() {
    print_info "检查运行权限..."
    
    if [ "$EUID" -ne 0 ]; then
        print_error "程序需要以 root 权限运行"
        print_info "请使用: sudo $0"
        exit 1
    fi
    
    print_success "权限检查通过"
}

# 检查内核版本
check_kernel_version() {
    print_info "检查内核版本..."
    
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    print_info "当前内核版本: $KERNEL_VERSION"
    
    # 检查最低版本要求 (4.19)
    if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 19 ]); then
        print_error "内核版本过低，至少需要 4.19"
        print_info "当前版本: $KERNEL_VERSION"
        exit 1
    fi
    
    # 检查是否支持 Ring Buffer (5.8+)
    if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
        print_success "内核支持 Ring Buffer (推荐)"
    else
        print_warning "内核不支持 Ring Buffer，将使用 Perf Buffer"
    fi
}

# 检查 eBPF 支持
check_ebpf_support() {
    print_info "检查 eBPF 支持..."
    
    # 检查 bpf 系统调用支持
    if [ ! -f "/proc/sys/kernel/unprivileged_bpf_disabled" ]; then
        print_warning "无法检查 eBPF 支持状态"
    else
        BPF_STATUS=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
        if [ "$BPF_STATUS" -eq 0 ]; then
            print_info "eBPF 支持: 启用（包括非特权用户）"
        else
            print_info "eBPF 支持: 启用（仅特权用户）"
        fi
    fi
    
    # 检查 debugfs 挂载
    if mount | grep -q debugfs; then
        print_success "debugfs 已挂载"
    else
        print_warning "debugfs 未挂载，某些功能可能受限"
    fi
    
    # 检查 tracefs 挂载
    if mount | grep -q tracefs; then
        print_success "tracefs 已挂载"
    else
        print_warning "tracefs 未挂载，某些功能可能受限"
    fi
    
    print_success "eBPF 支持检查完成"
}

# 检查程序文件
check_program_files() {
    print_info "检查程序文件..."
    
    # 检查用户态程序
    if [ ! -f "$PROGRAM_PATH" ]; then
        print_error "用户态程序未找到: $PROGRAM_PATH"
        print_info "请先运行构建脚本: $PROJECT_ROOT/scripts/build.sh"
        exit 1
    fi
    
    # 检查 eBPF 对象文件
    if [ ! -f "$EBPF_OBJECT" ]; then
        print_error "eBPF 程序未找到: $EBPF_OBJECT"
        print_info "请先运行构建脚本: $PROJECT_ROOT/scripts/build.sh"
        exit 1
    fi
    
    # 检查可执行权限
    if [ ! -x "$PROGRAM_PATH" ]; then
        print_warning "用户态程序没有可执行权限，正在修复..."
        chmod +x "$PROGRAM_PATH"
    fi
    
    print_success "程序文件检查完成"
}

# 检查系统资源
check_system_resources() {
    print_info "检查系统资源..."
    
    # 检查内存
    TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')
    AVAILABLE_MEM=$(free -m | awk 'NR==2{print $7}')
    
    print_info "总内存: ${TOTAL_MEM}MB, 可用内存: ${AVAILABLE_MEM}MB"
    
    if [ "$AVAILABLE_MEM" -lt 100 ]; then
        print_warning "可用内存较少，程序可能运行不稳定"
    fi
    
    # 检查磁盘空间
    LOG_DIR_SPACE=$(df -h "$PROJECT_ROOT/tests/log" | awk 'NR==2{print $4}')
    print_info "日志目录可用空间: $LOG_DIR_SPACE"
    
    print_success "系统资源检查完成"
}

# 设置内存锁定限制
set_memory_limit() {
    print_info "设置内存锁定限制..."
    
    # 临时设置无限制
    ulimit -l unlimited 2>/dev/null || {
        print_warning "无法设置内存锁定限制，程序可能需要额外配置"
    }
    
    print_success "内存锁定限制设置完成"
}

# 创建必要目录
create_directories() {
    print_info "创建必要目录..."
    
    # 创建日志目录
    mkdir -p "$PROJECT_ROOT/tests/log"
    chmod 755 "$PROJECT_ROOT/tests/log"
    
    # 创建测试文档目录
    mkdir -p "$PROJECT_ROOT/tests/test_docs"
    
    print_success "目录创建完成"
}

# 显示运行信息
show_run_info() {
    print_info "运行信息:"
    echo "  程序路径: $PROGRAM_PATH"
    echo "  eBPF 对象: $EBPF_OBJECT"
    echo "  日志目录: $PROJECT_ROOT/tests/log"
    echo "  内核版本: $(uname -r)"
    echo "  用户: $(whoami)"
    echo "  PID: $$"
    echo ""
    echo "控制命令:"
    echo "  Ctrl+C         - 停止程序"
    echo "  kill -USR1 $$  - 显示统计信息"
    echo "  kill -USR2 $$  - 重置统计信息"
    echo ""
}

# 安装信号处理程序
install_signal_handlers() {
    print_info "安装信号处理程序..."
    
    # 捕获 Ctrl+C
    trap 'print_info "收到终止信号，正在关闭程序..."; exit 0' INT TERM
    
    # 捕获 USR1 显示统计信息
    trap 'print_info "显示统计信息信号已发送给程序"' USR1
    
    # 捕获 USR2 重置统计信息
    trap 'print_info "重置统计信息信号已发送给程序"' USR2
    
    print_success "信号处理程序安装完成"
}

# 运行程序
run_program() {
    print_info "启动 eBPF 文件监控系统..."
    
    # 切换到程序目录
    cd "$BUILD_DIR"
    
    # 构建程序参数
    PROGRAM_ARGS=()
    
    # 添加用户指定的参数
    if [ -n "$LOG_FILE" ]; then
        PROGRAM_ARGS+=("-l" "$LOG_FILE")
    fi
    
    if [ -n "$LOG_LEVEL" ]; then
        PROGRAM_ARGS+=("-L" "$LOG_LEVEL")
    fi
    
    if [ "$DISABLE_SPOOFING" = "true" ]; then
        PROGRAM_ARGS+=("-d")
    fi
    
    if [ "$SHOW_STATS" = "true" ]; then
        PROGRAM_ARGS+=("-s")
    fi
    
    if [ -n "$STATS_INTERVAL" ]; then
        PROGRAM_ARGS+=("-i" "$STATS_INTERVAL")
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        PROGRAM_ARGS+=("-L" "0")  # DEBUG 级别
    fi
    
    # 显示运行信息
    show_run_info
    
    # 运行程序
    print_success "程序启动中..."
    print_info "按 Ctrl+C 停止程序"
    echo ""
    
    exec "$PROGRAM_PATH" "${PROGRAM_ARGS[@]}"
}

# 仅运行检查
dry_run() {
    print_info "执行环境检查（dry-run 模式）..."
    
    check_permissions
    check_kernel_version
    check_ebpf_support
    check_program_files
    check_system_resources
    
    print_success "环境检查完成，程序可以正常运行"
    print_info "使用 $0 启动程序"
}

# 解析命令行参数
parse_arguments() {
    VERBOSE=false
    DEBUG=false
    DISABLE_SPOOFING=false
    SHOW_STATS=false
    DRY_RUN=false
    LOG_FILE=""
    LOG_LEVEL=""
    STATS_INTERVAL=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--debug)
                DEBUG=true
                VERBOSE=true
                shift
                ;;
            -l|--log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            -L|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --disable-spoofing)
                DISABLE_SPOOFING=true
                shift
                ;;
            --show-stats)
                SHOW_STATS=true
                shift
                ;;
            --interval)
                STATS_INTERVAL="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                print_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 主函数
main() {
    print_info "ebpf_file_monitor 启动脚本"
    print_info "项目根目录: $PROJECT_ROOT"
    
    # 解析命令行参数
    parse_arguments "$@"
    
    # 如果是 dry-run 模式，只执行检查
    if [ "$DRY_RUN" = "true" ]; then
        dry_run
        exit 0
    fi
    
    # 执行启动步骤
    check_permissions
    check_kernel_version
    check_ebpf_support
    check_program_files
    check_system_resources
    set_memory_limit
    create_directories
    install_signal_handlers
    
    # 运行程序
    run_program
}

# 运行主函数
main "$@"