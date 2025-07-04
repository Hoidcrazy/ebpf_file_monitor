# #!/bin/bash
# set -e

# # 获取脚本所在目录
# SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# # 创建并进入 build 目录（在项目根目录下）
# rm -rf "$PROJECT_ROOT/build"
# mkdir -p "$PROJECT_ROOT/build"
# cd "$PROJECT_ROOT/build"

# # 构建项目
# cmake ..
# make VERBOSE=1

#!/bin/bash

# 一键构建脚本 - ebpf_file_monitor
# 编译 eBPF 程序和用户态程序

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

# 检查依赖
check_dependencies() {
    print_info "检查构建依赖..."
    
    # 检查 clang
    if ! command -v clang &> /dev/null; then
        print_error "clang 未安装，请安装 clang/llvm"
        exit 1
    fi
    
    # 检查 llvm-strip
    if ! command -v llvm-strip &> /dev/null; then
        print_error "llvm-strip 未安装，请安装 llvm 工具链"
        exit 1
    fi
    
    # 检查 cmake
    if ! command -v cmake &> /dev/null; then
        print_error "cmake 未安装，请安装 cmake"
        exit 1
    fi
    
    # 检查 make
    if ! command -v make &> /dev/null; then
        print_error "make 未安装，请安装 make"
        exit 1
    fi
    
    # 检查内核头文件
    if [ ! -d "/usr/src/linux-headers-$(uname -r)" ] && [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        print_warning "内核头文件未找到，可能需要安装 linux-headers-$(uname -r)"
    fi
    
    print_success "依赖检查完成"
}

# 检查权限
check_permissions() {
    print_info "检查运行权限..."
    
    if [ "$EUID" -ne 0 ]; then
        print_warning "当前不是 root 用户，运行时需要 sudo 权限"
    else
        print_success "权限检查通过"
    fi
}

# 创建构建目录
create_build_dir() {
    print_info "创建构建目录..."
    
    if [ -d "$BUILD_DIR" ]; then
        print_info "清理现有构建目录..."
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"
    print_success "构建目录创建完成: $BUILD_DIR"
}

# 检查 libbpf 静态库
check_libbpf() {
    print_info "检查 libbpf 静态库..."
    
    LIBBPF_DIR="$PROJECT_ROOT/external/libbpf"
    
    if [ ! -d "$LIBBPF_DIR" ]; then
        print_error "libbpf 目录不存在: $LIBBPF_DIR"
        print_info "请确保 external/libbpf 目录存在并包含 libbpf v1.4.7 静态库"
        exit 1
    fi
    
    # 检查头文件目录
    if [ ! -d "$LIBBPF_DIR/include" ]; then
        print_error "libbpf 头文件目录不存在: $LIBBPF_DIR/include"
        exit 1
    fi
    
    # 检查静态库文件
    LIBBPF_LIB=""
    for lib_path in "$LIBBPF_DIR/lib/libbpf.a" "$LIBBPF_DIR/src/libbpf.a" "$LIBBPF_DIR/libbpf.a"; do
        if [ -f "$lib_path" ]; then
            LIBBPF_LIB="$lib_path"
            break
        fi
    done
    
    if [ -z "$LIBBPF_LIB" ]; then
        print_error "未找到 libbpf 静态库文件"
        print_info "请检查以下路径之一是否存在 libbpf.a:"
        print_info "  - $LIBBPF_DIR/lib/libbpf.a"
        print_info "  - $LIBBPF_DIR/src/libbpf.a"
        print_info "  - $LIBBPF_DIR/libbpf.a"
        exit 1
    fi
    
    print_success "libbpf 静态库检查完成: $LIBBPF_LIB"
}

# 配置 CMake
configure_cmake() {
    print_info "配置 CMake..."
    
    cd "$BUILD_DIR"
    
    # 设置 CMake 参数
    CMAKE_ARGS=(
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=/usr/local
        -DCMAKE_C_COMPILER=clang
        -DCMAKE_CXX_COMPILER=clang++
    )
    
    cmake "${CMAKE_ARGS[@]}" "$PROJECT_ROOT"
    
    print_success "CMake 配置完成"
}

# 构建项目
build_project() {
    print_info "构建项目..."
    
    cd "$BUILD_DIR"
    
    # 并行构建
    make -j$(nproc)
    
    print_success "项目构建完成"
}

# 创建日志目录
create_log_dir() {
    print_info "创建日志目录..."
    
    mkdir -p "$PROJECT_ROOT/tests/log"
    chmod 755 "$PROJECT_ROOT/tests/log"
    
    print_success "日志目录创建完成"
}

# 创建测试文件
create_test_files() {
    print_info "创建测试文件..."
    
    mkdir -p "$PROJECT_ROOT/tests/test_docs"
    
    # 创建测试文件
    cat > "$PROJECT_ROOT/tests/test_docs/test_content.txt" << 'EOF'
这是一段初始测试文件。
用于测试 eBPF 文件监控系统的数据欺骗功能。
当程序读取此文件时，内容将被动态修改。
EOF
    
    print_success "测试文件创建完成"
}

# 设置权限
set_permissions() {
    print_info "设置文件权限..."
    
    # 设置可执行权限
    chmod +x "$PROJECT_ROOT/scripts/run.sh"
    
    if [ -f "$BUILD_DIR/src/user/ebpf_file_monitor" ]; then
        chmod +x "$BUILD_DIR/src/user/ebpf_file_monitor"
    fi
    
    print_success "权限设置完成"
}

# 验证构建结果
verify_build() {
    print_info "验证构建结果..."
    
    # 检查可执行文件
    if [ ! -f "$BUILD_DIR/src/user/ebpf_file_monitor" ]; then
        print_error "用户态程序构建失败"
        exit 1
    fi
    
    # 检查 eBPF 对象文件
    if [ ! -f "$BUILD_DIR/src/ebpf/file_monitor.bpf.o" ]; then
        print_error "eBPF 程序构建失败"
        exit 1
    fi
    
    # 检查文件大小
    USER_PROG_SIZE=$(stat -c%s "$BUILD_DIR/src/user/ebpf_file_monitor")
    EBPF_PROG_SIZE=$(stat -c%s "$BUILD_DIR/src/ebpf/file_monitor.bpf.o")
    
    print_success "构建验证通过"
    print_info "用户态程序大小: $USER_PROG_SIZE bytes"
    print_info "eBPF 程序大小: $EBPF_PROG_SIZE bytes"
}

# 显示构建信息
show_build_info() {
    print_info "构建信息:"
    echo "  项目根目录: $PROJECT_ROOT"
    echo "  构建目录: $BUILD_DIR"
    echo "  用户态程序: $BUILD_DIR/src/user/ebpf_file_monitor"
    echo "  eBPF 程序: $BUILD_DIR/src/ebpf/file_monitor.bpf.o"
    echo "  日志目录: $PROJECT_ROOT/tests/log"
    echo "  测试文件: $PROJECT_ROOT/tests/test_docs/test_content.txt"
    echo "  libbpf 库: $PROJECT_ROOT/external/libbpf"
    echo ""
    echo "运行方式:"
    echo "  sudo $PROJECT_ROOT/scripts/run.sh"
    echo "  或者:"
    echo "  cd $BUILD_DIR && sudo ./src/user/ebpf_file_monitor"
}

# 主函数
main() {
    print_info "开始构建 ebpf_file_monitor..."
    print_info "项目根目录: $PROJECT_ROOT"
    
    # 执行构建步骤
    check_dependencies
    check_permissions
    create_build_dir
    check_libbpf
    configure_cmake
    build_project
    create_log_dir
    create_test_files
    set_permissions
    verify_build
    
    print_success "构建完成！"
    show_build_info
}

# 捕获 Ctrl+C
trap 'print_error "构建被中断"; exit 1' INT

# 运行主函数
main "$@"