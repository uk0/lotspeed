#!/bin/bash
#
# LotSpeed v2.0 - 一键部署脚本
# Author: uk0 @ 2025-11-18 06:29:35
# GitHub: https://github.com/uk0/lotspeed
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
#   or
#   wget -qO- https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
#

set -e

# 配置
GITHUB_REPO="uk0/lotspeed"
GITHUB_BRANCH="main"
INSTALL_DIR="/opt/lotspeed"
MODULE_NAME="lotspeed"
VERSION="2.0"
CURRENT_TIME="2025-11-18 06:29:35"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 打印函数
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     _          _   ____                      _             ║
║    | |    ___ | |_/ ___| _ __   ___  ___  __| |            ║
║    | |   / _ \| __\___ \| '_ \ / _ \/ _ \/ _` |            ║
║    | |__| (_) | |_ ___) | |_) |  __/  __/ (_| |            ║
║    |_____\___/ \__|____/| .__/ \___|\___|\__,_|            ║
║                         |_|                                ║
║                                                            ║
║                        Modern LotServer                    ║
║                        Version 2.0                         ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${YELLOW}Try: curl -fsSL <url> | sudo bash${NC}"
        exit 1
    fi
}

# 检查系统
check_system() {
    log_info "Checking system compatibility..."

    # 检查 OS
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(cat /etc/redhat-release | sed 's/.*release \([0-9]\).*/\1/')
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version | cut -d. -f1)
        if grep -qi ubuntu /etc/os-release 2>/dev/null; then
            OS="ubuntu"
            OS_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d. -f1)
        fi
    else
        log_error "Unsupported operating system"
        exit 1
    fi

    # 检查内核版本
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

    if [[ $KERNEL_MAJOR -lt 4 ]] || ([[ $KERNEL_MAJOR -eq 4 ]] && [[ $KERNEL_MINOR -lt 9 ]]); then
        log_error "Kernel version must be >= 4.9 (current: $(uname -r))"
        exit 1
    fi

    # 检查架构
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "aarch64" ]]; then
        log_warn "Architecture $ARCH may not be fully tested"
    fi

    log_success "System: $OS $OS_VERSION (kernel $(uname -r), $ARCH)"
}

# 安装依赖
install_dependencies() {
    log_info "Installing dependencies..."

    if [[ "$OS" == "centos" ]]; then
        yum install -y gcc make kernel-devel-$(uname -r) kernel-headers-$(uname -r) wget curl bc 2>/dev/null || {
            log_warn "Some packages may be missing, trying alternative..."
            yum install -y gcc make kernel-devel kernel-headers wget curl bc
        }
    elif [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        apt-get update >/dev/null 2>&1
        apt-get install -y gcc make linux-headers-$(uname -r) wget curl bc 2>/dev/null || {
            log_warn "Some packages may be missing, trying alternative..."
            apt-get install -y gcc make linux-headers-generic wget curl bc
        }
    fi

    log_success "Dependencies installed"
}

# 下载源码
download_source() {
    log_info "Downloading LotSpeed source code..."

    # 创建安装目录
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR

    # 下载主文件
    curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/$GITHUB_BRANCH/lotspeed.c" -o lotspeed.c || {
        log_error "Failed to download lotspeed.c"
        exit 1
    }

    # 创建 Makefile
    cat > Makefile << 'EOF'
obj-m += lotspeed.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install: all
	insmod lotspeed.ko
	@echo "lotspeed" >> /etc/modules-load.d/lotspeed.conf 2>/dev/null || true
	@cp lotspeed.ko /lib/modules/$(shell uname -r)/kernel/net/ipv4/ 2>/dev/null || true
	@depmod -a

uninstall:
	-rmmod lotspeed 2>/dev/null
	@rm -f /etc/modules-load.d/lotspeed.conf
	@rm -f /lib/modules/$(shell uname -r)/kernel/net/ipv4/lotspeed.ko
	@depmod -a
EOF

    log_success "Source code downloaded"
}

# 编译模块
compile_module() {
    log_info "Compiling LotSpeed kernel module..."

    cd $INSTALL_DIR
    make clean >/dev/null 2>&1

    if ! make >/dev/null 2>&1; then
        log_error "Compilation failed. Checking error..."
        make 2>&1 | tail -20
        exit 1
    fi

    if [[ ! -f lotspeed.ko ]]; then
        log_error "Module compilation failed - lotspeed.ko not found"
        exit 1
    fi

    log_success "Module compiled successfully"
}

# 加载模块
load_module() {
    log_info "Loading LotSpeed module..."

    # 卸载旧模块（如果存在）
    rmmod lotspeed 2>/dev/null || true

    # 加载新模块
    insmod $INSTALL_DIR/lotspeed.ko || {
        log_error "Failed to load module"
        dmesg | tail -10
        exit 1
    }

    # 设置为默认拥塞控制算法
    sysctl -w net.ipv4.tcp_congestion_control=lotspeed >/dev/null 2>&1

    # 持久化设置
    if ! grep -q "net.ipv4.tcp_congestion_control=lotspeed" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=lotspeed" >> /etc/sysctl.conf
    fi

    # 设置开机自动加载
    echo "lotspeed" > /etc/modules-load.d/lotspeed.conf
    cp $INSTALL_DIR/lotspeed.ko /lib/modules/$(uname -r)/kernel/net/ipv4/ 2>/dev/null || true
    depmod -a

    log_success "Module loaded and set as default"
}

# 创建管理脚本
create_management_script() {
    log_info "Creating management script..."

    cat > /usr/local/bin/lotspeed << 'SCRIPT_EOF'
#!/bin/bash
# LotSpeed Management Script
# Generated by installer at 2025-11-18 07:20:03
# Author: uk0

ACTION=$1
INSTALL_DIR="/opt/lotspeed"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 安全停止函数
safe_stop() {
    echo -e "${YELLOW}Preparing to stop LotSpeed...${NC}"

    # 1. 先切换到 cubic
    echo -e "${CYAN}Step 1: Switching to cubic algorithm${NC}"
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1

    # 2. 检查活动连接
    echo -e "${CYAN}Step 2: Checking active connections${NC}"
    ACTIVE_CONNS=$(ss -tin | grep lotspeed | wc -l)
    if [ "$ACTIVE_CONNS" -gt 0 ]; then
        echo -e "${YELLOW}Warning: Found $ACTIVE_CONNS active connections using lotspeed${NC}"
        echo -e "${YELLOW}Waiting for connections to close (max 10 seconds)...${NC}"

        # 等待最多10秒
        for i in {1..10}; do
            sleep 1
            ACTIVE_CONNS=$(ss -tin | grep lotspeed | wc -l)
            if [ "$ACTIVE_CONNS" -eq 0 ]; then
                echo -e "${GREEN}All connections closed${NC}"
                break
            fi
            echo -n "."
        done
        echo

        if [ "$ACTIVE_CONNS" -gt 0 ]; then
            echo -e "${YELLOW}Still have $ACTIVE_CONNS connections, forcing stop...${NC}"
        fi
    fi

    # 3. 检查模块引用计数
    echo -e "${CYAN}Step 3: Checking module reference count${NC}"
    if lsmod | grep -q lotspeed; then
        REF_COUNT=$(lsmod | grep lotspeed | awk '{print $3}')
        if [ ! -z "$REF_COUNT" ] && [ "$REF_COUNT" -gt 0 ]; then
            echo -e "${YELLOW}Module reference count: $REF_COUNT${NC}"
        fi
    fi

    # 4. 卸载模块
    echo -e "${CYAN}Step 4: Unloading module${NC}"
    if rmmod lotspeed 2>/dev/null; then
        echo -e "${GREEN}✓ LotSpeed stopped successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}Normal unload failed, trying force unload...${NC}"
        if rmmod -f lotspeed 2>/dev/null; then
            echo -e "${GREEN}✓ LotSpeed force stopped${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed to stop LotSpeed${NC}"
            echo -e "${YELLOW}Try: 'dmesg | tail' to see errors${NC}"
            return 1
        fi
    fi
}

# 安全卸载函数
safe_uninstall() {
    echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
    echo -e "${YELLOW}       Uninstalling LotSpeed v2.0${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════${NC}"

    # 1. 停止模块
    safe_stop

    # 2. 删除文件
    echo -e "${CYAN}Removing files...${NC}"
    rm -rf $INSTALL_DIR
    rm -f /etc/modules-load.d/lotspeed.conf
    rm -f /lib/modules/$(uname -r)/kernel/net/ipv4/lotspeed.ko
    depmod -a

    # 3. 清理配置
    echo -e "${CYAN}Cleaning configuration...${NC}"
    sed -i '/net.ipv4.tcp_congestion_control=lotspeed/d' /etc/sysctl.conf

    # 4. 删除管理脚本（最后删除自己）
    echo -e "${GREEN}✓ LotSpeed uninstalled successfully${NC}"
    rm -f /usr/local/bin/lotspeed
}

show_status() {
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN}         LotSpeed Status Report${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"

    # 检查模块是否加载
    if lsmod | grep -q lotspeed; then
        echo -e "Module Status: ${GREEN}Loaded ✓${NC}"

        # 显示引用计数
        REF_COUNT=$(lsmod | grep lotspeed | awk '{print $3}')
        echo -e "Reference Count: ${CYAN}$REF_COUNT${NC}"

        # 显示活动连接数
        ACTIVE_CONNS=$(ss -tin | grep lotspeed | wc -l)
        echo -e "Active Connections: ${CYAN}$ACTIVE_CONNS${NC}"
    else
        echo -e "Module Status: ${RED}Not Loaded ✗${NC}"
        return
    fi

    # 检查是否为当前算法
    CURRENT=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$CURRENT" == "lotspeed" ]]; then
        echo -e "Active Algorithm: ${GREEN}lotspeed ✓${NC}"
    else
        echo -e "Active Algorithm: ${YELLOW}$CURRENT${NC}"
    fi

    echo ""
    echo -e "${CYAN}Current Parameters:${NC}"
    echo "───────────────────────────────────────────"

    if [[ -d /sys/module/lotspeed/parameters ]]; then
        for param in /sys/module/lotspeed/parameters/*; do
            name=$(basename $param)
            value=$(cat $param 2>/dev/null)
            case $name in
                lotserver_rate)
                    gbps=$((value / 125000000))
                    gbps_frac=$(((value % 125000000) * 100 / 125000000))
                    printf "  %-20s: %s (%d.%02d Gbps)\n" "$name" "$value" "$gbps" "$gbps_frac"
                    ;;
                lotserver_gain)
                    gain_x=$((value / 10))
                    gain_frac=$((value % 10))
                    printf "  %-20s: %s (%d.%dx)\n" "$name" "$value" "$gain_x" "$gain_frac"
                    ;;
                *)
                    printf "  %-20s: %s\n" "$name" "$value"
                    ;;
            esac
        done
    fi
    echo "═══════════════════════════════════════════"
}

apply_preset() {
    PRESET=$2

    echo -e "${CYAN}Applying preset: $PRESET${NC}"

    case $PRESET in
        conservative)
            echo 125000000 > /sys/module/lotspeed/parameters/lotserver_rate
            echo 15 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo -e "${GREEN}Applied conservative preset (1Gbps, 1.5x)${NC}"
            ;;
        balanced)
            echo 625000000 > /sys/module/lotspeed/parameters/lotserver_rate
            echo 25 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo -e "${GREEN}Applied balanced preset (5Gbps, 2.5x)${NC}"
            ;;
        aggressive)
            echo 1250000000 > /sys/module/lotspeed/parameters/lotserver_rate
            echo 40 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo -e "${GREEN}Applied aggressive preset (10Gbps, 4.0x)${NC}"
            ;;
        extreme)
            echo 2500000000 > /sys/module/lotspeed/parameters/lotserver_rate
            echo 50 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 0 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 1 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo -e "${YELLOW}⚡ Applied EXTREME preset (20Gbps, 5.0x, TURBO)${NC}"
            echo -e "${RED}WARNING: This may cause network congestion!${NC}"
            ;;
        *)
            echo "Available presets:"
            echo "  conservative - Safe for shared networks (1G, 1.5x)"
            echo "  balanced    - Good performance (5G, 2.5x) [RECOMMENDED]"
            echo "  aggressive  - High performance (10G, 4.0x)"
            echo "  extreme     - Maximum speed (20G, 5.0x, turbo) [USE WITH CAUTION]"
            exit 1
            ;;
    esac
}

set_param() {
    PARAM=$2
    VALUE=$3

    if [[ -z "$PARAM" ]] || [[ -z "$VALUE" ]]; then
        echo "Usage: lotspeed set <parameter> <value>"
        echo ""
        echo "Available parameters:"
        echo "  lotserver_rate     - Target rate in bytes/sec"
        echo "  lotserver_gain     - Gain multiplier x10 (30 = 3.0x)"
        echo "  lotserver_min_cwnd - Minimum congestion window"
        echo "  lotserver_max_cwnd - Maximum congestion window"
        echo "  lotserver_adaptive - Enable adaptive mode (0/1)"
        echo "  lotserver_turbo    - Enable turbo mode (0/1)"
        echo "  lotserver_verbose  - Enable verbose logging (0/1)"
        exit 1
    fi

    PARAM_FILE="/sys/module/lotspeed/parameters/$PARAM"
    if [[ -f "$PARAM_FILE" ]]; then
        OLD_VALUE=$(cat $PARAM_FILE)
        echo $VALUE > $PARAM_FILE
        echo -e "${GREEN}✓ Set $PARAM = $VALUE (was: $OLD_VALUE)${NC}"
    else
        echo -e "${RED}Error: Parameter $PARAM not found${NC}"
        exit 1
    fi
}

case "$ACTION" in
    start)
        if lsmod | grep -q lotspeed; then
            echo -e "${YELLOW}LotSpeed is already loaded${NC}"
        else
            modprobe lotspeed 2>/dev/null || insmod $INSTALL_DIR/lotspeed.ko
        fi
        sysctl -w net.ipv4.tcp_congestion_control=lotspeed >/dev/null
        echo -e "${GREEN}LotSpeed started${NC}"
        ;;
    stop)
        safe_stop
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        show_status
        ;;
    preset)
        apply_preset $@
        ;;
    set)
        set_param $@
        ;;
    log|logs)
        dmesg | grep lotspeed | tail -50
        ;;
    monitor)
        dmesg -w | grep --color=always lotspeed
        ;;
    uninstall)
        safe_uninstall
        ;;
    connections|conns)
        echo -e "${CYAN}Active connections using LotSpeed:${NC}"
        ss -tin | grep lotspeed || echo "No active connections"
        ;;
    *)
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║          LotSpeed v2.0 Management Tool                  ║"
        echo "║          Created by uk0 @ 2025-11-18                    ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo ""
        echo "Usage: lotspeed {command} [options]"
        echo ""
        echo "Commands:"
        echo "  start       - Start LotSpeed"
        echo "  stop        - Stop LotSpeed safely"
        echo "  restart     - Restart LotSpeed"
        echo "  status      - Show current status and parameters"
        echo "  preset      - Apply preset configuration"
        echo "  set         - Set parameter value"
        echo "  connections - Show active connections"
        echo "  log         - Show recent logs"
        echo "  monitor     - Monitor logs in real-time"
        echo "  uninstall   - Completely uninstall LotSpeed"
        echo ""
        echo "Presets:"
        echo "  lotspeed preset conservative  - 1Gbps, 1.5x gain"
        echo "  lotspeed preset balanced      - 5Gbps, 2.5x gain [RECOMMENDED]"
        echo "  lotspeed preset aggressive    - 10Gbps, 4.0x gain"
        echo "  lotspeed preset extreme       - 20Gbps, 5.0x gain, TURBO"
        echo ""
        echo "Examples:"
        echo "  lotspeed status"
        echo "  lotspeed preset balanced"
        echo "  lotspeed set lotserver_rate 1000000000"
        echo "  lotspeed set lotserver_turbo 1"
        echo "  lotspeed monitor"
        exit 1
        ;;
esac
SCRIPT_EOF

    chmod +x /usr/local/bin/lotspeed
    log_success "Management script created at /usr/local/bin/lotspeed"
}

# 显示配置信息
show_info() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}       LotSpeed v2.0 Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""

    # 显示当前状态
    /usr/local/bin/lotspeed status

    echo ""
    echo -e "${CYAN}Quick Start Commands:${NC}"
    echo "───────────────────────────────────────────────────────"
    echo -e "  ${WHITE}lotspeed status${NC}           - Check current status"
    echo -e "  ${WHITE}lotspeed preset balanced${NC}  - Apply balanced preset"
    echo -e "  ${WHITE}lotspeed preset extreme${NC}   - Apply extreme preset"
    echo -e "  ${WHITE}lotspeed monitor${NC}          - Monitor logs"
    echo -e "  ${WHITE}lotspeed set lotserver_rate 1000000000${NC} - Set custom rate"
    echo ""
    echo -e "${YELLOW}Recommended Settings:${NC}"
    echo "───────────────────────────────────────────────────────"
    echo "  • For VPS/Cloud:     lotspeed preset balanced"
    echo "  • For Dedicated:     lotspeed preset aggressive"
    echo "  • For Testing:       lotspeed preset extreme"
    echo ""
    echo -e "${GREEN}Installation Details:${NC}"
    echo "───────────────────────────────────────────────────────"
    echo "  Install Path:    $INSTALL_DIR"
    echo "  Management Tool: /usr/local/bin/lotspeed"
    echo "  Kernel Module:   /lib/modules/$(uname -r)/kernel/net/ipv4/lotspeed.ko"
    echo "  Install Time:    $CURRENT_TIME UTC"
    echo "  Installer:       uk0"
    echo ""
    echo -e "${MAGENTA}GitHub: https://github.com/$GITHUB_REPO${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"

    # 最后的提醒
    echo ""
    echo -e "${YELLOW}⚠ Important Notes:${NC}"
    echo "  • LotSpeed is now active and set as default TCP algorithm"
    echo "  • Use 'lotspeed preset balanced' for most scenarios"
    echo "  • Turbo mode should only be used on dedicated lines"
    echo "  • Monitor with: dmesg -w | grep lotspeed"
}

# 错误处理
error_exit() {
    log_error "$1"
    echo -e "${RED}Installation failed. Check logs above for details.${NC}"
    exit 1
}

# 主函数
main() {
    clear
    print_banner

    echo -e "${CYAN}Starting installation at $CURRENT_TIME UTC${NC}"
    echo -e "${CYAN}Installer: uk0${NC}"
    echo ""

    # 执行安装步骤
    check_root || error_exit "Root check failed"
    check_system || error_exit "System check failed"
    install_dependencies || error_exit "Dependency installation failed"
    download_source || error_exit "Source download failed"
    compile_module || error_exit "Module compilation failed"
    load_module || error_exit "Module loading failed"
    create_management_script || error_exit "Script creation failed"

    # 显示完成信息
    show_info

    # 记录安装日志
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] LotSpeed v$VERSION installed by uk0" >> /var/log/lotspeed_install.log
}

# 执行主函数
main