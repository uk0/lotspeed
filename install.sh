#!/bin/bash
#
# LotSpeed v5.6 - Zeta-TCP Auto-Scaling Edition
# Author: uk0 @ 2025-11-23
# GitHub: https://github.com/uk0/lotspeed
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/zeta-tcp/install.sh | sudo bash
#   or
#   wget -qO- https://raw.githubusercontent.com/uk0/lotspeed/zeta-tcp/install.sh | sudo bash
#

set -e

# 配置
GITHUB_REPO="uk0/lotspeed"
GITHUB_BRANCH="zeta-tcp"
INSTALL_DIR="/opt/lotspeed"
MODULE_NAME="lotspeed"
VERSION="5.6"
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')
CURRENT_USER=$(whoami)

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
║     _          _   ____                      _            ║
║    | |    ___ | |_/ ___| _ __   ___  ___  __| |           ║
║    | |   / _ \| __\___ \| '_ \ / _ \/ _ \/ _` |           ║
║    | |__| (_) | |_ ___) | |_) |  __/  __/ (_| |           ║
║    |_____\___/ \__|____/| .__/ \___|\___|\__,_|           ║
║                         |_|                                ║
║                                                            ║
║              Zeta-TCP Auto-Scaling Edition                ║
║                      Version 5.6                           ║
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
    log_info "Downloading LotSpeed v$VERSION source code..."

    # 创建安装目录
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR

    # 下载源代码
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
    log_info "Compiling LotSpeed v$VERSION kernel module..."

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
    log_info "Loading LotSpeed v$VERSION module..."

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
# LotSpeed v5.6 Management Script (Zeta-TCP Auto-Scaling Edition)

ACTION=$1
INSTALL_DIR="/opt/lotspeed"
VERSION="5.6"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# 格式化函数
format_bytes() {
    local bytes=$1
    if [[ $bytes -ge 1000000000 ]]; then
        echo "$(echo "scale=2; $bytes/1000000000" | bc) GB/s"
    elif [[ $bytes -ge 1000000 ]]; then
        echo "$(echo "scale=2; $bytes/1000000" | bc) MB/s"
    elif [[ $bytes -ge 1000 ]]; then
        echo "$(echo "scale=2; $bytes/1000" | bc) KB/s"
    else
        echo "$bytes B/s"
    fi
}

format_bps() {
    local bytes=$1
    local bits=$((bytes * 8))
    if [[ $bits -ge 1000000000 ]]; then
        echo "$(echo "scale=2; $bits/1000000000" | bc) Gbps"
    elif [[ $bits -ge 1000000 ]]; then
        echo "$(echo "scale=2; $bits/1000000" | bc) Mbps"
    elif [[ $bits -ge 1000 ]]; then
        echo "$(echo "scale=2; $bits/1000" | bc) Kbps"
    else
        echo "$bits bps"
    fi
}

# 获取系统默认的拥塞控制算法
get_default_congestion_control() {
    AVAILABLE=$(sysctl net.ipv4.tcp_available_congestion_control | awk -F= '{print $2}')
    if echo "$AVAILABLE" | grep -q "cubic"; then
        echo "cubic"
    elif echo "$AVAILABLE" | grep -q "reno"; then
        echo "reno"
    elif echo "$AVAILABLE" | grep -q "bbr"; then
        echo "bbr"
    else
        echo "$AVAILABLE" | awk '{print $1}'
    fi
}

show_status() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           LotSpeed v$VERSION Status (Zeta-TCP)                  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # 检查模块是否加载
    if lsmod | grep -q lotspeed; then
        echo -e "  Module Status      : ${GREEN}● Loaded${NC}"
        REF_COUNT=$(lsmod | grep lotspeed | awk '{print $3}')
        echo -e "  Reference Count    : ${CYAN}$REF_COUNT${NC}"
        ACTIVE_CONNS=$(ss -tin 2>/dev/null | grep -c lotspeed 2>/dev/null || echo "0")
        echo -e "  Active Connections : ${CYAN}$ACTIVE_CONNS${NC}"
    else
        echo -e "  Module Status      : ${RED}○ Not Loaded${NC}"
        return
    fi

    # 检查是否为当前算法
    CURRENT=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$CURRENT" == "lotspeed" ]]; then
        echo -e "  Active Algorithm   : ${GREEN}lotspeed ✓${NC}"
    else
        echo -e "  Active Algorithm   : ${YELLOW}$CURRENT${NC}"
    fi

    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                    Current Parameters                       │${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"

    if [[ -d /sys/module/lotspeed/parameters ]]; then
        # 读取所有参数
        for param in lotserver_rate lotserver_start_rate lotserver_gain lotserver_min_cwnd \
                     lotserver_max_cwnd lotserver_beta lotserver_adaptive lotserver_turbo \
                     lotserver_verbose lotserver_safe_mode; do
            param_file="/sys/module/lotspeed/parameters/$param"
            if [[ -f "$param_file" ]]; then
                value=$(cat $param_file 2>/dev/null)
                case $param in
                    lotserver_rate)
                        formatted=$(format_bytes $value)
                        bps=$(format_bps $value)
                        printf "  │ %-20s : %-18s (%s)%s│\n" "Global Rate Limit" "$formatted" "$bps" " "
                        ;;
                    lotserver_start_rate)
                        formatted=$(format_bytes $value)
                        bps=$(format_bps $value)
                        printf "  │ %-20s : %-18s (%s)%s│\n" "Soft Start Rate" "$formatted" "$bps" " "
                        ;;
                    lotserver_gain)
                        gain_x=$((value / 10))
                        gain_frac=$((value % 10))
                        printf "  │ %-20s : %-38s │\n" "Gain Factor" "${gain_x}.${gain_frac}x"
                        ;;
                    lotserver_beta)
                        beta_val=$((value * 100 / 1024))
                        printf "  │ %-20s : %-38s │\n" "Fairness (Beta)" "${beta_val}%"
                        ;;
                    lotserver_min_cwnd)
                        printf "  │ %-20s : %-38s │\n" "Min CWND" "$value packets"
                        ;;
                    lotserver_max_cwnd)
                        printf "  │ %-20s : %-38s │\n" "Max CWND" "$value packets"
                        ;;
                    lotserver_adaptive)
                        if [[ "$value" == "Y" ]] || [[ "$value" == "1" ]]; then
                            printf "  │ %-20s : ${GREEN}%-38s${NC} │\n" "Adaptive Mode" "Enabled"
                        else
                            printf "  │ %-20s : ${YELLOW}%-38s${NC} │\n" "Adaptive Mode" "Disabled"
                        fi
                        ;;
                    lotserver_turbo)
                        if [[ "$value" == "Y" ]] || [[ "$value" == "1" ]]; then
                            printf "  │ %-20s : ${YELLOW}%-38s${NC} │\n" "Turbo Mode" "Enabled ⚡"
                        else
                            printf "  │ %-20s : %-38s │\n" "Turbo Mode" "Disabled"
                        fi
                        ;;
                    lotserver_verbose)
                        if [[ "$value" == "Y" ]] || [[ "$value" == "1" ]]; then
                            printf "  │ %-20s : ${CYAN}%-38s${NC} │\n" "Verbose Logging" "Enabled"
                        else
                            printf "  │ %-20s : %-38s │\n" "Verbose Logging" "Disabled"
                        fi
                        ;;
                    lotserver_safe_mode)
                        if [[ "$value" == "Y" ]] || [[ "$value" == "1" ]]; then
                            printf "  │ %-20s : ${GREEN}%-38s${NC} │\n" "Safe Mode" "Enabled"
                        else
                            printf "  │ %-20s : %-38s │\n" "Safe Mode" "Disabled"
                        fi
                        ;;
                esac
            fi
        done
    fi
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
}

apply_preset() {
    PRESET=$2

    echo -e "${CYAN}Applying preset: $PRESET${NC}"

    case $PRESET in
        conservative)
            echo 125000000 > /sys/module/lotspeed/parameters/lotserver_rate     # 1Gbps
            echo 6250000 > /sys/module/lotspeed/parameters/lotserver_start_rate  # 50Mbps
            echo 15 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 16 > /sys/module/lotspeed/parameters/lotserver_min_cwnd
            echo 2000 > /sys/module/lotspeed/parameters/lotserver_max_cwnd
            echo 717 > /sys/module/lotspeed/parameters/lotserver_beta
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo 1 > /sys/module/lotspeed/parameters/lotserver_safe_mode
            echo -e "${GREEN}Applied conservative preset (1Gbps cap, 1.5x gain, safe mode)${NC}"
            ;;
        balanced)
            echo 625000000 > /sys/module/lotspeed/parameters/lotserver_rate     # 5Gbps
            echo 12500000 > /sys/module/lotspeed/parameters/lotserver_start_rate # 100Mbps
            echo 20 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 16 > /sys/module/lotspeed/parameters/lotserver_min_cwnd
            echo 5000 > /sys/module/lotspeed/parameters/lotserver_max_cwnd
            echo 717 > /sys/module/lotspeed/parameters/lotserver_beta
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo 1 > /sys/module/lotspeed/parameters/lotserver_safe_mode
            echo -e "${GREEN}Applied balanced preset (5Gbps cap, 2.0x gain, adaptive)${NC}"
            ;;
        aggressive)
            echo 1250000000 > /sys/module/lotspeed/parameters/lotserver_rate    # 10Gbps
            echo 62500000 > /sys/module/lotspeed/parameters/lotserver_start_rate # 500Mbps
            echo 30 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 32 > /sys/module/lotspeed/parameters/lotserver_min_cwnd
            echo 8000 > /sys/module/lotspeed/parameters/lotserver_max_cwnd
            echo 819 > /sys/module/lotspeed/parameters/lotserver_beta
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo 0 > /sys/module/lotspeed/parameters/lotserver_safe_mode
            echo -e "${GREEN}Applied aggressive preset (10Gbps cap, 3.0x gain, no safe mode)${NC}"
            ;;
        extreme)
            echo 2500000000 > /sys/module/lotspeed/parameters/lotserver_rate    # 20Gbps
            echo 125000000 > /sys/module/lotspeed/parameters/lotserver_start_rate # 1Gbps
            echo 50 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 50 > /sys/module/lotspeed/parameters/lotserver_min_cwnd
            echo 15000 > /sys/module/lotspeed/parameters/lotserver_max_cwnd
            echo 921 > /sys/module/lotspeed/parameters/lotserver_beta
            echo 0 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 1 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo 0 > /sys/module/lotspeed/parameters/lotserver_safe_mode
            echo -e "${YELLOW}⚡ Applied EXTREME preset (20Gbps, 5.0x gain, TURBO mode)${NC}"
            echo -e "${RED}WARNING: This preset ignores congestion signals!${NC}"
            ;;
        vps100m)
            echo 12500000 > /sys/module/lotspeed/parameters/lotserver_rate      # 100Mbps
            echo 1250000 > /sys/module/lotspeed/parameters/lotserver_start_rate  # 10Mbps
            echo 18 > /sys/module/lotspeed/parameters/lotserver_gain
            echo 10 > /sys/module/lotspeed/parameters/lotserver_min_cwnd
            echo 1000 > /sys/module/lotspeed/parameters/lotserver_max_cwnd
            echo 717 > /sys/module/lotspeed/parameters/lotserver_beta
            echo 1 > /sys/module/lotspeed/parameters/lotserver_adaptive
            echo 0 > /sys/module/lotspeed/parameters/lotserver_turbo
            echo 1 > /sys/module/lotspeed/parameters/lotserver_safe_mode
            echo -e "${GREEN}Applied VPS 100M preset (100Mbps cap, 1.8x gain, safe)${NC}"
            ;;
        debug)
            echo 1 > /sys/module/lotspeed/parameters/lotserver_verbose
            echo -e "${GREEN}Debug mode enabled - verbose logging ON${NC}"
            ;;
        *)
            echo -e "${CYAN}Available presets:${NC}"
            echo "  conservative - Safe for shared networks (1Gbps, 1.5x)"
            echo "  balanced     - Good performance (5Gbps, 2.0x) [RECOMMENDED]"
            echo "  aggressive   - High performance (10Gbps, 3.0x)"
            echo "  extreme      - Maximum speed (20Gbps, 5.0x, TURBO)"
            echo "  vps100m      - For 100Mbps VPS (100Mbps, 1.8x)"
            echo "  debug        - Enable verbose debug logging"
            exit 1
            ;;
    esac
}

set_param() {
    PARAM=$2
    VALUE=$3

    if [[ -z "$PARAM" ]] || [[ -z "$VALUE" ]]; then
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                  LotSpeed v$VERSION Parameters                    ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Usage: lotspeed set <parameter> <value>"
        echo ""
        echo "Available parameters:"
        echo "┌──────────────────────┬─────────────────────────────────────────┐"
        echo "│ Parameter            │ Description                             │"
        echo "├──────────────────────┼─────────────────────────────────────────┤"
        echo "│ lotserver_rate       │ Max rate cap in bytes/sec               │"
        echo "│ lotserver_start_rate │ Soft start rate in bytes/sec (v5.6 new) │"
        echo "│ lotserver_gain       │ Gain multiplier x10 (20 = 2.0x)         │"
        echo "│ lotserver_min_cwnd   │ Minimum congestion window (packets)     │"
        echo "│ lotserver_max_cwnd   │ Maximum congestion window (packets)     │"
        echo "│ lotserver_beta       │ Fairness factor /1024 (717 = 70%)       │"
        echo "│ lotserver_adaptive   │ Enable adaptive mode (0/1)              │"
        echo "│ lotserver_turbo      │ Enable turbo mode (0/1)                 │"
        echo "│ lotserver_verbose    │ Enable verbose logging (0/1)            │"
        echo "│ lotserver_safe_mode  │ Enable safe mode (0/1)                  │"
        echo "└──────────────────────┴─────────────────────────────────────────┘"
        echo ""
        echo "Examples:"
        echo "  lotspeed set lotserver_rate 1250000000       # 10Gbps cap"
        echo "  lotspeed set lotserver_start_rate 6250000    # 50Mbps start"
        echo "  lotspeed set lotserver_gain 25               # 2.5x gain"
        echo "  lotspeed set lotserver_beta 819              # 80% fairness"
        echo "  lotspeed set lotserver_turbo 1               # Enable turbo"
        echo "  lotspeed set lotserver_safe_mode 0           # Disable safe mode"
        exit 1
    fi

    PARAM_FILE="/sys/module/lotspeed/parameters/$PARAM"
    if [[ -f "$PARAM_FILE" ]]; then
        OLD_VALUE=$(cat $PARAM_FILE)
        echo $VALUE > $PARAM_FILE 2>/dev/null || {
            echo -e "${RED}Error: Failed to set parameter (invalid value?)${NC}"
            exit 1
        }

        # 特殊显示某些参数
        case $PARAM in
            lotserver_rate|lotserver_start_rate)
                formatted=$(format_bytes $VALUE)
                bps=$(format_bps $VALUE)
                echo -e "${GREEN}✓ Set $PARAM = $formatted ($bps)${NC}"
                echo -e "  Previous value: $(format_bytes $OLD_VALUE)"
                ;;
            lotserver_gain)
                gain_x=$((VALUE / 10))
                gain_frac=$((VALUE % 10))
                echo -e "${GREEN}✓ Set $PARAM = ${gain_x}.${gain_frac}x${NC}"
                echo -e "  Previous value: $OLD_VALUE"
                ;;
            lotserver_beta)
                beta_val=$((VALUE * 100 / 1024))
                echo -e "${GREEN}✓ Set $PARAM = ${beta_val}% fairness${NC}"
                echo -e "  Previous value: $OLD_VALUE"
                ;;
            *)
                echo -e "${GREEN}✓ Set $PARAM = $VALUE${NC}"
                echo -e "  Previous value: $OLD_VALUE"
                ;;
        esac
    else
        echo -e "${RED}Error: Parameter $PARAM not found${NC}"
        echo "Run 'lotspeed set' to see available parameters"
        exit 1
    fi
}

case "$ACTION" in
    start)
        if lsmod | grep -q lotspeed; then
            echo -e "${YELLOW}LotSpeed v$VERSION module is already loaded${NC}"
            CURRENT=$(sysctl -n net.ipv4.tcp_congestion_control)
            if [[ "$CURRENT" != "lotspeed" ]]; then
                echo -e "${CYAN}Switching algorithm to lotspeed...${NC}"
                sysctl -w net.ipv4.tcp_congestion_control=lotspeed >/dev/null
            fi
        else
            modprobe lotspeed 2>/dev/null || insmod $INSTALL_DIR/lotspeed.ko
            sysctl -w net.ipv4.tcp_congestion_control=lotspeed >/dev/null
        fi
        echo -e "${GREEN}✓ LotSpeed v$VERSION is active${NC}"
        ;;
    stop)
        DEFAULT_ALGO=$(get_default_congestion_control)
        sysctl -w net.ipv4.tcp_congestion_control=$DEFAULT_ALGO >/dev/null 2>&1
        rmmod lotspeed 2>/dev/null || {
            echo -e "${YELLOW}Module is in use, algorithm switched to $DEFAULT_ALGO${NC}"
            exit 0
        }
        echo -e "${GREEN}✓ LotSpeed stopped, using $DEFAULT_ALGO${NC}"
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
        echo -e "${CYAN}Recent LotSpeed kernel logs:${NC}"
        dmesg | grep -i lotspeed | tail -50
        ;;
    monitor)
        echo -e "${CYAN}Monitoring LotSpeed logs (Ctrl+C to stop)...${NC}"
        dmesg -w | grep --color=always -i lotspeed
        ;;
    connections|conns)
        echo -e "${CYAN}Active connections using LotSpeed:${NC}"
        ss -tin | grep lotspeed || echo "No active connections"
        ;;
    uninstall)
        echo -e "${YELLOW}Uninstalling LotSpeed v$VERSION...${NC}"
        $0 stop 2>/dev/null
        rm -rf $INSTALL_DIR
        rm -f /etc/modules-load.d/lotspeed.conf
        rm -f /lib/modules/$(uname -r)/kernel/net/ipv4/lotspeed.ko
        depmod -a
        sed -i '/net.ipv4.tcp_congestion_control=lotspeed/d' /etc/sysctl.conf
        rm -f /usr/local/bin/lotspeed
        echo -e "${GREEN}✓ LotSpeed v$VERSION uninstalled${NC}"
        ;;
    *)
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║            LotSpeed v$VERSION Management Tool                     ║${NC}"
        echo -e "${CYAN}║           Zeta-TCP Auto-Scaling Edition                       ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Usage: lotspeed {command} [options]"
        echo ""
        echo "Commands:"
        echo "  start       - Start LotSpeed"
        echo "  stop        - Stop LotSpeed"
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
        echo "  lotspeed preset conservative  - 1Gbps, 1.5x gain, safe mode"
        echo "  lotspeed preset balanced      - 5Gbps, 2.0x gain [RECOMMENDED]"
        echo "  lotspeed preset aggressive    - 10Gbps, 3.0x gain"
        echo "  lotspeed preset extreme       - 20Gbps, 5.0x gain, TURBO"
        echo "  lotspeed preset vps100m       - For 100Mbps VPS"
        echo "  lotspeed preset debug         - Enable debug logging"
        echo ""
        echo "Key Features in v$VERSION:"
        echo "  • Auto-Scaling: Automatically finds optimal speed"
        echo "  • Soft Start: Starts at 50Mbps, climbs if healthy"
        echo "  • Smart Guard: Loss rate cap & BDP protection"
        echo "  • Zeta Learning: Remembers best settings per destination"
        echo ""
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
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         LotSpeed v$VERSION Installation Complete!                 ║${NC}"
    echo -e "${GREEN}║          Zeta-TCP Auto-Scaling Edition                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # 显示当前状态
    /usr/local/bin/lotspeed status

    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                    Quick Start Guide                        │${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}lotspeed status${NC}           - Check current status            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}lotspeed preset balanced${NC}  - Apply balanced preset (5Gbps)  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}lotspeed preset vps100m${NC}   - For 100Mbps VPS                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}lotspeed monitor${NC}          - Monitor real-time logs         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}lotspeed set${NC}              - View all parameters            ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│                  Recommended Settings                       │${NC}"
    echo -e "${YELLOW}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${YELLOW}│${NC} • VPS/Cloud (≤1Gbps):  ${GREEN}lotspeed preset conservative${NC}        ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} • VPS/Cloud (>1Gbps):  ${GREEN}lotspeed preset balanced${NC}            ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} • Dedicated Server:    ${GREEN}lotspeed preset aggressive${NC}          ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} • Speed Testing:       ${GREEN}lotspeed preset extreme${NC}             ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} • Debug Issues:        ${GREEN}lotspeed preset debug${NC}               ${YELLOW}│${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│              What's New in Version 5.6                      │${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC} ✨ ${WHITE}Auto-Scaling${NC}: Automatically climbs to find true limit   ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ✨ ${WHITE}Soft Start${NC}: Begins at 50Mbps, protects slow clients    ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ✨ ${WHITE}Smart Guard${NC}: Loss rate cap (15%) & BDP protection      ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ✨ ${WHITE}Zeta Learning${NC}: AI-powered destination memory           ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ✨ ${WHITE}Safe Mode${NC}: New protection against network storms       ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${GREEN}Installation Details:${NC}"
    echo "  • Install Path:    $INSTALL_DIR"
    echo "  • Management Tool: /usr/local/bin/lotspeed"
    echo "  • Kernel Module:   /lib/modules/$(uname -r)/kernel/net/ipv4/lotspeed.ko"
    echo "  • Install Time:    $CURRENT_TIME"
    echo "  • Installed By:    $CURRENT_USER"
    echo ""
    echo -e "${CYAN}GitHub:${NC} https://github.com/$GITHUB_REPO"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
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

    echo -e "${CYAN}Starting installation at $CURRENT_TIME${NC}"
    echo -e "${CYAN}Installer: $CURRENT_USER${NC}"
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
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] LotSpeed v$VERSION installed by $CURRENT_USER" >> /var/log/lotspeed_install.log
}

# 执行主函数
main