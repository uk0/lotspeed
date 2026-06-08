#!/bin/bash
#
# LotSpeed v2.2 + NeoQ v3.1 - Complete Network Optimization Suite
# Author: uk0 @ 2025
# GitHub: https://github.com/uk0/lotspeed
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/merge_bl/install.sh | sudo bash
#   Or run locally: sudo bash install.sh
#

set -e

# ================= 配置区域 =================
GITHUB_REPO="uk0/lotspeed"
GITHUB_BRANCH="merge_bl"
INSTALL_DIR="/opt/lotspeed"
VERSION="2.2"
CONFIG_FILE="/etc/lotspeed.conf"
SYSCTL_FILE="/etc/sysctl.d/99-lotspeed.conf"
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')
CURRENT_USER=$(whoami)

# ================= 颜色定义 =================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ================= UI 核心算法 =================
BOX_WIDTH=70

get_width() {
    local str="$1"
    local clean_str=$(echo -e "$str" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" 2>/dev/null || echo "$str")
    echo ${#clean_str}
}

repeat_char() {
    local char="$1"
    local count="$2"
    if [ "$count" -gt 0 ]; then
        printf "%0.s$char" $(seq 1 $count)
    fi
}

print_box_top() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╔"
    repeat_char "═" $((BOX_WIDTH - 2))
    echo -e "╗${NC}"
}

print_box_div() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╟"
    repeat_char "─" $((BOX_WIDTH - 2))
    echo -e "╢${NC}"
}

print_box_bottom() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╚"
    repeat_char "═" $((BOX_WIDTH - 2))
    echo -e "╝${NC}"
}

print_box_row() {
    local content="$1"
    local align="${2:-left}"
    local color="${3:-$CYAN}"

    local content_width=$(get_width "$content")
    local total_padding=$((BOX_WIDTH - 2 - content_width))
    if [ $total_padding -lt 0 ]; then total_padding=0; fi

    echo -ne "${color}║${NC}"
    if [ "$align" == "center" ]; then
        local left_pad=$((total_padding / 2))
        local right_pad=$((total_padding - left_pad))
        repeat_char " " $left_pad
        echo -ne "$content"
        repeat_char " " $right_pad
    else
        echo -ne " $content"
        repeat_char " " $((total_padding - 1))
    fi
    echo -e "${color}║${NC}"
}

print_kv_row() {
    local key="$1"
    local val="$2"
    local color="${3:-$CYAN}"

    local key_width=$(get_width "$key")
    local val_width=$(get_width "$val")
    local available=$((BOX_WIDTH - 4))
    local padding=$((available - key_width - val_width))
    [ $padding -lt 1 ] && padding=1

    echo -ne "${color}║${NC} $key"
    repeat_char " " $padding
    echo -e "$val ${color}║${NC}"
}

# ================= 基础日志函数 =================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      _          _   ____                      _                      ║
║     | |    ___ | |_/ ___| _ __   ___  ___  __| |                     ║
║     | |   / _ \| __\___ \| '_ \ / _ \/ _ \/ _` |                     ║
║     | |__| (_) | |_ ___) | |_) |  __/  __/ (_| |                     ║
║     |_____\___/ \__|____/| .__/ \___|\___|\___|                      ║
║                          |_|                                         ║
║                                                                      ║
║        LotSpeed v2.2 + NeoQ v3.1 Network Optimization Suite          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

# ================= 系统检查函数 =================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${YELLOW}Try: sudo bash $0${NC}"
        exit 1
    fi
}

check_system() {
    log_info "Checking system compatibility..."

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

    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

    if [[ $KERNEL_MAJOR -lt 5 ]]; then
        log_error "Kernel version must be >= 5.0 (current: $(uname -r))"
        exit 1
    fi

    ARCH=$(uname -m)
    log_success "System: $OS $OS_VERSION (kernel $(uname -r), $ARCH)"
}

# ================= 检查旧模块是否已加载 =================

check_old_modules_loaded() {
    local lotspeed_loaded=0
    local neoq_loaded=0
    local lotspeed_ref=0
    local neoq_ref=0

    # 检查 lotspeed 模块
    if lsmod | grep -q "^lotspeed "; then
        lotspeed_loaded=1
        lotspeed_ref=$(lsmod | grep "^lotspeed " | awk '{print $3}')
    fi

    # 检查 sch_neoq 模块
    if lsmod | grep -q "^sch_neoq "; then
        neoq_loaded=1
        neoq_ref=$(lsmod | grep "^sch_neoq " | awk '{print $3}')
    fi

    # 如果任一模块已加载
    if [[ $lotspeed_loaded -eq 1 ]] || [[ $neoq_loaded -eq 1 ]]; then
        echo ""
        print_box_top "${YELLOW}"
        print_box_row "Warning: Old Kernel Modules Detected!" "center" "${YELLOW}"
        print_box_div "${YELLOW}"

        if [[ $lotspeed_loaded -eq 1 ]]; then
            print_kv_row "lotspeed module" "Loaded (ref: $lotspeed_ref)" "${YELLOW}"
        fi
        if [[ $neoq_loaded -eq 1 ]]; then
            print_kv_row "sch_neoq module" "Loaded (ref: $neoq_ref)" "${YELLOW}"
        fi

        print_box_div "${YELLOW}"
        print_box_row "Old modules must be unloaded before reinstalling." "left" "${YELLOW}"
        print_box_row "" "left" "${YELLOW}"
        print_box_row "Please follow these steps:" "left" "${YELLOW}"
        print_box_row "  1. Run: ${CYAN}lotspeed uninstall${NC}" "left" "${YELLOW}"
        print_box_row "  2. ${RED}Reboot${NC} the system" "left" "${YELLOW}"
        print_box_row "  3. ${RED}lsmod check${NC} ${YELLOW}lotspeed${NC} and ${YELLOW}sch_neoq${NC}" "left" "${YELLOW}"
        print_box_row "  4. Run this installer again" "left" "${YELLOW}"
        print_box_div "${YELLOW}"

        # 检查 lotspeed 命令是否存在
        if [[ -x /usr/local/bin/lotspeed ]]; then
            print_box_row "Or run directly:" "left" "${YELLOW}"
            print_box_row "  ${CYAN}lotspeed stop && lotspeed uninstall && sudo reboot${NC}" "left" "${YELLOW}"
            print_box_div "${YELLOW}"
        fi

        print_box_row "Continue anyway? (Not recommended)" "center" "${YELLOW}"
        print_box_bottom "${YELLOW}"

        echo ""
        read -p "Continue installation with modules loaded? [y/N]: " answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            log_info "Installation aborted. Please unload modules and reboot first."
            exit 0
        fi

        echo ""
        log_warn "Proceeding with modules loaded. This may cause issues!"
        log_warn "If installation fails, please reboot and try again."
        echo ""
        sleep 2
    fi
}

install_dependencies() {
    log_info "Installing dependencies..."

    if [[ "$OS" == "centos" ]]; then
        yum install -y gcc make kernel-devel-$(uname -r) kernel-headers-$(uname -r) wget curl bc iproute-tc 2>/dev/null || {
            yum install -y gcc make kernel-devel kernel-headers wget curl bc iproute-tc
        }
    elif [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        apt-get update >/dev/null 2>&1
        apt-get install -y gcc make linux-headers-$(uname -r) wget curl bc iproute2 2>/dev/null || {
            apt-get install -y gcc make linux-headers-generic wget curl bc iproute2
        }
    fi

    log_success "Dependencies installed"
}

# ================= 下载源码 =================

download_source() {
    log_info "Downloading source code..."

    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR

    # 下载 LotSpeed 源码
    curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/refs/heads/$GITHUB_BRANCH/lotspeed.c" -o lotspeed.c || {
        log_error "Failed to download lotspeed.c"
        exit 1
    }

    # 下载 NeoQ 源码
    curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/refs/heads/$GITHUB_BRANCH/qdisc_newneo.c" -o qdisc_newneo.c || {
        log_error "Failed to download qdisc_newneo.c"
        exit 1
    }

    # 下载 Auto-Tune 脚本
    curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/refs/heads/$GITHUB_BRANCH/lotspeed-autotune.sh" -o lotspeed-autotune.sh || {
        log_warn "Failed to download lotspeed-autotune.sh (optional)"
    }
    chmod +x lotspeed-autotune.sh 2>/dev/null || true

    # 创建 Makefile
    cat > Makefile << 'MAKEFILE'
KERNEL_RELEASE  ?= $(shell uname -r)
KERNEL_DIR      ?= /lib/modules/$(KERNEL_RELEASE)/build

obj-m += lotspeed.o
obj-m += sch_neoq.o
sch_neoq-objs := qdisc_newneo.o

ccflags-y := -std=gnu99 -DCONFIG_NET_SCH_DEFAULT

.PHONY: all clean install

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

install: all
	cp lotspeed.ko /lib/modules/$(KERNEL_RELEASE)/kernel/net/ipv4/ 2>/dev/null || true
	cp sch_neoq.ko /lib/modules/$(KERNEL_RELEASE)/kernel/net/sched/ 2>/dev/null || true
	depmod -a
MAKEFILE

    log_success "Source code downloaded"
}

# ================= 编译模块 =================

compile_modules() {
    log_info "Compiling kernel modules..."

    cd $INSTALL_DIR
    make clean >/dev/null 2>&1 || true

    if ! make 2>&1; then
        log_error "Compilation failed"
        exit 1
    fi

    if [[ ! -f lotspeed.ko ]]; then
        log_error "lotspeed.ko not found"
        exit 1
    fi

    if [[ ! -f sch_neoq.ko ]]; then
        log_error "sch_neoq.ko not found"
        exit 1
    fi

    log_success "Modules compiled successfully"
}

# ================= 安装模块 =================

install_modules() {
    log_info "Installing kernel modules..."

    cd $INSTALL_DIR

    # 复制到系统目录
    mkdir -p /lib/modules/$(uname -r)/kernel/net/ipv4/
    mkdir -p /lib/modules/$(uname -r)/kernel/net/sched/
    cp lotspeed.ko /lib/modules/$(uname -r)/kernel/net/ipv4/
    cp sch_neoq.ko /lib/modules/$(uname -r)/kernel/net/sched/
    depmod -a

    log_success "Modules installed"
}

# ================= 获取默认拥塞控制算法（排除 lotspeed）=================

get_default_cc() {
    local available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | grep -v "lotspeed")
    # 优先 bbr
    if echo "$available" | grep -qw "bbr"; then
        echo "bbr"
    elif echo "$available" | grep -qw "cubic"; then
        echo "cubic"
    elif echo "$available" | grep -qw "reno"; then
        echo "reno"
    else
        # 返回第一个可用的
        echo "$available" | head -1
    fi
}

# ================= 获取默认 qdisc（排除 neoq）=================

get_default_qdisc() {
    # 常见的默认 qdisc：fq_codel, pfifo_fast, fq
    local current=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [[ "$current" != "neoq" && -n "$current" ]]; then
        echo "$current"
    elif tc qdisc help 2>&1 | grep -q "fq_codel"; then
        echo "fq_codel"
    elif tc qdisc help 2>&1 | grep -q "fq"; then
        echo "fq"
    else
        echo "pfifo_fast"
    fi
}

# ================= 安全卸载模块 =================

safe_unload_module() {
    local module="$1"
    local algo_name="$2"

    print_box_top "${YELLOW}"
    print_box_row "Unloading: $module" "center" "${YELLOW}"
    print_box_div "${YELLOW}"

    # 1. 切换到默认算法
    local default_cc=$(get_default_cc)
    print_box_row "Switching to $default_cc..." "left" "${YELLOW}"
    sysctl -w net.ipv4.tcp_congestion_control=$default_cc >/dev/null 2>&1

    # 2. 强制卸载模块
    print_box_row "Force unloading module..." "left" "${YELLOW}"
    rmmod $module -f 2>/dev/null || true

    if lsmod | grep -q "^${module} "; then
        print_box_row "${YELLOW}Module still loaded. Reboot required.${NC}" "center" "${YELLOW}"
        print_box_bottom "${YELLOW}"
        return 1
    fi

    print_box_row "${GREEN}Module unloaded successfully${NC}" "center" "${YELLOW}"
    print_box_bottom "${YELLOW}"
    return 0
}

# ================= 创建管理脚本 =================

create_management_script() {
    log_info "Creating management script..."

    cat > /usr/local/bin/lotspeed << 'SCRIPT_EOF'
#!/bin/bash
#
# LotSpeed + NeoQ Management Script
#

INSTALL_DIR="/opt/lotspeed"
CONFIG_FILE="/etc/lotspeed.conf"
SYSCTL_PATH="/proc/sys/net/ipv4/lotspeed"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

BOX_WIDTH=70

get_width() {
    local str="$1"
    local clean_str=$(echo -e "$str" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" 2>/dev/null || echo "$str")
    echo ${#clean_str}
}

repeat_char() {
    if [ "$2" -gt 0 ]; then printf "%0.s$1" $(seq 1 $2); fi
}

print_box_top() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╔"
    repeat_char "═" $((BOX_WIDTH - 2))
    echo -e "╗${NC}"
}

print_box_div() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╟"
    repeat_char "─" $((BOX_WIDTH - 2))
    echo -e "╢${NC}"
}

print_box_bottom() {
    local color="${1:-$CYAN}"
    echo -ne "${color}╚"
    repeat_char "═" $((BOX_WIDTH - 2))
    echo -e "╝${NC}"
}

print_box_row() {
    local content="$1"
    local align="${2:-left}"
    local color="${3:-$CYAN}"
    local content_width=$(get_width "$content")
    local total_padding=$((BOX_WIDTH - 2 - content_width))
    [ $total_padding -lt 0 ] && total_padding=0
    echo -ne "${color}║${NC}"
    if [ "$align" == "center" ]; then
        local left_pad=$((total_padding / 2))
        local right_pad=$((total_padding - left_pad))
        repeat_char " " $left_pad
        echo -ne "$content"
        repeat_char " " $right_pad
    else
        echo -ne " $content"
        repeat_char " " $((total_padding - 1))
    fi
    echo -e "${color}║${NC}"
}

print_kv_row() {
    local key="$1"
    local val="$2"
    local color="${3:-$CYAN}"
    local key_width=$(get_width "$key")
    local val_width=$(get_width "$val")
    local available=$((BOX_WIDTH - 4))
    local padding=$((available - key_width - val_width))
    [ $padding -lt 1 ] && padding=1
    echo -ne "${color}║${NC} $key"
    repeat_char " " $padding
    echo -e "$val ${color}║${NC}"
}

get_default_cc() {
    local available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | grep -v "lotspeed")
    # 优先 bbr
    if echo "$available" | grep -qw "bbr"; then
        echo "bbr"
    elif echo "$available" | grep -qw "cubic"; then
        echo "cubic"
    elif echo "$available" | grep -qw "reno"; then
        echo "reno"
    else
        echo "$available" | head -1
    fi
}

get_default_qdisc() {
    local current=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [[ "$current" != "neoq" && -n "$current" ]]; then
        echo "$current"
    elif tc qdisc help 2>&1 | grep -q "fq_codel"; then
        echo "fq_codel"
    elif tc qdisc help 2>&1 | grep -q "fq"; then
        echo "fq"
    else
        echo "pfifo_fast"
    fi
}

# 安全卸载模块
safe_unload() {
    local module="$1"
    local algo_name="$2"

    # 切换算法
    local default_cc=$(get_default_cc)
    echo -e "${YELLOW}Switching to $default_cc...${NC}"
    sysctl -w net.ipv4.tcp_congestion_control=$default_cc >/dev/null 2>&1

    # 强制卸载模块
    echo -e "${YELLOW}Force unloading $module...${NC}"
    rmmod $module -f 2>/dev/null || true

    if lsmod | grep -q "^${module} "; then
        echo -e "${YELLOW}Module still loaded. Reboot required.${NC}"
        return 1
    fi
    echo -e "${GREEN}Module unloaded.${NC}"
}

# 显示状态
show_status() {
    print_box_top
    print_box_row "LotSpeed v2.2 + NeoQ v3.1 Status" "center"
    print_box_div

    # 当前算法
    local current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    print_kv_row "Active CC Algorithm" "${CYAN}$current${NC}"

    # LotSpeed 模块
    if lsmod | grep -q "^lotspeed "; then
        print_kv_row "LotSpeed Module" "${GREEN}● Loaded${NC}"
        local ref=$(lsmod | grep "^lotspeed " | awk '{print $3}')
        print_kv_row "  Reference Count" "$ref"
    else
        print_kv_row "LotSpeed Module" "${RED}○ Not Loaded${NC}"
    fi

    # NeoQ 模块
    if lsmod | grep -q "^sch_neoq "; then
        print_kv_row "NeoQ Module" "${GREEN}● Loaded${NC}"
        local ref=$(lsmod | grep "^sch_neoq " | awk '{print $3}')
        print_kv_row "  Reference Count" "$ref"
    else
        print_kv_row "NeoQ Module" "${RED}○ Not Loaded${NC}"
    fi

    # NeoQ qdisc
    local neoq_qdisc
    neoq_qdisc=$(tc qdisc show 2>/dev/null | grep -c "neoq" 2>/dev/null) || neoq_qdisc=0
    if [[ "$neoq_qdisc" -gt 0 ]]; then
        print_kv_row "NeoQ Qdisc" "${GREEN}Active on $neoq_qdisc interface(s)${NC}"
    fi

    # sysctl 接口
    if [[ -d "$SYSCTL_PATH" ]]; then
        print_kv_row "LotSpeed sysctl" "${GREEN}Available${NC}"
    fi

    # /proc/net/neoq
    if [[ -f /proc/net/neoq ]]; then
        print_kv_row "NeoQ Stats" "${GREEN}/proc/net/neoq${NC}"
    fi

    print_box_bottom
}

# 交互式菜单
interactive_menu() {
    while true; do
        clear
        print_box_top "${MAGENTA}"
        print_box_row "LotSpeed v2.2 + NeoQ v3.1 Management" "center" "${MAGENTA}"
        print_box_div "${MAGENTA}"

        local current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
        print_kv_row "Current Algorithm" "${CYAN}$current${NC}" "${MAGENTA}"
        print_box_div "${MAGENTA}"

        print_box_row "  ${BOLD}TCP Congestion Control${NC}" "left" "${MAGENTA}"
        print_kv_row "1)" "Enable LotSpeed (BBR v3 Hybrid)" "${MAGENTA}"
        print_kv_row "2)" "Disable LotSpeed (switch to default)" "${MAGENTA}"
        print_box_div "${MAGENTA}"

        print_box_row "  ${BOLD}Queue Discipline (NeoQ)${NC}" "left" "${MAGENTA}"
        print_kv_row "3)" "Enable NeoQ on interface" "${MAGENTA}"
        print_kv_row "4)" "Disable NeoQ on interface" "${MAGENTA}"
        print_kv_row "5)" "Show NeoQ statistics" "${MAGENTA}"
        print_box_div "${MAGENTA}"

        print_box_row "  ${BOLD}Module Management${NC}" "left" "${MAGENTA}"
        print_kv_row "6)" "Load all modules" "${MAGENTA}"
        print_kv_row "7)" "Disable all (switch to default)" "${MAGENTA}"
        print_box_div "${MAGENTA}"

        print_box_row "  ${BOLD}Other${NC}" "left" "${MAGENTA}"
        print_kv_row "8)" "Show status" "${MAGENTA}"
        print_kv_row "9)" "LotSpeed parameters" "${MAGENTA}"
        print_kv_row "0)" "Exit" "${MAGENTA}"
        print_box_bottom "${MAGENTA}"

        echo ""
        read -p "Select option [0-9]: " choice

        case $choice in
            1)
                echo ""
                if ! lsmod | grep -q "^lotspeed "; then
                    echo -e "${YELLOW}Loading LotSpeed module...${NC}"
                    modprobe lotspeed 2>/dev/null || insmod $INSTALL_DIR/lotspeed.ko
                    sleep 1
                fi
                sysctl -w net.ipv4.tcp_congestion_control=lotspeed
                echo -e "${GREEN}LotSpeed enabled!${NC}"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                safe_unload "lotspeed" "lotspeed"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                echo -e "${CYAN}Available interfaces:${NC}"
                ip -o link show | awk -F': ' '{print "  " $2}'
                echo ""
                read -p "Enter interface name (e.g., eth0): " iface
                if [[ -n "$iface" ]]; then
                    if ! lsmod | grep -q "^sch_neoq "; then
                        echo -e "${YELLOW}Loading NeoQ module...${NC}"
                        modprobe sch_neoq 2>/dev/null || insmod $INSTALL_DIR/sch_neoq.ko
                        sleep 1
                    fi
                    tc qdisc replace dev $iface root neoq
                    echo -e "${GREEN}NeoQ enabled on $iface${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                echo -e "${CYAN}Interfaces with NeoQ:${NC}"
                tc qdisc show 2>/dev/null | grep neoq | awk '{print "  " $5}'
                echo ""
                read -p "Enter interface name: " iface
                if [[ -n "$iface" ]]; then
                    tc qdisc del dev $iface root 2>/dev/null
                    echo -e "${GREEN}NeoQ disabled on $iface${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                echo ""
                if [[ -f /proc/net/neoq ]]; then
                    cat /proc/net/neoq
                else
                    echo -e "${RED}NeoQ not active${NC}"
                fi
                echo ""
                tc -s qdisc show 2>/dev/null | grep -A 20 neoq || true
                read -p "Press Enter to continue..."
                ;;
            6)
                echo ""
                echo -e "${YELLOW}Loading modules...${NC}"
                modprobe lotspeed 2>/dev/null || insmod $INSTALL_DIR/lotspeed.ko 2>/dev/null || true
                modprobe sch_neoq 2>/dev/null || insmod $INSTALL_DIR/sch_neoq.ko 2>/dev/null || true
                sleep 1
                echo -e "${GREEN}Modules loaded.${NC}"
                lsmod | grep -E "lotspeed|sch_neoq" || echo "No modules loaded"
                read -p "Press Enter to continue..."
                ;;
            7)
                echo ""
                # 切换到默认算法
                local default_cc=$(get_default_cc)
                echo -e "${YELLOW}Switching CC to $default_cc...${NC}"
                sysctl -w net.ipv4.tcp_congestion_control=$default_cc >/dev/null 2>&1

                # 还原 NeoQ qdisc 到默认
                echo -e "${YELLOW}Restoring default qdisc...${NC}"
                local default_qdisc=$(get_default_qdisc)
                for iface in $(tc qdisc show 2>/dev/null | grep neoq | awk '{print $5}'); do
                    tc qdisc replace dev $iface root $default_qdisc 2>/dev/null || \
                    tc qdisc del dev $iface root 2>/dev/null || true
                done

                echo -e "${GREEN}Algorithm switched to $default_cc${NC}"
                echo -e "${YELLOW}Kernel modules are still loaded in memory${NC}"
                echo -e "${YELLOW}To fully unload, reboot then run:${NC}"
                echo -e "${CYAN} lotspeed uninstall ${NC}"
                read -p "Press Enter to continue..."
                ;;
            8)
                echo ""
                show_status
                read -p "Press Enter to continue..."
                ;;
            9)
                echo ""
                if [[ -d "$SYSCTL_PATH" ]]; then
                    print_box_top
                    print_box_row "LotSpeed Parameters" "center"
                    print_box_div
                    for f in $SYSCTL_PATH/*; do
                        if [[ -f "$f" ]]; then
                            local name=$(basename "$f")
                            local val=$(cat "$f" 2>/dev/null)
                            print_kv_row "$name" "$val"
                        fi
                    done
                    print_box_bottom
                else
                    echo -e "${RED}LotSpeed sysctl interface not available${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            0|q|Q)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# ================= 参数操作函数 =================

# 读取 sysctl 参数
get_param() {
    local param="$1"
    if [[ -f "$SYSCTL_PATH/$param" ]]; then
        cat "$SYSCTL_PATH/$param" 2>/dev/null
    else
        echo "N/A"
    fi
}

# 设置 sysctl 参数
set_param() {
    local param="$1"
    local value="$2"
    if [[ -f "$SYSCTL_PATH/$param" ]]; then
        echo "$value" > "$SYSCTL_PATH/$param" 2>/dev/null
        return $?
    else
        return 1
    fi
}

# 保存当前配置到文件
save_config() {
    print_box_top "${GREEN}"
    print_box_row "Saving Configuration" "center" "${GREEN}"
    print_box_div "${GREEN}"

    # 创建配置文件
    echo "# LotSpeed v2.0 Configuration" > $CONFIG_FILE
    echo "# Saved at $(date '+%Y-%m-%d %H:%M:%S')" >> $CONFIG_FILE
    echo "" >> $CONFIG_FILE

    # 同时创建 sysctl.d 配置用于开机自动加载
    local SYSCTL_CONF="/etc/sysctl.d/99-lotspeed.conf"
    echo "# LotSpeed v2.0 sysctl configuration" > $SYSCTL_CONF
    echo "# Auto-generated at $(date '+%Y-%m-%d %H:%M:%S')" >> $SYSCTL_CONF
    echo "" >> $SYSCTL_CONF

    local count=0
    for param_file in $SYSCTL_PATH/*; do
        if [[ -f "$param_file" ]]; then
            local param=$(basename "$param_file")
            local value=$(cat "$param_file" 2>/dev/null)
            echo "$param = $value" >> $CONFIG_FILE
            echo "net.ipv4.lotspeed.$param = $value" >> $SYSCTL_CONF
            ((count++))
        fi
    done

    print_kv_row "Config File" "$CONFIG_FILE" "${GREEN}"
    print_kv_row "Sysctl File" "$SYSCTL_CONF" "${GREEN}"
    print_kv_row "Parameters Saved" "$count" "${GREEN}"
    print_box_div "${GREEN}"
    print_box_row "${GREEN}Config will be loaded on boot${NC}" "center" "${GREEN}"
    print_box_bottom "${GREEN}"
}

# 从文件加载配置
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    print_box_top "${CYAN}"
    print_box_row "Loading Configuration" "center" "${CYAN}"
    print_box_div "${CYAN}"

    local count=0
    local failed=0

    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # 解析 key = value
        if [[ "$line" =~ ^([a-z_]+)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            local param="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"
            value=$(echo "$value" | sed 's/[[:space:]]*$//')

            if set_param "$param" "$value"; then
                ((count++))
            else
                ((failed++))
            fi
        fi
    done < "$CONFIG_FILE"

    print_kv_row "Loaded" "${GREEN}$count${NC}" "${CYAN}"
    if [[ $failed -gt 0 ]]; then
        print_kv_row "Failed" "${RED}$failed${NC}" "${CYAN}"
    fi
    print_box_bottom "${CYAN}"
}

# 设置单个参数
set_single_param() {
    local param="$1"
    local value="$2"

    if [[ -z "$param" ]] || [[ -z "$value" ]]; then
        print_box_top "${RED}"
        print_box_row "Parameter Set Error" "center" "${RED}"
        print_box_div "${RED}"
        print_box_row "Usage: lotspeed set <param> <value>" "left" "${RED}"
        print_box_div "${RED}"
        print_box_row "Examples:" "left" "${RED}"
        print_kv_row "lotspeed set min_cwnd 4" "" "${RED}"
        print_kv_row "lotspeed set fast_alpha 25" "" "${RED}"
        print_kv_row "lotspeed set hd_enable 1" "" "${RED}"
        print_kv_row "lotspeed set ecn_enable 0" "" "${RED}"
        print_box_bottom "${RED}"
        return 1
    fi

    if set_param "$param" "$value"; then
        print_box_top "${GREEN}"
        print_box_row "Parameter Updated" "center" "${GREEN}"
        print_box_div "${GREEN}"
        print_kv_row "$param" "$value" "${GREEN}"
        print_box_div "${GREEN}"
        print_box_row "Use 'lotspeed save' to persist" "center" "${GREEN}"
        print_box_bottom "${GREEN}"
    else
        echo -e "${RED}Error: Failed to set $param${NC}"
        echo -e "${YELLOW}Check if parameter exists: ls $SYSCTL_PATH/${NC}"
        return 1
    fi
}

# 显示所有参数
show_all_params() {
    print_box_top
    print_box_row "LotSpeed Parameters" "center"
    print_box_div

    if [[ ! -d "$SYSCTL_PATH" ]]; then
        print_box_row "${RED}LotSpeed not loaded${NC}" "center"
        print_box_bottom
        return 1
    fi

    for param_file in $SYSCTL_PATH/*; do
        if [[ -f "$param_file" ]]; then
            local param=$(basename "$param_file")
            local value=$(cat "$param_file" 2>/dev/null)
            print_kv_row "$param" "$value"
        fi
    done

    print_box_bottom
}

# 应用预设配置
apply_preset() {
    local preset="$1"

    print_box_top
    print_box_row "Applying Preset: $preset" "center"
    print_box_div

    case $preset in
        conservative)
            set_param min_cwnd 4
            set_param max_cwnd 10000
            set_param beta 768
            set_param fast_alpha 15
            set_param fast_gamma 40
            set_param hd_enable 1
            set_param brave_enable 1
            set_param ecn_enable 1
            set_param fast_path 1
            # RACK-TLP
            set_param rack_enable 1
            set_param rack_reord_thresh 4
            set_param tlp_enable 1
            set_param tlp_timeout_div 2
            # Hybla
            set_param hybla_gain_exp 120
            set_param hybla_rtt_floor 25000
            print_box_row "Conservative: Low aggression, high fairness" "left"
            ;;
        balanced)
            set_param min_cwnd 4
            set_param max_cwnd 15000
            set_param beta 717
            set_param fast_alpha 20
            set_param fast_gamma 50
            set_param hd_enable 1
            set_param hd_cwnd_gain 150
            set_param brave_enable 1
            set_param ecn_enable 1
            set_param fast_path 1
            # RACK-TLP
            set_param rack_enable 1
            set_param rack_reord_thresh 4
            set_param rack_min_rtt_div 8
            set_param tlp_enable 1
            set_param tlp_timeout_div 2
            set_param tlp_max_probes 2
            # Hybla
            set_param hybla_gain_exp 150
            set_param hybla_rtt_floor 20000
            print_box_row "Balanced: Default settings" "left"
            ;;
        aggressive)
            set_param min_cwnd 4
            set_param max_cwnd 20000
            set_param beta 614
            set_param fast_alpha 30
            set_param fast_gamma 60
            set_param hd_enable 1
            set_param hd_cwnd_gain 200
            set_param hd_pacing_gain 150
            set_param brave_enable 1
            set_param brave_floor_pct 90
            set_param ecn_enable 1
            set_param fast_path 1
            # RACK-TLP
            set_param rack_enable 1
            set_param rack_reord_thresh 3
            set_param tlp_enable 1
            set_param tlp_timeout_div 2
            set_param tlp_max_probes 3
            # Hybla
            set_param hybla_gain_exp 180
            set_param hybla_rtt_floor 15000
            print_box_row "Aggressive: High throughput, more queue" "left"
            ;;
        highdelay)
            set_param min_cwnd 10
            set_param max_cwnd 20000
            set_param beta 717
            set_param fast_alpha 30
            set_param fast_gamma 60
            set_param hd_enable 1
            set_param hd_thresh_us 100000
            set_param hd_cwnd_gain 200
            set_param hd_pacing_gain 150
            set_param hd_min_cwnd 20
            set_param hd_startup_boost 80
            set_param brave_enable 1
            set_param brave_hold_ms 500
            set_param ecn_enable 0
            set_param fast_path 1
            # RACK-TLP
            set_param rack_enable 1
            set_param rack_reord_thresh 6
            set_param rack_min_rtt_div 10
            set_param tlp_enable 1
            set_param tlp_timeout_div 2
            set_param tlp_max_probes 2
            # Hybla
            set_param hybla_gain_exp 150
            set_param hybla_rtt_floor 15000
            print_box_row "High-Delay: Satellite/intercontinental" "left"
            ;;
        datacenter)
            set_param min_cwnd 4
            set_param max_cwnd 10000
            set_param beta 768
            set_param fast_alpha 10
            set_param fast_gamma 30
            set_param hd_enable 0
            set_param brave_enable 0
            set_param ecn_enable 1
            set_param ecn_factor 90
            set_param ecn_max_rtt_us 10000
            set_param fast_path 1
            # RACK-TLP
            set_param rack_enable 1
            set_param rack_reord_thresh 2
            set_param rack_min_rtt_div 4
            set_param tlp_enable 1
            set_param tlp_timeout_div 2
            set_param tlp_max_probes 3
            # Hybla (disabled for datacenter)
            set_param hybla_gain_exp 100
            set_param hybla_rtt_floor 50000
            print_box_row "Datacenter: Low latency, ECN-focused" "left"
            ;;
        *)
            print_box_row "${RED}Unknown preset: $preset${NC}" "left"
            print_box_div
            print_box_row "Available presets:" "left"
            print_kv_row "conservative" "Safe, fair with other flows"
            print_kv_row "balanced" "Default settings"
            print_kv_row "aggressive" "High throughput"
            print_kv_row "highdelay" "Satellite/intercontinental"
            print_kv_row "datacenter" "Low latency, ECN"
            print_box_bottom
            return 1
            ;;
    esac

    print_box_div
    print_box_row "${GREEN}Preset applied. Use 'lotspeed save' to persist.${NC}" "center"
    print_box_bottom
}

# 编辑配置文件
edit_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${YELLOW}Config file not found, creating from current...${NC}"
        save_config
    fi

    local editor=${EDITOR:-nano}
    if ! command -v $editor &>/dev/null; then
        editor=vi
    fi

    $editor $CONFIG_FILE

    echo ""
    read -p "Load the edited config now? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        load_config
        save_config
    fi
}

# 创建默认配置
create_default_config() {
    cat > $CONFIG_FILE << 'DEFCONF'
# LotSpeed v2.2 Configuration File
# BBR v3 + FAST TCP + Hybla Hybrid Edition

# ============== 基础参数 ==============
min_cwnd = 4
max_cwnd = 15000
beta = 717

# ============== FAST TCP 延迟控制 ==============
fast_alpha = 20
fast_gamma = 50

# ============== 高延迟优化 (Hybla) ==============
hd_enable = 1
hd_thresh_us = 150000
hd_ref_us = 50000
hd_boost = 25
hd_rho_max = 400
hd_cwnd_gain = 150
hd_pacing_gain = 130
hd_min_cwnd = 10
hd_startup_boost = 50

# ============== 勇敢模式 (抗抖动) ==============
brave_enable = 1
brave_rtt_pct = 25
brave_hold_ms = 300
brave_floor_pct = 85

# ============== ECN 支持 ==============
ecn_enable = 1
ecn_factor = 85
ecn_alpha_gain = 16
ecn_thresh = 50

# ============== 启动优化 ==============
turbo_startup = 1
startup_gain = 300

# ============== 快速路径 ==============
fast_path = 1

# ============== RACK-TLP 快速丢包检测 ==============
rack_enable = 1
rack_reord_thresh = 4
rack_min_rtt_div = 8
tlp_enable = 1
tlp_timeout_div = 2
tlp_max_probes = 2

# ============== Hybla 增强 ==============
hybla_gain_exp = 150
hybla_rtt_floor = 20000
DEFCONF
    echo -e "${GREEN}Default config created at $CONFIG_FILE${NC}"
}

# 快速命令
case "$1" in
    start)
        # 加载模块（如果未加载）
        if ! lsmod | grep -q "^lotspeed "; then
            modprobe lotspeed 2>/dev/null || insmod $INSTALL_DIR/lotspeed.ko 2>/dev/null || {
                echo -e "${RED}Failed to load lotspeed module${NC}"
                exit 1
            }
            sleep 1
        fi
        # 切换算法
        sysctl -w net.ipv4.tcp_congestion_control=lotspeed >/dev/null 2>&1
        # 加载保存的配置
        if [[ -f "$CONFIG_FILE" ]]; then
            load_config
        fi
        echo -e "${GREEN}LotSpeed started (CC: lotspeed)${NC}"
        ;;
    stop)
        # 只切换算法，不卸载模块
        _default_cc=$(get_default_cc)
        sysctl -w net.ipv4.tcp_congestion_control=$_default_cc >/dev/null 2>&1
        echo -e "${GREEN}LotSpeed stopped (CC: $_default_cc)${NC}"
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    neoq-start)
        iface="${2:-eth0}"
        modprobe sch_neoq 2>/dev/null || insmod $INSTALL_DIR/sch_neoq.ko
        sleep 1
        tc qdisc replace dev $iface root neoq
        echo -e "${GREEN}NeoQ started on $iface${NC}"
        ;;
    neoq-stop)
        iface="${2:-eth0}"
        tc qdisc del dev $iface root 2>/dev/null
        echo -e "${GREEN}NeoQ stopped on $iface${NC}"
        ;;
    neoq-stats)
        cat /proc/net/neoq 2>/dev/null || echo "NeoQ not active"
        ;;
    status)
        show_status
        ;;
    params|all)
        show_all_params
        ;;
    set)
        set_single_param "$2" "$3"
        ;;
    save)
        save_config
        ;;
    load)
        load_config
        ;;
    edit)
        edit_config
        ;;
    preset)
        apply_preset "$2"
        ;;
    default-config)
        create_default_config
        ;;
    log|logs)
        print_box_top
        print_box_row "Kernel Logs (Last 20)" "center"
        print_box_bottom
        dmesg | grep -iE "lotspeed|neoq" | tail -20
        ;;
    monitor)
        echo -e "${CYAN}Monitoring logs (Ctrl+C to stop)...${NC}"
        dmesg -w | grep --color=always -iE "lotspeed|neoq"
        ;;
    menu|interactive|"")
        interactive_menu
        ;;
    uninstall)
        print_box_top "${RED}"
        print_box_row "Uninstalling LotSpeed + NeoQ" "center" "${RED}"
        print_box_div "${RED}"

        # ========== 步骤 1: 停止并清理 autotune 脚本 ==========
        print_box_row "Step 1: Stopping autotune daemon..." "left" "${RED}"
        if [[ -f /var/run/lotspeed-autotune.pid ]]; then
            kill $(cat /var/run/lotspeed-autotune.pid) 2>/dev/null || true
            rm -f /var/run/lotspeed-autotune.pid
        fi
        pkill -f "lotspeed-autotune" 2>/dev/null || true

        # ========== 步骤 2: 停止并删除 systemd 服务 ==========
        print_box_row "Step 2: Removing systemd service..." "left" "${RED}"
        systemctl stop lotspeed.service 2>/dev/null || true
        systemctl disable lotspeed.service 2>/dev/null || true
        rm -f /etc/systemd/system/lotspeed.service
        systemctl daemon-reload 2>/dev/null || true

        # ========== 步骤 3: 切换到默认拥塞控制算法 ==========
        _default_cc=$(get_default_cc)
        print_box_row "Step 3: Switching CC to $_default_cc..." "left" "${RED}"
        sysctl -w net.ipv4.tcp_congestion_control=$_default_cc >/dev/null 2>&1

        # ========== 步骤 4: 还原 qdisc 到默认值 ==========
        print_box_row "Step 4: Restoring default qdisc..." "left" "${RED}"
        _default_qdisc=$(get_default_qdisc)
        for iface in $(tc qdisc show 2>/dev/null | grep neoq | awk '{print $5}'); do
            tc qdisc replace dev $iface root $_default_qdisc 2>/dev/null || \
            tc qdisc del dev $iface root 2>/dev/null || true
        done
        if [[ -n "$_default_qdisc" ]]; then
            sysctl -w net.core.default_qdisc=$_default_qdisc >/dev/null 2>&1 || true
        fi

        # ========== 步骤 5: 清理所有文件 ==========
        print_box_row "Step 5: Cleaning up all files..." "left" "${RED}"
        # 清理管理工具
        rm -f /usr/local/bin/lotspeed
        rm -f /usr/local/bin/lotspeed-autotune
        # 清理源码和编译目录
        rm -rf $INSTALL_DIR
        # 清理模块加载配置
        rm -f /etc/modules-load.d/lotspeed.conf
        rm -f /etc/modules-load.d/sch_neoq.conf
        # 清理 sysctl 配置
        rm -f $CONFIG_FILE
        rm -f /etc/sysctl.d/99-lotspeed.conf
        sed -i '/net.ipv4.tcp_congestion_control=lotspeed/d' /etc/sysctl.conf 2>/dev/null || true
        sed -i '/net.core.default_qdisc=neoq/d' /etc/sysctl.conf 2>/dev/null || true
        # 清理内核模块文件（所有内核版本）
        rm -f /lib/modules/*/kernel/net/ipv4/lotspeed.ko 2>/dev/null || true
        rm -f /lib/modules/*/kernel/net/sched/sch_neoq.ko 2>/dev/null || true
        rm -f /lib/modules/*/extra/lotspeed.ko 2>/dev/null || true
        rm -f /lib/modules/*/extra/sch_neoq.ko 2>/dev/null || true
        # 清理日志和临时文件
        rm -f /var/log/lotspeed-autotune.log
        rm -f /tmp/lotspeed-autotune.*
        rm -f /var/log/lotspeed_install.log
        # 更新模块依赖
        depmod -a 2>/dev/null || true

        # ========== 完成提示 ==========
        print_box_div "${RED}"
        print_box_row "${GREEN}Uninstall completed!${NC}" "center" "${RED}"
        print_box_div "${RED}"
        print_box_row "${YELLOW}Kernel modules are still loaded in memory${NC}" "center" "${RED}"
        print_box_row "Please reboot, then run:" "center" "${RED}"
        print_box_div "${RED}"
        print_box_row "${CYAN}sudo rmmod lotspeed${NC}" "left" "${RED}"
        print_box_row "${CYAN}sudo rmmod sch_neoq${NC}" "left" "${RED}"
        print_box_bottom "${RED}"
        ;;
    autotune)
        # 调用 autotune 脚本
        if [[ -x /usr/local/bin/lotspeed-autotune ]]; then
            shift
            /usr/local/bin/lotspeed-autotune "$@"
        elif [[ -x $INSTALL_DIR/lotspeed-autotune.sh ]]; then
            shift
            $INSTALL_DIR/lotspeed-autotune.sh "$@"
        else
            echo -e "${RED}lotspeed-autotune not found${NC}"
            exit 1
        fi
        ;;
    help|--help|-h)
        print_box_top
        print_box_row "LotSpeed v2.2 + NeoQ v3.1 Commands" "center"
        print_box_div
        print_box_row "${BOLD}Basic Commands${NC}" "left"
        print_kv_row "lotspeed" "Interactive menu"
        print_kv_row "lotspeed start" "Enable LotSpeed CC"
        print_kv_row "lotspeed stop" "Disable LotSpeed CC"
        print_kv_row "lotspeed restart" "Restart LotSpeed"
        print_kv_row "lotspeed status" "Show all status"
        print_box_div
        print_box_row "${BOLD}NeoQ Qdisc${NC}" "left"
        print_kv_row "lotspeed neoq-start [iface]" "Enable NeoQ qdisc"
        print_kv_row "lotspeed neoq-stop [iface]" "Disable NeoQ qdisc"
        print_kv_row "lotspeed neoq-stats" "Show NeoQ statistics"
        print_box_div
        print_box_row "${BOLD}Parameter Management${NC}" "left"
        print_kv_row "lotspeed params" "Show all parameters"
        print_kv_row "lotspeed set <k> <v>" "Set single parameter"
        print_kv_row "lotspeed preset <name>" "Apply preset config"
        print_kv_row "lotspeed save" "Save current config"
        print_kv_row "lotspeed load" "Load saved config"
        print_kv_row "lotspeed edit" "Edit config file"
        print_box_div
        print_box_row "${BOLD}Other${NC}" "left"
        print_kv_row "lotspeed log" "Show kernel logs"
        print_kv_row "lotspeed monitor" "Live log monitoring"
        print_kv_row "lotspeed autotune" "Auto-tune network params"
        print_kv_row "lotspeed uninstall" "Remove everything"
        print_box_div
        print_box_row "Presets: conservative, balanced, aggressive," "left"
        print_box_row "         highdelay, datacenter" "left"
        print_box_bottom
        ;;
    *)
        echo "Unknown command: $1"
        echo "Run 'lotspeed help' for usage"
        exit 1
        ;;
esac
SCRIPT_EOF

    chmod +x /usr/local/bin/lotspeed
    log_success "Management script created at /usr/local/bin/lotspeed"

    # 安装 autotune 脚本
    if [[ -f "$INSTALL_DIR/lotspeed-autotune.sh" ]]; then
        cp "$INSTALL_DIR/lotspeed-autotune.sh" /usr/local/bin/lotspeed-autotune
        chmod +x /usr/local/bin/lotspeed-autotune
        log_success "Autotune script installed at /usr/local/bin/lotspeed-autotune"
    fi
}

# ================= 创建 systemd 服务 =================

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/lotspeed.service << 'EOF'
[Unit]
Description=LotSpeed + NeoQ Network Optimization
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/lotspeed start
ExecStop=/usr/local/bin/lotspeed stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable lotspeed.service >/dev/null 2>&1

    log_success "Systemd service created"
}

# ================= 显示安装完成信息 =================

show_completion() {
    echo ""
    print_box_top "${GREEN}"
    print_box_row "Installation Complete!" "center" "${GREEN}"
    print_box_row "LotSpeed v2.2 + NeoQ v3.1" "center" "${GREEN}"
    print_box_bottom "${GREEN}"

    echo ""
    print_box_top "${CYAN}"
    print_box_row "Quick Start" "center" "${CYAN}"
    print_box_div "${CYAN}"
    print_kv_row "Interactive Menu" "lotspeed" "${CYAN}"
    print_box_div "${CYAN}"
    print_kv_row "Enable LotSpeed" "lotspeed start" "${CYAN}"
    print_kv_row "Enable NeoQ" "lotspeed neoq-start eth0" "${CYAN}"
    print_kv_row "Show Status" "lotspeed status" "${CYAN}"
    print_kv_row "NeoQ Stats" "cat /proc/net/neoq" "${CYAN}"
    print_box_div "${CYAN}"
    print_box_row "Auto-Tune (Network Optimization)" "center" "${CYAN}"
    print_kv_row "Analyze Network" "$INSTALL_DIR/lotspeed-autotune.sh" "${CYAN}"
    print_kv_row "Start Daemon" "$INSTALL_DIR/lotspeed-autotune.sh daemon" "${CYAN}"
    print_box_div "${CYAN}"
    print_box_row "Run 'lotspeed' for interactive menu" "center" "${CYAN}"
    print_box_bottom "${CYAN}"
    echo ""
}

# ================= 交互式安装菜单 =================

interactive_install() {
    # 检测是否通过 curl|bash 运行 (stdin 不是终端)
    if [[ ! -t 0 ]]; then
        log_info "Detected pipe input (curl|bash), running full auto-install..."
        # 重新打开 /dev/tty 用于交互
        exec < /dev/tty 2>/dev/null || {
            # 如果无法打开 tty，自动执行完整安装
            print_banner
            check_root
            check_system
            check_old_modules_loaded
            install_dependencies
            download_source
            compile_modules
            install_modules
            create_management_script
            create_systemd_service
            insmod $INSTALL_DIR/lotspeed.ko 2>/dev/null || true
            insmod $INSTALL_DIR/sch_neoq.ko 2>/dev/null || true
            show_completion
            return 0
        }
    fi

    clear
    print_banner

    # 检查旧模块是否已加载
    check_old_modules_loaded

    print_box_top "${MAGENTA}"
    print_box_row "Installation Options" "center" "${MAGENTA}"
    print_box_div "${MAGENTA}"
    print_kv_row "1)" "Install LotSpeed + NeoQ (Full)" "${MAGENTA}"
    print_kv_row "2)" "Install LotSpeed only" "${MAGENTA}"
    print_kv_row "3)" "Install NeoQ only" "${MAGENTA}"
    print_kv_row "4)" "Uninstall everything" "${MAGENTA}"
    print_kv_row "5)" "Check system status" "${MAGENTA}"
    print_kv_row "0)" "Exit" "${MAGENTA}"
    print_box_bottom "${MAGENTA}"

    echo ""
    read -p "Select option [0-5]: " choice

    case $choice in
        1)
            echo ""
            check_root
            check_system
            install_dependencies
            download_source
            compile_modules
            install_modules
            create_management_script
            create_systemd_service

            # 加载模块
            log_info "Loading modules..."
            insmod $INSTALL_DIR/lotspeed.ko 2>/dev/null || true
            insmod $INSTALL_DIR/sch_neoq.ko 2>/dev/null || true

            show_completion
            ;;
        2)
            echo ""
            check_root
            check_system
            install_dependencies

            mkdir -p $INSTALL_DIR
            cd $INSTALL_DIR
            curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/refs/heads/$GITHUB_BRANCH/lotspeed.c" -o lotspeed.c

            cat > Makefile << 'MF'
obj-m += lotspeed.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
MF
            make
            cp lotspeed.ko /lib/modules/$(uname -r)/kernel/net/ipv4/
            depmod -a
            insmod lotspeed.ko
            sysctl -w net.ipv4.tcp_congestion_control=lotspeed

            create_management_script
            log_success "LotSpeed installed and enabled!"
            ;;
        3)
            echo ""
            check_root
            check_system
            install_dependencies

            mkdir -p $INSTALL_DIR
            cd $INSTALL_DIR
            curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/refs/heads/$GITHUB_BRANCH/qdisc_newneo.c" -o qdisc_newneo.c

            cat > Makefile << 'MF'
obj-m += sch_neoq.o
sch_neoq-objs := qdisc_newneo.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
ccflags-y := -std=gnu99
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
MF
            make
            cp sch_neoq.ko /lib/modules/$(uname -r)/kernel/net/sched/
            depmod -a
            insmod sch_neoq.ko

            create_management_script
            log_success "NeoQ installed!"
            echo -e "${CYAN}Enable with: tc qdisc add dev eth0 root neoq${NC}"
            ;;
        4)
            echo ""
            check_root

            # 如果管理脚本存在，使用它卸载
            if [[ -x /usr/local/bin/lotspeed ]]; then
                /usr/local/bin/lotspeed uninstall
            else
                # 手动卸载
                print_box_top "${RED}"
                print_box_row "Manual Uninstall" "center" "${RED}"
                print_box_div "${RED}"

                # ========== 步骤 1: 停止并清理 autotune 脚本 ==========
                print_box_row "Step 1: Stopping autotune daemon..." "left" "${RED}"
                pkill -f "lotspeed-autotune" 2>/dev/null || true
                rm -f /var/run/lotspeed-autotune.pid

                # ========== 步骤 2: 停止并删除 systemd 服务 ==========
                print_box_row "Step 2: Removing systemd service..." "left" "${RED}"
                systemctl stop lotspeed.service 2>/dev/null || true
                systemctl disable lotspeed.service 2>/dev/null || true
                rm -f /etc/systemd/system/lotspeed.service
                systemctl daemon-reload 2>/dev/null || true

                # ========== 步骤 3: 切换到默认拥塞控制算法 ==========
                local default_cc=$(get_default_cc)
                print_box_row "Step 3: Switching CC to $default_cc..." "left" "${RED}"
                sysctl -w net.ipv4.tcp_congestion_control=$default_cc >/dev/null 2>&1

                # ========== 步骤 4: 还原 qdisc 到默认值 ==========
                print_box_row "Step 4: Restoring default qdisc..." "left" "${RED}"
                local default_qdisc=$(get_default_qdisc)
                for iface in $(tc qdisc show 2>/dev/null | grep neoq | awk '{print $5}'); do
                    tc qdisc replace dev $iface root $default_qdisc 2>/dev/null || \
                    tc qdisc del dev $iface root 2>/dev/null || true
                done
                if [[ -n "$default_qdisc" ]]; then
                    sysctl -w net.core.default_qdisc=$default_qdisc >/dev/null 2>&1 || true
                fi

                # ========== 步骤 5: 清理所有文件 ==========
                print_box_row "Step 5: Cleaning up all files..." "left" "${RED}"
                rm -f /usr/local/bin/lotspeed
                rm -rf $INSTALL_DIR
                rm -f /etc/modules-load.d/lotspeed.conf
                rm -f /etc/modules-load.d/sch_neoq.conf
                rm -f $CONFIG_FILE
                rm -f /etc/sysctl.d/99-lotspeed.conf
                sed -i '/net.ipv4.tcp_congestion_control=lotspeed/d' /etc/sysctl.conf 2>/dev/null || true
                sed -i '/net.core.default_qdisc=neoq/d' /etc/sysctl.conf 2>/dev/null || true
                rm -f /lib/modules/*/kernel/net/ipv4/lotspeed.ko 2>/dev/null || true
                rm -f /lib/modules/*/kernel/net/sched/sch_neoq.ko 2>/dev/null || true
                rm -f /lib/modules/*/extra/lotspeed.ko 2>/dev/null || true
                rm -f /lib/modules/*/extra/sch_neoq.ko 2>/dev/null || true
                rm -f /var/log/lotspeed-autotune.log
                rm -f /tmp/lotspeed-autotune.*
                rm -f /var/log/lotspeed_install.log
                depmod -a 2>/dev/null || true

                # ========== 完成提示 ==========
                print_box_div "${RED}"
                print_box_row "${GREEN}Uninstall completed!${NC}" "center" "${RED}"
                print_box_div "${RED}"
                print_box_row "${YELLOW}Kernel modules are still loaded in memory${NC}" "center" "${RED}"
                print_box_row "Please reboot, then run:" "center" "${RED}"
                print_box_div "${RED}"
                print_box_row "${CYAN}sudo rmmod lotspeed${NC}" "left" "${RED}"
                print_box_row "${CYAN}sudo rmmod sch_neoq${NC}" "left" "${RED}"
                print_box_bottom "${RED}"
            fi
            ;;
        5)
            echo ""
            /usr/local/bin/lotspeed status 2>/dev/null || {
                echo -e "${CYAN}System Information:${NC}"
                echo "  Kernel: $(uname -r)"
                echo "  CC: $(sysctl -n net.ipv4.tcp_congestion_control)"
                echo "  Available: $(sysctl -n net.ipv4.tcp_available_congestion_control)"
                lsmod | grep -E "lotspeed|sch_neoq" && echo "" || echo "  No optimization modules loaded"
            }
            ;;
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            log_error "Invalid option"
            exit 1
            ;;
    esac
}

# ================= 主入口 =================

main() {
    # 如果有参数，直接安装
    if [[ "$1" == "--full" ]] || [[ "$1" == "-f" ]]; then
        clear
        print_banner
        check_root
        check_system
        check_old_modules_loaded
        install_dependencies
        download_source
        compile_modules
        install_modules
        create_management_script
        create_systemd_service
        insmod $INSTALL_DIR/lotspeed.ko 2>/dev/null || true
        insmod $INSTALL_DIR/sch_neoq.ko 2>/dev/null || true
        show_completion
    elif [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  (no args)    Interactive installation menu"
        echo "  --full, -f   Full automatic installation"
        echo "  --help, -h   Show this help"
        exit 0
    else
        # 交互式安装
        interactive_install
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] LotSpeed+NeoQ installed by $CURRENT_USER" >> /var/log/lotspeed_install.log 2>/dev/null || true
}

main "$@"
