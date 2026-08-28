#!/bin/bash
#
# LotSpeed v2.2 + NeoQ v3.1 - installer / bootstrapper
# Author: uk0 @ 2025
# GitHub: https://github.com/uk0/lotspeed
#
# 这个脚本只做引导: 依赖检查 -> 取源码 -> 编译 -> 安装 -> sysctl -> systemd。
# 日常运维全部由 lotspeedctl (Go, 有 80 个测试) 负责; /usr/local/bin/lotspeed
# 只是一层薄包装, 见 install_wrapper()。
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/adaptive-accel/install.sh | sudo bash
#   sudo bash install.sh [--iface ens3] [--force-kernel] [--with-legacy-autotune]
#

set -e

# ================= 配置区域 =================
GITHUB_REPO="uk0/lotspeed"
GITHUB_BRANCH="adaptive-accel"
RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/refs/heads/${GITHUB_BRANCH}"
INSTALL_DIR="/opt/lotspeed"
VERSION="2.2"
SYSCTL_FILE="/etc/sysctl.d/99-lotspeed.conf"
ENV_DIR="/etc/lotspeed"
ENV_FILE="${ENV_DIR}/env"
MODLOAD_FILE="/etc/modules-load.d/lotspeed.conf"
UNIT_NAME="lotspeedctl@.service"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)"

# 命令行开关
IFACE=""                 # --iface: 覆盖自动检测
FORCE_KERNEL=0           # --force-kernel: 跳过内核版本硬门 (仅供测试)
WITH_LEGACY_AUTOTUNE=0   # --with-legacy-autotune: 装回老的 shell 自调优
ASSUME_YES=0             # --full / -f: 不问直接装

# ================= 颜色与日志 =================
# 注意: 这里**只有一份** UI 函数。之前 print_box_* 在 install.sh 和它生成的管理
# 脚本里各存一份拷贝, 改一处漏一处; 现在生成的包装脚本不做画框, 拷贝问题消失。
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }

print_banner() {
    echo -e "${CYAN}== LotSpeed v${VERSION} + NeoQ v3.1 installer ==${NC}"
}

# ================= 参数解析 =================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iface)                 IFACE="$2"; shift 2 ;;
            --force-kernel)          FORCE_KERNEL=1; shift ;;
            --with-legacy-autotune)  WITH_LEGACY_AUTOTUNE=1; shift ;;
            --full|-f|--yes|-y)      ASSUME_YES=1; shift ;;
            --help|-h)
                cat << 'USAGE'
Usage: sudo bash install.sh [options]

  --iface <name>            指定加速网卡 (默认: 自动取默认路由的出接口)
  --force-kernel            跳过内核版本硬门 (6.6+), 仅供测试
  --with-legacy-autotune    额外安装老的 lotspeed-autotune.sh
                            (默认不装: 它与 lotspeedctl optimize 写同一批
                             /proc/sys/net/ipv4/lotspeed/* 参数, 会互相打架)
  --full, -f                非交互, 直接完整安装
  --help, -h                显示本帮助
USAGE
                exit 0 ;;
            *) log_error "未知参数: $1 (--help 看用法)"; exit 1 ;;
        esac
    done
}

# ================= 系统检查 =================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "必须以 root 运行: sudo bash $0"
        exit 1
    fi
}

check_system() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(sed 's/.*release \([0-9]\).*/\1/' /etc/redhat-release)
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"; OS_VERSION=$(cut -d. -f1 /etc/debian_version)
        if grep -qi ubuntu /etc/os-release 2>/dev/null; then
            OS="ubuntu"; OS_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d. -f1)
        fi
    else
        log_error "不支持的发行版"; exit 1
    fi
    check_kernel
    log_success "System: $OS $OS_VERSION (kernel $(uname -r), $(uname -m))"
}

# 内核版本门槛。硬门 6.6, 依据是源码里实际用到的内核 API:
#   - lotspeed.c:2635 register_net_sysctl_sz()      -> 6.6+
#   - lotspeed.c:212  const struct ctl_table *table -> 6.11+ (proc_handler 签名变更)
#   - 文件头自称 "仅支持 Linux Kernel 6.18.2+"
# 老脚本只挡 <5.0, 于是 5.x 机器一路走到 make 才炸, 用户拿到一屏编译错误。
# 6.6-6.10 这一段过硬门但大概率编译失败, 所以单独给一条点名 const ctl_table 的警告;
# 最终以真实编译为准, 不再多加限制。
check_kernel() {
    local kmaj kmin
    kmaj=$(uname -r | cut -d. -f1)
    kmin=$(uname -r | cut -d. -f2 | sed 's/[^0-9].*//')
    : "${kmin:=0}"

    if (( kmaj < 6 || (kmaj == 6 && kmin < 6) )); then
        log_error "内核 $(uname -r) 太老: lotspeed.c 用了 register_net_sysctl_sz() (6.6+)"
        log_error "最低要求 6.6, 推荐 6.18.x"
        if [[ $FORCE_KERNEL -eq 1 ]]; then
            log_warn "--force-kernel: 强行继续, 编译多半会失败"
        else
            log_error "确要尝试请加 --force-kernel"
            exit 1
        fi
    elif (( kmaj == 6 && kmin < 11 )); then
        log_warn "内核 $(uname -r): lotspeed.c:212 使用 const struct ctl_table* (6.11+),"
        log_warn "这个内核上大概率编译失败。继续, 以真实编译结果为准。"
    elif (( kmaj != 6 || kmin != 18 )); then
        log_warn "内核 $(uname -r) 不是验证过的 6.18.x, 以真实编译结果为准。"
    fi
}

# 出接口自动检测。老脚本到处硬编码 eth0, 而 green1 的网卡是 ens3。
# 不用固定的 $5: 有网关时 `ip route get` 输出 "1.1.1.1 via GW dev ens3 src ...",
# 直连时是 "1.1.1.1 dev ens3 src ...", 字段位置会错开一位, 所以按 "dev" 关键字取。
detect_iface() {
    if [[ -n "$IFACE" ]]; then
        log_info "网卡 (--iface 指定): $IFACE"
    else
        IFACE=$(ip -o route get 1.1.1.1 2>/dev/null \
                | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        [[ -z "$IFACE" ]] && IFACE=$(ip -o route show default 2>/dev/null \
                | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        if [[ -z "$IFACE" ]]; then
            log_error "无法检测默认出接口, 请用 --iface <name> 指定"
            exit 1
        fi
        log_info "网卡 (自动检测): $IFACE"
    fi
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        log_error "网卡 $IFACE 不存在"; exit 1
    fi
}

# 已加载旧模块时不硬来: 重新编译不影响在跑的模块, 但最后的 insmod 会失败,
# 而且新旧 .ko 混用行为不可预期。让用户先走 `lotspeed uninstall` 的卸载纪律。
check_modules_loaded() {
    local loaded=""
    lsmod | grep -q "^lotspeed "  && loaded="lotspeed"
    lsmod | grep -q "^sch_neoq "  && loaded="$loaded sch_neoq"
    [[ -z "$loaded" ]] && return 0

    log_warn "检测到已加载的模块:$loaded"
    log_warn "请先执行:  lotspeed uninstall     (必要时重新登录后 lotspeed uninstall --finish)"
    if [[ $ASSUME_YES -eq 1 ]] || [[ ! -t 0 ]]; then
        log_error "非交互模式下拒绝在旧模块仍加载时安装"; exit 1
    fi
    read -r -p "仍要继续? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_info "已中止"; exit 0; }
}

install_dependencies() {
    log_info "安装编译依赖..."
    if [[ "$OS" == "centos" ]]; then
        yum install -y gcc make "kernel-devel-$(uname -r)" "kernel-headers-$(uname -r)" \
            curl bc iproute-tc >/dev/null 2>&1 \
            || yum install -y gcc make kernel-devel kernel-headers curl bc iproute-tc
    else
        apt-get update >/dev/null 2>&1 || true
        apt-get install -y gcc make "linux-headers-$(uname -r)" curl bc iproute2 >/dev/null 2>&1 \
            || apt-get install -y gcc make linux-headers-generic curl bc iproute2
    fi
    if [[ ! -d "/lib/modules/$(uname -r)/build" ]]; then
        log_error "缺少 /lib/modules/$(uname -r)/build (内核头文件), 无法编译"
        exit 1
    fi
    log_success "依赖就绪"
}

# ================= 取源码 =================
# 本地已有同名文件就直接用 (支持离线 / 在 clone 出来的仓库里跑), 否则从 GitHub 拉。
fetch() {
    local name="$1" required="${2:-1}"
    if [[ -f "$SRC_DIR/$name" ]]; then
        cp "$SRC_DIR/$name" "$INSTALL_DIR/$name"; return 0
    fi
    if curl -fsSL "$RAW_BASE/$name" -o "$INSTALL_DIR/$name"; then return 0; fi
    rm -f "$INSTALL_DIR/$name"
    if [[ "$required" == "1" ]]; then log_error "获取 $name 失败"; exit 1; fi
    return 1
}

download_source() {
    log_info "获取源码..."
    mkdir -p "$INSTALL_DIR"
    fetch lotspeed.c
    fetch qdisc_newneo.c
    # DKMS 由另一个 agent 提供 (dkms.conf 描述包, dkms-install.sh 提供 install_dkms())。
    # 两个都是可选: 拿不到就退回一次性 make 安装。
    fetch dkms.conf 0 || true
    [[ $WITH_LEGACY_AUTOTUNE -eq 1 ]] && { fetch lotspeed-autotune.sh 0 || true; }

    cat > "$INSTALL_DIR/Makefile" << 'MAKEFILE'
KERNEL_RELEASE  ?= $(shell uname -r)
KERNEL_DIR      ?= /lib/modules/$(KERNEL_RELEASE)/build

obj-m += lotspeed.o
obj-m += sch_neoq.o
sch_neoq-objs := qdisc_newneo.o

ccflags-y := -std=gnu99 -DCONFIG_NET_SCH_DEFAULT

.PHONY: all clean
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
MAKEFILE
    log_success "源码就绪: $INSTALL_DIR"
}

# ================= 编译 + 安装模块 =================
#
# ---- DKMS ------------------------------------------------------------------
# 之前这里是一段"由另一个 agent 提供 dkms-install.sh"的接口约定, 但那个文件从来
# 没有存在过。`declare -F install_dkms` 于是恒假, DKMS 分支是死代码, 每一次安装都
# 静默走下面的一次性 make —— 也就是这段代码本来要消灭的那个失效模式。现在就地实现,
# 不再依赖第二个文件。
#         返回   = 0 成功 / 非 0 失败
#   两者任一缺失, 或 install_dkms 返回非 0, 都回退到一次性 make 安装 ——
#   回退必须存在: 没有 dkms 的机器上装不上比"内核升级后失效"更糟。
# install_dkms <src_dir> —— 把模块交给 DKMS 管理, 内核升级后自动重建。
# 返回非 0 时调用方回退到一次性 make (那条路必须留着: 装不上比"内核升级后失效"更糟)。
install_dkms() {
    local src="$1" ver="$VERSION" name="lotspeed"
    local dst="/usr/src/${name}-${ver}"

    if ! command -v dkms >/dev/null 2>&1; then
        log_info "安装 dkms..."
        if   command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y dkms >/dev/null 2>&1
        elif command -v dnf     >/dev/null 2>&1; then dnf install -y dkms >/dev/null 2>&1
        elif command -v yum     >/dev/null 2>&1; then yum install -y dkms >/dev/null 2>&1
        fi
        command -v dkms >/dev/null 2>&1 || { log_warn "dkms 装不上"; return 1; }
    fi

    # 同版本残留会让 dkms add 直接失败, 先清干净 (--all: 覆盖所有已建内核)
    dkms remove -m "$name" -v "$ver" --all >/dev/null 2>&1 || true
    rm -rf "$dst"; mkdir -p "$dst"
    # 只铺 DKMS 需要的四个文件。整目录拷会把 .ko/.o/Module.symvers 一起带进
    # /usr/src, dkms 每次重建都从这个目录复制, 陈旧产物会混进构建目录。
    local f
    for f in dkms.conf Makefile lotspeed.c qdisc_newneo.c; do
        [[ -f "$src/$f" ]] || { log_warn "DKMS 源缺 $f"; return 1; }
        cp "$src/$f" "$dst/"
    done

    dkms add     -m "$name" -v "$ver" >/dev/null 2>&1 || true   # 已 add 过不算错
    dkms build   -m "$name" -v "$ver" || { log_warn "dkms build 失败, 见 /var/lib/dkms/$name/$ver/build/make.log"; return 1; }
    dkms install -m "$name" -v "$ver" --force || { log_warn "dkms install 失败"; return 1; }

    # DKMS 装到 updates/dkms/, 而 depmod 的搜索顺序里 updates 先于 kernel。若
    # kernel/net/ 下还留着一份手工装的旧 .ko, 它现在被遮住、看不出问题, 但下次
    # 内核升级 DKMS 只更新 updates/ 那份, 两份就此分叉 —— 而 `modinfo lotspeed`
    # 仍然只报一个路径, 排查时极难发现。装完就删掉手工副本, 让 DKMS 是唯一真相。
    rm -f "/lib/modules/$(uname -r)/kernel/net/ipv4/lotspeed.ko" \
          "/lib/modules/$(uname -r)/kernel/net/sched/sch_neoq.ko" \
          "/lib/modules/$(uname -r)/extra/lotspeed.ko" \
          "/lib/modules/$(uname -r)/extra/sch_neoq.ko"
    depmod -a

    # 装完就地验一次: modprobe 解析到的必须是 DKMS 那份。不验的话, 一个被旧副本
    # 遮蔽的安装会一路"成功"到用户重启才暴露。
    local resolved; resolved=$(modinfo -n lotspeed 2>/dev/null)
    case "$resolved" in
        */updates/dkms/*) log_info "DKMS: modprobe -> $resolved" ;;
        "")               log_warn "装完却解析不到 lotspeed 模块"; return 1 ;;
        *)                log_warn "modprobe 仍解析到 $resolved (非 DKMS 副本)"; return 1 ;;
    esac
    return 0
}

# --------------------------------------------------------------------------
build_and_install_modules() {
    if [[ -f "$INSTALL_DIR/dkms.conf" ]]; then
        log_info "走 DKMS 安装 (内核升级后自动重建)..."
        if install_dkms "$INSTALL_DIR"; then
            log_success "DKMS 安装完成"; return 0
        fi
        log_warn "DKMS 安装失败, 回退到一次性 make 安装 (内核升级后需重装)"
    fi

    log_info "编译内核模块..."
    make -C "$INSTALL_DIR" clean >/dev/null 2>&1 || true
    if ! make -C "$INSTALL_DIR"; then
        log_error "编译失败 (内核 $(uname -r); 本模块在 6.18.x 上验证)"; exit 1
    fi
    [[ -f "$INSTALL_DIR/lotspeed.ko" ]] || { log_error "lotspeed.ko 未生成"; exit 1; }
    [[ -f "$INSTALL_DIR/sch_neoq.ko" ]] || { log_error "sch_neoq.ko 未生成"; exit 1; }

    mkdir -p "/lib/modules/$(uname -r)/kernel/net/ipv4" "/lib/modules/$(uname -r)/kernel/net/sched"
    cp "$INSTALL_DIR/lotspeed.ko" "/lib/modules/$(uname -r)/kernel/net/ipv4/"
    cp "$INSTALL_DIR/sch_neoq.ko" "/lib/modules/$(uname -r)/kernel/net/sched/"
    depmod -a
    log_success "模块已编译并安装"
}

# ================= 安装 lotspeedctl (Go 控制器) =================
# 薄包装把绝大多数子命令转给它, 所以它是运行时依赖。仓库里没有提交预编译二进制,
# 只能本机 go build, 或按 README 在本地交叉编译后 scp 过来。取不到不是致命错误:
# 卸载序列 (lotspeed uninstall) 完全不依赖 lotspeedctl。
install_lotspeedctl() {
    local src=""
    if [[ -d "$SRC_DIR/lotspeedctl" ]]; then
        src="$SRC_DIR/lotspeedctl"
    elif command -v go >/dev/null 2>&1 && curl -fsSL \
         "https://github.com/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.tar.gz" \
         | tar xz -C "$INSTALL_DIR" 2>/dev/null; then
        # 取整包而不是逐个 curl *.go: 文件清单随开发漂移, 硬编码的列表必然过期
        src="$INSTALL_DIR/lotspeed-${GITHUB_BRANCH}/lotspeedctl"
    fi
    if [[ -n "$src" ]] && command -v go >/dev/null 2>&1 \
       && (cd "$src" && CGO_ENABLED=0 go build -o /usr/local/bin/lotspeedctl .); then
        log_success "lotspeedctl -> /usr/local/bin/lotspeedctl"; return 0
    fi
    [[ -x /usr/local/bin/lotspeedctl ]] && { log_info "沿用已存在的 lotspeedctl"; return 0; }
    log_warn "未安装 lotspeedctl (本机无 go, 仓库也没有预编译二进制)。请在开发机上:"
    log_warn "  cd lotspeedctl && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lotspeedctl ."
    log_warn "  scp lotspeedctl root@<host>:/usr/local/bin/"
}

# ================= sysctl 持久化 =================
#
# 老脚本第 20 行声明了 SYSCTL_FILE 之后全文再无引用 —— 持久化是零, 重启即回到
# 发行版默认值。这里真正写出来。
#
# tcp_rmem/tcp_wmem 上限 128MB 是本项目唯一已证的 3.4x 杠杆: 实测把接收端
# tcp_rmem 从 6MB 调到 128MB, 单流吞吐 47 -> 159 Mbps。
# 方向必须说清楚: 本机加速的是**发出**的流量, 而发送窗口受**对端** rmem 约束。
# 这个文件只解决本机侧; 对端 (下游客户端) 的 rmem 要求写在 README/交付文档里。
write_sysctl() {
    log_info "写入 $SYSCTL_FILE ..."

    # tcp_mem 三元组单位是**页**, 不是字节, 而且必须按本机 RAM 算, 不能硬编码。
    # 内核默认 (net/ipv4/tcp.c tcp_init): limit = nr_free_buffer_pages()/16,
    # 即 pressure ~= RAM 的 6.25%。把 rmem/wmem 上限抬到 128MB 之后, 几十条大 BDP
    # 连接就能吃穿这 6.25%; 一旦越过 pressure, 内核开始 tcp_collapse / 剪裁接收
    # 队列 —— green1 实测 TCPRcvCollapsed=127829 就是这条路径, 表现为吞吐塌陷。
    # 取值:
    #   high(硬上限) = RAM/4      TCP 最多吃 25% 内存
    #   pressure     = high*3/4   ~18.75% RAM 起进入内存压力
    #   low          = high/2     ~12.5% RAM 以下完全不回收
    # 留 75% 给 nginx/xray/docker; 这是上限不是预分配, 不占内存。
    local page_kb total_kb pages tm_low tm_pressure tm_high
    page_kb=$(( $(getconf PAGE_SIZE) / 1024 ))
    total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    pages=$(( total_kb / page_kb ))
    tm_high=$(( pages / 4 ))
    tm_pressure=$(( tm_high * 3 / 4 ))
    tm_low=$(( tm_high / 2 ))
    # 极小内存机器兜底: 不要写出比内核默认还小的值
    if (( tm_low < 4096 )); then tm_low=4096; tm_pressure=6144; tm_high=8192; fi

    cat > "$SYSCTL_FILE" << EOF
# LotSpeed v${VERSION} —— 由 install.sh 生成, 卸载时删除
#
# 收发缓冲: 本项目唯一已证的 3.4x 杠杆 (接收端 tcp_rmem 6MB -> 128MB,
# 单流吞吐 47 -> 159 Mbps)。本机加速的是发出的流量, 发送窗口受**对端** rmem
# 约束 —— 本文件只解决本机侧, 对端 (下游客户端) 也要放开 rmem 才吃得到。
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 262144 134217728
net.ipv4.tcp_wmem = 4096 262144 134217728

# tcp_mem 单位是页 (本机 PAGE_SIZE=${page_kb}KB, MemTotal=$((total_kb/1024))MB)。
# 内核默认 pressure ~= RAM/16 = 6.25%; 128MB 的 rmem 上限下几十条连接就能撞上,
# 之后内核开始 tcp_collapse 剪裁接收队列 (green1 实测 TCPRcvCollapsed=127829)。
# 这里按 low=RAM/8, pressure=RAM*3/16, high=RAM/4 重算, 留 75% 给其他服务。
net.ipv4.tcp_mem = ${tm_low} ${tm_pressure} ${tm_high}

# 长活隧道 idle 之后不要把窗口塌回 initcwnd 重新爬
net.ipv4.tcp_slow_start_after_idle = 0

# 丢包恢复全靠内核, 模块**不实现** RACK/TLP (见 commit 9621abc: 那段代码从未
# 执行过, 已删)。硬化过的镜像可能把这些关掉, 所以显式写回。
net.ipv4.tcp_recovery = 1        # RACK
net.ipv4.tcp_early_retrans = 3   # TLP
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_frto = 2            # 降低假 RTO 引发的无谓重传

# 默认拥塞控制。开机顺序: systemd-sysctl.service 有 After=systemd-modules-load.service,
# 而 ${MODLOAD_FILE} 会先把 lotspeed 装进内核, 所以这行在启动时写得进去。
net.ipv4.tcp_congestion_control = lotspeed
EOF

    # 模块开机自动加载 —— 没有它, 上面最后一行在开机时会因为算法不存在而失败
    cat > "$MODLOAD_FILE" << 'EOF'
# 必须早于 systemd-sysctl.service 加载, 否则 99-lotspeed.conf 里的
# net.ipv4.tcp_congestion_control=lotspeed 在开机时写不进去。
lotspeed
sch_neoq
EOF

    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || \
        log_warn "部分 sysctl 现在写不进去 (模块还没加载?), 下次开机会生效"
    log_success "sysctl 已持久化 (tcp_mem = $tm_low $tm_pressure $tm_high 页)"
}

write_env() {
    mkdir -p "$ENV_DIR"
    cat > "$ENV_FILE" << EOF
# 加速网卡。install.sh 自动检测 (默认路由的出接口), 可手工改或重装时 --iface 覆盖。
# systemd 用的是模板单元 lotspeedctl@<iface>.service, 实例名才是真正生效的网卡。
LOTSPEED_IFACE=${IFACE}
EOF
    log_success "$ENV_FILE  (LOTSPEED_IFACE=$IFACE)"
}

# ================= 薄包装 /usr/local/bin/lotspeed =================
# 原来这里是一个 942 行的 heredoc, 里面 status/enable/disable/params/preset/monitor
# 与 lotspeedctl 的子命令全量重复, 却一个测试都没有 (lotspeedctl 有 80 个)。
# 现在只留 lotspeedctl 确实没有的东西: 内核模块装卸 + 卸载纪律。
install_wrapper() {
    cat > /usr/local/bin/lotspeed << 'WRAPPER_EOF'
#!/bin/bash
# lotspeed —— 薄包装。绝大多数子命令直接转发给 lotspeedctl (它有 80 个测试),
# 这里只保留 lotspeedctl 做不到的运维动作: 内核模块装卸 + 卸载纪律。
CTL=/usr/local/bin/lotspeedctl; INSTALL_DIR=/opt/lotspeed; SYSCTL_FILE=/etc/sysctl.d/99-lotspeed.conf
[ -r /etc/lotspeed/env ] && . /etc/lotspeed/env
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
say(){ echo -e "$*"; }
need_root(){ [ "$(id -u)" = 0 ] || { say "${R}需要 root${N}"; exit 1; }; }
ctl(){ [ -x "$CTL" ] || { say "${R}缺少 $CTL${N} (见 README: 本地交叉编译后 scp)"; exit 1; }; exec "$CTL" "$@"; }
neoq_ifaces(){ tc qdisc show 2>/dev/null | awk '/qdisc neoq /{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'; }

# 绝不用 rmmod -f。强卸一个仍被 socket 引用的 CC 模块, 那些 socket 的 icsk_ca_ops
# 立刻指向已释放内存, 下一个包就是 UAF -> panic。卸不掉可以接受, panic 不行。
# 失败也不静默: 打出 refcount 和内核原话。
try_rmmod(){
    local m=$1 err
    lsmod | grep -q "^${m} " || { say "  ${G}$m 未加载${N}"; return 0; }
    if err=$(rmmod "$m" 2>&1); then say "  ${G}$m 已卸载${N}"; return 0; fi
    say "  ${Y}$m 卸载失败 (refcount=$(lsmod | awk -v m="$m" '$1==m{print $3}')): $err${N}"
    return 1
}
holders_hint(){
    say ""
    say "${C}诊断: 谁还持有 lotspeed${N}"
    say "  1) 已建立的连接 (ss 打印 cc 名):  ss -tin | grep -B1 -w lotspeed"
    say "  2) LISTEN socket 不会出现在上面 (ss 对 LISTEN 不打印 cc), 但它的 icsk_ca_ops"
    say "     同样在 socket 创建时就绑定了; 这些服务要 restart 才放手:  ss -tlnp"
    say "  3) 容器/netns 的默认 CC 同样持引用 (ss 只看宿主 netns, 上面两条查不到):"
    say "       lsns -t net -n -o PID | while read p; do nsenter -t \$p -n sysctl -n net.ipv4.tcp_congestion_control; done"
    say "       改法:  nsenter -t <pid> -n sysctl -w net.ipv4.tcp_congestion_control=bbr   (或重启该容器)"
    say "  4) 剩余引用计数:  lsmod | awk '\$1==\"lotspeed\"{print \$3}'"
}

# 卸载纪律 (1)-(6), 顺序不能换
unload_modules(){
    need_root
    say "${Y}[1/6]${N} 停控制器 —— 它自己也持 socket, 不停它 refcount 下不去"
    systemctl stop 'lotspeedctl@*.service' >/dev/null 2>&1 || true
    systemctl stop lotspeedctl.service lotspeed.service >/dev/null 2>&1 || true
    say "${Y}[2/6]${N} 关整形 (fail-open: rate=0 就是内核默认的完全不整形)"
    { echo 0 > /proc/net/neoq_rate; } 2>/dev/null || true
    say "${Y}[3/6]${N} 新 socket 切回 bbr (存量 socket 不受影响, 见第 6 步)"
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    say "${Y}[4/6]${N} 摘掉 neoq qdisc —— 不先摘, qdisc 恒持模块引用, rmmod 必失败"
    local qdisc_ok=0
    for i in $(neoq_ifaces); do
        # 如实报告每张网卡的结果。原来无论 tc 成败都打印 "-> fq", 于是会出现
        # "ens3 -> fq" 紧跟 "sch_neoq 卸载失败(refcount=2)" 的自相矛盾输出,
        # 而 qdisc 还挂着正是那个 refcount 的唯一来源 —— 操作者拿不到正确的下一步。
        if tc qdisc replace dev "$i" root fq 2>/dev/null \
          || tc qdisc replace dev "$i" root fq_codel 2>/dev/null \
          || tc qdisc del dev "$i" root 2>/dev/null; then
            say "  ${G}$i -> fq${N}"
        else
            say "  ${R}$i 摘 qdisc 失败${N} —— sch_neoq 会卸不掉, 手工: tc qdisc del dev $i root"
            qdisc_ok=1
        fi
    done
    # 两个 rmmod 的结果都要进返回值。原来第 5 步是 `try_rmmod sch_neoq || true`,
    # 结果被丢弃, 函数只看第 6 步 —— 于是 sch_neoq 仍驻留内核、仍挂在生产网卡上时,
    # `unload` 退出 0, 而 uninstall 的 `if unload_modules; then purge_files` 会据此
    # 删掉 .ko 和 wrapper, 此后既无法重挂 qdisc 也无法重新 insmod, 只能重启。
    local rc=0
    say "${Y}[5/6]${N} rmmod sch_neoq"; try_rmmod sch_neoq || rc=1
    say "${Y}[6/6]${N} rmmod lotspeed"; try_rmmod lotspeed || rc=1
    [ "$qdisc_ok" = 0 ] || rc=1
    return $rc
}

# 删掉除 wrapper 自身以外的一切: 第 6 步常常要等重新登录才成功, 在那之前必须
# 还能跑 `lotspeed uninstall --finish`, 所以 wrapper 留到最后再删。
purge_files(){
    systemctl disable 'lotspeedctl@*.service' >/dev/null 2>&1 || true
    # 也要清 README 早期版本教的、不带 @ 的那个 unit —— 'lotspeedctl@*' 匹配不到它。
    # 漏掉的话: 按旧文档部署过的机器 uninstall 后该 unit 仍 enabled 但 lotspeedctl
    # 已删, 重启后 Restart=always 变成 3 秒一次的重启循环刷屏 journal。
    systemctl disable lotspeedctl.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/lotspeedctl@.service /etc/systemd/system/lotspeedctl.service \
          /etc/systemd/system/lotspeed.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f "$SYSCTL_FILE" /etc/modules-load.d/lotspeed.conf /etc/lotspeed.conf /usr/local/bin/lotspeed-autotune
    rm -f /var/log/lotspeed-autotune.log /var/log/lotspeed_install.log /var/run/lotspeed-autotune.pid
    rm -rf "$INSTALL_DIR" /etc/lotspeed
    # DKMS 注册必须先摘: 只删 .ko 的话 /var/lib/dkms 里的记录还在, 下次内核升级
    # postinst hook 仍会去重建一个已经卸载的包。--all 覆盖所有已建内核。
    dkms remove -m lotspeed -v 2.2 --all >/dev/null 2>&1 || true
    rm -rf /usr/src/lotspeed-2.2
    rm -f /lib/modules/*/kernel/net/{ipv4/lotspeed.ko,sched/sch_neoq.ko} /lib/modules/*/extra/{lotspeed,sch_neoq}.ko
    rm -f /lib/modules/*/updates/dkms/{lotspeed,sch_neoq}.ko
    depmod -a 2>/dev/null || true
    # 重载剩余 sysctl.d。已生效的值要到重启才回到发行版默认, 这无害。
    sysctl --system >/dev/null 2>&1 || true
}
finish(){ rm -f /usr/local/bin/lotspeedctl /usr/local/bin/lotspeed; say "${G}卸载完成${N}"; }

case "${1:-}" in
  modload)
    need_root
    modprobe lotspeed 2>/dev/null || insmod "$INSTALL_DIR/lotspeed.ko"
    modprobe sch_neoq 2>/dev/null || insmod "$INSTALL_DIR/sch_neoq.ko"
    say "${G}模块已加载${N} —— 启用: lotspeedctl enable ${LOTSPEED_IFACE:-<iface>}" ;;
  load|save|edit)
    # 旧 wrapper 的 load 是 load_config (从 /etc/lotspeed.conf 恢复参数), 与"加载模块"
    # 完全是两回事。沿用同一个词会让老 runbook 里的 `lotspeed load` 静默改变行为 ——
    # 它不会报错, 会去装内核模块。所以这三个动词一律大声失败, 不做任何事。
    say "${R}`lotspeed $1` 已移除${N}"
    say "参数持久化改由安装器统一管理: ${C}$SYSCTL_FILE${N}"
    say "  查看/修改单个参数:  lotspeedctl get [param] / lotspeedctl set <param> <val>"
    say "  加载内核模块请用:    ${C}lotspeed modload${N}  (旧 \`load\` 是恢复配置, 不是装模块)"
    exit 1 ;;
  unload)
    unload_modules || { holders_hint; exit 1; } ;;
  uninstall)
    need_root
    if [ "${2:-}" = "--finish" ]; then          # 重试第 5/6 步
        # purge_files 必须也在这条路径上跑 (它是幂等的)。原来只做 try_rmmod+finish,
        # 于是把 --finish 当第一条命令执行时: 模块卸掉了、工具删了、屏幕显示"卸载完成",
        # 但 /etc/sysctl.d/99-lotspeed.conf 和 /etc/modules-load.d/lotspeed.conf 还在
        # —— 下次重启机器会把自己装回去, 而 enable 着的 unit 找不到 lotspeedctl,
        # Restart=always 变成 3 秒一次的重启循环, 且已无任何工具可清理。
        # 不能用 local: 这里是顶层 case 分支, 不在函数内。bash 会报
        # "local: can only be used in a function" 并让 frc 保持未定义, 于是下面的
        # [ "$frc" = 0 ] 恒假 —— 两个 rmmod 都成功时也会走失败路径, 既不 finish
        # 也不删二进制, 操作者看到的是"卸载失败"而实际已经卸干净了。
        frc=0
        try_rmmod sch_neoq || frc=1
        try_rmmod lotspeed || frc=1
        if [ "$frc" = 0 ]; then purge_files; finish; exit 0; fi
        purge_files
        holders_hint; exit 1
    fi
    if unload_modules; then purge_files; finish; exit 0; fi
    purge_files
    say ""
    say "${Y}存量连接 (包括你当前这条 SSH) 仍持有 lotspeed 模块。${N}"
    say "TCP socket 创建时就绑定了当时的默认 CC, 之后改 sysctl 不影响存量 socket ——"
    say "所以这是${G}正常现象, 不是错误${N}。请${C}重新登录${N}后执行:"
    say "    ${C}lotspeed uninstall --finish${N}"
    holders_hint
    exit 1 ;;
  ""|help|-h|--help)
    say "lotspeed —— 薄包装, 只做 lotspeedctl 做不了的运维动作:"
    say "  lotspeed modload / unload      装卸内核模块 (unload 走完整卸载序列)"
    say "  lotspeed uninstall [--finish]  卸载序列 + 删文件; --finish 重新登录后收尾"
    say "其余子命令全部转发给 lotspeedctl:"
    ctl help ;;
  *)
    ctl "$@" ;;   # 未知子命令交给 lotspeedctl 报错; 这里不维护第二份命令表
esac
WRAPPER_EOF
    chmod +x /usr/local/bin/lotspeed
    log_success "/usr/local/bin/lotspeed (薄包装)"
}

# ================= systemd =================
# lotspeedctl@.service 模板由另一个 agent 提供, 这里只负责安装 + enable。
# 用模板单元的原因: 实例名就是网卡名, eth0 不再被写死在单元文件里。
install_units() {
    local unit="/etc/systemd/system/$UNIT_NAME"
    if [[ -f "$SRC_DIR/$UNIT_NAME" ]]; then
        cp "$SRC_DIR/$UNIT_NAME" "$unit"
    elif [[ -f "$SRC_DIR/lotspeedctl/$UNIT_NAME" ]]; then
        cp "$SRC_DIR/lotspeedctl/$UNIT_NAME" "$unit"
    elif curl -fsSL "$RAW_BASE/$UNIT_NAME" -o "$unit" 2>/dev/null \
      || curl -fsSL "$RAW_BASE/lotspeedctl/$UNIT_NAME" -o "$unit" 2>/dev/null; then
        :
    else
        rm -f "$unit"
        log_warn "未找到 $UNIT_NAME, 跳过 systemd 安装 (该文件由另一个 agent 提供)"
        return 0
    fi
    systemctl daemon-reload
    if systemctl enable "lotspeedctl@${IFACE}.service" >/dev/null 2>&1; then
        log_success "enable lotspeedctl@${IFACE}.service (开机自启; 本次不自动 start)"
    else
        log_warn "enable lotspeedctl@${IFACE}.service 失败"
    fi
}

# 老的 shell 自调优默认不装: 它和 lotspeedctl optimize 写同一批
# /proc/sys/net/ipv4/lotspeed/* 参数 (autotune 的 set_param vs optimizer 的搜索),
# 两个循环互相覆盖, 学出来的全是噪声。留 --with-legacy-autotune 作退路。
install_legacy_autotune() {
    [[ $WITH_LEGACY_AUTOTUNE -eq 1 ]] || return 0
    if [[ ! -f "$INSTALL_DIR/lotspeed-autotune.sh" ]]; then
        log_warn "lotspeed-autotune.sh 未取到, 跳过"; return 0
    fi
    install -m 0755 "$INSTALL_DIR/lotspeed-autotune.sh" /usr/local/bin/lotspeed-autotune
    log_warn "已安装 legacy autotune: 切勿与 lotspeedctl optimize 同时运行"
}

show_completion() {
    echo ""
    # 回读内核的实际状态再下结论。原来无条件打印"CC 已切到 lotspeed", 于是
    # Secure Boot 拒签 / 版本不匹配 / 残留旧模块导致模块根本没进内核时, 安装照样
    # 报"成功"并 exit 0, 而 CC 实际还是 bbr —— 用户要等到发现没有加速才回头查。
    local cc_now avail
    cc_now=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
    if [[ "${MOD_OK:-1}" != "1" ]] || [[ "$cc_now" != "lotspeed" ]]; then
        echo ""
        log_error "安装未完全成功 —— 当前 CC 是 ${cc_now}, 不是 lotspeed"
        [[ "$avail" != *lotspeed* ]] && log_error "  lotspeed 未注册为可用算法 (模块没进内核)"
        log_warn "上面的模块加载错误就是原因。常见:"
        log_warn "  Required key not available  -> Secure Boot 拒绝未签名模块, 需关闭或签名"
        log_warn "  Invalid module format       -> 模块与运行内核不匹配, 检查内核头文件版本"
        log_warn "文件已就位, 排除原因后可重试:  lotspeed modload"
        echo ""
        return 1
    fi
    log_success "安装完成: LotSpeed v${VERSION} + NeoQ v3.1, iface=${IFACE}"
    echo -e "  CC        已切到 lotspeed (由 ${SYSCTL_FILE} 持久化, 重启保持)"
    echo -e "  挂 NeoQ   ${CYAN}lotspeedctl enable ${IFACE}${NC}"
    echo -e "  状态      ${CYAN}lotspeedctl status${NC}"
    echo -e "  自适应    ${CYAN}systemctl start lotspeedctl@${IFACE}${NC}"
    echo -e "  卸载      ${CYAN}lotspeed uninstall${NC}  (提示重新登录时: ${CYAN}lotspeed uninstall --finish${NC})"
    echo -e "  持久化    ${SYSCTL_FILE}  (卸载时删除)"
    echo ""
    log_warn "本机只加速**发出**的流量, 发送窗口受对端 rmem 约束:"
    log_warn "下游客户端也要把 net.ipv4.tcp_rmem 上限放到 128MB, 才吃得到实测的 3.4x。"
    echo ""
}

# ================= 主入口 =================
main() {
    parse_args "$@"
    check_root
    print_banner
    check_system
    detect_iface
    check_modules_loaded

    if [[ $ASSUME_YES -eq 0 && -t 0 ]]; then
        read -r -p "在 ${IFACE} 上安装 LotSpeed + NeoQ? [Y/n]: " ans
        [[ "$ans" =~ ^[Nn]$ ]] && { log_info "已取消"; exit 0; }
    fi

    install_dependencies
    download_source
    build_and_install_modules

    # 必须先加载模块再 write_sysctl: sysctl.d 里的 tcp_congestion_control=lotspeed
    # 在算法尚未注册时是写不进去的, 那样安装完 CC 其实还停在 bbr/cubic。
    # 保留 insmod 的 stderr。原来是 `insmod ... 2>/dev/null`, 于是加载失败时唯一有用的
    # 那句话被丢掉了 —— Secure Boot 拒签是 "Required key not available", 版本不匹配是
    # "Invalid module format", 两者的处理完全不同, 而用户只会看到一句"加载失败"。
    load_mod() {
        local name=$1 ko=$2 err
        modprobe "$name" 2>/dev/null && return 0
        if err=$(insmod "$ko" 2>&1); then return 0; fi
        log_error "$name 加载失败: $err"
        return 1
    }
    MOD_OK=1
    load_mod lotspeed "$INSTALL_DIR/lotspeed.ko" || MOD_OK=0
    load_mod sch_neoq "$INSTALL_DIR/sch_neoq.ko" || MOD_OK=0

    install_lotspeedctl
    write_sysctl
    write_env
    install_wrapper
    install_units
    install_legacy_autotune
    show_completion || exit 1
}

main "$@"
