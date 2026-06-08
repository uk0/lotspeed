#!/bin/bash
#
# LotSpeed Auto-Tune Daemon v2.1
# 基于实际网络状态自动调整 LotSpeed 参数
#
# 数据来源:
#   1. ss -ti          - TCP 连接详情 (RTT, cwnd, retrans, pacing_rate)
#   2. /proc/net/snmp  - 全局 TCP 统计 (重传, 丢包)
#   3. /proc/net/neoq  - NeoQ 队列统计 (如果启用)
#   4. netstat -s      - 协议统计
#
# 使用方法:
#   ./lotspeed-autotune.sh          # 单次检测
#   ./lotspeed-autotune.sh daemon   # 后台守护进程
#   ./lotspeed-autotune.sh status   # 查看状态
#   ./lotspeed-autotune.sh stop     # 停止守护进程
#

set -e

# ============================================================================
# 配置
# ============================================================================

SYSCTL_PATH="/proc/sys/net/ipv4/lotspeed"
LOG_FILE="/var/log/lotspeed-autotune.log"
PID_FILE="/var/run/lotspeed-autotune.pid"
STATE_FILE="/tmp/lotspeed-autotune.state"
HISTORY_FILE="/tmp/lotspeed-autotune.history"

# 采样间隔 (秒)
SAMPLE_INTERVAL=5

# 调整冷却时间 (秒)
ADJUST_COOLDOWN=30

# 历史样本数量
HISTORY_SIZE=12

# 上次调整时间
LAST_ADJUST_TIME=0

# 当前模式
CURRENT_MODE="unknown"

# 历史数据
declare -a RTT_HISTORY=()
declare -a LOSS_HISTORY=()
declare -a RETRANS_HISTORY=()
declare -a TIMEOUT_HISTORY=()

# 上一次采样的 SNMP 计数器 (用于计算增量)
PREV_RETRANS_SEGS=0
PREV_OUT_SEGS=0
PREV_LOSS_EVENTS=0
PREV_FAST_RETRANS=0
PREV_TIMEOUTS=0

# 激进模式配置
AGGRESSIVE_MODE=0
LOSS_RESPONSE_LEVEL=0  # 0=normal, 1=mild, 2=aggressive, 3=ultra

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ============================================================================
# 日志函数
# ============================================================================

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # 写入日志文件
    if [[ -w "$(dirname "$LOG_FILE")" ]] || [[ -w "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi

    # 终端输出
    case "$level" in
        INFO)   echo -e "${GREEN}[INFO]${NC} $msg" ;;
        WARN)   echo -e "${YELLOW}[WARN]${NC} $msg" ;;
        ERROR)  echo -e "${RED}[ERROR]${NC} $msg" ;;
        DEBUG)  [[ "${DEBUG:-0}" == "1" ]] && echo -e "${CYAN}[DEBUG]${NC} $msg" ;;
        ADJUST) echo -e "${BLUE}[ADJUST]${NC} $msg" ;;
        METRIC) echo -e "${MAGENTA}[METRIC]${NC} $msg" ;;
    esac
}

# ============================================================================
# 参数操作
# ============================================================================

# 检查 sysctl 路径
check_sysctl() {
    [[ -d "$SYSCTL_PATH" ]]
}

# 获取参数
get_param() {
    local param="$1"
    local path="$SYSCTL_PATH/$param"
    if [[ -f "$path" ]]; then
        cat "$path" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# 设置参数
set_param() {
    local param="$1"
    local value="$2"
    local path="$SYSCTL_PATH/$param"

    if [[ -f "$path" ]]; then
        local old_value=$(cat "$path" 2>/dev/null)
        if [[ "$old_value" != "$value" ]]; then
            echo "$value" > "$path" 2>/dev/null && {
                log DEBUG "Set $param: $old_value -> $value"
                return 0
            }
        fi
        return 0
    fi
    return 1
}

# ============================================================================
# 数据采集 - 核心改进
# ============================================================================

# 全局变量存储采集结果
declare -A METRICS

# 从 ss -ti 获取 TCP 连接统计 (POSIX 兼容)
collect_ss_stats() {
    local ss_output
    ss_output=$(ss -tin 2>/dev/null) || return

    # 初始化
    local rtt_sum=0 rtt_count=0 rtt_min=999999 rtt_max=0
    local cwnd_sum=0 cwnd_count=0
    local retrans_total=0
    local pacing_sum=0 pacing_count=0
    local conn_count=0
    local lotspeed_count=0

    # 逐行解析 (POSIX 兼容方式)
    while IFS= read -r line; do
        # 跳过空行和标题
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^State ]] && continue

        # 检查是否是 lotspeed 连接
        if echo "$line" | grep -q "lotspeed"; then
            lotspeed_count=$((lotspeed_count + 1))
        fi

        # 提取 RTT (格式: rtt:123.456/45.678)
        if echo "$line" | grep -q "rtt:"; then
            local rtt_str=$(echo "$line" | sed -n 's/.*rtt:\([0-9.]*\).*/\1/p')
            if [[ -n "$rtt_str" ]]; then
                # 取整数部分
                local rtt_int=${rtt_str%%.*}
                [[ -z "$rtt_int" || "$rtt_int" == "0" ]] && rtt_int=1

                rtt_sum=$((rtt_sum + rtt_int))
                rtt_count=$((rtt_count + 1))
                [[ $rtt_int -lt $rtt_min ]] && rtt_min=$rtt_int
                [[ $rtt_int -gt $rtt_max ]] && rtt_max=$rtt_int
            fi
        fi

        # 提取 cwnd
        if echo "$line" | grep -q "cwnd:"; then
            local cwnd_str=$(echo "$line" | sed -n 's/.*cwnd:\([0-9]*\).*/\1/p')
            if [[ -n "$cwnd_str" && "$cwnd_str" -gt 0 ]]; then
                cwnd_sum=$((cwnd_sum + cwnd_str))
                cwnd_count=$((cwnd_count + 1))
            fi
        fi

        # 提取重传 (格式: retrans:0/5)
        if echo "$line" | grep -q "retrans:"; then
            local retrans_str=$(echo "$line" | sed -n 's/.*retrans:[0-9]*\/\([0-9]*\).*/\1/p')
            [[ -n "$retrans_str" ]] && retrans_total=$((retrans_total + retrans_str))
        fi

        # 提取 pacing_rate (格式: pacing_rate 1234Mbps)
        if echo "$line" | grep -q "pacing_rate"; then
            local pacing_str=$(echo "$line" | sed -n 's/.*pacing_rate \([0-9.]*\).*/\1/p')
            if [[ -n "$pacing_str" ]]; then
                local pacing_int=${pacing_str%%.*}
                [[ -n "$pacing_int" && "$pacing_int" -gt 0 ]] && {
                    pacing_sum=$((pacing_sum + pacing_int))
                    pacing_count=$((pacing_count + 1))
                }
            fi
        fi

        conn_count=$((conn_count + 1))
    done <<< "$ss_output"

    # 计算统计值
    METRICS[conn_count]=$conn_count
    METRICS[lotspeed_count]=$lotspeed_count

    if [[ $rtt_count -gt 0 ]]; then
        METRICS[rtt_avg]=$((rtt_sum / rtt_count))
        METRICS[rtt_min]=$rtt_min
        METRICS[rtt_max]=$rtt_max
        METRICS[rtt_jitter]=$((rtt_max - rtt_min))
    else
        METRICS[rtt_avg]=0
        METRICS[rtt_min]=0
        METRICS[rtt_max]=0
        METRICS[rtt_jitter]=0
    fi

    if [[ $cwnd_count -gt 0 ]]; then
        METRICS[cwnd_avg]=$((cwnd_sum / cwnd_count))
    else
        METRICS[cwnd_avg]=0
    fi

    METRICS[retrans_total]=$retrans_total

    if [[ $pacing_count -gt 0 ]]; then
        METRICS[pacing_avg]=$((pacing_sum / pacing_count))
    else
        METRICS[pacing_avg]=0
    fi
}

# 从 /proc/net/snmp 获取全局 TCP 统计
collect_snmp_stats() {
    if [[ ! -f /proc/net/snmp ]]; then
        METRICS[tcp_retrans_segs]=0
        METRICS[tcp_in_segs]=0
        METRICS[tcp_out_segs]=0
        return
    fi

    # 获取 TCP 行
    local tcp_keys=$(grep "^Tcp:" /proc/net/snmp | head -1)
    local tcp_vals=$(grep "^Tcp:" /proc/net/snmp | tail -1)

    # 解析字段位置
    local retrans_idx=0 in_idx=0 out_idx=0
    local idx=1
    for key in $tcp_keys; do
        case "$key" in
            RetransSegs) retrans_idx=$idx ;;
            InSegs) in_idx=$idx ;;
            OutSegs) out_idx=$idx ;;
        esac
        idx=$((idx + 1))
    done

    # 安全提取值
    local val
    if [[ $retrans_idx -gt 0 ]]; then
        val=$(echo "$tcp_vals" | awk "{print \$$retrans_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_retrans_segs]=$val || METRICS[tcp_retrans_segs]=0
    else
        METRICS[tcp_retrans_segs]=0
    fi

    if [[ $in_idx -gt 0 ]]; then
        val=$(echo "$tcp_vals" | awk "{print \$$in_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_in_segs]=$val || METRICS[tcp_in_segs]=0
    else
        METRICS[tcp_in_segs]=0
    fi

    if [[ $out_idx -gt 0 ]]; then
        val=$(echo "$tcp_vals" | awk "{print \$$out_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_out_segs]=$val || METRICS[tcp_out_segs]=0
    else
        METRICS[tcp_out_segs]=0
    fi
}

# 从 /proc/net/netstat 获取扩展 TCP 统计
collect_netstat_stats() {
    if [[ ! -f /proc/net/netstat ]]; then
        METRICS[tcp_loss_events]=0
        METRICS[tcp_fast_retrans]=0
        METRICS[tcp_timeouts]=0
        METRICS[tcp_ecn_marks]=0
        METRICS[tcp_sack_recovery]=0
        METRICS[tcp_loss_probes]=0
        METRICS[tcp_loss_probe_recovery]=0
        return
    fi

    local tcpext_keys=$(grep "^TcpExt:" /proc/net/netstat | head -1)
    local tcpext_vals=$(grep "^TcpExt:" /proc/net/netstat | tail -1)

    # 查找字段位置
    local loss_idx=0 fast_idx=0 timeout_idx=0 ecn_idx=0
    local sack_idx=0 probe_idx=0 probe_recv_idx=0
    local idx=1
    for key in $tcpext_keys; do
        case "$key" in
            TCPLossEvents|TCPLoss) loss_idx=$idx ;;
            TCPFastRetrans) fast_idx=$idx ;;
            TCPTimeouts) timeout_idx=$idx ;;
            TCPECNFallback|TCPECERecv) ecn_idx=$idx ;;
            TCPSackRecovery) sack_idx=$idx ;;
            TCPLossProbes) probe_idx=$idx ;;
            TCPLossProbeRecovery) probe_recv_idx=$idx ;;
        esac
        idx=$((idx + 1))
    done

    # 安全提取数值 - 只有当索引 > 0 时才提取
    local val
    if [[ $loss_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$loss_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_loss_events]=$val || METRICS[tcp_loss_events]=0
    else
        METRICS[tcp_loss_events]=0
    fi

    if [[ $fast_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$fast_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_fast_retrans]=$val || METRICS[tcp_fast_retrans]=0
    else
        METRICS[tcp_fast_retrans]=0
    fi

    if [[ $timeout_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$timeout_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_timeouts]=$val || METRICS[tcp_timeouts]=0
    else
        METRICS[tcp_timeouts]=0
    fi

    if [[ $ecn_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$ecn_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_ecn_marks]=$val || METRICS[tcp_ecn_marks]=0
    else
        METRICS[tcp_ecn_marks]=0
    fi

    if [[ $sack_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$sack_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_sack_recovery]=$val || METRICS[tcp_sack_recovery]=0
    else
        METRICS[tcp_sack_recovery]=0
    fi

    if [[ $probe_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$probe_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_loss_probes]=$val || METRICS[tcp_loss_probes]=0
    else
        METRICS[tcp_loss_probes]=0
    fi

    if [[ $probe_recv_idx -gt 0 ]]; then
        val=$(echo "$tcpext_vals" | awk "{print \$$probe_recv_idx}" 2>/dev/null)
        [[ "$val" =~ ^[0-9]+$ ]] && METRICS[tcp_loss_probe_recovery]=$val || METRICS[tcp_loss_probe_recovery]=0
    else
        METRICS[tcp_loss_probe_recovery]=0
    fi
}

# 从 NeoQ 获取队列统计
collect_neoq_stats() {
    METRICS[neoq_packets]=0
    METRICS[neoq_dropped]=0
    METRICS[neoq_ecn_marked]=0
    METRICS[neoq_avg_delay]=0
    METRICS[neoq_express_packets]=0
    METRICS[neoq_recovery_flows]=0
    METRICS[neoq_retrans_detected]=0

    if [[ ! -f /proc/net/neoq ]]; then
        return
    fi

    local neoq_output=$(cat /proc/net/neoq 2>/dev/null)

    # 解析各层统计并累加
    local total_packets=0 total_dropped=0 total_ecn=0 express_packets=0

    while IFS= read -r line; do
        # 匹配数据行 (Express, High, Normal, Bulk)
        if echo "$line" | grep -qE "^\s*(Express|High|Normal|Bulk)"; then
            local tier_name=$(echo "$line" | awk '{print $1}')
            local packets=$(echo "$line" | awk '{print $2}')
            local dropped=$(echo "$line" | awk '{print $4}')
            local ecn=$(echo "$line" | awk '{print $5}')

            [[ -n "$packets" && "$packets" =~ ^[0-9]+$ ]] && total_packets=$((total_packets + packets))
            [[ -n "$dropped" && "$dropped" =~ ^[0-9]+$ ]] && total_dropped=$((total_dropped + dropped))
            [[ -n "$ecn" && "$ecn" =~ ^[0-9]+$ ]] && total_ecn=$((total_ecn + ecn))

            # Express tier 通常包含重传包
            if [[ "$tier_name" == "Express" ]]; then
                [[ -n "$packets" && "$packets" =~ ^[0-9]+$ ]] && express_packets=$packets
            fi
        fi

        # 提取平均延迟
        if echo "$line" | grep -q "Average:"; then
            local avg_delay=$(echo "$line" | sed -n 's/.*Average:\s*\([0-9]*\).*/\1/p')
            [[ -n "$avg_delay" ]] && METRICS[neoq_avg_delay]=$avg_delay
        fi

        # 提取 Recovery 流数量
        if echo "$line" | grep -qi "recovery"; then
            local recovery_cnt=$(echo "$line" | grep -oE "[0-9]+" | head -1)
            [[ -n "$recovery_cnt" ]] && METRICS[neoq_recovery_flows]=$recovery_cnt
        fi

        # 提取重传检测统计
        if echo "$line" | grep -qi "retrans"; then
            local retrans_cnt=$(echo "$line" | grep -oE "[0-9]+" | head -1)
            [[ -n "$retrans_cnt" ]] && METRICS[neoq_retrans_detected]=$retrans_cnt
        fi
    done <<< "$neoq_output"

    METRICS[neoq_packets]=$total_packets
    METRICS[neoq_dropped]=$total_dropped
    METRICS[neoq_ecn_marked]=$total_ecn
    METRICS[neoq_express_packets]=$express_packets
}

# 计算派生指标
calculate_derived_metrics() {
    # 辅助函数：确保值是数字
    _ensure_num() {
        local val="$1"
        if [[ "$val" =~ ^[0-9]+$ ]]; then
            echo "$val"
        else
            echo "0"
        fi
    }

    # 确保所有 METRICS 值是数字
    METRICS[neoq_packets]=$(_ensure_num "${METRICS[neoq_packets]}")
    METRICS[neoq_dropped]=$(_ensure_num "${METRICS[neoq_dropped]}")
    METRICS[neoq_ecn_marked]=$(_ensure_num "${METRICS[neoq_ecn_marked]}")
    METRICS[tcp_out_segs]=$(_ensure_num "${METRICS[tcp_out_segs]}")
    METRICS[tcp_retrans_segs]=$(_ensure_num "${METRICS[tcp_retrans_segs]}")
    METRICS[rtt_avg]=$(_ensure_num "${METRICS[rtt_avg]}")
    METRICS[rtt_jitter]=$(_ensure_num "${METRICS[rtt_jitter]}")
    METRICS[tcp_loss_events]=$(_ensure_num "${METRICS[tcp_loss_events]}")
    METRICS[tcp_fast_retrans]=$(_ensure_num "${METRICS[tcp_fast_retrans]}")
    METRICS[tcp_timeouts]=$(_ensure_num "${METRICS[tcp_timeouts]}")
    METRICS[neoq_express_packets]=$(_ensure_num "${METRICS[neoq_express_packets]}")

    # 丢包率 (基于 NeoQ 或 SNMP)
    local drop_rate=0
    if [[ ${METRICS[neoq_packets]} -gt 1000 ]]; then
        drop_rate=$((METRICS[neoq_dropped] * 1000 / METRICS[neoq_packets]))
    elif [[ ${METRICS[tcp_out_segs]} -gt 1000 ]]; then
        drop_rate=$((METRICS[tcp_retrans_segs] * 1000 / METRICS[tcp_out_segs]))
    fi
    METRICS[drop_rate_permille]=$drop_rate  # 千分比

    # ECN 标记率
    local ecn_rate=0
    if [[ ${METRICS[neoq_packets]} -gt 1000 ]]; then
        ecn_rate=$((METRICS[neoq_ecn_marked] * 1000 / METRICS[neoq_packets]))
    fi
    METRICS[ecn_rate_permille]=$ecn_rate

    # RTT 变异系数 (jitter / avg * 100)
    if [[ ${METRICS[rtt_avg]} -gt 0 ]]; then
        METRICS[rtt_cv]=$((METRICS[rtt_jitter] * 100 / METRICS[rtt_avg]))
    else
        METRICS[rtt_cv]=0
    fi

    # === 计算增量指标 (用于检测丢包事件率) ===
    local cur_retrans=$(_ensure_num "${METRICS[tcp_retrans_segs]}")
    local cur_out=$(_ensure_num "${METRICS[tcp_out_segs]}")
    local cur_loss=$(_ensure_num "${METRICS[tcp_loss_events]}")
    local cur_fast=$(_ensure_num "${METRICS[tcp_fast_retrans]}")
    local cur_timeout=$(_ensure_num "${METRICS[tcp_timeouts]}")

    # 计算增量
    local delta_retrans=0 delta_out=0 delta_loss=0 delta_fast=0 delta_timeout=0

    if [[ $PREV_OUT_SEGS -gt 0 && $cur_out -ge $PREV_OUT_SEGS ]]; then
        delta_retrans=$((cur_retrans - PREV_RETRANS_SEGS))
        delta_out=$((cur_out - PREV_OUT_SEGS))
        delta_loss=$((cur_loss - PREV_LOSS_EVENTS))
        delta_fast=$((cur_fast - PREV_FAST_RETRANS))
        delta_timeout=$((cur_timeout - PREV_TIMEOUTS))
    fi

    # 保存当前值用于下次计算
    PREV_RETRANS_SEGS=$cur_retrans
    PREV_OUT_SEGS=$cur_out
    PREV_LOSS_EVENTS=$cur_loss
    PREV_FAST_RETRANS=$cur_fast
    PREV_TIMEOUTS=$cur_timeout

    # 计算实时丢包率 (千分比)
    METRICS[realtime_loss_rate]=0
    if [[ $delta_out -gt 100 ]]; then
        METRICS[realtime_loss_rate]=$((delta_retrans * 1000 / delta_out))
    fi

    # 丢包事件率 (每秒)
    METRICS[loss_events_rate]=$((delta_loss / SAMPLE_INTERVAL))
    METRICS[fast_retrans_rate]=$((delta_fast / SAMPLE_INTERVAL))
    METRICS[timeout_rate]=$((delta_timeout / SAMPLE_INTERVAL))

    # === 计算综合丢包严重程度 (0-100) ===
    local loss_severity=0

    # 基于丢包率
    if [[ ${METRICS[realtime_loss_rate]} -gt 100 ]]; then  # >10%
        loss_severity=$((loss_severity + 40))
    elif [[ ${METRICS[realtime_loss_rate]} -gt 50 ]]; then  # >5%
        loss_severity=$((loss_severity + 25))
    elif [[ ${METRICS[realtime_loss_rate]} -gt 20 ]]; then  # >2%
        loss_severity=$((loss_severity + 15))
    elif [[ ${METRICS[realtime_loss_rate]} -gt 10 ]]; then  # >1%
        loss_severity=$((loss_severity + 8))
    fi

    # 基于超时率 (超时比快速重传更严重)
    if [[ ${METRICS[timeout_rate]} -gt 10 ]]; then
        loss_severity=$((loss_severity + 30))
    elif [[ ${METRICS[timeout_rate]} -gt 5 ]]; then
        loss_severity=$((loss_severity + 20))
    elif [[ ${METRICS[timeout_rate]} -gt 1 ]]; then
        loss_severity=$((loss_severity + 10))
    fi

    # 基于丢包事件率
    if [[ ${METRICS[loss_events_rate]} -gt 20 ]]; then
        loss_severity=$((loss_severity + 20))
    elif [[ ${METRICS[loss_events_rate]} -gt 5 ]]; then
        loss_severity=$((loss_severity + 10))
    fi

    # 基于 NeoQ 重传检测
    if [[ ${METRICS[neoq_express_packets]} -gt 1000 ]]; then
        loss_severity=$((loss_severity + 10))
    fi

    [[ $loss_severity -gt 100 ]] && loss_severity=100
    METRICS[loss_severity]=$loss_severity

    # 根据严重程度设置响应级别
    if [[ $loss_severity -ge 60 ]]; then
        LOSS_RESPONSE_LEVEL=3  # ultra
    elif [[ $loss_severity -ge 40 ]]; then
        LOSS_RESPONSE_LEVEL=2  # aggressive
    elif [[ $loss_severity -ge 20 ]]; then
        LOSS_RESPONSE_LEVEL=1  # mild
    else
        LOSS_RESPONSE_LEVEL=0  # normal
    fi

    log DEBUG "Derived: drop_rate=${drop_rate}‰ ecn_rate=${ecn_rate}‰ rtt_cv=${METRICS[rtt_cv]}%"
    log DEBUG "Loss: realtime=${METRICS[realtime_loss_rate]}‰ severity=$loss_severity level=$LOSS_RESPONSE_LEVEL"
}

# 综合采集
collect_all_metrics() {
    log DEBUG "Collecting metrics..."

    collect_ss_stats
    collect_snmp_stats
    collect_netstat_stats
    collect_neoq_stats
    calculate_derived_metrics

    log DEBUG "RTT: avg=${METRICS[rtt_avg]}ms min=${METRICS[rtt_min]}ms max=${METRICS[rtt_max]}ms jitter=${METRICS[rtt_jitter]}ms"
    log DEBUG "Connections: total=${METRICS[conn_count]} lotspeed=${METRICS[lotspeed_count]} cwnd_avg=${METRICS[cwnd_avg]}"
    log DEBUG "Retrans: total=${METRICS[retrans_total]} loss_events=${METRICS[tcp_loss_events]}"
}

# ============================================================================
# 历史数据管理
# ============================================================================

update_history() {
    # 添加新样本
    RTT_HISTORY+=("${METRICS[rtt_avg]}")
    LOSS_HISTORY+=("${METRICS[drop_rate_permille]}")
    RETRANS_HISTORY+=("${METRICS[retrans_total]}")

    # 保持固定大小
    while [[ ${#RTT_HISTORY[@]} -gt $HISTORY_SIZE ]]; do
        RTT_HISTORY=("${RTT_HISTORY[@]:1}")
    done
    while [[ ${#LOSS_HISTORY[@]} -gt $HISTORY_SIZE ]]; do
        LOSS_HISTORY=("${LOSS_HISTORY[@]:1}")
    done
    while [[ ${#RETRANS_HISTORY[@]} -gt $HISTORY_SIZE ]]; do
        RETRANS_HISTORY=("${RETRANS_HISTORY[@]:1}")
    done
}

# 计算历史平均 (兼容性版本)
get_history_avg() {
    local arr_name=$1
    local sum=0 count=0 val

    case "$arr_name" in
        RTT_HISTORY)
            for val in "${RTT_HISTORY[@]}"; do
                [[ -n "$val" && "$val" =~ ^[0-9]+$ ]] && { sum=$((sum + val)); count=$((count + 1)); }
            done
            ;;
        LOSS_HISTORY)
            for val in "${LOSS_HISTORY[@]}"; do
                [[ -n "$val" && "$val" =~ ^[0-9]+$ ]] && { sum=$((sum + val)); count=$((count + 1)); }
            done
            ;;
        RETRANS_HISTORY)
            for val in "${RETRANS_HISTORY[@]}"; do
                [[ -n "$val" && "$val" =~ ^[0-9]+$ ]] && { sum=$((sum + val)); count=$((count + 1)); }
            done
            ;;
    esac

    [[ $count -gt 0 ]] && echo $((sum / count)) || echo 0
}

# 计算历史趋势 (正=上升, 负=下降) - 兼容性版本
get_history_trend() {
    local arr_name=$1
    local len=0 first_half=0 second_half=0 mid=0 i=0
    local -a arr=()

    case "$arr_name" in
        RTT_HISTORY) arr=("${RTT_HISTORY[@]}") ;;
        LOSS_HISTORY) arr=("${LOSS_HISTORY[@]}") ;;
        RETRANS_HISTORY) arr=("${RETRANS_HISTORY[@]}") ;;
    esac

    len=${#arr[@]}
    [[ $len -lt 3 ]] && { echo 0; return; }

    mid=$((len / 2))

    for ((i=0; i<mid; i++)); do
        [[ -n "${arr[i]}" && "${arr[i]}" =~ ^[0-9]+$ ]] && first_half=$((first_half + arr[i]))
    done
    for ((i=mid; i<len; i++)); do
        [[ -n "${arr[i]}" && "${arr[i]}" =~ ^[0-9]+$ ]] && second_half=$((second_half + arr[i]))
    done

    [[ $mid -gt 0 ]] && first_half=$((first_half / mid)) || first_half=0
    local second_count=$((len - mid))
    [[ $second_count -gt 0 ]] && second_half=$((second_half / second_count)) || second_half=0

    echo $((second_half - first_half))
}

# ============================================================================
# 网络类型检测 - 核心改进
# ============================================================================

detect_network_type() {
    local rtt=${METRICS[rtt_avg]:-0}
    local jitter=${METRICS[rtt_jitter]:-0}
    local rtt_cv=${METRICS[rtt_cv]:-0}
    local drop_rate=${METRICS[drop_rate_permille]:-0}
    local ecn_rate=${METRICS[ecn_rate_permille]:-0}
    local retrans=${METRICS[retrans_total]:-0}

    # 使用历史数据平滑判断
    local rtt_trend=$(get_history_trend RTT_HISTORY) || rtt_trend=0
    local loss_trend=$(get_history_trend LOSS_HISTORY) || loss_trend=0

    local network_type="normal"
    local confidence=50
    local reason=""

    # 1. 数据中心网络: RTT < 5ms, 抖动 < 2ms, 无丢包
    if [[ $rtt -lt 5 && $jitter -lt 2 && $drop_rate -eq 0 ]]; then
        network_type="datacenter"
        confidence=95
        reason="RTT=${rtt}ms<5ms, jitter=${jitter}ms<2ms, no loss"

    # 2. 低延迟局域网: RTT < 20ms, 低抖动
    elif [[ $rtt -lt 20 && $rtt_cv -lt 30 && $drop_rate -lt 5 ]]; then
        network_type="lan"
        confidence=85
        reason="RTT=${rtt}ms<20ms, cv=${rtt_cv}%<30%"

    # 3. 超高延迟: RTT > 300ms (卫星)
    elif [[ $rtt -gt 300 ]]; then
        network_type="satellite"
        confidence=90
        reason="RTT=${rtt}ms>300ms (satellite-like)"

    # 4. 高延迟网络: RTT > 100ms
    elif [[ $rtt -gt 100 ]]; then
        network_type="highdelay"
        confidence=80
        reason="RTT=${rtt}ms>100ms"

    # 5. 严重丢包: > 5%
    elif [[ $drop_rate -gt 50 ]]; then
        network_type="lossy_severe"
        confidence=90
        reason="drop_rate=${drop_rate}‰>5%"

    # 6. 中度丢包: 1-5%
    elif [[ $drop_rate -gt 10 ]]; then
        network_type="lossy"
        confidence=75
        reason="drop_rate=${drop_rate}‰ (1-5%)"

    # 7. 高抖动: 变异系数 > 100% 或绝对抖动 > 50ms
    elif [[ $rtt_cv -gt 100 || $jitter -gt 50 ]]; then
        network_type="jittery"
        confidence=80
        reason="jitter=${jitter}ms, cv=${rtt_cv}%"

    # 8. 拥塞 (ECN 标记高)
    elif [[ $ecn_rate -gt 100 ]]; then
        network_type="congested"
        confidence=75
        reason="ecn_rate=${ecn_rate}‰>10%"

    # 9. 轻度拥塞
    elif [[ $ecn_rate -gt 30 || $drop_rate -gt 5 ]]; then
        network_type="mild_congestion"
        confidence=60
        reason="ecn=${ecn_rate}‰ drop=${drop_rate}‰"

    # 10. 正常网络
    else
        network_type="normal"
        confidence=70
        reason="RTT=${rtt}ms, jitter=${jitter}ms, drop=${drop_rate}‰"
    fi

    # 趋势调整置信度
    if [[ $rtt_trend -gt 20 ]]; then
        log DEBUG "RTT trending up (+${rtt_trend}ms), network may be degrading"
        confidence=$((confidence - 10))
    elif [[ $rtt_trend -lt -20 ]]; then
        log DEBUG "RTT trending down (${rtt_trend}ms), network improving"
        confidence=$((confidence + 5))
    fi

    METRICS[network_type]=$network_type
    METRICS[confidence]=$confidence
    METRICS[detection_reason]="$reason"

    log DEBUG "Network type: $network_type (confidence: $confidence%) - $reason"
    echo "$network_type"
}

# ============================================================================
# 参数预设 - 完整版 (对应 lotspeed.c 所有参数)
# ============================================================================

apply_preset() {
    local preset="$1"
    log ADJUST "Applying preset: $preset"

    case "$preset" in
        datacenter)
            # 数据中心: 超低延迟，最大吞吐
            set_param "min_cwnd" 64
            set_param "max_cwnd" 30000
            set_param "beta" 819           # 80% (快速恢复)
            set_param "fast_alpha" 5       # 很小的队列目标
            set_param "fast_gamma" 30      # 快速响应

            set_param "hd_enable" 0        # 不需要高延迟优化
            set_param "brave_enable" 0     # 不需要抗抖动
            set_param "turbo_startup" 1
            set_param "startup_gain" 350   # 激进启动

            set_param "ecn_enable" 1
            set_param "ecn_factor" 90
            set_param "ecn_thresh" 20      # 低阈值，敏感响应
            set_param "ecn_alpha_gain" 32  # 快速 EWMA

            set_param "fast_path" 1
            set_param "pacing_margin" 1
            set_param "probe_rtt_cwnd_pct" 70
            set_param "inflight_headroom" 10

            # RACK-TLP: 数据中心启用快速丢包检测
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 2      # 更敏感的乱序阈值
            set_param "rack_min_rtt_div" 4
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 3

            # Hybla: 数据中心不需要高延迟补偿
            set_param "hybla_gain_exp" 100       # 线性 (禁用)
            set_param "hybla_rtt_floor" 50000    # 50ms 阈值
            ;;

        lan)
            # 局域网: 低延迟，高吞吐
            set_param "min_cwnd" 64
            set_param "max_cwnd" 20000
            set_param "beta" 768           # 75%
            set_param "fast_alpha" 10
            set_param "fast_gamma" 40

            set_param "hd_enable" 0
            set_param "brave_enable" 0
            set_param "turbo_startup" 1
            set_param "startup_gain" 300

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 30
            set_param "ecn_alpha_gain" 24

            set_param "fast_path" 1
            set_param "pacing_margin" 2

            # RACK-TLP: 局域网启用
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 3
            set_param "rack_min_rtt_div" 6
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 局域网不需要
            set_param "hybla_gain_exp" 100
            set_param "hybla_rtt_floor" 30000
            ;;

        satellite)
            # 卫星链路: 超高延迟 (300-800ms)
            set_param "min_cwnd" 256
            set_param "max_cwnd" 50000     # 需要大窗口
            set_param "beta" 870           # 85% (保守恢复)
            set_param "fast_alpha" 100     # 允许较大队列
            set_param "fast_gamma" 80      # 慢速平滑

            set_param "hd_enable" 1
            set_param "hd_thresh_us" 200000
            set_param "hd_ref_us" 30000
            set_param "hd_cwnd_gain" 250   # 2.5x cwnd
            set_param "hd_pacing_gain" 200 # 2x pacing
            set_param "hd_min_cwnd" 64
            set_param "hd_startup_boost" 100
            set_param "hd_boost" 50
            set_param "hd_rho_max" 600     # 最大 6x

            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 40   # 允许 40% RTT 波动
            set_param "brave_hold_ms" 1000
            set_param "brave_floor_pct" 90

            set_param "turbo_startup" 1
            set_param "startup_gain" 400
            set_param "startup_min_rounds" 5

            set_param "ecn_enable" 0       # 卫星链路 ECN 不可靠
            set_param "fast_path" 0
            set_param "probe_rtt_cwnd_pct" 80
            set_param "probe_rtt_duration" 300

            set_param "bw_probe_base_us" 5000000   # 5秒探测间隔
            set_param "bw_probe_rand_us" 2000000

            # RACK-TLP: 卫星链路需要更保守的设置
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 8      # 更大的乱序容忍
            set_param "rack_min_rtt_div" 16      # 更大的 RTT 窗口
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 3        # 更长的 TLP 超时
            set_param "tlp_max_probes" 1         # 减少探测

            # Hybla: 卫星链路使用最激进的补偿
            set_param "hybla_gain_exp" 200       # rho^2.0 二次补偿
            set_param "hybla_rtt_floor" 10000    # 10ms 即开始补偿
            ;;

        highdelay)
            # 高延迟广域网 (100-300ms)
            set_param "min_cwnd" 128
            set_param "max_cwnd" 25000
            set_param "beta" 819           # 80%
            set_param "fast_alpha" 50
            set_param "fast_gamma" 60

            set_param "hd_enable" 1
            set_param "hd_thresh_us" 80000
            set_param "hd_ref_us" 40000
            set_param "hd_cwnd_gain" 180
            set_param "hd_pacing_gain" 150
            set_param "hd_min_cwnd" 32
            set_param "hd_startup_boost" 60
            set_param "hd_boost" 30
            set_param "hd_rho_max" 450

            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 30
            set_param "brave_hold_ms" 500
            set_param "brave_floor_pct" 85

            set_param "turbo_startup" 1
            set_param "startup_gain" 350

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 40
            set_param "ecn_max_rtt_us" 10000

            set_param "fast_path" 1
            set_param "probe_rtt_cwnd_pct" 60

            # RACK-TLP: 高延迟调整
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 6
            set_param "rack_min_rtt_div" 10
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 高延迟使用推荐的 rho^1.5 补偿
            set_param "hybla_gain_exp" 150       # rho^1.5 推荐
            set_param "hybla_rtt_floor" 15000    # 15ms 阈值
            ;;

        lossy_severe)
            # 严重丢包环境 (>5%)
            set_param "min_cwnd" 16
            set_param "max_cwnd" 5000
            set_param "beta" 512           # 50% (极保守)
            set_param "fast_alpha" 15
            set_param "fast_gamma" 30

            set_param "hd_enable" 0
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 20
            set_param "brave_hold_ms" 100
            set_param "brave_floor_pct" 70

            set_param "turbo_startup" 0    # 禁用快速启动
            set_param "startup_gain" 200

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 10
            set_param "ecn_factor" 70

            set_param "fast_recovery" 1
            set_param "recovery_boost" 10
            set_param "loss_thresh" 1
            set_param "full_loss_cnt" 3
            set_param "inflight_headroom" 25

            # RACK-TLP: 丢包环境非常重要
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 2      # 敏感检测
            set_param "rack_min_rtt_div" 4
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 3         # 更多探测

            # Hybla: 丢包环境不启用高延迟补偿
            set_param "hybla_gain_exp" 100
            set_param "hybla_rtt_floor" 50000
            ;;

        lossy)
            # 中度丢包环境 (1-5%)
            set_param "min_cwnd" 32
            set_param "max_cwnd" 8000
            set_param "beta" 614           # 60%
            set_param "fast_alpha" 25
            set_param "fast_gamma" 40

            set_param "hd_enable" 0
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 25
            set_param "brave_hold_ms" 200
            set_param "brave_floor_pct" 80

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 15
            set_param "ecn_factor" 75

            set_param "fast_recovery" 1
            set_param "recovery_boost" 15
            set_param "loss_thresh" 2
            set_param "inflight_headroom" 20

            # RACK-TLP: 中度丢包启用
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 3
            set_param "rack_min_rtt_div" 6
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 不启用
            set_param "hybla_gain_exp" 100
            set_param "hybla_rtt_floor" 40000
            ;;

        jittery)
            # 高抖动网络 (移动网络/WiFi)
            set_param "min_cwnd" 48
            set_param "max_cwnd" 12000
            set_param "beta" 716
            set_param "fast_alpha" 30
            set_param "fast_gamma" 70      # 慢速平滑

            set_param "hd_enable" 0
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 50   # 允许大波动
            set_param "brave_hold_ms" 600
            set_param "brave_floor_pct" 85

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 35

            set_param "fast_path" 0        # 禁用快速路径，需要持续监控
            set_param "ack_agg_enable" 1
            set_param "extra_acked_max_us" 200000

            # RACK-TLP: 高抖动需要更大容忍度
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 6      # 更大的乱序容忍
            set_param "rack_min_rtt_div" 8
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 3        # 更长超时
            set_param "tlp_max_probes" 1

            # Hybla: 抖动网络可能需要轻度补偿
            set_param "hybla_gain_exp" 120       # 轻度补偿
            set_param "hybla_rtt_floor" 25000
            ;;

        congested)
            # 拥塞网络 (ECN 高)
            set_param "min_cwnd" 32
            set_param "max_cwnd" 10000
            set_param "beta" 665           # 65%
            set_param "fast_alpha" 15
            set_param "fast_gamma" 50

            set_param "brave_enable" 0

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 10
            set_param "ecn_factor" 80
            set_param "ecn_alpha_gain" 8   # 快速响应 ECN
            set_param "full_ecn_cnt" 1

            set_param "pacing_margin" 5
            set_param "inflight_headroom" 20

            # RACK-TLP: 拥塞网络启用
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 4
            set_param "rack_min_rtt_div" 8
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 不启用
            set_param "hybla_gain_exp" 100
            set_param "hybla_rtt_floor" 30000
            ;;

        mild_congestion)
            # 轻度拥塞
            set_param "min_cwnd" 48
            set_param "max_cwnd" 12000
            set_param "beta" 716
            set_param "fast_alpha" 18
            set_param "fast_gamma" 50

            set_param "ecn_enable" 1
            set_param "ecn_thresh" 25
            set_param "ecn_alpha_gain" 12

            set_param "pacing_margin" 3

            # RACK-TLP: 轻度拥塞启用
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 4
            set_param "rack_min_rtt_div" 8
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 不启用
            set_param "hybla_gain_exp" 100
            set_param "hybla_rtt_floor" 30000
            ;;

        anti_loss)
            # 激进抗丢包模式: 针对高丢包环境优化吞吐量
            log ADJUST "Anti-loss mode: Aggressive recovery, fast retransmit"
            set_param "min_cwnd" 64
            set_param "max_cwnd" 20000
            set_param "beta" 870               # 85% (快速恢复，少削减)
            set_param "fast_alpha" 40          # 允许更大队列
            set_param "fast_gamma" 70          # 慢速平滑，避免震荡

            set_param "hd_enable" 1
            set_param "hd_thresh_us" 80000
            set_param "hd_ref_us" 30000
            set_param "hd_cwnd_gain" 180
            set_param "hd_pacing_gain" 160
            set_param "hd_min_cwnd" 32
            set_param "hd_startup_boost" 80
            set_param "hd_boost" 40
            set_param "hd_rho_max" 500

            # 勇敢模式: 容忍更大抖动
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 50       # 容忍 50% RTT 波动
            set_param "brave_hold_ms" 800      # 长时间保持
            set_param "brave_floor_pct" 90     # 保持 90% 窗口

            # 激进启动
            set_param "turbo_startup" 1
            set_param "startup_gain" 400       # 4x 启动增益
            set_param "startup_min_rounds" 2   # 更少轮次

            # ECN: 保守使用
            set_param "ecn_enable" 1
            set_param "ecn_factor" 95          # 仅削减 5%
            set_param "ecn_thresh" 80          # 高阈值
            set_param "ecn_alpha_gain" 8       # 慢速响应

            # 快速恢复: 最大化
            set_param "fast_recovery" 1
            set_param "recovery_boost" 40      # 40% 恢复增益
            set_param "loss_thresh" 5          # 5% 丢包才收缩
            set_param "full_loss_cnt" 10       # 更高容忍
            set_param "inflight_headroom" 25   # 25% 余量

            # RACK-TLP: 超敏感检测
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 2    # 非常敏感
            set_param "rack_min_rtt_div" 4     # 快速检测
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 4       # 更多探测

            # Hybla: 中等补偿
            set_param "hybla_gain_exp" 150
            set_param "hybla_rtt_floor" 15000

            set_param "fast_path" 1
            set_param "pacing_margin" 5        # 更多 pacing 余量
            set_param "burst_mode" 1           # 启用突发模式
            ;;

        ultra_aggressive)
            # 超激进模式: 最大吞吐量，不惜代价
            log ADJUST "Ultra-aggressive mode: Maximum throughput, accepting queue buildup"
            set_param "min_cwnd" 128
            set_param "max_cwnd" 50000         # 超大窗口
            set_param "beta" 922               # 90% (几乎不削减)
            set_param "fast_alpha" 80          # 大队列目标
            set_param "fast_gamma" 80          # 非常慢的平滑

            set_param "hd_enable" 1
            set_param "hd_thresh_us" 50000
            set_param "hd_ref_us" 20000
            set_param "hd_cwnd_gain" 250       # 2.5x cwnd
            set_param "hd_pacing_gain" 200     # 2x pacing
            set_param "hd_min_cwnd" 64
            set_param "hd_startup_boost" 100   # 满启动增益
            set_param "hd_boost" 60
            set_param "hd_rho_max" 800         # 8x 最大补偿

            # 勇敢模式: 极限容忍
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 80       # 容忍 80% RTT 波动
            set_param "brave_hold_ms" 1500     # 1.5秒保持
            set_param "brave_floor_pct" 95     # 保持 95% 窗口

            # 超激进启动
            set_param "turbo_startup" 1
            set_param "startup_gain" 500       # 5x 启动增益
            set_param "startup_min_rounds" 1

            # ECN: 几乎忽略
            set_param "ecn_enable" 1
            set_param "ecn_factor" 98          # 仅削减 2%
            set_param "ecn_thresh" 95
            set_param "ecn_alpha_gain" 4       # 最慢响应

            # 快速恢复: 极限
            set_param "fast_recovery" 1
            set_param "recovery_boost" 60      # 60% 恢复增益
            set_param "loss_thresh" 10         # 10% 丢包才收缩
            set_param "full_loss_cnt" 20
            set_param "inflight_headroom" 40   # 40% 余量

            # RACK-TLP: 最大化探测
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 1    # 最敏感
            set_param "rack_min_rtt_div" 2
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 1
            set_param "tlp_max_probes" 6

            # Hybla: 最大补偿
            set_param "hybla_gain_exp" 200     # rho^2.0
            set_param "hybla_rtt_floor" 10000

            set_param "fast_path" 0            # 禁用快速路径，全程监控
            set_param "pacing_margin" 10       # 大余量
            set_param "burst_mode" 1

            # 带宽探测: 更频繁
            set_param "bw_probe_base_us" 1000000   # 1秒
            set_param "bw_probe_rand_us" 500000
            ;;

        loss_recovery)
            # 丢包恢复模式: 检测到丢包后自动切换
            log ADJUST "Loss recovery mode: Optimized for active loss conditions"
            set_param "min_cwnd" 48
            set_param "max_cwnd" 15000
            set_param "beta" 819               # 80%
            set_param "fast_alpha" 30
            set_param "fast_gamma" 60

            # 勇敢模式
            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 40
            set_param "brave_hold_ms" 500
            set_param "brave_floor_pct" 85

            # 快速恢复
            set_param "fast_recovery" 1
            set_param "recovery_boost" 30
            set_param "loss_thresh" 3
            set_param "full_loss_cnt" 8
            set_param "inflight_headroom" 20

            # RACK-TLP: 敏感
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 2
            set_param "rack_min_rtt_div" 4
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 3

            # Hybla: 中等
            set_param "hybla_gain_exp" 140
            set_param "hybla_rtt_floor" 18000

            set_param "ecn_enable" 1
            set_param "ecn_factor" 90
            set_param "ecn_thresh" 60
            ;;

        normal|*)
            # 默认/平衡模式
            set_param "min_cwnd" 64
            set_param "max_cwnd" 15000
            set_param "beta" 717
            set_param "fast_alpha" 20
            set_param "fast_gamma" 50

            set_param "hd_enable" 1
            set_param "hd_thresh_us" 150000
            set_param "hd_ref_us" 50000
            set_param "hd_cwnd_gain" 150
            set_param "hd_pacing_gain" 130
            set_param "hd_min_cwnd" 10
            set_param "hd_startup_boost" 50
            set_param "hd_boost" 25
            set_param "hd_rho_max" 400

            set_param "brave_enable" 1
            set_param "brave_rtt_pct" 25
            set_param "brave_hold_ms" 300
            set_param "brave_floor_pct" 85

            set_param "hist_enable" 1
            set_param "hist_ttl_sec" 1200

            set_param "ecn_enable" 1
            set_param "ecn_factor" 85
            set_param "ecn_thresh" 50
            set_param "ecn_alpha_gain" 16
            set_param "ecn_max_rtt_us" 5000

            set_param "turbo_startup" 1
            set_param "startup_gain" 300
            set_param "startup_min_rounds" 3

            set_param "ack_agg_enable" 1
            set_param "extra_acked_max_us" 100000

            set_param "fast_recovery" 1
            set_param "recovery_boost" 20

            set_param "pacing_margin" 2
            set_param "probe_rtt_cwnd_pct" 50
            set_param "probe_rtt_duration" 150
            set_param "fast_path" 1

            set_param "loss_thresh" 2
            set_param "full_loss_cnt" 6
            set_param "inflight_headroom" 15

            # RACK-TLP: 默认启用
            set_param "rack_enable" 1
            set_param "rack_reord_thresh" 4
            set_param "rack_min_rtt_div" 8
            set_param "tlp_enable" 1
            set_param "tlp_timeout_div" 2
            set_param "tlp_max_probes" 2

            # Hybla: 默认使用推荐的 rho^1.5
            set_param "hybla_gain_exp" 150
            set_param "hybla_rtt_floor" 20000
            ;;
    esac
}

# ============================================================================
# 实时微调
# ============================================================================

fine_tune() {
    local network_type="$1"

    # 1. ECN 标记率高 -> 降低阈值
    if [[ ${METRICS[ecn_rate_permille]:-0} -gt 50 ]]; then
        local cur=$(get_param "ecn_thresh")
        if [[ ${cur:-0} -gt 15 ]]; then
            local new=$((cur - 5))
            set_param "ecn_thresh" $new
            log ADJUST "ECN rate high (${METRICS[ecn_rate_permille]:-0}‰), ecn_thresh: $cur -> $new"
        fi
    fi

    # 2. 抖动突然增大 -> 增加 brave_hold_ms
    if [[ ${METRICS[rtt_jitter]:-0} -gt 30 ]]; then
        local cur=$(get_param "brave_hold_ms")
        local jitter=${METRICS[rtt_jitter]:-0}
        local target=$((jitter * 10))
        target=$((target > 800 ? 800 : target))
        if [[ $target -gt ${cur:-0} ]]; then
            set_param "brave_hold_ms" $target
            set_param "brave_enable" 1
            log ADJUST "High jitter (${jitter}ms), brave_hold_ms: ${cur:-0} -> $target"
        fi
    fi

    # 3. RTT 持续上升 -> 降低 fast_alpha
    local rtt_trend=$(get_history_trend RTT_HISTORY) || rtt_trend=0
    if [[ ${rtt_trend:-0} -gt 30 ]]; then
        local cur=$(get_param "fast_alpha")
        if [[ ${cur:-0} -gt 10 ]]; then
            local new=$((cur - 5))
            set_param "fast_alpha" $new
            log ADJUST "RTT trending up (+${rtt_trend}), fast_alpha: $cur -> $new"
        fi
    fi

    # 4. 丢包率上升 -> 降低 max_cwnd
    local loss_trend=$(get_history_trend LOSS_HISTORY) || loss_trend=0
    if [[ ${loss_trend:-0} -gt 10 ]]; then
        local cur=$(get_param "max_cwnd")
        if [[ ${cur:-0} -gt 5000 ]]; then
            local new=$((cur * 9 / 10))
            set_param "max_cwnd" $new
            log ADJUST "Loss trending up (+${loss_trend}), max_cwnd: $cur -> $new"
        fi
    fi

    # 5. 网络稳定且 cwnd 使用率低 -> 可以提高 max_cwnd
    if [[ ${METRICS[rtt_cv]:-100} -lt 20 && ${METRICS[drop_rate_permille]:-0} -eq 0 ]]; then
        local cur_max=$(get_param "max_cwnd")
        local avg_cwnd=${METRICS[cwnd_avg]:-0}
        if [[ ${avg_cwnd:-0} -gt 0 && $((avg_cwnd * 2)) -gt ${cur_max:-0} && ${cur_max:-0} -lt 20000 ]]; then
            local new=$((cur_max + 1000))
            [[ $new -gt 25000 ]] && new=25000
            set_param "max_cwnd" $new
            log ADJUST "Network stable, avg_cwnd=$avg_cwnd, max_cwnd: $cur_max -> $new"
        fi
    fi

    # === 6. 激进丢包响应 ===
    local loss_severity=${METRICS[loss_severity]:-0}

    if [[ $loss_severity -ge 40 ]]; then
        # 严重丢包: 启用激进恢复
        local cur_beta=$(get_param "beta")
        if [[ ${cur_beta:-717} -lt 870 ]]; then
            set_param "beta" 870
            log ADJUST "Severe loss (severity=$loss_severity), beta: $cur_beta -> 870"
        fi

        # 增加恢复增益
        local cur_boost=$(get_param "recovery_boost")
        if [[ ${cur_boost:-20} -lt 40 ]]; then
            set_param "recovery_boost" 40
            log ADJUST "Enabling aggressive recovery_boost: 40"
        fi

        # 增加 inflight 余量
        set_param "inflight_headroom" 30

        # 增强 RACK-TLP
        set_param "rack_reord_thresh" 2
        set_param "tlp_max_probes" 4

        # 勇敢模式增强
        set_param "brave_enable" 1
        set_param "brave_rtt_pct" 50
        set_param "brave_hold_ms" 800
        set_param "brave_floor_pct" 90

    elif [[ $loss_severity -ge 20 ]]; then
        # 中度丢包: 轻度调整
        local cur_beta=$(get_param "beta")
        if [[ ${cur_beta:-717} -lt 819 ]]; then
            set_param "beta" 819
            log ADJUST "Moderate loss (severity=$loss_severity), beta: $cur_beta -> 819"
        fi

        set_param "recovery_boost" 30
        set_param "inflight_headroom" 20
        set_param "tlp_max_probes" 3
    fi

    # === 7. 超时率高 -> 需要更激进的 TLP ===
    if [[ ${METRICS[timeout_rate]:-0} -gt 5 ]]; then
        set_param "tlp_enable" 1
        set_param "tlp_timeout_div" 1       # 更短超时
        set_param "tlp_max_probes" 4
        log ADJUST "High timeout rate (${METRICS[timeout_rate]}/s), enhancing TLP"
    fi

    # === 8. NeoQ 集成: 调整 CoDel 参数 ===
    if [[ -f /proc/net/neoq ]]; then
        local rtt_avg=${METRICS[rtt_avg]:-0}
        local iface=""

        # 获取 NeoQ 启用的接口
        for dev in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
            if tc qdisc show dev "$dev" 2>/dev/null | grep -q neoq; then
                iface="$dev"
                break
            fi
        done

        if [[ -n "$iface" && $rtt_avg -gt 0 ]]; then
            local target_us=$((rtt_avg * 1000 / 4))   # RTT/4 作为目标
            local interval_us=$((rtt_avg * 1000 * 5)) # RTT*5 作为间隔

            # 限制范围
            [[ $target_us -lt 5000 ]] && target_us=5000
            [[ $target_us -gt 200000 ]] && target_us=200000
            [[ $interval_us -lt 20000 ]] && interval_us=20000
            [[ $interval_us -gt 1000000 ]] && interval_us=1000000

            # 丢包时更激进
            if [[ $loss_severity -ge 40 ]]; then
                target_us=$((target_us * 2))    # 更大队列容忍
                interval_us=$((interval_us * 2))
            fi

            # 更新 NeoQ (需要 tc 命令支持)
            tc qdisc change dev "$iface" root neoq target ${target_us}us interval ${interval_us}us 2>/dev/null && \
                log ADJUST "NeoQ adjusted: target=${target_us}us interval=${interval_us}us on $iface"
        fi
    fi

    # === 9. 丢包趋势下降时恢复 ===
    local loss_trend=$(get_history_trend LOSS_HISTORY) || loss_trend=0
    if [[ $loss_trend -lt -5 && ${METRICS[realtime_loss_rate]:-0} -lt 5 ]]; then
        # 丢包改善，可以逐步恢复
        local cur_beta=$(get_param "beta")
        if [[ ${cur_beta:-717} -gt 750 ]]; then
            local new_beta=$((cur_beta - 30))
            [[ $new_beta -lt 717 ]] && new_beta=717
            set_param "beta" $new_beta
            log ADJUST "Loss improving, beta: $cur_beta -> $new_beta"
        fi
    fi
}

# ============================================================================
# 主调整逻辑
# ============================================================================

do_adjust() {
    local now=$(date +%s)
    local elapsed=$((now - LAST_ADJUST_TIME))

    # 冷却检查
    if [[ $elapsed -lt $ADJUST_COOLDOWN ]]; then
        log DEBUG "In cooldown ($elapsed < $ADJUST_COOLDOWN seconds)"
        return 0
    fi

    # 更新历史
    update_history

    # 检测网络类型
    local network_type=$(detect_network_type)

    # 模式变化 -> 应用预设
    if [[ "$network_type" != "$CURRENT_MODE" ]]; then
        log INFO "Network type changed: $CURRENT_MODE -> $network_type (confidence: ${METRICS[confidence]:-0}%)"

        # 只有置信度 > 60% 才切换
        if [[ ${METRICS[confidence]:-0} -ge 60 ]]; then
            apply_preset "$network_type"
            CURRENT_MODE="$network_type"
            LAST_ADJUST_TIME=$now

            # 保存状态
            cat > "$STATE_FILE" << EOF
mode=$CURRENT_MODE
last_adjust=$LAST_ADJUST_TIME
rtt_avg=${METRICS[rtt_avg]:-0}
rtt_jitter=${METRICS[rtt_jitter]:-0}
drop_rate=${METRICS[drop_rate_permille]:-0}
ecn_rate=${METRICS[ecn_rate_permille]:-0}
confidence=${METRICS[confidence]:-0}
reason=${METRICS[detection_reason]:-unknown}
EOF
        else
            log DEBUG "Low confidence (${METRICS[confidence]:-0}%), keeping current mode"
        fi
    else
        # 同模式下微调
        fine_tune "$network_type"
    fi
}

# ============================================================================
# 状态显示
# ============================================================================

show_status() {
    # 禁用 set -e 防止采集失败导致退出
    set +e

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              LotSpeed Auto-Tune Status v2.1                        ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

    # 守护进程状态
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${CYAN}║${NC} Daemon: ${GREEN}Running${NC} (PID: $pid)"
        else
            # 自动清理过期 PID 文件
            rm -f "$PID_FILE"
            echo -e "${CYAN}║${NC} Daemon: ${YELLOW}Not running${NC} (cleaned stale PID)"
        fi
    else
        echo -e "${CYAN}║${NC} Daemon: ${YELLOW}Not running${NC}"
    fi

    # LotSpeed 模块状态
    if check_sysctl; then
        echo -e "${CYAN}║${NC} Module: ${GREEN}Loaded${NC}"
    else
        echo -e "${CYAN}║${NC} Module: ${RED}Not loaded${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
        return
    fi

    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

    # 采集指标
    collect_all_metrics

    echo -e "${CYAN}║${NC} ${YELLOW}Network Metrics:${NC}"
    printf "${CYAN}║${NC}   %-14s %s\n" "Connections:" "${METRICS[conn_count]} total, ${METRICS[lotspeed_count]} lotspeed"
    printf "${CYAN}║${NC}   %-14s avg=%dms min=%dms max=%dms jitter=%dms\n" "RTT:" \
        "${METRICS[rtt_avg]}" "${METRICS[rtt_min]}" "${METRICS[rtt_max]}" "${METRICS[rtt_jitter]}"
    printf "${CYAN}║${NC}   %-14s %d (cv=%d%%)\n" "Avg cwnd:" "${METRICS[cwnd_avg]}" "${METRICS[rtt_cv]}"
    printf "${CYAN}║${NC}   %-14s %d\n" "Retrans:" "${METRICS[retrans_total]}"
    printf "${CYAN}║${NC}   %-14s %d‰ (%.1f%%)\n" "Drop rate:" "${METRICS[drop_rate_permille]}" \
        "$(echo "scale=1; ${METRICS[drop_rate_permille]} / 10" | bc 2>/dev/null || echo "?")"
    printf "${CYAN}║${NC}   %-14s %d‰\n" "ECN rate:" "${METRICS[ecn_rate_permille]}"

    if [[ ${METRICS[neoq_packets]} -gt 0 ]]; then
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║${NC} ${YELLOW}NeoQ Stats:${NC}"
        printf "${CYAN}║${NC}   Packets: %d  Dropped: %d  ECN: %d  Delay: %dus\n" \
            "${METRICS[neoq_packets]}" "${METRICS[neoq_dropped]}" \
            "${METRICS[neoq_ecn_marked]}" "${METRICS[neoq_avg_delay]}"
    fi

    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

    # 检测网络类型
    local network_type=$(detect_network_type)
    echo -e "${CYAN}║${NC} ${YELLOW}Detection:${NC}"
    printf "${CYAN}║${NC}   Type:       ${GREEN}%s${NC}\n" "$network_type"
    printf "${CYAN}║${NC}   Confidence: %d%%\n" "${METRICS[confidence]}"
    printf "${CYAN}║${NC}   Reason:     %s\n" "${METRICS[detection_reason]}"

    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Current Parameters:${NC}"
    printf "${CYAN}║${NC}   min_cwnd=%-6d max_cwnd=%-6d beta=%-4d\n" \
        "$(get_param min_cwnd)" "$(get_param max_cwnd)" "$(get_param beta)"
    printf "${CYAN}║${NC}   fast_alpha=%-4d fast_gamma=%-4d\n" \
        "$(get_param fast_alpha)" "$(get_param fast_gamma)"
    printf "${CYAN}║${NC}   hd_enable=%-4d  hd_cwnd_gain=%-4d hd_pacing_gain=%-4d\n" \
        "$(get_param hd_enable)" "$(get_param hd_cwnd_gain)" "$(get_param hd_pacing_gain)"
    printf "${CYAN}║${NC}   brave_enable=%-2d brave_hold_ms=%-4d\n" \
        "$(get_param brave_enable)" "$(get_param brave_hold_ms)"
    printf "${CYAN}║${NC}   ecn_enable=%-4d ecn_thresh=%-4d ecn_factor=%-4d\n" \
        "$(get_param ecn_enable)" "$(get_param ecn_thresh)" "$(get_param ecn_factor)"
    printf "${CYAN}║${NC}   rack_enable=%-3d rack_thresh=%-3d tlp_enable=%-3d tlp_div=%-3d\n" \
        "$(get_param rack_enable)" "$(get_param rack_reord_thresh)" \
        "$(get_param tlp_enable)" "$(get_param tlp_timeout_div)"
    printf "${CYAN}║${NC}   hybla_exp=%-5d hybla_floor=%-6d\n" \
        "$(get_param hybla_gain_exp)" "$(get_param hybla_rtt_floor)"

    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
}

# ============================================================================
# 守护进程控制
# ============================================================================

start_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log ERROR "Daemon already running (PID: $pid)"
            exit 1
        fi
        rm -f "$PID_FILE"
    fi

    if ! check_sysctl; then
        log ERROR "LotSpeed module not loaded"
        exit 1
    fi

    # 确保日志目录存在
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/lotspeed-autotune.log"

    log INFO "Starting LotSpeed Auto-Tune daemon v2.1..."

    # 使用 setsid 创建新会话，确保进程完全脱离终端
    if command -v setsid &>/dev/null; then
        setsid "$0" run >> "$LOG_FILE" 2>&1 &
    else
        nohup "$0" run >> "$LOG_FILE" 2>&1 &
        disown 2>/dev/null || true
    fi

    # 等待 PID 文件被子进程创建
    local wait_count=0
    while [[ ! -f "$PID_FILE" ]] && [[ $wait_count -lt 10 ]]; do
        sleep 0.5
        wait_count=$((wait_count + 1))
    done

    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log INFO "Daemon started (PID: $pid)"
            echo -e "${GREEN}Daemon started (PID: $pid)${NC}"
            echo "Log: $LOG_FILE"
        else
            echo -e "${RED}Daemon process exited unexpectedly${NC}"
            echo "Check log: $LOG_FILE"
            tail -10 "$LOG_FILE" 2>/dev/null
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo -e "${RED}Failed to start daemon (timeout waiting for PID)${NC}"
        echo "Check log: $LOG_FILE"
        tail -10 "$LOG_FILE" 2>/dev/null
        exit 1
    fi
}

stop_daemon() {
    if [[ ! -f "$PID_FILE" ]]; then
        echo -e "${YELLOW}Daemon not running${NC}"
        return 0
    fi

    local pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        log INFO "Stopping daemon (PID: $pid)..."
        kill "$pid"
        rm -f "$PID_FILE"
        echo -e "${GREEN}Daemon stopped${NC}"
    else
        rm -f "$PID_FILE"
        echo -e "${YELLOW}Daemon was not running (cleaned stale PID)${NC}"
    fi
}

run_loop() {
    # 禁用 set -e，防止命令失败导致守护进程退出
    set +e

    # 设置信号处理，确保正常退出时清理 PID 文件
    trap 'rm -f "$PID_FILE"; log INFO "Daemon stopped"; exit 0' SIGTERM SIGINT SIGHUP

    # 写入 PID (run 模式下自己的 PID)
    echo $$ > "$PID_FILE"

    log INFO "Auto-tune daemon started (PID: $$)"

    if ! check_sysctl; then
        log ERROR "LotSpeed module not loaded"
        rm -f "$PID_FILE"
        exit 1
    fi

    # 初始检测
    collect_all_metrics || true
    CURRENT_MODE=$(detect_network_type) || CURRENT_MODE="normal"
    apply_preset "$CURRENT_MODE" || true
    LAST_ADJUST_TIME=$(date +%s)
    log INFO "Initial mode: $CURRENT_MODE (confidence: ${METRICS[confidence]:-0}%)"

    # 主循环
    while true; do
        # 检查 LotSpeed 模块是否仍然加载
        if ! check_sysctl; then
            log WARN "LotSpeed module unloaded, waiting..."
            sleep $SAMPLE_INTERVAL
            continue
        fi

        collect_all_metrics || true
        do_adjust || true
        sleep $SAMPLE_INTERVAL
    done
}

# ============================================================================
# 单次运行
# ============================================================================

run_once() {
    # 禁用 set -e 防止采集失败导致退出
    set +e

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              LotSpeed Auto-Tune - Analysis                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo

    if ! check_sysctl; then
        echo -e "${YELLOW}[WARN] LotSpeed module not loaded - running in analysis mode${NC}"
        echo
    fi

    echo -e "${YELLOW}Step 1: Collecting metrics...${NC}"
    collect_all_metrics || true
    echo -e "${GREEN}Done${NC}"
    echo

    echo -e "${YELLOW}Step 2: Current metrics:${NC}"
    printf "  %-20s %d total, %d using lotspeed\n" "Connections:" "${METRICS[conn_count]}" "${METRICS[lotspeed_count]}"
    printf "  %-20s avg=%dms min=%dms max=%dms jitter=%dms\n" "RTT:" \
        "${METRICS[rtt_avg]}" "${METRICS[rtt_min]}" "${METRICS[rtt_max]}" "${METRICS[rtt_jitter]}"
    printf "  %-20s %d (variation: %d%%)\n" "Average cwnd:" "${METRICS[cwnd_avg]}" "${METRICS[rtt_cv]}"
    printf "  %-20s %d\n" "Total retrans:" "${METRICS[retrans_total]}"
    printf "  %-20s %d‰ (%.2f%%)\n" "Drop rate:" "${METRICS[drop_rate_permille]}" \
        "$(echo "scale=2; ${METRICS[drop_rate_permille]} / 10" | bc 2>/dev/null || echo "?")"
    printf "  %-20s %d‰\n" "ECN mark rate:" "${METRICS[ecn_rate_permille]}"
    echo

    echo -e "${YELLOW}Step 3: Detecting network type...${NC}"
    local network_type=$(detect_network_type)
    echo -e "  Type:       ${GREEN}$network_type${NC}"
    echo -e "  Confidence: ${METRICS[confidence]}%"
    echo -e "  Reason:     ${METRICS[detection_reason]}"
    echo

    echo -e "${YELLOW}Step 4: Recommended preset:${NC}"
    echo -e "  ${GREEN}$network_type${NC}"
    echo
    echo "  Key parameters for this preset:"
    case "$network_type" in
        datacenter)
            echo "    - Aggressive settings for ultra-low latency"
            echo "    - max_cwnd=30000, beta=819 (80%)"
            echo "    - hd_enable=0, brave_enable=0"
            echo "    - ecn_thresh=20 (sensitive)"
            echo "    - RACK-TLP: enabled, sensitive detection"
            echo "    - Hybla: disabled (rho^1.0)"
            ;;
        satellite)
            echo "    - Optimized for very high latency (300+ ms)"
            echo "    - max_cwnd=50000, min_cwnd=256"
            echo "    - hd_cwnd_gain=250 (2.5x compensation)"
            echo "    - brave_hold_ms=1000"
            echo "    - RACK-TLP: enabled with conservative thresholds"
            echo "    - Hybla: rho^2.0 (maximum compensation)"
            ;;
        highdelay)
            echo "    - Optimized for 100-300ms RTT"
            echo "    - max_cwnd=25000, hd_enable=1"
            echo "    - hd_cwnd_gain=180, hd_pacing_gain=150"
            echo "    - RACK-TLP: enabled with adjusted thresholds"
            echo "    - Hybla: rho^1.5 (recommended compensation)"
            ;;
        lossy*)
            echo "    - Conservative for packet loss"
            echo "    - Lower max_cwnd, higher recovery"
            echo "    - beta=512-614 (50-60%)"
            echo "    - RACK-TLP: enabled, sensitive detection"
            echo "    - Hybla: disabled"
            ;;
        jittery)
            echo "    - Brave mode for RTT variance"
            echo "    - brave_hold_ms=600, brave_rtt_pct=50"
            echo "    - RACK-TLP: enabled with tolerant thresholds"
            echo "    - Hybla: light compensation (rho^1.2)"
            ;;
        congested)
            echo "    - ECN-responsive"
            echo "    - ecn_thresh=10, ecn_alpha_gain=8"
            echo "    - RACK-TLP: enabled"
            echo "    - Hybla: disabled"
            ;;
        *)
            echo "    - Balanced settings"
            echo "    - RACK-TLP: enabled (default)"
            echo "    - Hybla: rho^1.5 (recommended)"
            ;;
    esac
    echo

    if check_sysctl; then
        echo -e "${YELLOW}Apply this preset? [y/N]${NC} "
        read -r answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            apply_preset "$network_type"
            echo -e "${GREEN}Preset applied!${NC}"
        else
            echo "Skipped."
        fi
    fi
}

# ============================================================================
# 主入口
# ============================================================================

case "${1:-}" in
    daemon|start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 1
        start_daemon
        ;;
    status)
        show_status
        ;;
    run)
        run_loop
        ;;
    aggressive|anti-loss|anti_loss)
        # 快速应用激进抗丢包预设
        if ! check_sysctl; then
            echo -e "${RED}LotSpeed module not loaded${NC}"
            exit 1
        fi
        echo -e "${CYAN}Applying anti-loss preset...${NC}"
        apply_preset "anti_loss"
        echo -e "${GREEN}Done! Parameters optimized for loss recovery.${NC}"
        echo
        echo "Key settings:"
        echo "  beta=870 (85% recovery)"
        echo "  recovery_boost=40"
        echo "  brave_hold_ms=800"
        echo "  tlp_max_probes=4"
        ;;
    ultra|ultra-aggressive|ultra_aggressive)
        # 快速应用超激进预设
        if ! check_sysctl; then
            echo -e "${RED}LotSpeed module not loaded${NC}"
            exit 1
        fi
        echo -e "${CYAN}Applying ultra-aggressive preset...${NC}"
        apply_preset "ultra_aggressive"
        echo -e "${GREEN}Done! Maximum throughput mode enabled.${NC}"
        echo
        echo "Key settings:"
        echo "  beta=922 (90% recovery)"
        echo "  max_cwnd=50000"
        echo "  startup_gain=500"
        echo "  hybla_gain_exp=200 (rho^2.0)"
        ;;
    preset)
        # 手动应用指定预设
        if [[ -z "$2" ]]; then
            echo "Usage: $0 preset <name>"
            echo "Available: normal, anti_loss, ultra_aggressive, loss_recovery,"
            echo "           datacenter, satellite, highdelay, lossy, lossy_severe,"
            echo "           jittery, congested, lan, mild_congestion"
            exit 1
        fi
        if ! check_sysctl; then
            echo -e "${RED}LotSpeed module not loaded${NC}"
            exit 1
        fi
        echo -e "${CYAN}Applying preset: $2${NC}"
        apply_preset "$2"
        echo -e "${GREEN}Done!${NC}"
        ;;
    once|test|"")
        run_once
        ;;
    -h|--help|help)
        echo "LotSpeed Auto-Tune Daemon v2.1"
        echo
        echo "Usage: $0 [command]"
        echo
        echo "Commands:"
        echo "  (none)    Analyze network and suggest preset"
        echo "  status    Show current status and metrics"
        echo "  daemon    Start background daemon"
        echo "  stop      Stop background daemon"
        echo "  restart   Restart daemon"
        echo "  aggressive    Apply anti_loss preset immediately"
        echo "  ultra         Apply ultra_aggressive preset"
        echo
        echo "Presets (use with 'preset <name>'):"
        echo "  normal        Balanced settings (default)"
        echo "  anti_loss     Aggressive loss recovery, fast retransmit"
        echo "  ultra_aggressive  Maximum throughput, large queues"
        echo "  loss_recovery Optimized for active loss conditions"
        echo "  datacenter    Ultra-low latency, ECN-focused"
        echo "  satellite     Very high delay (300+ ms)"
        echo "  highdelay     High delay WAN (100-300ms)"
        echo "  lossy         Moderate packet loss (1-5%)"
        echo "  lossy_severe  Severe packet loss (>5%)"
        echo "  jittery       High RTT variance (mobile/WiFi)"
        echo "  congested     High ECN marks"
        echo
        echo "Environment:"
        echo "  DEBUG=1   Enable debug output"
        echo
        echo "Files:"
        echo "  Log:    $LOG_FILE"
        echo "  PID:    $PID_FILE"
        echo "  State:  $STATE_FILE"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Run '$0 --help' for usage"
        exit 1
        ;;
esac
