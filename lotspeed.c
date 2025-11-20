// lotspeed.c  ——  2025 年的"锐速"复活版 v2.1 (动态速率优化版)
// Author: uk0 @ 2025-11-19 17:06:58
// 致敬经典 LotServer/ServerSpeeder，为新时代而生

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

// 版本兼容性检测 - 修正版本判断逻辑
// 根据实际测试：6.8.0 使用旧API，6.17+ 使用新API
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)
#define KERNEL_6_17_PLUS 1
    #define NEW_CONG_CONTROL_API 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0) && LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)
// 6.9 - 6.16 使用新API (需要进一步测试确认)
    #define NEW_CONG_CONTROL_API 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0) && LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
// 5.19 - 6.7.x 使用新API
    #define NEW_CONG_CONTROL_API 1
#else
// 6.8.0 - 6.8.x 以及更早版本使用旧API
#define OLD_CONG_CONTROL_API 1
#endif

// 可调参数（通过 sysfs 动态修改）
static unsigned long lotserver_rate = 125000000ULL;  // 默认 1Gbps (现在是最高速率上限)
static unsigned int lotserver_gain = 15;               // 1.5x 默认增益
static unsigned int lotserver_min_cwnd = 50;           // 最小拥塞窗口
static unsigned int lotserver_max_cwnd = 10000;        // 最大拥塞窗口
static bool lotserver_adaptive = true;                 // 自适应模式
static bool lotserver_turbo = false;                   // 涡轮模式
static bool lotserver_verbose = false;                  // 详细日志模式
static bool force_unload = false;

// 参数变更回调 - 速率
static int param_set_rate(const char *val, const struct kernel_param *kp)
{
    unsigned long old_val = lotserver_rate;
    int ret = param_set_ulong(val, kp);

    if (ret == 0 && old_val != lotserver_rate && lotserver_verbose) {
        unsigned long gbps_int = lotserver_rate / 125000000;
        unsigned long gbps_frac = (lotserver_rate % 125000000) * 100 / 125000000;
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] rate changed: %lu -> %lu (%lu.%02lu Gbps)\n",
                old_val, lotserver_rate, gbps_int, gbps_frac);
    }
    return ret;
}

// 参数变更回调 - 增益
static int param_set_gain(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_gain;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_gain && lotserver_verbose) {
        unsigned int gain_int = lotserver_gain / 10;
        unsigned int gain_frac = lotserver_gain % 10;
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] gain changed: %u -> %u (%u.%ux)\n",
                old_val, lotserver_gain, gain_int, gain_frac);
    }
    return ret;
}

// 参数变更回调 - 最小窗口
static int param_set_min_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_min_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_min_cwnd && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] min_cwnd changed: %u -> %u\n",
                old_val, lotserver_min_cwnd);
    }
    return ret;
}

// 参数变更回调 - 最大窗口
static int param_set_max_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_max_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_max_cwnd && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] max_cwnd changed: %u -> %u\n",
                old_val, lotserver_max_cwnd);
    }
    return ret;
}

// 参数变更回调 - 自适应模式
static int param_set_adaptive(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_adaptive;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_adaptive && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] adaptive mode: %s -> %s\n",
                old_val ? "ON" : "OFF", lotserver_adaptive ? "ON" : "OFF");
    }
    return ret;
}

// 参数变更回调 - 涡轮模式
static int param_set_turbo(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_turbo;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_turbo && lotserver_verbose) {
        if (lotserver_turbo) {
            pr_info("lotspeed: [uk0@2025-11-19 17:06:58] ⚡⚡⚡ TURBO MODE ACTIVATED ⚡⚡⚡\n");
            pr_info("lotspeed: WARNING: Ignoring ALL congestion signals!\n");
        } else {
            pr_info("lotspeed: [uk0@2025-11-19 17:06:58] Turbo mode DEACTIVATED\n");
        }
    }
    return ret;
}

// 自定义参数操作
static const struct kernel_param_ops param_ops_rate = {
        .set = param_set_rate,
        .get = param_get_ulong,
};

static const struct kernel_param_ops param_ops_gain = {
        .set = param_set_gain,
        .get = param_get_uint,
};

static const struct kernel_param_ops param_ops_min_cwnd = {
        .set = param_set_min_cwnd,
        .get = param_get_uint,
};

static const struct kernel_param_ops param_ops_max_cwnd = {
        .set = param_set_max_cwnd,
        .get = param_get_uint,
};

static const struct kernel_param_ops param_ops_adaptive = {
        .set = param_set_adaptive,
        .get = param_get_bool,
};

static const struct kernel_param_ops param_ops_turbo = {
        .set = param_set_turbo,
        .get = param_get_bool,
};

// 注册参数
module_param(force_unload, bool, 0644);
MODULE_PARM_DESC(force_unload, "Force unload module ignoring references");

module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
MODULE_PARM_DESC(lotserver_rate, "Target rate in bytes/sec (default 1Gbps)");

module_param_cb(lotserver_gain, &param_ops_gain, &lotserver_gain, 0644);
MODULE_PARM_DESC(lotserver_gain, "Gain multiplier x10 (30 = 3.0x)");

module_param_cb(lotserver_min_cwnd, &param_ops_min_cwnd, &lotserver_min_cwnd, 0644);
MODULE_PARM_DESC(lotserver_min_cwnd, "Minimum congestion window");

module_param_cb(lotserver_max_cwnd, &param_ops_max_cwnd, &lotserver_max_cwnd, 0644);
MODULE_PARM_DESC(lotserver_max_cwnd, "Maximum congestion window");

module_param_cb(lotserver_adaptive, &param_ops_adaptive, &lotserver_adaptive, 0644);
MODULE_PARM_DESC(lotserver_adaptive, "Enable adaptive rate control");

module_param_cb(lotserver_turbo, &param_ops_turbo, &lotserver_turbo, 0644);
MODULE_PARM_DESC(lotserver_turbo, "Turbo mode - ignore all congestion signals");

module_param(lotserver_verbose, bool, 0644);
MODULE_PARM_DESC(lotserver_verbose, "Enable verbose logging");

// 统计信息
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t total_losses = ATOMIC_INIT(0);
static atomic_t module_ref_count = ATOMIC_INIT(0);

// 定义自适应速率调整的状态
enum lotspeed_adapt_state {
    PROBING,  // 探测更高带宽
    CRUISING, // 稳定在瓶颈带宽
    AVOIDING, // 拥塞规避
};

struct lotspeed {
    u64 target_rate;
    u64 actual_rate;
    u32 cwnd_gain;
    u32 loss_count;
    u32 rtt_min;
    u32 rtt_cnt;
    u64 last_update;
    bool ss_mode;
    u32 probe_cnt;
    u64 bytes_sent;
    u64 start_time;
    enum lotspeed_adapt_state adapt_state; // 新增：自适应状态
    u64 last_cruise_ts;                   // 新增：上次进入 CRUISING 状态的时间戳
};

static struct tcp_congestion_ops lotspeed_ops;

// 初始化连接
static void lotspeed_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);

    // 初始化状态
    tp->snd_ssthresh = lotserver_turbo ? TCP_INFINITE_SSTHRESH : tp->snd_cwnd * 2;
    ca->target_rate = lotserver_rate;
    ca->actual_rate = 0;
    ca->cwnd_gain = lotserver_gain;
    ca->loss_count = 0;
    ca->rtt_min = 0;
    ca->rtt_cnt = 0;
    ca->last_update = tcp_jiffies32;
    ca->ss_mode = true;
    ca->probe_cnt = 0;
    ca->bytes_sent = 0;
    ca->start_time = ktime_get_real_seconds();
    ca->adapt_state = PROBING; // 初始状态为探测
    ca->last_cruise_ts = 0;    // 初始化时间戳

    // 强制开启 pacing
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);
    atomic_inc(&module_ref_count);

    if (lotserver_verbose) {
        unsigned long gbps_int = ca->target_rate / 125000000;
        unsigned long gbps_frac = (ca->target_rate % 125000000) * 100 / 125000000;
        unsigned int gain_int = ca->cwnd_gain / 10;
        unsigned int gain_frac = ca->cwnd_gain % 10;

        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] NEW connection #%d | rate=%lu.%02lu Gbps | gain=%u.%ux | mode=%s\n",
                atomic_read(&active_connections),
                gbps_int, gbps_frac,
                gain_int, gain_frac,
                lotserver_turbo ? "TURBO" : (lotserver_adaptive ? "adaptive" : "fixed"));
    }
}

// 释放连接
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 duration;

    // 添加空指针检查
    if (!ca) {
        pr_warn("lotspeed: [uk0@2025-11-19 17:06:58] release called with NULL ca\n");
        atomic_dec(&active_connections);
        return;
    }

    // 安全获取 duration
    if (ca->start_time > 0) {
        duration = ktime_get_real_seconds() - ca->start_time;
    } else {
        duration = 0;
    }

    atomic_dec(&active_connections);

    // 只有在有数据时才更新统计
    if (ca->bytes_sent > 0) {
        atomic64_add(ca->bytes_sent, &total_bytes_sent);
    }
    if (ca->loss_count > 0) {
        atomic_add(ca->loss_count, &total_losses);
    }

    if (lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-19 17:06:58] connection released, active=%d\n",
                atomic_read(&active_connections));
    }

    // 清理 ca 结构
    memset(ca, 0, sizeof(struct lotspeed));
}

// 更新 RTT 统计
static void lotspeed_update_rtt(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u32 rtt_us = tp->srtt_us >> 3;

    if (!rtt_us || rtt_us == 0)
        return;

    // 记录最小 RTT 作为基准
    if (!ca->rtt_min || rtt_us < ca->rtt_min) {
        ca->rtt_min = rtt_us;
        if (lotserver_verbose && ca->rtt_cnt > 100) {
            pr_debug("lotspeed: new min RTT: %u us\n", ca->rtt_min);
        }
    }

    ca->rtt_cnt++;
}

// 自适应速率调整 (v2.1 状态机版本)
static void lotspeed_adapt_rate(struct sock *sk, const struct rate_sample *rs)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 bw;
    u32 rtt_us = tp->srtt_us >> 3;
    bool congestion_detected;

    // 如果关闭自适应模式，则直接返回
    if (!lotserver_adaptive) {
        ca->target_rate = lotserver_rate; // 始终使用全局设定值
        ca->cwnd_gain = lotserver_gain;
        return;
    }

    // 必须有有效的 rate_sample 和 RTT
    if (!rs || rs->delivered <= 0 || rs->interval_us <= 0 || !rtt_us)
        return;

    // 计算当前实际带宽 (Bps)
    bw = (u64)rs->delivered * USEC_PER_SEC;
    do_div(bw, rs->interval_us);
    ca->actual_rate = bw;

    // 更新发送字节数 (修正：rs->delivered 本身就是字节数)
    ca->bytes_sent += rs->delivered;

    // --- 状态机逻辑 ---

    // 拥塞信号检测：RTT膨胀 或 丢包
    congestion_detected = (ca->rtt_min > 0 && rtt_us > ca->rtt_min * 12 / 10 + 1000); // RTT膨胀超过20% + 1ms
    if (rs->losses > 0) {
        congestion_detected = true;
    }

    // 状态转换：
    // 1. 如果检测到拥塞，立即进入 AVOIDING 状态
    if (congestion_detected && ca->adapt_state != AVOIDING) {
        ca->adapt_state = AVOIDING;
        if (lotserver_verbose)
            pr_info("lotspeed: [uk0] adapt -> AVOIDING (RTT: %u > %u or loss)\n", rtt_us, ca->rtt_min * 12 / 10);
    }
        // 2. 如果带宽利用率高且无拥塞，可能已达瓶颈，进入 CRUISING
    else if (!congestion_detected && bw > ca->target_rate * 9 / 10 && ca->adapt_state == PROBING) {
        ca->adapt_state = CRUISING;
        ca->last_cruise_ts = tcp_jiffies32;
        if (lotserver_verbose)
            pr_info("lotspeed: [uk0] adapt -> CRUISING (bw: %llu, target: %llu)\n", bw, ca->target_rate);
    }
        // 3. 如果在 AVOIDING 状态下拥塞消失，切换回 PROBING
    else if (!congestion_detected && ca->adapt_state == AVOIDING) {
        ca->adapt_state = PROBING;
        if (lotserver_verbose)
            pr_info("lotspeed: [uk0] adapt -> PROBING (congestion cleared)\n");
    }

    // --- 根据状态调整速率和增益 ---
    switch (ca->adapt_state) {
        case PROBING:
            // 积极探测：每次增加 10% 的速率，增益也逐步恢复
            ca->target_rate = ca->target_rate * 11 / 10;
            ca->cwnd_gain = min_t(u32, ca->cwnd_gain + 1, lotserver_gain);
            break;

        case CRUISING:
            // 稳定巡航：将目标速率设定为略高于当前实测带宽，以保持链路饱满
            ca->target_rate = bw * 11 / 10; // 设定 10% 的headroom

            // 周期性探测：每隔一段时间（如200ms）主动进入PROBING，以防瓶颈带宽变大
            if (jiffies_to_msecs(tcp_jiffies32 - ca->last_cruise_ts) > 200) {
                ca->adapt_state = PROBING;
                if (lotserver_verbose)
                    pr_info("lotspeed: [uk0] adapt -> PROBING (periodic probe)\n");
            }
            break;

        case AVOIDING:
            // 拥塞规避：将目标速率降低到当前实测带宽的 90%，并大幅降低增益
            ca->target_rate = max_t(u64, bw * 9 / 10, lotserver_rate / 10); // 速率乘性降低，但有下限
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10); // 增益也降低
            break;
    }

    // 最后，对 target_rate 和 cwnd_gain 应用全局限制
    ca->target_rate = min_t(u64, ca->target_rate, lotserver_rate); // 不能超过用户设定的最大值
    ca->target_rate = max_t(u64, ca->target_rate, lotserver_rate / 20); // 保证一个最小速率 (5%)
    ca->cwnd_gain = min_t(u32, ca->cwnd_gain, lotserver_gain); // 增益不超过全局设定
    ca->cwnd_gain = max_t(u32, ca->cwnd_gain, 10); // 最小增益为 1.0x
}

// 核心拥塞控制逻辑实现（内部函数）
static void lotspeed_cong_control_impl(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 rate;
    u32 cwnd;
    u32 rtt_us = tp->srtt_us >> 3;
    u32 mss = tp->mss_cache;
    u32 target_cwnd;

    // 默认值处理
    if (!rtt_us) rtt_us = 1000;   // 1ms 默认
    if (!mss) mss = 1460;          // 标准以太网 MSS

    // 更新 RTT 统计
    lotspeed_update_rtt(sk);

    // 自适应调整
    lotspeed_adapt_rate(sk, rs);

    // 选择速率
    rate = ca->target_rate;

    // 核心公式：CWND = (rate × RTT) / MSS × gain
    target_cwnd = div64_u64(rate * (u64)rtt_us, (u64)mss * 1000000);
    target_cwnd = div_u64(target_cwnd * ca->cwnd_gain, 10);

    // 慢启动阶段特殊处理
    if (ca->ss_mode && tp->snd_cwnd < tp->snd_ssthresh) {
        // 指数增长
        cwnd = tp->snd_cwnd * 2;
        if (cwnd >= target_cwnd) {
            ca->ss_mode = false;
            cwnd = target_cwnd;
        }
    } else {
        // 正常阶段
        cwnd = target_cwnd;

        // 周期性探测更高速率
        ca->probe_cnt++;
        if (ca->probe_cnt >= 100) {  // 每 100 个 RTT 探测一次
            cwnd = cwnd * 11 / 10;   // 探测 +10%
            ca->probe_cnt = 0;
        }
    }

    // 应用安全限制
    cwnd = max_t(u32, cwnd, lotserver_min_cwnd);
    cwnd = min_t(u32, cwnd, lotserver_max_cwnd);
    cwnd = min_t(u32, cwnd, tp->snd_cwnd_clamp);

    // 设置拥塞窗口和 pacing 速率
    tp->snd_cwnd = cwnd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    // 改进: 给予 20% 的 Overhead 空间，防止 Pacing 限制了 TCP 本身的突发能力
    // 许多网卡需要小规模的突发来维持高吞吐
    sk->sk_pacing_rate = (rate * 6) / 5; // Rate * 1.2
#endif

    // 定期状态输出
    if (lotserver_verbose && ca->rtt_cnt > 0 && ca->rtt_cnt % 1000 == 0) {
        unsigned long gbps_int = rate / 125000000;
        unsigned long gbps_frac = (rate % 125000000) * 100 / 125000000;
        unsigned int gain_int = ca->cwnd_gain / 10;
        unsigned int gain_frac = ca->cwnd_gain % 10;

        pr_info("lotspeed: [uk0] STATUS: cwnd=%u | rate=%lu.%02lu Gbps | RTT=%u us | gain=%u.%ux | losses=%u\n",
                cwnd, gbps_int, gbps_frac, rtt_us, gain_int, gain_frac, ca->loss_count);
    }
}

// 主拥塞控制函数 - 兼容不同内核版本
#ifdef NEW_CONG_CONTROL_API
// 新版本内核 (5.19-6.7.x, 6.9+, 6.17+)
static void lotspeed_cong_control(struct sock *sk, u32 ack, int flag,
                                  const struct rate_sample *rs)
{
    // 新版本可以使用 ack 和 flag 参数进行更精细的控制
    #ifdef KERNEL_6_17_PLUS
    // 6.17+ 内核的特殊处理
    if (flag & CA_ACK_ECE && lotserver_verbose) {
        pr_debug("lotspeed: [6.17+] ECN echo received, ack=%u\n", ack);
    }
    #endif

    // 调用实际的拥塞控制逻辑
    lotspeed_cong_control_impl(sk, rs);
}
#else
// 旧版本内核 (5.18 及以下, 6.8.0-6.8.x)
static void lotspeed_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    // 直接调用实际的拥塞控制逻辑
    lotspeed_cong_control_impl(sk, rs);
}
#endif

// 处理状态变化
static void lotspeed_set_state(struct sock *sk, u8 new_state)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    switch (new_state) {
        case TCP_CA_Loss:
            // 涡轮模式完全无视丢包
            if (lotserver_turbo) {
                tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
                if (lotserver_verbose && ca->loss_count % 10 == 0) {
                    pr_info("lotspeed: [uk0] TURBO: Ignoring loss #%u\n", ca->loss_count + 1);
                }
                return;
            }
            // 记录丢包
            ca->loss_count++;
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);

            if (lotserver_verbose && (ca->loss_count == 1 || ca->loss_count % 10 == 0)) {
                unsigned int gain_int = ca->cwnd_gain / 10;
                unsigned int gain_frac = ca->cwnd_gain % 10;
                pr_info("lotspeed: [uk0] LOSS #%u detected, gain reduced to %u.%ux\n",
                        ca->loss_count, gain_int, gain_frac);
            }
            break;

        case TCP_CA_Recovery:
            // 进入恢复阶段
            if (!lotserver_turbo) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 9 / 10, 15);
            }
            break;

        case TCP_CA_Open:
            // 恢复正常
            ca->ss_mode = false;
            break;

        default:
            break;
    }
}

// 丢包时的 ssthresh
static u32 lotspeed_ssthresh(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    // 涡轮模式：永不降速
    if (lotserver_turbo) {
        return TCP_INFINITE_SSTHRESH;
    }

    // 温和降速
    ca->loss_count++;
    ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);

    return max_t(u32, tp->snd_cwnd * 7 / 10, lotserver_min_cwnd);
}

// 恢复拥塞窗口
static u32 lotspeed_undo_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);

    // 误判恢复，重置丢包计数
    ca->loss_count = 0;
    ca->ss_mode = false;

    return max(tp->snd_cwnd, tp->prior_cwnd);
}

// 处理拥塞事件
static void lotspeed_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct lotspeed *ca = inet_csk_ca(sk);

    switch (event) {
        case CA_EVENT_LOSS:
            // 发生丢包
            ca->loss_count++;
            if (!lotserver_turbo) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain - 5, 10);
            }
            break;

        case CA_EVENT_TX_START:
            // 开始传输
            ca->ss_mode = true;
            ca->probe_cnt = 0;
            break;

        case CA_EVENT_CWND_RESTART:
            // 重新开始
            ca->ss_mode = true;
            ca->loss_count = 0;
            ca->probe_cnt = 0;
            break;

        default:
            // 其他事件忽略
            break;
    }
}

static struct tcp_congestion_ops lotspeed_ops __read_mostly = {
        .name           = "lotspeed",
        .owner          = THIS_MODULE,
        .init           = lotspeed_init,
        .release        = lotspeed_release,
        .cong_control   = lotspeed_cong_control,
        .set_state      = lotspeed_set_state,
        .ssthresh       = lotspeed_ssthresh,
        .undo_cwnd      = lotspeed_undo_cwnd,
        .cwnd_event     = lotspeed_cwnd_event,
        .flags          = TCP_CONG_NON_RESTRICTED,
};

// 辅助函数来格式化带边框的行
static void print_boxed_line(const char *prefix, const char *content)
{
    int prefix_len = strlen(prefix);
    int content_len = strlen(content);
    int total_len = prefix_len + content_len;
    int padding = 56 - total_len;  // 56 = 60 - 2个边框字符

    if (padding < 0) padding = 0;

    pr_info("║%s%s%*s║\n", prefix, content, padding, "");
}

static int __init lotspeed_module_init(void)
{
    unsigned long gbps_int, gbps_frac;
    unsigned int gain_int, gain_frac;
    char buffer[128];

    BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);

    pr_info("╔════════════════════════════════════════════════════════╗\n");
    pr_info("║          LotSpeed v2.1 - 锐速复活版 (动态优化)         ║\n");

    // 动态生成时间和用户行
    snprintf(buffer, sizeof(buffer), "uk0 @ 2025-11-19 17:06:58");
    print_boxed_line("          Created by ", buffer);

    // 动态生成内核版本行
    snprintf(buffer, sizeof(buffer), "%u.%u.%u",
             LINUX_VERSION_CODE >> 16,
             (LINUX_VERSION_CODE >> 8) & 0xff,
             LINUX_VERSION_CODE & 0xff);
    print_boxed_line("          Kernel: ", buffer);

    // 显示API版本信息
#ifdef KERNEL_6_17_PLUS
    pr_info("║          API: NEW (6.17+ special)                      ║\n");
#elif defined(NEW_CONG_CONTROL_API)
    pr_info("║          API: NEW (5.19-6.7.x, 6.9+)                   ║\n");
#elif defined(OLD_CONG_CONTROL_API)
    pr_info("║          API: LEGACY (6.8.0-6.8.x and older)           ║\n");
#else
    pr_info("║          API: LEGACY (<5.19)                           ║\n");
#endif

    pr_info("╚════════════════════════════════════════════════════════╝\n");

    gbps_int = lotserver_rate / 125000000;
    gbps_frac = (lotserver_rate % 125000000) * 100 / 125000000;
    gain_int = lotserver_gain / 10;
    gain_frac = lotserver_gain % 10;

    pr_info("Initial Parameters:\n");
    pr_info("  Max Rate: %lu.%02lu Gbps\n", gbps_int, gbps_frac);
    pr_info("  Max Gain: %u.%ux\n", gain_int, gain_frac);
    pr_info("  Min/Max CWND: %u/%u\n", lotserver_min_cwnd, lotserver_max_cwnd);
    pr_info("  Adaptive: %s | Turbo: %s | Verbose: %s\n",
            lotserver_adaptive ? "ON" : "OFF",
            lotserver_turbo ? "ON" : "OFF",
            lotserver_verbose ? "ON" : "OFF");

    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    u64 total_bytes;
    u64 gb_sent, mb_sent;
    int active_conns;
    int retry_count = 0;

    pr_info("lotspeed: [uk0@2025-11-19 17:06:58] Beginning module unload\n");

    // 先注销算法，防止新连接使用
    tcp_unregister_congestion_control(&lotspeed_ops);
    pr_info("lotspeed: Unregistered from TCP stack\n");

    // 等待现有连接释放（最多等待5秒）
    while (atomic_read(&active_connections) > 0 && retry_count < 50) {
        pr_info("lotspeed: Waiting for %d connections to close (attempt %d/50)\n",
                atomic_read(&active_connections), retry_count + 1);
        msleep(100);  // 等待100ms
        retry_count++;
    }

    active_conns = atomic_read(&active_connections);

    if (active_conns > 0) {
        pr_err("lotspeed: WARNING - Force unloading with %d active connections!\n", active_conns);
        pr_err("lotspeed: This may cause system instability!\n");

        if (!force_unload) {
            pr_err("lotspeed: Refusing to unload. Set force_unload=1 to override\n");
            pr_err("lotspeed: echo 1 > /sys/module/lotspeed/parameters/force_unload\n");

            // 重新注册以保持稳定
            tcp_register_congestion_control(&lotspeed_ops);
            return;  // 拒绝卸载
        }
    }

    total_bytes = atomic64_read(&total_bytes_sent);
    gb_sent = total_bytes >> 30;
    mb_sent = (total_bytes >> 20) & 0x3FF;

    pr_info("╔════════════════════════════════════════════════════════╗\n");
    pr_info("║          LotSpeed v2.1 Unloaded                        ║\n");
    pr_info("║          Time: 2025-11-19 17:06:58                     ║\n");
    pr_info("║          User: uk0                                     ║\n");
    pr_info("║          Active Connections: %-26d║\n", active_conns);
    pr_info("║          Data Sent: %llu.%llu GB%*s║\n",
            gb_sent, mb_sent * 1000 / 1024,
            (int)(30 - snprintf(NULL, 0, "%llu.%llu GB", gb_sent, mb_sent * 1000 / 1024)), "");
    pr_info("╚════════════════════════════════════════════════════════╝\n");
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0 <github.com/uk0>");
MODULE_VERSION("2.1");
MODULE_DESCRIPTION("LotSpeed v2.1 - Modern LotServer/ServerSpeeder replacement with dynamic rate control");
MODULE_ALIAS("tcp_lotspeed");