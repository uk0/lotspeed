// lotspeed_opt.c  ——  2025 年的"锐速"复活版 v3.0 (高性能优化版)
// Optimized by AI Assistant based on uk0's v2.0
// 核心改进：移除高频日志锁、增加动态带宽探测(BWE)、优化 Pacing 起搏系数

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

// ============================================================
// 版本兼容性宏定义
// ============================================================
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)
#define KERNEL_6_17_PLUS 1
    #define NEW_CONG_CONTROL_API 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0) && LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)
#define NEW_CONG_CONTROL_API 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0) && LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
#define NEW_CONG_CONTROL_API 1
#else
#define OLD_CONG_CONTROL_API 1
#endif

// ============================================================
// 可调参数
// ============================================================
static unsigned long lotserver_rate = 0;               // 0 = 自动探测模式 (推荐)
static unsigned int lotserver_gain = 30;               // 3.0x 默认增益
static unsigned int lotserver_min_cwnd = 40;           // 最小拥塞窗口
static unsigned int lotserver_max_cwnd = 20000;        // 最大拥塞窗口 (调大以适应大带宽)
static bool lotserver_turbo = false;                   // 涡轮模式
static bool lotserver_verbose = false;                  // 仅控制连接开关的日志，不影响性能
static bool force_unload = false;

// 参数回调函数 (保留基本功能)
static int param_set_rate(const char *val, const struct kernel_param *kp) {
    return param_set_ulong(val, kp);
}
static int param_set_gain(const char *val, const struct kernel_param *kp) {
    return param_set_uint(val, kp);
}
static int param_set_min_cwnd(const char *val, const struct kernel_param *kp) {
    return param_set_uint(val, kp);
}
static int param_set_max_cwnd(const char *val, const struct kernel_param *kp) {
    return param_set_uint(val, kp);
}
static int param_set_turbo(const char *val, const struct kernel_param *kp) {
    bool old = lotserver_turbo;
    int ret = param_set_bool(val, kp);
    if (ret == 0 && old != lotserver_turbo && lotserver_verbose) {
        pr_info("lotspeed: Turbo Mode %s\n", lotserver_turbo ? "ACTIVATED" : "DEACTIVATED");
    }
    return ret;
}

static const struct kernel_param_ops param_ops_rate = { .set = param_set_rate, .get = param_get_ulong };
static const struct kernel_param_ops param_ops_gain = { .set = param_set_gain, .get = param_get_uint };
static const struct kernel_param_ops param_ops_min_cwnd = { .set = param_set_min_cwnd, .get = param_get_uint };
static const struct kernel_param_ops param_ops_max_cwnd = { .set = param_set_max_cwnd, .get = param_get_uint };
static const struct kernel_param_ops param_ops_turbo = { .set = param_set_turbo, .get = param_get_bool };

module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
MODULE_PARM_DESC(lotserver_rate, "Min target rate (0=Auto, >0=Static Floor)");
module_param_cb(lotserver_gain, &param_ops_gain, &lotserver_gain, 0644);
MODULE_PARM_DESC(lotserver_gain, "Gain multiplier x10 (30 = 3.0x)");
module_param_cb(lotserver_min_cwnd, &param_ops_min_cwnd, &lotserver_min_cwnd, 0644);
module_param_cb(lotserver_max_cwnd, &param_ops_max_cwnd, &lotserver_max_cwnd, 0644);
module_param_cb(lotserver_turbo, &param_ops_turbo, &lotserver_turbo, 0644);
module_param(lotserver_verbose, bool, 0644);
module_param(force_unload, bool, 0644);

// ============================================================
// 数据结构与统计
// ============================================================
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t total_losses = ATOMIC_INIT(0);

struct lotspeed {
    u64 max_bw;         // 观测到的最大带宽 (Bandwidth Estimation)
    u64 current_bw;     // 当前采样带宽
    u32 cwnd_gain;
    u32 loss_count;
    u32 rtt_min;
    u64 bytes_sent;
    u64 start_time;
    bool ss_mode;       // 慢启动标记
};

static struct tcp_congestion_ops lotspeed_ops;

// ============================================================
// 核心逻辑
// ============================================================

static void lotspeed_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);

    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH; // 起步即最高速

    ca->max_bw = lotserver_rate > 0 ? lotserver_rate : 12500000; // 默认最小 100Mbps 起步
    ca->current_bw = 0;
    ca->cwnd_gain = lotserver_gain;
    ca->loss_count = 0;
    ca->rtt_min = 0;
    ca->ss_mode = true;
    ca->bytes_sent = 0;
    ca->start_time = ktime_get_real_seconds();

    // 强制开启 pacing
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);

    if (lotserver_verbose) {
        pr_info("lotspeed: [+CONN] Active: %d | Init BW: %llu | Gain: %u.%u\n",
                atomic_read(&active_connections), ca->max_bw, ca->cwnd_gain/10, ca->cwnd_gain%10);
    }
}

static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);

    if (!ca) {
        atomic_dec(&active_connections);
        return;
    }

    atomic_dec(&active_connections);
    if (ca->bytes_sent > 0) atomic64_add(ca->bytes_sent, &total_bytes_sent);
    if (ca->loss_count > 0) atomic_add(ca->loss_count, &total_losses);

    if (lotserver_verbose) {
        pr_info("lotspeed: [-CONN] Active: %d | MaxBW: %llu Bps | Losses: %u\n",
                atomic_read(&active_connections), ca->max_bw, ca->loss_count);
    }
    memset(ca, 0, sizeof(struct lotspeed));
}

// 更新最小 RTT
static inline void lotspeed_update_rtt(struct sock *sk, struct lotspeed *ca)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 rtt_us = tp->srtt_us >> 3;

    if (rtt_us > 0 && (ca->rtt_min == 0 || rtt_us < ca->rtt_min)) {
        ca->rtt_min = rtt_us;
    }
}

// 核心：带宽探测与速率计算
// 这是性能优化的关键：基于真实采样数据，而不是猜测
static void lotspeed_update_bandwidth(struct sock *sk, const struct rate_sample *rs)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 bw = 0;

    if (!rs || rs->delivered <= 0 || rs->interval_us <= 0)
        return;

    // 计算采样带宽 (Bytes/sec)
    bw = (u64)rs->delivered * USEC_PER_SEC;
    do_div(bw, rs->interval_us);

    ca->current_bw = bw;
    ca->bytes_sent += rs->delivered * tp->mss_cache;

    // 峰值带宽保持 (Peak Hold)
    // 锐速逻辑：相信曾经达到的最大速度，除非长期无法达到
    if (bw > ca->max_bw) {
        ca->max_bw = bw;
    } else {
        // 缓慢衰减 max_bw，防止一次错误的尖峰导致永久虚高
        // 每收到一次采样，如果低于 max，衰减极小比例 (0.1%)
        // 这样既激进，又能在网络变差时慢慢回归
        u64 decay = ca->max_bw >> 10;
        if (ca->max_bw > decay) ca->max_bw -= decay;
    }
}

// 通用拥塞控制逻辑
static void lotspeed_cong_control_impl(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 rate_bps;
    u32 cwnd, target_cwnd;
    u32 rtt_us = tp->srtt_us >> 3;
    u32 mss = tp->mss_cache;

    if (!mss) mss = 1460;
    if (!rtt_us) rtt_us = 1000; // 1ms 兜底

    lotspeed_update_rtt(sk, ca);
    lotspeed_update_bandwidth(sk, rs);

    // 1. 确定目标速率
    // 如果用户设定了 lotserver_rate (非0)，则取 max(max_bw, user_rate)
    // 否则完全依赖 BWE 探测
    rate_bps = ca->max_bw;
    if (lotserver_rate > 0 && rate_bps < lotserver_rate) {
        rate_bps = lotserver_rate;
    }
    // 防止 rate 为 0
    if (rate_bps == 0) rate_bps = 12500000; // 100Mbps fallback

    // 2. 计算 BDP 目标窗口
    // Target CWND = (Rate * minRTT) / MSS * Gain
    // 使用 minRTT 而不是 srtt 可以抵抗 Bufferbloat
    u64 bdp_bytes = (rate_bps * (u64)ca->rtt_min);
    do_div(bdp_bytes, USEC_PER_SEC); // Bytes in flight

    target_cwnd = div_u64(bdp_bytes, mss); // BDP in packets
    target_cwnd = (target_cwnd * ca->cwnd_gain) / 10; // 应用增益

    // 3. 慢启动与窗口调整
    if (ca->ss_mode) {
        if (tp->snd_cwnd < target_cwnd) {
            cwnd = tp->snd_cwnd * 2; // 指数增长
        } else {
            ca->ss_mode = false;
            cwnd = target_cwnd;
        }
    } else {
        cwnd = target_cwnd;
        // 即使在稳定期，也保持微量的探测增长
        if (!lotserver_turbo) {
            // 简单的加性增益
            cwnd += 2;
        }
    }

    // 4. 边界限制
    cwnd = max_t(u32, cwnd, lotserver_min_cwnd);
    cwnd = min_t(u32, cwnd, lotserver_max_cwnd);
    cwnd = min_t(u32, cwnd, tp->snd_cwnd_clamp); // 遵守系统最大限制

    tp->snd_cwnd = cwnd;

    // 5. Pacing 设置 (关键优化)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    {
        // 设置 Pacing 为 125% 的目标速率
        // 留出 25% 的 Headroom 给 ACK 聚合和突发，防止过度平滑导致吞吐上不去
        u64 pacing_rate = rate_bps + (rate_bps >> 2);
        sk->sk_pacing_rate = min_t(u64, pacing_rate, sk->sk_max_pacing_rate);
    }
#endif

    // 移除所有 pr_info 以保证性能
}

// 接口适配
#ifdef NEW_CONG_CONTROL_API
static void lotspeed_cong_control(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs) {
    lotspeed_cong_control_impl(sk, rs);
}
#else
static void lotspeed_cong_control(struct sock *sk, const struct rate_sample *rs) {
    lotspeed_cong_control_impl(sk, rs);
}
#endif

// 状态与事件处理
static void lotspeed_set_state(struct sock *sk, u8 new_state)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    if (new_state == TCP_CA_Loss) {
        // Turbo 模式下无视丢包
        if (lotserver_turbo) {
            tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
            return;
        }

        ca->loss_count++;

        // 发生丢包时，稍微降低 max_bw，模拟乘性减小
        // 降低 20%
        ca->max_bw = (ca->max_bw * 8) / 10;

        // 重置为最小速率以防万一
        if (ca->max_bw < 125000) ca->max_bw = 125000; // 1Mbps min
    }
}

static u32 lotspeed_ssthresh(struct sock *sk)
{
    // Turbo 模式不降速
    return lotserver_turbo ? TCP_INFINITE_SSTHRESH : tcp_sk(sk)->snd_cwnd;
}

static u32 lotspeed_undo_cwnd(struct sock *sk)
{
    return tcp_sk(sk)->snd_cwnd;
}

static void lotspeed_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    switch (event) {
        case CA_EVENT_TX_START:
        case CA_EVENT_CWND_RESTART:
            ca->ss_mode = true;
            break;
        default:
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

// ============================================================
// 模块初始化与退出
// ============================================================
static int __init lotspeed_module_init(void)
{
    pr_info("lotspeed: v3.0 Optimized Init. Rate: %s, Gain: %u.%ux, Turbo: %s\n",
            lotserver_rate == 0 ? "AUTO" : "STATIC",
            lotserver_gain/10, lotserver_gain%10,
            lotserver_turbo ? "ON" : "OFF");
    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    int retries = 0;
    tcp_unregister_congestion_control(&lotspeed_ops);

    while (atomic_read(&active_connections) > 0 && retries < 20) {
        msleep(100);
        retries++;
    }

    if (atomic_read(&active_connections) > 0 && !force_unload) {
        pr_err("lotspeed: Busy. Use force_unload=1 to kill.\n");
        // Re-register to avoid crash
        tcp_register_congestion_control(&lotspeed_ops);
        return;
    }

    u64 total = atomic64_read(&total_bytes_sent);
    pr_info("lotspeed: Unloaded. Total Sent: %llu MB.\n", total >> 20);
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0 (Optimized)");
MODULE_VERSION("3.0");
MODULE_DESCRIPTION("High-Performance TCP Congestion Control");