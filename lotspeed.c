// lotspeed.c  ——  2025 年的"锐速"复活版 v2.0
// Author: uk0 @ 2025-11-17
// 致敬经典 LotServer/ServerSpeeder，为新时代而生

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

// 可调参数（通过 sysfs 动态修改）
static unsigned long lotserver_rate = 125000000ULL;  // 默认 1Gbps
static unsigned int lotserver_gain = 30;               // 3.0x 默认增益
static unsigned int lotserver_min_cwnd = 50;           // 最小拥塞窗口
static unsigned int lotserver_max_cwnd = 10000;        // 最大拥塞窗口
static bool lotserver_adaptive = false;                 // 自适应模式
static bool lotserver_turbo = true;                   // 涡轮模式
static bool lotserver_verbose = true;                  // 详细日志模式

// 参数变更回调 - 速率
static int param_set_rate(const char *val, const struct kernel_param *kp)
{
    unsigned long old_val = lotserver_rate;
    int ret = param_set_ulong(val, kp);

    if (ret == 0 && old_val != lotserver_rate && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] rate changed: %lu -> %lu (%.2f Gbps)\n",
                old_val, lotserver_rate, (float)lotserver_rate / 125000000.0);
    }
    return ret;
}

// 参数变更回调 - 增益
static int param_set_gain(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_gain;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_gain && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] gain changed: %u -> %u (%.1fx)\n",
                old_val, lotserver_gain, (float)lotserver_gain / 10.0);
    }
    return ret;
}

// 参数变更回调 - 最小窗口
static int param_set_min_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_min_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_min_cwnd && lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] min_cwnd changed: %u -> %u\n",
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
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] max_cwnd changed: %u -> %u\n",
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
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] adaptive mode: %s -> %s\n",
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
            pr_info("lotspeed: [uk0@2025-11-17 12:53:48] ⚡⚡⚡ TURBO MODE ACTIVATED ⚡⚡⚡\n");
            pr_info("lotspeed: WARNING: Ignoring ALL congestion signals!\n");
        } else {
            pr_info("lotspeed: [uk0@2025-11-17 12:53:48] Turbo mode DEACTIVATED\n");
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
module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
MODULE_PARM_DESC(lotserver_rate, "Target rate in bytes/sec (default 10Gbps)");

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
    u64 bytes_sent;     // 添加字节统计
    u64 start_time;     // 连接开始时间
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

    // 强制开启 pacing
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);

    if (lotserver_verbose) {
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] NEW connection #%d | rate=%.2f Gbps | gain=%.1fx | mode=%s\n",
                atomic_read(&active_connections),
                (float)ca->target_rate / 125000000.0,
                (float)ca->cwnd_gain / 10.0,
                lotserver_turbo ? "TURBO" : (lotserver_adaptive ? "adaptive" : "fixed"));
    }
}

// 释放连接
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 duration = ktime_get_real_seconds() - ca->start_time;

    atomic_dec(&active_connections);
    atomic64_add(ca->bytes_sent, &total_bytes_sent);
    atomic_add(ca->loss_count, &total_losses);

    if (lotserver_verbose && ca->bytes_sent > 1048576) {  // 只记录超过 1MB 的连接
        pr_info("lotspeed: [uk0@2025-11-17 12:53:48] CLOSED connection | sent=%.2f MB | duration=%llu s | losses=%u | active=%d\n",
                (float)ca->bytes_sent / 1048576.0,
                duration,
                ca->loss_count,
                atomic_read(&active_connections));
    }
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

// 自适应速率调整
static void lotspeed_adapt_rate(struct sock *sk, const struct rate_sample *rs)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 bw = 0;

    if (!lotserver_adaptive)
        return;

    // 计算实际带宽
    if (rs->delivered > 0 && rs->interval_us > 0) {
        bw = (u64)rs->delivered * USEC_PER_SEC;
        do_div(bw, rs->interval_us);
        ca->actual_rate = bw;

        // 更新发送字节数
        ca->bytes_sent += rs->delivered * tp->mss_cache;

        // 如果实际速率远低于目标，可能遇到瓶颈
        if (bw < ca->target_rate / 2 && ca->loss_count > 0) {
            // 温和降速
            ca->target_rate = max_t(u64, bw * 15 / 10, lotserver_rate / 4);
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain - 5, 15);
            if (lotserver_verbose) {
                pr_info("lotspeed: [uk0] adapt DOWN: rate=%.2f Gbps, gain=%.1fx\n",
                        (float)ca->target_rate / 125000000.0,
                        (float)ca->cwnd_gain / 10.0);
            }
        }
            // 如果表现良好，逐步恢复
        else if (bw > ca->target_rate * 8 / 10 && ca->loss_count == 0) {
            ca->target_rate = min_t(u64, ca->target_rate * 11 / 10, lotserver_rate);
            ca->cwnd_gain = min_t(u32, ca->cwnd_gain + 2, lotserver_gain);
        }
    }

    // RTT 膨胀检测
    if (ca->rtt_min && tp->srtt_us >> 3 > ca->rtt_min * 3 / 2) {
        // RTT 膨胀超过 50%，可能有队列堆积
        if (!lotserver_turbo) {
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 9 / 10, 15);
        }
    }
}

// 主拥塞控制逻辑
static void lotspeed_cong_control(struct sock *sk, const struct rate_sample *rs)
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
    sk->sk_pacing_rate = rate;
#endif

    // 定期状态输出
    if (lotserver_verbose && ca->rtt_cnt > 0 && ca->rtt_cnt % 1000 == 0) {
        pr_info("lotspeed: [uk0] STATUS: cwnd=%u | rate=%.2f Gbps | RTT=%u us | gain=%.1fx | losses=%u\n",
                cwnd, (float)rate / 125000000.0, rtt_us,
                (float)ca->cwnd_gain / 10.0, ca->loss_count);
    }
}

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
                pr_info("lotspeed: [uk0] LOSS #%u detected, gain reduced to %.1fx\n",
                        ca->loss_count, (float)ca->cwnd_gain / 10.0);
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
        .release        = lotspeed_release,  // 添加释放函数
        .cong_control   = lotspeed_cong_control,
        .set_state      = lotspeed_set_state,
        .ssthresh       = lotspeed_ssthresh,
        .undo_cwnd      = lotspeed_undo_cwnd,
        .cwnd_event     = lotspeed_cwnd_event,
};

static int __init lotspeed_module_init(void)
{
    BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);

    pr_info("╔════════════════════════════════════════════════════════╗\n");
    pr_info("║          LotSpeed v2.0 - 锐速复活版                    ║\n");
    pr_info("║          Created by uk0 @ 2025-11-17 12:53:48          ║\n");
    pr_info("║          Kernel: %u.%u.%u                                ║\n",
            LINUX_VERSION_CODE >> 16,
            (LINUX_VERSION_CODE >> 8) & 0xff,
            LINUX_VERSION_CODE & 0xff);
    pr_info("╚════════════════════════════════════════════════════════╝\n");
    pr_info("Initial Parameters:\n");
    pr_info("  Rate: %.2f Gbps\n", (float)lotserver_rate / 125000000.0);
    pr_info("  Gain: %.1fx\n", (float)lotserver_gain / 10.0);
    pr_info("  Min/Max CWND: %u/%u\n", lotserver_min_cwnd, lotserver_max_cwnd);
    pr_info("  Adaptive: %s | Turbo: %s | Verbose: %s\n",
            lotserver_adaptive ? "ON" : "OFF",
            lotserver_turbo ? "ON" : "OFF",
            lotserver_verbose ? "ON" : "OFF");

    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    tcp_unregister_congestion_control(&lotspeed_ops);

    pr_info("LotSpeed v2.0 unloaded | Stats: connections=%d, sent=%.2f GB, losses=%d\n",
            atomic_read(&active_connections),
            (float)atomic64_read(&total_bytes_sent) / 1073741824.0,
            atomic_read(&total_losses));
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0 <github.com/uk0>");
MODULE_VERSION("2.0");
MODULE_DESCRIPTION("LotSpeed v2.0 - Modern LotServer/ServerSpeeder replacement for 1G~40G networks");
MODULE_ALIAS("tcp_lotspeed");