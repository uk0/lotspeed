// lotspeed.c  ——  v3.1 "公路超跑" 企业级优化版 (兼容性修复)
// Author: uk0 @ 2025-11-21
// 致敬经典，超越经典。引入 ECN、智能启动、ProbeRTT 和公平性退避。

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>

// --- v3.0 新增：算法核心参数 ---
#define LOTSPEED_BETA_SCALE 1024 // 用于公平性退避的 beta 因子精度
#define LOTSPEED_PROBE_RTT_INTERVAL_MS 10000 // 10秒进行一次 RTT 探测
#define LOTSPEED_PROBE_RTT_DURATION_MS 200   // RTT 探测持续 200ms
#define LOTSPEED_STARTUP_GROWTH_TARGET 1280  // 慢启动带宽增长目标 (1.25x)，1024=1.0x
#define LOTSPEED_STARTUP_EXIT_ROUNDS 3       // 慢启动带宽增长停滞多少轮后退出

// 版本兼容性检测 (v3.1 修正)
// 6.8.x and older kernels use the old cong_control signature
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0))
#define LOTSPEED_NEW_CONG_CONTROL_API 1
#else
#define LOTSPEED_OLD_CONG_CONTROL_API 1
#endif


// --- 可调参数 ---
static unsigned long lotserver_rate = 125000000ULL;  // 1Gbps 最高速率上限
static unsigned int lotserver_gain = 20;               // 2.0x 默认增益 (BBR-style)
static unsigned int lotserver_min_cwnd = 16;           // 最小拥塞窗口
static unsigned int lotserver_max_cwnd = 10000;        // 最大拥塞窗口
static unsigned int lotserver_beta = 717;              // 717/1024 ≈ 0.7 (CUBIC/Reno-like backoff)
static bool lotserver_adaptive = true;
static bool lotserver_turbo = false;
static bool lotserver_verbose = false;
static bool force_unload = false;

// --- 参数回调 ---
static int param_set_rate(const char *val, const struct kernel_param *kp)
{
    unsigned long old_val = lotserver_rate;
    int ret = param_set_ulong(val, kp);

    if (ret == 0 && old_val != lotserver_rate && lotserver_verbose) {
        unsigned long gbps_int = lotserver_rate / 125000000;
        unsigned long gbps_frac = (lotserver_rate % 125000000) * 100 / 125000000;
        pr_info("lotspeed: rate changed: %lu -> %lu (%lu.%02lu Gbps)\n",
                old_val, lotserver_rate, gbps_int, gbps_frac);
    }
    return ret;
}

static int param_set_gain(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_gain;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_gain && lotserver_verbose) {
        unsigned int gain_int = lotserver_gain / 10;
        unsigned int gain_frac = lotserver_gain % 10;
        pr_info("lotspeed: gain changed: %u -> %u (%u.%ux)\n",
                old_val, lotserver_gain, gain_int, gain_frac);
    }
    return ret;
}

static int param_set_min_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_min_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_min_cwnd && lotserver_verbose) {
        pr_info("lotspeed: min_cwnd changed: %u -> %u\n",
                old_val, lotserver_min_cwnd);
    }
    return ret;
}

static int param_set_max_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_max_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_max_cwnd && lotserver_verbose) {
        pr_info("lotspeed: max_cwnd changed: %u -> %u\n",
                old_val, lotserver_max_cwnd);
    }
    return ret;
}

static int param_set_adaptive(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_adaptive;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_adaptive && lotserver_verbose) {
        pr_info("lotspeed: adaptive mode: %s -> %s\n",
                old_val ? "ON" : "OFF", lotserver_adaptive ? "ON" : "OFF");
    }
    return ret;
}

static int param_set_turbo(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_turbo;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_turbo && lotserver_verbose) {
        if (lotserver_turbo) {
            pr_info("lotspeed: ⚡⚡⚡ TURBO MODE ACTIVATED ⚡⚡⚡\n");
            pr_info("lotspeed: WARNING: Ignoring ALL congestion signals!\n");
        } else {
            pr_info("lotspeed: Turbo mode DEACTIVATED\n");
        }
    }
    return ret;
}

static int param_set_beta(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_beta;
    int ret = param_set_uint(val, kp);
    if (ret == 0 && old_val != lotserver_beta && lotserver_verbose) {
        pr_info("lotspeed: fairness beta changed: %u -> %u (%u/1024)\n",
                old_val, lotserver_beta);
    }
    return ret;
}

static const struct kernel_param_ops param_ops_rate = { .set = param_set_rate, .get = param_get_ulong, };
static const struct kernel_param_ops param_ops_gain = { .set = param_set_gain, .get = param_get_uint, };
static const struct kernel_param_ops param_ops_min_cwnd = { .set = param_set_min_cwnd, .get = param_get_uint, };
static const struct kernel_param_ops param_ops_max_cwnd = { .set = param_set_max_cwnd, .get = param_get_uint, };
static const struct kernel_param_ops param_ops_adaptive = { .set = param_set_adaptive, .get = param_get_bool, };
static const struct kernel_param_ops param_ops_turbo = { .set = param_set_turbo, .get = param_get_bool, };
static const struct kernel_param_ops param_ops_beta = { .set = param_set_beta, .get = param_get_uint, };

// --- 注册参数 ---
module_param(force_unload, bool, 0644);
MODULE_PARM_DESC(force_unload, "Force unload module ignoring references");

module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
MODULE_PARM_DESC(lotserver_rate, "Target rate in bytes/sec (default 1Gbps)");

module_param_cb(lotserver_gain, &param_ops_gain, &lotserver_gain, 0644);
MODULE_PARM_DESC(lotserver_gain, "Gain multiplier x10 (20 = 2.0x)");

module_param_cb(lotserver_min_cwnd, &param_ops_min_cwnd, &lotserver_min_cwnd, 0644);
MODULE_PARM_DESC(lotserver_min_cwnd, "Minimum congestion window");

module_param_cb(lotserver_max_cwnd, &param_ops_max_cwnd, &lotserver_max_cwnd, 0644);
MODULE_PARM_DESC(lotserver_max_cwnd, "Maximum congestion window");

module_param_cb(lotserver_adaptive, &param_ops_adaptive, &lotserver_adaptive, 0644);
MODULE_PARM_DESC(lotserver_adaptive, "Enable adaptive rate control");

module_param_cb(lotserver_turbo, &param_ops_turbo, &lotserver_turbo, 0644);
MODULE_PARM_DESC(lotserver_turbo, "Turbo mode - ignore all congestion signals");

module_param_cb(lotserver_beta, &param_ops_beta, &lotserver_beta, 0644);
MODULE_PARM_DESC(lotserver_beta, "Beta for fairness backoff on loss (default 717, i.e. 0.7 * 1024)");

module_param(lotserver_verbose, bool, 0644);
MODULE_PARM_DESC(lotserver_verbose, "Enable verbose logging");


// --- 统计信息 ---
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t total_losses = ATOMIC_INIT(0);

// --- v3.0 核心状态机 ---
enum lotspeed_state {
    STARTUP,  // 智能慢启动
    PROBING,  // 探测更高带宽
    CRUISING, // 稳定在瓶颈带宽
    AVOIDING, // 拥塞规避
    PROBE_RTT // RTT 探测
};

// --- v3.0 核心数据结构 ---
struct lotspeed {
    // 核心速率与增益
    u64 target_rate;
    u64 actual_rate;
    u32 cwnd_gain;

    // 状态与时间戳 (v3.1 修正: u64 -> u32)
    enum lotspeed_state state;
    u32 last_state_ts;
    u32 probe_rtt_ts;

    // RTT 与丢包统计
    u32 rtt_min;
    u32 rtt_cnt;
    u32 loss_count;

    // 智能启动所需
    u64 last_bw;
    u32 bw_stalled_rounds;

    // 调试与统计
    u64 bytes_sent;
    u64 start_time;
};

// 将状态转换为字符串，用于日志
static const char* state_to_str(enum lotspeed_state state) {
    switch (state) {
        case STARTUP: return "STARTUP";
        case PROBING: return "PROBING";
        case CRUISING: return "CRUISING";
        case AVOIDING: return "AVOIDING";
        case PROBE_RTT: return "PROBE_RTT";
        default: return "UNKNOWN";
    }
}

// 切换状态并记录日志
static void enter_state(struct sock *sk, enum lotspeed_state new_state) {
    struct lotspeed *ca = inet_csk_ca(sk);
    if (ca->state != new_state) {
        if (lotserver_verbose) {
            pr_info("lotspeed: state %s -> %s\n", state_to_str(ca->state), state_to_str(new_state));
        }
        ca->state = new_state;
        ca->last_state_ts = tcp_jiffies32;
    }
}

// 初始化连接
static void lotspeed_init(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);

    memset(ca, 0, sizeof(struct lotspeed));

    // 初始状态为智能启动
    ca->state = STARTUP;
    ca->last_state_ts = tcp_jiffies32;
    ca->probe_rtt_ts = tcp_jiffies32; // 初始化RTT探测计时器

    // 初始目标速率设为全局上限，让智能启动去探索
    ca->target_rate = lotserver_rate;
    ca->cwnd_gain = lotserver_gain;
    ca->start_time = ktime_get_real_seconds();

    // 强制开启 pacing
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);
    if (lotserver_verbose) {
        pr_info("lotspeed: NEW connection #%d, initial state: %s\n",
                atomic_read(&active_connections), state_to_str(ca->state));
    }
}

// 释放连接
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    if (!ca) return;
    atomic_dec(&active_connections);
    atomic64_add(ca->bytes_sent, &total_bytes_sent);
    atomic_add(ca->loss_count, &total_losses);
    if (lotserver_verbose) {
        pr_info("lotspeed: connection released, active=%d\n", atomic_read(&active_connections));
    }
}

// 更新 RTT 统计
static void lotspeed_update_rtt(struct sock *sk, u32 rtt_us)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    if (!rtt_us) return;

    // 在 PROBE_RTT 状态下，我们更有可能获得真实的 rtt_min
    if (ca->state == PROBE_RTT || !ca->rtt_min || rtt_us < ca->rtt_min) {
        if (lotserver_verbose && ca->rtt_min > 0 && rtt_us < ca->rtt_min)
            pr_info("lotspeed: new min_rtt: %u us (was %u)\n", rtt_us, ca->rtt_min);
        ca->rtt_min = rtt_us;
    }
    ca->rtt_cnt++;
}

// --- v3.0 核心：自适应速率与状态机 ---
static void lotspeed_adapt_and_control(struct sock *sk, const struct rate_sample *rs, int flag)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 bw = 0;
    u32 rtt_us = tp->srtt_us >> 3;
    u32 cwnd;
    u32 target_cwnd;
    bool congestion_detected = false;

    // --- 1. 数据采集与预处理 ---
    lotspeed_update_rtt(sk, rtt_us);
    if (rs && rs->delivered > 0) {
        ca->bytes_sent += rs->delivered;
        if (rs->interval_us > 0) {
            bw = (u64)rs->delivered * USEC_PER_SEC;
            do_div(bw, rs->interval_us);
            ca->actual_rate = bw;
        }
    }

    // --- 2. 拥塞信号检测 (ECN, RTT膨胀, 丢包) ---
    if (!lotserver_turbo) {
        // ECN 是最优先的拥塞信号
        if (flag & CA_ACK_ECE)
            congestion_detected = true;

        // RTT 膨胀是早期信号
        if (ca->rtt_min > 0 && rtt_us > ca->rtt_min * 12 / 10 + 1000)
            congestion_detected = true;
        // 丢包是明确的拥塞信号
        if (rs && rs->losses > 0)
            congestion_detected = true;
    }

    // --- 3. 核心状态机转换 ---

    // 周期性进入 PROBE_RTT (v3.1 修正: time_after -> time_after32)
    if (ca->state != PROBE_RTT && ca->rtt_min > 0 &&
        time_after32(tcp_jiffies32, ca->probe_rtt_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_INTERVAL_MS))) {
        enter_state(sk, PROBE_RTT);
    }

    // 状态转换逻辑
    switch (ca->state) {
        case STARTUP:
            if (congestion_detected) {
                enter_state(sk, AVOIDING);
            } else if (bw > 0) {
                // 带宽仍在快速增长，保持 STARTUP
                if (bw * 1024 > ca->last_bw * LOTSPEED_STARTUP_GROWTH_TARGET) {
                    ca->last_bw = bw;
                    ca->bw_stalled_rounds = 0;
                } else {
                    ca->bw_stalled_rounds++;
                }
                // 如果带宽增长停滞，退出 STARTUP
                if (ca->bw_stalled_rounds >= LOTSPEED_STARTUP_EXIT_ROUNDS) {
                    ca->target_rate = bw; // 将瓶颈速率设为当前探测到的值
                    enter_state(sk, PROBING);
                }
            }
            break;
        case PROBING:
            if (congestion_detected) enter_state(sk, AVOIDING);
            else if (bw > ca->target_rate * 9 / 10) enter_state(sk, CRUISING);
            break;
        case CRUISING:
            if (congestion_detected) enter_state(sk, AVOIDING);
                // 周期性探测更高带宽 (v3.1 修正: time_after -> time_after32)
            else if (time_after32(tcp_jiffies32, ca->last_state_ts + msecs_to_jiffies(200))) {
                enter_state(sk, PROBING);
            }
            break;
        case AVOIDING:
            if (!congestion_detected) enter_state(sk, PROBING);
            break;
        case PROBE_RTT:
            // 探测时间结束，恢复并重置计时器 (v3.1 修正: time_after -> time_after32)
            if (time_after32(tcp_jiffies32, ca->last_state_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_DURATION_MS))) {
                ca->probe_rtt_ts = tcp_jiffies32;
                enter_state(sk, STARTUP); // 重新开始探测
            }
            break;
    }

    // --- 4. 根据当前状态调整速率、增益和CWND ---
    switch (ca->state) {
        case STARTUP:
            // 智能启动：使用高增益快速填充管道
            ca->cwnd_gain = lotserver_gain * 12 / 10; // 2.5x gain
            ca->target_rate = lotserver_rate; // 保持高速率目标
            break;
        case PROBING:
            // 积极探测：每次增加 10% 的速率
            ca->target_rate = ca->target_rate * 11 / 10;
            ca->cwnd_gain = lotserver_gain;
            break;
        case CRUISING:
            // 稳定巡航：将目标速率设定为略高于当前实测带宽
            ca->target_rate = bw * 11 / 10;
            ca->cwnd_gain = lotserver_gain;
            break;
        case AVOIDING:
            // 拥塞规避：速率乘性降低，但有下限
            ca->target_rate = max_t(u64, bw * 9 / 10, lotserver_rate / 20);
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10); // 增益也降低
            break;
        case PROBE_RTT:
            // RTT探测：不调整速率，仅将CWND降至最低以排空队列
            // CWND的调整在下面进行
            break;
    }

    // 应用全局速率限制
    if (lotserver_adaptive) {
        ca->target_rate = min_t(u64, ca->target_rate, lotserver_rate);
        ca->target_rate = max_t(u64, ca->target_rate, lotserver_rate / 20);
    } else {
        ca->target_rate = lotserver_rate;
    }

    // --- 5. 计算并设置 CWND ---
    if (ca->state == PROBE_RTT) {
        cwnd = lotserver_min_cwnd;
    } else {
        u32 mss = tp->mss_cache ? : 1460;
        u32 rtt = rtt_us ? : 1000; // 默认1ms
        // 核心公式：CWND = (rate × RTT) / MSS × gain
        target_cwnd = div64_u64(ca->target_rate * (u64)rtt, (u64)mss * 1000000);
        target_cwnd = div_u64(target_cwnd * ca->cwnd_gain, 10);

        if (ca->state == STARTUP && rs) {
            cwnd = tp->snd_cwnd + rs->acked_sacked; // 更平滑的慢启动增长
        } else {
            cwnd = target_cwnd;
        }
    }

    // 应用安全限制
    tp->snd_cwnd = clamp(cwnd, lotserver_min_cwnd, lotserver_max_cwnd);
    tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);

    // 设置 pacing 速率
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    sk->sk_pacing_rate = (ca->target_rate * 6) / 5; // Rate * 1.2
#endif

    // 定期状态输出
    if (lotserver_verbose && ca->rtt_cnt > 0 && ca->rtt_cnt % 1000 == 0) {
        pr_info("lotspeed: [%s] cwnd=%u rate=%llu Mbps rtt=%u min_rtt=%u gain=%u.%ux loss=%u\n",
                state_to_str(ca->state), tp->snd_cwnd, ca->target_rate / 125000,
                rtt_us, ca->rtt_min, ca->cwnd_gain / 10, ca->cwnd_gain % 10, ca->loss_count);
    }
}

// 主拥塞控制函数 - 兼容不同内核版本 (v3.1 修正)
#ifdef LOTSPEED_NEW_CONG_CONTROL_API
static void lotspeed_cong_control(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
    lotspeed_adapt_and_control(sk, rs, flag);
}
#else // LOTSPEED_OLD_CONG_CONTROL_API
static void lotspeed_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    lotspeed_adapt_and_control(sk, rs, 0); // 旧API没有flag，传0
}
#endif

// 处理丢包时的 ssthresh (引入公平性退避)
static u32 lotspeed_ssthresh(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (lotserver_turbo) {
        return TCP_INFINITE_SSTHRESH;
    }
    // 使用 lotserver_beta (默认0.7) 进行乘性降低，与其他算法保持公平
    return max_t(u32, (tp->snd_cwnd * lotserver_beta) / LOTSPEED_BETA_SCALE, lotserver_min_cwnd);
}

// 处理状态变化 (TCP_CA_Loss)
static void lotspeed_set_state_hook(struct sock *sk, u8 new_state)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    if (new_state == TCP_CA_Loss) {
        if (lotserver_turbo) return;
        ca->loss_count++;
        // 丢包后，强制进入拥塞规避状态
        enter_state(sk, AVOIDING);
    }
}

static u32 lotspeed_undo_cwnd(struct sock *sk) { return tcp_sk(sk)->snd_cwnd; }

static void lotspeed_cwnd_event(struct sock *sk, enum tcp_ca_event event) { }


static struct tcp_congestion_ops lotspeed_ops __read_mostly = {
        .name           = "lotspeed",
        .owner          = THIS_MODULE,
        .init           = lotspeed_init,
        .release        = lotspeed_release,
        .cong_control   = lotspeed_cong_control,
        .ssthresh       = lotspeed_ssthresh,
        .set_state      = lotspeed_set_state_hook,
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

// --- 模块初始化与退出 ---
static int __init lotspeed_module_init(void)
{
    char buffer[128];
    BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);

    pr_info("╔════════════════════════════════════════════════════════╗\n");
    pr_info("║      LotSpeed v3.1 - 公路超跑 (兼容性修复)       ║\n");

    snprintf(buffer, sizeof(buffer), "uk0 @ 2025-11-21");
    print_boxed_line("          Created by ", buffer);

    snprintf(buffer, sizeof(buffer), "%u.%u.%u",
             LINUX_VERSION_CODE >> 16,
             (LINUX_VERSION_CODE >> 8) & 0xff,
             LINUX_VERSION_CODE & 0xff);
    print_boxed_line("          Kernel: ", buffer);

#ifdef LOTSPEED_NEW_CONG_CONTROL_API
    pr_info("║          API: NEW (5.19-6.7, 6.9+)                     ║\n");
#else
    pr_info("║          API: LEGACY (6.8 and older)                   ║\n");
#endif

    pr_info("╚════════════════════════════════════════════════════════╝\n");

    pr_info("Initial Parameters:\n");
    pr_info("  Max Rate: %lu Mbps, Max Gain: %u.%ux, Fairness Beta: %u/1024\n",
            (unsigned long)lotserver_rate / 125000, lotserver_gain / 10, lotserver_gain % 10, lotserver_beta);
    pr_info("  Adaptive: %s, Turbo: %s, Verbose: %s\n",
            lotserver_adaptive ? "ON" : "OFF", lotserver_turbo ? "ON" : "OFF", lotserver_verbose ? "ON" : "OFF");

    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    int active_conns;
    int retry_count = 0;

    pr_info("lotspeed: Beginning module unload\n");

    tcp_unregister_congestion_control(&lotspeed_ops);
    pr_info("lotspeed: Unregistered from TCP stack\n");

    while (atomic_read(&active_connections) > 0 && retry_count < 50) {
        pr_info("lotspeed: Waiting for %d connections to close (attempt %d/50)\n",
                atomic_read(&active_connections), retry_count + 1);
        msleep(100);
        retry_count++;
    }

    active_conns = atomic_read(&active_connections);
    if (active_conns > 0) {
        pr_err("lotspeed: WARNING - Force unloading with %d active connections!\n", active_conns);
        if (!force_unload) {
            pr_err("lotspeed: Refusing to unload. Set force_unload=1 to override.\n");
            tcp_register_congestion_control(&lotspeed_ops);
            return;
        }
    }

    pr_info("lotspeed: v3.1 unloaded. Goodbye!\n");
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0 <github.com/uk0>");
MODULE_VERSION("3.1");
MODULE_DESCRIPTION("LotSpeed v3.1 - Enterprise-grade CCA with ECN, Smart Startup, ProbeRTT and Fairness");
MODULE_ALIAS("tcp_lotspeed");