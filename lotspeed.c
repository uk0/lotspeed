/*
 * lotspeed_zeta_v5.c
 * "公路超跑" Zeta-TCP 深度复刻版 - 安全增强版
 * Author: uk0 (Modified and Fixed)
 *
 * Features:
 * 1. Zeta-Like Learning Mode (历史带宽记忆，实现 0-RTT 满速启动)
 * 2. RTT-based Loss Differentiation (基于延迟梯度的丢包区分)
 * 3. BBR-style Pacing & Probing
 * 4. Safety Guards (防止内核恐慌的安全检查)
 *
 * Based on ZetaTCP Paper: https://web.archive.org/web/20170921172032/http://appexnetworks.com/white-papers/ZetaTCP.pdf
 */

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/rtc.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>

// --- 安全性宏定义 ---
#define SAFETY_CHECK(ptr, ret) do { \
    if (unlikely(!(ptr))) { \
        pr_err("lotspeed: NULL pointer at %s:%d\n", __func__, __LINE__); \
        return ret; \
    } \
} while(0)

#define SAFE_DIV(n, d) ((d) ? (n)/(d) : 0)
#define SAFE_DIV64(n, d) ((d) ? div64_u64(n, d) : 0)

// --- 基础宏定义 ---
#define CURRENT_TIMESTAMP ({ \
    static char __ts[32]; \
    struct timespec64 ts; \
    struct tm tm; \
    ktime_get_real_ts64(&ts); \
    time64_to_tm(ts.tv_sec, 0, &tm); \
    snprintf(__ts, sizeof(__ts), "%04ld-%02d-%02d %02d:%02d:%02d", \
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, \
            tm.tm_hour, tm.tm_min, tm.tm_sec); \
    __ts; \
})

// --- Zeta-TCP 核心配置 (基于论文) ---
#define HISTORY_BITS 10              // 哈希表大小 2^10 = 1024 桶
#define HISTORY_MAX_ENTRIES 4096     // 最大历史记录数（新增：防止内存耗尽）
#define HISTORY_TTL_SEC 3600         // 记忆有效期 1小时
#define LOSS_DIFFERENTIATION_K 125  // RTT 容忍度系数 1.25倍 (125%)
#define RTT_JITTER_TOLERANCE_US 2000 // 抖动容忍 2ms

// Zeta-TCP 论文参数
#define ZETA_ALPHA 85                // 历史带宽使用率 85%
#define ZETA_PROBE_GAIN 110          // 探测增益 110%
#define ZETA_MIN_SAMPLES 10          // 最少采样数才记录历史

// --- BBR/LotSpeed 参数 ---
#define LOTSPEED_BETA_SCALE 1024
#define LOTSPEED_PROBE_RTT_INTERVAL_MS 10000
#define LOTSPEED_PROBE_RTT_DURATION_MS 500
#define LOTSPEED_STARTUP_GROWTH_TARGET 1280
#define LOTSPEED_STARTUP_EXIT_ROUNDS 2
#define LOTSPEED_MAX_U32 ((u32)~0U)
#define LOTSPEED_MAX_U64 ((u64)~0ULL)

// API 兼容性
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#define LOTSPEED_NEW_CONG_CONTROL_API 1
#else
#define LOTSPEED_OLD_CONG_CONTROL_API 1
#endif

// --- 模块参数 ---
static unsigned long lotserver_rate = 125000000ULL;  // 1Gbps
static unsigned int lotserver_gain = 20;             // 2.0x
static unsigned int lotserver_min_cwnd = 16;
static unsigned int lotserver_max_cwnd = 20000;
static unsigned int lotserver_beta = 717;
static bool lotserver_adaptive = true;
static bool lotserver_turbo = false;
static bool lotserver_verbose = false;
static bool lotserver_safe_mode = true;              // 新增：安全模式

// --- 参数回调 (保留原有实现) ---
static int param_set_rate(const char *val, const struct kernel_param *kp)
{
    unsigned long old_val = lotserver_rate;
    int ret = param_set_ulong(val, kp);

    if (ret == 0 && old_val != lotserver_rate && lotserver_verbose) {
        unsigned long gbps_int = SAFE_DIV(lotserver_rate, 125000000);
        unsigned long gbps_frac = SAFE_DIV((lotserver_rate % 125000000) * 100, 125000000);
        pr_info("lotspeed: [uk0@%s] rate changed: %lu -> %lu (%lu.%02lu Gbps)\n",
                CURRENT_TIMESTAMP, old_val, lotserver_rate, gbps_int, gbps_frac);
    }
    return ret;
}

static int param_set_gain(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_gain;
    int ret = param_set_uint(val, kp);

    if (ret == 0 && old_val != lotserver_gain && lotserver_verbose) {
        unsigned int gain_int = SAFE_DIV(lotserver_gain, 10);
        unsigned int gain_frac = lotserver_gain % 10;
        pr_info("lotspeed: [uk0@%s] gain changed: %u -> %u (%u.%ux)\n",
                CURRENT_TIMESTAMP, old_val, lotserver_gain, gain_int, gain_frac);
    }
    return ret;
}

static int param_set_min_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_min_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0) {
        if (lotserver_min_cwnd < 4) lotserver_min_cwnd = 4;  // 最小值保护
        if (old_val != lotserver_min_cwnd && lotserver_verbose) {
            pr_info("lotspeed: [uk0@%s] min_cwnd changed: %u -> %u\n",
                    CURRENT_TIMESTAMP, old_val, lotserver_min_cwnd);
        }
    }
    return ret;
}

static int param_set_max_cwnd(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_max_cwnd;
    int ret = param_set_uint(val, kp);

    if (ret == 0) {
        if (lotserver_max_cwnd > 100000) lotserver_max_cwnd = 100000;  // 上限保护
        if (old_val != lotserver_max_cwnd && lotserver_verbose) {
            pr_info("lotspeed: [uk0@%s] max_cwnd changed: %u -> %u\n",
                    CURRENT_TIMESTAMP, old_val, lotserver_max_cwnd);
        }
    }
    return ret;
}

static int param_set_adaptive(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_adaptive;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_adaptive && lotserver_verbose) {
        pr_info("lotspeed: [uk0@%s] adaptive mode: %s -> %s\n",
                CURRENT_TIMESTAMP, old_val ? "ON" : "OFF", lotserver_adaptive ? "ON" : "OFF");
    }
    return ret;
}

static int param_set_turbo(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_turbo;
    int ret = param_set_bool(val, kp);

    if (ret == 0 && old_val != lotserver_turbo) {
        if (lotserver_turbo) {
            pr_warn("lotspeed: [uk0@%s] ⚡⚡⚡ TURBO MODE ACTIVATED ⚡⚡⚡\n", CURRENT_TIMESTAMP);
            pr_warn("lotspeed: WARNING: Ignoring ALL congestion signals! Use with caution!\n");
            if (lotserver_safe_mode) {
                pr_info("lotspeed: Safety mode is ON, some protections remain active\n");
            }
        } else {
            pr_info("lotspeed: [uk0@%s] Turbo mode DEACTIVATED\n", CURRENT_TIMESTAMP);
        }
    }
    return ret;
}

static int param_set_beta(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_beta;
    int ret = param_set_uint(val, kp);

    if (ret == 0) {
        if (lotserver_beta > LOTSPEED_BETA_SCALE) lotserver_beta = LOTSPEED_BETA_SCALE;
        if (lotserver_beta < 512) lotserver_beta = 512;  // 最小0.5

        if (old_val != lotserver_beta && lotserver_verbose) {
            pr_info("lotspeed: [uk0@%s] beta changed: %u -> %u (%u/1024)\n",
                    CURRENT_TIMESTAMP, old_val, lotserver_beta, lotserver_beta);
        }
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

// --- 参数定义 ---
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

module_param(lotserver_safe_mode, bool, 0644);
MODULE_PARM_DESC(lotserver_safe_mode, "Enable safety checks (recommended)");

// --- 全局统计 ---
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t total_losses = ATOMIC_INIT(0);
static atomic_t history_entries_count = ATOMIC_INIT(0);  // 新增：记录历史条目数

// --- ZETA 学习引擎结构 (增强版) ---
struct zeta_history_entry {
    struct hlist_node node;
    struct rcu_head rcu;        // 新增：RCU头
    u32 daddr;                  // 目标 IP
    u64 cached_bw;              // 历史带宽 (Bytes/sec)
    u32 cached_min_rtt;         // 历史最小 RTT (us)
    u32 cached_median_rtt;      // 历史中位 RTT (us) - 新增
    u64 last_update;            // 时间戳
    u32 sample_count;           // 采样次数 - 新增
    u32 loss_count;             // 丢包次数 - 新增
};

// 全局哈希表与锁
static DEFINE_HASHTABLE(zeta_history_map, HISTORY_BITS);
static DEFINE_SPINLOCK(zeta_history_lock);

// --- 核心状态机 ---
enum lotspeed_state {
    STARTUP,
    PROBING,
    CRUISING,
    AVOIDING,
    PROBE_RTT
};

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

// --- 私有数据结构 (增强版) ---
struct lotspeed {
    u64 target_rate;
    u64 actual_rate;
    u32 cwnd_gain;

    enum lotspeed_state state;
    u32 last_state_ts;
    u32 probe_rtt_ts;
    u32 last_cruise_ts;

    u32 rtt_min;
    u32 rtt_median;          // 新增：中位RTT
    u32 rtt_cnt;
    u32 loss_count;

    u64 last_bw;
    u32 bw_stalled_rounds;

    bool ss_mode;
    u32 probe_cnt;
    bool history_hit;

    u64 bytes_sent;
    u64 start_time;

    // 新增：Zeta-TCP 论文算法需要的字段
    u32 rtt_variance;        // RTT方差
    u32 last_loss_rtt;       // 上次丢包时的RTT
    u32 sample_count;        // 采样计数
};

// --- 安全的历史引擎函数 ---
static void free_history_entry_rcu(struct rcu_head *head)
{
    struct zeta_history_entry *entry = container_of(head, struct zeta_history_entry, rcu);
    kfree(entry);
    atomic_dec(&history_entries_count);
}

static struct zeta_history_entry *find_history_safe(u32 daddr)
{
    struct zeta_history_entry *entry;

    hash_for_each_possible_rcu(zeta_history_map, entry, node, daddr) {
        if (entry && entry->daddr == daddr) {
            return entry;
        }
    }
    return NULL;
}

static void update_history_safe(u32 daddr, u64 bw, u32 rtt, u32 loss_count)
{
    struct zeta_history_entry *entry, *oldest = NULL;
    u64 oldest_time = ULLONG_MAX;
    bool found = false;
    int bkt;

    if (!bw || !rtt) return;  // 无效数据不记录

    spin_lock_bh(&zeta_history_lock);

    // 查找现有记录
    entry = find_history_safe(daddr);
    if (entry) {
        // Zeta-TCP 论文算法：指数加权移动平均
        entry->cached_bw = (entry->cached_bw * 7 + bw * 3) / 10;

        // 更新最小RTT
        if (rtt < entry->cached_min_rtt) {
            entry->cached_min_rtt = rtt;
        }

        // 更新中位RTT（简化实现）
        entry->cached_median_rtt = (entry->cached_median_rtt * 9 + rtt) / 10;

        entry->loss_count += loss_count;
        entry->sample_count++;
        entry->last_update = get_jiffies_64();
        found = true;
    }

    if (!found) {
        // 检查是否超过最大条目数
        if (atomic_read(&history_entries_count) >= HISTORY_MAX_ENTRIES) {
            // 找到最旧的条目进行替换
            struct zeta_history_entry *tmp;
            hash_for_each_rcu(zeta_history_map, bkt, tmp, node) {
                if (tmp && tmp->last_update < oldest_time) {
                    oldest_time = tmp->last_update;
                    oldest = tmp;
                }
            }

            if (oldest) {
                hash_del_rcu(&oldest->node);
                call_rcu(&oldest->rcu, free_history_entry_rcu);
            }
        }

        // 创建新条目
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->daddr = daddr;
            entry->cached_bw = bw;
            entry->cached_min_rtt = rtt;
            entry->cached_median_rtt = rtt;
            entry->loss_count = loss_count;
            entry->sample_count = 1;
            entry->last_update = get_jiffies_64();

            hash_add_rcu(zeta_history_map, &entry->node, daddr);
            atomic_inc(&history_entries_count);

            if (lotserver_verbose) {
                pr_info("lotspeed: [Zeta] New path learned to %pI4 (Total: %d)\n",
                        &daddr, atomic_read(&history_entries_count));
            }
        }
    }

    spin_unlock_bh(&zeta_history_lock);
}

// --- 状态切换 ---
static void enter_state(struct sock *sk, enum lotspeed_state new_state)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    if (ca->state != new_state) {
        if (lotserver_verbose) {
            pr_info("lotspeed: [uk0@%s] state %s -> %s\n",
                    CURRENT_TIMESTAMP, state_to_str(ca->state), state_to_str(new_state));
        }
        ca->state = new_state;
        ca->last_state_ts = tcp_jiffies32;
        if (new_state == CRUISING) {
            ca->last_cruise_ts = tcp_jiffies32;
        }
    }
}

// --- 初始化：集成 Zeta 学习模式 ---
static void lotspeed_init(struct sock *sk)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;
    struct zeta_history_entry *history;
    u32 daddr;

    SAFETY_CHECK(sk, );
    tp = tcp_sk(sk);
    SAFETY_CHECK(tp, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    daddr = sk->sk_daddr;

    memset(ca, 0, sizeof(struct lotspeed));

    // 默认设置
    ca->state = STARTUP;
    ca->last_state_ts = tcp_jiffies32;
    ca->probe_rtt_ts = tcp_jiffies32;
    ca->target_rate = lotserver_rate;
    ca->cwnd_gain = lotserver_gain;
    ca->start_time = ktime_get_real_seconds();
    ca->ss_mode = true;
    ca->history_hit = false;
    ca->rtt_min = 0;
    ca->rtt_median = 0;

    tp->snd_ssthresh = lotserver_turbo ? TCP_INFINITE_SSTHRESH : max(tp->snd_cwnd * 2, 10U);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);

    // === Zeta Learning Logic (基于论文算法) ===
    rcu_read_lock();
    history = find_history_safe(daddr);
    if (history && history->sample_count >= ZETA_MIN_SAMPLES) {
        u64 age_ms = jiffies_to_msecs(get_jiffies_64() - history->last_update);

        // 记忆未过期且数据有效
        if (age_ms < HISTORY_TTL_SEC * 1000ULL && history->cached_bw > 0) {
            // Zeta-TCP 算法：使用历史带宽的 ALPHA%
            ca->target_rate = (history->cached_bw * ZETA_ALPHA) / 100;
            ca->rtt_min = history->cached_min_rtt;
            ca->rtt_median = history->cached_median_rtt;
            ca->history_hit = true;

            // 计算初始窗口 (基于BDP)
            if (tp->mss_cache > 0 && ca->rtt_min > 0) {
                u64 bdp = ca->target_rate * (u64)ca->rtt_min;
                u32 init_cwnd = SAFE_DIV64(bdp, (u64)tp->mss_cache * 1000000ULL);

                // 安全边界检查
                init_cwnd = clamp(init_cwnd, 10U, lotserver_max_cwnd);

                tp->snd_cwnd = init_cwnd;
                tp->snd_ssthresh = max(init_cwnd, 10U);

                // 跳过慢启动，直接进入探测
                ca->state = PROBING;
                ca->ss_mode = false;

                if (lotserver_verbose) {
                    pr_info("lotspeed: [Zeta] HIT! %pI4 | Samples=%u | Rate=%llu Mbps | RTT=%uus | CWND=%u\n",
                            &daddr, history->sample_count,
                            ca->target_rate * 8 / 1000000, ca->rtt_min, init_cwnd);
                }
            }
        }
    }
    rcu_read_unlock();
    // ===========================

    if (lotserver_verbose && !ca->history_hit) {
        pr_info("lotspeed: [uk0@%s] NEW connection #%d to %pI4 (Fresh start)\n",
                CURRENT_TIMESTAMP, atomic_read(&active_connections), &daddr);
    }
}

// --- 释放连接：存储学习结果 ---
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca;
    u64 duration = 0;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);

    if (!ca) {
        atomic_dec(&active_connections);
        return;
    }

    if (ca->start_time > 0) {
        duration = ktime_get_real_seconds() - ca->start_time;
    }

    atomic_dec(&active_connections);

    if (ca->bytes_sent > 0) {
        atomic64_add(ca->bytes_sent, &total_bytes_sent);
    }
    if (ca->loss_count > 0) {
        atomic_add(ca->loss_count, &total_losses);
    }

    // === Zeta Learning Logic ===
    // 只有足够的采样才记录
    if (ca->sample_count >= ZETA_MIN_SAMPLES &&
        ca->bytes_sent > 1048576 &&
        ca->actual_rate > 0 &&
        ca->rtt_min > 0 &&
        sk->sk_daddr != 0) {  // 确保有效的目标地址

        update_history_safe(sk->sk_daddr, ca->actual_rate, ca->rtt_min, ca->loss_count);
    }
    // ===========================

    if (lotserver_verbose) {
        pr_info("lotspeed: [uk0@%s] Released. Duration=%llus Sent=%llu MB Losses=%u Active=%d\n",
                CURRENT_TIMESTAMP, duration, ca->bytes_sent >> 20,
                ca->loss_count, atomic_read(&active_connections));
    }
}

static void lotspeed_update_rtt(struct sock *sk, u32 rtt_us)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    if (!rtt_us) return;

    // 更新最小RTT
    if (ca->state == PROBE_RTT || !ca->rtt_min || rtt_us < ca->rtt_min) {
        ca->rtt_min = rtt_us;
    }

    // 更新中位RTT（简化的滑动平均）
    if (ca->rtt_median == 0) {
        ca->rtt_median = rtt_us;
    } else {
        ca->rtt_median = (ca->rtt_median * 9 + rtt_us) / 10;
    }

    // 更新RTT方差（用于丢包区分）
    if (ca->rtt_min > 0) {
        u32 diff = (rtt_us > ca->rtt_min) ? (rtt_us - ca->rtt_min) : 0;
        ca->rtt_variance = (ca->rtt_variance * 3 + diff) / 4;
    }

    ca->rtt_cnt++;
    ca->sample_count++;
}

// --- 核心算法逻辑 ---
static void lotspeed_adapt_and_control(struct sock *sk, const struct rate_sample *rs, int flag)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;
    u64 bw = 0;
    u32 rtt_us;
    u32 cwnd, target_cwnd;
    u32 mss;
    bool congestion_detected = false;

    SAFETY_CHECK(sk, );
    tp = tcp_sk(sk);
    SAFETY_CHECK(tp, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    rtt_us = tp->srtt_us >> 3;
    lotspeed_update_rtt(sk, rtt_us);

    if (!rtt_us) rtt_us = 1000;  // 默认1ms

    // 获取MSS，防止除零
    mss = tp->mss_cache;
    if (mss == 0) mss = 1460;  // 默认值

    // 带宽采样
    if (rs && rs->delivered > 0) {
        ca->bytes_sent += rs->delivered;
        if (rs->interval_us > 0) {
            bw = (u64)rs->delivered * USEC_PER_SEC;
            bw = SAFE_DIV64(bw, (u64)rs->interval_us);
            ca->actual_rate = bw;
        }
    }

    // 拥塞信号检测 (Turbo 模式忽略，但保留安全检查)
    if (!lotserver_turbo || lotserver_safe_mode) {
        if (flag & CA_ACK_ECE) {
            congestion_detected = true;
        }

        // Zeta 优化：基于RTT方差的拥塞检测
        if (ca->rtt_min > 0 && ca->rtt_variance > 0) {
            u32 threshold = ca->rtt_min + (ca->rtt_min >> 2) + ca->rtt_variance;
            if (rtt_us > threshold) {
                congestion_detected = true;
            }
        }
    }

    // 状态机转换
    if (ca->state != PROBE_RTT && ca->rtt_min > 0 &&
        time_after32(tcp_jiffies32, ca->probe_rtt_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_INTERVAL_MS))) {
        enter_state(sk, PROBE_RTT);
    }

    switch (ca->state) {
        case STARTUP:
            if (congestion_detected) {
                enter_state(sk, AVOIDING);
            } else if (bw > 0) {
                if (ca->last_bw > 0 && bw * 1024 > ca->last_bw * LOTSPEED_STARTUP_GROWTH_TARGET) {
                    ca->last_bw = bw;
                    ca->bw_stalled_rounds = 0;
                } else {
                    ca->bw_stalled_rounds++;
                }

                if (ca->bw_stalled_rounds >= LOTSPEED_STARTUP_EXIT_ROUNDS) {
                    ca->target_rate = bw;
                    ca->ss_mode = false;
                    enter_state(sk, PROBING);
                }

                if (ca->last_bw == 0) ca->last_bw = bw;
            }
            break;

        case PROBING:
            if (congestion_detected) {
                enter_state(sk, AVOIDING);
            } else if (bw > 0 && bw > ca->target_rate * 9 / 10) {
                enter_state(sk, CRUISING);
            }
            ca->probe_cnt++;
            if (ca->probe_cnt >= 100) ca->probe_cnt = 0;
            break;

        case CRUISING:
            if (congestion_detected) {
                enter_state(sk, AVOIDING);
            } else if (time_after32(tcp_jiffies32, ca->last_cruise_ts + msecs_to_jiffies(200))) {
                enter_state(sk, PROBING);
            }
            break;

        case AVOIDING:
            if (!congestion_detected) {
                enter_state(sk, PROBING);
            }
            break;

        case PROBE_RTT:
            if (time_after32(tcp_jiffies32, ca->last_state_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_DURATION_MS))) {
                ca->probe_rtt_ts = tcp_jiffies32;
                enter_state(sk, STARTUP);
            }
            break;
    }

    // 速率调整（基于Zeta-TCP论文）
    switch (ca->state) {
        case STARTUP:
            ca->cwnd_gain = min(lotserver_gain * 12 / 10, 30U);  // 防止过大
            ca->target_rate = min(lotserver_rate, LOTSPEED_MAX_U64 / 2);
            break;

        case PROBING:
            ca->target_rate = min(ca->target_rate * ZETA_PROBE_GAIN / 100, LOTSPEED_MAX_U64 / 2);
            ca->cwnd_gain = lotserver_gain;
            break;

        case CRUISING:
            if (bw > 0) {
                ca->target_rate = min(bw * 11 / 10, LOTSPEED_MAX_U64 / 2);
            }
            ca->cwnd_gain = lotserver_gain;
            break;

        case AVOIDING:
            if (bw > 0) {
                ca->target_rate = max_t(u64, bw * 9 / 10, lotserver_rate / 20);
            } else {
                ca->target_rate = max_t(u64, ca->target_rate * 9 / 10, lotserver_rate / 20);
            }
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);
            break;

        case PROBE_RTT:
            break;
    }

    // 自适应速率限制
    if (lotserver_adaptive) {
        ca->target_rate = clamp(ca->target_rate, lotserver_rate / 20, lotserver_rate);
    } else {
        ca->target_rate = lotserver_rate;
    }

    // CWND 计算（防止溢出）
    target_cwnd = 0;
    if (mss > 0 && rtt_us > 0 && ca->target_rate < LOTSPEED_MAX_U64 / rtt_us) {
        u64 bdp = ca->target_rate * (u64)rtt_us;
        target_cwnd = (u32)SAFE_DIV64(bdp, (u64)mss * 1000000ULL);

        if (ca->cwnd_gain > 0 && target_cwnd < LOTSPEED_MAX_U32 / ca->cwnd_gain) {
            target_cwnd = (target_cwnd * ca->cwnd_gain) / 10;
        }
    }

    // 状态特定的CWND设置
    if (ca->state == PROBE_RTT) {
        cwnd = lotserver_min_cwnd;
    } else if (ca->ss_mode && tp->snd_cwnd < tp->snd_ssthresh) {
        // 慢启动阶段
        if (tp->snd_cwnd < LOTSPEED_MAX_U32 / 2) {
            cwnd = tp->snd_cwnd * 2;
        } else {
            cwnd = tp->snd_cwnd + 1;  // 防止溢出
        }

        if (target_cwnd > 0 && cwnd >= target_cwnd) {
            ca->ss_mode = false;
            cwnd = target_cwnd;
        }
    } else {
        // 正常拥塞避免
        if (ca->state == STARTUP && rs && rs->acked_sacked > 0) {
            if (tp->snd_cwnd < LOTSPEED_MAX_U32 - rs->acked_sacked) {
                cwnd = tp->snd_cwnd + rs->acked_sacked;
            } else {
                cwnd = tp->snd_cwnd;
            }
        } else {
            cwnd = target_cwnd;
        }

        // 周期性探测
        if (ca->probe_cnt > 0 && ca->probe_cnt % 100 == 0) {
            if (cwnd < LOTSPEED_MAX_U32 * 10 / 11) {
                cwnd = cwnd * 11 / 10;
            }
        }
    }

    // 应用CWND（带边界检查）
    tp->snd_cwnd = clamp(cwnd, lotserver_min_cwnd, lotserver_max_cwnd);
    tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);

    // 设置pacing rate
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    if (ca->target_rate < LOTSPEED_MAX_U64 * 5 / 6) {
        sk->sk_pacing_rate = (ca->target_rate * 6) / 5;
    } else {
        sk->sk_pacing_rate = ca->target_rate;
    }
#endif
}

#ifdef LOTSPEED_NEW_CONG_CONTROL_API
static void lotspeed_cong_control(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs) {
    lotspeed_adapt_and_control(sk, rs, flag);
}
#else
static void lotspeed_cong_control(struct sock *sk, const struct rate_sample *rs) {
    lotspeed_adapt_and_control(sk, rs, 0);
}
#endif

// --- SSTHRESH: Zeta 核心智能丢包判断（基于论文算法） ---
static u32 lotspeed_ssthresh(struct sock *sk)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;
    u32 rtt_us;
    u32 tolerance;
    u32 new_ssthresh;

    SAFETY_CHECK(sk, TCP_INFINITE_SSTHRESH);
    tp = tcp_sk(sk);
    SAFETY_CHECK(tp, TCP_INFINITE_SSTHRESH);
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, TCP_INFINITE_SSTHRESH);

    if (lotserver_turbo && !lotserver_safe_mode) {
        return TCP_INFINITE_SSTHRESH;
    }

    rtt_us = tp->srtt_us >> 3;
    if (!rtt_us) rtt_us = ca->rtt_median ? ca->rtt_median : 20000;

    // === Zeta Loss Differentiation Logic (基于论文) ===
    u32 base_rtt = ca->rtt_min ? ca->rtt_min : rtt_us;

    // 容忍度计算：基准RTT * K + 抖动容忍 + RTT方差
    tolerance = (base_rtt * LOSS_DIFFERENTIATION_K) / 100;
    tolerance += RTT_JITTER_TOLERANCE_US;
    if (ca->rtt_variance > 0) {
        tolerance += ca->rtt_variance / 2;  // 加入方差的一半
    }

    // 核心判断：RTT是否在容忍范围内？
    if (rtt_us <= tolerance) {
        // RTT稳定，判定为非拥塞丢包
        if (lotserver_verbose) {
            pr_info("lotspeed: [Zeta] Non-congestion loss detected! "
                    "RTT=%uus (base=%uus, tolerance=%uus). Maintaining cwnd.\n",
                    rtt_us, base_rtt, tolerance);
        }

        // 记录此次丢包的RTT，用于后续学习
        ca->last_loss_rtt = rtt_us;

        // 保持窗口不变或轻微降低
        if (lotserver_safe_mode) {
            // 安全模式：轻微降低5%
            new_ssthresh = (tp->snd_cwnd * 95) / 100;
        } else {
            // 激进模式：完全不降
            new_ssthresh = tp->snd_cwnd;
        }
    } else {
        // RTT膨胀，判定为拥塞丢包
        if (lotserver_verbose) {
            pr_info("lotspeed: [Zeta] Congestion loss detected! "
                    "RTT=%uus (base=%uus, tolerance=%uus). Reducing cwnd.\n",
                    rtt_us, base_rtt, tolerance);
        }

        ca->loss_count++;
        ca->last_loss_rtt = rtt_us;
        ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);

        // 标准降速
        new_ssthresh = (tp->snd_cwnd * lotserver_beta) / LOTSPEED_BETA_SCALE;
    }
    // =======================================

    return max_t(u32, new_ssthresh, lotserver_min_cwnd);
}

static void lotspeed_set_state_hook(struct sock *sk, u8 new_state)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    switch (new_state) {
        case TCP_CA_Loss:
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->loss_count++;
                enter_state(sk, AVOIDING);
            }
            break;

        case TCP_CA_Recovery:
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 9 / 10, 15);
            }
            break;

        case TCP_CA_Open:
            ca->ss_mode = false;
            break;
    }
}

static u32 lotspeed_undo_cwnd(struct sock *sk)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;

    SAFETY_CHECK(sk, 10);
    tp = tcp_sk(sk);
    SAFETY_CHECK(tp, 10);
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, 10);

    ca->loss_count = max_t(s32, (s32)ca->loss_count - 1, 0);
    ca->ss_mode = false;

    return max(tp->snd_cwnd, tp->prior_cwnd);
}

static void lotspeed_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    switch (event) {
        case CA_EVENT_LOSS:
            ca->loss_count++;
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain - 5, 10);
            }
            break;

        case CA_EVENT_TX_START:
        case CA_EVENT_CWND_RESTART:
            ca->ss_mode = true;
            ca->probe_cnt = 0;
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
        .ssthresh       = lotspeed_ssthresh,
        .set_state      = lotspeed_set_state_hook,
        .undo_cwnd      = lotspeed_undo_cwnd,
        .cwnd_event     = lotspeed_cwnd_event,
        .flags          = TCP_CONG_NON_RESTRICTED,
};

// --- 模块生命周期 ---
static int __init lotspeed_module_init(void)
{
    BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);

    pr_info("╔════════════════════════════════════════════════════════════╗\n");
    pr_info("║      LotSpeed Zeta v5.0 - Safety Enhanced Edition          ║\n");
    pr_info("║      Author: uk0  Date: %s                    ║\n", CURRENT_TIMESTAMP);
    pr_info("║      Features: Learning Mode, Loss Immunity, Safety Guards ║\n");
    pr_info("║      Based on ZetaTCP Paper by AppEx Networks              ║\n");
    pr_info("╚════════════════════════════════════════════════════════════╝\n");

    if (lotserver_safe_mode) {
        pr_info("lotspeed: Safety mode is ENABLED - Additional protections active\n");
    }

    // 初始化哈希表
    hash_init(zeta_history_map);

    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    struct zeta_history_entry *entry;
    struct hlist_node *tmp;
    int bkt;
    int wait_count = 0;
    const int max_wait = 300;  // 最多等待5分钟

    // 先注销，阻止新连接
    tcp_unregister_congestion_control(&lotspeed_ops);

    // 等待现有连接关闭
    while (atomic_read(&active_connections) > 0 && wait_count < max_wait) {
        if (wait_count % 30 == 0) {  // 每30秒打印一次
            pr_info("lotspeed: Waiting for %d active connections to close... (%d/%d)\n",
                    atomic_read(&active_connections), wait_count, max_wait);
        }
        msleep(1000);
        wait_count++;
    }

    if (atomic_read(&active_connections) > 0) {
        pr_warn("lotspeed: WARNING: %d connections still active after %d seconds!\n",
                atomic_read(&active_connections), max_wait);
        if (!lotserver_safe_mode) {
            pr_warn("lotspeed: Forcing unload may cause instability!\n");
        } else {
            pr_err("lotspeed: Safety mode prevents forced unload. Aborting.\n");
            // 重新注册以保持稳定
            tcp_register_congestion_control(&lotspeed_ops);
            return;
        }
    }

    // 等待RCU grace period
    synchronize_rcu();

    // 清理历史记录
    spin_lock_bh(&zeta_history_lock);
    hash_for_each_safe(zeta_history_map, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
        atomic_dec(&history_entries_count);
    }
    spin_unlock_bh(&zeta_history_lock);

    pr_info("lotspeed: Module unloaded successfully. Total bytes sent: %llu MB\n",
            atomic64_read(&total_bytes_sent) >> 20);
    pr_info("lotspeed: Total losses: %d, History entries cleared: %d\n",
            atomic_read(&total_losses),
            atomic_read(&history_entries_count));
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0");
MODULE_VERSION("5.0");
MODULE_DESCRIPTION("LotSpeed Zeta - Learning-based Congestion Control with Safety Guards");
MODULE_ALIAS("tcp_lotspeed");