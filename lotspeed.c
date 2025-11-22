/*
 * lotspeed_zeta_v5_fixed.c
 * "公路超跑" Zeta-TCP 深度复刻版 - 修复版
 * Author: uk0 (Size Optimized)
 *
 * Features:
 * 1. Zeta-Like Learning Mode (历史带宽记忆，实现 0-RTT 满速启动)
 * 2. RTT-based Loss Differentiation (基于延迟梯度的丢包区分)
 * 3. BBR-style Pacing & Probing
 * 4. Safety Guards (防止内核恐慌的安全检查)
 */

#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

// --- 安全性宏定义 ---
#define SAFETY_CHECK(ptr, ret) do { \
    if (unlikely(!(ptr))) { \
        if (lotserver_verbose) \
            pr_err("lotspeed: NULL pointer at %s:%d\n", __func__, __LINE__); \
        return ret; \
    } \
} while(0)

#define SAFE_DIV(n, d) ((d) ? (n)/(d) : 0)
#define SAFE_DIV64(n, d) ((d) ? div64_u64(n, d) : 0)

// --- Zeta-TCP 核心配置 ---
#define HISTORY_BITS 10
#define HISTORY_MAX_ENTRIES 4096
#define HISTORY_TTL_SEC 3600
#define LOSS_DIFFERENTIATION_K 125
#define RTT_JITTER_TOLERANCE_US 2000

#define ZETA_ALPHA 85
#define ZETA_PROBE_GAIN 110
#define ZETA_MIN_SAMPLES 10

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
static unsigned long lotserver_rate = 125000000ULL;
static unsigned int lotserver_gain = 20;
static unsigned int lotserver_min_cwnd = 16;
static unsigned int lotserver_max_cwnd = 20000;
static unsigned int lotserver_beta = 717;
static bool lotserver_adaptive = true;
static bool lotserver_turbo = false;
static bool lotserver_verbose = false;
static bool lotserver_safe_mode = true;

// --- 参数回调函数 ---
static int param_set_rate(const char *val, const struct kernel_param *kp)
{
    unsigned long old_val = lotserver_rate;
    int ret = param_set_ulong(val, kp);
    if (ret == 0 && old_val != lotserver_rate && lotserver_verbose) {
        pr_info("lotspeed: rate changed: %lu -> %lu\n", old_val, lotserver_rate);
    }
    return ret;
}

static int param_set_gain(const char *val, const struct kernel_param *kp)
{
    unsigned int old_val = lotserver_gain;
    int ret = param_set_uint(val, kp);
    if (ret == 0 && old_val != lotserver_gain && lotserver_verbose) {
        pr_info("lotspeed: gain changed: %u -> %u\n", old_val, lotserver_gain);
    }
    return ret;
}

static int param_set_turbo(const char *val, const struct kernel_param *kp)
{
    bool old_val = lotserver_turbo;
    int ret = param_set_bool(val, kp);
    if (ret == 0 && old_val != lotserver_turbo) {
        if (lotserver_turbo) {
            pr_warn("lotspeed: ⚡ TURBO MODE ACTIVATED ⚡\n");
        } else {
            pr_info("lotspeed: Turbo mode deactivated\n");
        }
    }
    return ret;
}

static const struct kernel_param_ops param_ops_rate = {
        .set = param_set_rate,
        .get = param_get_ulong,
};

static const struct kernel_param_ops param_ops_gain = {
        .set = param_set_gain,
        .get = param_get_uint,
};

static const struct kernel_param_ops param_ops_turbo = {
        .set = param_set_turbo,
        .get = param_get_bool,
};

// --- 参数定义 ---
module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
MODULE_PARM_DESC(lotserver_rate, "Target rate in bytes/sec (default 1Gbps)");

module_param_cb(lotserver_gain, &param_ops_gain, &lotserver_gain, 0644);
MODULE_PARM_DESC(lotserver_gain, "Gain multiplier x10 (20 = 2.0x)");

module_param(lotserver_min_cwnd, uint, 0644);
MODULE_PARM_DESC(lotserver_min_cwnd, "Minimum congestion window");

module_param(lotserver_max_cwnd, uint, 0644);
MODULE_PARM_DESC(lotserver_max_cwnd, "Maximum congestion window");

module_param(lotserver_adaptive, bool, 0644);
MODULE_PARM_DESC(lotserver_adaptive, "Enable adaptive rate control");

module_param_cb(lotserver_turbo, &param_ops_turbo, &lotserver_turbo, 0644);
MODULE_PARM_DESC(lotserver_turbo, "Turbo mode - ignore congestion signals");

module_param(lotserver_beta, uint, 0644);
MODULE_PARM_DESC(lotserver_beta, "Beta for fairness (default 717 = 0.7)");

module_param(lotserver_verbose, bool, 0644);
MODULE_PARM_DESC(lotserver_verbose, "Enable verbose logging");

module_param(lotserver_safe_mode, bool, 0644);
MODULE_PARM_DESC(lotserver_safe_mode, "Enable safety checks");

// --- 全局统计 ---
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t history_entries_count = ATOMIC_INIT(0);

// --- ZETA 历史记录结构 ---
struct zeta_history_entry {
    struct hlist_node node;
    struct rcu_head rcu;
    u32 daddr;
    u64 cached_bw;
    u32 cached_min_rtt;
    u64 last_update;
    u16 sample_count;  // 减小为u16
    u16 loss_count;    // 减小为u16
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

// --- 精简的私有数据结构 (优化大小) ---
struct lotspeed {
    // 64-bit fields (8 bytes each) - 总共24字节
    u64 target_rate;
    u64 actual_rate;
    u64 bytes_sent;

    // 32-bit fields (4 bytes each) - 总共48字节
    u32 rtt_min;
    u32 last_state_ts;
    u32 probe_rtt_ts;
    u32 last_bw;
    u32 cwnd_gain;
    u32 start_time;
    u32 rtt_median;
    u32 rtt_variance;
    u32 last_loss_rtt;
    u32 last_cruise_ts;
    u16 sample_count;    // 16-bit
    u16 loss_count;      // 16-bit

    // 8-bit fields (1 byte each) - 总共8字节
    u8 state;
    u8 probe_cnt;
    u8 bw_stalled_rounds;
    u8 rtt_cnt;
    u8 flags;            // 位域标志: ss_mode(bit0), history_hit(bit1)
    u8 reserved[3];      // 对齐填充
}; // 总大小: 24 + 48 + 8 = 80字节

// 标志位操作宏
#define FLAG_SS_MODE      0x01
#define FLAG_HISTORY_HIT  0x02

#define SET_FLAG(ca, flag)    ((ca)->flags |= (flag))
#define CLEAR_FLAG(ca, flag)  ((ca)->flags &= ~(flag))
#define CHECK_FLAG(ca, flag)  ((ca)->flags & (flag))

// --- 历史管理函数 ---
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
        if (entry && entry->daddr == daddr) return entry;
    }
    return NULL;
}

static void update_history_safe(u32 daddr, u64 bw, u32 rtt, u16 loss_count)
{
    struct zeta_history_entry *entry;
    bool found = false;

    if (!bw || !rtt) return;

    spin_lock_bh(&zeta_history_lock);

    entry = find_history_safe(daddr);
    if (entry) {
        entry->cached_bw = (entry->cached_bw * 7 + bw * 3) / 10;
        if (rtt < entry->cached_min_rtt) {
            entry->cached_min_rtt = rtt;
        }
        entry->loss_count = min_t(u32, entry->loss_count + loss_count, 65535);
        entry->sample_count = min_t(u32, entry->sample_count + 1, 65535);
        entry->last_update = get_jiffies_64();
        found = true;
    }

    if (!found && atomic_read(&history_entries_count) < HISTORY_MAX_ENTRIES) {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->daddr = daddr;
            entry->cached_bw = bw;
            entry->cached_min_rtt = rtt;
            entry->loss_count = loss_count;
            entry->sample_count = 1;
            entry->last_update = get_jiffies_64();
            hash_add_rcu(zeta_history_map, &entry->node, daddr);
            atomic_inc(&history_entries_count);
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
            pr_info("lotspeed: state %d -> %d\n", ca->state, new_state);
        }
        ca->state = new_state;
        ca->last_state_ts = tcp_jiffies32;
        if (new_state == CRUISING) {
            ca->last_cruise_ts = tcp_jiffies32;
        }
    }
}

// --- 初始化 ---
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

    memset(ca, 0, sizeof(struct lotspeed));

    daddr = sk->sk_daddr;
    ca->state = STARTUP;
    ca->last_state_ts = tcp_jiffies32;
    ca->probe_rtt_ts = tcp_jiffies32;
    ca->target_rate = lotserver_rate;
    ca->cwnd_gain = lotserver_gain;
    ca->start_time = ktime_get_real_seconds();
    SET_FLAG(ca, FLAG_SS_MODE);

    tp->snd_ssthresh = lotserver_turbo ? TCP_INFINITE_SSTHRESH : max(tp->snd_cwnd * 2, 10U);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif

    atomic_inc(&active_connections);

    // Zeta Learning
    rcu_read_lock();
    history = find_history_safe(daddr);
    if (history && history->sample_count >= ZETA_MIN_SAMPLES) {
        u64 age_ms = jiffies_to_msecs(get_jiffies_64() - history->last_update);

        if (age_ms < HISTORY_TTL_SEC * 1000ULL && history->cached_bw > 0) {
            ca->target_rate = (history->cached_bw * ZETA_ALPHA) / 100;
            ca->rtt_min = history->cached_min_rtt;
            SET_FLAG(ca, FLAG_HISTORY_HIT);

            if (tp->mss_cache > 0 && ca->rtt_min > 0) {
                u64 bdp = ca->target_rate * (u64)ca->rtt_min;
                u32 init_cwnd = SAFE_DIV64(bdp, (u64)tp->mss_cache * 1000000ULL);
                init_cwnd = clamp(init_cwnd, 10U, lotserver_max_cwnd);

                tp->snd_cwnd = init_cwnd;
                tp->snd_ssthresh = max(init_cwnd, 10U);
                ca->state = PROBING;
                CLEAR_FLAG(ca, FLAG_SS_MODE);

                if (lotserver_verbose) {
                    pr_info("lotspeed: Zeta HIT! cwnd=%u\n", init_cwnd);
                }
            }
        }
    }
    rcu_read_unlock();
}

// --- 释放连接 ---
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);

    if (!ca) {
        atomic_dec(&active_connections);
        return;
    }

    atomic_dec(&active_connections);

    if (ca->bytes_sent > 0) {
        atomic64_add(ca->bytes_sent, &total_bytes_sent);
    }

    if (ca->sample_count >= ZETA_MIN_SAMPLES &&
        ca->bytes_sent > 1048576 &&
        ca->actual_rate > 0 &&
        ca->rtt_min > 0 &&
        sk->sk_daddr != 0) {
        update_history_safe(sk->sk_daddr, ca->actual_rate, ca->rtt_min, ca->loss_count);
    }
}

static void lotspeed_update_rtt(struct sock *sk, u32 rtt_us)
{
    struct lotspeed *ca;

    SAFETY_CHECK(sk, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    if (!rtt_us) return;

    if (ca->state == PROBE_RTT || !ca->rtt_min || rtt_us < ca->rtt_min) {
        ca->rtt_min = rtt_us;
    }

    if (ca->rtt_median == 0) {
        ca->rtt_median = rtt_us;
    } else {
        ca->rtt_median = (ca->rtt_median * 9 + rtt_us) / 10;
    }

    if (ca->rtt_min > 0) {
        u32 diff = (rtt_us > ca->rtt_min) ? (rtt_us - ca->rtt_min) : 0;
        ca->rtt_variance = (ca->rtt_variance * 3 + diff) / 4;
    }

    ca->rtt_cnt = min(ca->rtt_cnt + 1, 255U);
    ca->sample_count = min(ca->sample_count + 1, 65535U);
}

// --- 核心算法 ---
static void lotspeed_adapt_and_control(struct sock *sk, const struct rate_sample *rs, int flag)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;
    u64 bw = 0;
    u32 rtt_us, cwnd, target_cwnd, mss;
    bool congestion_detected = false;

    SAFETY_CHECK(sk, );
    tp = tcp_sk(sk);
    SAFETY_CHECK(tp, );
    ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    rtt_us = tp->srtt_us >> 3;
    lotspeed_update_rtt(sk, rtt_us);
    if (!rtt_us) rtt_us = 1000;

    mss = tp->mss_cache;
    if (mss == 0) mss = 1460;

    if (rs && rs->delivered > 0) {
        ca->bytes_sent += rs->delivered;
        if (rs->interval_us > 0) {
            bw = (u64)rs->delivered * USEC_PER_SEC;
            bw = SAFE_DIV64(bw, (u64)rs->interval_us);
            ca->actual_rate = bw;
        }
    }

    if (!lotserver_turbo || lotserver_safe_mode) {
        if (flag & CA_ACK_ECE) {
            congestion_detected = true;
        }

        if (ca->rtt_min > 0 && ca->rtt_variance > 0) {
            u32 threshold = ca->rtt_min + (ca->rtt_min >> 2) + ca->rtt_variance;
            if (rtt_us > threshold) {
                congestion_detected = true;
            }
        }
    }

    // 状态机
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
                    ca->bw_stalled_rounds = min(ca->bw_stalled_rounds + 1, 255U);
                }

                if (ca->bw_stalled_rounds >= LOTSPEED_STARTUP_EXIT_ROUNDS) {
                    ca->target_rate = bw;
                    CLEAR_FLAG(ca, FLAG_SS_MODE);
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
            ca->probe_cnt = min(ca->probe_cnt + 1, 255U);
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

    // 速率调整
    switch (ca->state) {
        case STARTUP:
            ca->cwnd_gain = min(lotserver_gain * 12 / 10, 30U);
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

    if (lotserver_adaptive) {
        ca->target_rate = clamp(ca->target_rate, lotserver_rate / 20, lotserver_rate);
    } else {
        ca->target_rate = lotserver_rate;
    }

    // CWND 计算
    target_cwnd = 0;
    if (mss > 0 && rtt_us > 0 && ca->target_rate < LOTSPEED_MAX_U64 / rtt_us) {
        u64 bdp = ca->target_rate * (u64)rtt_us;
        target_cwnd = (u32)SAFE_DIV64(bdp, (u64)mss * 1000000ULL);

        if (ca->cwnd_gain > 0 && target_cwnd < LOTSPEED_MAX_U32 / ca->cwnd_gain) {
            target_cwnd = (target_cwnd * ca->cwnd_gain) / 10;
        }
    }

    if (ca->state == PROBE_RTT) {
        cwnd = lotserver_min_cwnd;
    } else if (CHECK_FLAG(ca, FLAG_SS_MODE) && tp->snd_cwnd < tp->snd_ssthresh) {
        if (tp->snd_cwnd < LOTSPEED_MAX_U32 / 2) {
            cwnd = tp->snd_cwnd * 2;
        } else {
            cwnd = tp->snd_cwnd + 1;
        }

        if (target_cwnd > 0 && cwnd >= target_cwnd) {
            CLEAR_FLAG(ca, FLAG_SS_MODE);
            cwnd = target_cwnd;
        }
    } else {
        if (ca->state == STARTUP && rs && rs->acked_sacked > 0) {
            if (tp->snd_cwnd < LOTSPEED_MAX_U32 - rs->acked_sacked) {
                cwnd = tp->snd_cwnd + rs->acked_sacked;
            } else {
                cwnd = tp->snd_cwnd;
            }
        } else {
            cwnd = target_cwnd;
        }

        if (ca->probe_cnt > 0 && ca->probe_cnt % 100 == 0) {
            if (cwnd < LOTSPEED_MAX_U32 * 10 / 11) {
                cwnd = cwnd * 11 / 10;
            }
        }
    }

    tp->snd_cwnd = clamp(cwnd, lotserver_min_cwnd, lotserver_max_cwnd);
    tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);

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

// --- SSTHRESH: Zeta Loss Differentiation ---
static u32 lotspeed_ssthresh(struct sock *sk)
{
    struct tcp_sock *tp;
    struct lotspeed *ca;
    u32 rtt_us, tolerance, new_ssthresh;

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

    u32 base_rtt = ca->rtt_min ? ca->rtt_min : rtt_us;

    tolerance = (base_rtt * LOSS_DIFFERENTIATION_K) / 100;
    tolerance += RTT_JITTER_TOLERANCE_US;
    if (ca->rtt_variance > 0) {
        tolerance += ca->rtt_variance / 2;
    }

    if (rtt_us <= tolerance) {
        if (lotserver_verbose) {
            pr_info("lotspeed: Non-congestion loss, RTT=%u\n", rtt_us);
        }
        ca->last_loss_rtt = rtt_us;

        if (lotserver_safe_mode) {
            new_ssthresh = (tp->snd_cwnd * 95) / 100;
        } else {
            new_ssthresh = tp->snd_cwnd;
        }
    } else {
        if (lotserver_verbose) {
            pr_info("lotspeed: Congestion loss, RTT=%u\n", rtt_us);
        }

        ca->loss_count = min(ca->loss_count + 1, 65535U);
        ca->last_loss_rtt = rtt_us;
        ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);

        new_ssthresh = (tp->snd_cwnd * lotserver_beta) / LOTSPEED_BETA_SCALE;
    }

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
                ca->loss_count = min(ca->loss_count + 1, 65535U);
                enter_state(sk, AVOIDING);
            }
            break;

        case TCP_CA_Recovery:
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 9 / 10, 15);
            }
            break;

        case TCP_CA_Open:
            CLEAR_FLAG(ca, FLAG_SS_MODE);
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

    if (ca->loss_count > 0) ca->loss_count--;
    CLEAR_FLAG(ca, FLAG_SS_MODE);

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
            ca->loss_count = min(ca->loss_count + 1, 65535U);
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->cwnd_gain = max_t(u32, ca->cwnd_gain - 5, 10);
            }
            break;

        case CA_EVENT_TX_START:
        case CA_EVENT_CWND_RESTART:
            SET_FLAG(ca, FLAG_SS_MODE);
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

    pr_info("╔════════════════════════════════════════════════════╗\n");
    pr_info("║     LotSpeed Zeta v5.0 - Optimized Edition        ║\n");
    pr_info("║     Size: %zu bytes (limit: %d)                    ║\n",
            sizeof(struct lotspeed), ICSK_CA_PRIV_SIZE);
    pr_info("╚════════════════════════════════════════════════════╝\n");

    hash_init(zeta_history_map);

    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    struct zeta_history_entry *entry;
    struct hlist_node *tmp;
    int bkt, wait_count = 0;
    const int max_wait = 100;

    tcp_unregister_congestion_control(&lotspeed_ops);

    while (atomic_read(&active_connections) > 0 && wait_count < max_wait) {
        msleep(100);
        wait_count++;
    }

    synchronize_rcu();

    spin_lock_bh(&zeta_history_lock);
    hash_for_each_safe(zeta_history_map, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
        atomic_dec(&history_entries_count);
    }
    spin_unlock_bh(&zeta_history_lock);

    pr_info("lotspeed: Module unloaded. Total sent: %llu MB\n",
            atomic64_read(&total_bytes_sent) >> 20);
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0");
MODULE_VERSION("5.0-fixed");
MODULE_DESCRIPTION("LotSpeed Zeta - Size Optimized TCP Congestion Control");
MODULE_ALIAS("tcp_lotspeed");