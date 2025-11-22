/*
 * lotspeed_zeta_v5_1.c
 * "公路超跑" Zeta-TCP 深度复刻版 - 内存优化修正版
 * Author: uk0 (Fixed by Gemini)
 *
 * Fixes:
 * - Solved "BUILD_BUG_ON" compilation error by optimizing struct layout.
 * - Removed non-critical statistics (start_time, bytes_sent) to fit in kernel memory.
 * - Reordered fields to minimize padding.
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

// --- 参数回调 (保持不变) ---
static int param_set_rate(const char *val, const struct kernel_param *kp) { return param_set_ulong(val, kp); }
static int param_set_gain(const char *val, const struct kernel_param *kp) { return param_set_uint(val, kp); }
static int param_set_min_cwnd(const char *val, const struct kernel_param *kp) {
    int ret = param_set_uint(val, kp);
    if (!ret && lotserver_min_cwnd < 4) lotserver_min_cwnd = 4;
    return ret;
}
static int param_set_max_cwnd(const char *val, const struct kernel_param *kp) {
    int ret = param_set_uint(val, kp);
    if (!ret && lotserver_max_cwnd > 100000) lotserver_max_cwnd = 100000;
    return ret;
}
static int param_set_adaptive(const char *val, const struct kernel_param *kp) { return param_set_bool(val, kp); }
static int param_set_turbo(const char *val, const struct kernel_param *kp) { return param_set_bool(val, kp); }
static int param_set_beta(const char *val, const struct kernel_param *kp) {
    int ret = param_set_uint(val, kp);
    if (!ret) {
        if (lotserver_beta > LOTSPEED_BETA_SCALE) lotserver_beta = LOTSPEED_BETA_SCALE;
        if (lotserver_beta < 512) lotserver_beta = 512;
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

module_param_cb(lotserver_rate, &param_ops_rate, &lotserver_rate, 0644);
module_param_cb(lotserver_gain, &param_ops_gain, &lotserver_gain, 0644);
module_param_cb(lotserver_min_cwnd, &param_ops_min_cwnd, &lotserver_min_cwnd, 0644);
module_param_cb(lotserver_max_cwnd, &param_ops_max_cwnd, &lotserver_max_cwnd, 0644);
module_param_cb(lotserver_adaptive, &param_ops_adaptive, &lotserver_adaptive, 0644);
module_param_cb(lotserver_turbo, &param_ops_turbo, &lotserver_turbo, 0644);
module_param_cb(lotserver_beta, &param_ops_beta, &lotserver_beta, 0644);
module_param(lotserver_verbose, bool, 0644);
module_param(lotserver_safe_mode, bool, 0644);

// --- 全局统计 ---
static atomic_t active_connections = ATOMIC_INIT(0);
static atomic64_t total_bytes_sent = ATOMIC64_INIT(0);
static atomic_t total_losses = ATOMIC_INIT(0);
static atomic_t history_entries_count = ATOMIC_INIT(0);

// --- ZETA 学习引擎结构 ---
struct zeta_history_entry {
    struct hlist_node node;
    struct rcu_head rcu;
    u32 daddr;
    u64 cached_bw;
    u32 cached_min_rtt;
    u32 cached_median_rtt;
    u64 last_update;
    u32 sample_count;
    u32 loss_count;
};

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

// --- 私有数据结构 (内存优化版) ---
// 严禁随意添加字段，否则会导致编译失败 (BUILD_BUG_ON)
struct lotspeed {
    // 1. 8字节对齐字段 (u64) - 放在最前面
    u64 target_rate;
    u64 actual_rate;
    u64 last_bw;

    // 2. 4字节对齐字段 (u32, enum)
    u32 cwnd_gain;
    u32 last_state_ts;
    u32 probe_rtt_ts;
    u32 last_cruise_ts;

    u32 rtt_min;
    u32 rtt_median;
    u32 rtt_cnt;
    u32 loss_count;

    u32 bw_stalled_rounds;
    u32 probe_cnt;
    u32 rtt_variance;
    u32 last_loss_rtt;
    u32 sample_count;

    enum lotspeed_state state; // 通常是4字节

    // 3. 1字节对齐字段 (bool) - 放在最后减少padding
    bool ss_mode;
    bool history_hit;

    // 已移除: start_time, bytes_sent (节省16字节)
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

    if (!bw || !rtt) return;

    spin_lock_bh(&zeta_history_lock);

    entry = find_history_safe(daddr);
    if (entry) {
        entry->cached_bw = (entry->cached_bw * 7 + bw * 3) / 10;
        if (rtt < entry->cached_min_rtt) entry->cached_min_rtt = rtt;
        entry->cached_median_rtt = (entry->cached_median_rtt * 9 + rtt) / 10;
        entry->loss_count += loss_count;
        entry->sample_count++;
        entry->last_update = get_jiffies_64();
        found = true;
    }

    if (!found) {
        if (atomic_read(&history_entries_count) >= HISTORY_MAX_ENTRIES) {
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
                pr_info("lotspeed: [Zeta] Learned %pI4\n", &daddr);
            }
        }
    }
    spin_unlock_bh(&zeta_history_lock);
}

// --- 状态切换 ---
static void enter_state(struct sock *sk, enum lotspeed_state new_state)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );

    if (ca->state != new_state) {
        if (lotserver_verbose) {
            pr_info("lotspeed: [uk0] %s -> %s\n", state_to_str(ca->state), state_to_str(new_state));
        }
        ca->state = new_state;
        ca->last_state_ts = tcp_jiffies32;
        if (new_state == CRUISING) ca->last_cruise_ts = tcp_jiffies32;
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
    ca = inet_csk_ca(sk);
    daddr = sk->sk_daddr;

    memset(ca, 0, sizeof(struct lotspeed));

    ca->state = STARTUP;
    ca->last_state_ts = tcp_jiffies32;
    ca->probe_rtt_ts = tcp_jiffies32;
    ca->target_rate = lotserver_rate;
    ca->cwnd_gain = lotserver_gain;
    ca->ss_mode = true;
    ca->history_hit = false;

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
            ca->rtt_median = history->cached_median_rtt;
            ca->history_hit = true;

            if (tp->mss_cache > 0 && ca->rtt_min > 0) {
                u64 bdp = ca->target_rate * (u64)ca->rtt_min;
                u32 init_cwnd = SAFE_DIV64(bdp, (u64)tp->mss_cache * 1000000ULL);
                init_cwnd = clamp(init_cwnd, 10U, lotserver_max_cwnd);
                tp->snd_cwnd = init_cwnd;
                tp->snd_ssthresh = max(init_cwnd, 10U);
                ca->state = PROBING;
                ca->ss_mode = false;
                if (lotserver_verbose) {
                    pr_info("lotspeed: [Zeta] HIT %pI4! CWND=%u\n", &daddr, init_cwnd);
                }
            }
        }
    }
    rcu_read_unlock();
}

// --- 释放连接 ---
static void lotspeed_release(struct sock *sk)
{
    struct lotspeed *ca = inet_csk_ca(sk);

    if (!ca) {
        atomic_dec(&active_connections);
        return;
    }

    atomic_dec(&active_connections);
    if (ca->loss_count > 0) atomic_add(ca->loss_count, &total_losses);

    // Zeta Learning: 只依赖采样数和速率，不依赖 bytes_sent
    if (ca->sample_count >= ZETA_MIN_SAMPLES &&
        ca->actual_rate > 0 &&
        ca->rtt_min > 0 &&
        sk->sk_daddr != 0) {
        update_history_safe(sk->sk_daddr, ca->actual_rate, ca->rtt_min, ca->loss_count);
    }
}

static void lotspeed_update_rtt(struct sock *sk, u32 rtt_us)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    SAFETY_CHECK(ca, );
    if (!rtt_us) return;

    if (ca->state == PROBE_RTT || !ca->rtt_min || rtt_us < ca->rtt_min) {
        ca->rtt_min = rtt_us;
    }

    if (ca->rtt_median == 0) ca->rtt_median = rtt_us;
    else ca->rtt_median = (ca->rtt_median * 9 + rtt_us) / 10;

    if (ca->rtt_min > 0) {
        u32 diff = (rtt_us > ca->rtt_min) ? (rtt_us - ca->rtt_min) : 0;
        ca->rtt_variance = (ca->rtt_variance * 3 + diff) / 4;
    }

    ca->rtt_cnt++;
    ca->sample_count++;
}

// --- 核心算法 ---
static void lotspeed_adapt_and_control(struct sock *sk, const struct rate_sample *rs, int flag)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    u64 bw = 0;
    u32 rtt_us = tp->srtt_us >> 3;
    u32 cwnd, target_cwnd;
    u32 mss = tp->mss_cache ? : 1460;
    bool congestion_detected = false;

    lotspeed_update_rtt(sk, rtt_us);
    if (!rtt_us) rtt_us = 1000;

    if (rs && rs->delivered > 0 && rs->interval_us > 0) {
        bw = (u64)rs->delivered * USEC_PER_SEC;
        bw = SAFE_DIV64(bw, (u64)rs->interval_us);
        ca->actual_rate = bw;
    }

    if (!lotserver_turbo || lotserver_safe_mode) {
        if (flag & CA_ACK_ECE) congestion_detected = true;
        if (ca->rtt_min > 0 && ca->rtt_variance > 0) {
            u32 threshold = ca->rtt_min + (ca->rtt_min >> 2) + ca->rtt_variance;
            if (rtt_us > threshold) congestion_detected = true;
        }
    }

    if (ca->state != PROBE_RTT && ca->rtt_min > 0 &&
        time_after32(tcp_jiffies32, ca->probe_rtt_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_INTERVAL_MS))) {
        enter_state(sk, PROBE_RTT);
    }

    switch (ca->state) {
        case STARTUP:
            if (congestion_detected) enter_state(sk, AVOIDING);
            else if (bw > 0) {
                if (ca->last_bw > 0 && bw * 1024 > ca->last_bw * LOTSPEED_STARTUP_GROWTH_TARGET) {
                    ca->last_bw = bw;
                    ca->bw_stalled_rounds = 0;
                } else ca->bw_stalled_rounds++;

                if (ca->bw_stalled_rounds >= LOTSPEED_STARTUP_EXIT_ROUNDS) {
                    ca->target_rate = bw;
                    ca->ss_mode = false;
                    enter_state(sk, PROBING);
                }
                if (ca->last_bw == 0) ca->last_bw = bw;
            }
            break;
        case PROBING:
            if (congestion_detected) enter_state(sk, AVOIDING);
            else if (bw > 0 && bw > ca->target_rate * 9 / 10) enter_state(sk, CRUISING);
            ca->probe_cnt++;
            if (ca->probe_cnt >= 100) ca->probe_cnt = 0;
            break;
        case CRUISING:
            if (congestion_detected) enter_state(sk, AVOIDING);
            else if (time_after32(tcp_jiffies32, ca->last_cruise_ts + msecs_to_jiffies(200))) enter_state(sk, PROBING);
            break;
        case AVOIDING:
            if (!congestion_detected) enter_state(sk, PROBING);
            break;
        case PROBE_RTT:
            if (time_after32(tcp_jiffies32, ca->last_state_ts + msecs_to_jiffies(LOTSPEED_PROBE_RTT_DURATION_MS))) {
                ca->probe_rtt_ts = tcp_jiffies32;
                enter_state(sk, STARTUP);
            }
            break;
    }

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
            if (bw > 0) ca->target_rate = min(bw * 11 / 10, LOTSPEED_MAX_U64 / 2);
            ca->cwnd_gain = lotserver_gain;
            break;
        case AVOIDING:
            if (bw > 0) ca->target_rate = max_t(u64, bw * 9 / 10, lotserver_rate / 20);
            else ca->target_rate = max_t(u64, ca->target_rate * 9 / 10, lotserver_rate / 20);
            ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);
            break;
        case PROBE_RTT: break;
    }

    if (lotserver_adaptive) ca->target_rate = clamp(ca->target_rate, lotserver_rate / 20, lotserver_rate);
    else ca->target_rate = lotserver_rate;

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
    } else if (ca->ss_mode && tp->snd_cwnd < tp->snd_ssthresh) {
        if (tp->snd_cwnd < LOTSPEED_MAX_U32 / 2) cwnd = tp->snd_cwnd * 2;
        else cwnd = tp->snd_cwnd + 1;
        if (target_cwnd > 0 && cwnd >= target_cwnd) {
            ca->ss_mode = false;
            cwnd = target_cwnd;
        }
    } else {
        if (ca->state == STARTUP && rs && rs->acked_sacked > 0) {
            cwnd = (tp->snd_cwnd < LOTSPEED_MAX_U32 - rs->acked_sacked) ? tp->snd_cwnd + rs->acked_sacked : tp->snd_cwnd;
        } else {
            cwnd = target_cwnd;
        }
        if (ca->probe_cnt > 0 && ca->probe_cnt % 100 == 0 && cwnd < LOTSPEED_MAX_U32 * 10 / 11) {
            cwnd = cwnd * 11 / 10;
        }
    }

    tp->snd_cwnd = clamp(cwnd, lotserver_min_cwnd, lotserver_max_cwnd);
    tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    if (ca->target_rate < LOTSPEED_MAX_U64 * 5 / 6) sk->sk_pacing_rate = (ca->target_rate * 6) / 5;
    else sk->sk_pacing_rate = ca->target_rate;
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
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    u32 rtt_us = tp->srtt_us >> 3;
    u32 tolerance, new_ssthresh;

    if (lotserver_turbo && !lotserver_safe_mode) return TCP_INFINITE_SSTHRESH;

    if (!rtt_us) rtt_us = ca->rtt_median ? ca->rtt_median : 20000;
    u32 base_rtt = ca->rtt_min ? ca->rtt_min : rtt_us;

    tolerance = (base_rtt * LOSS_DIFFERENTIATION_K) / 100;
    tolerance += RTT_JITTER_TOLERANCE_US;
    if (ca->rtt_variance > 0) tolerance += ca->rtt_variance / 2;

    if (rtt_us <= tolerance) {
        // Loss Immunity: 只降5%或不降
        ca->last_loss_rtt = rtt_us;
        if (lotserver_safe_mode) new_ssthresh = (tp->snd_cwnd * 95) / 100;
        else new_ssthresh = tp->snd_cwnd;
    } else {
        // Congestion
        ca->loss_count++;
        ca->last_loss_rtt = rtt_us;
        ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 8 / 10, 10);
        new_ssthresh = (tp->snd_cwnd * lotserver_beta) / LOTSPEED_BETA_SCALE;
    }

    return max_t(u32, new_ssthresh, lotserver_min_cwnd);
}

static void lotspeed_set_state_hook(struct sock *sk, u8 new_state)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    switch (new_state) {
        case TCP_CA_Loss:
            if (!lotserver_turbo || lotserver_safe_mode) {
                ca->loss_count++;
                enter_state(sk, AVOIDING);
            }
            break;
        case TCP_CA_Recovery:
            if (!lotserver_turbo || lotserver_safe_mode) ca->cwnd_gain = max_t(u32, ca->cwnd_gain * 9 / 10, 15);
            break;
        case TCP_CA_Open:
            ca->ss_mode = false;
            break;
    }
}

static u32 lotspeed_undo_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct lotspeed *ca = inet_csk_ca(sk);
    if (ca->loss_count > 0) ca->loss_count--;
    ca->ss_mode = false;
    return max(tp->snd_cwnd, tp->prior_cwnd);
}

static void lotspeed_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct lotspeed *ca = inet_csk_ca(sk);
    switch (event) {
        case CA_EVENT_LOSS:
            ca->loss_count++;
            if (!lotserver_turbo || lotserver_safe_mode) ca->cwnd_gain = max_t(u32, ca->cwnd_gain - 5, 10);
            break;
        case CA_EVENT_TX_START:
        case CA_EVENT_CWND_RESTART:
            ca->ss_mode = true;
            ca->probe_cnt = 0;
            break;
        default: break;
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

static int __init lotspeed_module_init(void)
{
    BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);
    pr_info("lotspeed v5.1 loaded. Safety mode: %s\n", lotserver_safe_mode ? "ON" : "OFF");
    hash_init(zeta_history_map);
    return tcp_register_congestion_control(&lotspeed_ops);
}

static void __exit lotspeed_module_exit(void)
{
    struct zeta_history_entry *entry;
    struct hlist_node *tmp;
    int bkt, retry=0;

    tcp_unregister_congestion_control(&lotspeed_ops);
    while (atomic_read(&active_connections) > 0 && retry < 50) { msleep(100); retry++; }
    synchronize_rcu();

    spin_lock_bh(&zeta_history_lock);
    hash_for_each_safe(zeta_history_map, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    spin_unlock_bh(&zeta_history_lock);
    pr_info("lotspeed v5.1 unloaded.\n");
}

module_init(lotspeed_module_init);
module_exit(lotspeed_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0");
MODULE_VERSION("5.1");
MODULE_DESCRIPTION("LotSpeed Zeta - Memory Optimized");
MODULE_ALIAS("tcp_lotspeed");