/*
 * zeta_core.h - Zeta-TCP Core Definitions (High-Performance Version)
 * Learning-based TCP Accelerator via NetFilter
 * Author: uk0
 *
 * Features:
 * - Per-CPU statistics and processing
 * - NAPI-style batch processing
 * - ACK Splitting support
 * - Microsecond precision timing
 */

#ifndef _ZETA_CORE_H
#define _ZETA_CORE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <net/tcp.h>

/* ========== 版本与配置 ========== */
#ifndef ZETA_VERSION
#define ZETA_VERSION "2.0.0"
#endif

#define ZETA_CONN_CACHE_SIZE    4096    /* 预分配连接数 */
#define ZETA_HISTORY_POOL_SIZE  (8 *1024 * 1024)  /* 8MB 历史数据池 */

#define ZETA_HASH_BITS          16      /* 增大哈希表 不要太大导致哈希表数组溢出 */
#define ZETA_MAX_CONNECTIONS    16384
#define ZETA_HISTORY_SIZE       512
#define ZETA_SAMPLE_WINDOW      32
#define ZETA_CONN_TIMEOUT_SEC   300
#define ZETA_GC_INTERVAL_MS     5000

/* ========== 批处理配置 ========== */
#define ZETA_BATCH_SIZE         64      /* 批处理大小 */
#define ZETA_BATCH_TIMEOUT_US   1000    /* 批处理超时（微秒）*/

/* ========== ACK Splitting 配置 ========== */
#define ZETA_ACK_SPLIT_ENABLE   1       /* 启用 ACK Splitting */
#define ZETA_ACK_SPLIT_RATIO    2       /* 每 N 个数据包发送一个 ACK */
#define ZETA_ACK_SPLIT_MAX      4       /* 最大分割数 */

/* ========== 拥塞判断阈值 ========== */
#define ZETA_RTT_INCREASE_THRESH    150
#define ZETA_LOSS_BURST_THRESH      3
#define ZETA_LOSS_RANDOM_RATE       2
#define ZETA_DELAY_STABLE_THRESH    10
#define ZETA_CWND_MIN               4
#define ZETA_CWND_MAX               65535
#define ZETA_MIN_RWND               5840    /* 4 MSS */

/* ========== 拥塞状态枚举 ========== */
typedef enum {
    ZETA_STATE_NORMAL = 0,
    ZETA_STATE_RANDOM_LOSS,
    ZETA_STATE_DELAY_RISING,
    ZETA_STATE_BURST_LOSS,
    ZETA_STATE_STABLE_DELAY,
    ZETA_STATE_RECOVERING
} zeta_cong_state_t;

/* ========== 丢包模式分类 ========== */
typedef enum {
    LOSS_NONE = 0,
    LOSS_RANDOM,
    LOSS_BURST,
    LOSS_TAIL,
} zeta_loss_pattern_t;

/* ========== RTT 样本结构 ========== */
struct zeta_rtt_sample {
    u32 rtt_us;
    u64 timestamp;
    u8  loss_flag;
};

/* ========== 学习特征向量 ========== */
struct zeta_features {
    /* RTT 特征 */
    u32 rtt_min;
    u32 rtt_avg;
    u32 rtt_max;
    u32 rtt_variance;
    s32 rtt_trend;

    /* 丢包特征 */
    u32 loss_total;
    u32 loss_recent;
    u32 loss_burst_count;
    u32 loss_interval_avg;

    /* 带宽特征 */
    u64 bw_estimate;
    u64 bw_max_seen;

    /* 综合评分 */
    u32 congestion_score;
};

/* ========== ACK Splitting 状态 ========== */
struct zeta_ack_split {
    u32 pending_acks;           /* 待发送的 ACK 数量 */
    u32 last_ack_seq;           /* 上次 ACK 的序列号 */
    u64 last_ack_time_us;       /* 上次 ACK 时间（微秒）*/
    u16 split_ratio;            /* 当前分割比例 */
    u16 accumulated_bytes;      /* 累积字节数 */
    bool enabled;               /* 是否启用 */
};

/* ========== 连接跟踪结构 ========== */
struct zeta_conn {
    struct hlist_node   hnode;
    struct rcu_head     rcu;

    /* 连接标识 */
    __be32              saddr;
    __be32              daddr;
    __be16              sport;
    __be16              dport;
    u32                 hash_key;

    /* 状态 */
    zeta_cong_state_t   state;
    zeta_loss_pattern_t loss_pattern;
    spinlock_t          lock;

    /* 序列号跟踪 */
    u32                 snd_una;
    u32                 snd_nxt;
    u32                 rcv_nxt;
    u32                 last_ack;

    /* RTT 测量（微秒精度）*/
    u64                 rtt_measure_start;
    u32                 rtt_measure_seq;
    struct zeta_rtt_sample rtt_history[ZETA_HISTORY_SIZE];
    u32                 rtt_history_idx;

    /* 学习引擎数据 */
    struct zeta_features features;

    /* ACK 控制 */
    u32                 ack_delay_us;
    u16                 ack_rwnd_scale;
    u8                  ack_suppress_count;
    u8                  ack_dup_thresh;

    /* ACK Splitting */
    struct zeta_ack_split ack_split;

    /* 窗口控制 */
    u32                 virtual_cwnd;
    u32                 target_rate;

    /* 统计 */
    u64                 bytes_sent;
    u64                 bytes_acked;
    u32                 pkts_sent;
    u32                 pkts_retrans;
    u32                 pkts_lost;

    /* 时间戳（微秒）*/
    u64                 create_time_us;
    u64                 last_active_us;
    u64                 last_loss_time_us;

    /* 兼容字段 */
    u64                 create_time;
    u64                 last_active;
    u64                 last_loss_time;

    /* CPU 亲和性 */
    int                 preferred_cpu;
};

/* ========== Per-CPU 统计结构 ========== */
struct zeta_percpu_stats {
    u64 pkts_in;
    u64 pkts_out;
    u64 pkts_modified;
    u64 acks_delayed;
    u64 acks_suppressed;
    u64 acks_split;
    u64 batch_count;
    u64 learning_decisions;
};

/* ========== Per-CPU 批处理队列 ========== */
struct zeta_batch_queue {
    struct sk_buff_head queue;
    u64 last_flush_us;
    spinlock_t lock;
    int pending_count;
};

/* ========== 全局统计结构（聚合用）========== */
struct zeta_stats {
    atomic64_t conns_total;
    atomic64_t conns_active;
    atomic64_t pkts_in;
    atomic64_t pkts_out;
    atomic64_t pkts_modified;
    atomic64_t acks_delayed;
    atomic64_t acks_suppressed;
    atomic64_t acks_split;
    atomic64_t cwnd_reductions;
    atomic64_t learning_decisions;
    atomic64_t batch_flushes;
};

/* ========== 全局上下文 ========== */
struct zeta_ctx {
    /* 连接哈希表 */
    DECLARE_HASHTABLE(conn_table, ZETA_HASH_BITS);
    spinlock_t conn_lock;
    atomic_t conn_count;

    /* NetFilter Hooks */
    struct nf_hook_ops hook_in;
    struct nf_hook_ops hook_out;

    /* GC 定时器 */
    struct timer_list gc_timer;

    /* Per-CPU 数据 */
    struct zeta_percpu_stats __percpu *percpu_stats;
    struct zeta_batch_queue __percpu *percpu_batch;

    /* 聚合统计 */
    struct zeta_stats stats;

    /* 配置 */
    bool enabled;
    bool verbose;
    bool ack_split_enabled;
    u32 max_rate;
    u32 start_rate;
    u32 batch_size;
    u32 batch_timeout_us;
};

/* ========== 全局变量声明 ========== */
extern struct zeta_ctx *g_zeta;

/* ========== 辅助宏 ========== */
#define ZETA_LOG(fmt, ...) \
    pr_info("zeta-tcp: " fmt, ##__VA_ARGS__)

#define ZETA_DBG(fmt, ...) \
    do { if (g_zeta && g_zeta->verbose) \
        pr_debug("zeta-tcp: " fmt, ##__VA_ARGS__); \
    } while(0)

#define ZETA_WARN(fmt, ...) \
    pr_warn("zeta-tcp: " fmt, ##__VA_ARGS__)

/* 安全除法 */
static inline u64 zeta_div64(u64 n, u64 d) {
    return d ? div64_u64(n, d) : 0;
}

static inline u32 zeta_div32(u32 n, u32 d) {
    return d ? n / d : 0;
}

/* 高精度时间戳（微秒）*/
static inline u64 zeta_now_us(void) {
    return ktime_get_ns() / 1000;
}

static inline u64 zeta_now_ms(void) {
    return ktime_get_ns() / 1000000;
}

/* 纳秒时间戳（最高精度）*/
static inline u64 zeta_now_ns(void) {
    return ktime_get_ns();
}

/* TCP 序列号比较 */
static inline bool zeta_seq_before(u32 a, u32 b) {
    return (s32)(a - b) < 0;
}

static inline bool zeta_seq_after(u32 a, u32 b) {
    return (s32)(a - b) > 0;
}

/* Per-CPU 统计更新（无锁）*/
static inline void zeta_percpu_stats_inc(u64 __percpu *stat) {
    this_cpu_inc(*stat);
}

static inline void zeta_percpu_stats_add(u64 __percpu *stat, u64 val) {
    this_cpu_add(*stat, val);
}

/* ========== 函数声明 ========== */

/* zeta_conn.c */
struct zeta_conn *zeta_conn_find(__be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport);
struct zeta_conn *zeta_conn_create(__be32 saddr, __be32 daddr,
                                    __be16 sport, __be16 dport);
void zeta_conn_destroy(struct zeta_conn *conn);
void zeta_conn_gc(struct timer_list *t);
void zeta_conn_init(void);
void zeta_conn_cleanup(void);

/* zeta_learning.c */
void zeta_learn_update(struct zeta_conn *conn, struct tcphdr *th,
                       int payload_len, bool is_ack);
zeta_cong_state_t zeta_learn_classify(struct zeta_conn *conn);
void zeta_learn_rtt_sample(struct zeta_conn *conn, u32 rtt_us);
u32 zeta_learn_get_cwnd(struct zeta_conn *conn);
u32 zeta_learn_get_rate(struct zeta_conn *conn);

/* zeta_ack_control.c */
int zeta_ack_process(struct zeta_conn *conn, struct sk_buff *skb,
                     struct tcphdr *th);
void zeta_ack_modify_rwnd(struct zeta_conn *conn, struct tcphdr *th);
bool zeta_ack_should_suppress(struct zeta_conn *conn);
void zeta_ack_generate_dupack(struct zeta_conn *conn, struct sk_buff *skb);
void zeta_ack_handle_ecn(struct zeta_conn *conn, struct tcphdr *th,
                         struct iphdr *iph);
void zeta_ack_emergency_brake(struct zeta_conn *conn, struct tcphdr *th);

/* ACK Splitting */
int zeta_ack_split_process(struct zeta_conn *conn, struct sk_buff *skb,
                           struct tcphdr *th, int payload_len);
void zeta_ack_split_flush(struct zeta_conn *conn, struct sk_buff *skb);
void zeta_ack_split_init(struct zeta_conn *conn);

/* zeta_hooks.c */
int zeta_hooks_register(void);
void zeta_hooks_unregister(void);

/* zeta_batch.c */
int zeta_batch_init(void);
void zeta_batch_cleanup(void);
void zeta_batch_enqueue(struct sk_buff *skb, int cpu);
void zeta_batch_flush(int cpu);
void zeta_batch_flush_all(void);

/* zeta_percpu.c */
int zeta_percpu_init(void);
void zeta_percpu_cleanup(void);
void zeta_percpu_stats_aggregate(struct zeta_stats *total);

/* zeta_proc.c */
int zeta_proc_init(void);
void zeta_proc_cleanup(void);

#endif /* _ZETA_CORE_H */