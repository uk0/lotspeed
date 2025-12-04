/*
 * zeta_core.h - Zeta-TCP Core Definitions
 * Learning-based TCP Accelerator via NetFilter
 * Author: uk0
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
#include <net/tcp.h>

/* ========== 版本与配置 ========== */
#ifndef ZETA_VERSION
#define ZETA_VERSION "1.0.0"
#endif

#define ZETA_HASH_BITS          12
#define ZETA_MAX_CONNECTIONS    8192
#define ZETA_HISTORY_SIZE       64
#define ZETA_SAMPLE_WINDOW      32
#define ZETA_CONN_TIMEOUT_SEC   300
#define ZETA_GC_INTERVAL_MS     10000

/* ========== 拥塞判断阈值 ========== */
#define ZETA_RTT_INCREASE_THRESH    150   /* RTT增长150%触发延迟判断 */
#define ZETA_LOSS_BURST_THRESH      3     /* 连续丢包>=3判断为阵发丢包 */
#define ZETA_LOSS_RANDOM_RATE       2     /* 随机丢包率<2%忽略 */
#define ZETA_DELAY_STABLE_THRESH    10    /* RTT抖动<10%判断为稳定延迟 */
#define ZETA_CWND_MIN               4
#define ZETA_CWND_MAX               65535

/* ========== 拥塞状态枚举 ========== */
typedef enum {
    ZETA_STATE_NORMAL = 0,      /* 正常传输 */
    ZETA_STATE_RANDOM_LOSS,     /* 随机丢包(非拥塞) */
    ZETA_STATE_DELAY_RISING,    /* 延迟递增(拥塞) */
    ZETA_STATE_BURST_LOSS,      /* 阵发丢包(拥塞) */
    ZETA_STATE_STABLE_DELAY,    /* 稳定延迟(非拥塞) */
    ZETA_STATE_RECOVERING       /* 恢复中 */
} zeta_cong_state_t;

/* ========== 丢包模式分类 ========== */
typedef enum {
    LOSS_NONE = 0,
    LOSS_RANDOM,        /* 随机丢包 - 非拥塞因素 */
    LOSS_BURST,         /* 阵发丢包 - 深队列拥塞 */
    LOSS_TAIL,          /* 尾部丢包 - 浅队列拥塞 */
} zeta_loss_pattern_t;

/* ========== RTT 样本结构 ========== */
struct zeta_rtt_sample {
    u32 rtt_us;
    u64 timestamp;
    u8  loss_flag;      /* 该周期是否有丢包 */
};

/* ========== 学习特征向量 ========== */
struct zeta_features {
    /* RTT 特征 */
    u32 rtt_min;
    u32 rtt_avg;
    u32 rtt_max;
    u32 rtt_variance;
    s32 rtt_trend;          /* 正=上升, 负=下降 */

    /* 丢包特征 */
    u32 loss_total;
    u32 loss_recent;        /* 最近窗口丢包数 */
    u32 loss_burst_count;   /* 连续丢包计数 */
    u32 loss_interval_avg;  /* 平均丢包间隔 */

    /* 带宽特征 */
    u64 bw_estimate;        /* bytes/sec */
    u64 bw_max_seen;

    /* 综合评分 */
    u32 congestion_score;   /* 0-100, 越高越拥塞 */
};

/* ========== 连接跟踪结构 ========== */
struct zeta_conn {
    struct hlist_node   hnode;
    struct rcu_head     rcu;

    /* 连接标识 - 四元组 */
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
    u32                 snd_una;        /* 最小未确认 */
    u32                 snd_nxt;        /* 下一个发送 */
    u32                 rcv_nxt;        /* 期望接收 */
    u32                 last_ack;

    /* RTT 测量 */
    u64                 rtt_measure_start;
    u32                 rtt_measure_seq;
    struct zeta_rtt_sample rtt_history[ZETA_HISTORY_SIZE];
    u32                 rtt_history_idx;

    /* 学习引擎数据 */
    struct zeta_features features;

    /* ACK 控制 */
    u32                 ack_delay_us;       /* ACK 延迟 */
    u16                 ack_rwnd_scale;     /* 窗口缩放因子 (0-100%) */
    u8                  ack_suppress_count; /* ACK 抑制计数 */
    u8                  ack_dup_thresh;     /* DupACK 阈值 */

    /* 窗口控制 */
    u32                 virtual_cwnd;       /* 虚拟拥塞窗口 */
    u32                 target_rate;        /* 目标速率 bytes/s */

    /* 统计 */
    u64                 bytes_sent;
    u64                 bytes_acked;
    u32                 pkts_sent;
    u32                 pkts_retrans;
    u32                 pkts_lost;

    /* 时间戳 */
    u64                 create_time;
    u64                 last_active;
    u64                 last_loss_time;
};

/* ========== 全局统计结构 ========== */
struct zeta_stats {
    atomic64_t  conns_total;
    atomic64_t  conns_active;
    atomic64_t  pkts_in;
    atomic64_t  pkts_out;
    atomic64_t  pkts_modified;
    atomic64_t  acks_delayed;
    atomic64_t  acks_suppressed;
    atomic64_t  cwnd_reductions;
    atomic64_t  learning_decisions;
};

/* ========== 全局上下文 ========== */
struct zeta_ctx {
    /* 连接哈希表 */
    DECLARE_HASHTABLE(conn_table, ZETA_HASH_BITS);
    spinlock_t          conn_lock;
    atomic_t            conn_count;

    /* NetFilter Hooks */
    struct nf_hook_ops  hook_in;
    struct nf_hook_ops  hook_out;

    /* GC 定时器 */
    struct timer_list   gc_timer;

    /* 统计 */
    struct zeta_stats   stats;

    /* 配置 */
    bool                enabled;
    bool                verbose;
    u32                 max_rate;       /* 全局限速 bytes/s */
    u32                 start_rate;     /* 起始速率 */
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

/* 时间戳 */
static inline u64 zeta_now_us(void) {
    return ktime_get_ns() / 1000;
}

static inline u64 zeta_now_ms(void) {
    return ktime_get_ns() / 1000000;
}

/* TCP 序列号比较 */
static inline bool zeta_seq_before(u32 a, u32 b) {
    return (s32)(a - b) < 0;
}

static inline bool zeta_seq_after(u32 a, u32 b) {
    return (s32)(a - b) > 0;
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

/* zeta_hooks.c */
int zeta_hooks_register(void);
void zeta_hooks_unregister(void);

/* zeta_proc.c */
int zeta_proc_init(void);
void zeta_proc_cleanup(void);

#endif /* _ZETA_CORE_H */