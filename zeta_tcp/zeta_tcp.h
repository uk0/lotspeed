/*
 * zeta_tcp.h - Zeta-TCP Implementation
 *
 * 基于 AppEx Networks ZetaTCP 白皮书重建
 * 核心特性：
 *   1.混合拥塞检测（RTT + 丢包联合判断）
 *   2.概率丢包检测（per-packet loss probability）
 *   3.智能重传决策
 *   4.反向路径优化
 *   5.动态窗口控制
 */

#ifndef ZETA_TCP_H
#define ZETA_TCP_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>

/* ============ 版本兼容 ============ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    #define ZETA_NF_NEW_HOOK_API 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    #define ZETA_OKFN_NEW_API 1
    typedef int (*zeta_okfn_t)(struct net *, struct sock *, struct sk_buff *);
#else
    typedef int (*zeta_okfn_t)(struct sk_buff *);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    #define ZETA_PDE_DATA(inode) pde_data(inode)
#else
    #define ZETA_PDE_DATA(inode) PDE_DATA(inode)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    #define ZETA_USE_PROC_OPS 1
#endif

/* ============ 时间工具 ============ */
static inline u64 zeta_get_time_ns(void)
{
    return ktime_to_ns(ktime_get());
}

static inline u32 zeta_get_time_us(void)
{
    return (u32)(zeta_get_time_ns() / 1000ULL);
}

static inline u32 zeta_get_time_ms(void)
{
    return (u32)(zeta_get_time_ns() / 1000000ULL);
}

#define US_TO_NS(x)    ((x) * 1000ULL)
#define MS_TO_NS(x)    ((x) * 1000000ULL)
#define MS_TO_US(x)    ((x) * 1000U)

/* ============ 常量定义 ============ */

/* 流方向 */
#define FLOW_DIR_UNKNOWN    0
#define FLOW_DIR_OUTBOUND   1   /* 本机发起 */
#define FLOW_DIR_INBOUND    2   /* 外部发起 */

/* 拥塞状态（Zeta-TCP 概率模型） */
enum zeta_cong_state {
    ZETA_STATE_OPEN = 0,        /* 无拥塞 */
    ZETA_STATE_DISORDER,        /* 轻微乱序/丢包 */
    ZETA_STATE_CWR,             /* 拥塞窗口减少 */
    ZETA_STATE_RECOVERY,        /* 快速恢复 */
    ZETA_STATE_LOSS,            /* 严重丢包 */
};

/* 网络状态（用于混合判断） */
enum zeta_net_quality {
    ZETA_NET_EXCELLENT = 0,     /* 优秀：低延迟、无丢包 */
    ZETA_NET_GOOD,              /* 良好：略有抖动 */
    ZETA_NET_FAIR,              /* 一般：有拥塞迹象 */
    ZETA_NET_POOR,              /* 较差：明显拥塞 */
    ZETA_NET_BAD,               /* 很差：严重拥塞/丢包 */
};

/* 流标志 */
#define ZETA_FLAG_SACK_OK       (1 << 0)
#define ZETA_FLAG_TS_OK         (1 << 1)
#define ZETA_FLAG_ECN_OK        (1 << 2)
#define ZETA_FLAG_WSCALE_OK     (1 << 3)
#define ZETA_FLAG_LOSS_SEEN     (1 << 4)
#define ZETA_FLAG_RECOVERY      (1 << 5)
#define ZETA_FLAG_THROTTLE      (1 << 6)
#define ZETA_FLAG_ACCELERATE    (1 << 7)

/* 参数限制 */
#define ZETA_RTT_MIN_US         1000        /* 1ms */
#define ZETA_RTT_MAX_US         30000000    /* 30s */
#define ZETA_RTT_HISTORY_SIZE   16
#define ZETA_LOSS_HISTORY_SIZE  32
#define ZETA_SACK_BLOCKS_MAX    4

/* 概率阈值（x1000） */
#define ZETA_CONG_PROB_LOW      100     /* 10% */
#define ZETA_CONG_PROB_MED      300     /* 30% */
#define ZETA_CONG_PROB_HIGH     600     /* 60% */
#define ZETA_CONG_PROB_CERTAIN  900     /* 90% */

#define ZETA_LOSS_PROB_THRESH   500     /* 50% - 触发重传 */

/* 流表参数 */
#define ZETA_FLOW_TABLE_BITS    10
#define ZETA_FLOW_TABLE_SIZE    (1 << ZETA_FLOW_TABLE_BITS)
#define ZETA_FLOW_MAX_COUNT     65536
#define ZETA_FLOW_TIMEOUT_US    120000000   /* 2分钟 */

/* 包队列 */
#define ZETA_PKT_QUEUE_SIZE     262144

/* ============ 数据结构 ============ */

/* SACK 块 */
struct zeta_sack_block {
    u32 start;
    u32 end;
};

struct zeta_sack_info {
    u8 num_blocks;
    struct zeta_sack_block blocks[ZETA_SACK_BLOCKS_MAX];
};

/* RTT 测量（高精度） */
struct zeta_rtt_info {
    u32 srtt;           /* 平滑 RTT (us) */
    u32 rttvar;         /* RTT 方差 (us) */
    u32 min_rtt;        /* 最小 RTT */
    u32 max_rtt;        /* 最大 RTT */
    u32 latest_rtt;     /* 最新 RTT */

    /* RTT 历史（用于趋势分析） */
    u32 history[ZETA_RTT_HISTORY_SIZE];
    u8  history_idx;
    u8  history_count;

    /* 时间戳跟踪 */
    u32 ts_recent;      /* 最近收到的 TSval */
    u32 ts_recent_time; /* 收到时间 */
    u32 ts_echo;        /* 要回显的值 */
    u32 last_sent_ts;   /* 最近发送的 TSval */
    u32 last_sent_time; /* 发送时间 */
};

/*
 * Zeta-TCP 核心：概率丢包检测
 * 为每个未确认的包计算丢包概率
 */
struct zeta_loss_detector {
    u32 high_seq;           /* 最高已发送序号 */
    u32 snd_una;            /* 最小未确认序号 */
    u32 retrans_out;        /* 在途重传包数 */
    u32 sacked_out;         /* SACK 确认但未 ACK 的包数 */
    u32 lost_out;           /* 被标记为丢失的包数 */

    /* 丢包历史（用于计算丢包率） */
    u32 loss_history[ZETA_LOSS_HISTORY_SIZE];
    u8  loss_idx;
    u8  loss_count;

    /* 重复 ACK */
    u32 dup_ack_seq;        /* 重复 ACK 的序号 */
    u8  dup_ack_count;      /* 连续重复 ACK 数 */

    /* SACK 信息 */
    struct zeta_sack_info sack;
    u32 sack_seq;           /* SACK 对应的 ACK 序号 */
};

/*
 * Zeta-TCP 核心：混合拥塞检测
 * 结合 RTT 变化和丢包率判断拥塞
 */
struct zeta_cong_detector {
    /* 拥塞概率（0-1000） */
    u32 cong_probability;

    /* RTT 趋势分析 */
    s32 rtt_gradient;       /* RTT 变化梯度 */
    u32 rtt_standing;       /* 站立 RTT（空闲时的 RTT） */
    u32 rtt_probe_rtt;      /* 探测到的最小 RTT */

    /* 丢包率分析 */
    u32 loss_rate;          /* 丢包率 (x1000) */
    u32 ecn_rate;           /* ECN 标记率 (x1000) */

    /* 带宽估计 */
    u64 bw_estimate;        /* 估计带宽 (bytes/sec) */
    u64 bw_lo;              /* 带宽下限 */
    u64 bw_hi;              /* 带宽上限 */
    u32 delivered;          /* 已确认发送的字节数 */
    u32 delivered_time;     /* 上次更新时间 */

    /* 状态 */
    enum zeta_cong_state state;
    enum zeta_net_quality quality;
};

/*
 * 窗口控制
 */
struct zeta_win_ctrl {
    u32 cwnd;               /* 拥塞窗口 (字节) */
    u32 ssthresh;           /* 慢启动阈值 */
    u32 rwnd;               /* 接收窗口 */
    u32 awnd;               /* 可用窗口 */

    u8  snd_wscale;         /* 发送窗口缩放 */
    u8  rcv_wscale;         /* 接收窗口缩放 */

    /* 窗口放大（用于反向加速） */
    u32 win_inflate_factor; /* 放大倍数 (x1000) */
    u32 advertised_win;     /* 广告窗口 */

    /* Pacing */
    u64 pacing_rate;        /* 发送速率 (bytes/sec) */
    u64 next_send_time;     /* 下次发送时间 (ns) */
};

/*
 * 反向路径控制（用于上传加速）
 */
struct zeta_reverse_ctrl {
    u32 rcv_nxt;            /* 期望接收的下一个序号 */
    u32 last_ack_sent;      /* 上次发送的 ACK */
    u32 delayed_acks;       /* 延迟 ACK 计数 */
    u32 bytes_received;     /* 收到的字节数 */
    u32 ooo_count;          /* 乱序包计数 */
    u32 last_rcv_time;      /* 上次收到数据时间 */

    /* SACK 生成 */
    struct zeta_sack_info rcv_sack;
};

/*
 * 流信息（完整）
 */
struct zeta_flow_info {
    /* 基础信息 */
    u8  direction;
    u8  state;
    u16 flags;
    u32 mss;
    u32 last_update;

    /* 序号跟踪 */
    u32 snd_una;            /* 最小未确认 */
    u32 snd_nxt;            /* 下一个发送 */
    u32 snd_wl1;            /* 用于窗口更新的序号 */
    u32 snd_wl2;            /* 用于窗口更新的 ACK */

    /* 各子模块 */
    struct zeta_rtt_info rtt;
    struct zeta_loss_detector loss;
    struct zeta_cong_detector cong;
    struct zeta_win_ctrl win;
    struct zeta_reverse_ctrl rev;

    /* 统计 */
    u64 bytes_sent;
    u64 bytes_acked;
    u64 bytes_retrans;
    u32 pkts_sent;
    u32 pkts_retrans;
};

/*
 * 流结构
 */
struct zeta_flow {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;

    struct zeta_flow_info info;
    struct list_head list;

    spinlock_t lock;
};

/*
 * 流表
 */
struct zeta_flow_table {
    struct list_head buckets[ZETA_FLOW_TABLE_SIZE];
    u32 count;
    spinlock_t lock;
};

/*
 * 包节点
 */
struct zeta_pkt_node {
    struct sk_buff *skb;
    zeta_okfn_t okfn;
    u32 seq;                /* 包的起始序号 */
    u32 len;                /* 数据长度 */
    u32 enqueue_time;       /* 入队时间 */
    u32 send_time;          /* 计划发送时间 */
    u8  retrans;            /* 是否是重传 */
};

/*
 * 包队列
 */
struct zeta_pkt_queue {
    struct zeta_pkt_node *ring;
    u32 head;
    u32 tail;
    u32 size;
    u32 capacity;
    spinlock_t lock;
};

/*
 * 全局参数
 */
struct zeta_params {
    /* 基础 */
    u32 debug;
    char nic[32];
    u32 mss;

    /* RTT */
    u32 min_rtt_us;
    u32 max_rtt_us;

    /* 拥塞控制 */
    u32 cong_alpha;         /* RTT 权重 (x1000) */
    u32 cong_beta;          /* 丢包权重 (x1000) */
    u32 cwnd_gain;          /* 窗口增益 (x1000) */
    u32 pacing_gain;        /* Pacing 增益 (x1000) */

    /* 丢包检测 */
    u32 loss_prob_thresh;   /* 丢包概率阈值 (x1000) */
    u32 dup_ack_thresh;     /* 重复 ACK 阈值 */

    /* 反向控制 */
    u32 win_inflate_factor; /* 窗口放大倍数 */
    u32 ack_ratio;          /* ACK 比例 */

    /* 缓冲区 */
    u32 buffer_size;        /* 令牌桶大小 */
    u32 max_delay_us;       /* 最大排队延迟 */

    /* 定时器 */
    u32 timer_interval_us;

    /* 功能开关 */
    u32 enable_sack;
    u32 enable_ecn;
    u32 enable_pacing;
    u32 enable_reverse;
};

/*
 * 全局统计
 */
struct zeta_stats {
    /* 流 */
    u64 flows_created;
    u64 flows_destroyed;

    /* 包 */
    u64 pkts_rx;
    u64 pkts_tx;
    u64 pkts_queued;
    u64 pkts_dropped;
    u64 pkts_retrans;

    /* 字节 */
    u64 bytes_rx;
    u64 bytes_tx;

    /* 拥塞 */
    u64 cong_events;
    u64 loss_events;
    u64 recovery_events;

    /* 反向控制 */
    u64 win_inflated;
    u64 acks_generated;
    u64 sacks_generated;

    /* RTT */
    u64 rtt_samples;
    u32 avg_rtt;
    u32 min_rtt;
};

/*
 * 全局引擎
 */
struct zeta_engine {
    struct zeta_params params;
    struct zeta_flow_table ft;

    /* 包队列 */
    struct zeta_pkt_queue *tx_queue;

    /* 令牌桶 */
    u64 tokens;
    u64 bucket_size;
    spinlock_t token_lock;

    /* 全局 RTT 估计 */
    u32 global_rtt;
    u32 global_min_rtt;
    u64 global_bw;
    spinlock_t global_lock;

    /* 统计 */
    struct zeta_stats stats;

    /* 定时器 */
    struct hrtimer timer;
    bool running;
};

/* ============ 序号比较 ============ */
static inline bool zeta_seq_lt(u32 a, u32 b)  { return (s32)(a - b) < 0; }
static inline bool zeta_seq_leq(u32 a, u32 b) { return (s32)(a - b) <= 0; }
static inline bool zeta_seq_gt(u32 a, u32 b)  { return (s32)(a - b) > 0; }
static inline bool zeta_seq_geq(u32 a, u32 b) { return (s32)(a - b) >= 0; }

static inline u32 zeta_seq_diff(u32 a, u32 b)
{
    s32 diff = (s32)(a - b);
    return diff > 0 ? diff : 0;
}

/* ============ 日志宏 ============ */
#define ZETA_LOG(eng, fmt, ...) do { \
    if ((eng)->params.debug) \
        printk(KERN_DEBUG "ZetaTCP: " fmt, ##__VA_ARGS__); \
} while(0)

#define ZETA_INFO(fmt, ...) \
    printk(KERN_INFO "ZetaTCP: " fmt, ##__VA_ARGS__)

#define ZETA_ERR(fmt, ...) \
    printk(KERN_ERR "ZetaTCP: " fmt, ##__VA_ARGS__)

/* ============ 函数声明 ============ */

/* zeta_cong. c */
u32 zeta_calc_congestion_probability(struct zeta_flow_info *info,
                                      struct zeta_params *params);
void zeta_adjust_cwnd(struct zeta_flow_info *info, struct zeta_params *params);
void zeta_update_loss_rate(struct zeta_flow_info *info, bool is_loss);

/* zeta_loss.c */
u32 zeta_calc_packet_loss_prob(struct zeta_flow_info *info, u32 seq, u32 len);
bool zeta_should_retransmit(struct zeta_flow_info *info, u32 seq, u32 len,
                             struct zeta_params *params);
void zeta_process_ack(struct zeta_flow_info *info, u32 ack_seq,
                       struct zeta_sack_info *sack, struct zeta_params *params,
                       struct zeta_stats *stats);
int zeta_parse_sack(struct tcphdr *th, u32 tcp_hdr_len, struct zeta_sack_info *sack);

/* zeta_rtt.c */
void zeta_update_rtt(struct zeta_rtt_info *rtt, u32 sample_rtt);
u32 zeta_measure_rtt_incoming(struct sk_buff *skb, struct zeta_flow_info *info);
void zeta_stamp_outgoing(struct sk_buff *skb, struct zeta_flow_info *info);
u16 zeta_inflate_window(struct zeta_flow_info *info, u16 orig_win,
                         struct zeta_params *params);
void zeta_modify_ack_window(struct sk_buff *skb, struct zeta_flow_info *info,
                             struct zeta_params *params);
void zeta_update_reverse_stats(struct zeta_flow_info *info, u32 seq, u32 len);

#endif /* ZETA_TCP_H */