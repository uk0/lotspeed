/*
 * tapac.h - TCP Acceleration + PAC v2.2
 * 完整版：修复 ACK 调度器，参考 tcp_accel_engine.c
 */

#ifndef TAPAC_H
#define TAPAC_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/netdevice.h>

/* ============ 版本兼容 ============ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    #define TAPAC_NF_NEW_HOOK_API 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    #define TAPAC_OKFN_NEW_API 1
    typedef int (*tapac_okfn_t)(struct net *, struct sock *, struct sk_buff *);
#else
    typedef int (*tapac_okfn_t)(struct sk_buff *);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    #define TAPAC_PDE_DATA(inode) pde_data(inode)
#else
    #define TAPAC_PDE_DATA(inode) PDE_DATA(inode)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    #define TAPAC_USE_PROC_OPS 1
#endif

static inline u32 tapac_get_time_us(void)
{
    return (u32)(ktime_to_ns(ktime_get()) / 1000ULL);
}

static inline u32 tapac_get_time_ms(void)
{
    return (u32)(ktime_to_ns(ktime_get()) / 1000000ULL);
}

/* ============ 单位转换 ============ */
#define US_TO_NS(x)    ((x) * 1000ULL)
#define MS_TO_NS(x)    ((x) * 1000000ULL)
#define MS_TO_US(x)    ((x) * 1000U)

/* ============ 流方向 ============ */
#define FLOW_DIR_SERVER     0
#define FLOW_DIR_CLIENT     1

/* ============ TCP 阶段 ============ */
#define PHASE_SLOW_START    0
#define PHASE_CONG_AVOID    1
#define PHASE_FAST_RECOVERY 2

/* ============ 优先级 ============ */
#define PRIO_HIGH           1
#define PRIO_LOW            0

/* ============ 流标志 ============ */
#define FLOW_FLAG_FAST_PATH      (1 << 0)
#define FLOW_FLAG_HAS_SACK       (1 << 1)
#define FLOW_FLAG_ECN_CAPABLE    (1 << 2)
#define FLOW_FLAG_LOSS_DETECTED  (1 << 3)
#define FLOW_FLAG_WIN_SCALED     (1 << 4)
#define FLOW_FLAG_ACK_PENDING    (1 << 5)
#define FLOW_FLAG_UPLOAD_ACCEL   (1 << 6)
#define FLOW_FLAG_SACK_PERMITTED (1 << 7)
#define FLOW_FLAG_TS_ENABLED     (1 << 8)

/* ============ ACK 优化参数（参考 tcp_accel_engine.c） ============ */
#define ACK_BUCKETS              32
#define ACK_MAX_QUEUE_DEPTH      64
#define ACK_MAX_DELTA_BYTES      0x15B4   /* 5556 bytes */
#define ACK_DELAY_TICKS_MS       50       /* 默认 50ms 后发送 ACK */
#define ACK_DELAY_MIN_MS         5
#define ACK_DELAY_MAX_MS         40
#define ACK_COMPRESS_THRESH      4
#define MAX_SACK_BLOCKS          4

/* ============ 窗口控制参数 ============ */
#define WIN_SCALE_MAX       14
#define WIN_ADVERTISE_MIN   65535
#define WIN_ADVERTISE_MAX   (1 << 30)
#define WIN_INFLATE_FACTOR  4

/* ============ 流表参数 ============ */
#define FLOW_TABLE_BITS     8
#define FLOW_TABLE_SIZE     (1 << FLOW_TABLE_BITS)
#define FLOW_MAX_COUNT      10240

/* ============ 包队列参数 ============ */
#define PKT_QUEUE_SIZE      2500000

/* ============ RTT 历史记录 ============ */
#define RTT_HISTORY_SIZE    8

/* ============ SACK 信息结构 ============ */
struct tapac_sack_block {
    u32 start;
    u32 end;
};

struct tapac_sack_info {
    u8 num_blocks;
    struct tapac_sack_block blocks[MAX_SACK_BLOCKS];
};

/* ============ 窗口控制信息 ============ */
struct tapac_win_info {
    u8  snd_wscale;
    u8  rcv_wscale;
    u16 advertised_win;
    u32 max_win;
    u32 inflated_win;
    u32 last_win_update;
};

/* ============ RTT 测量信息 ============ */
struct tapac_rtt_info {
    u32 last_tsval;
    u32 last_tsval_time;
    u32 history[RTT_HISTORY_SIZE];
    u8  history_idx;
    u8  history_count;
    u32 min_rtt;
    u32 max_rtt;
    u32 var_rtt;
};

/* ============ 上传加速信息 ============ */
struct tapac_upload_accel {
    u32 bytes_received;
    u32 bytes_acked;
    u32 pending_acks;
    u32 last_ack_time;
    u32 ack_interval;
    u32 expected_seq;
    u8  dup_ack_trigger;
    u8  ooo_count;
};

/* ============ 下载令牌桶 ============ */
struct tapac_download_bucket {
    u64 tokens;
    u32 bucket_size;
    u32 last_update;
};

/* ============ 上传令牌桶 ============ */
struct tapac_upload_bucket {
    u64 ack_tokens;
    u32 ack_bucket_size;
    u32 last_ack_time;
};

/* ============ 前向声明 ============ */
struct tapac_flow;
struct tapac_engine;

/* ============ ACK 节点（参考 tcp_accel_engine.c） ============ */
struct tapac_ack_node {
    /* per-flow 双向链表 */
    struct tapac_ack_node *flow_prev;
    struct tapac_ack_node *flow_next;
    /* 全局调度 bucket 双向链表 */
    struct tapac_ack_node *sched_prev;
    struct tapac_ack_node *sched_next;

    struct tapac_flow *flow;

    u32 ack_seq;
    u16 ack_win;
    u16 age_ticks;           /* 用于判断是否该发 ACK (ms) */
    u32 last_ts_ms;          /* 最近更新时间戳 */
    u16 last_ack_delta;      /* 最近 ACK 进展 delta */

    /* 用于发送 ACK */
    u32 tsval;
    u32 tsecr;
    u32 seq;                 /* 我方 SEQ */
};

/* ============ ACK 队列（per-flow） ============ */
struct tapac_ack_queue {
    struct tapac_ack_node *head;
    struct tapac_ack_node *tail;
    u16 depth;
    u8  bucket_idx;
    u8  scheduled;
};

/* ============ ACK Bucket（全局调度） ============ */
struct tapac_ack_bucket {
    struct tapac_ack_node *head;
    struct tapac_ack_node *tail;
};

/* ============ 默认参数 ============ */
struct tapac_params {
    u32 debug;
    char nic[32];
    u32 mss;
    u32 min_win;
    u32 timer_interval_us;
    u32 min_rtt;
    u32 max_rtt;
    u32 max_delay;
    u32 bucket_size;
    u32 min_pkt_len;
    u32 throughput_smooth;
    u32 rtt_smooth;
    u32 alpha;
    u16 reduction_thresh;
    u64 prio_thresh;
    u64 ss_thresh;
    u32 ack_delay_ms;
    u32 win_inflate_factor;
    u32 ack_every_n_packets;
    u32 upload_accel_thresh;
    u32 use_ack_scheduler;
    u32 generate_sack;
    u32 separate_buckets;
    u32 upload_bucket_size;
};

/* ============ 流信息 ============ */
struct tapac_flow_info {
    u32 srtt;
    u32 last_update;
    u8  phase;
    u8  direction;
    u16 flags;
    u8  dup_ack_count;
    u8  sack_permitted;
    u8  ts_enabled;
    u8  _pad;
    u16 throughput_reduction_num;
    u32 last_throughput;
    u64 bytes_sent_total;
    u32 bytes_sent_latest;
    u32 last_ack_seq;
    u32 last_data_seq;
    u16 default_win;
    u16 queued_acks;
    struct tapac_ack_queue ackq;
    struct tapac_win_info win;
    struct tapac_upload_accel upload;
    struct tapac_rtt_info rtt;
    struct tapac_download_bucket dl_bucket;
    u32 rcv_nxt;
    struct tapac_sack_info rcv_sack;
    /* 用于发送 ACK 的信息 */
    u32 my_seq;              /* 我方当前 SEQ */
    u32 peer_tsval;          /* 对端最新 TSval */
};

/* ============ 流结构 ============ */
struct tapac_flow {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;
    struct tapac_flow_info info;
    struct list_head list;
};

/* ============ 流表 ============ */
struct tapac_flow_table {
    struct list_head buckets[FLOW_TABLE_SIZE];
    u32 count;
    spinlock_t lock;
};

/* ============ 包节点 ============ */
struct tapac_pkt_node {
    struct sk_buff *skb;
    tapac_okfn_t okfn;
    u32 trigger;
    u32 enqueue_time;
};

/* ============ 包队列 ============ */
struct tapac_pkt_queue {
    struct tapac_pkt_node *ring;
    u32 head;
    u32 tail;
    u32 size;
    u32 capacity;
    spinlock_t lock;
};

/* ============ 统计信息 ============ */
struct tapac_stats {
    u64 ack_merged;
    u64 ack_created;
    u64 ack_sent;
    u64 ack_queue_full;
    u64 ack_compressed;
    u64 ack_scheduled;
    u64 ack_real_sent;       /* 真正发送的 ACK */
    u64 loss_detected;
    u64 fast_retransmit;
    u64 fast_path_hits;
    u64 flows_created;
    u64 flows_destroyed;
    u64 pkts_rx;
    u64 pkts_tx;
    u64 pkts_queued;
    u64 pkts_dropped;
    u64 bytes_rx;
    u64 bytes_tx;
    u64 win_inflated;
    u64 ack_accelerated;
    u64 sack_generated;
    u64 sack_parsed;
    u64 upload_bytes_accel;
    u64 rtt_samples;
    u64 ooo_packets;
};

/* ============ 全局引擎 ============ */
struct tapac_engine {
    struct tapac_params params;
    struct tapac_flow_table ft;

    /* ACK 调度器（参考 tcp_accel_engine.c） */
    struct tapac_ack_bucket ack_buckets[ACK_BUCKETS];
    u8  ack_cursor;
    u16 ack_scheduled_flows;
    spinlock_t ack_lock;

    /* 下载令牌桶（全局） */
    u64 dl_tokens;
    spinlock_t dl_token_lock;

    /* 上传令牌桶（全局） */
    u64 ul_tokens;
    spinlock_t ul_token_lock;

    /* 兼容旧接口 */
    u64 tokens;
    spinlock_t token_lock;

    struct tapac_pkt_queue *q_high;
    struct tapac_pkt_queue *q_low;

    u64 traffic;
    u64 ecn_traffic;
    u64 total_rtt;
    u32 samples;
    u32 avg_rtt;
    u32 avg_throughput;
    u32 last_global_update;
    spinlock_t global_lock;

    struct tapac_stats stats;
    struct hrtimer timer;
    bool running;

    /* 用于发送 ACK */
    struct net_device *ndev;
};

/* ============ 日志宏 ============ */
#define TAPAC_LOG(eng, fmt, ...) do { \
    if ((eng)->params.debug) \
        printk(KERN_DEBUG "TAPAC: " fmt, ##__VA_ARGS__); \
} while(0)

#define TAPAC_INFO(fmt, ...) \
    printk(KERN_INFO "TAPAC: " fmt, ##__VA_ARGS__)

#define TAPAC_ERR(fmt, ...) \
    printk(KERN_ERR "TAPAC: " fmt, ##__VA_ARGS__)

/* ============ 序号比较 ============ */
static inline bool tapac_seq_lt(u32 a, u32 b)
{
    return (s32)(a - b) < 0;
}

static inline bool tapac_seq_leq(u32 a, u32 b)
{
    return (s32)(a - b) <= 0;
}

static inline bool tapac_seq_gt(u32 a, u32 b)
{
    return (s32)(a - b) > 0;
}

static inline bool tapac_seq_geq(u32 a, u32 b)
{
    return (s32)(a - b) >= 0;
}

static inline u32 tapac_seq_diff(u32 a, u32 b)
{
    s32 diff = (s32)(a - b);
    return diff > 0 ? diff : 0;
}

/* ============ 函数声明 ============ */
/* 流表 */
int tapac_flow_cleanup_timeout(struct tapac_flow_table *ft, u32 timeout_us);

/* ACK 优化函数 */
int tapac_parse_sack(struct tcphdr *th, u32 tcp_hdr_len, struct tapac_sack_info *sack);
void tapac_detect_loss(struct tapac_engine *eng, struct tapac_flow_info *info, u32 ack_seq, struct tapac_sack_info *sack);
void tapac_check_fast_path(struct tapac_engine *eng, struct tapac_flow_info *info);
bool tapac_should_compress_ack(struct tapac_engine *eng, struct tapac_flow_info *info, u32 ack_seq, u32 payload_len);
u32 tapac_calc_optimized_trigger(struct tapac_engine *eng, struct tapac_flow_info *info, u32 ack_delta, u32 payload_len, struct tapac_sack_info *sack);
u32 tapac_calc_ack_delay(struct tapac_engine *eng, struct tapac_flow_info *info);
void tapac_dynamic_tuning(struct tapac_engine *eng);

/* 上传加速函数 */
void tapac_parse_win_scale(struct tcphdr *th, u32 tcp_hdr_len, struct tapac_win_info *win);
u16 tapac_inflate_window(struct tapac_engine *eng, struct tapac_flow_info *info, u16 orig_win);
void tapac_modify_ack_window(struct sk_buff *skb, struct tapac_engine *eng, struct tapac_flow *flow);
bool tapac_should_accelerate_ack(struct tapac_engine *eng, struct tapac_flow_info *info);
void tapac_update_upload_stats(struct tapac_flow_info *info, u32 payload_len, u32 seq);
int tapac_process_upload_data(struct tapac_engine *eng, struct sk_buff *skb, struct tapac_flow *flow);
int tapac_process_upload_ack(struct tapac_engine *eng, struct sk_buff *skb, struct tapac_flow *flow);

/* RTT 测量函数 */
u32 tapac_measure_rtt_v2(struct sk_buff *skb, struct tapac_flow *flow, struct tapac_engine *eng);
void tapac_update_rtt_stats(struct tapac_flow_info *info, u32 rtt);
void tapac_record_tsval(struct tapac_flow_info *info, u32 tsval);

/* ACK 调度器函数（重新设计） */
void tapac_ack_init(struct tapac_engine *eng);
void tapac_ack_cleanup(struct tapac_engine *eng);
int tapac_ack_queue(struct tapac_engine *eng, struct tapac_flow *flow, u32 ack_seq, u16 ack_win);
void tapac_ack_schedule(struct tapac_engine *eng);
void tapac_ack_flush_flow(struct tapac_engine *eng, struct tapac_flow *flow);
int tapac_build_and_send_ack(struct tapac_engine *eng, struct tapac_flow *flow,
                              u32 ack_seq, u16 win, u32 tsval, u32 tsecr);

/* SACK 生成函数 */
int tapac_generate_sack(struct tapac_flow_info *info, u8 *opt_buf, int max_len);
void tapac_update_sack_blocks(struct tapac_flow_info *info, u32 seq, u32 len);

#endif /* TAPAC_H */