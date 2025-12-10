/*
 * APX 加速器 v6.0 - 核心头文件
 * 完整的LotServer功能实现
 */

#ifndef _APX_CORE_H
#define _APX_CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rhashtable.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/dst.h>
#include <asm/unaligned.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/percpu.h>
#include <linux/jiffies.h>

/* =========================================================================
 * 配置和宏定义
 * ========================================================================= */

#define APX_MAGIC_MARK 0x41505801
#define PACING_INTERVAL_NS 500000
#define MAX_QUEUE_LEN 1000
#define MIN_MSS 536
#define MAX_MSS 1460
#define DEFAULT_MSS 1460
#define MAX_TX_BATCH 32
#define RTT_HISTORY_SIZE 32
#define ACK_TRAIN_SIZE 16

/* 队列优先级 */
#define APX_QUEUE_CONTROL     0  /* 控制包:  SYN/FIN/RST */
#define APX_QUEUE_INTERACTIVE 1  /* 交互包: 小ACK，小数据 */
#define APX_QUEUE_BULK        2  /* 批量包: 大数据 */
#define APX_NUM_QUEUES        3

/* =========================================================================
 * 数据结构定义
 * ========================================================================= */

/* 全局配置结构体 */
struct apx_configuration {
    u32 initial_cwnd_scale;
    u32 max_cwnd;
    u64 pacing_rate;
    u32 rtt_scale;
    u8  turbo_mode;
    u8  wan_enforce;
    u32 max_flows;
    u32 flow_timeout;
    bool enabled;
    bool dynamic_bw;        /* 动态带宽探测 */
    bool smart_retrans;     /* 智能重传 */
    bool multi_queue;       /* 多队列QoS */
};

/* 流标识键结构 */
struct apx_flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

/* 带宽探测器 */
struct apx_bandwidth_estimator {
    u64 last_ack_time;
    u32 last_ack_seq;
    u64 ack_train[ACK_TRAIN_SIZE];
    u32 ack_seq[ACK_TRAIN_SIZE];
    u8  ack_index;
    u64 estimated_bw;
    u64 smooth_bw;
    u64 max_bw_sample;
    u32 bw_samples;
    u64 prev_delivered;
    u64 prev_ack_time;
    bool is_app_limited;
};

/* RTT趋势分析器 */
struct apx_rtt_analyzer {
    u32 history[RTT_HISTORY_SIZE];
    u8  history_index;
    u8  history_count;
    u32 base_rtt;          /* 基线RTT（物理延迟） */
    u32 current_rtt;        /* 当前RTT（包含排队） */
    u32 min_rtt;           /* 最小观测RTT */
    u32 trend;             /* 0=稳定, 1=上升, 2=下降 */
    u32 jitter;            /* 抖动程度 */
    u32 spike_count;       /* 尖峰计数 */
    s32 queue_delay;       /* 排队延迟 */
    bool congestion_detected;
    u32 cwnd_gain;         /* 动态窗口增益 */
};

/* 重传控制器 */
struct apx_retrans_controller {
    struct sk_buff_head inflight_queue;  /* 在途包队列 */
    u32 last_sent_seq;
    u64 last_sent_time;
    u32 unacked_packets[16];
    u64 send_times[16];
    u8  packet_index;
    u8  dup_ack_count;
    u32 last_ack;
    bool fast_retrans_armed;
    u32 retrans_count;
    u32 early_retrans_count;
};

/* 多优先级队列 */
struct apx_priority_queues {
    struct sk_buff_head queues[APX_NUM_QUEUES];
    atomic_t queue_lens[APX_NUM_QUEUES];
    u32 weights[APX_NUM_QUEUES];
    u32 credits[APX_NUM_QUEUES];
};

/* 数据包元数据 */
struct apx_packet_meta {
    u32 seq;
    u64 tx_time;
    bool is_sacked;
    bool is_retrans;
    u8 retrans_count;
};

/* 延迟传输工作结构 */
struct apx_tx_work {
    struct work_struct work;
    struct sk_buff_head skb_list;
    struct apx_flow_context *ctx;
};

/* 流上下文主结构 - 完整版 */
struct apx_flow_context {
    /* 基础字段 */
    struct rhash_head node;
    struct apx_flow_key key;
    struct rcu_head rcu;
    spinlock_t lock;
    atomic_t refcount;

    /* 状态管理 */
    enum {
        APX_STATE_SYN,
        APX_STATE_ESTABLISHED,
        APX_STATE_FIN_WAIT,
        APX_STATE_CLOSED
    } state;

    unsigned long last_activity;

    /* TCP选项 */
    u16 mss;
    u8  snd_wscale;
    u8  rcv_wscale;
    bool wscale_ok;
    bool timestamps_ok;

    /* 拥塞控制 */
    u32 cwnd;
    u32 ssthresh;
    u32 in_flight;
    u32 bytes_acked;

    /* 高级功能模块 */
    struct apx_bandwidth_estimator bw_estimator;
    struct apx_rtt_analyzer rtt_analyzer;
    struct apx_retrans_controller retrans_ctrl;
    struct apx_priority_queues priority_queues;

    /* 动态速率控制 */
    u64 dynamic_pacing_rate;
    s64 token_bucket;
    s64 max_tokens;
    ktime_t last_refill;

    /* 统计信息 */
    u64 bytes_sent;
    u64 bytes_received;
    u32 packets_sent;
    u32 packets_received;
    u32 packets_dropped;
    u32 packets_retransmitted;

    /* 流控制 */
    u32 fake_rcv_wnd;
    u32 last_ack;
    u32 last_seq;

    /* 延迟工作 */
    struct apx_tx_work tx_work;
    bool tx_scheduled;
};

/* 全局变量声明 */
extern struct apx_configuration g_cfg;
extern struct rhashtable apx_flow_table;
extern struct hrtimer apx_pacing_timer;
extern atomic_t apx_flow_count;
extern struct workqueue_struct *apx_wq;

/* 日志宏 */
#define APX_LOG(fmt, ...) printk(KERN_INFO "APX: " fmt, ##__VA_ARGS__)
#define APX_ERR(fmt, ...) printk(KERN_ERR "APX: 错误: " fmt, ##__VA_ARGS__)
#define APX_DBG(fmt, ...) pr_debug("APX: " fmt, ##__VA_ARGS__)

/* =========================================================================
 * 函数声明
 * ========================================================================= */

/* 流管理函数 */
void apx_flow_get(struct apx_flow_context *ctx);
void apx_flow_put(struct apx_flow_context *ctx);
struct apx_flow_context *apx_find_flow(const struct apx_flow_key *key);
struct apx_flow_context *apx_create_flow(const struct apx_flow_key *key);
void apx_destroy_flow(struct apx_flow_context *ctx);

/* 带宽探测函数 */
void apx_update_bandwidth_estimate(struct apx_flow_context *ctx, u32 ack_seq);
u64 apx_calculate_bdp(struct apx_flow_context *ctx);
void apx_adjust_window_by_bandwidth(struct apx_flow_context *ctx);

/* RTT分析函数 */
void apx_analyze_rtt_trend(struct apx_flow_context *ctx, u32 new_rtt);
void apx_adjust_gain_by_congestion(struct apx_flow_context *ctx);
void apx_update_rtt(struct apx_flow_context *ctx, u32 measured_rtt);

/* 重传控制函数 */
void apx_track_packet(struct apx_flow_context *ctx, struct sk_buff *skb);
void apx_check_early_retransmit(struct apx_flow_context *ctx);
void apx_trigger_fast_retransmit(struct apx_flow_context *ctx, struct sk_buff *orig_skb);
void apx_handle_dup_ack(struct apx_flow_context *ctx, u32 ack_seq);
void apx_cleanup_acked_packets(struct apx_flow_context *ctx, u32 ack_seq);

/* 队列管理函数 */
int apx_enqueue_priority(struct apx_flow_context *ctx, struct sk_buff *skb);
struct sk_buff *apx_dequeue_priority(struct apx_flow_context *ctx);
void apx_init_priority_queues(struct apx_flow_context *ctx);
void apx_destroy_priority_queues(struct apx_flow_context *ctx);

#endif /* _APX_CORE_H */