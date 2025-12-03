/*
 * tapac_standalone.c - TCP Acceleration PAC v4.0
 *
 * 独立的内核 TCP 加速模块，包含：
 *   - 双向流分离 + 动态窗口放大
 *   - ACK 调度器（bucket 轮询 + age 判定 + 合并）
 *   - SACK 解析、维护、生成、注入
 *   - RTT 测量 + 速率控制
 *   - 令牌桶流量控制 + Pacing
 *   - 快速校验和修正
 *
 * 参考：appex/LotServer ACK 调度思想
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TAPAC Project");
MODULE_VERSION("4.0");
MODULE_DESCRIPTION("TCP Acceleration PAC - Standalone Edition");

/* ============================================================
 * 版本兼容宏
 * ============================================================ */

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

/* ============================================================
 * 常量定义
 * ============================================================ */

/* 时间工具 */
#define TAPAC_TIME_SHIFT        10
#define US_TO_NS(x)             ((x) * 1000ULL)
#define MS_TO_NS(x)             ((x) * 1000000ULL)
#define MS_TO_US(x)             ((x) * 1000U)

/* 流方向 */
#define FLOW_DIR_SERVER         0
#define FLOW_DIR_CLIENT         1

/* TCP 阶段 */
#define PHASE_SLOW_START        0
#define PHASE_CONG_AVOID        1
#define PHASE_FAST_RECOVERY     2

/* 流标志 */
#define FLOW_FLAG_FAST_PATH         (1 << 0)
#define FLOW_FLAG_HAS_SACK          (1 << 1)
#define FLOW_FLAG_LOSS_DETECTED     (1 << 2)
#define FLOW_FLAG_WIN_SCALED        (1 << 3)
#define FLOW_FLAG_UPLOAD_ACCEL      (1 << 4)
#define FLOW_FLAG_SACK_PERMITTED    (1 << 5)
#define FLOW_FLAG_TS_ENABLED        (1 << 6)
#define FLOW_FLAG_BIDIR_INIT        (1 << 7)
#define FLOW_FLAG_ACK_PENDING       (1 << 8)

/* ACK 调度器参数 */
#define ACK_BUCKETS                 32
#define ACK_MAX_QUEUE_DEPTH         64
#define ACK_MAX_DELTA_BYTES         0x15B4
#define ACK_DELAY_DEFAULT_MS        20
#define ACK_DELAY_MIN_MS            2
#define ACK_DELAY_MAX_MS            50

/* SACK 参数 */
#define MAX_SACK_BLOCKS             4
#define SACK_INJECT_MIN_BLOCKS      1
#define SACK_INDEPENDENT_ACK_GAP    10000   /* 10ms */

/* 窗口控制参数 */
#define WIN_SCALE_MAX               14
#define WIN_INFLATE_MIN             1
#define WIN_INFLATE_MAX             16

/* 流表参数 */
#define FLOW_TABLE_BITS             8
#define FLOW_TABLE_SIZE             (1 << FLOW_TABLE_BITS)
#define FLOW_MAX_COUNT              10240
#define FLOW_TIMEOUT_US             60000000

/* 包队列参数 */
#define PKT_QUEUE_SIZE              131072

/* RTT 历史 */
#define RTT_HISTORY_SIZE            8

/* 速率控制 */
#define RATE_MIN_BPS                96000
#define RATE_MAX_BPS                10000000000ULL
#define RATE_INCREASE_FACTOR        1077
#define RATE_DECREASE_FACTOR        888
#define RATE_MILD_DECREASE          966

/* Pacing */
#define PACING_MIN_INTERVAL_NS      50000
#define PACING_MAX_INTERVAL_NS      10000000

/* ============================================================
 * 时间工具函数
 * ============================================================ */

static inline u32 tapac_get_time_us(void)
{
    return (u32)(ktime_to_ns(ktime_get()) >> TAPAC_TIME_SHIFT);
}

static inline u32 tapac_get_time_ms(void)
{
    return tapac_get_time_us() / 1000;
}

/* ============================================================
 * 序号比较工具（处理回绕）
 * ============================================================ */

static inline bool tapac_seq_lt(u32 a, u32 b)  { return (s32)(a - b) < 0; }
static inline bool tapac_seq_leq(u32 a, u32 b) { return (s32)(a - b) <= 0; }
static inline bool tapac_seq_gt(u32 a, u32 b)  { return (s32)(a - b) > 0; }
static inline bool tapac_seq_geq(u32 a, u32 b) { return (s32)(a - b) >= 0; }

static inline u32 tapac_seq_diff(u32 a, u32 b)
{
    s32 diff = (s32)(a - b);
    return diff > 0 ? diff : 0;
}

/* ============================================================
 * 数据结构定义
 * ============================================================ */

/* SACK 块 */
struct tapac_sack_block {
    u32 start;
    u32 end;
};

struct tapac_sack_info {
    u8 num_blocks;
    struct tapac_sack_block blocks[MAX_SACK_BLOCKS];
};

/* 窗口信息 */
struct tapac_win_info {
    u8  snd_wscale;
    u8  rcv_wscale;
    u16 advertised_win;
    u32 max_win;
    u32 last_win_update;
};

/* RTT 信息 */
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

/* 双向流状态 */
struct tapac_bidir_state {
    /* 下载方向（服务端→客户端） */
    u32 dl_last_ack_seq;
    u32 dl_last_data_seq;
    u32 dl_inflight;
    u32 dl_bytes_sent;
    u32 dl_bytes_acked;
    u8  dl_dup_ack_count;
    u8  dl_loss_detected;
    u8  dl_phase;
    u8  dl_reserved;

    /* 上传方向（客户端→服务端） */
    u32 ul_last_ack_seq;
    u32 ul_last_data_seq;
    u32 ul_rcv_nxt;
    u32 ul_bytes_received;
    u32 ul_bytes_acked;
    u32 ul_last_ack_time;
    u8  ul_ooo_count;
    u8  ul_need_ack;
    u8  ul_pending_acks;
    u8  ul_reserved;

    /* 动态窗口控制 */
    u32 current_win_factor;     /* x1000 */
    u32 target_win_factor;
    u32 win_adjust_time;
    u32 consecutive_loss;
    u32 consecutive_good;
};

/* 前向声明 */
struct tapac_flow;
struct tapac_engine;

/* ACK 节点 */
struct tapac_ack_node {
    struct tapac_ack_node *flow_prev;
    struct tapac_ack_node *flow_next;
    struct tapac_ack_node *sched_prev;
    struct tapac_ack_node *sched_next;

    struct tapac_flow *flow;

    u32 ack_seq;
    u32 my_seq;
    u16 ack_win;
    u16 age_ticks;
    u32 last_ts_ms;
    u16 last_ack_delta;

    u32 tsval;
    u32 tsecr;
};

/* ACK 队列（per-flow） */
struct tapac_ack_queue {
    struct tapac_ack_node *head;
    struct tapac_ack_node *tail;
    u16 depth;
    u8  bucket_idx;
    u8  scheduled;
};

/* ACK Bucket（全局） */
struct tapac_ack_bucket {
    struct tapac_ack_node *head;
    struct tapac_ack_node *tail;
};

/* 流信息 */
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
    u32 my_seq;
    u32 peer_tsval;
    u32 rcv_nxt;

    u16 default_win;
    u16 queued_acks;

    struct tapac_ack_queue ackq;
    struct tapac_win_info win;
    struct tapac_rtt_info rtt;
    struct tapac_sack_info rcv_sack;
    struct tapac_bidir_state bidir;
};

/* 流结构 */
struct tapac_flow {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;
    struct tapac_flow_info info;
    struct list_head list;
};

/* 流表 */
struct tapac_flow_table {
    struct list_head buckets[FLOW_TABLE_SIZE];
    u32 count;
    spinlock_t lock;
};

/* 包节点 */
struct tapac_pkt_node {
    struct sk_buff *skb;
    tapac_okfn_t okfn;
    u32 trigger;
    u32 enqueue_time;
};

/* 包队列 */
struct tapac_pkt_queue {
    struct tapac_pkt_node *ring;
    u32 head;
    u32 tail;
    u32 size;
    u32 capacity;
    spinlock_t lock;
};

/* 网络状态枚举 */
enum tapac_net_state {
    NET_STATE_UNKNOWN = 0,
    NET_STATE_HEALTHY,
    NET_STATE_CONGESTED,
    NET_STATE_SEVERE_CONGESTION,
    NET_STATE_LOSS_DETECTED,
};

/* 速率控制 */
struct tapac_rate_control {
    u64 current_rate;
    u64 target_rate;
    u64 min_rate;
    u64 max_rate;

    u32 cwnd;
    u32 ssthresh;

    u32 base_rtt;
    u32 last_rtt;
    s32 rtt_trend;

    u32 loss_count;
    u32 total_packets;
    u32 loss_rate;

    u32 last_update;
    enum tapac_net_state state;
    u8 in_slow_start;

    u64 pacing_rate;
    u64 next_send_ns;
    u32 pacing_gain;

    spinlock_t lock;
};

/* 统计信息 */
struct tapac_stats {
    u64 ack_merged;
    u64 ack_created;
    u64 ack_sent;
    u64 ack_queue_full;
    u64 ack_scheduled;
    u64 ack_real_sent;
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
    u64 dl_acks_processed;
    u64 ul_data_processed;
    u64 win_factor_reduced;
    u64 win_factor_increased;
};

/* 参数 */
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
    u32 upload_accel_thresh;
    u32 use_ack_scheduler;
    u32 generate_sack;
    u32 win_inflate_factor;
    u32 ack_delay_ms;
};

/* 全局引擎 */
struct tapac_engine {
    struct tapac_params params;
    struct tapac_flow_table ft;

    /* ACK 调度器 */
    struct tapac_ack_bucket ack_buckets[ACK_BUCKETS];
    u8  ack_cursor;
    u16 ack_scheduled_flows;
    spinlock_t ack_lock;

    /* 令牌桶 */
    u64 dl_tokens;
    spinlock_t dl_token_lock;
    u64 ul_tokens;
    spinlock_t ul_token_lock;

    /* 包队列 */
    struct tapac_pkt_queue *q_high;
    struct tapac_pkt_queue *q_low;

    /* 全局统计 */
    u64 traffic;
    u64 total_rtt;
    u32 samples;
    u32 avg_rtt;
    u32 avg_throughput;
    u32 last_global_update;
    spinlock_t global_lock;

    struct tapac_stats stats;
    struct tapac_rate_control rate;
    struct hrtimer timer;
    bool running;

    struct net_device *ndev;
};

/* ============================================================
 * 全局变量
 * ============================================================ */

static struct tapac_engine *g_engine = NULL;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;
static struct tasklet_struct dequeue_tasklet;
static struct proc_dir_entry *proc_dir = NULL;

static char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Network interface");
module_param(param_dev, charp, 0);

/* ============================================================
 * 日志宏
 * ============================================================ */

#define TAPAC_LOG(eng, fmt, ...) do { \
    if ((eng)->params.debug) \
        printk(KERN_DEBUG "TAPAC: " fmt, ##__VA_ARGS__); \
} while(0)

#define TAPAC_INFO(fmt, ...) \
    printk(KERN_INFO "TAPAC: " fmt, ##__VA_ARGS__)

#define TAPAC_ERR(fmt, ...) \
    printk(KERN_ERR "TAPAC: " fmt, ##__VA_ARGS__)

/* ============================================================
 * 校验和计算
 * ============================================================ */

static inline __sum16 tapac_fold_u32(u32 sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (__sum16)(~sum);
}

static u32 tapac_sum_16(const u8 *p, size_t len)
{
    u32 sum = 0;
    while (len > 1) {
        sum += ((u32)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (u32)p[0] << 8;
    return sum;
}

static __sum16 tapac_ip4_checksum(const struct iphdr *iph)
{
    u32 sum = tapac_sum_16((const u8 *)iph, iph->ihl * 4);
    return tapac_fold_u32(sum);
}

static __sum16 tapac_l4_checksum(const struct iphdr *iph, const void *l4,
                                  size_t len, u8 proto)
{
    u32 sum = 0;
    sum += ntohs((__force __be16)(iph->saddr >> 16));
    sum += ntohs((__force __be16)(iph->saddr & 0xFFFF));
    sum += ntohs((__force __be16)(iph->daddr >> 16));
    sum += ntohs((__force __be16)(iph->daddr & 0xFFFF));
    sum += proto;
    sum += len;
    sum += tapac_sum_16(l4, len);
    return tapac_fold_u32(sum);
}

static void tapac_fix_checksums(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *th;
    int tcplen;

    if (!skb || !pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return;

    if (! pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

    iph->check = 0;
    iph->check = tapac_ip4_checksum(iph);

    th->check = 0;
    th->check = tapac_l4_checksum(iph, th, tcplen, IPPROTO_TCP);

    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* ============================================================
 * 包队列管理
 * ============================================================ */

static struct tapac_pkt_queue *tapac_queue_alloc(u32 capacity)
{
    struct tapac_pkt_queue *q;

    q = kzalloc(sizeof(*q), GFP_KERNEL);
    if (!q)
        return NULL;

    q->ring = vzalloc(capacity * sizeof(struct tapac_pkt_node));
    if (!q->ring) {
        kfree(q);
        return NULL;
    }

    q->capacity = capacity;
    spin_lock_init(&q->lock);
    return q;
}

static void tapac_queue_free(struct tapac_pkt_queue *q)
{
    if (! q)
        return;
    if (q->ring)
        vfree(q->ring);
    kfree(q);
}

static int tapac_queue_enqueue(struct tapac_pkt_queue *q, struct sk_buff *skb,
                                tapac_okfn_t okfn, u32 trigger, u32 enqueue_time)
{
    unsigned long flags;

    if (!q || !q->ring || ! skb)
        return 0;

    spin_lock_irqsave(&q->lock, flags);

    if (q->size >= q->capacity) {
        spin_unlock_irqrestore(&q->lock, flags);
        return 0;
    }

    q->ring[q->tail].skb = skb;
    q->ring[q->tail].okfn = okfn;
    q->ring[q->tail].trigger = trigger;
    q->ring[q->tail].enqueue_time = enqueue_time;

    q->tail = (q->tail + 1) % q->capacity;
    q->size++;

    spin_unlock_irqrestore(&q->lock, flags);
    return 1;
}

static int tapac_queue_dequeue(struct tapac_pkt_queue *q)
{
    struct tapac_pkt_node *pkt;
    struct sk_buff *skb;
    tapac_okfn_t okfn;
    unsigned long flags;

    if (!q || !q->ring)
        return 0;

    spin_lock_irqsave(&q->lock, flags);

    if (q->size == 0) {
        spin_unlock_irqrestore(&q->lock, flags);
        return 0;
    }

    pkt = &q->ring[q->head];
    skb = pkt->skb;
    okfn = pkt->okfn;

    pkt->skb = NULL;
    pkt->okfn = NULL;

    q->head = (q->head + 1) % q->capacity;
    q->size--;

    spin_unlock_irqrestore(&q->lock, flags);

    if (okfn && skb) {
#if defined(TAPAC_OKFN_NEW_API)
        okfn(&init_net, NULL, skb);
#else
        okfn(skb);
#endif
    }

    return 1;
}

static struct tapac_pkt_node *tapac_queue_peek(struct tapac_pkt_queue *q)
{
    if (!q || !q->ring || q->size == 0)
        return NULL;
    return &q->ring[q->head];
}

static u32 tapac_queue_size(struct tapac_pkt_queue *q)
{
    return q ?  q->size : 0;
}

/* ============================================================
 * 流表管理
 * ============================================================ */

static inline u32 tapac_flow_hash(__be32 saddr, __be32 daddr,
                                   __be16 sport, __be16 dport)
{
    u32 a = (__force u32)saddr ^ (__force u32)daddr;
    u32 b = ((__force u32)sport << 16) | (__force u32)dport;
    return jhash_2words(a, b, 0) & (FLOW_TABLE_SIZE - 1);
}

static void tapac_flow_table_init(struct tapac_flow_table *ft)
{
    int i;
    for (i = 0; i < FLOW_TABLE_SIZE; i++)
        INIT_LIST_HEAD(&ft->buckets[i]);
    ft->count = 0;
    spin_lock_init(&ft->lock);
}

static void tapac_flow_table_cleanup(struct tapac_flow_table *ft)
{
    struct tapac_flow *flow, *tmp;
    unsigned long flags;
    int i;

    spin_lock_irqsave(&ft->lock, flags);

    for (i = 0; i < FLOW_TABLE_SIZE; i++) {
        list_for_each_entry_safe(flow, tmp, &ft->buckets[i], list) {
            list_del(&flow->list);
            kfree(flow);
        }
        INIT_LIST_HEAD(&ft->buckets[i]);
    }
    ft->count = 0;

    spin_unlock_irqrestore(&ft->lock, flags);
}

static struct tapac_flow *tapac_flow_lookup(struct tapac_flow_table *ft,
                                             __be32 saddr, __be32 daddr,
                                             __be16 sport, __be16 dport)
{
    struct tapac_flow *flow;
    u32 hash = tapac_flow_hash(saddr, daddr, sport, dport);

    list_for_each_entry(flow, &ft->buckets[hash], list) {
        if (flow->local_ip == saddr && flow->remote_ip == daddr &&
            flow->local_port == sport && flow->remote_port == dport)
            return flow;
    }
    return NULL;
}

static void tapac_bidir_init(struct tapac_flow_info *info);

static struct tapac_flow *tapac_flow_create(struct tapac_flow_table *ft,
                                             __be32 saddr, __be32 daddr,
                                             __be16 sport, __be16 dport,
                                             u8 direction, u32 min_rtt)
{
    struct tapac_flow *flow;
    u32 hash;
    unsigned long flags;

    spin_lock_irqsave(&ft->lock, flags);

    flow = tapac_flow_lookup(ft, saddr, daddr, sport, dport);
    if (flow) {
        spin_unlock_irqrestore(&ft->lock, flags);
        return flow;
    }

    if (ft->count >= FLOW_MAX_COUNT) {
        spin_unlock_irqrestore(&ft->lock, flags);
        return NULL;
    }

    flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
    if (! flow) {
        spin_unlock_irqrestore(&ft->lock, flags);
        return NULL;
    }

    flow->local_ip = saddr;
    flow->remote_ip = daddr;
    flow->local_port = sport;
    flow->remote_port = dport;

    flow->info.direction = direction;
    flow->info.phase = PHASE_SLOW_START;
    flow->info.srtt = min_rtt;
    flow->info.last_update = tapac_get_time_us();
    flow->info.default_win = 65535;

    flow->info.ackq.bucket_idx = ((__force u16)sport ^ (__force u16)dport) & (ACK_BUCKETS - 1);

    tapac_bidir_init(&flow->info);

    hash = tapac_flow_hash(saddr, daddr, sport, dport);
    list_add(&flow->list, &ft->buckets[hash]);
    ft->count++;

    spin_unlock_irqrestore(&ft->lock, flags);
    return flow;
}

static void tapac_flow_delete(struct tapac_flow_table *ft,
                               __be32 saddr, __be32 daddr,
                               __be16 sport, __be16 dport)
{
    struct tapac_flow *flow;
    unsigned long flags;
    u32 hash = tapac_flow_hash(saddr, daddr, sport, dport);

    spin_lock_irqsave(&ft->lock, flags);

    list_for_each_entry(flow, &ft->buckets[hash], list) {
        if (flow->local_ip == saddr && flow->remote_ip == daddr &&
            flow->local_port == sport && flow->remote_port == dport) {
            list_del(&flow->list);
            if (ft->count > 0)
                ft->count--;
            kfree(flow);
            break;
        }
    }

    spin_unlock_irqrestore(&ft->lock, flags);
}

static int tapac_flow_cleanup_timeout(struct tapac_flow_table *ft, u32 timeout_us)
{
    struct tapac_flow *flow, *tmp;
    unsigned long flags;
    u32 now = tapac_get_time_us();
    int cleaned = 0;
    int i;

    spin_lock_irqsave(&ft->lock, flags);

    for (i = 0; i < FLOW_TABLE_SIZE; i++) {
        list_for_each_entry_safe(flow, tmp, &ft->buckets[i], list) {
            if (now - flow->info.last_update > timeout_us) {
                list_del(&flow->list);
                if (ft->count > 0)
                    ft->count--;
                kfree(flow);
                cleaned++;
            }
        }
    }

    spin_unlock_irqrestore(&ft->lock, flags);
    return cleaned;
}

/* ============================================================
 * 双向状态初始化
 * ============================================================ */

static void tapac_bidir_init(struct tapac_flow_info *info)
{
    struct tapac_bidir_state *bidir;

    if (! info)
        return;

    bidir = &info->bidir;
    memset(bidir, 0, sizeof(*bidir));

    bidir->current_win_factor = 2000;  /* 2x */
    bidir->target_win_factor = 2000;
    bidir->win_adjust_time = tapac_get_time_us();

    info->flags |= FLOW_FLAG_BIDIR_INIT;
}

/* ============================================================
 * TCP 选项解析
 * ============================================================ */

static void tapac_parse_tcp_ts(struct tcphdr *th, u32 tcp_hdr_len,
                                u32 *tsval, u32 *tsecr)
{
    u8 *opt, *end;
    u8 kind, len;

    *tsval = 0;
    *tsecr = 0;

    if (tcp_hdr_len <= 20)
        return;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 8 && len == 10) {
            *tsval = ntohl(*(u32 *)(opt + 2));
            *tsecr = ntohl(*(u32 *)(opt + 6));
            return;
        }

        opt += len;
    }
}

static void tapac_parse_win_scale(struct tcphdr *th, u32 tcp_hdr_len,
                                   struct tapac_win_info *win)
{
    u8 *opt, *end;
    u8 kind, len;

    if (! th || !win || tcp_hdr_len <= 20)
        return;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 3 && len == 3) {
            win->rcv_wscale = *(opt + 2);
            if (win->rcv_wscale > WIN_SCALE_MAX)
                win->rcv_wscale = WIN_SCALE_MAX;
            return;
        }

        opt += len;
    }
}

static bool tapac_check_sack_permitted(struct tcphdr *th, u32 tcp_hdr_len)
{
    u8 *opt, *end;
    u8 kind, len;

    if (!th || tcp_hdr_len <= 20)
        return false;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 4 && len == 2)
            return true;

        opt += len;
    }

    return false;
}

/* ============================================================
 * SACK 处理
 * ============================================================ */

static int tapac_parse_sack(struct tcphdr *th, u32 tcp_hdr_len,
                             struct tapac_sack_info *sack)
{
    u8 *opt, *end;
    u8 kind, len;
    int i;

    if (!th || ! sack)
        return 0;

    sack->num_blocks = 0;

    if (tcp_hdr_len <= 20)
        return 0;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 5 && len >= 10) {
            int num_blocks = (len - 2) / 8;
            u8 *block_ptr = opt + 2;

            for (i = 0; i < num_blocks && i < MAX_SACK_BLOCKS; i++) {
                sack->blocks[i].start = ntohl(*(u32 *)block_ptr);
                sack->blocks[i].end = ntohl(*(u32 *)(block_ptr + 4));
                block_ptr += 8;
            }
            sack->num_blocks = i;
            return i;
        }

        opt += len;
    }

    return 0;
}

static void tapac_sack_merge_blocks(struct tapac_sack_info *sack)
{
    int i, j, k;
    bool merged;

    if (!sack || sack->num_blocks <= 1)
        return;

    do {
        merged = false;
        for (i = 0; i < sack->num_blocks && !merged; i++) {
            for (j = i + 1; j < sack->num_blocks; j++) {
                if (sack->blocks[i].end >= sack->blocks[j].start &&
                    sack->blocks[i].start <= sack->blocks[j].end) {
                    if (tapac_seq_lt(sack->blocks[j].start, sack->blocks[i].start))
                        sack->blocks[i].start = sack->blocks[j].start;
                    if (tapac_seq_gt(sack->blocks[j].end, sack->blocks[i].end))
                        sack->blocks[i].end = sack->blocks[j].end;
                    for (k = j; k < sack->num_blocks - 1; k++)
                        sack->blocks[k] = sack->blocks[k + 1];
                    sack->num_blocks--;
                    merged = true;
                    break;
                }
            }
        }
    } while (merged && sack->num_blocks > 1);
}

static void tapac_sack_sort_blocks(struct tapac_sack_info *sack)
{
    int i, j;
    struct tapac_sack_block tmp;

    if (! sack || sack->num_blocks <= 1)
        return;

    for (i = 0; i < sack->num_blocks - 1; i++) {
        for (j = i + 1; j < sack->num_blocks; j++) {
            if (tapac_seq_gt(sack->blocks[i].start, sack->blocks[j].start)) {
                tmp = sack->blocks[i];
                sack->blocks[i] = sack->blocks[j];
                sack->blocks[j] = tmp;
            }
        }
    }
}

static void tapac_update_sack_blocks(struct tapac_flow_info *info, u32 seq, u32 len)
{
    struct tapac_sack_info *sack;
    u32 seq_end;
    int i, j;

    if (!info || len == 0)
        return;

    sack = &info->rcv_sack;
    seq_end = seq + len;

    if (info->rcv_nxt == 0) {
        info->rcv_nxt = seq_end;
        return;
    }

    if (seq == info->rcv_nxt) {
        info->rcv_nxt = seq_end;

        for (i = 0; i < sack->num_blocks; ) {
            if (tapac_seq_leq(sack->blocks[i].start, info->rcv_nxt)) {
                if (tapac_seq_gt(sack->blocks[i].end, info->rcv_nxt))
                    info->rcv_nxt = sack->blocks[i].end;
                for (j = i; j < sack->num_blocks - 1; j++)
                    sack->blocks[j] = sack->blocks[j + 1];
                sack->num_blocks--;
            } else {
                i++;
            }
        }
        return;
    }

    if (tapac_seq_lt(seq, info->rcv_nxt)) {
        if (tapac_seq_leq(seq_end, info->rcv_nxt))
            return;
        seq = info->rcv_nxt;
    }

    for (i = 0; i < sack->num_blocks; i++) {
        if (seq_end == sack->blocks[i].start) {
            sack->blocks[i].start = seq;
            tapac_sack_merge_blocks(sack);
            return;
        }
        if (seq == sack->blocks[i].end) {
            sack->blocks[i].end = seq_end;
            tapac_sack_merge_blocks(sack);
            return;
        }
        if (tapac_seq_geq(seq, sack->blocks[i].start) &&
            tapac_seq_leq(seq_end, sack->blocks[i].end))
            return;
        if (tapac_seq_lt(seq, sack->blocks[i].end) &&
            tapac_seq_gt(seq_end, sack->blocks[i].start)) {
            if (tapac_seq_lt(seq, sack->blocks[i].start))
                sack->blocks[i].start = seq;
            if (tapac_seq_gt(seq_end, sack->blocks[i].end))
                sack->blocks[i].end = seq_end;
            tapac_sack_merge_blocks(sack);
            return;
        }
    }

    if (sack->num_blocks < MAX_SACK_BLOCKS) {
        sack->blocks[sack->num_blocks].start = seq;
        sack->blocks[sack->num_blocks].end = seq_end;
        sack->num_blocks++;
        tapac_sack_sort_blocks(sack);
        tapac_sack_merge_blocks(sack);
    }
}

static int tapac_generate_sack(struct tapac_flow_info *info, u8 *opt_buf, int max_len)
{
    struct tapac_sack_info *sack;
    int i, opt_len, num_blocks;
    u8 *p;

    if (! info || !opt_buf || max_len < 10)
        return 0;

    sack = &info->rcv_sack;

    if (sack->num_blocks == 0)
        return 0;

    num_blocks = (max_len - 2) / 8;
    if (num_blocks > sack->num_blocks)
        num_blocks = sack->num_blocks;
    if (num_blocks > MAX_SACK_BLOCKS)
        num_blocks = MAX_SACK_BLOCKS;
    if (num_blocks == 0)
        return 0;

    opt_len = 2 + 8 * num_blocks;
    p = opt_buf;

    *p++ = 5;       /* kind = SACK */
    *p++ = opt_len;

    for (i = 0; i < num_blocks; i++) {
        *(u32 *)p = htonl(sack->blocks[i].start);
        p += 4;
        *(u32 *)p = htonl(sack->blocks[i].end);
        p += 4;
    }

    return opt_len;
}

static void tapac_sack_clear(struct tapac_flow_info *info)
{
    if (info)
        info->rcv_sack.num_blocks = 0;
}

/* ============================================================
 * ACK 调度器（参考 appex 的 bucket 轮询 + age 判定）
 * ============================================================ */

static struct tapac_ack_node *tapac_alloc_ack_node(struct tapac_engine *eng)
{
    struct tapac_ack_node *n;

    n = kzalloc(sizeof(*n), GFP_ATOMIC);
    if (! n)
        eng->stats.ack_queue_full++;

    return n;
}

static void tapac_free_ack_node(struct tapac_ack_node *n)
{
    kfree(n);
}

static void tapac_bucket_unlink_node(struct tapac_engine *eng,
                                      struct tapac_ack_node *n)
{
    struct tapac_flow *flow = n->flow;
    struct tapac_ack_queue *ackq = &flow->info.ackq;
    struct tapac_ack_bucket *b;
    u8 idx;

    idx = ackq->bucket_idx & (ACK_BUCKETS - 1);
    b = &eng->ack_buckets[idx];

    /* 从 per-flow 链表摘除 */
    if (n->flow_prev)
        n->flow_prev->flow_next = n->flow_next;
    else
        ackq->head = n->flow_next;

    if (n->flow_next)
        n->flow_next->flow_prev = n->flow_prev;
    else
        ackq->tail = n->flow_prev;

    if (ackq->depth > 0)
        ackq->depth--;

    if (flow->info.queued_acks > 0)
        flow->info.queued_acks--;

    /* 从 bucket 链表摘除 */
    if (n->sched_prev)
        n->sched_prev->sched_next = n->sched_next;
    else
        b->head = n->sched_next;

    if (n->sched_next)
        n->sched_next->sched_prev = n->sched_prev;
    else
        b->tail = n->sched_prev;

    if (ackq->depth == 0 && ackq->scheduled) {
        ackq->scheduled = 0;
        if (eng->ack_scheduled_flows > 0)
            eng->ack_scheduled_flows--;
    }

    n->flow_prev = NULL;
    n->flow_next = NULL;
    n->sched_prev = NULL;
    n->sched_next = NULL;
}

static void tapac_ack_init(struct tapac_engine *eng)
{
    int i;

    for (i = 0; i < ACK_BUCKETS; i++) {
        eng->ack_buckets[i].head = NULL;
        eng->ack_buckets[i].tail = NULL;
    }

    eng->ack_cursor = 0;
    eng->ack_scheduled_flows = 0;
    spin_lock_init(&eng->ack_lock);
}

static void tapac_ack_cleanup(struct tapac_engine *eng)
{
    struct tapac_ack_node *n, *next;
    unsigned long flags;
    int i;

    spin_lock_irqsave(&eng->ack_lock, flags);

    for (i = 0; i < ACK_BUCKETS; i++) {
        n = eng->ack_buckets[i].head;
        while (n) {
            next = n->sched_next;
            tapac_free_ack_node(n);
            n = next;
        }
        eng->ack_buckets[i].head = NULL;
        eng->ack_buckets[i].tail = NULL;
    }

    eng->ack_scheduled_flows = 0;

    spin_unlock_irqrestore(&eng->ack_lock, flags);
}

static void tapac_ack_flush_flow(struct tapac_engine *eng, struct tapac_flow *flow)
{
    struct tapac_ack_node *n, *next;
    struct tapac_ack_queue *ackq;
    unsigned long flags;

    if (!eng || !flow)
        return;

    ackq = &flow->info.ackq;

    spin_lock_irqsave(&eng->ack_lock, flags);

    n = ackq->head;
    while (n) {
        next = n->flow_next;
        tapac_bucket_unlink_node(eng, n);
        tapac_free_ack_node(n);
        n = next;
    }

    ackq->head = NULL;
    ackq->tail = NULL;
    ackq->depth = 0;
    ackq->scheduled = 0;
    flow->info.queued_acks = 0;

    spin_unlock_irqrestore(&eng->ack_lock, flags);
}

/* ACK 入队（参考 appex _APX_ESchdQueueAckPacket） */
static int tapac_ack_queue(struct tapac_engine *eng, struct tapac_flow *flow,
                            u32 ack_seq, u16 ack_win, u32 tsval, u32 tsecr)
{
    struct tapac_flow_info *info = &flow->info;
    struct tapac_ack_queue *ackq = &info->ackq;
    struct tapac_ack_node *n;
    struct tapac_ack_bucket *b;
    u32 now_ms;
    s32 delta_bytes;
    unsigned long flags;

    if (!eng->params.use_ack_scheduler)
        return -1;

    now_ms = tapac_get_time_ms();

    spin_lock_irqsave(&eng->ack_lock, flags);

    /* ACK 没有前进，记为合并丢弃 */
    if (tapac_seq_leq(ack_seq, info->last_ack_seq)) {
        eng->stats.ack_merged++;
        spin_unlock_irqrestore(&eng->ack_lock, flags);
        return 0;
    }

    /* 尝试合并到队尾 */
    n = ackq->tail;
    if (n && tapac_seq_geq(ack_seq, n->ack_seq)) {
        n->ack_seq = ack_seq;
        n->ack_win = ack_win ?  ack_win : info->default_win;
        n->tsval = tsval;
        n->tsecr = tsecr;
        n->last_ts_ms = now_ms;

        eng->stats.ack_merged++;
        info->last_ack_seq = ack_seq;

        spin_unlock_irqrestore(&eng->ack_lock, flags);
        return 0;
    }

    /* 队列已满 */
    if (ackq->depth >= ACK_MAX_QUEUE_DEPTH) {
        eng->stats.ack_queue_full++;
        spin_unlock_irqrestore(&eng->ack_lock, flags);
        return -ENOMEM;
    }

    /* 分配新节点 */
    n = tapac_alloc_ack_node(eng);
    if (!n) {
        spin_unlock_irqrestore(&eng->ack_lock, flags);
        return -ENOMEM;
    }

    n->flow = flow;
    n->ack_seq = ack_seq;
    n->my_seq = info->my_seq;
    n->ack_win = ack_win ?  ack_win : info->default_win;
    n->tsval = tsval;
    n->tsecr = tsecr;
    n->last_ts_ms = now_ms;
    n->age_ticks = 0;
    n->last_ack_delta = 0;

    /* 插入 per-flow 链表 */
    n->flow_prev = ackq->tail;
    n->flow_next = NULL;

    if (ackq->tail)
        ackq->tail->flow_next = n;
    else
        ackq->head = n;

    ackq->tail = n;
    ackq->depth++;
    info->queued_acks++;

    /* 插入 bucket */
    b = &eng->ack_buckets[ackq->bucket_idx & (ACK_BUCKETS - 1)];

    n->sched_prev = b->tail;
    n->sched_next = NULL;

    if (b->tail)
        b->tail->sched_next = n;
    else
        b->head = n;

    b->tail = n;

    if (! ackq->scheduled) {
        ackq->scheduled = 1;
        eng->ack_scheduled_flows++;
    }

    /* 记录 delta */
    delta_bytes = (s32)(ack_seq - info->last_ack_seq);
    if (delta_bytes > 0) {
        u16 capped = (delta_bytes > ACK_MAX_DELTA_BYTES) ?
                     ACK_MAX_DELTA_BYTES : (u16)delta_bytes;
        n->last_ack_delta = capped;
        n->age_ticks = capped;
    }

    info->last_ack_seq = ack_seq;
    eng->stats.ack_created++;

    spin_unlock_irqrestore(&eng->ack_lock, flags);
    return 0;
}

/* 发送 ACK（构建并发送 ACK-only 包） */
static int tapac_send_ack_node(struct tapac_engine *eng, struct tapac_ack_node *n)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *th;
    struct net_device *ndev;
    struct rtable *rt;
    struct flowi4 fl4;
    struct tapac_flow *flow;
    int hdr_len;
    int tcp_len;
    u8 *opt;

    if (!eng || !n || !n->flow)
        return -EINVAL;

    flow = n->flow;

    ndev = dev_get_by_name(&init_net, eng->params.nic);
    if (!ndev)
        return -ENODEV;

    tcp_len = 32;  /* 20 + 12 (timestamp) */
    hdr_len = sizeof(struct iphdr) + tcp_len;

    skb = alloc_skb(LL_MAX_HEADER + hdr_len, GFP_ATOMIC);
    if (! skb) {
        dev_put(ndev);
        return -ENOMEM;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_network_header(skb);

    /* IP 头 */
    iph = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(hdr_len);
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = flow->local_ip;
    iph->daddr = flow->remote_ip;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    /* TCP 头 */
    skb_set_transport_header(skb, sizeof(struct iphdr));
    th = (struct tcphdr *)skb_put(skb, tcp_len);
    memset(th, 0, tcp_len);
    th->source = flow->local_port;
    th->dest = flow->remote_port;
    th->seq = htonl(n->my_seq);
    th->ack_seq = htonl(n->ack_seq);
    th->doff = tcp_len / 4;
    th->ack = 1;
    th->window = htons(n->ack_win);

    /* 时间戳选项 */
    opt = (u8 *)th + 20;
    *opt++ = 1;   /* NOP */
    *opt++ = 1;   /* NOP */
    *opt++ = 8;   /* Timestamp kind */
    *opt++ = 10;  /* Timestamp length */
    *(u32 *)opt = htonl(n->tsval ?  n->tsval : tapac_get_time_us());
    opt += 4;
    *(u32 *)opt = htonl(n->tsecr);

    /* TCP 校验和 */
    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcp_len, IPPROTO_TCP,
                                   csum_partial((char *)th, tcp_len, 0));

    /* 路由 */
    memset(&fl4, 0, sizeof(fl4));
    fl4.saddr = flow->local_ip;
    fl4.daddr = flow->remote_ip;
    fl4.flowi4_oif = ndev->ifindex;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt)) {
        kfree_skb(skb);
        dev_put(ndev);
        return PTR_ERR(rt);
    }

    skb_dst_set(skb, &rt->dst);
    skb->dev = ndev;
    skb->protocol = htons(ETH_P_IP);

    ip_local_out(&init_net, NULL, skb);

    dev_put(ndev);
    eng->stats.ack_real_sent++;

    return 0;
}

/* ACK 调度（bucket 轮询 + age 判定） */
static void tapac_ack_schedule(struct tapac_engine *eng)
{
    struct tapac_ack_bucket *b;
    struct tapac_ack_node *n, *next;
    u32 now_ms;
    u32 delta_ms;
    bool should_send;
    u8 bucket_idx;
    unsigned long flags;
    int sent = 0;

    if (!eng || !eng->params.use_ack_scheduler)
        return;

    now_ms = tapac_get_time_ms();

    spin_lock_irqsave(&eng->ack_lock, flags);

    bucket_idx = eng->ack_cursor & (ACK_BUCKETS - 1);
    b = &eng->ack_buckets[bucket_idx];

    n = b->head;
    while (n && sent < 16) {
        next = n->sched_next;
        should_send = false;

        /* 计算 age */
        if (now_ms > n->last_ts_ms) {
            delta_ms = now_ms - n->last_ts_ms;
            if (delta_ms > ACK_MAX_DELTA_BYTES)
                delta_ms = ACK_MAX_DELTA_BYTES;
            n->age_ticks = (u16)delta_ms;
        } else {
            n->age_ticks = 0;
        }

        /* 触发条件 */
        if (n->age_ticks >= eng->params.ack_delay_ms)
            should_send = true;

        if (n->last_ack_delta >= 3 * eng->params.mss)
            should_send = true;

        if (n->flow && (n->flow->info.flags & FLOW_FLAG_LOSS_DETECTED))
            should_send = true;

        if (should_send) {
            tapac_bucket_unlink_node(eng, n);
            spin_unlock_irqrestore(&eng->ack_lock, flags);

            tapac_send_ack_node(eng, n);
            tapac_free_ack_node(n);
            sent++;

            spin_lock_irqsave(&eng->ack_lock, flags);
            n = b->head;  /* 重新从头开始 */
            continue;
        }

        n = next;
    }

    eng->ack_cursor = (eng->ack_cursor + 1) & (ACK_BUCKETS - 1);
    eng->stats.ack_scheduled += sent;

    spin_unlock_irqrestore(&eng->ack_lock, flags);
}

/* ============================================================
 * 速率控制
 * ============================================================ */

static void tapac_rate_init(struct tapac_engine *eng)
{
    eng->rate.current_rate = (u64)eng->params.bucket_size * 8;
    eng->rate.target_rate = eng->rate.current_rate;
    eng->rate.min_rate = RATE_MIN_BPS;
    eng->rate.max_rate = RATE_MAX_BPS;
    eng->rate.cwnd = 500;
    eng->rate.ssthresh = 1000;
    eng->rate.base_rtt = eng->params.min_rtt;
    eng->rate.last_rtt = eng->params.min_rtt;
    eng->rate.in_slow_start = 1;
    eng->rate.state = NET_STATE_UNKNOWN;
    eng->rate.last_update = tapac_get_time_us();
    eng->rate.pacing_rate = eng->rate.current_rate / 8;
    eng->rate.next_send_ns = ktime_to_ns(ktime_get());
    eng->rate.pacing_gain = 1000;

    spin_lock_init(&eng->rate.lock);
}

static void tapac_rate_update_loss(struct tapac_engine *eng, bool is_loss)
{
    unsigned long flags;

    if (!eng)
        return;

    spin_lock_irqsave(&eng->rate.lock, flags);

    eng->rate.total_packets++;
    if (is_loss)
        eng->rate.loss_count++;

    if (eng->rate.total_packets >= 1000) {
        eng->rate.loss_rate = (eng->rate.loss_count * 1000) / eng->rate.total_packets;
        eng->rate.loss_count = 0;
        eng->rate.total_packets = 0;
    }

    spin_unlock_irqrestore(&eng->rate.lock, flags);
}

static void tapac_rate_update_rtt(struct tapac_engine *eng, u32 rtt_us)
{
    unsigned long flags;
    s32 trend;

    if (! eng || rtt_us == 0 || rtt_us > 10000000)
        return;

    spin_lock_irqsave(&eng->rate.lock, flags);

    if (rtt_us < eng->rate.base_rtt || eng->rate.base_rtt == 0)
        eng->rate.base_rtt = rtt_us;

    trend = (s32)rtt_us - (s32)eng->rate.last_rtt;
    eng->rate.rtt_trend = (eng->rate.rtt_trend * 7 + trend) / 8;
    eng->rate.last_rtt = rtt_us;

    spin_unlock_irqrestore(&eng->rate.lock, flags);
}

static enum tapac_net_state tapac_detect_net_state(struct tapac_engine *eng)
{
    u32 rtt_ratio;

    if (eng->rate.loss_rate >= 100)
        return NET_STATE_LOSS_DETECTED;

    if (eng->rate.base_rtt > 0) {
        rtt_ratio = eng->rate.last_rtt / eng->rate.base_rtt;

        if (rtt_ratio >= 3)
            return NET_STATE_SEVERE_CONGESTION;

        if (rtt_ratio >= 2)
            return NET_STATE_CONGESTED;
    }

    if (eng->rate.rtt_trend > (s32)(eng->rate.base_rtt / 4))
        return NET_STATE_CONGESTED;

    if (eng->rate.loss_rate >= 50)
        return NET_STATE_CONGESTED;

    return NET_STATE_HEALTHY;
}

static void tapac_rate_adjust(struct tapac_engine *eng)
{
    unsigned long flags;
    u32 now;
    u64 new_rate;
    enum tapac_net_state state;

    if (! eng)
        return;

    now = tapac_get_time_us();

    if (now - eng->rate.last_update < 100000)
        return;

    spin_lock_irqsave(&eng->rate.lock, flags);

    eng->rate.last_update = now;
    state = tapac_detect_net_state(eng);
    eng->rate.state = state;

    new_rate = eng->rate.current_rate;

    switch (state) {
    case NET_STATE_HEALTHY:
        if (eng->rate.in_slow_start) {
            new_rate = new_rate * 2;
            if (new_rate >= (u64)eng->rate.ssthresh * 8 * eng->params.mss)
                eng->rate.in_slow_start = 0;
        } else {
            new_rate = new_rate * RATE_INCREASE_FACTOR / 1000;
        }
        break;

    case NET_STATE_CONGESTED:
        new_rate = new_rate * RATE_MILD_DECREASE / 1000;
        eng->rate.in_slow_start = 0;
        break;

    case NET_STATE_SEVERE_CONGESTION:
    case NET_STATE_LOSS_DETECTED:
        new_rate = new_rate * RATE_DECREASE_FACTOR / 1000;
        eng->rate.ssthresh = eng->rate.cwnd / 2;
        if (eng->rate.ssthresh < 4)
            eng->rate.ssthresh = 4;
        eng->rate.in_slow_start = (state == NET_STATE_LOSS_DETECTED) ? 1 : 0;
        break;

    default:
        break;
    }

    if (new_rate < eng->rate.min_rate)
        new_rate = eng->rate.min_rate;
    if (new_rate > eng->rate.max_rate)
        new_rate = eng->rate.max_rate;

    eng->rate.target_rate = new_rate;

    if (new_rate > eng->rate.current_rate) {
        eng->rate.current_rate = (eng->rate.current_rate * 7 + new_rate) / 8;
    } else {
        eng->rate.current_rate = (eng->rate.current_rate * 3 + new_rate) / 4;
    }

    /* 更新 pacing rate */
    eng->rate.pacing_rate = (eng->rate.current_rate * eng->rate.pacing_gain) / 8000;

    spin_unlock_irqrestore(&eng->rate.lock, flags);
}

/* ============================================================
 * 窗口放大
 * ============================================================ */

static void tapac_update_win_factor(struct tapac_engine *eng,
                                     struct tapac_flow_info *info,
                                     bool is_loss)
{
    struct tapac_bidir_state *bidir;
    u32 now;
    u32 elapsed;
    u32 new_factor;

    if (!eng || !info)
        return;

    bidir = &info->bidir;
    now = tapac_get_time_us();
    elapsed = now - bidir->win_adjust_time;

    if (elapsed < 100000 && ! is_loss)
        return;

    bidir->win_adjust_time = now;

    if (is_loss) {
        bidir->consecutive_loss++;
        bidir->consecutive_good = 0;

        if (bidir->consecutive_loss >= 3) {
            new_factor = WIN_INFLATE_MIN * 1000;
        } else if (bidir->consecutive_loss >= 2) {
            new_factor = bidir->current_win_factor / 2;
        } else {
            new_factor = bidir->current_win_factor * 700 / 1000;
        }

        if (new_factor < WIN_INFLATE_MIN * 1000)
            new_factor = WIN_INFLATE_MIN * 1000;

        bidir->target_win_factor = new_factor;
        bidir->current_win_factor = new_factor;

        eng->stats.win_factor_reduced++;
    } else {
        bidir->consecutive_good++;
        bidir->consecutive_loss = 0;

        if (eng->rate.state == NET_STATE_HEALTHY) {
            if (bidir->consecutive_good >= 10) {
                new_factor = bidir->target_win_factor * 1100 / 1000;
            } else if (bidir->consecutive_good >= 5) {
                new_factor = bidir->target_win_factor * 1050 / 1000;
            } else {
                new_factor = bidir->target_win_factor;
            }
        } else if (eng->rate.state == NET_STATE_CONGESTED) {
            new_factor = bidir->target_win_factor * 950 / 1000;
        } else {
            new_factor = bidir->target_win_factor * 800 / 1000;
        }

        if (new_factor < WIN_INFLATE_MIN * 1000)
            new_factor = WIN_INFLATE_MIN * 1000;
        if (new_factor > WIN_INFLATE_MAX * 1000)
            new_factor = WIN_INFLATE_MAX * 1000;

        bidir->target_win_factor = new_factor;

        if (new_factor > bidir->current_win_factor) {
            bidir->current_win_factor = (bidir->current_win_factor * 7 + new_factor) / 8;
            eng->stats.win_factor_increased++;
        } else {
            bidir->current_win_factor = (bidir->current_win_factor * 3 + new_factor) / 4;
        }
    }
}

static u16 tapac_inflate_window(struct tapac_engine *eng,
                                 struct tapac_flow_info *info,
                                 u16 orig_win)
{
    struct tapac_bidir_state *bidir;
    u32 real_win;
    u32 inflated_win;
    u32 factor;

    if (! eng || !info)
        return orig_win;

    bidir = &info->bidir;

    if (bidir->current_win_factor == 0) {
        bidir->current_win_factor = 2000;
        bidir->target_win_factor = 2000;
    }

    real_win = (u32)orig_win << info->win.rcv_wscale;

    if (bidir->dl_loss_detected)
        return orig_win;

    if (bidir->ul_ooo_count > 3) {
        factor = bidir->current_win_factor / 2;
        if (factor < WIN_INFLATE_MIN * 1000)
            factor = WIN_INFLATE_MIN * 1000;
    } else if (info->phase == PHASE_FAST_RECOVERY) {
        factor = WIN_INFLATE_MIN * 1000 + 500;
    } else {
        factor = bidir->current_win_factor;
    }

    inflated_win = (real_win * factor) / 1000;

    if (inflated_win > (1U << 30))
        inflated_win = (1U << 30);

    if (info->win.rcv_wscale > 0) {
        u16 new_win = inflated_win >> info->win.rcv_wscale;
        if (new_win == 0)
            new_win = 1;
        if (new_win < orig_win)
            new_win = orig_win;
        return new_win;
    }

    return (u16)(inflated_win > 65535 ? 65535 : inflated_win);
}

static void tapac_modify_ack_window(struct sk_buff *skb,
                                     struct tapac_engine *eng,
                                     struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u16 orig_win;
    u16 new_win;
    struct tapac_flow_info *info;

    if (!skb || ! eng || !flow)
        return;

    info = &flow->info;

    if (info->direction != FLOW_DIR_SERVER)
        return;

    if (skb_cloned(skb)) {
        if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
            return;
    }

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (! th->ack)
        return;

    orig_win = ntohs(th->window);
    new_win = tapac_inflate_window(eng, info, orig_win);

    if (new_win <= orig_win)
        return;

    th->window = htons(new_win);
    info->win.advertised_win = new_win;
    info->win.last_win_update = tapac_get_time_us();
    eng->stats.win_inflated++;
}

/* ============================================================
 * RTT 测量
 * ============================================================ */

static u8 *tapac_find_ts_option(struct tcphdr *th, u32 tcp_hdr_len)
{
    u8 *opt, *end;
    u8 kind, len;

    if (tcp_hdr_len < 32)
        return NULL;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 8 && len == 10)
            return opt;

        opt += len;
    }

    return NULL;
}

static void tapac_record_tsval(struct tapac_flow_info *info, u32 tsval)
{
    if (! info)
        return;

    info->rtt.last_tsval = tsval;
    info->rtt.last_tsval_time = tapac_get_time_us();
}

static void tapac_stamp_tsval(struct sk_buff *skb, u32 tsval)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;

    if (!skb)
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    ts_opt = tapac_find_ts_option(th, th->doff * 4);
    if (! ts_opt)
        return;

    *(u32 *)(ts_opt + 2) = htonl(tsval);
}

static u32 tapac_measure_rtt(struct sk_buff *skb, struct tapac_flow *flow,
                              struct tapac_engine *eng)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 tsval, tsecr;
    u32 rtt = 0;
    struct tapac_flow_info *info;

    if (!skb || !flow || !eng)
        return 0;

    info = &flow->info;
    iph = ip_hdr(skb);

    if (! iph || iph->protocol != IPPROTO_TCP)
        return 0;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    ts_opt = tapac_find_ts_option(th, th->doff * 4);
    if (!ts_opt) {
        info->ts_enabled = 0;
        return 0;
    }

    info->ts_enabled = 1;
    info->flags |= FLOW_FLAG_TS_ENABLED;

    tsval = ntohl(*(u32 *)(ts_opt + 2));
    tsecr = ntohl(*(u32 *)(ts_opt + 6));

    if (tsecr != 0 && info->rtt.last_tsval != 0) {
        if (tsecr == info->rtt.last_tsval) {
            rtt = tapac_get_time_us() - info->rtt.last_tsval_time;
        } else {
            u32 now = tapac_get_time_us();
            if (tsecr < now && (now - tsecr) < 10000000) {
                rtt = now - tsecr;
            }
        }
    }

    if (rtt > 0 && rtt < 10000000) {
        if (info->srtt == 0 || info->srtt == eng->params.min_rtt) {
            info->srtt = rtt;
        } else {
            info->srtt = (info->srtt * 875 + rtt * 125) / 1000;
        }

        if (rtt < info->rtt.min_rtt || info->rtt.min_rtt == 0)
            info->rtt.min_rtt = rtt;
        if (rtt > info->rtt.max_rtt)
            info->rtt.max_rtt = rtt;

        eng->stats.rtt_samples++;
    }

    return rtt;
}

/* ============================================================
 * 丢包检测
 * ============================================================ */

static void tapac_detect_loss_bidir(struct tapac_engine *eng,
                                     struct tapac_flow_info *info,
                                     u32 ack_seq,
                                     struct tapac_sack_info *sack,
                                     bool is_download_ack)
{
    struct tapac_bidir_state *bidir;

    if (!eng || !info)
        return;

    bidir = &info->bidir;

    if (is_download_ack) {
        if (ack_seq == bidir->dl_last_ack_seq) {
            bidir->dl_dup_ack_count++;

            if (bidir->dl_dup_ack_count == 3) {
                bidir->dl_loss_detected = 1;
                bidir->dl_phase = PHASE_FAST_RECOVERY;
                info->flags |= FLOW_FLAG_LOSS_DETECTED;
                eng->stats.fast_retransmit++;

                tapac_update_win_factor(eng, info, true);
            }

            eng->stats.loss_detected++;
        } else if (tapac_seq_gt(ack_seq, bidir->dl_last_ack_seq)) {
            u32 advance = ack_seq - bidir->dl_last_ack_seq;

            bidir->dl_dup_ack_count = 0;
            bidir->dl_bytes_acked += advance;

            if (advance > 3 * 1460) {
                bidir->dl_loss_detected = 0;
                info->flags &= ~FLOW_FLAG_LOSS_DETECTED;
                if (bidir->dl_phase == PHASE_FAST_RECOVERY)
                    bidir->dl_phase = PHASE_CONG_AVOID;

                tapac_update_win_factor(eng, info, false);
            }

            bidir->dl_last_ack_seq = ack_seq;
        }
    }

    if (sack && sack->num_blocks > 0) {
        info->flags |= FLOW_FLAG_HAS_SACK;
        info->sack_permitted = 1;

        if (is_download_ack && ack_seq == bidir->dl_last_ack_seq && sack->num_blocks >= 1) {
            u32 hole_start = ack_seq;
            u32 hole_end = sack->blocks[0].start;
            u32 hole_size = tapac_seq_diff(hole_end, hole_start);

            if (hole_size > 0 && hole_size < 100 * 1460) {
                bidir->dl_loss_detected = 1;
                info->flags |= FLOW_FLAG_LOSS_DETECTED;
                tapac_update_win_factor(eng, info, true);
            }
        }
    }
}

static void tapac_check_fast_path(struct tapac_engine *eng,
                                   struct tapac_flow_info *info)
{
    if (!eng || !info)
        return;

    if (info->bytes_sent_total > 1024 * 1024 &&
        !(info->flags & FLOW_FLAG_LOSS_DETECTED) &&
        info->throughput_reduction_num == 0 &&
        info->dup_ack_count == 0 &&
        info->phase != PHASE_FAST_RECOVERY &&
        info->rtt.var_rtt < info->srtt / 4) {
        info->flags |= FLOW_FLAG_FAST_PATH;
    } else {
        info->flags &= ~FLOW_FLAG_FAST_PATH;
    }
}

/* ============================================================
 * 令牌桶
 * ============================================================ */

static bool tapac_dl_token_try_get(struct tapac_engine *eng, u32 amount)
{
    unsigned long flags;
    bool result = false;
    u64 max_tokens;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    max_tokens = (u64)eng->avg_throughput * eng->avg_rtt / 8000;
    if (max_tokens < 1024 * 1024)
        max_tokens = 1024 * 1024;
    if (max_tokens > eng->params.bucket_size)
        max_tokens = eng->params.bucket_size;

    if (eng->dl_tokens + amount <= max_tokens) {
        eng->dl_tokens += amount;
        result = true;
    }

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
    return result;
}

static void tapac_dl_token_release(struct tapac_engine *eng, u32 amount)
{
    unsigned long flags;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    if (eng->dl_tokens >= amount)
        eng->dl_tokens -= amount;
    else
        eng->dl_tokens = 0;

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
}

static void tapac_dl_token_ack_release(struct tapac_engine *eng, u32 ack_bytes)
{
    unsigned long flags;
    u32 release;

    release = ack_bytes + ack_bytes / 4;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    if (eng->dl_tokens >= release)
        eng->dl_tokens -= release;
    else
        eng->dl_tokens = 0;

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
}

static void tapac_dl_token_decay(struct tapac_engine *eng)
{
    unsigned long flags;
    u64 decay;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    decay = eng->dl_tokens / 20;
    if (decay < 1024)
        decay = 1024;

    if (eng->dl_tokens >= decay)
        eng->dl_tokens -= decay;
    else
        eng->dl_tokens = 0;

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
}

/* ============================================================
 * 上传加速
 * ============================================================ */

static void tapac_update_upload_stats(struct tapac_flow_info *info,
                                       u32 payload_len, u32 seq)
{
    struct tapac_bidir_state *bidir;

    if (!info || payload_len == 0)
        return;

    bidir = &info->bidir;

    bidir->ul_bytes_received += payload_len;

    if (bidir->ul_rcv_nxt != 0) {
        if (tapac_seq_gt(seq, bidir->ul_rcv_nxt)) {
            bidir->ul_ooo_count++;
        } else if (seq == bidir->ul_rcv_nxt) {
            if (bidir->ul_ooo_count > 0)
                bidir->ul_ooo_count--;
        }
    }

    if (tapac_seq_gt(seq + payload_len, bidir->ul_rcv_nxt))
        bidir->ul_rcv_nxt = seq + payload_len;

    if (bidir->ul_bytes_received > 10 * 1024)
        info->flags |= FLOW_FLAG_UPLOAD_ACCEL;
}

static void tapac_process_upload_data(struct tapac_engine *eng,
                                       struct sk_buff *skb,
                                       struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow_info *info;
    u32 payload_len;
    u32 seq;

    if (!eng || !skb || ! flow)
        return;

    info = &flow->info;

    if (info->direction != FLOW_DIR_SERVER)
        return;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;
    seq = ntohl(th->seq);

    if (payload_len == 0)
        return;

    tapac_update_upload_stats(info, payload_len, seq);

    eng->stats.ul_data_processed++;
}

static void tapac_process_upload_ack(struct tapac_engine *eng,
                                      struct sk_buff *skb,
                                      struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow_info *info;
    struct tapac_bidir_state *bidir;
    u32 ack_seq;
    u32 payload_len;

    if (!eng || !skb || ! flow)
        return;

    info = &flow->info;
    bidir = &info->bidir;

    if (info->direction != FLOW_DIR_SERVER)
        return;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (! th->ack)
        return;

    ack_seq = ntohl(th->ack_seq);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

    if (payload_len == 0) {
        if (tapac_seq_gt(ack_seq, bidir->ul_last_ack_seq)) {
            u32 acked = ack_seq - bidir->ul_last_ack_seq;
            bidir->ul_bytes_acked += acked;
            bidir->ul_last_ack_seq = ack_seq;
            eng->stats.upload_bytes_accel += acked;
        }

        bidir->ul_last_ack_time = tapac_get_time_us();
        bidir->ul_pending_acks = 0;
        bidir->ul_need_ack = 0;

        if (bidir->ul_ooo_count == 0)
            tapac_update_win_factor(eng, info, false);
    }
}

/* ============================================================
 * 发送独立 SACK ACK
 * ============================================================ */

static int tapac_send_sack_ack(struct tapac_engine *eng, struct tapac_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *th;
    struct net_device *ndev;
    struct rtable *rt;
    struct flowi4 fl4;
    struct tapac_flow_info *info;
    u8 *opt;
    u8 sack_opt[34];
    int sack_len;
    int tcp_hdr_len;
    int total_len;
    static u32 last_sack_ack_time = 0;
    u32 now;

    if (! eng || !flow)
        return -EINVAL;

    info = &flow->info;

    if (info->rcv_sack.num_blocks < SACK_INJECT_MIN_BLOCKS)
        return 0;

    if (! info->sack_permitted)
        return 0;

    now = tapac_get_time_us();
    if (now - last_sack_ack_time < SACK_INDEPENDENT_ACK_GAP)
        return 0;

    sack_len = tapac_generate_sack(info, sack_opt, sizeof(sack_opt));
    if (sack_len == 0)
        return 0;

    ndev = dev_get_by_name(&init_net, eng->params.nic);
    if (!ndev)
        return -ENODEV;

    /* 20(TCP) + 12(TS) + 2(NOP) + sack_len */
    tcp_hdr_len = 20 + 12 + 2 + sack_len;
    tcp_hdr_len = (tcp_hdr_len + 3) & ~3;

    total_len = sizeof(struct iphdr) + tcp_hdr_len;

    skb = alloc_skb(LL_MAX_HEADER + total_len, GFP_ATOMIC);
    if (!skb) {
        dev_put(ndev);
        return -ENOMEM;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_network_header(skb);

    /* IP 头 */
    iph = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(total_len);
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = flow->local_ip;
    iph->daddr = flow->remote_ip;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    /* TCP 头 */
    skb_set_transport_header(skb, sizeof(struct iphdr));
    th = (struct tcphdr *)skb_put(skb, tcp_hdr_len);
    memset(th, 0, tcp_hdr_len);

    th->source = flow->local_port;
    th->dest = flow->remote_port;
    th->seq = htonl(info->my_seq);
    th->ack_seq = htonl(info->rcv_nxt);
    th->doff = tcp_hdr_len / 4;
    th->ack = 1;
    th->window = htons(info->default_win);

    /* TCP 选项 */
    opt = (u8 *)th + 20;

    /* 时间戳 */
    *opt++ = 1;   /* NOP */
    *opt++ = 1;   /* NOP */
    *opt++ = 8;   /* Timestamp kind */
    *opt++ = 10;  /* Timestamp length */
    *(u32 *)opt = htonl(tapac_get_time_us());
    opt += 4;
    *(u32 *)opt = htonl(info->peer_tsval);
    opt += 4;

    /* NOP 对齐 */
    *opt++ = 1;
    *opt++ = 1;

    /* SACK */
    memcpy(opt, sack_opt, sack_len);
    opt += sack_len;

    /* 填充 */
    while ((opt - (u8 *)th) < tcp_hdr_len)
        *opt++ = 0;

    /* TCP 校验和 */
    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcp_hdr_len, IPPROTO_TCP,
                                   csum_partial((char *)th, tcp_hdr_len, 0));

    /* 路由 */
    memset(&fl4, 0, sizeof(fl4));
    fl4.saddr = flow->local_ip;
    fl4.daddr = flow->remote_ip;
    fl4.flowi4_oif = ndev->ifindex;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt)) {
        kfree_skb(skb);
        dev_put(ndev);
        return PTR_ERR(rt);
    }

    skb_dst_set(skb, &rt->dst);
    skb->dev = ndev;
    skb->protocol = htons(ETH_P_IP);

    ip_local_out(&init_net, NULL, skb);

    dev_put(ndev);

    last_sack_ack_time = now;
    eng->stats.sack_generated++;
    eng->stats.ack_real_sent++;

    return 1;
}

/* ============================================================
 * Tasklet 出队
 * ============================================================ */

static void tapac_dequeue_tasklet_func(unsigned long data)
{
    struct tapac_engine *eng = (struct tapac_engine *)data;
    struct tapac_pkt_node *pkt;
    u32 now;
    int sent = 0;

    if (!eng || !eng->running)
        return;

    now = tapac_get_time_us();

    /* 高优先级队列 */
    while (sent < 64 && tapac_queue_size(eng->q_high) > 0) {
        pkt = tapac_queue_peek(eng->q_high);
        if (! pkt)
            break;

        if (now - pkt->enqueue_time >= eng->params.max_delay) {
            tapac_queue_dequeue(eng->q_high);
            sent++;
            continue;
        }

        if (tapac_dl_token_try_get(eng, pkt->trigger)) {
            tapac_queue_dequeue(eng->q_high);
            sent++;
        } else {
            if (now - pkt->enqueue_time >= 5000) {
                tapac_queue_dequeue(eng->q_high);
                sent++;
            } else {
                break;
            }
        }
    }

    /* 低优先级队列 */
    while (sent < 64 && tapac_queue_size(eng->q_high) == 0 &&
           tapac_queue_size(eng->q_low) > 0) {
        pkt = tapac_queue_peek(eng->q_low);
        if (!pkt)
            break;

        if (now - pkt->enqueue_time >= eng->params.max_delay ||
            tapac_dl_token_try_get(eng, pkt->trigger)) {
            tapac_queue_dequeue(eng->q_low);
            sent++;
        } else {
            if (now - pkt->enqueue_time >= 10000) {
                tapac_queue_dequeue(eng->q_low);
                sent++;
            } else {
                break;
            }
        }
    }

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);
}

/* ============================================================
 * Netfilter Hooks
 * ============================================================ */

#if defined(TAPAC_NF_NEW_HOOK_API)
static unsigned int tapac_hook_in(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    const struct net_device *in = state->in;
#else
static unsigned int tapac_hook_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
#endif
    struct tapac_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow *flow;
    struct tapac_flow_info *info;
    struct tapac_bidir_state *bidir;
    struct tapac_sack_info sack = {0};
    u32 rtt;
    u32 payload_len;
    u32 tcp_hdr_len;
    u32 now;
    u32 seq;
    u32 tsval, tsecr;
    unsigned long flags;
    bool is_upload_data;
    bool is_ooo = false;

    if (!eng || !eng->running)
        return NF_ACCEPT;

    if (!in || strcmp(in->name, eng->params.nic) != 0)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcp_hdr_len;
    seq = ntohl(th->seq);

    eng->stats.pkts_rx++;
    eng->stats.bytes_rx += skb->len;

    now = tapac_get_time_us();

    /* SYN 处理：客户端发起连接 */
    if (th->syn && !th->ack) {
        spin_lock_irqsave(&eng->ft.lock, flags);
        flow = tapac_flow_lookup(&eng->ft, iph->daddr, iph->saddr,
                                 th->dest, th->source);
        if (! flow) {
            spin_unlock_irqrestore(&eng->ft.lock, flags);
            flow = tapac_flow_create(&eng->ft, iph->daddr, iph->saddr,
                                     th->dest, th->source,
                                     FLOW_DIR_SERVER, eng->params.min_rtt);
            if (flow) {
                flow->info.last_update = now;
                if (tapac_check_sack_permitted(th, tcp_hdr_len)) {
                    flow->info.sack_permitted = 1;
                    flow->info.flags |= FLOW_FLAG_SACK_PERMITTED;
                }
                tapac_parse_win_scale(th, tcp_hdr_len, &flow->info.win);
                flow->info.bidir.ul_rcv_nxt = seq + 1;
                eng->stats.flows_created++;
            }
        } else {
            spin_unlock_irqrestore(&eng->ft.lock, flags);
        }
        return NF_ACCEPT;
    }

    /* SYN-ACK 处理 */
    if (th->syn && th->ack) {
        spin_lock_irqsave(&eng->ft.lock, flags);
        flow = tapac_flow_lookup(&eng->ft, iph->daddr, iph->saddr,
                                 th->dest, th->source);
        spin_unlock_irqrestore(&eng->ft.lock, flags);

        if (flow) {
            info = &flow->info;
            if (tapac_check_sack_permitted(th, tcp_hdr_len)) {
                info->sack_permitted = 1;
                info->flags |= FLOW_FLAG_SACK_PERMITTED;
            }
            tapac_parse_win_scale(th, tcp_hdr_len, &info->win);
            info->bidir.dl_last_data_seq = seq;
            info->last_update = now;
        }
        return NF_ACCEPT;
    }

    /* 查找流 */
    spin_lock_irqsave(&eng->ft.lock, flags);
    flow = tapac_flow_lookup(&eng->ft, iph->daddr, iph->saddr,
                             th->dest, th->source);
    spin_unlock_irqrestore(&eng->ft.lock, flags);

    if (!flow)
        return NF_ACCEPT;

    info = &flow->info;
    bidir = &info->bidir;

    if (!(info->flags & FLOW_FLAG_BIDIR_INIT))
        tapac_bidir_init(info);

    if (info->direction == FLOW_DIR_CLIENT)
        return NF_ACCEPT;

    tapac_parse_tcp_ts(th, tcp_hdr_len, &tsval, &tsecr);
    if (tsval != 0)
        info->peer_tsval = tsval;

    /* FIN/RST */
    if (th->fin || th->rst) {
        tapac_ack_flush_flow(eng, flow);
        tapac_sack_clear(info);
        tapac_flow_delete(&eng->ft, iph->daddr, iph->saddr,
                          th->dest, th->source);
        eng->stats.flows_destroyed++;
        return NF_ACCEPT;
    }

    /* 解析 SACK */
    if (tapac_parse_sack(th, tcp_hdr_len, &sack) > 0) {
        eng->stats.sack_parsed++;
        info->flags |= FLOW_FLAG_HAS_SACK;
    }

    is_upload_data = (payload_len > 0);

    /* ACK 处理 */
    if (th->ack) {
        u32 ack_seq = ntohl(th->ack_seq);

        if (! is_upload_data) {
            tapac_detect_loss_bidir(eng, info, ack_seq, &sack, true);
            eng->stats.dl_acks_processed++;
            tapac_rate_update_loss(eng, bidir->dl_loss_detected ?  true : false);

            if (tapac_seq_gt(ack_seq, bidir->dl_last_ack_seq)) {
                u32 ack_advance = ack_seq - bidir->dl_last_ack_seq;
                if (ack_advance <= 10 * 1024 * 1024)
                    tapac_dl_token_ack_release(eng, ack_advance);
                bidir->dl_last_ack_seq = ack_seq;
            }
        } else {
            if (tapac_seq_gt(ack_seq, bidir->dl_last_ack_seq)) {
                u32 ack_advance = ack_seq - bidir->dl_last_ack_seq;
                if (ack_advance <= 10 * 1024 * 1024)
                    tapac_dl_token_ack_release(eng, ack_advance);
                bidir->dl_last_ack_seq = ack_seq;
            }
        }
    }

    /* 处理上传数据 */
    if (is_upload_data) {
        u32 seq_end = seq + payload_len;

        tapac_process_upload_data(eng, skb, flow);

        if (bidir->ul_rcv_nxt != 0) {
            if (tapac_seq_gt(seq, bidir->ul_rcv_nxt)) {
                is_ooo = true;
                eng->stats.ooo_packets++;
                bidir->ul_ooo_count++;
                if (bidir->ul_ooo_count >= 2)
                    bidir->ul_need_ack = 1;
            } else if (seq == bidir->ul_rcv_nxt) {
                if (bidir->ul_ooo_count > 0)
                    bidir->ul_ooo_count--;
            }
        }

        if (eng->params.generate_sack && info->sack_permitted) {
            tapac_update_sack_blocks(info, seq, payload_len);
            if (is_ooo && info->rcv_sack.num_blocks > 0) {
                bidir->ul_need_ack = 1;
                bidir->ul_pending_acks++;
            }
        }

        if (tapac_seq_gt(seq_end, bidir->ul_rcv_nxt) && !is_ooo)
            bidir->ul_rcv_nxt = seq_end;

        info->rcv_nxt = bidir->ul_rcv_nxt;

        if (tapac_seq_gt(seq_end - 1, info->last_data_seq))
            info->last_data_seq = seq_end - 1;
        bidir->ul_last_data_seq = seq_end - 1;
    }

    tapac_check_fast_path(eng, info);
    if (info->flags & FLOW_FLAG_FAST_PATH)
        eng->stats.fast_path_hits++;

    /* RTT 测量 */
    rtt = tapac_measure_rtt(skb, flow, eng);
    if (rtt > 0 && rtt < 10000000) {
        tapac_rate_update_rtt(eng, rtt);
        spin_lock_irqsave(&eng->global_lock, flags);
        eng->total_rtt += rtt;
        eng->samples++;
        spin_unlock_irqrestore(&eng->global_lock, flags);
    }

    info->bytes_sent_latest += payload_len;
    if (info->bytes_sent_total <= 4294900000UL)
        info->bytes_sent_total += payload_len;

    info->last_update = now;

    spin_lock_irqsave(&eng->global_lock, flags);
    eng->traffic += skb->len;
    spin_unlock_irqrestore(&eng->global_lock, flags);

    /* 触发独立 SACK ACK */
    if (is_ooo && eng->params.generate_sack && info->sack_permitted &&
        info->rcv_sack.num_blocks >= 1 && bidir->ul_ooo_count >= 5) {
        tapac_send_sack_ack(eng, flow);
        bidir->ul_ooo_count = 0;
        bidir->ul_need_ack = 0;
    }

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);

    return NF_ACCEPT;
}

#if defined(TAPAC_NF_NEW_HOOK_API)
static unsigned int tapac_hook_out(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    const struct net_device *out = state->out;
    tapac_okfn_t okfn = state->okfn;
#else
static unsigned int tapac_hook_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
#endif
    struct tapac_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow *flow = NULL;
    struct tapac_flow_info *info = NULL;
    struct tapac_bidir_state *bidir = NULL;
    u32 payload_len;
    u32 ack;
    u32 trigger = 0;
    u32 tsval;
    unsigned long flags;
    int result;

    if (! eng || !eng->running)
        return NF_ACCEPT;

    if (! out || strcmp(out->name, eng->params.nic) != 0)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    if (skb_linearize(skb) != 0)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

    eng->stats.pkts_tx++;
    eng->stats.bytes_tx += skb->len;

    tsval = tapac_get_time_us();

    /* SYN 处理 */
    if (th->syn) {
        if (! th->ack) {
            flow = tapac_flow_create(&eng->ft, iph->saddr, iph->daddr,
                                     th->source, th->dest,
                                     FLOW_DIR_CLIENT, eng->params.min_rtt);
            if (flow) {
                flow->info.last_data_seq = ntohl(th->seq);
                flow->info.my_seq = ntohl(th->seq);
                flow->info.last_update = tapac_get_time_us();
                if (tapac_check_sack_permitted(th, th->doff * 4)) {
                    flow->info.sack_permitted = 1;
                    flow->info.flags |= FLOW_FLAG_SACK_PERMITTED;
                }
                eng->stats.flows_created++;
            }
            return NF_ACCEPT;
        } else {
            flow = tapac_flow_create(&eng->ft, iph->saddr, iph->daddr,
                                     th->source, th->dest,
                                     FLOW_DIR_SERVER, eng->params.min_rtt);
            if (flow) {
                flow->info.last_ack_seq = ntohl(th->ack_seq);
                flow->info.my_seq = ntohl(th->seq);
                flow->info.last_update = tapac_get_time_us();
                tapac_parse_win_scale(th, th->doff * 4, &flow->info.win);
                if (tapac_check_sack_permitted(th, th->doff * 4)) {
                    flow->info.sack_permitted = 1;
                    flow->info.flags |= FLOW_FLAG_SACK_PERMITTED;
                }
                eng->stats.flows_created++;
            }
            return NF_ACCEPT;
        }
    }

    /* FIN/RST */
    if (th->fin || th->rst) {
        spin_lock_irqsave(&eng->ft.lock, flags);
        flow = tapac_flow_lookup(&eng->ft, iph->saddr, iph->daddr,
                                 th->source, th->dest);
        spin_unlock_irqrestore(&eng->ft.lock, flags);

        if (flow) {
            tapac_ack_flush_flow(eng, flow);
            tapac_flow_delete(&eng->ft, iph->saddr, iph->daddr,
                              th->source, th->dest);
            eng->stats.flows_destroyed++;
        }
        return NF_ACCEPT;
    }

    /* 查找流 */
    spin_lock_irqsave(&eng->ft.lock, flags);
    flow = tapac_flow_lookup(&eng->ft, iph->saddr, iph->daddr,
                             th->source, th->dest);
    spin_unlock_irqrestore(&eng->ft.lock, flags);

    if (!flow || flow->info.direction == FLOW_DIR_CLIENT)
        return NF_ACCEPT;

    info = &flow->info;
    bidir = &info->bidir;
    info->my_seq = ntohl(th->seq);

    /* 纯 ACK 处理 */
    if (th->ack && payload_len == 0) {
        ack = ntohl(th->ack_seq);

        if (bidir->ul_bytes_received > eng->params.upload_accel_thresh) {
            info->flags |= FLOW_FLAG_UPLOAD_ACCEL;
            tapac_modify_ack_window(skb, eng, flow);
            tapac_process_upload_ack(eng, skb, flow);
        }

        if (tapac_seq_gt(ack, bidir->ul_last_ack_seq)) {
            bidir->ul_last_ack_seq = ack;
            info->last_ack_seq = ack;
            eng->stats.ack_created++;
        }

        tapac_stamp_tsval(skb, tsval);
        tapac_record_tsval(info, tsval);
        tapac_fix_checksums(skb);
        return NF_ACCEPT;
    }

    /* 数据包处理 */
    if (payload_len > 0) {
        u32 seq = ntohl(th->seq);
        u32 seq_end = seq + payload_len - 1;

        if (tapac_seq_gt(seq_end, bidir->dl_last_data_seq)) {
            bidir->dl_last_data_seq = seq_end;
            bidir->dl_bytes_sent += payload_len;
        }

        if (tapac_seq_gt(bidir->dl_last_data_seq, bidir->dl_last_ack_seq))
            bidir->dl_inflight = bidir->dl_last_data_seq - bidir->dl_last_ack_seq;
    }

    trigger = skb->len;

    tapac_stamp_tsval(skb, tsval);
    tapac_record_tsval(info, tsval);
    tapac_fix_checksums(skb);

    /* 快速路径 */
    if (tapac_dl_token_try_get(eng, trigger)) {
        if (tapac_queue_size(eng->q_high) == 0 && tapac_queue_size(eng->q_low) == 0)
            return NF_ACCEPT;
        tapac_dl_token_release(eng, trigger);
    }

    /* 入队 */
    result = tapac_queue_enqueue(eng->q_high, skb, okfn, trigger, tapac_get_time_us());

    if (result == 1) {
        eng->stats.pkts_queued++;
        tasklet_schedule(&dequeue_tasklet);
        return NF_STOLEN;
    }

    return NF_ACCEPT;
}

/* ============================================================
 * 定时器
 * ============================================================ */

static enum hrtimer_restart tapac_timer_callback(struct hrtimer *timer)
{
    struct tapac_engine *eng = container_of(timer, struct tapac_engine, timer);
    ktime_t interval;
    unsigned long flags;
    u32 time_delta;
    u32 current_time;
    u64 throughput;
    int cleaned;
    static u32 decay_counter = 0;
    static u32 rate_adjust_counter = 0;
    static u32 cleanup_counter = 0;

    if (!eng || !eng->running)
        return HRTIMER_NORESTART;

    current_time = tapac_get_time_us();

    /* 每 10ms 衰减令牌 */
    decay_counter++;
    if (decay_counter >= 10) {
        tapac_dl_token_decay(eng);
        decay_counter = 0;
    }

    /* 每 200ms 调整速率 */
    rate_adjust_counter++;
    if (rate_adjust_counter >= 200) {
        tapac_rate_adjust(eng);
        rate_adjust_counter = 0;
    }

    /* 每 100ms 更新统计 */
    spin_lock_irqsave(&eng->global_lock, flags);

    time_delta = current_time - eng->last_global_update;
    eng->last_global_update = current_time;

    if (time_delta > 0) {
        throughput = (eng->traffic * 8000ULL) / time_delta;
        eng->avg_throughput = (eng->avg_throughput * 7 + (u32)throughput) / 8;
    }

    if (eng->samples > 0) {
        eng->avg_rtt = eng->total_rtt / eng->samples;
        if (eng->avg_rtt < eng->params.min_rtt)
            eng->avg_rtt = eng->params.min_rtt;
        if (eng->avg_rtt > eng->params.max_rtt)
            eng->avg_rtt = eng->params.max_rtt;
    }

    eng->traffic = 0;
    eng->total_rtt = 0;
    eng->samples = 0;

    spin_unlock_irqrestore(&eng->global_lock, flags);

    /* ACK 调度 */
    tapac_ack_schedule(eng);

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);

    /* 每 20 秒清理超时流 */
    cleanup_counter++;
    if (cleanup_counter >= 20000) {
        cleaned = tapac_flow_cleanup_timeout(&eng->ft, FLOW_TIMEOUT_US);
        if (cleaned > 0)
            eng->stats.flows_destroyed += cleaned;
        cleanup_counter = 0;
    }

    interval = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_forward_now(timer, interval);

    return HRTIMER_RESTART;
}

/* ============================================================
 * /proc 接口
 * ============================================================ */

static int tapac_stats_show(struct seq_file *m, void *v)
{
    struct tapac_engine *eng = g_engine;

    if (!eng)
        return 0;

    seq_printf(m, "=== TAPAC Statistics v4.0 ===\n");
    seq_printf(m, "Interface: %s\n", eng->params.nic);
    seq_printf(m, "Running: %s\n", eng->running ? "YES" : "NO");
    seq_printf(m, "Flows: %u / %u\n", eng->ft.count, FLOW_MAX_COUNT);

    seq_printf(m, "\n--- ACK Scheduler ---\n");
    seq_printf(m, "Enabled: %s\n", eng->params.use_ack_scheduler ? "YES" : "NO");
    seq_printf(m, "Scheduled flows: %u\n", eng->ack_scheduled_flows);
    seq_printf(m, "Created: %llu\n", eng->stats.ack_created);
    seq_printf(m, "Merged: %llu\n", eng->stats.ack_merged);
    seq_printf(m, "Scheduled: %llu\n", eng->stats.ack_scheduled);
    seq_printf(m, "Real sent: %llu\n", eng->stats.ack_real_sent);
    seq_printf(m, "Queue full: %llu\n", eng->stats.ack_queue_full);

    seq_printf(m, "\n--- SACK ---\n");
    seq_printf(m, "Generate: %s\n", eng->params.generate_sack ?  "YES" : "NO");
    seq_printf(m, "Parsed: %llu\n", eng->stats.sack_parsed);
    seq_printf(m, "Generated: %llu\n", eng->stats.sack_generated);

    seq_printf(m, "\n--- Loss Detection ---\n");
    seq_printf(m, "Loss detected: %llu\n", eng->stats.loss_detected);
    seq_printf(m, "Fast retransmit: %llu\n", eng->stats.fast_retransmit);
    seq_printf(m, "Fast path hits: %llu\n", eng->stats.fast_path_hits);
    seq_printf(m, "OOO packets: %llu\n", eng->stats.ooo_packets);

    seq_printf(m, "\n--- Upload Acceleration ---\n");
    seq_printf(m, "Window inflated: %llu\n", eng->stats.win_inflated);
    seq_printf(m, "ACK accelerated: %llu\n", eng->stats.ack_accelerated);
    seq_printf(m, "Upload bytes: %llu\n", eng->stats.upload_bytes_accel);

    seq_printf(m, "\n--- Bidirectional ---\n");
    seq_printf(m, "DL ACKs processed: %llu\n", eng->stats.dl_acks_processed);
    seq_printf(m, "UL data processed: %llu\n", eng->stats.ul_data_processed);
    seq_printf(m, "Win factor reduced: %llu\n", eng->stats.win_factor_reduced);
    seq_printf(m, "Win factor increased: %llu\n", eng->stats.win_factor_increased);

    seq_printf(m, "\n--- RTT ---\n");
    seq_printf(m, "Samples: %llu\n", eng->stats.rtt_samples);
    seq_printf(m, "Avg RTT: %u us (%u.%02u ms)\n",
               eng->avg_rtt, eng->avg_rtt / 1000, (eng->avg_rtt % 1000) / 10);

    seq_printf(m, "\n--- Flows ---\n");
    seq_printf(m, "Created: %llu\n", eng->stats.flows_created);
    seq_printf(m, "Destroyed: %llu\n", eng->stats.flows_destroyed);

    seq_printf(m, "\n--- Packets ---\n");
    seq_printf(m, "RX: %llu\n", eng->stats.pkts_rx);
    seq_printf(m, "TX: %llu\n", eng->stats.pkts_tx);
    seq_printf(m, "Queued: %llu\n", eng->stats.pkts_queued);
    seq_printf(m, "Dropped: %llu\n", eng->stats.pkts_dropped);

    seq_printf(m, "\n--- Traffic ---\n");
    seq_printf(m, "Bytes RX: %llu\n", eng->stats.bytes_rx);
    seq_printf(m, "Bytes TX: %llu\n", eng->stats.bytes_tx);
    seq_printf(m, "Avg Throughput: %u bps\n", eng->avg_throughput);

    seq_printf(m, "\n--- Queues ---\n");
    seq_printf(m, "High priority: %u / %u\n",
               eng->q_high ?  eng->q_high->size : 0, PKT_QUEUE_SIZE);
    seq_printf(m, "Low priority: %u / %u\n",
               eng->q_low ? eng->q_low->size : 0, PKT_QUEUE_SIZE);

    seq_printf(m, "\n--- Token Buckets ---\n");
    seq_printf(m, "DL Tokens: %llu / %u\n", eng->dl_tokens, eng->params.bucket_size);
    seq_printf(m, "UL Tokens: %llu\n", eng->ul_tokens);

    seq_printf(m, "\n--- Rate Control ---\n");
    seq_printf(m, "Current rate: %llu bps\n", eng->rate.current_rate);
    seq_printf(m, "Target rate: %llu bps\n", eng->rate.target_rate);
    seq_printf(m, "CWND: %u\n", eng->rate.cwnd);
    seq_printf(m, "SSThresh: %u\n", eng->rate.ssthresh);
    seq_printf(m, "Base RTT: %u us\n", eng->rate.base_rtt);
    seq_printf(m, "Last RTT: %u us\n", eng->rate.last_rtt);
    seq_printf(m, "RTT trend: %d\n", eng->rate.rtt_trend);
    seq_printf(m, "Loss rate: %u/1000\n", eng->rate.loss_rate);
    seq_printf(m, "State: %d\n", eng->rate.state);
    seq_printf(m, "Slow start: %s\n", eng->rate.in_slow_start ?  "YES" : "NO");
    seq_printf(m, "Pacing rate: %llu Bps\n", eng->rate.pacing_rate);

    seq_printf(m, "\n--- Parameters ---\n");
    seq_printf(m, "MSS: %u\n", eng->params.mss);
    seq_printf(m, "Min RTT: %u us\n", eng->params.min_rtt);
    seq_printf(m, "Max RTT: %u us\n", eng->params.max_rtt);
    seq_printf(m, "Max delay: %u us\n", eng->params.max_delay);
    seq_printf(m, "Bucket size: %u\n", eng->params.bucket_size);
    seq_printf(m, "ACK delay: %u ms\n", eng->params.ack_delay_ms);
    seq_printf(m, "Win inflate factor: %u\n", eng->params.win_inflate_factor);
    seq_printf(m, "Upload accel thresh: %u\n", eng->params.upload_accel_thresh);

    return 0;
}

static int tapac_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, tapac_stats_show, NULL);
}

/* 参数读写 */
static int tapac_param_show(struct seq_file *m, void *v)
{
    struct tapac_engine *eng = g_engine;
    const char *name = m->private;

    if (!eng || !name)
        return 0;

    if (strcmp(name, "debug") == 0)
        seq_printf(m, "%u\n", eng->params.debug);
    else if (strcmp(name, "nic") == 0)
        seq_printf(m, "%s\n", eng->params.nic);
    else if (strcmp(name, "mss") == 0)
        seq_printf(m, "%u\n", eng->params.mss);
    else if (strcmp(name, "min_rtt") == 0)
        seq_printf(m, "%u\n", eng->params.min_rtt);
    else if (strcmp(name, "max_rtt") == 0)
        seq_printf(m, "%u\n", eng->params.max_rtt);
    else if (strcmp(name, "max_delay") == 0)
        seq_printf(m, "%u\n", eng->params.max_delay);
    else if (strcmp(name, "bucket_size") == 0)
        seq_printf(m, "%u\n", eng->params.bucket_size);
    else if (strcmp(name, "ack_delay_ms") == 0)
        seq_printf(m, "%u\n", eng->params.ack_delay_ms);
    else if (strcmp(name, "win_inflate_factor") == 0)
        seq_printf(m, "%u\n", eng->params.win_inflate_factor);
    else if (strcmp(name, "upload_accel_thresh") == 0)
        seq_printf(m, "%u\n", eng->params.upload_accel_thresh);
    else if (strcmp(name, "use_ack_scheduler") == 0)
        seq_printf(m, "%u\n", eng->params.use_ack_scheduler);
    else if (strcmp(name, "generate_sack") == 0)
        seq_printf(m, "%u\n", eng->params.generate_sack);

    return 0;
}

static int tapac_param_open(struct inode *inode, struct file *file)
{
    return single_open(file, tapac_param_show, TAPAC_PDE_DATA(inode));
}

static ssize_t tapac_param_write(struct file *file, const char __user *buf,
                                  size_t count, loff_t *pos)
{
    struct seq_file *m = file->private_data;
    struct tapac_engine *eng = g_engine;
    const char *name = m->private;
    char kbuf[64];
    unsigned long val;
    char *p;
    int ret;

    if (!eng || !name)
        return -EINVAL;

    if (count > sizeof(kbuf) - 1)
        count = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    p = strchr(kbuf, '\n');
    if (p)
        *p = '\0';

    if (strcmp(name, "nic") == 0) {
        strncpy(eng->params.nic, kbuf, sizeof(eng->params.nic) - 1);
        eng->params.nic[sizeof(eng->params.nic) - 1] = '\0';
        return count;
    }

    ret = kstrtoul(kbuf, 10, &val);
    if (ret < 0)
        return ret;

    if (strcmp(name, "debug") == 0)
        eng->params.debug = (u32)val;
    else if (strcmp(name, "mss") == 0)
        eng->params.mss = (u32)val;
    else if (strcmp(name, "min_rtt") == 0)
        eng->params.min_rtt = (u32)val;
    else if (strcmp(name, "max_rtt") == 0)
        eng->params.max_rtt = (u32)val;
    else if (strcmp(name, "max_delay") == 0)
        eng->params.max_delay = (u32)val;
    else if (strcmp(name, "bucket_size") == 0)
        eng->params.bucket_size = (u32)val;
    else if (strcmp(name, "ack_delay_ms") == 0)
        eng->params.ack_delay_ms = (u32)val;
    else if (strcmp(name, "win_inflate_factor") == 0)
        eng->params.win_inflate_factor = (u32)val;
    else if (strcmp(name, "upload_accel_thresh") == 0)
        eng->params.upload_accel_thresh = (u32)val;
    else if (strcmp(name, "use_ack_scheduler") == 0)
        eng->params.use_ack_scheduler = (u32)val;
    else if (strcmp(name, "generate_sack") == 0)
        eng->params.generate_sack = (u32)val;

    return count;
}

#if defined(TAPAC_USE_PROC_OPS)
static const struct proc_ops tapac_stats_fops = {
    .proc_open = tapac_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops tapac_param_fops = {
    .proc_open = tapac_param_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = tapac_param_write,
};
#else
static const struct file_operations tapac_stats_fops = {
    .open = tapac_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static const struct file_operations tapac_param_fops = {
    .open = tapac_param_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = tapac_param_write,
};
#endif

static const char *param_names[] = {
    "debug", "nic", "mss", "min_rtt", "max_rtt", "max_delay",
    "bucket_size", "ack_delay_ms", "win_inflate_factor",
    "upload_accel_thresh", "use_ack_scheduler", "generate_sack",
    NULL
};

static int tapac_proc_init(struct tapac_engine *eng)
{
    int i;

    proc_dir = proc_mkdir("tapac", NULL);
    if (! proc_dir) {
        TAPAC_ERR("Failed to create /proc/tapac\n");
        return -ENOMEM;
    }

    if (! proc_create("stats", 0444, proc_dir, &tapac_stats_fops)) {
        TAPAC_ERR("Failed to create /proc/tapac/stats\n");
    }

    for (i = 0; param_names[i]; i++) {
        if (!proc_create_data(param_names[i], 0644, proc_dir,
                              &tapac_param_fops, (void *)param_names[i])) {
            TAPAC_ERR("Failed to create /proc/tapac/%s\n", param_names[i]);
        }
    }

    TAPAC_INFO("Created /proc/tapac\n");
    return 0;
}

static void tapac_proc_cleanup(void)
{
    int i;

    if (! proc_dir)
        return;

    remove_proc_entry("stats", proc_dir);

    for (i = 0; param_names[i]; i++) {
        remove_proc_entry(param_names[i], proc_dir);
    }

    remove_proc_entry("tapac", NULL);
    proc_dir = NULL;

    TAPAC_INFO("Removed /proc/tapac\n");
}

/* ============================================================
 * 参数默认值
 * ============================================================ */

static void tapac_params_default(struct tapac_params *p)
{
    p->debug = 0;
    strncpy(p->nic, "eth0", sizeof(p->nic) - 1);
    p->nic[sizeof(p->nic) - 1] = '\0';
    p->mss = 1460;
    p->min_win = 10;
    p->timer_interval_us = 1000;
    p->min_rtt = 20000;
    p->max_rtt = 500000;
    p->max_delay = 15000;
    p->bucket_size = 64 * 1024 * 1024;
    p->upload_accel_thresh = 10 * 1024;
    p->use_ack_scheduler = 1;
    p->generate_sack = 1;
    p->win_inflate_factor = 4;
    p->ack_delay_ms = 20;
}

/* ============================================================
 * 引擎初始化和清理
 * ============================================================ */

static int tapac_engine_init(struct tapac_engine *eng)
{
    ktime_t ktime;
    int i;

    tapac_params_default(&eng->params);

    if (param_dev && strlen(param_dev) > 0) {
        strncpy(eng->params.nic, param_dev, sizeof(eng->params.nic) - 1);
        eng->params.nic[sizeof(eng->params.nic) - 1] = '\0';
    }

    /* 清理换行符 */
    for (i = 0; i < (int)sizeof(eng->params.nic) && eng->params.nic[i]; i++) {
        if (eng->params.nic[i] == '\n') {
            eng->params.nic[i] = '\0';
            break;
        }
    }

    tapac_flow_table_init(&eng->ft);
    tapac_ack_init(eng);
    tapac_rate_init(eng);

    eng->dl_tokens = 0;
    spin_lock_init(&eng->dl_token_lock);
    eng->ul_tokens = 0;
    spin_lock_init(&eng->ul_token_lock);

    eng->q_high = tapac_queue_alloc(PKT_QUEUE_SIZE);
    if (!eng->q_high) {
        TAPAC_ERR("Failed to allocate high priority queue\n");
        return -ENOMEM;
    }

    eng->q_low = tapac_queue_alloc(PKT_QUEUE_SIZE);
    if (!eng->q_low) {
        TAPAC_ERR("Failed to allocate low priority queue\n");
        tapac_queue_free(eng->q_high);
        return -ENOMEM;
    }

    eng->traffic = 0;
    eng->total_rtt = 0;
    eng->samples = 0;
    eng->avg_rtt = eng->params.min_rtt;
    eng->avg_throughput = 0;
    eng->last_global_update = tapac_get_time_us();
    spin_lock_init(&eng->global_lock);

    memset(&eng->stats, 0, sizeof(eng->stats));

    tasklet_init(&dequeue_tasklet, tapac_dequeue_tasklet_func, (unsigned long)eng);

    ktime = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_init(&eng->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    eng->timer.function = tapac_timer_callback;

    eng->running = true;
    hrtimer_start(&eng->timer, ktime, HRTIMER_MODE_REL);

    return 0;
}

static void tapac_engine_cleanup(struct tapac_engine *eng)
{
    if (!eng)
        return;

    eng->running = false;
    hrtimer_cancel(&eng->timer);
    tasklet_kill(&dequeue_tasklet);
    tapac_ack_cleanup(eng);
    tapac_flow_table_cleanup(&eng->ft);

    if (eng->q_high) {
        tapac_queue_free(eng->q_high);
        eng->q_high = NULL;
    }
    if (eng->q_low) {
        tapac_queue_free(eng->q_low);
        eng->q_low = NULL;
    }
}

/* ============================================================
 * 模块入口
 * ============================================================ */

static int __init tapac_init(void)
{
    int ret;

    TAPAC_INFO("Loading module v4.0 - Standalone Edition\n");

    g_engine = kzalloc(sizeof(struct tapac_engine), GFP_KERNEL);
    if (!g_engine) {
        TAPAC_ERR("Failed to allocate engine\n");
        return -ENOMEM;
    }

    ret = tapac_engine_init(g_engine);
    if (ret) {
        kfree(g_engine);
        return ret;
    }

    tapac_proc_init(g_engine);

    nfho_in.hook = tapac_hook_in;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;

    nfho_out.hook = tapac_hook_out;
    nfho_out.hooknum = NF_INET_POST_ROUTING;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

#if defined(TAPAC_NF_NEW_HOOK_API)
    ret = nf_register_net_hook(&init_net, &nfho_in);
    if (ret)
        goto err_hook_in;
    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret)
        goto err_hook_out;
#else
    ret = nf_register_hook(&nfho_in);
    if (ret)
        goto err_hook_in;
    ret = nf_register_hook(&nfho_out);
    if (ret)
        goto err_hook_out;
#endif

    TAPAC_INFO("Module loaded successfully\n");
    TAPAC_INFO("  Interface: %s\n", g_engine->params.nic);
    TAPAC_INFO("  Bucket size: %u MB\n", g_engine->params.bucket_size / (1024 * 1024));
    TAPAC_INFO("  Max delay: %u us\n", g_engine->params.max_delay);
    TAPAC_INFO("  ACK scheduler: %s\n", g_engine->params.use_ack_scheduler ? "ON" : "OFF");
    TAPAC_INFO("  SACK generation: %s\n", g_engine->params.generate_sack ? "ON" : "OFF");
    TAPAC_INFO("  Win inflate factor: %u (dynamic)\n", g_engine->params.win_inflate_factor);

    return 0;

err_hook_out:
#if defined(TAPAC_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_in);
#endif
err_hook_in:
    tapac_proc_cleanup();
    tapac_engine_cleanup(g_engine);
    kfree(g_engine);
    g_engine = NULL;
    return ret;
}

static void __exit tapac_exit(void)
{
    TAPAC_INFO("Unloading module\n");

#if defined(TAPAC_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_out);
    nf_unregister_hook(&nfho_in);
#endif

    tapac_proc_cleanup();

    if (g_engine) {
        tapac_engine_cleanup(g_engine);
        kfree(g_engine);
        g_engine = NULL;
    }

    TAPAC_INFO("Module unloaded\n");
}

module_init(tapac_init);
module_exit(tapac_exit);