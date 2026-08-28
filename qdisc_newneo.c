// SPDX-License-Identifier: GPL-2.0-only
/*
 * NeoQ v3.1: High-Performance Queue Discipline for Linux
 *
 * Optimized for:
 * - Ultra-fast multi-tier packet transmission
 * - HTTP/HTTPS/TCP traffic prioritization
 * - Batch dequeuing for maximum throughput
 * - Low-latency CoDel AQM
 *
 * v3.1 Enhancements:
 * - Retransmit packet detection -> Express priority for fast loss recovery
 * - Flow state tracking (NEW/STARTUP/STEADY/RECOVERY/DRAIN)
 * - Loss protection levels for flows in recovery
 *
 * 本轮 (整形器) 新增:
 * - CAKE 式虚拟时钟整形器 (/proc/net/neoq_rate, 默认关闭): 把瓶颈从远端路由器
 *   "买"回本机。本机上联远快于洲际路径时本机根本不排队, 所有 AQM 全程空转
 *   (实测 qlen=0 / t3_drops=0 / t3_peak_delay_us=5), 分档/CoDel/重传免疫全部
 *   拿不到输入; 整形后队列在本机成形, 且丢弃从昂贵的洲际段挪回本机。
 * - 整形开启时拆分 GSO 超级包: 12Mbps 下一个 64KB 包 = 43ms 路径传输时间, 不拆
 *   则虚拟时钟粒度/DRR 公平粒度/CoDel 采样粒度全部退化成 43ms。
 * - Express 防滥用门改用相对阈值 (相对链路常态重传率), 见 neoq_retrans_rel。
 * - CoDel target/interval 只有一个真相: 全局 /proc/net/neoq_codel。netlink 的
 *   TCA_NEOQ_TARGET/INTERVAL 直写同一对全局量。RTT 自适应由用户态 lotspeedctl
 *   从 ss 测得后写入 —— egress-only qdisc 看不到入向 TSecr, 自己算不出 RTT。
 *
 * Copyright (c) 2024-2025 LotSpeed Project
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/hash.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/version.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>
#include <net/inet_ecn.h>
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
/* skb_gso_segment() 在 6.5 被从 netdevice.h 拆到 net/gso.h (上游 "net: move gso
 * declarations and functions to their own files")。GSO 拆分薄壳要用它, 6.5 以下
 * 仍由 net/sch_generic.h -> netdevice.h 间接带入, 故只在 6.5+ 显式包含。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#include <net/gso.h>
#endif

/* Kernel compatibility */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define nla_nest_start_noflag(skb, attr) nla_nest_start(skb, attr)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define kvzalloc(size, flags) vzalloc(size)
#define kvfree(ptr) vfree(ptr)
#endif

/* ========================================================================
 * Configuration
 * ======================================================================== */

#define NEOQ_VERSION            "3.1"

/* Flow configuration - optimized for performance */
#define NEOQ_QUEUES             1024
#define NEOQ_FLOW_HASH_BITS     10
#define NEOQ_SET_WAYS           8

/* Priority tiers */
#define NEOQ_MAX_TIERS          4
#define NEOQ_TIER_EXPRESS       0
#define NEOQ_TIER_HIGH          1
#define NEOQ_TIER_NORMAL        2
#define NEOQ_TIER_BULK          3

/* Scheduling */
#define NEOQ_QUANTUM            1514
#define NEOQ_QUANTUM_MIN        256
#define NEOQ_QUANTUM_MAX        65535

/* Limits */
#define NEOQ_LIMIT_DEFAULT      10240
#define NEOQ_MEMORY_LIMIT       (32 * 1024 * 1024)

/* AQM - CoDel parameters (default for normal RTT) */
#define NEOQ_TARGET_US          5000
#define NEOQ_INTERVAL_US        100000

/* 注: 原 NEOQ_RTT_*_US (RTT-aware CoDel 阈值) 已随该特性整体删除。egress-only
 * qdisc 算不出 RTT (需匹配出向 TSval 与入向 TSecr, 后者只存在于 ingress), 故
 * flow->srtt_us 恒为 0, 依赖它的分支恒假。RTT 自适应的职责已由用户态承担:
 * lotspeedctl 从 ss 取 RTT 后写 /proc/net/neoq_codel 全局旋钮 —— 那条路是活的。 */

/* Flow state for tracking */
#define FLOW_STATE_NEW          0
#define FLOW_STATE_STARTUP      1
#define FLOW_STATE_STEADY       2
#define FLOW_STATE_RECOVERY     3
#define FLOW_STATE_DRAIN        4

/* Loss protection levels */
#define LOSS_PROTECT_NONE       0
#define LOSS_PROTECT_LOW        1
#define LOSS_PROTECT_MED        2
#define LOSS_PROTECT_HIGH       3

/* Priority ports */
#define HTTP_PORT               80
#define HTTPS_PORT              443
#define DNS_PORT                53
#define SSH_PORT                22

/* Batch dequeue size */
#define NEOQ_BATCH_SIZE         8

/* ========================================================================
 * Netlink Attributes
 * ======================================================================== */

enum {
    TCA_NEOQ_UNSPEC,
    TCA_NEOQ_LIMIT,
    TCA_NEOQ_MEMORY,
    TCA_NEOQ_QUANTUM,
    TCA_NEOQ_TARGET,
    TCA_NEOQ_INTERVAL,
    TCA_NEOQ_ECN,
    TCA_NEOQ_HTTP_BOOST,
    TCA_NEOQ_FLOWS,
    TCA_NEOQ_PAD,
    /* 追加在尾部以保持既有编号不变。仅为 dump 完整性: 整形速率的主控制面是
     * /proc/net/neoq_rate, 因为 stock tc 不认识 neoq 的私有属性, 根本发不出
     * 这个 TLV。单位 = bit/s, 与 /proc 的 rate_kbps 同口径 (不引入第二种单位)。 */
    TCA_NEOQ_RATE64,
    __TCA_NEOQ_MAX
};
#define TCA_NEOQ_MAX (__TCA_NEOQ_MAX - 1)

/* Statistics attributes - for tc -s display (like CAKE) */
enum {
    TCA_NEOQ_STATS_UNSPEC,
    TCA_NEOQ_STATS_MEMORY_USED,
    TCA_NEOQ_STATS_MEMORY_LIMIT,
    TCA_NEOQ_STATS_FLOWS_TOTAL,
    TCA_NEOQ_STATS_FLOWS_ACTIVE,
    TCA_NEOQ_STATS_AVG_DELAY_US,
    TCA_NEOQ_STATS_PEAK_DELAY_US,
    TCA_NEOQ_STATS_BASE_DELAY_US,
    TCA_NEOQ_STATS_TIN_STATS,
    TCA_NEOQ_STATS_PAD,
    __TCA_NEOQ_STATS_MAX
};
#define TCA_NEOQ_STATS_MAX (__TCA_NEOQ_STATS_MAX - 1)

/* Per-tier stats attributes */
enum {
    TCA_NEOQ_TIN_STATS_UNSPEC,
    TCA_NEOQ_TIN_STATS_PACKETS,
    TCA_NEOQ_TIN_STATS_BYTES64,
    TCA_NEOQ_TIN_STATS_DROPPED,
    TCA_NEOQ_TIN_STATS_ECN_MARKED,
    TCA_NEOQ_TIN_STATS_BACKLOG,
    TCA_NEOQ_TIN_STATS_FLOWS,
    TCA_NEOQ_TIN_STATS_AVG_DELAY_US,
    TCA_NEOQ_TIN_STATS_PEAK_DELAY_US,
    TCA_NEOQ_TIN_STATS_BASE_DELAY_US,
    TCA_NEOQ_TIN_STATS_WAY_INDIRECT,
    TCA_NEOQ_TIN_STATS_WAY_MISS,
    TCA_NEOQ_TIN_STATS_WAY_COLLIDE,
    TCA_NEOQ_TIN_STATS_PAD,
    __TCA_NEOQ_TIN_STATS_MAX
};
#define TCA_NEOQ_TIN_STATS_MAX (__TCA_NEOQ_TIN_STATS_MAX - 1)

/* Stats structure for tc display */
struct neoq_xstats {
    __u32 memory_used;
    __u32 memory_limit;
    __u32 flows_total;
    __u32 flows_active;

    /* Per-tier stats */
    __u32 tier_packets[NEOQ_MAX_TIERS];
    __u32 tier_bytes[NEOQ_MAX_TIERS];
    __u32 tier_drops[NEOQ_MAX_TIERS];
    __u32 tier_marks[NEOQ_MAX_TIERS];
    __u32 tier_backlog[NEOQ_MAX_TIERS];
    __u32 tier_flows[NEOQ_MAX_TIERS];

    /* Delay stats (microseconds) */
    __u32 avg_delay_us;
    __u32 peak_delay_us;
    __u32 base_delay_us;
};

/* ========================================================================
 * SKB Control Block
 * ======================================================================== */

struct neoq_skb_cb {
    u64     enqueue_time;
    u32     adjusted_len;
    /* === NEW: retrans 免疫标记 ===
     * retrans 判定发生在 enqueue (classify 路径), 丢弃判定在 dequeue (CoDel)。
     * 该标记随 skb 旅行, 使 dequeue 无需在 highest_seq 已前移后重新解析 TCP seq。
     * cb 布局: 8(enqueue_time)+4(adjusted_len)+1(is_retrans)=13B, 经 u64 对齐 ->
     * sizeof(struct)=16B <= QDISC_CB_PRIV_LEN(20B), 由下方 validate 保证。 */
    u8      is_retrans;
};

static struct neoq_skb_cb *get_neoq_cb(const struct sk_buff *skb)
{
    qdisc_cb_private_validate(skb, sizeof(struct neoq_skb_cb));
    return (struct neoq_skb_cb *)qdisc_skb_cb(skb)->data;
}

/* ========================================================================
 * Per-Flow Structure (Enhanced for retransmit detection & RTT-aware)
 * ======================================================================== */

struct neoq_flow {
    struct sk_buff      *head;
    struct sk_buff      *tail;
    struct list_head    flowchain;
    s32                 deficit;
    u32                 backlog;
    u32                 dropped;

    /* CoDel state */
    u32                 count;
    u32                 rec_inv_sqrt;
    u64                 drop_next;
    u8                  dropping:1;
    u8                  ecn_marked:1;

    /* Classification */
    u8                  set;
    u8                  tier;

    /* === NEW: Retransmit detection === */
    u32                 highest_seq;        /* Highest seq seen (for retrans detect) */
    u32                 retrans_count;      /* Retransmit packet count */
    u32                 total_packets;      /* Total packets for this flow */

    /* === NEW: Flow state tracking === */
    u8                  flow_state;         /* FLOW_STATE_* */
    u8                  loss_protect_level; /* LOSS_PROTECT_* */
    u16                 startup_packets;    /* Packets in startup phase */

    /* 注: 原 srtt_us / rtt_min_us / last_rtt_update 已删除 (见文件头): egress-only
     * qdisc 拿不到 RTT, 三者恒为 0, 唯一读它们的 CoDel 分支恒假, 属纯死代码。 */

    /* === NEW: CAKE 风格稀疏/批量行为门控 ===
     * 在一个滑动窗口内累计 flow 的字节数，窗口到期后衰减/重置。
     * 若窗口内速率低于稀疏阈值, flow 仍可享受 Express/High; 持续高于阈值则被
     * 降级到按包大小决定的档位 (Normal/Bulk), 即便命中 hint 端口。 */
    u32                 bytes_window;       /* 当前窗口内累计字节 */
    u64                 window_start;       /* 当前窗口起点 (ns) */
    u8                  is_bulk_behave:1;   /* 1=已判定为批量(降级), 0=稀疏 */

    /* === NEW (FIX1): 近窗 retrans 占比 (Express 防滥用) ===
     * retrans_count/total_packets 是累积量, 无法反映"近期"丢包压力。这里搭车
     * sparse 门控的 100ms 窗口: window_pkts/window_retrans 随该窗口一起重置,
     * 窗口滚动时用刚结束窗口算出占比存入 prev_retrans_share (u8 百分比 0-100)。
     * 分类时读 prev_retrans_share (上一完整窗口), 仅当它 > 旋钮阈值且 flow 已被判为
     * 批量行为时, 才停止把该流的重传提到 Express (重传仍保留 CoDel 免疫, 只是不插队)。
     * 全部塞进结构尾部既有 padding (offset 121-125), 不增大 struct, 不跨 cacheline。 */
    u16                 window_pkts;        /* 当前窗口内包数 (含重传) */
    u16                 window_retrans;     /* 当前窗口内重传包数 */
    u8                  prev_retrans_share; /* 上一完整窗口的重传占比, 0-100% */
} ____cacheline_aligned_in_smp;

enum {
    FLOW_NONE = 0,
    FLOW_NEW,
    FLOW_SPARSE,
    FLOW_BULK,
};

/* ========================================================================
 * NEW (FIX2): 分类计算结果 (compute-then-commit)
 *
 * 旧实现里 classify_packet_enhanced 直接改写 flow 检测状态 (highest_seq 前移、
 * retrans_count++、sparse 窗口累加/滚动、is_bulk_behave 翻转), 但限额丢弃判定在
 * 其后: 一旦本包被丢, flow 状态已被一个从未入队的包推进 -> 该段后续真正发送会被误
 * 判为重传, 且被丢字节抬高 sparse 速率导致错误降级。
 *
 * 修复: classify 只"计算"(读 flow, 不写), 把所有待写状态收进本结构; 仅当包被接受
 * 入队后, 由 neoq_commit_classify() 一次性提交。保持单次分类 (不重复解析头部)。
 * 注: 窗口滚动 (window_start/bytes_window 重置 + prev_retrans_share 计算) 也只在
 * 接受时提交; 一个 100% 被丢的区间只是延长当前窗口, 这是可接受且更简单的语义。 */
struct neoq_classify_result {
    /* tier 决策仍由 classify_packet_enhanced 的返回值带出, 不入本结构。 */
    bool    is_retrans;         /* retrans 判定 (供 cb 标记 / Express 提权) */
    bool    retrans_demoted_hint; /* FIX1: 本重传被防滥用门控拒绝 Express, 调用方计数 */

    /* --- seq 跟踪待写 (源自只读 tcp_retransmit_compute) --- */
    bool    seq_update;         /* 是否需要把 highest_seq 写成 new_highest_seq */
    u32     new_highest_seq;    /* seq_update 时的目标值 */
    bool    count_retrans;      /* 是否需要 retrans_count++ (=is_retrans 的 TCP 真值) */

    /* --- sparse 窗口待写 (源自只读 flow_sparse_compute) ---
     * compute 已算出本包提交后窗口各字段的"终值", commit 仅照抄, 无需再判分支。 */
    bool    win_touched;        /* 本包是否参与了窗口逻辑 (>=128B 且 flow 非空且 thresh!=0) */
    u64     win_start_set;      /* 提交后 window_start 的终值 (ns) */
    u32     win_bytes_set;      /* 提交后 bytes_window 的终值 */
    u16     win_pkts_set;       /* 提交后 window_pkts 的终值 */
    u16     win_retrans_set;    /* 提交后 window_retrans 的终值 */
    bool    win_prev_share_upd; /* 是否需要写 prev_retrans_share (仅窗口滚动时) */
    u8      win_prev_share_set; /* win_prev_share_upd 时写入的 prev_retrans_share */
    bool    win_bulk_set;       /* 提交后 is_bulk_behave 的终值 */
};

/* ========================================================================
 * Per-Tier Structure
 * ======================================================================== */

struct neoq_tier {
    /* 注: flows/backlogs/tags 已上移为全局表 (见 neoq_sched_data),
     * 一个 5-tuple 只对应一个 neoq_flow; 每个 tier 仍各自持有 DRR 链表。 */
    struct list_head    new_flows;
    struct list_head    old_flows;

    /* === NEW: 跨档位防饿死 WRR 的每档字节赤字 === */
    s64                 tier_deficit;       /* 按权重补充, 工作保持 */

    u32                 sparse_cnt;
    u32                 bulk_cnt;
    u32                 backlog;

    /* Stats */
    u64                 packets;
    u64                 bytes;
    u32                 dropped;
    u32                 ecn_marked;

    /* Delay tracking */
    u64                 avg_delay;
    u64                 peak_delay;
    u64                 base_delay;
    /* === NEW: 供 /proc/net/neoq_ml 的"近期峰值", read-on-reset 语义 ===
     * 与 peak_delay 同步更新, 但仅 neoq_ml 读取时清零, 使 tuner 看到最近窗口的峰值
     * 而非全时段峰值。human-readable 的 /proc/net/neoq 仍用 peak_delay (全时段)。 */
    u64                 peak_delay_ml;

    /* 注: 原每档 codel_interval/codel_target 已删除 —— 它们只被赋值、从未被读
     * (codel_should_drop 一直只读全局 neoq_codel_target_ns/interval_ns), 是
     * netlink 与 /proc 之外的第三份影子真相, 留着只会误导后来者。 */

    u32                 quantum;
} ____cacheline_aligned_in_smp;

/* ========================================================================
 * Main Scheduler Structure
 * ======================================================================== */

struct neoq_sched_data {
    struct neoq_tier    *tiers;

    /* === NEW: 全局 5-tuple 流表 (替代每档独立表), 一份实例, 保持原集合相联方案 ===
     * 一条 TCP 连接的状态 (highest_seq/srtt/retrans/CoDel) 不再被切碎到 4 个档位。 */
    struct neoq_flow    *flows;         /* NEOQ_QUEUES 项 */
    u32                 *backlogs;       /* 每槽 backlog 镜像 (与 flow->backlog 同步) */
    u32                 *tags;           /* 集合相联 tag 表 */

    /* 全局哈希表统计 (原为每档, 因表已全局而上移) */
    u32                 way_indirect;
    u32                 way_miss;
    u32                 way_collide;

    /* Config */
    u32                 limit;
    u32                 quantum;
    u32                 memory_limit;
    u32                 memory_used;
    /* 注: 原 q->target / q->interval 已删除。CoDel 参数的唯一真相是全局
     * neoq_codel_target_ns / neoq_codel_interval_ns, netlink 与 /proc 都直接
     * 读写它 —— 消除"netlink 一份、/proc 一份"的双真相。 */

    /* Features */
    u8                  ecn:1;
    u8                  http_boost:1;

    /* State */
    u16                 cur_tier;
    u16                 cur_flow;
    u32                 perturbation;
    u32                 flows_cnt;

    /* Global stats */
    u64                 total_packets;
    u64                 total_bytes;

    /* === NEW: retrans 免疫效果计数 (供 /proc/net/neoq_ml) ===
     * retrans_seen: enqueue 处判为 retrans 的包数;
     * retrans_protected: dequeue 处本应被 CoDel 丢弃、却因免疫而保留(交付或仅 ECN 标记)
     *   的 retrans 包数 -> 即本特性的有效性计数。 */
    u64                 retrans_seen;
    u64                 retrans_protected;
    /* === NEW (FIX1): 被 Express 防滥用门控拒绝提权的重传包数 ===
     * 即"本应进 Express、但因所在批量流近窗重传占比过高而被留在原档位"的重传计数。
     * 供 /proc/net/neoq_ml 观察门控的触发量。 */
    u64                 retrans_demoted;

    /* === NEW (B3): 全局 ambient 重传占比, 供 Express 防滥用门算相对阈值 ===
     * 为什么必须相对: 绝对阈值 (share_max=15%) 在整体重传率 18-20% 的洲际链路上
     * 永远触发 —— 实测 retrans_seen=6602 / retrans_demoted=5133 = 77.7% 的重传被
     * 拒绝升 Express。该门本意是防"批量流的重传洪泛挤占交互快车道", 结果把正常的
     * 丢包恢复也一并拦了。在 18% 丢包的链路上重传 18% 不是滥用, 是生存。
     * 1 秒滚动窗口; 全部在持 root lock 的 enqueue 路径内累加, 无并发问题。 */
    u32                 glob_win_pkts;
    u32                 glob_win_retrans;
    u64                 glob_win_start;
    u8                  ambient_share;      /* 上一完整 1s 窗口的全局重传占比 0-100 */

    /* === NEW (B1): CAKE 式虚拟时钟整形器状态 ===
     * time_next_packet: 下一个包被允许离开 qdisc 的虚拟时刻 (ns, 与 ktime_get_ns
     * 同一时钟域)。shaper_sent_bytes / shaper_defer_cnt 供 /proc/net/neoq_rate 与
     * neoq_ml 观测整形器是否真的在起作用 (defer=0 就说明根本没排到队)。 */
    u64                 time_next_packet;
    u64                 shaper_sent_bytes;
    u64                 shaper_defer_cnt;

    /* 整形闸门靠它把 qdisc 重新唤醒。注: 该字段在 v3.1 里就已存在, 但全文件从未被
     * schedule 过 —— 是预留却没接上的死设施, 从 B1 起真正接上。 */
    struct qdisc_watchdog watchdog;
};

/* Global for proc stats access */
static struct Qdisc *neoq_active_qdisc;
static DEFINE_SPINLOCK(neoq_lock);

/* ========================================================================
 * CoDel Helpers
 * ======================================================================== */

#define REC_INV_SQRT_CACHE 16
static const u32 inv_sqrt_cache[REC_INV_SQRT_CACHE] = {
    ~0U, ~0U, 3037000500U, 2479700525U,
    2147483647U, 1920767767U, 1753413056U, 1623345051U,
    1518500250U, 1431655765U, 1358187914U, 1294981364U,
    1239850263U, 1191209601U, 1147878294U, 1108955788U
};

static inline void codel_newton_step(struct neoq_flow *f)
{
    u32 invsqrt = f->rec_inv_sqrt;
    u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
    u64 val = (3LL << 32) - ((u64)f->count * invsqrt2);
    val = (val >> 2) * invsqrt >> (32 - 2 + 1);
    f->rec_inv_sqrt = (u32)val;
}

static inline void codel_cache_invsqrt(struct neoq_flow *f)
{
    if (f->count < REC_INV_SQRT_CACHE)
        f->rec_inv_sqrt = inv_sqrt_cache[f->count];
    else
        codel_newton_step(f);
}

static inline u64 codel_control_law(u64 t, u64 interval, u32 inv_sqrt)
{
    return t + reciprocal_scale(interval, inv_sqrt);
}

/* ========================================================================
 * Queue Helpers
 * ======================================================================== */

static inline void flow_queue_add(struct neoq_flow *flow, struct sk_buff *skb)
{
    if (!flow->head)
        flow->head = skb;
    else
        flow->tail->next = skb;
    flow->tail = skb;
    skb->next = NULL;
}

static inline struct sk_buff *flow_dequeue(struct neoq_flow *flow)
{
    struct sk_buff *skb = flow->head;
    if (skb) {
        flow->head = skb->next;
        skb_mark_not_on_list(skb);
    }
    return skb;
}

/* ========================================================================
 * NEW: Retransmit Packet Detection (FIX2: 只读计算版)
 *
 * Detect retransmit by checking if TCP seq < highest_seq seen.
 * Retransmit packets get Express priority for faster loss recovery.
 *
 * 本函数为只读: 仅读取 flow->highest_seq, 把待写状态填入 res (seq_update/
 * new_highest_seq/count_retrans), 绝不改 flow。原地写回由 neoq_commit_classify()
 * 在包被接受后完成。判定逻辑与原 is_tcp_retransmit 逐分支等价。
 * 返回值 = 本包是否为重传 (= res->count_retrans)。 */
static __always_inline bool tcp_retransmit_compute(const struct sk_buff *skb,
                                                    const struct neoq_flow *flow,
                                                    struct neoq_classify_result *res)
{
    const struct iphdr *iph;
    const struct tcphdr *th;
    u32 seq, end_seq;
    int offset;

    if (skb->protocol != htons(ETH_P_IP))
        return false;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return false;

    offset = iph->ihl << 2;
    th = (const struct tcphdr *)((const u8 *)iph + offset);
    if ((const u8 *)(th + 1) > skb_tail_pointer(skb))
        return false;

    seq = ntohl(th->seq);
    end_seq = seq + (ntohs(iph->tot_len) - offset - (th->doff << 2));

    /* First packet for this flow - initialize (待写: highest_seq = end_seq) */
    if (flow->highest_seq == 0 && !th->syn) {
        res->seq_update = true;
        res->new_highest_seq = end_seq;
        return false;
    }

    /* SYN packet - reset tracking (待写: highest_seq = end_seq) */
    if (th->syn) {
        res->seq_update = true;
        res->new_highest_seq = end_seq;
        return false;
    }

    /* Retransmit detection: seq < highest_seq means retransmit
     * (待写: retrans_count++, 由 count_retrans 表达; 不前移 highest_seq) */
    if (before(seq, flow->highest_seq)) {
        res->count_retrans = true;
        return true;
    }

    /* Update highest seq for new data (待写: highest_seq = end_seq) */
    if (after(end_seq, flow->highest_seq)) {
        res->seq_update = true;
        res->new_highest_seq = end_seq;
    }

    return false;
}

/* ========================================================================
 * 注: 原 update_flow_codel_params() (RTT-aware CoDel 动态 target/interval) 已整体
 * 删除 —— 全文件零调用点, 且它唯一的输入 rtt_us 无从获得。
 *
 * 为什么是删而不是修: 出向 qdisc 要算 RTT, 得把出向包的 TCP TSval 与入向 ACK 的
 * TSecr 配对, 而后者只出现在 ingress —— egress-only 的 qdisc 结构上就拿不到。
 * RTT 自适应的职责已由用户态承担: lotspeedctl 从 ss 读 RTT, 写 /proc/net/neoq_codel
 * 的全局 target/interval。那条路是活的, 内核这份是死的。
 * ======================================================================== */

/* ========================================================================
 * NEW: Flow State Management
 *
 * Track flow lifecycle for smarter scheduling:
 * - NEW: First packets, needs quick delivery
 * - STARTUP: Building up cwnd, sensitive to loss
 * - STEADY: Normal operation
 * - RECOVERY: After loss, needs priority
 * - DRAIN: Winding down
 * ======================================================================== */

static inline void update_flow_state(struct neoq_flow *flow, bool is_retrans)
{
    flow->total_packets++;

    switch (flow->flow_state) {
    case FLOW_STATE_NEW:
        if (flow->total_packets >= 3)
            flow->flow_state = FLOW_STATE_STARTUP;
        break;

    case FLOW_STATE_STARTUP:
        flow->startup_packets++;
        if (is_retrans) {
            /* Loss during startup - transition to recovery */
            flow->flow_state = FLOW_STATE_RECOVERY;
            flow->loss_protect_level = LOSS_PROTECT_MED;
        } else if (flow->startup_packets >= 10) {
            flow->flow_state = FLOW_STATE_STEADY;
        }
        break;

    case FLOW_STATE_STEADY:
        if (is_retrans) {
            flow->flow_state = FLOW_STATE_RECOVERY;
            /* Set protection level based on retrans rate */
            if (flow->total_packets > 0) {
                u32 loss_rate = (flow->retrans_count * 1000) / flow->total_packets;
                if (loss_rate > 50)      /* >5% loss */
                    flow->loss_protect_level = LOSS_PROTECT_HIGH;
                else if (loss_rate > 10) /* >1% loss */
                    flow->loss_protect_level = LOSS_PROTECT_MED;
                else
                    flow->loss_protect_level = LOSS_PROTECT_LOW;
            }
        }
        break;

    case FLOW_STATE_RECOVERY:
        if (!is_retrans && flow->total_packets > flow->retrans_count + 10) {
            /* Recovery successful, back to steady */
            flow->flow_state = FLOW_STATE_STEADY;
            flow->loss_protect_level = LOSS_PROTECT_NONE;
        }
        break;

    case FLOW_STATE_DRAIN:
        /* Stay in drain until flow becomes inactive */
        break;
    }
}

/* ========================================================================
 * Traffic Classification - Enhanced with Retransmit Priority
 * ======================================================================== */

/*
 * Classification priority (highest to lowest):
 * 行为分类 (CAKE 风格稀疏流), 由高到低:
 * 1. Retransmit 包 -> EXPRESS (最快丢包恢复, 现因全局流表而可靠)
 * 2. 纯 ACK / pkt_len<128 / SYN|FIN|RST -> EXPRESS (无条件)
 * 3. hint 端口 (http_boost + 配置位图) 仅对 *小包* (<256B) 提权到 EXPRESS/HIGH;
 *    大包 (>=1400B) 永远不会因端口 hint 进 EXPRESS。
 * 4. 每流行为门控: 窗口内速率低于稀疏阈值 -> 保持 Express/High;
 *    持续高于阈值 -> 降级到按包大小的档位 (Normal/Bulk), 即便命中 hint 端口。
 * 5. 小交互包 (<256B) -> HIGH
 * 6. 大包 (>=1400B) -> BULK
 * 7. 其余 -> NORMAL
 */
/* Configurable priority-port bitmap (game/web boost), set via /proc/net/neoq_prio */
static DECLARE_BITMAP(neoq_prio_portmap, 65536);

/* 注: 原 neoq_rwnd_boost 旋钮 / neoq_boost_rwnd() / /proc/net/neoq_boost 已整体删除。
 * 真正的死因: 它只改写了线上 TCP 头的 window 字段, 却没有同步本机的 tp->rcv_wnd。
 * 对端据此多发出来的数据到达本机入向时, 会被 tcp_sequence() 判为 out-of-window 直接
 * 丢弃 —— 对上传方向是净伤害, 而不只是 no-op。
 * (原注释把死因写成"egress 拿不到对端 wscale", 那是错的: 乘法对 scale 不变,
 *  字段 x k 就是有效窗口 x k, 与 wscale 的 shift 无关。留此更正供后人查。) */

/* === NEW: CAKE 风格稀疏门控旋钮 (runtime-tunable via /proc/net/neoq_sparse) ===
 * window_ns: 行为采样窗口 (默认 100ms); thresh_bytes: 窗口内字节阈值, 超过即判为
 * 批量并降级。默认阈值 = 2*NEOQ_QUANTUM ≈ 3028B/100ms ≈ 0.24Mbps, 一次网页突发
 * (几百 KB) 会瞬间超过 -> 但网页流多为短突发, 窗口到期 (空闲)后迅速重新稀疏化;
 * 持续下载在数个窗口内即被钉为批量。0 阈值表示禁用降级 (永远稀疏)。 */
static u64 neoq_sparse_window_ns = 100ULL * NSEC_PER_MSEC;
static u32 neoq_sparse_thresh_bytes = 2 * NEOQ_QUANTUM;

/* === NEW (FIX1): Express 防滥用阈值 (runtime-tunable via /proc/net/neoq_retrans) ===
 * 一条批量流在 10% 丢包链路上会重传约 10% 的海量包; 若每个重传都进 Express, 这些重传
 * 会排在真正的交互包前面 (丢包下的优先级反转)。当某流上一完整窗口的重传占比超过本阈值
 * 且该流已被判为批量行为(is_bulk_behave)时, 其重传不再提到 Express, 而是留在按行为决定
 * 的档位(批量流即 Normal/Bulk)。重传仍保留 CoDel 免疫(永不被 CoDel 丢), 只是不再插队。
 * 稀疏/交互流的重传(量本来就小)不受影响, 继续进 Express。
 * B3 起 share_max 的语义降级为"下限地板": 有效阈值 = max(share_max, ambient*rel/100)。
 * 链路很干净时 ambient≈0, 地板防止阈值塌到 0 而误杀正常突发。
 * 默认 15(%)。0 = 关闭本门控 = 旧行为(所有重传一律进 Express)。 */
static u32 neoq_retrans_share_max = 15;

/* === NEW (B3): Express 防滥用门的相对倍数 (百分比, 200 = 常态的 2 倍) ===
 * 有效阈值 = max(neoq_retrans_share_max, min(100, rel * ambient_share / 100))。
 * ambient_share 是全链路上一秒的整体重传占比 (见 struct neoq_sched_data)。
 * green1 实测 ambient≈18-20%, rel=200 -> 有效阈值 36-40%, 只有重传占比达到链路常态
 * 两倍以上的流才被判为滥用; 预期把 demoted/seen 从 77.7% 压到 <10%。
 * 写侧钳到 <=10000, 保证 rel * ambient(<=100) 不会在 u32 里溢出。 */
static u32 neoq_retrans_rel = 200;

/* Global CoDel target/interval (ns), runtime-tunable via /proc/net/neoq_codel.
 * Default 5ms/100ms suits LAN; raise target for high-RTT intercontinental links
 * (else CoDel over-drops and starves the CC -> low goodput). */
static u64 neoq_codel_target_ns = (u64)NEOQ_TARGET_US * 1000;
static u64 neoq_codel_interval_ns = (u64)NEOQ_INTERVAL_US * 1000;

/* ========================================================================
 * NEW (B1): CAKE 式虚拟时钟整形器旋钮 (runtime-tunable via /proc/net/neoq_rate)
 *
 * 为什么要在本机整形: 本机上联 (日本机房) 远快于洲际路径, 队列和瓶颈全都在远端
 * 路由器上 (实测 ~300ms 常驻队列在远端), 本机 qdisc 根本不排队 -> qlen 恒为 0,
 * CoDel/分档/重传免疫全部空转。整形器把瓶颈"买"回本机 (CAKE/SQM 思路): 队列在本机
 * 成形, AQM 才有输入; 同时把丢弃从昂贵的洲际段挪到本机, 丢一个包不再浪费一整程
 * RTT 的传输。
 *
 * 为什么是虚拟时钟而不是 token bucket:
 *   TBF 的桶会在空闲期积攒 token, 恢复发送时线速倾泻一个 burst。为容纳 64KB 的
 *   GSO 包, 桶至少得 64KB —— 在 12Mbps 下就是 43ms 的线速突发, 与"控延迟"这个
 *   目标直接冲突。虚拟时钟逐包平滑推进, 无桶、无倾泻; 空闲期的额度由 burst_ns
 *   地板钳死 (见 neoq_dequeue), 只用来吸收 hrtimer 的迟到抖动。
 *
 * 为什么把 (mult, shift) 打包进单个 u64 而不用 psched_ratecfg_precompute():
 *   psched_ratecfg 是多字段结构, /proc 高频写 vs dequeue 热路径读会撕裂 (读到新
 *   mult 配旧 shift = 速率算错几个数量级), 除非上锁。打包进一个 u64 后一次
 *   READ_ONCE 取整, 免锁且天然无撕裂。
 * ======================================================================== */

/* 0 = 关闭整形 = 透明直通。默认 0 (fail-open: 没配就跟改动前逐字一样)。单位 bit/s。 */
static u64 neoq_rate_bps;
/* 打包的 (mult << 8) | shift, 写侧预计算。0 = 关闭 (dequeue 闸门只看这一个量)。 */
static u64 neoq_rate_cfg;
/* 允许虚拟时钟落后 now 的上限, 只吸收 hrtimer 迟到抖动, 不是 TBF 的桶。 */
static u64 neoq_burst_ns = 4 * NSEC_PER_MSEC;

/* === F5: burst 的上钳 ===
 * 原来错在: /proc 写进来的 burst_us 是 sscanf 的 %u, 直接 *NSEC_PER_USEC 落盘, 毫无
 * 上界。echo "12000 4294967295" 就得到 4295 秒的 burst, dequeue 里 floor = now-burst
 * 把 time_next_packet 永久拽到 71 分钟前 -> 闸门 now < time_next_packet 永远不成立,
 * 整形器实际被关掉, 而读回来的 rate_kbps 仍是用户设的值 —— 最难查的那类静默失效。
 * 1 秒已远超任何 hrtimer 迟到抖动 (burst 的唯一用途), 够用且不会把它变成 TBF 的桶。 */
#define NEOQ_BURST_US_MAX       1000000U

/* === F1: 整形开启时队列上界必须随速率派生, 不能固定在 q->limit ===
 * 原来错在: 拆 GSO 会静默打掉 TCP Small Queues。skb_segment() 只在
 * head_skb->destructor == sock_wfree 时才把 socket 所有权转给尾段, 而 TCP 出向包的
 * destructor 是 tcp_wfree (__tcp_transmit_skb 设的), 不匹配; __copy_skb_header() 也
 * 明确不复制 old->sk。于是拆出来的每一段都是 sk=NULL / destructor=NULL, 而拆分末尾的
 * consume_skb(skb) 在**入队时刻**就调用 tcp_wfree() 把整个 64KB 的 sk_wmem_alloc 还了
 * 回去 -> tcp_small_queue_check 从此永不触发。
 * (mainline sch_tbf/sch_cake 拆 GSO 时行为完全相同 —— 这是 qdisc 层拆包的固有代价,
 *  不是写错。错的是 NeoQ 把 limit 固定在 10240 段、没有随 rate 缩放。)
 * 后果: TSQ 原本用 sk_wmem_alloc > max(2*truesize,...) 把单个 socket 在 qdisc 里的
 * 驻留量卡在 ~132KB ≈ 88ms; 拆分后唯一的上界退化成 q->limit=10240 段 ≈ 14.8MB,
 * 在 12Mbps 下 = 9.9 秒常驻队列 (memory_limit 32MB 要到 ~14200 段才拦, 先撞不上)。
 * 那正是整形器要消灭的东西, 只是从洲际段搬到了本机。
 * 修法: 上界的单位改成"时间", 由速率换算成段数。
 * 12Mbps/100ms -> 100 段; 100Mbps -> 833 段; 1Gbps -> 8333 段 (仍在 q->limit 之下)。 */
#define NEOQ_QUEUE_MS_DEFAULT   100U
#define NEOQ_QUEUE_MS_MAX       10000U  /* 上钳: 防 rate_bytes*queue_ms 溢出成天文数字 */
#define NEOQ_QUEUE_MSS          1500U   /* 换算段数用的名义段长 (拆分后每段 ~1 MSS) */
/* 下钳 64 段: 只在 rate < 64*MSS*1000/queue_ms ≈ 7.7Mbps(@100ms) 时才真正生效, 而那个
 * 速率区间必然低于 neoq_split_gso_thresh(300Mbps), GSO 一定被拆成"每 skb 记 1 段",
 * 64 段足够让队列跑起来; 即便分段失败回退整包, 64KB 超级包最多 45 段也仍在 64 之内。 */
#define NEOQ_QUEUE_MIN_PKTS     64U

/* 队列的时间目标 (ms), 可经 /proc/net/neoq_rate 第三个字段调。 */
static u32 neoq_queue_ms = NEOQ_QUEUE_MS_DEFAULT;
/* 由 rate 与 neoq_queue_ms 派生的段数上界。0 = 整形关闭 -> enqueue 退回 q->limit,
 * 逐字保持改动前行为 (与 neoq_rate_cfg 的 fail-open 语义一致)。 */
static u32 neoq_limit_pkts;

/* 整形开启且速率低于该阈值 (bit/s) 时才拆 GSO 超级包; 高于它不拆 (拆分本身的
 * 代价在高速下超过收益, 且高速下一个 64KB 包的传输时间已经可以忽略)。 */
static u32 neoq_split_gso_thresh = 300000000U;   /* 300 Mbps */

/* 写侧预计算: len_ns = plen * NSEC_PER_SEC / rate_Bps 变成一次乘法 + 一次右移。
 * 溢出验算: rate_Bps>=1 => mult_init = 2^20 * 1e9 / rate_Bps < 2^50, 最多右移 18 次
 * 即可 <= U32_MAX, 故 shift 落在 [2,20], 绝不会减到负数。
 * 读侧 len_ns = ((u64)plen * (u32)(cfg>>8)) >> (u8)cfg:
 *   常规 GSO plen <= 2^16, mult <= 2^32 -> 乘积 <= 2^48; 即便 BIG TCP 把 skb->len
 *   顶到 512KB (2^19) 也只有 2^51, 距 u64 溢出还差 13 位。mult<<8 <= 2^40 不溢出。
 * 精度下界: 结果按 ns 取整, 故 rate 很高时小包会算成 0 ns (1Gbps 下 64B = 0.512ns)。
 *   这是 ns 时钟的分辨率地板, 不是定点表示的问题; 本整形器的目标区间 (~12Mbps)
 *   下 64B = 42666ns, 精确。
 * kbps 为单位: u32 可覆盖到 4.3Tbps, 用户态高频写一个整数即可。 */
static void neoq_rate_set(u32 kbps)
{
    u64 bps, rate_bytes, mult, lim;
    u32 shift;

    if (!kbps) {
        /* 先清 cfg 再清 bps: dequeue 闸门只看 cfg, 保证"关闭"这一步是原子的
         * fail-open, 不会出现 cfg 还在、bps 已归零的中间态。 */
        WRITE_ONCE(neoq_rate_cfg, 0);
        WRITE_ONCE(neoq_rate_bps, 0);
        /* F1: 最后清限额 —— 清它是放宽方向 (退回 q->limit), 中间态无害。 */
        WRITE_ONCE(neoq_limit_pkts, 0);
        return;
    }

    bps = (u64)kbps * 1000;
    rate_bytes = bps >> 3;
    if (!rate_bytes)                /* < 8 bps: 钳到 1 B/s, 防除零 */
        rate_bytes = 1;

    shift = 20;
    mult = div64_u64((u64)NSEC_PER_SEC << 20, rate_bytes);
    while (mult > U32_MAX) {
        mult >>= 1;
        shift--;
    }

    /* F1: 由速率派生段数上界。溢出验算: rate_bytes <= U32_MAX*1000/8 < 2^39,
     * neoq_queue_ms <= 10000 < 2^14 -> 被除数 < 2^53, u64 内无溢出; 商 < 2^53/1.5e6
     * < 2^33 仍可能超 u32, 故先 clamp 到 U32_MAX 再截。rate_bytes >= 1 保证不除零,
     * 下钳 NEOQ_QUEUE_MIN_PKTS 保证结果不为 0 (否则 enqueue 会把它当成"整形关闭")。
     * 先写 limit_pkts 再写 cfg: 开启整形的一瞬限额已经到位, 不会有"整形已生效
     * 但队列上界还是 10240"的窗口。 */
    lim = div64_u64(rate_bytes * READ_ONCE(neoq_queue_ms),
                    1000ULL * NEOQ_QUEUE_MSS);
    WRITE_ONCE(neoq_limit_pkts,
               (u32)clamp_t(u64, lim, NEOQ_QUEUE_MIN_PKTS, (u64)U32_MAX));

    WRITE_ONCE(neoq_rate_bps, bps);
    WRITE_ONCE(neoq_rate_cfg, (mult << 8) | shift);
}

/* === NEW: CAKE 风格每流稀疏门控 (FIX2: 只读计算版) ===
 * 在 ~window_ns 滑动窗口内累计 flow 字节; 窗口到期则衰减(重置)累加器, 并依据刚结束
 * 窗口的字节量更新 is_bulk_behave; 窗口内一旦累计超过阈值立即钉为批量。
 * 返回 true 表示该 flow 当前为"稀疏", 可保留 Express/High; false 表示已被降级。
 *
 * 本函数只读 flow, 把本包提交后窗口各字段的终值算进 res (win_*); commit 仅照抄。
 * 因丢弃判定在 classify 之后, 必须保证被丢的包不污染窗口 (见 neoq_classify_result)。
 * FIX1: 同步维护 window_pkts/window_retrans; 窗口滚动时由刚结束窗口算出重传占比,
 *       存入 prev_retrans_share, 供 Express 防滥用门控读取上一完整窗口的占比。
 * is_retrans: 本包是否为重传 (须由调用方先经 tcp_retransmit_compute 算出再传入),
 *             用于把本包计入终态 window_retrans。
 * 注: 必须在 enqueue 持 root lock 路径内调用 (无额外加锁), 由调用方保证。 */
static __always_inline bool flow_sparse_compute(const struct neoq_flow *flow,
                                                u32 pkt_len, u64 now,
                                                bool is_retrans,
                                                struct neoq_classify_result *res)
{
    u32 thresh = READ_ONCE(neoq_sparse_thresh_bytes);
    u64 window = READ_ONCE(neoq_sparse_window_ns);
    u64 wstart;
    u32 bytes;
    u16 pkts, rxmt;
    bool bulk;

    if (thresh == 0)            /* 阈值=0: 禁用降级, 永远稀疏 (不触碰窗口字段) */
        return true;

    res->win_touched = true;

    /* 取当前窗口状态的本地副本 (绝不写 flow) */
    wstart = flow->window_start ? flow->window_start : now;   /* window_start==0 -> 起点=now */
    bytes  = flow->bytes_window;
    pkts   = flow->window_pkts;
    rxmt   = flow->window_retrans;
    bulk   = flow->is_bulk_behave;

    if (now - wstart >= window) {
        /* 窗口滚动: 用刚结束窗口的字节量决定稀疏/批量, 然后重置累加器。
         * 空闲期(几乎无字节)会把 flow 重新判回稀疏 -> 网页突发后快速恢复。
         * FIX1: 同步用刚结束窗口的 (window_retrans/window_pkts) 算百分比存入 prev share。 */
        bulk = (bytes >= thresh) ? 1 : 0;
        res->win_prev_share_upd = true;
        res->win_prev_share_set = pkts ? (u8)((u32)rxmt * 100 / pkts) : 0;
        bytes = 0;
        pkts  = 0;
        rxmt  = 0;
        wstart = now;
    }

    /* 累加本包 (终值) */
    bytes += pkt_len;
    if (pkts < U16_MAX)
        pkts++;
    if (is_retrans && rxmt < U16_MAX)
        rxmt++;
    if (bytes >= thresh)        /* 窗口内即时触发降级 */
        bulk = 1;

    res->win_start_set  = wstart;
    res->win_bytes_set  = bytes;
    res->win_pkts_set   = pkts;
    res->win_retrans_set = rxmt;
    res->win_bulk_set   = bulk;

    return !bulk;
}

/* 单次分类 (FIX2: 只读计算, 不改 flow; 待写状态全收进 res 由 commit 提交):
 * 头部解析一次, flow 已在手(含 retrans 分支)。
 * 行为分类核心 (修复 P1): hint 端口只提权小包; 持续高速率的 flow 即便命中 hint
 * 端口或 <256B 规则也被降级到按大小决定的档位。
 *
 * FIX1: 重传不再无条件进 Express。当某流上一完整窗口重传占比 > neoq_retrans_share_max
 * 且该流为批量行为时, 其重传留在按行为决定的档位(批量流即 Normal/Bulk), 仅保留 CoDel
 * 免疫(仍置 is_retrans), 不再插队 Express; 计 res->retrans_demoted_hint 供调用方计数。
 * 稀疏/交互流的重传不受影响, 继续进 Express。 */
static __always_inline u8 classify_packet_enhanced(struct neoq_sched_data *q,
                                                    const struct sk_buff *skb,
                                                    struct neoq_flow *flow,
                                                    u64 now,
                                                    struct neoq_classify_result *res)
{
    const struct iphdr *iph;
    const struct tcphdr *th;
    const struct udphdr *uh;
    u16 sport = 0, dport = 0;
    u8 proto;
    u32 pkt_len;
    int offset;
    bool is_retrans = false;
    bool sparse = true;
    bool port_hint = false;

    pkt_len = qdisc_pkt_len(skb);

    /* === 硬规则: 任何流量都无条件保持 Express === */
    /* 小包(ACK/控制); 与原实现一致: 不在此计算 retrans/窗口, is_retrans 保持 false。 */
    if (pkt_len < 128)
        return NEOQ_TIER_EXPRESS;

    /* FIX2 顺序调整: 先只读计算 retrans 判定 (供 sparse 窗口统计 window_retrans),
     * 再算 sparse。两者读写 flow 字段互不相交, 不改变各自结论。
     * tcp_retransmit_compute 内部自带 IP/TCP/越界检查, 非 TCP 返回 false。 */
    if (flow)
        is_retrans = tcp_retransmit_compute(skb, flow, res);
    res->is_retrans = is_retrans;

    /* 每流行为门控(对 >=128B 的包才有意义); flow 为空时(legacy 路径)按稀疏处理 */
    if (flow)
        sparse = flow_sparse_compute(flow, pkt_len, now, is_retrans, res);

    if (skb->protocol != htons(ETH_P_IP)) {
        /* P6: v6 不解析端口/retrans, 仅按大小分档, 不会误进 Express(除<128已返回) */
        if (pkt_len >= 1400)
            return NEOQ_TIER_BULK;
        if (pkt_len < 256 && sparse)
            return NEOQ_TIER_HIGH;
        return NEOQ_TIER_NORMAL;
    }

    iph = ip_hdr(skb);
    if (unlikely(!iph))
        return NEOQ_TIER_NORMAL;

    proto = iph->protocol;
    offset = iph->ihl << 2;

    if (proto == IPPROTO_TCP) {
        th = (const struct tcphdr *)((const u8 *)iph + offset);
        if ((const u8 *)(th + 1) <= skb_tail_pointer(skb)) {
            sport = ntohs(th->source);
            dport = ntohs(th->dest);

            /* === KEY: Retransmit -> Express, 但受 FIX1 防滥用门控约束 ===
             * gate 条件: 旋钮启用(>0) 且 上一完整窗口重传占比 > 阈值 且 本流为批量行为。
             * 命中 gate -> 不提 Express, 落入下方大小/行为分档(批量流=Normal/Bulk);
             * is_retrans 仍为真 -> cb 免疫标记照置, 重传永不被 CoDel 丢, 只是不插队。 */
            if (is_retrans) {
                u32 share_max = READ_ONCE(neoq_retrans_share_max);
                /* B3: 绝对阈值 -> 相对阈值。
                 * 有效阈值 = max(地板 share_max, 链路常态 ambient_share x rel/100)。
                 * 绝对阈值在整体重传率 18-20% 的链路上永远触发 (实测 77.7% 的重传
                 * 被拒 Express), 把正常的丢包恢复也一并拦了。相对化之后, 只有重传
                 * 占比显著高于链路常态的流才算滥用。ambient_share 上限 100, rel 写侧
                 * 钳到 <=10000, 故 rel*ambient/100 <= 10000, min 再压回 100, 不溢出。 */
                u32 thresh = max_t(u32, share_max,
                                   min_t(u32, 100,
                                         READ_ONCE(neoq_retrans_rel) *
                                         q->ambient_share / 100));
                bool gate = share_max && !sparse &&
                            flow && flow->prev_retrans_share > thresh;

                if (gate)
                    res->retrans_demoted_hint = true;   /* 由调用方累计 retrans_demoted */
                else
                    return NEOQ_TIER_EXPRESS;
                /* gate 命中: 继续向下, 按行为/大小分档 */
            }

            /* 纯 ACK -> Express (硬规则) */
            if (ntohs(iph->tot_len) == offset + (th->doff << 2) &&
                th->ack && !th->syn && !th->fin)
                return NEOQ_TIER_EXPRESS;

            /* SYN/FIN/RST -> 连接控制, 硬规则 Express(快速建连/拆连)
             * (原为 HIGH, 但 SYN/FIN/RST 都是稀疏控制包, 提到 Express 更合理且
             *  不受 behavior gate 影响) */
            if (th->syn || th->fin || th->rst)
                return NEOQ_TIER_EXPRESS;
        }
    } else if (proto == IPPROTO_UDP) {
        uh = (const struct udphdr *)((const u8 *)iph + offset);
        if ((const u8 *)(uh + 1) <= skb_tail_pointer(skb)) {
            sport = ntohs(uh->source);
            dport = ntohs(uh->dest);
        }
    }

    /* === 端口 hint: 只对小包(<256B)提权; 大包永不因 hint 进 Express === */
    port_hint = test_bit(dport, neoq_prio_portmap) ||
                test_bit(sport, neoq_prio_portmap);
    if (q->http_boost) {
        if (dport == HTTP_PORT || sport == HTTP_PORT ||
            dport == HTTPS_PORT || sport == HTTPS_PORT ||
            dport == DNS_PORT || sport == DNS_PORT ||
            dport == SSH_PORT || sport == SSH_PORT)
            port_hint = true;
    }

    /* hint 端口 + 小包 + 稀疏 -> Express; 否则落入大小/行为分档。
     * 大包(>=1400)直接绕过 hint 进 Bulk -> HTTPS 大下载不再霸占 Express。 */
    if (port_hint && pkt_len < 256 && sparse)
        return NEOQ_TIER_EXPRESS;

    /* 大包 -> Bulk (P1: 早于交互/HIGH 判定, 端口 hint 已无法救它) */
    if (pkt_len >= 1400)
        return NEOQ_TIER_BULK;

    /* 小交互包: 仅稀疏流享受 HIGH; 高速流降级 Normal */
    if (pkt_len < 256) {
        if (sparse)
            return NEOQ_TIER_HIGH;
        return NEOQ_TIER_NORMAL;
    }

    /* Gaming/VoIP UDP 端口 (中等包), 仅稀疏流 -> HIGH */
    if (proto == IPPROTO_UDP && sparse) {
        if ((sport >= 16384 && sport <= 32767) ||
            (dport >= 16384 && dport <= 32767))
            return NEOQ_TIER_HIGH;
    }

    return NEOQ_TIER_NORMAL;
}

/* === NEW (FIX2): 提交分类计算结果到 flow ===
 * 仅在包被接受入队后调用 (溢出/限额丢弃路径不调用), 把 classify 阶段算出的待写状态
 * 一次性落到 flow。这样被丢的包不会推进 highest_seq / retrans_count / sparse 窗口,
 * 避免: (a) 同一段后续真发被误判重传; (b) 被丢字节抬高 sparse 速率致错误降级。
 * 注: 必须与 classify 在同一持锁路径、针对同一 flow, 其间无其它写者, 故 compute 时读到
 *     的 flow 状态与此处一致, 直接照抄 res 的终值即可。 */
static __always_inline void neoq_commit_classify(struct neoq_flow *flow,
                                                 const struct neoq_classify_result *res)
{
    /* seq 跟踪 */
    if (res->seq_update)
        flow->highest_seq = res->new_highest_seq;
    if (res->count_retrans)
        flow->retrans_count++;

    /* sparse 窗口 (含 FIX1 的 window_pkts/window_retrans/prev_retrans_share) */
    if (res->win_touched) {
        flow->window_start  = res->win_start_set;
        flow->bytes_window  = res->win_bytes_set;
        flow->window_pkts   = res->win_pkts_set;
        flow->window_retrans = res->win_retrans_set;
        flow->is_bulk_behave = res->win_bulk_set;
        if (res->win_prev_share_upd)
            flow->prev_retrans_share = res->win_prev_share_set;
    }
}

/* ========================================================================
 * Flow Hashing - Set Associative
 * ======================================================================== */

/* 全局 5-tuple 哈希: 表已上移到 q->flows/tags, 一个连接只占一个槽。
 * P6: 增加 IPv6 分支, 哈希 v6 地址+端口, 否则所有 v6 流塌缩到同一桶。
 *
 * === NEW (B4): 8 路集合饱和时的冲突守卫 ===
 * 旧行为是走 "Collision - use original" 分支并把 q->tags[slot] 抢过来。危害:
 * victim flow 的包还在那个槽的 FIFO 里, 于是两个不同的 5-tuple 共享同一个
 * neoq_flow -> highest_seq 被两条流交错前移 -> 假重传风暴。而假重传还自带
 * CoDel 免疫 + Express 插队, 危害被放大; sparse 窗口也被互相污染。
 * 新行为: 冲突时置 *collided=true 且**不写 tags**(不抢 tag、不共享状态)。包物理上
 * 仍进该槽的 FIFO (总得有地方排队), 但由调用方按"无状态包"处理。way_collide 计数照旧。 */
static u32 flow_hash(struct neoq_sched_data *q, const struct sk_buff *skb,
                     u32 perturbation, bool *collided)
{
    const struct iphdr *iph;
    u32 hash, reduced;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8 proto = 0;

    *collided = false;

    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        if (iph) {
            int off = iph->ihl << 2;
            saddr = iph->saddr;
            daddr = iph->daddr;
            proto = iph->protocol;

            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
                const __be16 *ports = (const __be16 *)((const u8 *)iph + off);
                if ((const u8 *)(ports + 2) <= skb_tail_pointer(skb)) {
                    sport = (__force u16)ports[0];
                    dport = (__force u16)ports[1];
                }
            }
        }
        hash = jhash_3words(saddr, daddr, (sport << 16) | dport, perturbation);
        hash ^= proto << 24;
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        const struct ipv6hdr *ip6 = ipv6_hdr(skb);

        if (ip6) {
            proto = ip6->nexthdr;
            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
                const __be16 *ports = (const __be16 *)(ip6 + 1);
                if ((const u8 *)(ports + 2) <= skb_tail_pointer(skb)) {
                    sport = (__force u16)ports[0];
                    dport = (__force u16)ports[1];
                }
            }
            /* 把 16 字节 v6 地址折叠进 jhash; 用 jhash2 散列两个 in6_addr。 */
            hash = jhash2((const u32 *)&ip6->saddr, 4, perturbation);
            hash = jhash2((const u32 *)&ip6->daddr, 4, hash);
            hash = jhash_3words((sport << 16) | dport, proto, 0, hash);
        } else {
            hash = jhash_3words(0, 0, 0, perturbation);
        }
    } else {
        hash = jhash_3words(0, 0, 0, perturbation);
    }

    reduced = hash % NEOQ_QUEUES;

    /* Set-associative lookup */
    if (likely(q->tags[reduced] == hash && q->flows[reduced].set))
        return reduced;

    {
        u32 inner = reduced % NEOQ_SET_WAYS;
        u32 outer = reduced - inner;
        u32 i, k = inner;

        /* Search for existing flow */
        for (i = 0; i < NEOQ_SET_WAYS; i++, k = (k + 1) % NEOQ_SET_WAYS) {
            if (q->tags[outer + k] == hash) {
                if (i)
                    q->way_indirect++;
                reduced = outer + k;
                goto found;
            }
        }

        /* Find empty slot */
        for (i = 0; i < NEOQ_SET_WAYS; i++, k = (k + 1) % NEOQ_SET_WAYS) {
            if (!q->flows[outer + k].set) {
                q->way_miss++;
                reduced = outer + k;
                goto found;
            }
        }

        /* Collision - 集合已饱和: 借槽排队但不抢 tag, 见函数头 B4 说明。
         * 直接 return 以绕过下方 found: 处的 q->tags 写入 —— 一旦写了 tag, victim
         * 的后续包就会被判成"另一条流", 状态污染即刻发生。 */
        q->way_collide++;
        *collided = true;
        return outer + inner;
found:
        q->tags[reduced] = hash;
    }

    return reduced;
}

/* ========================================================================
 * CoDel Decision - Enhanced with Flow Protection
 *
 * Flow protection levels reduce drop probability for flows in recovery:
 * - NONE:  Normal CoDel behavior
 * - LOW:   50% drop probability reduction
 * - MED:   75% drop probability reduction
 * - HIGH:  90% drop probability reduction (only ECN mark)
 * ======================================================================== */

static bool codel_should_drop(struct neoq_flow *flow, struct neoq_tier *tier,
                              u64 now, struct sk_buff *skb)
{
    u64 sojourn = now - get_neoq_cb(skb)->enqueue_time;
    u64 effective_target = READ_ONCE(neoq_codel_target_ns);
    bool over, due;

    flow->ecn_marked = 0;

    /* 注: 此处原有一段按 flow->srtt_us 缩放 effective_target 的 "RTT-aware" 逻辑,
     * 已随 srtt_us 字段一并删除 —— srtt_us 永远是 0, 该分支恒假。高 RTT 链路要放宽
     * target, 请写 /proc/net/neoq_codel (用户态 lotspeedctl 已在做)。 */

    /* Flow protection: increase target for protected flows */
    switch (flow->loss_protect_level) {
    case LOSS_PROTECT_LOW:
        effective_target = effective_target * 3 / 2;  /* 1.5x target */
        break;
    case LOSS_PROTECT_MED:
        effective_target = effective_target * 2;      /* 2x target */
        break;
    case LOSS_PROTECT_HIGH:
        effective_target = effective_target * 4;      /* 4x target */
        break;
    default:
        break;
    }

    over = sojourn > effective_target;
    due = flow->count && (s64)(now - flow->drop_next) >= 0;

    if (over) {
        if (!flow->dropping) {
            flow->dropping = 1;
            flow->drop_next = codel_control_law(now, READ_ONCE(neoq_codel_interval_ns),
                                                 flow->rec_inv_sqrt);
        }
        if (!flow->count)
            flow->count = 1;
    } else if (flow->dropping) {
        flow->dropping = 0;
    }

    if (due && flow->dropping) {
        /* F3: 状态机必须无条件推进 —— 原来错在 LOSS_PROTECT_HIGH 直接 return false
         * 且不动 count/drop_next。调用方是 `if (!codel_should_drop(...) || !flow->head)
         * break;`, 返回 false 就直接交付, 下面的 ECN 分支根本不可达: 注释承诺的
         * "caller should try ECN first" 从未实现, flow->ecn_marked 是死写。更糟的是
         * drop_next 停在过去 -> 该流永远 due 却永远不丢不标, drop token 被无限期挂起,
         * 完全逃出 AQM。本链路 ambient 重传 18-20%, 而 update_flow_state 在
         * retrans/total > 5% 时就置 HIGH -> 约 1/5 的出队瞬间 CoDel 被旁路。改动前
         * qlen 恒为 0、CoDel 从不运行, 这无所谓; 整形器把队列买回本机之后, CoDel 是
         * 唯一的队列控制手段, 不能有洞。
         * 因此: 先照常推进 count/drop_next (与非保护流逐字一致), 再决定动作。 */
        flow->count++;
        if (!flow->count)
            flow->count--;
        codel_cache_invsqrt(flow);
        flow->drop_next = codel_control_law(flow->drop_next,
                                             READ_ONCE(neoq_codel_interval_ns),
                                             flow->rec_inv_sqrt);

        /* HIGH 由"完全免疫"降级为"只标不丢": 只有 CE 真的打上去了才免于丢弃。
         * Not-ECT (本链路常态) 打标失败时必须 return true 落回正常丢弃逻辑, 否则又
         * 变回"既不标也不丢"的老洞。这里自己打标而不是交给调用方的 ECN 分支, 原因有
         * 二: 那个分支受 q->ecn 开关约束 (q->ecn=0 时会变成"标了还丢"), 且
         * INET_ECN_set_ce 对已 CE 的包同样返回 1, 会把 tier->ecn_marked 记两次。 */
        if (flow->loss_protect_level == LOSS_PROTECT_HIGH &&
            INET_ECN_set_ce(skb)) {
            tier->ecn_marked++;
            flow->ecn_marked = 1;
            return false;
        }
        return true;
    }

    while (due) {
        flow->count--;
        codel_cache_invsqrt(flow);
        flow->drop_next = codel_control_law(flow->drop_next,
                                             READ_ONCE(neoq_codel_interval_ns),
                                             flow->rec_inv_sqrt);
        due = flow->count && (s64)(now - flow->drop_next) >= 0;
    }

    return false;
}

/* ========================================================================
 * EWMA Helper
 * ======================================================================== */

static inline u64 ewma(u64 avg, u64 sample, u32 weight)
{
    return avg - (avg >> weight) + (sample >> weight);
}

/* ========================================================================
 * GSO 段计数: limit/q.qlen/tier->packets 以"段"为单位计数 (P7)。
 * gso_segs 在排队期间不变, 故入队/出队/驱逐均用本函数从 skb 重算, 保证 ++/-- 对称。
 * ======================================================================== */

static inline u32 neoq_gso_segs(const struct sk_buff *skb)
{
    u32 segs = skb_shinfo(skb)->gso_segs;
    return segs ? segs : 1;
}

/* 跨档位 WRR 权重 Express:High:Normal:Bulk = 8:4:2:1 (供迁移/入队/出队共用) */
static const u32 neoq_tier_weight[NEOQ_MAX_TIERS] = { 8, 4, 2, 1 };

/* ========================================================================
 * 全局流表 <-> 每档 DRR 链表
 *
 * 迁移策略 (注释要求):
 *   一个 5-tuple 只有一个 neoq_flow, 其 skb 队列内嵌在 flow 结构里 (head/tail),
 *   因此一个 flow 任一时刻只属于一个档位的 DRR 链表。当后续分类把 flow 判到新档位
 *   而它仍在旧档位排队时, 由于整条队列随 flow 结构一起搬动 (不存在把同一 FIFO 拆到
 *   两个链表的问题), 我们直接把 flow 整体重挂到新档位的 new_flows, 并把它的 backlog
 *   字节与 sparse/bulk 计数从旧档位转移到新档位, deficit 重置。即"立即迁移"策略。
 * ======================================================================== */

/* 把已在某档位排队的 flow 迁移到 new_tier_idx 档位。调用前 flow->set != FLOW_NONE。 */
static void neoq_flow_migrate(struct neoq_sched_data *q, struct neoq_flow *flow,
                              u8 new_tier_idx)
{
    struct neoq_tier *old = &q->tiers[flow->tier];
    struct neoq_tier *nt = &q->tiers[new_tier_idx];

    /* 从旧档位计数中扣除 (按当前 set 决定 sparse/bulk 桶) */
    if (flow->set == FLOW_BULK)
        old->bulk_cnt--;
    else
        old->sparse_cnt--;        /* FLOW_NEW / FLOW_SPARSE */

    /* 转移 backlog 字节 */
    old->backlog -= flow->backlog;
    nt->backlog += flow->backlog;

    /* 目标档位此前为空则重置 WRR 赤字 (同 enqueue 新流路径) */
    if (!nt->sparse_cnt && !nt->bulk_cnt)
        nt->tier_deficit = (s64)neoq_tier_weight[new_tier_idx] * q->quantum;

    /* 以"新流"身份重挂到新档位, 拿到稀疏优先与新鲜 deficit */
    list_move_tail(&flow->flowchain, &nt->new_flows);
    flow->set = FLOW_NEW;
    flow->tier = new_tier_idx;
    flow->deficit = nt->quantum;
    nt->sparse_cnt++;
}

/* 从指定档位驱逐一个包以腾出空间 (P3)。
 * 选该档 backlog 最大的 flow (排除 skip 指向的到来包自身的 flow), 丢其 *队首* 包
 * (单链表无 O(1) 队尾, 队首丢弃对 AQM 等效且更廉价)。完整记账并在 flow 排空时摘链。
 * 返回被丢字节数, 0 表示该档无可驱逐对象。 */
static u32 neoq_evict_from_tier(struct Qdisc *sch, u8 tier_idx,
                                const struct neoq_flow *skip)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier = &q->tiers[tier_idx];
    struct neoq_flow *flow, *victim = NULL;
    struct sk_buff *skb;
    u32 len, gso, idx;

    list_for_each_entry(flow, &tier->new_flows, flowchain) {
        if (flow == skip)
            continue;
        if (!victim || flow->backlog > victim->backlog)
            victim = flow;
    }
    list_for_each_entry(flow, &tier->old_flows, flowchain) {
        if (flow == skip)
            continue;
        if (!victim || flow->backlog > victim->backlog)
            victim = flow;
    }
    if (!victim)
        return 0;

    skb = flow_dequeue(victim);
    if (!skb)
        return 0;

    idx = victim - q->flows;
    len = qdisc_pkt_len(skb);
    gso = neoq_gso_segs(skb);

    q->backlogs[idx] -= len;
    victim->backlog -= len;
    tier->backlog -= len;
    sch->qstats.backlog -= len;
    q->memory_used -= skb->truesize;
    sch->q.qlen -= gso;

    victim->dropped++;
    tier->dropped++;
    qdisc_tree_reduce_backlog(sch, gso, len);
    qdisc_qstats_drop(sch);
    kfree_skb(skb);

    /* flow 排空 -> 摘链, 与 dequeue 空流路径保持一致 */
    if (!victim->head) {
        list_del_init(&victim->flowchain);
        if (victim->set == FLOW_BULK)
            tier->bulk_cnt--;
        else
            tier->sparse_cnt--;
        victim->set = FLOW_NONE;
        q->flows_cnt--;
    }
    return len;
}

/* ========================================================================
 * Enqueue - Enhanced with Retransmit Priority & Flow State
 * ======================================================================== */

/* 单个 skb 的入队主体。B2 起 neoq_enqueue 变成只做 GSO 拆分的薄壳, 拆出来的每一段
 * 都完整走一遍本函数 (classify -> 限额检查 -> commit), 因此 compute-then-commit 的
 * 语义对每段独立成立, 不会被拆分打乱。 */
static int neoq_enqueue_one(struct sk_buff *skb, struct Qdisc *sch,
                            struct sk_buff **to_free)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    struct neoq_classify_result res = {0};   /* FIX2: classify 把待写状态收进此处 */
    u32 idx, len, gso, limit_eff;
    u8 tier_idx;
    bool is_retrans = false;
    bool new_flow;
    bool collided;
    u64 now;

    len = qdisc_pkt_len(skb);
    gso = neoq_gso_segs(skb);

    /* === 单次分类 (P2): 解析头部一次 -> flow_hash 一次 -> 拿到 flow -> 分类一次 ===
     * enqueue_time 在分类前写入, 供 sparse 门控读取同一时钟。 */
    now = ktime_get_ns();
    get_neoq_cb(skb)->enqueue_time = now;

    idx = flow_hash(q, skb, q->perturbation, &collided);
    flow = &q->flows[idx];

    /* 全新槽位: 先把每流检测状态清零 *再* 分类, 使 retrans/sparse 看到干净状态。
     * 此时尚未挂链 (tier 未知); 若随后被拒纳, 槽位仍为 FLOW_NONE 的干净零态。
     * B4: 冲突包借的是别人的槽, 绝不能触发"新流初始化"(那会把 victim 的状态清光)。
     * 事实上 collided 只在 8 路全非空时才为真, flow->set 必然 != FLOW_NONE, 这里
     * 显式带上 !collided 只是把这个不变式写进代码。 */
    new_flow = !collided && (flow->set == FLOW_NONE);
    if (new_flow) {
        /* 与原 FLOW_NONE 初始化集合一致 (仅顺序提前), 外加新增的 sparse 门控字段。 */
        flow->flow_state = FLOW_STATE_NEW;
        flow->loss_protect_level = LOSS_PROTECT_NONE;
        flow->highest_seq = 0;
        flow->retrans_count = 0;
        flow->total_packets = 0;
        flow->startup_packets = 0;
        flow->bytes_window = 0;
        flow->window_start = 0;
        flow->is_bulk_behave = 0;
        flow->window_pkts = 0;          /* FIX1: 近窗占比统计字段随新流清零 */
        flow->window_retrans = 0;
        flow->prev_retrans_share = 0;
    }

    if (unlikely(collided)) {
        /* === B4: 冲突包按"无状态包"处理 ===
         * 不读也不写 victim 的 flow 状态, 因此不做 classify —— classify 的两个输出
         * (tier 与 is_retrans) 对冲突包都必须丢弃, 再解析一遍头部是纯浪费。res 保持
         * 全零 -> is_retrans=false, 下方的 commit / update_flow_state 也一并跳过。
         *
         * 关键 (原规格易漏): 必须沿用 victim 当前的档位。若让冲突包自行分类出一个
         * 档位, 下方 "flow->tier != tier_idx -> neoq_flow_migrate" 会把 victim 的
         * 整条 backlog 拖去另一个档位 —— 比它本要避免的假重传问题更糟。这里
         * tier_idx == flow->tier, 迁移分支自然不成立。 */
        tier_idx = flow->tier;
    } else {
        /* FIX2: classify 只读计算 (不改 flow), 结果存 res; 接受入队后才 commit。 */
        tier_idx = classify_packet_enhanced(q, skb, flow, now, &res);
    }
    is_retrans = res.is_retrans;
    tier = &q->tiers[tier_idx];

    /* === F1: 整形开启时用速率派生的队列上界, 而不是固定的 q->limit ===
     * 拆 GSO 打掉了 TCP Small Queues (详见 neoq_limit_pkts 处的推导), 本机队列的唯一
     * 上界就只剩这一处; 10240 段在 12Mbps 下是 9.9 秒。q->limit 仍是硬顶 (用户显式
     * 配置的上界不能被派生值突破), 整形关闭时 limit_pkts=0 -> 逐字退回原行为。 */
    limit_eff = READ_ONCE(neoq_limit_pkts);
    if (!limit_eff || limit_eff > q->limit)
        limit_eff = q->limit;

    /* === 限额检查 (P3/P7: 以段计数; 溢出时对 Express/High 驱逐低优先级队列) === */
    if (unlikely(sch->q.qlen + gso > limit_eff ||
                 q->memory_used + skb->truesize > q->memory_limit)) {
        if (tier_idx == NEOQ_TIER_EXPRESS || tier_idx == NEOQ_TIER_HIGH) {
            /* 从最低优先级的非空档位 (Bulk 优先) 驱逐, 直到能容纳到来的包。
             * 到来包为 Express/High, 只驱逐 vt>tier_idx 的更低档位, 故被驱逐的绝不是
             * 到来包自身的 flow。 */
            int vt;

            for (vt = NEOQ_MAX_TIERS - 1; vt > (int)tier_idx; vt--) {
                while (sch->q.qlen + gso > limit_eff ||
                       q->memory_used + skb->truesize > q->memory_limit) {
                    /* skip=flow: 绝不驱逐到来包自身的 flow (它即将上迁并入队),
                     * 否则 new_flow/flow->set 失效, 迁移会双重扣减计数。 */
                    if (!neoq_evict_from_tier(sch, vt, flow))
                        break;          /* 该档已无可驱逐对象, 换更高档位 */
                }
                if (sch->q.qlen + gso <= limit_eff &&
                    q->memory_used + skb->truesize <= q->memory_limit)
                    break;
            }
            /* 仍放不下 (无更低优先级流量可驱逐) -> 只能丢弃到来的包 */
            if (sch->q.qlen + gso > limit_eff ||
                q->memory_used + skb->truesize > q->memory_limit) {
                qdisc_qstats_drop(sch);
                __qdisc_drop(skb, to_free);
                return NET_XMIT_DROP;
            }
        } else {
            /* Normal/Bulk: 维持原行为, 丢弃到来的包 */
            qdisc_qstats_drop(sch);
            __qdisc_drop(skb, to_free);
            return NET_XMIT_DROP;
        }
    }

    /* === 确认纳入: 此后才提交分类待写状态并推进 flow 生命周期 (只统计真入队的包) ===
     * FIX2: commit 必须早于 update_flow_state —— 后者读 retrans_count/total_packets 算
     * loss_rate, 而旧实现里 retrans_count++ 发生在 classify(即 update_flow_state 之前),
     * 故此处先 commit (落 retrans_count 等) 再 update_flow_state, 保持原顺序语义不变。 */
    if (likely(!collided)) {
        neoq_commit_classify(flow, &res);
        update_flow_state(flow, is_retrans);

        /* === B3: 全局 ambient 重传占比 (1 秒滚动窗口) ===
         * 分母口径必须与 flow->prev_retrans_share 一致, 否则两者不可比:
         * 后者只统计 >=128B 的包 (classify 对 <128B 直接 return Express, 从不做
         * retrans 判定), 若把纯 ACK 也计进分母, ambient 会被系统性稀释 -> 相对阈值
         * 偏低 -> 门又开始误杀。冲突包没有 flow 状态 (is_retrans 恒 false), 同样排除。
         * 全在持 root lock 的 enqueue 路径内, 无并发问题。 */
        if (len >= 128) {
            if (!q->glob_win_start)
                q->glob_win_start = now;
            q->glob_win_pkts++;
            if (is_retrans)
                q->glob_win_retrans++;
            if (now - q->glob_win_start >= NSEC_PER_SEC) {
                q->ambient_share = q->glob_win_pkts ?
                    (u8)min_t(u32, 100,
                              q->glob_win_retrans * 100 / q->glob_win_pkts) : 0;
                q->glob_win_pkts = 0;
                q->glob_win_retrans = 0;
                q->glob_win_start = now;
            }
        }
    }

    /* retrans 免疫标记随 skb 旅行到 dequeue (CoDel 丢弃判定处)。
     * 仅对真正入队的包置位/计数 (溢出丢弃路径已提前 return)。 */
    get_neoq_cb(skb)->is_retrans = is_retrans ? 1 : 0;
    if (is_retrans)
        q->retrans_seen++;
    /* FIX1: 本重传因防滥用门控被拒 Express (留在按行为决定的档位) -> 计数。 */
    if (res.retrans_demoted_hint)
        q->retrans_demoted++;

    /* === Flow 链表管理必须在字节记账之前 ===
     * 迁移会把 flow->backlog (本包之前的旧 backlog) 在档位间整体搬移; 若先把本包的 len
     * 计入, 迁移会重复计 len。故先迁移/挂链使 flow->tier == tier_idx, 再统一记账。 */
    if (new_flow) {
        /* 全新 flow: 挂入当前档位 new_flows。
         * 若该档位此前为空, 重置 WRR 赤字为 w*quantum -> Express 一有流量即获满额度,
         * 不被 Bulk 反压 (P5 延迟下界关键)。 */
        if (!tier->sparse_cnt && !tier->bulk_cnt)
            tier->tier_deficit = (s64)neoq_tier_weight[tier_idx] * q->quantum;
        list_add_tail(&flow->flowchain, &tier->new_flows);
        flow->set = FLOW_NEW;
        flow->tier = tier_idx;
        flow->deficit = tier->quantum;
        tier->sparse_cnt++;
        q->flows_cnt++;
    } else if (flow->tier != tier_idx) {
        /* 已排队的 flow 改判到新档位 -> 整体迁移 (见 neoq_flow_migrate 注释) */
        neoq_flow_migrate(q, flow, tier_idx);
    }

    /* Add to flow (physical) */
    flow_queue_add(flow, skb);

    /* Update stats (字节/truesize 不按段; qlen/packets 按段)。
     * 此处 tier == &q->tiers[tier_idx] == flow 当前所在档位, 与 flow->tier 一致。 */
    q->backlogs[idx] += len;
    flow->backlog += len;
    tier->backlog += len;
    sch->qstats.backlog += len;
    q->memory_used += skb->truesize;
    sch->q.qlen += gso;
    tier->packets += gso;
    tier->bytes += len;

    return NET_XMIT_SUCCESS;
}

/* ========================================================================
 * NEW (B2): GSO 拆分薄壳
 *
 * 为什么整形开启时必须拆: 12Mbps 下一个 64KB 的 GSO 超级包 = 43ms 路径传输时间。
 * 不拆则虚拟时钟的推进粒度是 43ms、DRR 的公平粒度是 43ms、Express 最坏排队 +43ms、
 * CoDel 按"血块"采样 —— 整形器和 AQM 同时失去分辨率。
 * 副作用收益: tcp_retransmit_compute 只看 GSO 头部, 一个 44 段的超级包在
 * window_pkts 里只计 1; 拆分后重传检测 / 稀疏门 / 近窗占比统计全部变准。
 *
 * 记账 (仿 sch_cake): 上游(父 qdisc)把这次入队记成 1 个包 len 字节, 而我们实际持有
 * numsegs 个包共 slen 字节, 故 qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen)
 * 报告差量 (通常为负 = 让父 qdisc 加回来)。NeoQ 自身的 sch->q.qlen 一直按"段"计数,
 * 拆分前后都是 numsegs (neoq_gso_segs 对单段 skb 返回 1), 内部记账不受影响。
 * 中途被限额丢掉的段不计入 numsegs/slen —— 差量报的必须是"实际持有"。
 * ======================================================================== */

static int neoq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                        struct sk_buff **to_free)
{
    struct sk_buff *segs, *nskb;
    netdev_features_t features;
    unsigned int slen = 0, numsegs = 0;
    u64 rate = READ_ONCE(neoq_rate_bps);
    u32 len;

    /* 整形关闭 (rate=0) 时逐字维持改动前行为: 不拆, 直通。 */
    if (!rate || !skb_is_gso(skb) ||
        rate >= (u64)READ_ONCE(neoq_split_gso_thresh))
        return neoq_enqueue_one(skb, sch, to_free);

    features = netif_skb_features(skb);
    segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
    /* 清掉 NETIF_F_GSO_MASK 是为了强制"完全分段"(顺带禁掉 GSO_PARTIAL), 这样每个
     * 段的 gso_segs=0 -> neoq_gso_segs() 返回 1, 段计数与拆分前的总段数一致。 */
    if (IS_ERR_OR_NULL(segs))
        return neoq_enqueue_one(skb, sch, to_free);  /* 分段失败 -> 回退整包路径 */

    len = qdisc_pkt_len(skb);       /* 必须在 consume_skb 之前取 */

    skb_list_walk_safe(segs, segs, nskb) {
        /* seglen 必须在 neoq_enqueue_one 之前取: 调用返回后这个 skb 已经归 qdisc
         * 队列或 to_free 链表所有, 不再该被本函数读写。 */
        unsigned int seglen = segs->len;

        skb_mark_not_on_list(segs);
        qdisc_skb_cb(segs)->pkt_len = seglen;
        if (neoq_enqueue_one(segs, sch, to_free) == NET_XMIT_SUCCESS) {
            slen += seglen;
            numsegs++;
        }
    }

    /* F2: numsegs==0 (所有段都被限额丢掉) 时绝不能上报差量。原来错在无条件调用:
     * 那一路退化成 qdisc_tree_reduce_backlog(sch, 1, len), 把父 qdisc 的 q.qlen -= 1、
     * qstats.backlog -= len —— 但本函数这一路返回 NET_XMIT_DROP, 父 qdisc (HTB/prio 等)
     * 在子 enqueue 返回非 SUCCESS 时 **从来没有加过** 这个包 (直接 return, 不做
     * qlen++/backlog+=len)。于是每丢一个整包, 父及其所有祖先的 q.qlen(unsigned) 与
     * qstats.backlog(__u32) 各减 1/len, 向下回绕成 ~4e9; HTB 随即认为该 class 永久有
     * backlog, qlen_notify 再也不触发。sch_tbf.c:tbf_segment 的 if (nb > 1) 正是为此。
     * 当前 lotspeed 只挂 root (root 的 qdisc_tree_reduce_backlog 第一轮就 break, 是
     * 空操作), 所以今天看不出来 —— 任何人把 neoq 挂到 HTB 之下就立刻暴露。 */
    if (numsegs)
        qdisc_tree_reduce_backlog(sch, 1 - numsegs, len - slen);
    consume_skb(skb);
    /* 全部段都被限额丢掉时如实返回 DROP, 让套接字拿到正确的背压信号 (每段自己
     * 已经计过 qdisc_qstats_drop 并挂进 to_free, 不存在重复释放)。 */
    return numsegs ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

/* ========================================================================
 * Dequeue - Optimized Multi-Tier
 * ======================================================================== */

static struct sk_buff *neoq_dequeue_flow(struct Qdisc *sch,
                                         struct neoq_tier *tier,
                                         struct neoq_flow *flow)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;
    u32 len, idx, gso;

    idx = flow - q->flows;          /* 全局表索引 */
    skb = flow_dequeue(flow);
    if (!skb)
        return NULL;

    len = qdisc_pkt_len(skb);
    gso = neoq_gso_segs(skb);        /* 与入队加的段数相同 (P7 对称) */
    q->backlogs[idx] -= len;
    flow->backlog -= len;
    tier->backlog -= len;
    sch->qstats.backlog -= len;
    q->memory_used -= skb->truesize;
    sch->q.qlen -= gso;

    return skb;
}

/* === NEW: 跨档位防饿死 WRR (P4) ===
 * 权重 Express:High:Normal:Bulk = 8:4:2:1 (按字节赤字)。工作保持: 空闲档不消耗份额。
 * 选取规则: 由高到低找第一个"非空且赤字>0"的档位; 若所有非空档位赤字都已耗尽, 则只给
 * 非空档位补充 w*quantum (空闲档不累积), 再重试。新激活的档位在 enqueue 中把赤字重置
 * 为 w*quantum, 因此 Express 一有包就立刻拿到额度, 不会被 Bulk 反压。
 * 单次 dequeue 仅出一个包, 故最多一个低档 GSO 包(≤64KB≈0.5ms@1Gbps)排在 Express 前。 */
static int neoq_pick_tier(struct neoq_sched_data *q)
{
    int t;

    /* 补充循环不能设固定上限: 一个 64KB GSO 包可把低权重档的赤字打到
     * 约 -64K, 每轮仅补 weight*quantum (最低 256), 限 2 轮会导致
     * 非空队列被误判为空 -> qdisc 假空停摆。每轮每个非空档至少 +256,
     * 至多 ~43 轮必有档位转正, 循环必然终止且不触碰 skb。 */
    for (;;) {
        bool any = false;

        for (t = 0; t < NEOQ_MAX_TIERS; t++) {
            struct neoq_tier *tier = &q->tiers[t];

            if (!tier->sparse_cnt && !tier->bulk_cnt)
                continue;
            any = true;
            if (tier->tier_deficit > 0)
                return t;
        }
        if (!any)
            return -1;          /* 无任何非空档位 */

        /* 所有非空档位赤字耗尽 -> 仅补充非空档位 (空闲档不累积额度) */
        for (t = 0; t < NEOQ_MAX_TIERS; t++) {
            struct neoq_tier *tier = &q->tiers[t];

            if (tier->sparse_cnt || tier->bulk_cnt)
                tier->tier_deficit += (s64)neoq_tier_weight[t] * q->quantum;
        }
    }
}

static struct sk_buff *neoq_dequeue(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    struct list_head *head;
    struct sk_buff *skb;
    u64 now, delay, cfg;
    u32 plen, gso;
    int t;

begin:
    if (!sch->q.qlen)
        return NULL;

    now = ktime_get_ns();

    /* === B1: 虚拟时钟整形闸门 ===
     * 这是本函数里唯一"有 backlog 却返回 NULL"的路径, 因此必须挂 watchdog, 否则
     * qdisc 会停摆到下一次 enqueue 才被唤醒。其余 NULL 出口 (begin: 的 !qlen 与
     * neoq_pick_tier 返回 -1) 都等价于队列为空, 不需要定时器。
     * 用直接的 u64 比较 (参照 sch_cake 的写法), 不引入不确定是否存在的 helper。
     * cfg 在此无条件取一次, 出队记账处复用同一份快照 —— 避免闸门与推进用到不同
     * 的速率配置。 */
    cfg = READ_ONCE(neoq_rate_cfg);
    if (cfg && now < q->time_next_packet) {
        q->shaper_defer_cnt++;
        qdisc_qstats_overlimit(sch);    /* 与 tbf/cake 同口径, tc -s qdisc 可见 */
        qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
        return NULL;
    }

    /* WRR 选档 (替代纯严格优先级) */
    t = neoq_pick_tier(q);
    if (t < 0)
        return NULL;
    tier = &q->tiers[t];

retry:
    /* New flows first (sparse priority) */
    head = &tier->new_flows;
    if (list_empty(head)) {
        head = &tier->old_flows;
        if (list_empty(head)) {
            /* 该档计数与链表不一致兜底; 正常不会到达。原严格优先级实现此处 continue
             * 跳到下一档, WRR 重写后外层 for 已不存在。为防 qlen!=0 却 return NULL 造成
             * qdisc 失速(假"空"队列直到下次 enqueue 才被唤醒), 这里自愈: 把该档计数清零
             * 使 neoq_pick_tier 不再选中它, 再 goto begin 重新选档。每次最多重选
             * NEOQ_MAX_TIERS 档, 保证终止, 且不触碰任何 skb / qlen, 无泄漏。 */
            tier->sparse_cnt = 0;
            tier->bulk_cnt = 0;
            goto begin;
        }
    }

    flow = list_first_entry(head, struct neoq_flow, flowchain);

    /* DRR check (档内每流) */
    if (flow->deficit <= 0) {
        flow->deficit += tier->quantum;
        list_move_tail(&flow->flowchain, &tier->old_flows);

        if (flow->set == FLOW_NEW || flow->set == FLOW_SPARSE) {
            flow->set = FLOW_BULK;
            tier->sparse_cnt--;
            tier->bulk_cnt++;
        }
        goto retry;
    }

    /* Get packet with CoDel */
    while (1) {
        skb = neoq_dequeue_flow(sch, tier, flow);
        if (!skb) {
            /* Flow empty - remove */
            list_del_init(&flow->flowchain);
            if (flow->set == FLOW_NEW || flow->set == FLOW_SPARSE)
                tier->sparse_cnt--;
            else if (flow->set == FLOW_BULK)
                tier->bulk_cnt--;
            flow->set = FLOW_NONE;
            q->flows_cnt--;
            goto begin;
        }

        /* CoDel - but don't drop last packet。
         * 注: codel_should_drop 总是先于免疫判定执行, CoDel 状态机 (count/drop_next/
         * dropping/rec_inv_sqrt) 对每个包 (含 retrans) 一律照常推进; 免疫只改变"本包"
         * 的动作 (丢 vs 交付), 绝不篡改状态转移。故非 retrans 流量的状态机与改前逐字
         * 一致, 不会卡死成恒丢/恒不丢; retrans 已"消费"掉这一次 drop token, 下一次
         * due 触发时落到届时队首的包 (即把丢弃动作顺延到下一个非 retrans 包)。 */
        if (!codel_should_drop(flow, tier, now, skb) || !flow->head)
            break;

        /* === NEW: retrans 免疫 (仅针对 CoDel 触发的丢弃) ===
         * 250ms RTT 下丢一个重传包会让恢复时间翻倍, 是最坏结果。本应被丢的 retrans:
         * 若 ECN-capable 则改打 CE (拥塞信号但不丢包); 否则直接交付。两种情况都 break
         * (交付该包), 绝不落入下方丢弃路径。limit/溢出驱逐仍对所有包生效 (满队列就是满)。 */
        if (get_neoq_cb(skb)->is_retrans) {
            if (INET_ECN_set_ce(skb)) {
                tier->ecn_marked++;
                flow->ecn_marked = 1;
            }
            q->retrans_protected++;
            break;
        }

        /* Try ECN mark first */
        if (q->ecn && INET_ECN_set_ce(skb)) {
            tier->ecn_marked++;
            flow->ecn_marked = 1;
            break;
        }

        /* Drop (P7: 段计数) */
        gso = neoq_gso_segs(skb);
        plen = qdisc_pkt_len(skb);
        flow->dropped++;
        tier->dropped++;
        flow->deficit -= plen;
        qdisc_tree_reduce_backlog(sch, gso, plen);
        qdisc_qstats_drop(sch);
        kfree_skb(skb);
    }

    /* Update delay stats */
    delay = now - get_neoq_cb(skb)->enqueue_time;
    tier->avg_delay = ewma(tier->avg_delay, delay, 8);
    tier->peak_delay = ewma(tier->peak_delay, delay,
                            delay > tier->peak_delay ? 2 : 8);
    /* 近期峰值: 取真实最大值 (而非 EWMA), 由 neoq_ml 读取时清零 -> "上次读取以来的峰值"。 */
    if (delay > tier->peak_delay_ml)
        tier->peak_delay_ml = delay;
    if (delay < tier->base_delay || tier->base_delay == ~0ULL)
        tier->base_delay = delay;

    plen = qdisc_pkt_len(skb);
    flow->deficit -= plen;
    tier->tier_deficit -= plen;     /* WRR: 按服务字节扣减档位赤字 */

    /* === B1: 推进虚拟时钟 ===
     * 只对真正交付的包推进 —— 上面 CoDel 循环里被丢的包不占路径预算, 这正是"把丢弃
     * 从洲际段挪到本机"的收益本体 (丢一个包立刻腾出它那份发送时间给下一个包)。
     * floor 钳制是关键: 它杜绝空闲期积攒 credit (那正是 TBF 的桶会做、而我们要避免
     * 的事)。burst_ns 只用来吸收 hrtimer 的迟到抖动, 不是一个"桶"。
     * floor 用 now>burst 保护: ktime_get_ns() 在刚启动时可能小于 burst_ns, 无保护的
     * 减法会下溢成天文数字, 把 time_next_packet 顶到未来 -> qdisc 永久停摆。 */
    if (cfg) {
        u64 burst = READ_ONCE(neoq_burst_ns);
        u64 floor = now > burst ? now - burst : 0;
        u64 len_ns = ((u64)plen * (u32)(cfg >> 8)) >> (u8)cfg;

        if (q->time_next_packet < floor)
            q->time_next_packet = floor;
        q->time_next_packet += len_ns;
        q->shaper_sent_bytes += plen;
    }

    qdisc_bstats_update(sch, skb);
    q->total_packets++;
    q->total_bytes += plen;

    return skb;
}

static struct sk_buff *neoq_peek(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    int t;

    for (t = 0; t < NEOQ_MAX_TIERS; t++) {
        tier = &q->tiers[t];
        if (!list_empty(&tier->new_flows)) {
            flow = list_first_entry(&tier->new_flows,
                                    struct neoq_flow, flowchain);
            if (flow->head)
                return flow->head;
        }
        if (!list_empty(&tier->old_flows)) {
            flow = list_first_entry(&tier->old_flows,
                                    struct neoq_flow, flowchain);
            if (flow->head)
                return flow->head;
        }
    }
    return NULL;
}

/* ========================================================================
 * Init / Reset / Destroy
 * ======================================================================== */

/* 清空全局流表里所有 skb (表已不再每档独立), 并复位每个 flow 槽。 */
static void neoq_clear_flows(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;
    int i;

    if (!q->flows)
        return;

    for (i = 0; i < NEOQ_QUEUES; i++) {
        struct neoq_flow *flow = &q->flows[i];
        while ((skb = flow_dequeue(flow)) != NULL) {
            sch->qstats.backlog -= qdisc_pkt_len(skb);
            q->memory_used -= skb->truesize;
            sch->q.qlen -= neoq_gso_segs(skb);      /* 与入队段数对称 */
            kfree_skb(skb);
        }
        q->backlogs[i] = 0;
        INIT_LIST_HEAD(&flow->flowchain);
        flow->set = FLOW_NONE;
        flow->backlog = 0;
    }
}

/* 复位单个档位的 DRR 链表与计数 (skb 已由 neoq_clear_flows 释放) */
static void neoq_clear_tier(struct neoq_tier *tier)
{
    INIT_LIST_HEAD(&tier->new_flows);
    INIT_LIST_HEAD(&tier->old_flows);
    tier->sparse_cnt = 0;
    tier->bulk_cnt = 0;
    tier->backlog = 0;
    tier->tier_deficit = 0;
    tier->peak_delay_ml = 0;    /* 近期峰值随复位归零 */
}

static int neoq_init(struct Qdisc *sch, struct nlattr *opt,
                     struct netlink_ext_ack *extack)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    size_t tier_size, flow_size, total;
    int i, j;

    /* Default config */
    sch->limit = NEOQ_LIMIT_DEFAULT;
    q->limit = NEOQ_LIMIT_DEFAULT;
    q->quantum = NEOQ_QUANTUM;
    q->memory_limit = NEOQ_MEMORY_LIMIT;
    q->ecn = 1;
    q->http_boost = 1;  /* Enable by default */
    q->flows_cnt = 0;
    q->time_next_packet = 0;    /* B1: 虚拟时钟从"现在就可以发"起步 */

    /* 注: CoDel 的 target/interval 不在这里初始化 —— 它们是模块级全局量, 已在定义处
     * 带默认值。若在 init 里重写, 新建第二个 qdisc 实例会把用户态调好的值冲掉。 */

    get_random_bytes(&q->perturbation, sizeof(q->perturbation));

    /* Allocate tiers (仅元数据, flows 已全局) */
    tier_size = sizeof(struct neoq_tier) * NEOQ_MAX_TIERS;
    q->tiers = kvzalloc(tier_size, GFP_KERNEL);
    if (!q->tiers)
        return -ENOMEM;

    /* === 分配单一全局流表 (替代每档独立表) === */
    flow_size = sizeof(struct neoq_flow) * NEOQ_QUEUES;
    q->flows = kvzalloc(flow_size, GFP_KERNEL);
    q->backlogs = kvzalloc(sizeof(u32) * NEOQ_QUEUES, GFP_KERNEL);
    q->tags = kvzalloc(sizeof(u32) * NEOQ_QUEUES, GFP_KERNEL);
    if (!q->flows || !q->backlogs || !q->tags)
        goto err_free;

    total = flow_size + sizeof(u32) * NEOQ_QUEUES * 2;

    for (j = 0; j < NEOQ_QUEUES; j++) {
        INIT_LIST_HEAD(&q->flows[j].flowchain);
        q->flows[j].rec_inv_sqrt = ~0U;
    }

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        struct neoq_tier *tier = &q->tiers[i];

        INIT_LIST_HEAD(&tier->new_flows);
        INIT_LIST_HEAD(&tier->old_flows);
        tier->quantum = q->quantum;
        tier->tier_deficit = 0;
        tier->base_delay = ~0ULL;
    }

    qdisc_watchdog_init(&q->watchdog, sch);

    /* Register for proc stats */
    spin_lock_bh(&neoq_lock);
    neoq_active_qdisc = sch;
    spin_unlock_bh(&neoq_lock);

    pr_info("NeoQ v%s: %d tiers, global %d-queue flow table, %zu KB allocated\n",
            NEOQ_VERSION, NEOQ_MAX_TIERS, NEOQ_QUEUES, total / 1024);

    return 0;

err_free:
    kvfree(q->flows);
    kvfree(q->backlogs);
    kvfree(q->tags);
    kvfree(q->tiers);
    q->flows = NULL;
    q->backlogs = NULL;
    q->tags = NULL;
    q->tiers = NULL;
    return -ENOMEM;
}

static void neoq_reset(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    int i;

    if (!q->tiers)
        return;

    neoq_clear_flows(sch);              /* 释放全局表中所有 skb + 复位 flow 槽 */
    for (i = 0; i < NEOQ_MAX_TIERS; i++)
        neoq_clear_tier(&q->tiers[i]);  /* 复位每档链表/计数 */

    q->memory_used = 0;
    q->flows_cnt = 0;
    q->retrans_seen = 0;        /* retrans 免疫计数随复位归零 */
    q->retrans_protected = 0;
    q->retrans_demoted = 0;     /* FIX1: Express 防滥用计数随复位归零 */

    /* B3: ambient 采样窗口随复位归零, 否则复位后第一个包会立刻以一个极小样本
     * 滚动窗口, 算出一个无意义的 ambient_share。 */
    q->glob_win_pkts = 0;
    q->glob_win_retrans = 0;
    q->glob_win_start = 0;
    q->ambient_share = 0;

    /* B1: 队列已清空, 虚拟时钟必须归零 —— 否则重新激活后第一个包会被一个陈旧的
     * time_next_packet 无谓地挡住。同时取消可能在飞的整形定时器 (同 sch_tbf)。 */
    qdisc_watchdog_cancel(&q->watchdog);
    q->time_next_packet = 0;
    q->shaper_sent_bytes = 0;
    q->shaper_defer_cnt = 0;
}

static void neoq_destroy(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);

    /* Unregister from proc stats */
    spin_lock_bh(&neoq_lock);
    if (neoq_active_qdisc == sch)
        neoq_active_qdisc = NULL;
    spin_unlock_bh(&neoq_lock);

    qdisc_watchdog_cancel(&q->watchdog);
    neoq_reset(sch);

    /* 各结构各释放一次 */
    kvfree(q->flows);
    kvfree(q->backlogs);
    kvfree(q->tags);
    kvfree(q->tiers);
    q->flows = NULL;
    q->backlogs = NULL;
    q->tags = NULL;
    q->tiers = NULL;
}

/* ========================================================================
 * Netlink Config
 * ======================================================================== */

static const struct nla_policy neoq_policy[TCA_NEOQ_MAX + 1] = {
    [TCA_NEOQ_LIMIT]     = { .type = NLA_U32 },
    [TCA_NEOQ_MEMORY]    = { .type = NLA_U32 },
    [TCA_NEOQ_QUANTUM]   = { .type = NLA_U32 },
    [TCA_NEOQ_TARGET]    = { .type = NLA_U32 },
    [TCA_NEOQ_INTERVAL]  = { .type = NLA_U32 },
    [TCA_NEOQ_ECN]       = { .type = NLA_U32 },
    [TCA_NEOQ_HTTP_BOOST]= { .type = NLA_U32 },
    [TCA_NEOQ_FLOWS]     = { .type = NLA_U32 },
    [TCA_NEOQ_RATE64]    = { .type = NLA_U64 },
};

static int neoq_change(struct Qdisc *sch, struct nlattr *opt,
                       struct netlink_ext_ack *extack)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_NEOQ_MAX + 1];
    int err, i;

    if (!opt)
        return -EINVAL;

    err = nla_parse_nested(tb, TCA_NEOQ_MAX, opt, neoq_policy, extack);
    if (err < 0)
        return err;

    sch_tree_lock(sch);

    if (tb[TCA_NEOQ_LIMIT]) {
        q->limit = nla_get_u32(tb[TCA_NEOQ_LIMIT]);
        sch->limit = q->limit;
    }
    if (tb[TCA_NEOQ_MEMORY])
        q->memory_limit = nla_get_u32(tb[TCA_NEOQ_MEMORY]);
    if (tb[TCA_NEOQ_QUANTUM])
        q->quantum = clamp_t(u32, nla_get_u32(tb[TCA_NEOQ_QUANTUM]),
                             NEOQ_QUANTUM_MIN, NEOQ_QUANTUM_MAX);
    /* B5: target/interval 直写全局 —— netlink 与 /proc/net/neoq_codel 从此是同一份
     * 真相, 不再各存一份互不同步的副本。单位仍是微秒 (保持既有 netlink ABI)。 */
    if (tb[TCA_NEOQ_TARGET])
        WRITE_ONCE(neoq_codel_target_ns,
                   (u64)max_t(u32, nla_get_u32(tb[TCA_NEOQ_TARGET]), 1) * NSEC_PER_USEC);
    if (tb[TCA_NEOQ_INTERVAL])
        WRITE_ONCE(neoq_codel_interval_ns,
                   (u64)max_t(u32, nla_get_u32(tb[TCA_NEOQ_INTERVAL]), 1) * NSEC_PER_USEC);
    /* 整形速率: 主控制面是 /proc/net/neoq_rate, 这里只为 netlink 侧的对称性。
     * 属性单位 bit/s, 转成 kbps 交给同一个预计算函数, 不产生第二条计算路径。 */
    if (tb[TCA_NEOQ_RATE64]) {
        u64 rate64 = nla_get_u64(tb[TCA_NEOQ_RATE64]);
        u64 kbps = div64_u64(rate64, 1000);

        /* F4: 原来错在直接取整 —— 任何 0 < rate64 < 1000 都被 div64_u64 抹成 0, 而
         * neoq_rate_set(0) 的语义是"关闭整形 = 线速直通"。用户要 500bps, 拿到的是
         * 完全不限速: fail-open 的方向反了 (整形器的 fail-open 只允许发生在"没人配
         * 置"时, 不允许发生在"配了一个很小的值"时)。非零速率一律至少 1kbps;
         * rate64==0 仍保留"关闭"语义, 与 /proc 的 rate_kbps=0 和 neoq_dump 一致。 */
        if (rate64 && !kbps)
            kbps = 1;
        neoq_rate_set((u32)min_t(u64, kbps, (u64)U32_MAX));
    }
    if (tb[TCA_NEOQ_ECN])
        q->ecn = !!nla_get_u32(tb[TCA_NEOQ_ECN]);
    if (tb[TCA_NEOQ_HTTP_BOOST])
        q->http_boost = !!nla_get_u32(tb[TCA_NEOQ_HTTP_BOOST]);

    for (i = 0; i < NEOQ_MAX_TIERS; i++)
        q->tiers[i].quantum = q->quantum;

    sch_tree_unlock(sch);
    return 0;
}

static int neoq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct nlattr *opts;

    opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
    if (!opts)
        goto nla_put_failure;

    if (nla_put_u32(skb, TCA_NEOQ_LIMIT, q->limit) ||
        nla_put_u32(skb, TCA_NEOQ_MEMORY, q->memory_limit) ||
        nla_put_u32(skb, TCA_NEOQ_QUANTUM, q->quantum) ||
        /* B5: 从全局量反向换算回微秒上报, 不再有本地副本可与之不一致。 */
        nla_put_u32(skb, TCA_NEOQ_TARGET,
                    (u32)(READ_ONCE(neoq_codel_target_ns) / NSEC_PER_USEC)) ||
        nla_put_u32(skb, TCA_NEOQ_INTERVAL,
                    (u32)(READ_ONCE(neoq_codel_interval_ns) / NSEC_PER_USEC)) ||
        nla_put_u32(skb, TCA_NEOQ_ECN, q->ecn) ||
        nla_put_u32(skb, TCA_NEOQ_HTTP_BOOST, q->http_boost) ||
        nla_put_u32(skb, TCA_NEOQ_FLOWS, q->flows_cnt) ||
        nla_put_u64_64bit(skb, TCA_NEOQ_RATE64, READ_ONCE(neoq_rate_bps),
                          TCA_NEOQ_PAD))
        goto nla_put_failure;

    return nla_nest_end(skb, opts);

nla_put_failure:
    nla_nest_cancel(skb, opts);
    return -EMSGSIZE;
}

static int neoq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct nlattr *stats, *tstats, *ts;
    int i;

    /* Start app-specific stats nest */
    stats = nla_nest_start_noflag(d->skb, TCA_STATS_APP);
    if (!stats)
        return -1;

    /* Global stats */
    if (nla_put_u32(d->skb, TCA_NEOQ_STATS_MEMORY_USED, q->memory_used) ||
        nla_put_u32(d->skb, TCA_NEOQ_STATS_MEMORY_LIMIT, q->memory_limit) ||
        nla_put_u32(d->skb, TCA_NEOQ_STATS_FLOWS_TOTAL, NEOQ_QUEUES) ||
        nla_put_u32(d->skb, TCA_NEOQ_STATS_FLOWS_ACTIVE, q->flows_cnt))
        goto nla_put_failure;

    /* Delay stats from tier 0 (express) */
    if (q->tiers) {
        struct neoq_tier *t0 = &q->tiers[0];
        u32 avg_us = (u32)(t0->avg_delay / 1000);
        u32 peak_us = (u32)(t0->peak_delay / 1000);
        u32 base_us = t0->base_delay == ~0ULL ? 0 : (u32)(t0->base_delay / 1000);

        if (nla_put_u32(d->skb, TCA_NEOQ_STATS_AVG_DELAY_US, avg_us) ||
            nla_put_u32(d->skb, TCA_NEOQ_STATS_PEAK_DELAY_US, peak_us) ||
            nla_put_u32(d->skb, TCA_NEOQ_STATS_BASE_DELAY_US, base_us))
            goto nla_put_failure;
    }

    /* Per-tier stats (nested like CAKE) */
    tstats = nla_nest_start_noflag(d->skb, TCA_NEOQ_STATS_TIN_STATS);
    if (!tstats)
        goto nla_put_failure;

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        struct neoq_tier *tier = &q->tiers[i];
        u32 avg_us, peak_us, base_us;

        ts = nla_nest_start_noflag(d->skb, i + 1);
        if (!ts)
            goto nla_put_failure;

        avg_us = (u32)(tier->avg_delay / 1000);
        peak_us = (u32)(tier->peak_delay / 1000);
        base_us = tier->base_delay == ~0ULL ? 0 : (u32)(tier->base_delay / 1000);

        if (nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_PACKETS, (u32)tier->packets) ||
            nla_put_u64_64bit(d->skb, TCA_NEOQ_TIN_STATS_BYTES64, tier->bytes,
                              TCA_NEOQ_TIN_STATS_PAD) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_DROPPED, tier->dropped) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_ECN_MARKED, tier->ecn_marked) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_BACKLOG, tier->backlog) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_FLOWS,
                        tier->sparse_cnt + tier->bulk_cnt) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_AVG_DELAY_US, avg_us) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_PEAK_DELAY_US, peak_us) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_BASE_DELAY_US, base_us) ||
            /* way_* 哈希表统计已全局, 仅在 tier 0 (Express) 上报真实值, 其余报 0 */
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_INDIRECT,
                        i == 0 ? q->way_indirect : 0) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_MISS,
                        i == 0 ? q->way_miss : 0) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_COLLIDE,
                        i == 0 ? q->way_collide : 0))
            goto nla_put_failure;

        nla_nest_end(d->skb, ts);
    }

    nla_nest_end(d->skb, tstats);
    return nla_nest_end(d->skb, stats);

nla_put_failure:
    nla_nest_cancel(d->skb, stats);
    return -1;
}

/* ========================================================================
 * Proc Interface for Statistics
 * ======================================================================== */

static const char *tier_names[] = {"Express", "High", "Normal", "Bulk"};

static int neoq_stats_show(struct seq_file *m, void *v)
{
    struct Qdisc *sch;
    struct neoq_sched_data *q;
    int i;

    spin_lock_bh(&neoq_lock);
    sch = neoq_active_qdisc;
    if (!sch) {
        spin_unlock_bh(&neoq_lock);
        seq_puts(m, "NeoQ: No active instance\n");
        return 0;
    }

    q = qdisc_priv(sch);

    seq_puts(m, "===============================================\n");
    seq_printf(m, " NeoQ v%s Statistics\n", NEOQ_VERSION);
    seq_puts(m, "===============================================\n");
    seq_printf(m, " Queue Length:    %u / %u packets\n", sch->q.qlen, q->limit);
    seq_printf(m, " Memory:          %u / %u bytes\n", q->memory_used, q->memory_limit);
    seq_printf(m, " Active Flows:    %u / %u\n", q->flows_cnt, NEOQ_QUEUES);
    seq_printf(m, " HTTP Boost:      %s\n", q->http_boost ? "ON" : "OFF");
    seq_printf(m, " ECN:             %s\n", q->ecn ? "ON" : "OFF");
    seq_printf(m, " Target Delay:    %llu us\n", READ_ONCE(neoq_codel_target_ns) / 1000);
    seq_printf(m, " Interval:        %llu us\n", READ_ONCE(neoq_codel_interval_ns) / 1000);
    seq_puts(m, "-----------------------------------------------\n");
    seq_puts(m, " Tier       Packets       Bytes    Drops  Marks  Flows  Backlog\n");
    seq_puts(m, "-----------------------------------------------\n");

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        struct neoq_tier *tier = &q->tiers[i];
        seq_printf(m, " %-8s %10llu %11llu %8u %6u %6u %8u\n",
                   tier_names[i],
                   tier->packets,
                   tier->bytes,
                   tier->dropped,
                   tier->ecn_marked,
                   tier->sparse_cnt + tier->bulk_cnt,
                   tier->backlog);
    }

    seq_puts(m, "-----------------------------------------------\n");
    seq_puts(m, " Delay Statistics (Tier 0 - Express):\n");
    if (q->tiers[0].avg_delay > 0) {
        seq_printf(m, "   Average:  %llu us\n", q->tiers[0].avg_delay / 1000);
        seq_printf(m, "   Peak:     %llu us\n", q->tiers[0].peak_delay / 1000);
        seq_printf(m, "   Base:     %llu us\n",
                   q->tiers[0].base_delay == ~0ULL ? 0 : q->tiers[0].base_delay / 1000);
    } else {
        seq_puts(m, "   (no data yet)\n");
    }
    seq_puts(m, "===============================================\n");

    spin_unlock_bh(&neoq_lock);
    return 0;
}

static int neoq_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_stats_show, NULL);
}

static const struct proc_ops neoq_proc_ops = {
    .proc_open    = neoq_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *neoq_proc_entry;

/* === /proc/net/neoq_prio: configurable game/web priority ports === */
static int neoq_prio_show(struct seq_file *m, void *v)
{
    unsigned int port;
    int n = 0;
    seq_puts(m, "NeoQ priority ports (-> EXPRESS tier):\n");
    for_each_set_bit(port, neoq_prio_portmap, 65536) {
        seq_printf(m, "%u ", port);
        if (++n % 16 == 0)
            seq_putc(m, '\n');
    }
    seq_printf(m, "\ntotal %d; usage: echo \"+27015 +443 -80 clear\" > /proc/net/neoq_prio\n", n);
    return 0;
}

static int neoq_prio_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_prio_show, NULL);
}

static ssize_t neoq_prio_write(struct file *file, const char __user *ubuf,
                               size_t len, loff_t *ppos)
{
    char buf[256], *p, *tok;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    p = buf;
    while ((tok = strsep(&p, " \t\n")) != NULL) {
        int add = 1;
        unsigned int port;
        if (*tok == '\0')
            continue;
        if (!strcmp(tok, "clear")) {
            bitmap_zero(neoq_prio_portmap, 65536);
            continue;
        }
        if (*tok == '+') {
            tok++;
        } else if (*tok == '-') {
            add = 0;
            tok++;
        }
        if (kstrtouint(tok, 10, &port) || port > 65535)
            continue;
        if (add)
            set_bit(port, neoq_prio_portmap);
        else
            clear_bit(port, neoq_prio_portmap);
    }
    return len;
}

static const struct proc_ops neoq_prio_proc_ops = {
    .proc_open    = neoq_prio_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_prio_write,
};

static struct proc_dir_entry *neoq_prio_entry;

/* 注: /proc/net/neoq_boost 已随 neoq_boost_rwnd() 一并删除 (死因见该函数原址注释)。 */

/* === /proc/net/neoq_codel: CoDel target/interval in microseconds === */
static int neoq_codel_show(struct seq_file *m, void *v)
{
    seq_printf(m, "target_us=%llu interval_us=%llu\nusage: echo \"<target_us> <interval_us>\" > /proc/net/neoq_codel\n",
               READ_ONCE(neoq_codel_target_ns) / 1000, READ_ONCE(neoq_codel_interval_ns) / 1000);
    return 0;
}
static int neoq_codel_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_codel_show, NULL);
}
static ssize_t neoq_codel_write(struct file *file, const char __user *ubuf,
                                size_t len, loff_t *ppos)
{
    char buf[64];
    unsigned int t = 0, iv = 0;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    if (sscanf(buf, "%u %u", &t, &iv) >= 1) {
        if (t)
            WRITE_ONCE(neoq_codel_target_ns, (u64)t * 1000);
        if (iv)
            WRITE_ONCE(neoq_codel_interval_ns, (u64)iv * 1000);
    }
    return len;
}
static const struct proc_ops neoq_codel_proc_ops = {
    .proc_open    = neoq_codel_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_codel_write,
};
static struct proc_dir_entry *neoq_codel_entry;

/* === /proc/net/neoq_sparse: CAKE 风格稀疏门控窗口/阈值 === */
static int neoq_sparse_show(struct seq_file *m, void *v)
{
    seq_printf(m, "window_us=%llu thresh_bytes=%u\nusage: echo \"<window_us> <thresh_bytes>\" > /proc/net/neoq_sparse  (thresh=0 disables demotion)\n",
               READ_ONCE(neoq_sparse_window_ns) / 1000,
               READ_ONCE(neoq_sparse_thresh_bytes));
    return 0;
}
static int neoq_sparse_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_sparse_show, NULL);
}
static ssize_t neoq_sparse_write(struct file *file, const char __user *ubuf,
                                 size_t len, loff_t *ppos)
{
    char buf[64];
    unsigned int win = 0, thr = 0;
    int got;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    got = sscanf(buf, "%u %u", &win, &thr);
    if (got >= 1 && win)
        WRITE_ONCE(neoq_sparse_window_ns, (u64)win * 1000);
    if (got >= 2)                       /* thr=0 合法: 表示禁用降级 */
        WRITE_ONCE(neoq_sparse_thresh_bytes, thr);
    return len;
}
static const struct proc_ops neoq_sparse_proc_ops = {
    .proc_open    = neoq_sparse_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_sparse_write,
};
static struct proc_dir_entry *neoq_sparse_entry;

/* === /proc/net/neoq_retrans: Express 防滥用门 (地板 + 相对倍数) ===
 * B3: 有效阈值 = max(share_max, min(100, rel_factor * ambient_share / 100))。
 * share_max 是地板 (0 = 关闭整个门), rel_factor 是相对链路常态重传率的倍数(%)。 */
static int neoq_retrans_show(struct seq_file *m, void *v)
{
    struct Qdisc *sch;
    u32 ambient = 0;

    spin_lock_bh(&neoq_lock);
    sch = neoq_active_qdisc;
    if (sch)
        ambient = ((struct neoq_sched_data *)qdisc_priv(sch))->ambient_share;
    spin_unlock_bh(&neoq_lock);

    seq_printf(m, "share_max=%u rel_factor=%u ambient_share=%u\n"
                  "usage: echo \"<share_max> [rel_factor]\" > /proc/net/neoq_retrans  (share_max=0 disables gate; defaults 15 200)\n",
               READ_ONCE(neoq_retrans_share_max), READ_ONCE(neoq_retrans_rel),
               ambient);
    return 0;
}
static int neoq_retrans_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_retrans_show, NULL);
}
static ssize_t neoq_retrans_write(struct file *file, const char __user *ubuf,
                                  size_t len, loff_t *ppos)
{
    char buf[64];
    unsigned int share = 0, rel = 0;
    int got;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    got = sscanf(buf, "%u %u", &share, &rel);
    if (got >= 1) {                     /* share=0 合法 = 关闭门控 */
        if (share > 100)                /* 占比上限 100% */
            share = 100;
        WRITE_ONCE(neoq_retrans_share_max, share);
    }
    if (got >= 2 && rel) {
        if (rel > 10000)                /* 钳到 100 倍: 保证 rel*ambient 不溢出 u32 */
            rel = 10000;
        WRITE_ONCE(neoq_retrans_rel, rel);
    }
    return len;
}
static const struct proc_ops neoq_retrans_proc_ops = {
    .proc_open    = neoq_retrans_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_retrans_write,
};
static struct proc_dir_entry *neoq_retrans_entry;

/* === /proc/net/neoq_rate: B1 虚拟时钟整形器速率/突发 ===
 * 写 "<rate_kbps> [burst_us]", rate_kbps=0 关闭整形 (透明直通)。
 * 用 kbps 做单位: u32 可覆盖到 4.3Tbps, 用户态高频写一个整数即可, 无需浮点。
 * defer 是"因整形而推迟出队"的次数 —— 它长期为 0 就说明整形根本没排到队 (速率设高了)。 */
static int neoq_rate_show(struct seq_file *m, void *v)
{
    struct Qdisc *sch;
    u64 sent = 0, defer = 0;

    spin_lock_bh(&neoq_lock);
    sch = neoq_active_qdisc;
    if (sch) {
        struct neoq_sched_data *q = qdisc_priv(sch);

        sent = q->shaper_sent_bytes;
        defer = q->shaper_defer_cnt;
    }
    spin_unlock_bh(&neoq_lock);

    /* burst_us / limit_pkts 都读的是内核实际生效值 (已钳制过), 这样 F5 的钳制和 F1
     * 的派生上界都能被 cat 出来看见, 不会出现"写进去的值和跑着的值不一样"的静默失效。 */
    seq_printf(m, "rate_kbps=%u burst_us=%llu queue_ms=%u limit_pkts=%u sent_bytes=%llu defer=%llu\n"
                  "usage: echo \"<rate_kbps> [burst_us] [queue_ms]\" > /proc/net/neoq_rate  (0 disables shaping)\n",
               (u32)div64_u64(READ_ONCE(neoq_rate_bps), 1000),
               READ_ONCE(neoq_burst_ns) / 1000,
               READ_ONCE(neoq_queue_ms), READ_ONCE(neoq_limit_pkts),
               sent, defer);
    return 0;
}
static int neoq_rate_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_rate_show, NULL);
}
static ssize_t neoq_rate_write(struct file *file, const char __user *ubuf,
                               size_t len, loff_t *ppos)
{
    char buf[64];
    unsigned int kbps = 0, burst_us = 0, queue_ms = 0;
    int got;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    got = sscanf(buf, "%u %u %u", &kbps, &burst_us, &queue_ms);
    if (got < 1)
        return len;
    /* 先设 burst / queue_ms 再设速率: 速率一旦生效 dequeue 就会用到 burst_ns, 而
     * queue_ms 是 neoq_rate_set 里派生段数上界的输入, 必须先就位。
     * F5: burst 上钳到 NEOQ_BURST_US_MAX —— 原来 %u 直接落盘, 4294967295 会把 burst
     * 变成 4295 秒, 整形闸门静默失效 (推导见 NEOQ_BURST_US_MAX 处)。 */
    if (got >= 2 && burst_us)
        WRITE_ONCE(neoq_burst_ns,
                   (u64)min_t(unsigned int, burst_us, NEOQ_BURST_US_MAX) *
                   NSEC_PER_USEC);
    if (got >= 3 && queue_ms)
        WRITE_ONCE(neoq_queue_ms,
                   clamp_t(unsigned int, queue_ms, 1U, NEOQ_QUEUE_MS_MAX));
    neoq_rate_set(kbps);                /* kbps=0 = 关闭 */
    return len;
}
static const struct proc_ops neoq_rate_proc_ops = {
    .proc_open    = neoq_rate_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_rate_write,
};
static struct proc_dir_entry *neoq_rate_entry;

/* === /proc/net/neoq_ml: 机器可读单行 key=value, 供 Go tuner 每隔数秒解析 ===
 * 与 neoq_stats_show 共用 neoq_lock。键名短且稳定 (即 CLI 的 API), 切勿随意改名。
 * peak_delay_us 为"上次读取以来"的峰值 -> 本处 read-on-reset 清零 (human-readable 的
 * /proc/net/neoq 不受影响, 仍是全时段 EWMA 峰值)。 */
static int neoq_ml_show(struct seq_file *m, void *v)
{
    struct Qdisc *sch;
    struct neoq_sched_data *q;
    u32 sparse_total = 0, bulk_total = 0;
    int i;

    spin_lock_bh(&neoq_lock);
    sch = neoq_active_qdisc;
    if (!sch) {
        spin_unlock_bh(&neoq_lock);
        /* 无活动实例: 仍输出零值单行, 使 tuner 解析逻辑统一 (无需特判空文件)。 */
        seq_puts(m,
            "qlen=0 mem=0 flows=0 sparse_flows=0 bulk_flows=0 "
            "t0_pkts=0 t0_bytes=0 t0_drops=0 t0_marks=0 t0_avg_delay_us=0 t0_peak_delay_us=0 "
            "t1_pkts=0 t1_bytes=0 t1_drops=0 t1_marks=0 t1_avg_delay_us=0 t1_peak_delay_us=0 "
            "t2_pkts=0 t2_bytes=0 t2_drops=0 t2_marks=0 t2_avg_delay_us=0 t2_peak_delay_us=0 "
            "t3_pkts=0 t3_bytes=0 t3_drops=0 t3_marks=0 t3_avg_delay_us=0 t3_peak_delay_us=0 "
            "retrans_seen=0 retrans_protected=0 retrans_demoted=0 "
            "rate_kbps=0 backlog=0 shaper_sent=0 shaper_defer=0 ambient_share=0\n");
        return 0;
    }

    q = qdisc_priv(sch);

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        sparse_total += q->tiers[i].sparse_cnt;
        bulk_total += q->tiers[i].bulk_cnt;
    }

    seq_printf(m, "qlen=%u mem=%u flows=%u sparse_flows=%u bulk_flows=%u",
               sch->q.qlen, q->memory_used, q->flows_cnt,
               sparse_total, bulk_total);

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        struct neoq_tier *tier = &q->tiers[i];
        u64 avg_us = tier->avg_delay / 1000;
        u64 peak_us = tier->peak_delay_ml / 1000;

        seq_printf(m,
            " t%d_pkts=%llu t%d_bytes=%llu t%d_drops=%u t%d_marks=%u t%d_avg_delay_us=%llu t%d_peak_delay_us=%llu",
            i, tier->packets, i, tier->bytes, i, tier->dropped,
            i, tier->ecn_marked, i, avg_us, i, peak_us);

        tier->peak_delay_ml = 0;        /* read-on-reset: 清掉已上报的近期峰值 */
    }

    /* 新键追加在行尾: Go 侧解析器对未知键忽略, 老版本 tuner 前向兼容。
     * backlog 用 sch->qstats.backlog (字节), 与 qlen(段数) 互补 —— 整形开启后
     * 队列在本机成形, 这两个量才是判断"整形是否真的生效"的直接证据。
     * ambient_share: 上一完整 1s 窗口的全链路重传占比 (0-100)。此前只在人可读的
     * /proc/net/neoq_retrans 里露出, 机器可读口这边没有, 用户态只能用 ss 差分自己
     * 估环境丢包 —— 口径更脏 (不是滚动窗、含纯 ACK、含哈希冲突包)。qdisc 侧这份是
     * 现成的干净锚点, 直接导出即可。 */
    seq_printf(m, " retrans_seen=%llu retrans_protected=%llu retrans_demoted=%llu"
                  " rate_kbps=%u backlog=%u shaper_sent=%llu shaper_defer=%llu"
                  " ambient_share=%u\n",
               q->retrans_seen, q->retrans_protected, q->retrans_demoted,
               (u32)div64_u64(READ_ONCE(neoq_rate_bps), 1000),
               sch->qstats.backlog, q->shaper_sent_bytes, q->shaper_defer_cnt,
               q->ambient_share);

    spin_unlock_bh(&neoq_lock);
    return 0;
}

static int neoq_ml_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_ml_show, NULL);
}

static const struct proc_ops neoq_ml_proc_ops = {
    .proc_open    = neoq_ml_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
static struct proc_dir_entry *neoq_ml_entry;

/* ========================================================================
 * Module Registration
 * ======================================================================== */

static struct Qdisc_ops neoq_qdisc_ops __read_mostly = {
    .id         = "neoq",
    .priv_size  = sizeof(struct neoq_sched_data),
    .enqueue    = neoq_enqueue,
    .dequeue    = neoq_dequeue,
    .peek       = neoq_peek,
    .init       = neoq_init,
    .reset      = neoq_reset,
    .destroy    = neoq_destroy,
    .change     = neoq_change,
    .dump       = neoq_dump,
    .dump_stats = neoq_dump_stats,
    .owner      = THIS_MODULE,
};

static int __init neoq_module_init(void)
{
    int ret;

    pr_info("NeoQ v%s: High-Performance Multi-Tier Queue Discipline\n",
            NEOQ_VERSION);

    ret = register_qdisc(&neoq_qdisc_ops);
    if (ret) {
        pr_err("NeoQ: register_qdisc failed: %d\n", ret);
        return ret;
    }

    /* Create /proc/net/neoq using init_net.proc_net as parent */
    neoq_proc_entry = proc_create("neoq", 0444, init_net.proc_net, &neoq_proc_ops);
    if (!neoq_proc_entry)
        pr_warn("NeoQ: Failed to create /proc/net/neoq\n");
    else
        pr_info("NeoQ: Stats available at /proc/net/neoq\n");

    neoq_prio_entry = proc_create("neoq_prio", 0644, init_net.proc_net, &neoq_prio_proc_ops);
    if (neoq_prio_entry)
        pr_info("NeoQ: Priority ports config at /proc/net/neoq_prio\n");

    neoq_rate_entry = proc_create("neoq_rate", 0644, init_net.proc_net, &neoq_rate_proc_ops);
    if (neoq_rate_entry)
        pr_info("NeoQ: Virtual-clock shaper at /proc/net/neoq_rate\n");

    neoq_codel_entry = proc_create("neoq_codel", 0644, init_net.proc_net, &neoq_codel_proc_ops);
    if (neoq_codel_entry)
        pr_info("NeoQ: CoDel target/interval at /proc/net/neoq_codel\n");

    neoq_sparse_entry = proc_create("neoq_sparse", 0644, init_net.proc_net, &neoq_sparse_proc_ops);
    if (neoq_sparse_entry)
        pr_info("NeoQ: Sparse gate window/thresh at /proc/net/neoq_sparse\n");

    neoq_retrans_entry = proc_create("neoq_retrans", 0644, init_net.proc_net, &neoq_retrans_proc_ops);
    if (neoq_retrans_entry)
        pr_info("NeoQ: Express retrans-abuse gate at /proc/net/neoq_retrans\n");

    neoq_ml_entry = proc_create("neoq_ml", 0444, init_net.proc_net, &neoq_ml_proc_ops);
    if (neoq_ml_entry)
        pr_info("NeoQ: Machine-readable stats at /proc/net/neoq_ml\n");

    return 0;
}

static void __exit neoq_module_exit(void)
{
    if (neoq_proc_entry)
        proc_remove(neoq_proc_entry);
    if (neoq_prio_entry)
        proc_remove(neoq_prio_entry);
    if (neoq_rate_entry)
        proc_remove(neoq_rate_entry);
    if (neoq_codel_entry)
        proc_remove(neoq_codel_entry);
    if (neoq_sparse_entry)
        proc_remove(neoq_sparse_entry);
    if (neoq_retrans_entry)
        proc_remove(neoq_retrans_entry);
    if (neoq_ml_entry)
        proc_remove(neoq_ml_entry);

    unregister_qdisc(&neoq_qdisc_ops);
    pr_info("NeoQ: Unloaded\n");
}

module_init(neoq_module_init);
module_exit(neoq_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LotSpeed Project");
MODULE_DESCRIPTION("NeoQ v3.1: High-Performance Multi-Tier Queue Discipline with Retransmit Priority");
MODULE_VERSION(NEOQ_VERSION);
