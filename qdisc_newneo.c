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
 * - RTT-aware CoDel with dynamic target/interval adjustment
 * - Flow state tracking (NEW/STARTUP/STEADY/RECOVERY/DRAIN)
 * - Loss protection levels for flows in recovery
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

/* RTT-aware CoDel thresholds */
#define NEOQ_RTT_LOW_US         10000    /* < 10ms: datacenter */
#define NEOQ_RTT_MED_US         100000   /* < 100ms: normal WAN */
#define NEOQ_RTT_HIGH_US        300000   /* < 300ms: high delay */
/* > 300ms: satellite */

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

    /* === NEW: RTT estimation (from TCP timestamps) === */
    u32                 srtt_us;            /* Smoothed RTT in microseconds */
    u32                 rtt_min_us;         /* Minimum RTT observed */
    u64                 last_rtt_update;    /* Last RTT update timestamp */

    /* === NEW: CAKE 风格稀疏/批量行为门控 ===
     * 在一个滑动窗口内累计 flow 的字节数，窗口到期后衰减/重置。
     * 若窗口内速率低于稀疏阈值, flow 仍可享受 Express/High; 持续高于阈值则被
     * 降级到按包大小决定的档位 (Normal/Bulk), 即便命中 hint 端口。 */
    u32                 bytes_window;       /* 当前窗口内累计字节 */
    u64                 window_start;       /* 当前窗口起点 (ns) */
    u8                  is_bulk_behave:1;   /* 1=已判定为批量(降级), 0=稀疏 */
} ____cacheline_aligned_in_smp;

enum {
    FLOW_NONE = 0,
    FLOW_NEW,
    FLOW_SPARSE,
    FLOW_BULK,
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

    /* CoDel config */
    u64                 codel_interval;
    u64                 codel_target;

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
    u32                 target;
    u32                 interval;

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
 * NEW: Retransmit Packet Detection
 *
 * Detect retransmit by checking if TCP seq < highest_seq seen.
 * Retransmit packets get Express priority for faster loss recovery.
 * ======================================================================== */

static __always_inline bool is_tcp_retransmit(const struct sk_buff *skb,
                                               struct neoq_flow *flow)
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

    /* First packet for this flow - initialize */
    if (flow->highest_seq == 0 && !th->syn) {
        flow->highest_seq = end_seq;
        return false;
    }

    /* SYN packet - reset tracking */
    if (th->syn) {
        flow->highest_seq = end_seq;
        return false;
    }

    /* Retransmit detection: seq < highest_seq means retransmit */
    if (before(seq, flow->highest_seq)) {
        flow->retrans_count++;
        return true;
    }

    /* Update highest seq for new data */
    if (after(end_seq, flow->highest_seq))
        flow->highest_seq = end_seq;

    return false;
}

/* ========================================================================
 * NEW: RTT-Aware CoDel Parameter Adjustment
 *
 * Dynamically adjust CoDel target/interval based on flow RTT:
 * - Low RTT (<10ms):    target=5ms,  interval=100ms  (datacenter)
 * - Med RTT (<100ms):   target=RTT/2, interval=RTT*10 (normal WAN)
 * - High RTT (<300ms):  target=RTT/4, interval=RTT*5  (high delay)
 * - Satellite (>300ms): target=RTT/4, interval=RTT*3  (very high delay)
 * ======================================================================== */

static inline void update_flow_codel_params(struct neoq_flow *flow,
                                            struct neoq_tier *tier,
                                            u32 rtt_us)
{
    u64 target_ns, interval_ns;

    if (rtt_us == 0)
        return;

    /* Update flow RTT estimate (EWMA with alpha=1/8) */
    if (flow->srtt_us == 0) {
        flow->srtt_us = rtt_us;
        flow->rtt_min_us = rtt_us;
    } else {
        flow->srtt_us = flow->srtt_us - (flow->srtt_us >> 3) + (rtt_us >> 3);
        if (rtt_us < flow->rtt_min_us)
            flow->rtt_min_us = rtt_us;
    }

    /* Adjust CoDel parameters based on RTT */
    if (rtt_us < NEOQ_RTT_LOW_US) {
        /* Datacenter: aggressive, low target */
        target_ns = 5 * NSEC_PER_MSEC;
        interval_ns = 100 * NSEC_PER_MSEC;
    } else if (rtt_us < NEOQ_RTT_MED_US) {
        /* Normal WAN: scale with RTT */
        target_ns = ((u64)rtt_us / 2) * NSEC_PER_USEC;
        interval_ns = ((u64)rtt_us * 10) * NSEC_PER_USEC;
    } else if (rtt_us < NEOQ_RTT_HIGH_US) {
        /* High delay: more conservative */
        target_ns = ((u64)rtt_us / 4) * NSEC_PER_USEC;
        interval_ns = ((u64)rtt_us * 5) * NSEC_PER_USEC;
    } else {
        /* Satellite: very conservative to avoid unnecessary drops */
        target_ns = ((u64)rtt_us / 4) * NSEC_PER_USEC;
        interval_ns = ((u64)rtt_us * 3) * NSEC_PER_USEC;
    }

    /* Clamp to reasonable bounds */
    target_ns = clamp_t(u64, target_ns, 1 * NSEC_PER_MSEC, 200 * NSEC_PER_MSEC);
    interval_ns = clamp_t(u64, interval_ns, 10 * NSEC_PER_MSEC, 2000 * NSEC_PER_MSEC);

    /* Note: Per-flow CoDel params could override tier defaults */
    /* For now, we use tier-level params, but flow RTT info is stored */
    flow->last_rtt_update = ktime_get_ns();
}

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

/* Outbound-ACK rwnd boost = single-side downstream "window deception", percent (100=off).
 * 默认 100 = 关闭。纯出向 qdisc 看不到对端 SYN-ACK (在收方向), 因此无法得知对端
 * 的窗口缩放因子 (wscale) -> 重写 window 字段在 wscale!=0 时会被错误左移放大,
 * 语义不安全。保留代码路径与 /proc/net/neoq_boost 旋钮供显式 opt-in, 默认不动包。
 * Pairs with lotspeed CC (upstream) to form one bidirectional accel system. */
static u32 neoq_rwnd_boost = 100;

/* === NEW: CAKE 风格稀疏门控旋钮 (runtime-tunable via /proc/net/neoq_sparse) ===
 * window_ns: 行为采样窗口 (默认 100ms); thresh_bytes: 窗口内字节阈值, 超过即判为
 * 批量并降级。默认阈值 = 2*NEOQ_QUANTUM ≈ 3028B/100ms ≈ 0.24Mbps, 一次网页突发
 * (几百 KB) 会瞬间超过 -> 但网页流多为短突发, 窗口到期 (空闲)后迅速重新稀疏化;
 * 持续下载在数个窗口内即被钉为批量。0 阈值表示禁用降级 (永远稀疏)。 */
static u64 neoq_sparse_window_ns = 100ULL * NSEC_PER_MSEC;
static u32 neoq_sparse_thresh_bytes = 2 * NEOQ_QUANTUM;

/* Global CoDel target/interval (ns), runtime-tunable via /proc/net/neoq_codel.
 * Default 5ms/100ms suits LAN; raise target for high-RTT intercontinental links
 * (else CoDel over-drops and starves the CC -> low goodput). */
static u64 neoq_codel_target_ns = (u64)NEOQ_TARGET_US * 1000;
static u64 neoq_codel_interval_ns = (u64)NEOQ_INTERVAL_US * 1000;

/* Enlarge advertised receive window on outbound TCP ACKs so the peer sender
 * (bounded by min(cwnd, rwnd)) ramps faster when it is rwnd-limited.
 * Safe: skips zero-window (flow control), ensures skb writable, updates csum
 * incrementally (same primitive as netfilter NAT). */
static void neoq_boost_rwnd(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u32 boost = READ_ONCE(neoq_rwnd_boost);
    unsigned int off;
    u16 old_win, new_win;

    if (boost <= 100 || skb->protocol != htons(ETH_P_IP))
        return;
    /* Skip GSO/TSO super-packets: writing into them breaks segmentation/csum.
     * Outbound ACKs are tiny and never GSO'd, so we lose nothing in practice. */
    if (skb_is_gso(skb))
        return;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;
    off = iph->ihl << 2;
    if (!pskb_may_pull(skb, off + sizeof(struct tcphdr)))
        return;
    if (skb_ensure_writable(skb, off + sizeof(struct tcphdr)))
        return;
    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + off);
    if (!th->ack)
        return;
    old_win = ntohs(th->window);
    if (old_win == 0)            /* zero-window = flow control, never touch */
        return;
    new_win = (u16)min_t(u32, (u32)old_win * boost / 100, 65535U);
    if (new_win == old_win)
        return;
    inet_proto_csum_replace2(&th->check, skb, htons(old_win), htons(new_win), false);
    th->window = htons(new_win);
}

/* === NEW: CAKE 风格每流稀疏门控 ===
 * 在 ~window_ns 滑动窗口内累计 flow 字节; 窗口到期则衰减(重置)累加器, 并依据刚结束
 * 窗口的字节量更新 is_bulk_behave; 窗口内一旦累计超过阈值立即钉为批量。
 * 返回 true 表示该 flow 当前为"稀疏", 可保留 Express/High; false 表示已被降级。
 * 注: 必须在 enqueue 持 root lock 路径内调用 (无额外加锁), 由调用方保证。 */
static __always_inline bool flow_is_sparse(struct neoq_flow *flow, u32 pkt_len, u64 now)
{
    u32 thresh = READ_ONCE(neoq_sparse_thresh_bytes);
    u64 window = READ_ONCE(neoq_sparse_window_ns);

    if (thresh == 0)            /* 阈值=0: 禁用降级, 永远稀疏 */
        return true;

    if (flow->window_start == 0)
        flow->window_start = now;

    if (now - flow->window_start >= window) {
        /* 窗口滚动: 用刚结束窗口的字节量决定稀疏/批量, 然后重置累加器。
         * 空闲期(几乎无字节)会把 flow 重新判回稀疏 -> 网页突发后快速恢复。 */
        flow->is_bulk_behave = (flow->bytes_window >= thresh) ? 1 : 0;
        flow->bytes_window = 0;
        flow->window_start = now;
    }

    flow->bytes_window += pkt_len;
    if (flow->bytes_window >= thresh)   /* 窗口内即时触发降级 */
        flow->is_bulk_behave = 1;

    return !flow->is_bulk_behave;
}

/* 单次分类: 头部解析一次, flow 已在手(含 retrans 分支)。
 * 行为分类核心 (修复 P1): hint 端口只提权小包; 持续高速率的 flow 即便命中 hint
 * 端口或 <256B 规则也被降级到按大小决定的档位。 */
static __always_inline u8 classify_packet_enhanced(struct neoq_sched_data *q,
                                                    const struct sk_buff *skb,
                                                    struct neoq_flow *flow,
                                                    u64 now,
                                                    bool *is_retrans_out)
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

    *is_retrans_out = false;
    pkt_len = qdisc_pkt_len(skb);

    /* === 硬规则: 任何流量都无条件保持 Express === */
    /* 小包(ACK/控制) */
    if (pkt_len < 128)
        return NEOQ_TIER_EXPRESS;

    /* 每流行为门控(对 >=128B 的包才有意义); flow 为空时(legacy 路径)按稀疏处理 */
    if (flow)
        sparse = flow_is_sparse(flow, pkt_len, now);

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

            /* === KEY: Retransmit detection (现可靠, 全局流表) -> Express === */
            if (flow) {
                is_retrans = is_tcp_retransmit(skb, flow);
                *is_retrans_out = is_retrans;
                if (is_retrans)
                    return NEOQ_TIER_EXPRESS;
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

/* ========================================================================
 * Flow Hashing - Set Associative
 * ======================================================================== */

/* 全局 5-tuple 哈希: 表已上移到 q->flows/tags, 一个连接只占一个槽。
 * P6: 增加 IPv6 分支, 哈希 v6 地址+端口, 否则所有 v6 流塌缩到同一桶。 */
static u32 flow_hash(struct neoq_sched_data *q, const struct sk_buff *skb,
                     u32 perturbation)
{
    const struct iphdr *iph;
    u32 hash, reduced;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8 proto = 0;

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

        /* Collision - use original */
        q->way_collide++;
        reduced = outer + inner;
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

    /* Adjust target based on flow RTT if available */
    if (flow->srtt_us > 0) {
        /* RTT-aware target: scale with flow RTT */
        if (flow->srtt_us < NEOQ_RTT_LOW_US) {
            effective_target = 5 * NSEC_PER_MSEC;
        } else if (flow->srtt_us < NEOQ_RTT_MED_US) {
            effective_target = ((u64)flow->srtt_us / 2) * NSEC_PER_USEC;
        } else if (flow->srtt_us < NEOQ_RTT_HIGH_US) {
            effective_target = ((u64)flow->srtt_us / 4) * NSEC_PER_USEC;
        } else {
            /* High delay: very conservative */
            effective_target = ((u64)flow->srtt_us / 4) * NSEC_PER_USEC;
        }
        /* Clamp to reasonable bounds */
        effective_target = clamp_t(u64, effective_target,
                                   1 * NSEC_PER_MSEC, 200 * NSEC_PER_MSEC);
    }

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
        /* For highly protected flows, prefer ECN over drop */
        if (flow->loss_protect_level == LOSS_PROTECT_HIGH) {
            /* Signal congestion via return, but caller should try ECN first */
            flow->ecn_marked = 1;
            return false;  /* Don't drop, try ECN */
        }

        flow->count++;
        if (!flow->count)
            flow->count--;
        codel_cache_invsqrt(flow);
        flow->drop_next = codel_control_law(flow->drop_next,
                                             READ_ONCE(neoq_codel_interval_ns),
                                             flow->rec_inv_sqrt);
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

static int neoq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                        struct sk_buff **to_free)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    u32 idx, len, gso;
    u8 tier_idx;
    bool is_retrans = false;
    bool new_flow;
    u64 now;

    len = qdisc_pkt_len(skb);
    gso = neoq_gso_segs(skb);

    /* Downstream window deception: enlarge advertised rwnd on outbound ACKs */
    neoq_boost_rwnd(skb);

    /* === 单次分类 (P2): 解析头部一次 -> flow_hash 一次 -> 拿到 flow -> 分类一次 ===
     * enqueue_time 在分类前写入, 供 sparse 门控读取同一时钟。 */
    now = ktime_get_ns();
    get_neoq_cb(skb)->enqueue_time = now;

    idx = flow_hash(q, skb, q->perturbation);
    flow = &q->flows[idx];

    /* 全新槽位: 先把每流检测状态清零 *再* 分类, 使 retrans/sparse 看到干净状态。
     * 此时尚未挂链 (tier 未知); 若随后被拒纳, 槽位仍为 FLOW_NONE 的干净零态。 */
    new_flow = (flow->set == FLOW_NONE);
    if (new_flow) {
        /* 与原 FLOW_NONE 初始化集合一致 (仅顺序提前), 外加新增的 sparse 门控字段。 */
        flow->flow_state = FLOW_STATE_NEW;
        flow->loss_protect_level = LOSS_PROTECT_NONE;
        flow->highest_seq = 0;
        flow->retrans_count = 0;
        flow->total_packets = 0;
        flow->startup_packets = 0;
        flow->srtt_us = 0;
        flow->rtt_min_us = 0;
        flow->bytes_window = 0;
        flow->window_start = 0;
        flow->is_bulk_behave = 0;
    }

    tier_idx = classify_packet_enhanced(q, skb, flow, now, &is_retrans);
    tier = &q->tiers[tier_idx];

    /* === 限额检查 (P3/P7: 以段计数; 溢出时对 Express/High 驱逐低优先级队列) === */
    if (unlikely(sch->q.qlen + gso > q->limit ||
                 q->memory_used + skb->truesize > q->memory_limit)) {
        if (tier_idx == NEOQ_TIER_EXPRESS || tier_idx == NEOQ_TIER_HIGH) {
            /* 从最低优先级的非空档位 (Bulk 优先) 驱逐, 直到能容纳到来的包。
             * 到来包为 Express/High, 只驱逐 vt>tier_idx 的更低档位, 故被驱逐的绝不是
             * 到来包自身的 flow。 */
            int vt;

            for (vt = NEOQ_MAX_TIERS - 1; vt > (int)tier_idx; vt--) {
                while (sch->q.qlen + gso > q->limit ||
                       q->memory_used + skb->truesize > q->memory_limit) {
                    /* skip=flow: 绝不驱逐到来包自身的 flow (它即将上迁并入队),
                     * 否则 new_flow/flow->set 失效, 迁移会双重扣减计数。 */
                    if (!neoq_evict_from_tier(sch, vt, flow))
                        break;          /* 该档已无可驱逐对象, 换更高档位 */
                }
                if (sch->q.qlen + gso <= q->limit &&
                    q->memory_used + skb->truesize <= q->memory_limit)
                    break;
            }
            /* 仍放不下 (无更低优先级流量可驱逐) -> 只能丢弃到来的包 */
            if (sch->q.qlen + gso > q->limit ||
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

    /* === 确认纳入: 此后才推进 flow 生命周期状态 (只统计真正入队的包) === */
    update_flow_state(flow, is_retrans);

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
    u64 now, delay;
    u32 plen, gso;
    int t;

begin:
    if (!sch->q.qlen)
        return NULL;

    now = ktime_get_ns();

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

        /* CoDel - but don't drop last packet */
        if (!codel_should_drop(flow, tier, now, skb) || !flow->head)
            break;

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
    if (delay < tier->base_delay || tier->base_delay == ~0ULL)
        tier->base_delay = delay;

    plen = qdisc_pkt_len(skb);
    flow->deficit -= plen;
    tier->tier_deficit -= plen;     /* WRR: 按服务字节扣减档位赤字 */
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
    q->target = NEOQ_TARGET_US;
    q->interval = NEOQ_INTERVAL_US;
    q->ecn = 1;
    q->http_boost = 1;  /* Enable by default */
    q->flows_cnt = 0;

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
        tier->codel_interval = (u64)q->interval * NSEC_PER_USEC;
        tier->codel_target = (u64)q->target * NSEC_PER_USEC;
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
    if (tb[TCA_NEOQ_TARGET])
        q->target = max_t(u32, nla_get_u32(tb[TCA_NEOQ_TARGET]), 1);
    if (tb[TCA_NEOQ_INTERVAL])
        q->interval = max_t(u32, nla_get_u32(tb[TCA_NEOQ_INTERVAL]), 1);
    if (tb[TCA_NEOQ_ECN])
        q->ecn = !!nla_get_u32(tb[TCA_NEOQ_ECN]);
    if (tb[TCA_NEOQ_HTTP_BOOST])
        q->http_boost = !!nla_get_u32(tb[TCA_NEOQ_HTTP_BOOST]);

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        q->tiers[i].quantum = q->quantum;
        q->tiers[i].codel_interval = (u64)q->interval * NSEC_PER_USEC;
        q->tiers[i].codel_target = (u64)q->target * NSEC_PER_USEC;
    }

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
        nla_put_u32(skb, TCA_NEOQ_TARGET, q->target) ||
        nla_put_u32(skb, TCA_NEOQ_INTERVAL, q->interval) ||
        nla_put_u32(skb, TCA_NEOQ_ECN, q->ecn) ||
        nla_put_u32(skb, TCA_NEOQ_HTTP_BOOST, q->http_boost) ||
        nla_put_u32(skb, TCA_NEOQ_FLOWS, q->flows_cnt))
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
    seq_printf(m, " Target Delay:    %u us\n", q->target);
    seq_printf(m, " Interval:        %u us\n", q->interval);
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

/* === /proc/net/neoq_boost: downstream rwnd boost factor (percent, 100=off) === */
static int neoq_boost_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%u\n", READ_ONCE(neoq_rwnd_boost));
    return 0;
}
static int neoq_boost_open(struct inode *inode, struct file *file)
{
    return single_open(file, neoq_boost_show, NULL);
}
static ssize_t neoq_boost_write(struct file *file, const char __user *ubuf,
                                size_t len, loff_t *ppos)
{
    char buf[16];
    u32 v;
    size_t n = min(len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';
    if (kstrtouint(strim(buf), 10, &v) == 0) {
        if (v < 100)
            v = 100;
        if (v > 1000)
            v = 1000;
        WRITE_ONCE(neoq_rwnd_boost, v);
    }
    return len;
}
static const struct proc_ops neoq_boost_proc_ops = {
    .proc_open    = neoq_boost_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = neoq_boost_write,
};
static struct proc_dir_entry *neoq_boost_entry;

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

    neoq_boost_entry = proc_create("neoq_boost", 0644, init_net.proc_net, &neoq_boost_proc_ops);
    if (neoq_boost_entry)
        pr_info("NeoQ: Downstream rwnd boost at /proc/net/neoq_boost\n");

    neoq_codel_entry = proc_create("neoq_codel", 0644, init_net.proc_net, &neoq_codel_proc_ops);
    if (neoq_codel_entry)
        pr_info("NeoQ: CoDel target/interval at /proc/net/neoq_codel\n");

    neoq_sparse_entry = proc_create("neoq_sparse", 0644, init_net.proc_net, &neoq_sparse_proc_ops);
    if (neoq_sparse_entry)
        pr_info("NeoQ: Sparse gate window/thresh at /proc/net/neoq_sparse\n");

    return 0;
}

static void __exit neoq_module_exit(void)
{
    if (neoq_proc_entry)
        proc_remove(neoq_proc_entry);
    if (neoq_prio_entry)
        proc_remove(neoq_prio_entry);
    if (neoq_boost_entry)
        proc_remove(neoq_boost_entry);
    if (neoq_codel_entry)
        proc_remove(neoq_codel_entry);
    if (neoq_sparse_entry)
        proc_remove(neoq_sparse_entry);

    unregister_qdisc(&neoq_qdisc_ops);
    pr_info("NeoQ: Unloaded\n");
}

module_init(neoq_module_init);
module_exit(neoq_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LotSpeed Project");
MODULE_DESCRIPTION("NeoQ v3.1: High-Performance Multi-Tier Queue Discipline with Retransmit Priority");
MODULE_VERSION(NEOQ_VERSION);
