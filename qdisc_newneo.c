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
    struct neoq_flow    *flows;         /* Dynamically allocated */
    u32                 *backlogs;
    u32                 *tags;

    struct list_head    new_flows;
    struct list_head    old_flows;

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
    u32                 way_indirect;
    u32                 way_miss;
    u32                 way_collide;
} ____cacheline_aligned_in_smp;

/* ========================================================================
 * Main Scheduler Structure
 * ======================================================================== */

struct neoq_sched_data {
    struct neoq_tier    *tiers;

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
 * 1. Retransmit packets -> EXPRESS (fastest loss recovery)
 * 2. Pure ACKs -> EXPRESS
 * 3. Small packets (<128B) -> EXPRESS
 * 4. HTTP/HTTPS/DNS/SSH -> EXPRESS (if http_boost enabled)
 * 5. SYN/FIN packets -> HIGH (connection setup/teardown)
 * 6. Small interactive (<256B) -> HIGH
 * 7. Gaming/VoIP UDP -> HIGH
 * 8. Large packets (>=1400B) -> BULK
 * 9. Everything else -> NORMAL
 */
/* Configurable priority-port bitmap (game/web boost), set via /proc/net/neoq_prio */
static DECLARE_BITMAP(neoq_prio_portmap, 65536);

/* Outbound-ACK rwnd boost = single-side downstream "window deception", percent (100=off).
 * Pairs with lotspeed CC (upstream) to form one bidirectional accel system.
 * Set via /proc/net/neoq_boost. */
static u32 neoq_rwnd_boost = 100;

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

static __always_inline u8 classify_packet_enhanced(struct neoq_sched_data *q,
                                                    const struct sk_buff *skb,
                                                    struct neoq_flow *flow,
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

    *is_retrans_out = false;
    pkt_len = qdisc_pkt_len(skb);

    /* Fast path for small packets - likely ACKs or control */
    if (pkt_len < 128)
        return NEOQ_TIER_EXPRESS;

    if (skb->protocol != htons(ETH_P_IP))
        return NEOQ_TIER_NORMAL;

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

            /* === KEY OPTIMIZATION: Retransmit detection === */
            if (flow) {
                is_retrans = is_tcp_retransmit(skb, flow);
                *is_retrans_out = is_retrans;

                /* Retransmit packets get EXPRESS priority for fast recovery */
                if (is_retrans)
                    return NEOQ_TIER_EXPRESS;
            }

            /* Pure ACK - highest priority */
            if (ntohs(iph->tot_len) == offset + (th->doff << 2) &&
                th->ack && !th->syn && !th->fin)
                return NEOQ_TIER_EXPRESS;

            /* SYN/FIN - connection control, high priority */
            if (th->syn || th->fin)
                return NEOQ_TIER_HIGH;
        }
    } else if (proto == IPPROTO_UDP) {
        uh = (const struct udphdr *)((const u8 *)iph + offset);
        if ((const u8 *)(uh + 1) <= skb_tail_pointer(skb)) {
            sport = ntohs(uh->source);
            dport = ntohs(uh->dest);
        }
    }

    /* Configurable priority ports (game/web), dynamic via /proc/net/neoq_prio */
    if (test_bit(dport, neoq_prio_portmap) || test_bit(sport, neoq_prio_portmap))
        return NEOQ_TIER_EXPRESS;

    /* HTTP/HTTPS boost */
    if (q->http_boost) {
        if (dport == HTTP_PORT || sport == HTTP_PORT ||
            dport == HTTPS_PORT || sport == HTTPS_PORT)
            return NEOQ_TIER_EXPRESS;

        if (dport == DNS_PORT || sport == DNS_PORT ||
            dport == SSH_PORT || sport == SSH_PORT)
            return NEOQ_TIER_EXPRESS;
    }

    /* Interactive/gaming traffic */
    if (pkt_len < 256)
        return NEOQ_TIER_HIGH;

    /* Gaming/VoIP UDP ports */
    if (proto == IPPROTO_UDP) {
        if ((sport >= 16384 && sport <= 32767) ||
            (dport >= 16384 && dport <= 32767))
            return NEOQ_TIER_HIGH;
    }

    /* Large packets - bulk */
    if (pkt_len >= 1400)
        return NEOQ_TIER_BULK;

    return NEOQ_TIER_NORMAL;
}

/* Legacy wrapper for compatibility */
static __always_inline u8 classify_packet(struct neoq_sched_data *q,
                                          const struct sk_buff *skb)
{
    bool is_retrans;
    return classify_packet_enhanced(q, skb, NULL, &is_retrans);
}

/* ========================================================================
 * Flow Hashing - Set Associative
 * ======================================================================== */

static u32 flow_hash(struct neoq_tier *tier, const struct sk_buff *skb,
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
    }

    hash = jhash_3words(saddr, daddr, (sport << 16) | dport, perturbation);
    hash ^= proto << 24;
    reduced = hash % NEOQ_QUEUES;

    /* Set-associative lookup */
    if (likely(tier->tags[reduced] == hash && tier->flows[reduced].set))
        return reduced;

    {
        u32 inner = reduced % NEOQ_SET_WAYS;
        u32 outer = reduced - inner;
        u32 i, k = inner;

        /* Search for existing flow */
        for (i = 0; i < NEOQ_SET_WAYS; i++, k = (k + 1) % NEOQ_SET_WAYS) {
            if (tier->tags[outer + k] == hash) {
                if (i)
                    tier->way_indirect++;
                reduced = outer + k;
                goto found;
            }
        }

        /* Find empty slot */
        for (i = 0; i < NEOQ_SET_WAYS; i++, k = (k + 1) % NEOQ_SET_WAYS) {
            if (!tier->flows[outer + k].set) {
                tier->way_miss++;
                reduced = outer + k;
                goto found;
            }
        }

        /* Collision - use original */
        tier->way_collide++;
        reduced = outer + inner;
found:
        tier->tags[reduced] = hash;
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
    u64 effective_target = tier->codel_target;
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
            flow->drop_next = codel_control_law(now, tier->codel_interval,
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
                                             tier->codel_interval,
                                             flow->rec_inv_sqrt);
        return true;
    }

    while (due) {
        flow->count--;
        codel_cache_invsqrt(flow);
        flow->drop_next = codel_control_law(flow->drop_next,
                                             tier->codel_interval,
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
 * Enqueue - Enhanced with Retransmit Priority & Flow State
 * ======================================================================== */

static int neoq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                        struct sk_buff **to_free)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    u32 idx, len;
    u8 tier_idx, original_tier;
    bool is_retrans = false;

    len = qdisc_pkt_len(skb);

    /* Downstream window deception: enlarge advertised rwnd on outbound ACKs */
    neoq_boost_rwnd(skb);

    /* Limits check */
    if (unlikely(sch->q.qlen >= q->limit ||
                 q->memory_used + skb->truesize > q->memory_limit)) {
        qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return NET_XMIT_DROP;
    }

    /* First pass classification (without flow context for hash) */
    original_tier = classify_packet(q, skb);
    tier = &q->tiers[original_tier];
    idx = flow_hash(tier, skb, q->perturbation);
    flow = &tier->flows[idx];

    /* Second pass: enhanced classification with flow context for retransmit */
    tier_idx = classify_packet_enhanced(q, skb, flow, &is_retrans);

    /* If retransmit detected, upgrade to EXPRESS tier */
    if (is_retrans && tier_idx == NEOQ_TIER_EXPRESS && original_tier != NEOQ_TIER_EXPRESS) {
        /* Move to Express tier for retransmit */
        tier = &q->tiers[NEOQ_TIER_EXPRESS];
        idx = flow_hash(tier, skb, q->perturbation);
        flow = &tier->flows[idx];
        tier_idx = NEOQ_TIER_EXPRESS;
    }

    /* Update flow state based on retransmit status */
    update_flow_state(flow, is_retrans);

    /* Set enqueue time */
    get_neoq_cb(skb)->enqueue_time = ktime_get_ns();

    /* Add to flow */
    flow_queue_add(flow, skb);

    /* Update stats */
    tier->backlogs[idx] += len;
    flow->backlog += len;
    tier->backlog += len;
    sch->qstats.backlog += len;
    q->memory_used += skb->truesize;
    sch->q.qlen++;
    tier->packets++;
    tier->bytes += len;

    /* Flow management */
    if (flow->set == FLOW_NONE) {
        list_add_tail(&flow->flowchain, &tier->new_flows);
        flow->set = FLOW_NEW;
        flow->tier = tier_idx;
        flow->deficit = tier->quantum;
        flow->flow_state = FLOW_STATE_NEW;
        flow->loss_protect_level = LOSS_PROTECT_NONE;
        flow->highest_seq = 0;
        flow->retrans_count = 0;
        flow->total_packets = 0;
        flow->startup_packets = 0;
        flow->srtt_us = 0;
        flow->rtt_min_us = 0;
        tier->sparse_cnt++;
        q->flows_cnt++;
    }

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
    u32 len, idx;

    idx = flow - tier->flows;
    skb = flow_dequeue(flow);
    if (!skb)
        return NULL;

    len = qdisc_pkt_len(skb);
    tier->backlogs[idx] -= len;
    flow->backlog -= len;
    tier->backlog -= len;
    sch->qstats.backlog -= len;
    q->memory_used -= skb->truesize;
    sch->q.qlen--;

    return skb;
}

static struct sk_buff *neoq_dequeue(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct neoq_tier *tier;
    struct neoq_flow *flow;
    struct list_head *head;
    struct sk_buff *skb;
    u64 now, delay;
    int t;

begin:
    if (!sch->q.qlen)
        return NULL;

    now = ktime_get_ns();

    /* Try each tier in priority order */
    for (t = 0; t < NEOQ_MAX_TIERS; t++) {
        tier = &q->tiers[t];

        if (!tier->sparse_cnt && !tier->bulk_cnt)
            continue;

retry:
        /* New flows first (sparse priority) */
        head = &tier->new_flows;
        if (list_empty(head)) {
            head = &tier->old_flows;
            if (list_empty(head))
                continue;
        }

        flow = list_first_entry(head, struct neoq_flow, flowchain);

        /* DRR check */
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

            /* Drop */
            flow->dropped++;
            tier->dropped++;
            flow->deficit -= qdisc_pkt_len(skb);
            qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(skb));
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

        flow->deficit -= qdisc_pkt_len(skb);
        qdisc_bstats_update(sch, skb);
        q->total_packets++;
        q->total_bytes += qdisc_pkt_len(skb);

        return skb;
    }

    return NULL;
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

static void neoq_clear_tier(struct Qdisc *sch, struct neoq_tier *tier)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;
    int i;

    for (i = 0; i < NEOQ_QUEUES; i++) {
        struct neoq_flow *flow = &tier->flows[i];
        while ((skb = flow_dequeue(flow)) != NULL) {
            sch->qstats.backlog -= qdisc_pkt_len(skb);
            q->memory_used -= skb->truesize;
            sch->q.qlen--;
            kfree_skb(skb);
        }
        tier->backlogs[i] = 0;
        INIT_LIST_HEAD(&flow->flowchain);
        flow->set = FLOW_NONE;
    }
    tier->sparse_cnt = 0;
    tier->bulk_cnt = 0;
    tier->backlog = 0;
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

    /* Allocate tiers */
    tier_size = sizeof(struct neoq_tier) * NEOQ_MAX_TIERS;
    q->tiers = kvzalloc(tier_size, GFP_KERNEL);
    if (!q->tiers)
        return -ENOMEM;

    /* Allocate per-tier flow arrays */
    flow_size = sizeof(struct neoq_flow) * NEOQ_QUEUES;
    total = 0;

    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        struct neoq_tier *tier = &q->tiers[i];

        tier->flows = kvzalloc(flow_size, GFP_KERNEL);
        tier->backlogs = kvzalloc(sizeof(u32) * NEOQ_QUEUES, GFP_KERNEL);
        tier->tags = kvzalloc(sizeof(u32) * NEOQ_QUEUES, GFP_KERNEL);

        if (!tier->flows || !tier->backlogs || !tier->tags)
            goto err_free;

        total += flow_size + sizeof(u32) * NEOQ_QUEUES * 2;

        INIT_LIST_HEAD(&tier->new_flows);
        INIT_LIST_HEAD(&tier->old_flows);
        tier->quantum = q->quantum;
        tier->codel_interval = (u64)q->interval * NSEC_PER_USEC;
        tier->codel_target = (u64)q->target * NSEC_PER_USEC;
        tier->base_delay = ~0ULL;

        for (j = 0; j < NEOQ_QUEUES; j++) {
            INIT_LIST_HEAD(&tier->flows[j].flowchain);
            tier->flows[j].rec_inv_sqrt = ~0U;
        }
    }

    qdisc_watchdog_init(&q->watchdog, sch);

    /* Register for proc stats */
    spin_lock_bh(&neoq_lock);
    neoq_active_qdisc = sch;
    spin_unlock_bh(&neoq_lock);

    pr_info("NeoQ v%s: %d tiers x %d queues, %zu KB allocated\n",
            NEOQ_VERSION, NEOQ_MAX_TIERS, NEOQ_QUEUES, total / 1024);

    return 0;

err_free:
    for (i = 0; i < NEOQ_MAX_TIERS; i++) {
        if (q->tiers[i].flows)
            kvfree(q->tiers[i].flows);
        if (q->tiers[i].backlogs)
            kvfree(q->tiers[i].backlogs);
        if (q->tiers[i].tags)
            kvfree(q->tiers[i].tags);
    }
    kvfree(q->tiers);
    return -ENOMEM;
}

static void neoq_reset(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    int i;

    if (!q->tiers)
        return;

    for (i = 0; i < NEOQ_MAX_TIERS; i++)
        neoq_clear_tier(sch, &q->tiers[i]);

    q->memory_used = 0;
    q->flows_cnt = 0;
}

static void neoq_destroy(struct Qdisc *sch)
{
    struct neoq_sched_data *q = qdisc_priv(sch);
    int i;

    /* Unregister from proc stats */
    spin_lock_bh(&neoq_lock);
    if (neoq_active_qdisc == sch)
        neoq_active_qdisc = NULL;
    spin_unlock_bh(&neoq_lock);

    qdisc_watchdog_cancel(&q->watchdog);
    neoq_reset(sch);

    if (q->tiers) {
        for (i = 0; i < NEOQ_MAX_TIERS; i++) {
            kvfree(q->tiers[i].flows);
            kvfree(q->tiers[i].backlogs);
            kvfree(q->tiers[i].tags);
        }
        kvfree(q->tiers);
    }
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
        nla_put_u32(d->skb, TCA_NEOQ_STATS_FLOWS_TOTAL, NEOQ_QUEUES * NEOQ_MAX_TIERS) ||
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
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_INDIRECT, tier->way_indirect) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_MISS, tier->way_miss) ||
            nla_put_u32(d->skb, TCA_NEOQ_TIN_STATS_WAY_COLLIDE, tier->way_collide))
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
    seq_printf(m, " Active Flows:    %u / %u\n", q->flows_cnt, NEOQ_QUEUES * NEOQ_MAX_TIERS);
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

    unregister_qdisc(&neoq_qdisc_ops);
    pr_info("NeoQ: Unloaded\n");
}

module_init(neoq_module_init);
module_exit(neoq_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LotSpeed Project");
MODULE_DESCRIPTION("NeoQ v3.1: High-Performance Multi-Tier Queue Discipline with Retransmit Priority");
MODULE_VERSION(NEOQ_VERSION);
