/*
 * tcp_accel_engine.c
 *
 * A standalone TCP acceleration helper inspired by the appex0v3.c engine,
 *
 * Features:
 *   - Per‑flow ACK queue with coalescing
 *   - Global ACK scheduler with buckets
 *   - Helper for fast IPv4 + TCP/UDP checksum calculation
 *
 * This file is self‑contained and only depends on standard Linux kernel
 * networking headers. You are expected to:
 *   - Call tcp_accel_engine_init() once at module init
 *   - Call tcp_accel_engine_cleanup() at module exit
 *   - Create a tcp_accel_flow_ctx for each TCP flow you want to accelerate
 *   - Wire your own hook to call tcp_accel_queue_ack() and
 *     tcp_accel_schedule_acks() at appropriate times
 *
 * IMPORTANT:
 *   - This file does NOT touch any global Netfilter hooks by itself.
 *   - It does NOT allocate or send sk_buffs; instead it calls a user‑provided
 *     callback to actually create and send ACK‑only packets.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* =========================
 * Time helpers (microseconds)
 * ========================= */

static inline u32 tcpaccel_get_time_us(void)
{
    /* ktime_get_ns() is monotonic; convert to microseconds */
    return (u32)(ktime_to_ns(ktime_get()) / 1000ULL);
}

/* =========================
 * Checksum helpers
 * ========================= */

static inline __sum16 tcpaccel_fold_u32(u32 sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (__sum16)(~sum);
}

static u32 tcpaccel_sum_16(const u8 *p, size_t len)
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

/* IPv4 header checksum */
static __sum16 tcpaccel_ip4_checksum(const struct iphdr *iph)
{
    u32 sum = tcpaccel_sum_16((const u8 *)iph, iph->ihl * 4u);
    return tcpaccel_fold_u32(sum);
}

/* TCP/UDP checksum including IPv4 pseudo header */
static __sum16 tcpaccel_l4_checksum(const struct iphdr *iph,
                                    const void *l4,
                                    size_t len,
                                    u8 proto)
{
    u32 sum = 0;
    const u8 *p = l4;

    /* pseudo header */
    sum += ntohs((__force __be16)(iph->saddr >> 16));
    sum += ntohs((__force __be16)(iph->saddr & 0xFFFFu));
    sum += ntohs((__force __be16)(iph->daddr >> 16));
    sum += ntohs((__force __be16)(iph->daddr & 0xFFFFu));
    sum += proto;
    sum += len;

    sum += tcpaccel_sum_16(p, len);
    return tcpaccel_fold_u32(sum);
}

/*
 * Fast TX checksum helper: software version of what appex0v3.c did in
 * _ACCE_LinuxFastTxChecksum, but simplified and without ACCE dependencies.
 *
 * Call this right before sending an skb, AFTER all header fields are
 * final (IP length, ports, flags, etc).
 *
 * If your NIC supports hardware checksum offload you can choose to skip
 * or adapt parts of this function.
 */
void tcpaccel_fast_tx_fix_checksums(struct sk_buff *skb, bool force_sw)
{
    struct iphdr *iph;
    void *l4;
    u16 ip_tot_len;
    u16 ihl_bytes;
    u16 l4_len;

    if (!skb)
        return;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return;

    ihl_bytes = iph->ihl * 4u;
    if (!pskb_may_pull(skb, ihl_bytes))
        return;

    ip_tot_len = ntohs(iph->tot_len);
    if (ip_tot_len < ihl_bytes)
        return;

    if (!pskb_may_pull(skb, ip_tot_len))
        return;

    l4 = (u8 *)iph + ihl_bytes;
    l4_len = ip_tot_len - ihl_bytes;

    /* If caller does NOT force software checksum and hardware offload is
     * enabled, you may want to just set skb->ip_summed = CHECKSUM_PARTIAL
     * and fill csum_start / csum_offset instead of computing here.
     */
    if (!force_sw && skb->ip_summed == CHECKSUM_PARTIAL)
        return;

    /* Recompute IPv4 header checksum */
    iph->check = 0;
    iph->check = tcpaccel_ip4_checksum(iph);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        th->check = 0;
        th->check = tcpaccel_l4_checksum(iph, th, l4_len, IPPROTO_TCP);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        uh->check = 0;
        uh->check = tcpaccel_l4_checksum(iph, uh, l4_len, IPPROTO_UDP);
        if (uh->check == 0)
            uh->check = CSUM_MANGLED_0;
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    } else {
        /* Non‑TCP/UDP, nothing to do */
    }
}

/* =========================
 * ACK queue & scheduler
 * ========================= */

/*
 * We keep the ACK scheduling logic separate from any particular flow
 * structure. The engine sees opaque "flow context" pointers and calls
 * a user‑provided callback to actually build & send ACK‑only packets.
 */

/* forward declaration so we can reference struct tcp_accel_flow later */
struct tcp_accel_flow;

/*
 * User‑provided operations for ACK‑only packet generation.
 *
 * build_and_send_ack() must:
 *   - Construct an ACK‑only skb for the given flow / ack_seq / ack_win
 *   - Fix headers & checksums as necessary (you may call the helper above)
 *   - Queue it for TX (netif_rx / dev_queue_xmit / nf_hook / etc)
 *
 * Return 0 on success, <0 on error.
 */
struct tcp_accel_flow_ops {
    int (*build_and_send_ack)(struct tcp_accel_flow *flow,
                              u32 ack_seq,
                              u16 ack_win);
};

/* One queued ACK node */
struct tcp_accel_ack_node {
    struct tcp_accel_ack_node *flow_prev;
    struct tcp_accel_ack_node *flow_next;

    struct tcp_accel_ack_node *sched_prev;
    struct tcp_accel_ack_node *sched_next;

    struct tcp_accel_flow *flow;

    u32 ack_seq;
    u16 ack_win;
    u16 age_ticks;   /* how long this ACK has been pending (ms) */
    u32 last_ts;     /* last update timestamp in us */
};

/* Per‑flow ACK queue information */
struct tcp_accel_ack_queue {
    struct tcp_accel_ack_node *head;
    struct tcp_accel_ack_node *tail;
    u16 depth;
    u8  bucket_idx;  /* which bucket we are in */
    u8  scheduled;   /* 1 if this flow is present in engine's sched buckets */
};

/*
 * Per‑flow context used by the engine.
 * You are free to embed this into your own flow structure or keep a
 * separate mapping from your Flow struct to this.
 */
struct tcp_accel_flow {
    void *user_flow;               /* opaque pointer back to your own Flow */
    struct tcp_accel_ack_queue ackq;

    u32 last_acked_seq;
    u16 queued_acks;
    u16 flags;

    u16 default_win;
};

/* Engine‑global configuration and state */

#define TCPACCEL_ACK_BUCKETS          32u
#define TCPACCEL_ACK_MAX_QUEUE_DEPTH  64u
#define TCPACCEL_ACK_MAX_AGE_TICKS    0x15B4  /* from appex: max delta clamp (~5.5 KB analogy) */
#define TCPACCEL_ACK_DELAY_TICKS      50      /* default delay threshold in ms */

/* One bucket contains flows that currently have pending ACKs */
struct tcp_accel_bucket {
    struct tcp_accel_ack_node *head;
    struct tcp_accel_ack_node *tail;
};

struct tcp_accel_engine {
    struct tcp_accel_bucket buckets[TCPACCEL_ACK_BUCKETS];
    u8   bucket_cursor;     /* round‑robin cursor */
    u16  scheduled_flows;   /* number of flows present in buckets */
    u32  stat_ack_q_full;
    u32  stat_ack_merge;
    u32  stat_ack_created;

    struct tcp_accel_flow_ops ops;

    /* Protects all engine + flow ack structures */
    spinlock_t lock;
};

/* =========================
 * Engine init / cleanup
 * ========================= */

void tcpaccel_engine_init(struct tcp_accel_engine *eng,
                          const struct tcp_accel_flow_ops *ops)
{
    int i;

    memset(eng, 0, sizeof(*eng));
    for (i = 0; i < TCPACCEL_ACK_BUCKETS; ++i) {
        eng->buckets[i].head = NULL;
        eng->buckets[i].tail = NULL;
    }
    if (ops)
        eng->ops = *ops;
    spin_lock_init(&eng->lock);
}

void tcpaccel_engine_cleanup(struct tcp_accel_engine *eng)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&eng->lock, flags);
    for (i = 0; i < TCPACCEL_ACK_BUCKETS; ++i) {
        struct tcp_accel_ack_node *n = eng->buckets[i].head;
        while (n) {
            struct tcp_accel_ack_node *next = n->sched_next;
            kfree(n);
            n = next;
        }
        eng->buckets[i].head = NULL;
        eng->buckets[i].tail = NULL;
    }
    eng->scheduled_flows = 0;
    spin_unlock_irqrestore(&eng->lock, flags);
}

/* You are expected to call this when a new flow is created.
 * 'user_flow' is any pointer that lets you get back to your own flow
 * structure; default_win is the initial receive window for this flow.
 */
void tcpaccel_flow_init(struct tcp_accel_flow *flow, void *user_flow, u16 default_win)
{
    memset(flow, 0, sizeof(*flow));
    flow->user_flow   = user_flow;
    flow->default_win = default_win;
}

/* =========================
 * Internal helpers
 * ========================= */

static inline u32 tcpaccel_get_time_ms(void)
{
    return tcpaccel_get_time_us() / 1000U;
}

static struct tcp_accel_ack_node *
tcpaccel_alloc_ack_node(struct tcp_accel_engine *eng)
{
    struct tcp_accel_ack_node *n = kzalloc(sizeof(*n), GFP_ATOMIC);
    if (!n)
        eng->stat_ack_q_full++;
    return n;
}

static void
tcpaccel_free_ack_node(struct tcp_accel_ack_node *n)
{
    kfree(n);
}

static void
tcpaccel_unlink_ack_node(struct tcp_accel_engine *eng,
                         struct tcp_accel_ack_node *n)
{
    struct tcp_accel_flow *flow = n->flow;
    struct tcp_accel_bucket *b =
        &eng->buckets[flow->ackq.bucket_idx & (TCPACCEL_ACK_BUCKETS - 1u)];

    /* unlink from per‑flow list */
    if (n->flow_prev)
        n->flow_prev->flow_next = n->flow_next;
    else
        flow->ackq.head = n->flow_next;

    if (n->flow_next)
        n->flow_next->flow_prev = n->flow_prev;
    else
        flow->ackq.tail = n->flow_prev;

    if (flow->ackq.depth)
        flow->ackq.depth--;
    if (flow->queued_acks)
        flow->queued_acks--;

    /* unlink from bucket list */
    if (n->sched_prev)
        n->sched_prev->sched_next = n->sched_next;
    else
        b->head = n->sched_next;

    if (n->sched_next)
        n->sched_next->sched_prev = n->sched_prev;
    else
        b->tail = n->sched_prev;

    if (!flow->ackq.depth && flow->ackq.scheduled) {
        flow->ackq.scheduled = 0;
        if (eng->scheduled_flows)
            eng->scheduled_flows--;
    }
}

/*
 * Main entry: queue a new ACK for a flow.
 *
 * Behaviour mirrors the semantics in _ACCE_ESchdQueueAckPacket:
 *   - If ack_seq does not advance, just update internal delta and return
 *   - If there is already a pending ACK node for this flow, coalesce:
 *       keep only the newest (largest) ack_seq / window
 *   - When the first ACK is queued for a flow, insert flow into the
 *     engine's bucket list
 *
 * Returns:
 *   0 on success
 *   -ENOMEM if queue full / allocation fails
 */
int tcpaccel_queue_ack(struct tcp_accel_engine *eng,
                       struct tcp_accel_flow *flow,
                       u32 ack_seq,
                       u16 ack_win)
{
    struct tcp_accel_ack_node *n;
    struct tcp_accel_bucket *b;
    u32 now_ms;
    int delta;
    unsigned long flags;

    if (!eng || !flow)
        return -EINVAL;

    now_ms = tcpaccel_get_time_ms();

    spin_lock_irqsave(&eng->lock, flags);

    /* No progress: treat as merge discard */
    if ((s32)(ack_seq - flow->last_acked_seq) <= 0) {
        eng->stat_ack_merge++;
        spin_unlock_irqrestore(&eng->lock, flags);
        return 0;
    }

    n = flow->ackq.tail;

    if (n) {
        /* Coalesce: keep only the newest ACK */
        if ((s32)(ack_seq - n->ack_seq) >= 0) {
            n->ack_seq = ack_seq;
            n->ack_win = ack_win;
            eng->stat_ack_merge++;

            delta = (s32)(now_ms - n->last_ts);
            if (delta > 0) {
                if (delta > TCPACCEL_ACK_MAX_AGE_TICKS)
                    delta = TCPACCEL_ACK_MAX_AGE_TICKS;
                n->age_ticks = (u16)delta;
            } else {
                n->age_ticks = 0;
            }
            n->last_ts = now_ms;

            spin_unlock_irqrestore(&eng->lock, flags);
            return 0;
        }
    }

    /* Too many pending ACKs for this flow */
    if (flow->ackq.depth >= TCPACCEL_ACK_MAX_QUEUE_DEPTH) {
        eng->stat_ack_q_full++;
        spin_unlock_irqrestore(&eng->lock, flags);
        return -ENOMEM;
    }

    n = tcpaccel_alloc_ack_node(eng);
    if (!n) {
        spin_unlock_irqrestore(&eng->lock, flags);
        return -ENOMEM;
    }

    n->flow    = flow;
    n->ack_seq = ack_seq;
    n->ack_win = ack_win ? ack_win : flow->default_win;
    n->last_ts = now_ms;
    n->age_ticks = 0;

    /* insert into per‑flow list tail */
    n->flow_prev = flow->ackq.tail;
    n->flow_next = NULL;

    if (flow->ackq.tail)
        flow->ackq.tail->flow_next = n;
    else
        flow->ackq.head = n;

    flow->ackq.tail = n;
    flow->ackq.depth++;
    flow->queued_acks++;

    /* first time this flow gets queued: insert into buckets */
    if (!flow->ackq.scheduled) {
        u8 idx = flow->ackq.bucket_idx & (TCPACCEL_ACK_BUCKETS - 1u);
        b = &eng->buckets[idx];

        n->sched_prev = b->tail;
        n->sched_next = NULL;

        if (b->tail)
            b->tail->sched_next = n;
        else
            b->head = n;

        b->tail = n;

        flow->ackq.scheduled = 1;
        eng->scheduled_flows++;
    } else {
        /* already scheduled: just link into same bucket */
        u8 idx = flow->ackq.bucket_idx & (TCPACCEL_ACK_BUCKETS - 1u);
        b = &eng->buckets[idx];

        n->sched_prev = b->tail;
        n->sched_next = NULL;

        if (b->tail)
            b->tail->sched_next = n;
        else
            b->head = n;

        b->tail = n;
    }

    /* Update last_acked_seq and a synthetic "delta" like appex did */
    delta = (s32)(ack_seq - flow->last_acked_seq);
    if (delta > 0) {
        int capped = delta;

        flow->last_acked_seq = ack_seq;

        if (capped > TCPACCEL_ACK_MAX_AGE_TICKS)
            capped = TCPACCEL_ACK_MAX_AGE_TICKS;

        /* In appex this "delta" would feed into delay heuristics;
         * here we store it in age_ticks of the newest node.
         */
        n->age_ticks = (u16)capped;
    }

    eng->stat_ack_created++;

    spin_unlock_irqrestore(&eng->lock, flags);
    return 0;
}

/*
 * Send one ACK‑only packet for the given node.
 * We simply delegate to user‑provided callback.
 */
static int
tcpaccel_send_ack_node(struct tcp_accel_engine *eng,
                       struct tcp_accel_ack_node *n)
{
    if (!eng->ops.build_and_send_ack)
        return -ENOSYS;

    return eng->ops.build_and_send_ack(n->flow, n->ack_seq, n->ack_win);
}

/*
 * Round‑robin scheduler: process the current bucket and move cursor.
 *
 * Should be called periodically from a timer or from your main scheduler.
 * We use the pending age (ms) to decide whether an ACK is "ripe" enough;
 * flows that explicitly need an immediate ACK can call tcpaccel_queue_ack()
 * with a small default_win and then call this right away.
 */
void tcpaccel_schedule_acks(struct tcp_accel_engine *eng)
{
    u8 bucket_idx;
    struct tcp_accel_bucket *b;
    struct tcp_accel_ack_node *n, *next;
    u32 now_ms;
    unsigned long flags;

    if (!eng)
        return;

    now_ms = tcpaccel_get_time_ms();

    spin_lock_irqsave(&eng->lock, flags);

    bucket_idx = eng->bucket_cursor & (TCPACCEL_ACK_BUCKETS - 1u);
    b = &eng->buckets[bucket_idx];

    n = b->head;
    while (n) {
        int delta;

        next = n->sched_next;

        delta = (s32)(now_ms - n->last_ts);
        if (delta > 0) {
            if (delta > TCPACCEL_ACK_MAX_AGE_TICKS)
                delta = TCPACCEL_ACK_MAX_AGE_TICKS;
            n->age_ticks = (u16)delta;
        } else {
            n->age_ticks = 0;
        }
        n->last_ts = now_ms;

        if (n->age_ticks >= TCPACCEL_ACK_DELAY_TICKS) {
            /* Release lock while sending:
             * build_and_send_ack() may sleep or re‑enter networking.
             */
            spin_unlock_irqrestore(&eng->lock, flags);
            (void)tcpaccel_send_ack_node(eng, n);
            spin_lock_irqsave(&eng->lock, flags);

            tcpaccel_unlink_ack_node(eng, n);
            tcpaccel_free_ack_node(n);
        }

        n = next;
    }

    eng->bucket_cursor = (u8)((bucket_idx + 1u) & (TCPACCEL_ACK_BUCKETS - 1u));

    spin_unlock_irqrestore(&eng->lock, flags);
}

/* =========================
 * Simple seq helpers
 * ========================= */

static inline bool tcpaccel_seq_leq(u32 a, u32 b)
{
    return (s32)(a - b) <= 0;
}

static inline bool tcpaccel_seq_lt(u32 a, u32 b)
{
    return (s32)(a - b) < 0;
}

/*
 * Example helper for processing an incoming RX skb and updating flow
 * state + queuing an ACK. This is intentionally generic: you can call
 * it from your Netfilter hook after you have identified the flow and
 * decided that you want to accelerate its ACKs.
 *
 * Returns:
 *   0  if everything is fine (caller should continue normal processing)
 *   <0 on parse errors
 */
int tcpaccel_rx_track_ack(struct tcp_accel_engine *eng,
                          struct tcp_accel_flow *flow,
                          struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u16 ihl_bytes;

    if (!eng || !flow || !skb)
        return -EINVAL;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return -EINVAL;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return 0; /* nothing to do */

    ihl_bytes = iph->ihl * 4u;
    if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct tcphdr)))
        return -EINVAL;

    th = (struct tcphdr *)((u8 *)iph + ihl_bytes);

    if (!th->ack)
        return 0;

    if (tcpaccel_seq_leq(ntohl(th->ack_seq), flow->last_acked_seq))
        return 0;

    /* For now we just use the advertised window as ack_win */
    (void)tcpaccel_queue_ack(eng, flow,
                             ntohl(th->ack_seq),
                             ntohs(th->window));
    return 0;
}

/*
 * This file intentionally does NOT declare module_init / module_exit;
 * you should include it into your own kernel module and call its
 * functions from your existing Netfilter hooks and flow management
 * code.
 */

EXPORT_SYMBOL(tcpaccel_fast_tx_fix_checksums);
EXPORT_SYMBOL(tcpaccel_engine_init);
EXPORT_SYMBOL(tcpaccel_engine_cleanup);
EXPORT_SYMBOL(tcpaccel_flow_init);
EXPORT_SYMBOL(tcpaccel_queue_ack);
EXPORT_SYMBOL(tcpaccel_schedule_acks);
EXPORT_SYMBOL(tcpaccel_rx_track_ack);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic TCP acceleration helpers (ACK scheduler + checksums)");
MODULE_AUTHOR("your-project");