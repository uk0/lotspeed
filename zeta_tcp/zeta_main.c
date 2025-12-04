/*
 * zeta_main.c - Zeta-TCP 主模块
 *
 * 基于 AppEx Networks ZetaTCP 白皮书重建
 * 实现混合拥塞检测 + 概率丢包检测
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include <net/checksum.h>

#include "zeta_tcp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZetaTCP Project");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Zeta-TCP - Hybrid Congestion Control with Probabilistic Loss Detection");

static char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Network interface");
module_param(param_dev, charp, 0);

static struct zeta_engine *g_engine = NULL;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;
static struct tasklet_struct tx_tasklet;
static struct proc_dir_entry *proc_dir = NULL;

#define PROC_DIR_NAME "zetatcp"

/* ============ 外部函数声明 ============ */
extern u32 zeta_calc_congestion_probability(struct zeta_flow_info *info,
                                             struct zeta_params *params);
extern void zeta_adjust_cwnd(struct zeta_flow_info *info,
                              struct zeta_params *params);
extern void zeta_update_loss_rate(struct zeta_flow_info *info, bool is_loss);
extern void zeta_process_ack(struct zeta_flow_info *info,
                              u32 ack_seq,
                              struct zeta_sack_info *sack,
                              struct zeta_params *params,
                              struct zeta_stats *stats);
extern int zeta_parse_sack(struct tcphdr *th, u32 tcp_hdr_len,
                            struct zeta_sack_info *sack);
extern void zeta_update_rtt(struct zeta_rtt_info *rtt, u32 sample_rtt);
extern u32 zeta_measure_rtt_incoming(struct sk_buff *skb,
                                      struct zeta_flow_info *info);
extern void zeta_stamp_outgoing(struct sk_buff *skb,
                                 struct zeta_flow_info *info);
extern void zeta_modify_ack_window(struct sk_buff *skb,
                                    struct zeta_flow_info *info,
                                    struct zeta_params *params);
extern void zeta_update_reverse_stats(struct zeta_flow_info *info,
                                       u32 seq, u32 len);
extern u16 zeta_inflate_window(struct zeta_flow_info *info,
                                u16 orig_win,
                                struct zeta_params *params);

/* ============ 流表操作 ============ */

static inline u32 zeta_flow_hash(__be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport)
{
    u32 a = (__force u32)saddr ^ (__force u32)daddr;
    u32 b = ((__force u32)sport << 16) | (__force u32)dport;
    return jhash_2words(a, b, 0) & (ZETA_FLOW_TABLE_SIZE - 1);
}

static void zeta_flow_table_init(struct zeta_flow_table *ft)
{
    int i;
    for (i = 0; i < ZETA_FLOW_TABLE_SIZE; i++)
        INIT_LIST_HEAD(&ft->buckets[i]);
    ft->count = 0;
    spin_lock_init(&ft->lock);
}

static void zeta_flow_table_cleanup(struct zeta_flow_table *ft)
{
    struct zeta_flow *flow, *tmp;
    unsigned long flags;
    int i;

    spin_lock_irqsave(&ft->lock, flags);
    for (i = 0; i < ZETA_FLOW_TABLE_SIZE; i++) {
        list_for_each_entry_safe(flow, tmp, &ft->buckets[i], list) {
            list_del(&flow->list);
            kfree(flow);
        }
        INIT_LIST_HEAD(&ft->buckets[i]);
    }
    ft->count = 0;
    spin_unlock_irqrestore(&ft->lock, flags);
}

static struct zeta_flow *zeta_flow_lookup(struct zeta_flow_table *ft,
                                           __be32 saddr, __be32 daddr,
                                           __be16 sport, __be16 dport)
{
    struct zeta_flow *flow;
    u32 hash = zeta_flow_hash(saddr, daddr, sport, dport);

    list_for_each_entry(flow, &ft->buckets[hash], list) {
        if (flow->local_ip == saddr && flow->remote_ip == daddr &&
            flow->local_port == sport && flow->remote_port == dport)
            return flow;
    }
    return NULL;
}

/* 双向查找 */
static struct zeta_flow *zeta_flow_lookup_bidir(struct zeta_flow_table *ft,
                                                 __be32 saddr, __be32 daddr,
                                                 __be16 sport, __be16 dport,
                                                 int *is_reverse)
{
    struct zeta_flow *flow;

    *is_reverse = 0;

    /* 正向查找 */
    flow = zeta_flow_lookup(ft, saddr, daddr, sport, dport);
    if (flow)
        return flow;

    /* 反向查找 */
    flow = zeta_flow_lookup(ft, daddr, saddr, dport, sport);
    if (flow) {
        *is_reverse = 1;
        return flow;
    }

    return NULL;
}

static struct zeta_flow *zeta_flow_create(struct zeta_flow_table *ft,
                                           __be32 saddr, __be32 daddr,
                                           __be16 sport, __be16 dport,
                                           u8 direction,
                                           struct zeta_params *params)
{
    struct zeta_flow *flow;
    u32 hash;
    unsigned long flags;

    spin_lock_irqsave(&ft->lock, flags);

    /* 检查是否已存在 */
    flow = zeta_flow_lookup(ft, saddr, daddr, sport, dport);
    if (flow) {
        spin_unlock_irqrestore(&ft->lock, flags);
        return flow;
    }

    /* 检查数量限制 */
    if (ft->count >= ZETA_FLOW_MAX_COUNT) {
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
    spin_lock_init(&flow->lock);

    /* 初始化流信息 */
    flow->info.direction = direction;
    flow->info.state = ZETA_STATE_OPEN;
    flow->info.mss = params->mss;
    flow->info.last_update = zeta_get_time_us();

    /* 初始化 RTT */
    flow->info.rtt.srtt = params->min_rtt_us;
    flow->info.rtt.min_rtt = params->min_rtt_us;

    /* 初始化窗口控制 */
    flow->info.win.cwnd = 10 * params->mss;  /* IW10 */
    flow->info.win.ssthresh = 0xFFFFFFFF;

    /* 初始化拥塞检测 */
    flow->info.cong.state = ZETA_STATE_OPEN;
    flow->info.cong.quality = ZETA_NET_GOOD;

    hash = zeta_flow_hash(saddr, daddr, sport, dport);
    list_add(&flow->list, &ft->buckets[hash]);
    ft->count++;

    spin_unlock_irqrestore(&ft->lock, flags);

    return flow;
}

static void zeta_flow_delete(struct zeta_flow_table *ft,
                              __be32 saddr, __be32 daddr,
                              __be16 sport, __be16 dport)
{
    struct zeta_flow *flow;
    u32 hash = zeta_flow_hash(saddr, daddr, sport, dport);
    unsigned long flags;

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

/* 清理超时流 */
static int zeta_flow_cleanup_timeout(struct zeta_flow_table *ft, u32 timeout_us)
{
    struct zeta_flow *flow, *tmp;
    unsigned long flags;
    u32 now = zeta_get_time_us();
    int cleaned = 0;
    int i;

    spin_lock_irqsave(&ft->lock, flags);

    for (i = 0; i < ZETA_FLOW_TABLE_SIZE; i++) {
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

/* ============ 包队列操作 ============ */

static struct zeta_pkt_queue *zeta_queue_alloc(u32 capacity)
{
    struct zeta_pkt_queue *q;

    q = kzalloc(sizeof(*q), GFP_KERNEL);
    if (! q)
        return NULL;

    q->ring = vzalloc(capacity * sizeof(struct zeta_pkt_node));
    if (! q->ring) {
        kfree(q);
        return NULL;
    }

    q->capacity = capacity;
    spin_lock_init(&q->lock);

    return q;
}

static void zeta_queue_free(struct zeta_pkt_queue *q)
{
    if (! q)
        return;
    if (q->ring)
        vfree(q->ring);
    kfree(q);
}

static int zeta_queue_enqueue(struct zeta_pkt_queue *q, struct sk_buff *skb,
                               zeta_okfn_t okfn, u32 seq, u32 len, u32 time)
{
    unsigned long flags;

    if (! q || !q->ring || ! skb)
        return 0;

    spin_lock_irqsave(&q->lock, flags);

    if (q->size >= q->capacity) {
        spin_unlock_irqrestore(&q->lock, flags);
        return 0;
    }

    q->ring[q->tail].skb = skb;
    q->ring[q->tail].okfn = okfn;
    q->ring[q->tail].seq = seq;
    q->ring[q->tail].len = len;
    q->ring[q->tail].enqueue_time = time;
    q->ring[q->tail].send_time = time;
    q->ring[q->tail].retrans = 0;

    q->tail = (q->tail + 1) % q->capacity;
    q->size++;

    spin_unlock_irqrestore(&q->lock, flags);

    return 1;
}

static int zeta_queue_dequeue(struct zeta_pkt_queue *q)
{
    struct zeta_pkt_node *pkt;
    struct sk_buff *skb;
    zeta_okfn_t okfn;
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

    /* 发送包 */
    if (okfn && skb) {
#if defined(ZETA_OKFN_NEW_API)
        okfn(&init_net, NULL, skb);
#else
        okfn(skb);
#endif
    }

    return 1;
}

static struct zeta_pkt_node *zeta_queue_peek(struct zeta_pkt_queue *q)
{
    if (!q || !q->ring || q->size == 0)
        return NULL;
    return &q->ring[q->head];
}

static u32 zeta_queue_size(struct zeta_pkt_queue *q)
{
    if (!q)
        return 0;
    return q->size;
}

/* ============ 令牌桶操作 ============ */

static bool zeta_token_get(struct zeta_engine *eng, u32 amount)
{
    unsigned long flags;
    bool result = false;

    spin_lock_irqsave(&eng->token_lock, flags);

    if (eng->bucket_size >= eng->tokens + amount) {
        eng->tokens += amount;
        result = true;
    }

    spin_unlock_irqrestore(&eng->token_lock, flags);
    return result;
}

static void zeta_token_release(struct zeta_engine *eng, u32 amount)
{
    unsigned long flags;

    spin_lock_irqsave(&eng->token_lock, flags);

    if (eng->tokens >= amount)
        eng->tokens -= amount;
    else
        eng->tokens = 0;

    spin_unlock_irqrestore(&eng->token_lock, flags);
}

/* ============ 参数默认值 ============ */

static void zeta_params_default(struct zeta_params *p)
{
    p->debug = 0;
    strncpy(p->nic, "eth0", sizeof(p->nic) - 1);
    p->nic[sizeof(p->nic) - 1] = '\0';
    p->mss = 1460;

    /* RTT */
    p->min_rtt_us = 1000;       /* 1ms */
    p->max_rtt_us = 1000000;    /* 1s */

    /* 拥塞控制 */
    p->cong_alpha = 500;        /* RTT 权重 50% */
    p->cong_beta = 500;         /* 丢包权重 50% */
    p->cwnd_gain = 1000;        /* 1x */
    p->pacing_gain = 1000;      /* 1x */

    /* 丢包检测 */
    p->loss_prob_thresh = 500;  /* 50% */
    p->dup_ack_thresh = 3;

    /* 反向控制 */
    p->win_inflate_factor = 8;
    p->ack_ratio = 2;

    /* 缓冲区 */
    p->buffer_size = 32 * 1024 * 1024;  /* 32MB */
    p->max_delay_us = 200000;           /* 200ms */

    /* 定时器 */
    p->timer_interval_us = 1000;        /* 1ms */

    /* 功能开关 */
    p->enable_sack = 1;
    p->enable_ecn = 1;
    p->enable_pacing = 0;
    p->enable_reverse = 1;
}

/* ============ Tasklet - 出队发送 ============ */

static void zeta_tx_tasklet(unsigned long data)
{
    struct zeta_engine *eng = (struct zeta_engine *)data;
    struct zeta_pkt_node *pkt;
    u32 now;
    int sent = 0;

    if (!eng || !eng->running)
        return;

    now = zeta_get_time_us();

    while (sent < 64) {
        if (zeta_queue_size(eng->tx_queue) == 0)
            break;

        pkt = zeta_queue_peek(eng->tx_queue);
        if (!pkt)
            break;

        /* 检查令牌 */
        if (zeta_token_get(eng, pkt->len + 54)) {
            zeta_queue_dequeue(eng->tx_queue);
            sent++;
        }
        /* 超时强制发送 */
        else if (now - pkt->enqueue_time >= eng->params.max_delay_us) {
            zeta_queue_dequeue(eng->tx_queue);
            sent++;
        }
        else {
            break;
        }
    }

    /* 如果还有包待发送，重新调度 */
    if (zeta_queue_size(eng->tx_queue) > 0)
        tasklet_schedule(&tx_tasklet);
}

/* ============ 解析 TCP 选项 ============ */

static void zeta_parse_tcp_options(struct tcphdr *th, u32 tcp_hdr_len,
                                    struct zeta_flow_info *info)
{
    u8 *opt, *end;
    u8 kind, len;

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

        switch (kind) {
        case 3:  /* Window Scale */
            if (len == 3) {
                info->win.rcv_wscale = *(opt + 2);
                if (info->win.rcv_wscale > 14)
                    info->win.rcv_wscale = 14;
                info->flags |= ZETA_FLAG_WSCALE_OK;
            }
            break;
        case 4:  /* SACK Permitted */
            if (len == 2) {
                info->flags |= ZETA_FLAG_SACK_OK;
            }
            break;
        case 8:  /* Timestamp */
            if (len == 10) {
                info->flags |= ZETA_FLAG_TS_OK;
            }
            break;
        }

        opt += len;
    }
}

/* ============ 入站 Hook ============ */

#if defined(ZETA_NF_NEW_HOOK_API)
static unsigned int zeta_hook_in(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    const struct net_device *in = state->in;
#else
static unsigned int zeta_hook_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
#endif
    struct zeta_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct zeta_flow *flow;
    struct zeta_flow_info *info;
    struct zeta_sack_info sack = {0};
    u32 payload_len;
    u32 tcp_hdr_len;
    u32 rtt;
    u32 now;
    unsigned long flags;
    int is_reverse = 0;

    if (!eng || !eng->running)
        return NF_ACCEPT;

    if (! in)
        return NF_ACCEPT;

    if (strcmp(in->name, eng->params.nic) != 0)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcp_hdr_len;
    now = zeta_get_time_us();

    eng->stats.pkts_rx++;
    eng->stats.bytes_rx += skb->len;

    /* 查找流（双向） */
    spin_lock_irqsave(&eng->ft.lock, flags);
    flow = zeta_flow_lookup_bidir(&eng->ft, iph->daddr, iph->saddr,
                                   th->dest, th->source, &is_reverse);
    spin_unlock_irqrestore(&eng->ft.lock, flags);

    /* 入站 SYN（到服务器）：创建流 */
    if (th->syn && !th->ack && !flow) {
        flow = zeta_flow_create(&eng->ft, iph->daddr, iph->saddr,
                                 th->dest, th->source,
                                 FLOW_DIR_INBOUND, &eng->params);
        if (flow) {
            zeta_parse_tcp_options(th, tcp_hdr_len, &flow->info);
            flow->info.loss.snd_una = ntohl(th->seq) + 1;
            eng->stats.flows_created++;
            ZETA_LOG(eng, "Flow created (inbound SYN): %pI4:%u\n",
                    &iph->saddr, ntohs(th->source));
        }
        return NF_ACCEPT;
    }

    if (! flow)
        return NF_ACCEPT;

    info = &flow->info;

    /* 客户端发起的流（OUTBOUND）在入站时是反向的 */
    if (info->direction == FLOW_DIR_OUTBOUND) {
        /* 这是服务器的响应，直接放行 */
        return NF_ACCEPT;
    }

    /* 以下处理 INBOUND 流（本机是服务器） */

    /* FIN/RST */
    if (th->fin || th->rst) {
        zeta_flow_delete(&eng->ft, flow->local_ip, flow->remote_ip,
                          flow->local_port, flow->remote_port);
        eng->stats.flows_destroyed++;
        return NF_ACCEPT;
    }

    /* 解析 SACK */
    if (eng->params.enable_sack && (info->flags & ZETA_FLAG_SACK_OK)) {
        zeta_parse_sack(th, tcp_hdr_len, &sack);
    }

    /* RTT 测量 */
    rtt = zeta_measure_rtt_incoming(skb, info);
    if (rtt > 0 && rtt < ZETA_RTT_MAX_US) {
        eng->stats.rtt_samples++;

        spin_lock_irqsave(&eng->global_lock, flags);
        if (eng->global_min_rtt == 0 || rtt < eng->global_min_rtt)
            eng->global_min_rtt = rtt;
        eng->global_rtt = (eng->global_rtt * 7 + rtt) / 8;
        spin_unlock_irqrestore(&eng->global_lock, flags);
    }

    /* ACK 处理 */
    if (th->ack) {
        u32 ack_seq = ntohl(th->ack_seq);

        /* 令牌释放 */
        if (zeta_seq_gt(ack_seq, info->loss.snd_una)) {
            u32 acked = zeta_seq_diff(ack_seq, info->loss.snd_una);
            zeta_token_release(eng, acked + acked * 54 / eng->params.mss);
        }

        /* 处理 ACK（更新丢包检测、拥塞概率等） */
        zeta_process_ack(info, ack_seq, &sack, &eng->params, &eng->stats);
    }

    /* 上传数据处理 */
    if (payload_len > 0) {
        u32 seq = ntohl(th->seq);
        zeta_update_reverse_stats(info, seq, payload_len);
    }

    info->last_update = now;

    /* 触发出队 */
    if (zeta_queue_size(eng->tx_queue) > 0)
        tasklet_schedule(&tx_tasklet);

    return NF_ACCEPT;
}

/* ============ 出站 Hook ============ */

#if defined(ZETA_NF_NEW_HOOK_API)
static unsigned int zeta_hook_out(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    const struct net_device *out = state->out;
    zeta_okfn_t okfn = state->okfn;
#else
static unsigned int zeta_hook_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
#endif
    struct zeta_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct zeta_flow *flow = NULL;
    struct zeta_flow_info *info = NULL;
    u32 payload_len;
    u32 tcp_hdr_len;
    u32 seq;
    u32 now;
    unsigned long flags;
    int is_reverse = 0;
    int result;

    if (!eng || !eng->running)
        return NF_ACCEPT;

    if (!out)
        return NF_ACCEPT;

    if (strcmp(out->name, eng->params.nic) != 0)
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
    tcp_hdr_len = th->doff * 4;
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcp_hdr_len;
    seq = ntohl(th->seq);
    now = zeta_get_time_us();

    eng->stats.pkts_tx++;
    eng->stats.bytes_tx += skb->len;

    /* ============ SYN 处理 ============ */
    if (th->syn) {
        if (! th->ack) {
            /* 纯 SYN：客户端发起连接 */
            flow = zeta_flow_create(&eng->ft, iph->saddr, iph->daddr,
                                     th->source, th->dest,
                                     FLOW_DIR_OUTBOUND, &eng->params);
            if (flow) {
                zeta_parse_tcp_options(th, tcp_hdr_len, &flow->info);
                flow->info.snd_nxt = seq + 1;
                eng->stats.flows_created++;
                ZETA_LOG(eng, "Flow created (outbound SYN): %pI4:%u -> %pI4:%u\n",
                        &iph->saddr, ntohs(th->source),
                        &iph->daddr, ntohs(th->dest));
            }
            /* 客户端连接：不控制，直接放行 */
            return NF_ACCEPT;
        } else {
            /* SYN-ACK：服务器响应 */
            spin_lock_irqsave(&eng->ft.lock, flags);
            flow = zeta_flow_lookup_bidir(&eng->ft, iph->saddr, iph->daddr,
                                           th->source, th->dest, &is_reverse);
            spin_unlock_irqrestore(&eng->ft.lock, flags);

            if (flow) {
                info = &flow->info;
                info->snd_nxt = seq + 1;
                info->loss.high_seq = seq + 1;
                zeta_parse_tcp_options(th, tcp_hdr_len, info);
            }
            /* SYN-ACK 不入队，修改时间戳后放行 */
            if (info)
                zeta_stamp_outgoing(skb, info);
            return NF_ACCEPT;
        }
    }

    /* ============ 查找流 ============ */
    spin_lock_irqsave(&eng->ft.lock, flags);
    flow = zeta_flow_lookup_bidir(&eng->ft, iph->saddr, iph->daddr,
                                   th->source, th->dest, &is_reverse);
    spin_unlock_irqrestore(&eng->ft.lock, flags);

    if (!flow)
        return NF_ACCEPT;

    info = &flow->info;

    /* 客户端发起的连接：不控制 */
    if (info->direction == FLOW_DIR_OUTBOUND) {
        return NF_ACCEPT;
    }

    /* ============ FIN/RST ============ */
    if (th->fin || th->rst) {
        zeta_flow_delete(&eng->ft, flow->local_ip, flow->remote_ip,
                          flow->local_port, flow->remote_port);
        eng->stats.flows_destroyed++;
        zeta_stamp_outgoing(skb, info);
        return NF_ACCEPT;
    }

    /* ============ 服务器连接：Zeta-TCP 控制 ============ */

    /* 更新序号跟踪 */
    if (payload_len > 0) {
        u32 seq_end = seq + payload_len;
        if (zeta_seq_gt(seq_end, info->loss.high_seq))
            info->loss.high_seq = seq_end;
        if (zeta_seq_gt(seq_end, info->snd_nxt))
            info->snd_nxt = seq_end;
        info->bytes_sent += payload_len;
        info->pkts_sent++;
    }

    /* 纯 ACK 处理：窗口放大 */
    if (th->ack && payload_len == 0 && eng->params.enable_reverse) {
        zeta_modify_ack_window(skb, info, &eng->params);
        eng->stats.win_inflated++;
    }

    /* 修改时间戳 */
    zeta_stamp_outgoing(skb, info);

    /* 计算拥塞概率 */
    u32 cong_prob = zeta_calc_congestion_probability(info, &eng->params);

    /*
     * Zeta-TCP 核心决策：
     * - 拥塞概率低：直接发送
     * - 拥塞概率高：入队等待
     */
    if (cong_prob < ZETA_CONG_PROB_MED) {
        /* 网络状况良好，直接发送 */
        if (zeta_token_get(eng, payload_len + 54)) {
            return NF_ACCEPT;
        }
    }

    /* 令牌检查 */
    if (zeta_token_get(eng, payload_len + 54)) {
        if (zeta_queue_size(eng->tx_queue) == 0) {
            return NF_ACCEPT;
        }
        zeta_token_release(eng, payload_len + 54);
    }

    /* 入队 */
    result = zeta_queue_enqueue(eng->tx_queue, skb, okfn, seq, payload_len, now);
    if (result == 1) {
        eng->stats.pkts_queued++;
        tasklet_schedule(&tx_tasklet);
        return NF_STOLEN;
    }

    eng->stats.pkts_dropped++;
    return NF_DROP;
}

/* ============ 定时器回调 ============ */

static enum hrtimer_restart zeta_timer_callback(struct hrtimer *timer)
{
    struct zeta_engine *eng = container_of(timer, struct zeta_engine, timer);
    ktime_t interval;
    static u32 cleanup_counter = 0;

    if (! eng || !eng->running)
        return HRTIMER_NORESTART;

    /* 触发出队 */
    if (zeta_queue_size(eng->tx_queue) > 0)
        tasklet_schedule(&tx_tasklet);

    /* 定期清理超时流 */
    cleanup_counter++;
    if (cleanup_counter >= 10000) {  /* 每 10 秒 */
        int cleaned = zeta_flow_cleanup_timeout(&eng->ft, ZETA_FLOW_TIMEOUT_US);
        if (cleaned > 0)
            eng->stats.flows_destroyed += cleaned;
        cleanup_counter = 0;
    }

    interval = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_forward_now(timer, interval);

    return HRTIMER_RESTART;
}

/* ============ Proc 文件系统 ============ */

static int zeta_stats_show(struct seq_file *m, void *v)
{
    struct zeta_engine *eng = g_engine;

    if (!eng)
        return 0;

    seq_printf(m, "=== Zeta-TCP Statistics ===\n\n");

    seq_printf(m, "--- Flows ---\n");
    seq_printf(m, "Active: %u\n", eng->ft.count);
    seq_printf(m, "Created: %llu\n", eng->stats.flows_created);
    seq_printf(m, "Destroyed: %llu\n", eng->stats.flows_destroyed);

    seq_printf(m, "\n--- Packets ---\n");
    seq_printf(m, "RX: %llu\n", eng->stats.pkts_rx);
    seq_printf(m, "TX: %llu\n", eng->stats.pkts_tx);
    seq_printf(m, "Queued: %llu\n", eng->stats.pkts_queued);
    seq_printf(m, "Dropped: %llu\n", eng->stats.pkts_dropped);
    seq_printf(m, "Retrans: %llu\n", eng->stats.pkts_retrans);

    seq_printf(m, "\n--- Bytes ---\n");
    seq_printf(m, "RX: %llu\n", eng->stats.bytes_rx);
    seq_printf(m, "TX: %llu\n", eng->stats.bytes_tx);

    seq_printf(m, "\n--- Congestion ---\n");
    seq_printf(m, "Cong events: %llu\n", eng->stats.cong_events);
    seq_printf(m, "Loss events: %llu\n", eng->stats.loss_events);
    seq_printf(m, "Recovery events: %llu\n", eng->stats.recovery_events);

    seq_printf(m, "\n--- Reverse Control ---\n");
    seq_printf(m, "Window inflated: %llu\n", eng->stats.win_inflated);
    seq_printf(m, "ACKs generated: %llu\n", eng->stats.acks_generated);
    seq_printf(m, "SACKs generated: %llu\n", eng->stats.sacks_generated);

    seq_printf(m, "\n--- RTT ---\n");
    seq_printf(m, "Samples: %llu\n", eng->stats.rtt_samples);
    seq_printf(m, "Global RTT: %u us\n", eng->global_rtt);
    seq_printf(m, "Global Min RTT: %u us\n", eng->global_min_rtt);

    seq_printf(m, "\n--- Queue ---\n");
    seq_printf(m, "TX Queue size: %u\n", zeta_queue_size(eng->tx_queue));
    seq_printf(m, "Tokens: %llu / %llu\n", eng->tokens, eng->bucket_size);

    seq_printf(m, "\n--- Parameters ---\n");
    seq_printf(m, "NIC: %s\n", eng->params.nic);
    seq_printf(m, "MSS: %u\n", eng->params.mss);
    seq_printf(m, "Min RTT: %u us\n", eng->params.min_rtt_us);
    seq_printf(m, "Cong Alpha (RTT weight): %u\n", eng->params.cong_alpha);
    seq_printf(m, "Cong Beta (Loss weight): %u\n", eng->params.cong_beta);
    seq_printf(m, "Loss Prob Thresh: %u\n", eng->params.loss_prob_thresh);
    seq_printf(m, "Win Inflate Factor: %u\n", eng->params.win_inflate_factor);
    seq_printf(m, "Buffer Size: %u MB\n", eng->params.buffer_size / (1024 * 1024));

    return 0;
}

static int zeta_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_stats_show, NULL);
}

#if defined(ZETA_USE_PROC_OPS)
static const struct proc_ops zeta_stats_fops = {
    .proc_open = zeta_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zeta_stats_fops = {
    .open = zeta_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

/* 参数读写 */
struct zeta_param_entry {
    const char *name;
    u32 *ptr;
};

static struct zeta_param_entry zeta_param_entries[] = {
    {"debug", NULL},
    {"mss", NULL},
    {"min_rtt_us", NULL},
    {"max_rtt_us", NULL},
    {"cong_alpha", NULL},
    {"cong_beta", NULL},
    {"loss_prob_thresh", NULL},
    {"dup_ack_thresh", NULL},
    {"win_inflate_factor", NULL},
    {"buffer_size", NULL},
    {"max_delay_us", NULL},
    {"enable_sack", NULL},
    {"enable_ecn", NULL},
    {"enable_pacing", NULL},
    {"enable_reverse", NULL},
    {NULL, NULL}
};

static void zeta_init_param_ptrs(struct zeta_engine *eng)
{
    zeta_param_entries[0].ptr = &eng->params.debug;
    zeta_param_entries[1].ptr = &eng->params.mss;
    zeta_param_entries[2].ptr = &eng->params.min_rtt_us;
    zeta_param_entries[3].ptr = &eng->params.max_rtt_us;
    zeta_param_entries[4].ptr = &eng->params.cong_alpha;
    zeta_param_entries[5].ptr = &eng->params.cong_beta;
    zeta_param_entries[6].ptr = &eng->params.loss_prob_thresh;
    zeta_param_entries[7].ptr = &eng->params.dup_ack_thresh;
    zeta_param_entries[8].ptr = &eng->params.win_inflate_factor;
    zeta_param_entries[9].ptr = &eng->params.buffer_size;
    zeta_param_entries[10].ptr = &eng->params.max_delay_us;
    zeta_param_entries[11].ptr = &eng->params.enable_sack;
    zeta_param_entries[12].ptr = &eng->params.enable_ecn;
    zeta_param_entries[13].ptr = &eng->params.enable_pacing;
    zeta_param_entries[14].ptr = &eng->params.enable_reverse;
}

static int zeta_param_show(struct seq_file *m, void *v)
{
    struct zeta_param_entry *entry = m->private;
    if (entry && entry->ptr)
        seq_printf(m, "%u\n", *entry->ptr);
    return 0;
}

static int zeta_param_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_param_show, ZETA_PDE_DATA(inode));
}

static ssize_t zeta_param_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *pos)
{
    struct seq_file *m = file->private_data;
    struct zeta_param_entry *entry = m->private;
    char kbuf[32];
    unsigned long val;
    int ret;

    if (! entry || !entry->ptr)
        return -EINVAL;

    if (count > sizeof(kbuf) - 1)
        count = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    ret = kstrtoul(kbuf, 10, &val);
    if (ret < 0)
        return ret;

    *entry->ptr = (u32)val;

    /* 特殊处理：buffer_size 变化时更新 bucket_size */
    if (g_engine && entry->ptr == &g_engine->params.buffer_size) {
        g_engine->bucket_size = val;
    }

    return count;
}

#if defined(ZETA_USE_PROC_OPS)
static const struct proc_ops zeta_param_fops = {
    .proc_open = zeta_param_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = zeta_param_write,
};
#else
static const struct file_operations zeta_param_fops = {
    .open = zeta_param_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = zeta_param_write,
};
#endif

static int zeta_proc_init(struct zeta_engine *eng)
{
    struct zeta_param_entry *entry;

    zeta_init_param_ptrs(eng);

    proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (! proc_dir) {
        ZETA_ERR("Failed to create /proc/%s\n", PROC_DIR_NAME);
        return -ENOMEM;
    }

    if (! proc_create("stats", 0444, proc_dir, &zeta_stats_fops)) {
        ZETA_ERR("Failed to create /proc/%s/stats\n", PROC_DIR_NAME);
    }

    for (entry = zeta_param_entries; entry->name; entry++) {
        if (! proc_create_data(entry->name, 0644, proc_dir, &zeta_param_fops, entry)) {
            ZETA_ERR("Failed to create /proc/%s/%s\n", PROC_DIR_NAME, entry->name);
        }
    }

    ZETA_INFO("Created /proc/%s\n", PROC_DIR_NAME);
    return 0;
}

static void zeta_proc_cleanup(void)
{
    struct zeta_param_entry *entry;

    if (! proc_dir)
        return;

    remove_proc_entry("stats", proc_dir);

    for (entry = zeta_param_entries; entry->name; entry++) {
        remove_proc_entry(entry->name, proc_dir);
    }

    remove_proc_entry(PROC_DIR_NAME, NULL);
    proc_dir = NULL;

    ZETA_INFO("Removed /proc/%s\n", PROC_DIR_NAME);
}

/* ============ 引擎初始化/清理 ============ */

static int zeta_engine_init(struct zeta_engine *eng)
{
    int i;
    ktime_t ktime;

    zeta_params_default(&eng->params);

    if (param_dev && strlen(param_dev) > 0) {
        strncpy(eng->params.nic, param_dev, sizeof(eng->params.nic) - 1);
        eng->params.nic[sizeof(eng->params.nic) - 1] = '\0';
    }

    /* 去除换行符 */
    for (i = 0; i < sizeof(eng->params.nic) && eng->params.nic[i]; i++) {
        if (eng->params.nic[i] == '\n') {
            eng->params.nic[i] = '\0';
            break;
        }
    }

    /* 初始化流表 */
    zeta_flow_table_init(&eng->ft);

    /* 初始化令牌桶 */
    eng->tokens = 0;
    eng->bucket_size = eng->params.buffer_size;
    spin_lock_init(&eng->token_lock);

    /* 初始化全局 RTT */
    eng->global_rtt = eng->params.min_rtt_us;
    eng->global_min_rtt = 0;
    eng->global_bw = 0;
    spin_lock_init(&eng->global_lock);

    /* 初始化包队列 */
    eng->tx_queue = zeta_queue_alloc(ZETA_PKT_QUEUE_SIZE);
    if (!eng->tx_queue) {
        ZETA_ERR("Failed to allocate TX queue\n");
        return -ENOMEM;
    }

    /* 初始化统计 */
    memset(&eng->stats, 0, sizeof(eng->stats));

    /* 初始化 tasklet */
    tasklet_init(&tx_tasklet, zeta_tx_tasklet, (unsigned long)eng);

    /* 初始化定时器 */
    ktime = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_init(&eng->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    eng->timer.function = zeta_timer_callback;

    eng->running = true;
    hrtimer_start(&eng->timer, ktime, HRTIMER_MODE_REL);

    return 0;
}

static void zeta_engine_cleanup(struct zeta_engine *eng)
{
    if (!eng)
        return;

    eng->running = false;
    hrtimer_cancel(&eng->timer);
    tasklet_kill(&tx_tasklet);

    zeta_flow_table_cleanup(&eng->ft);

    if (eng->tx_queue) {
        zeta_queue_free(eng->tx_queue);
        eng->tx_queue = NULL;
    }
}

/* ============ 模块入口 ============ */

static int __init zeta_init(void)
{
    int ret;

    ZETA_INFO("Loading Zeta-TCP module v1.0\n");

    g_engine = kzalloc(sizeof(struct zeta_engine), GFP_KERNEL);
    if (!g_engine) {
        ZETA_ERR("Failed to allocate engine\n");
        return -ENOMEM;
    }

    ret = zeta_engine_init(g_engine);
    if (ret) {
        kfree(g_engine);
        return ret;
    }

    zeta_proc_init(g_engine);

    /* 注册 Netfilter hooks */
    nfho_in.hook = zeta_hook_in;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;

    nfho_out.hook = zeta_hook_out;
    nfho_out.hooknum = NF_INET_POST_ROUTING;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

#if defined(ZETA_NF_NEW_HOOK_API)
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

    ZETA_INFO("Module loaded, interface: %s\n", g_engine->params.nic);
    ZETA_INFO("Hybrid congestion detection: alpha=%u, beta=%u\n",
             g_engine->params.cong_alpha, g_engine->params.cong_beta);
    ZETA_INFO("Loss probability threshold: %u/1000\n",
             g_engine->params.loss_prob_thresh);

    return 0;

err_hook_out:
#if defined(ZETA_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_in);
#endif
err_hook_in:
    zeta_proc_cleanup();
    zeta_engine_cleanup(g_engine);
    kfree(g_engine);
    g_engine = NULL;
    return ret;
}

static void __exit zeta_exit(void)
{
    ZETA_INFO("Unloading Zeta-TCP module\n");

#if defined(ZETA_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_out);
    nf_unregister_hook(&nfho_in);
#endif

    zeta_proc_cleanup();

    if (g_engine) {
        zeta_engine_cleanup(g_engine);
        kfree(g_engine);
        g_engine = NULL;
    }

    ZETA_INFO("Module unloaded\n");
}

module_init(zeta_init);
module_exit(zeta_exit);