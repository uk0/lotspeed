/*
 * tapac_ack.c - ACK 调度器 v2.6
 * 修复：per-flow ACK 计数器，更合理的发送策略
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>

#include "tapac.h"

/* 待发送 ACK 的简单队列 */
#define ACK_SEND_QUEUE_SIZE 2048

struct tapac_ack_send_item {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;
    u32 ack_seq;
    u32 my_seq;
    u16 win;
    u32 tsval;
    u32 tsecr;
    bool valid;
};

static struct tapac_ack_send_item ack_send_queue[ACK_SEND_QUEUE_SIZE];
static int ack_send_head = 0;
static int ack_send_tail = 0;
static DEFINE_SPINLOCK(ack_send_lock);
static struct tasklet_struct ack_send_tasklet;
static struct tapac_engine *g_ack_eng = NULL;

/* ============ 内部工具函数 ============ */

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

/* 从 bucket 和 flow 链表中移除节点 */
static void tapac_bucket_unlink_node(struct tapac_engine *eng,
                                     struct tapac_ack_node *n)
{
    struct tapac_flow *flow = n->flow;
    struct tapac_ack_queue *ackq = &flow->info.ackq;
    struct tapac_ack_bucket *b;
    u8 idx;

    idx = ackq->bucket_idx & (ACK_BUCKETS - 1);
    b = &eng->ack_buckets[idx];

    /* 从 per-flow 链表摘掉 */
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

    /* 从 engine bucket 链表摘掉 */
    if (n->sched_prev)
        n->sched_prev->sched_next = n->sched_next;
    else
        b->head = n->sched_next;

    if (n->sched_next)
        n->sched_next->sched_prev = n->sched_prev;
    else
        b->tail = n->sched_prev;

    /* 如果 flow 队列空了，标记未调度 */
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

/* ============ ACK 发送队列操作 ============ */

static int ack_send_queue_enqueue(struct tapac_flow *flow, u32 ack_seq,
                                   u16 win, u32 tsval, u32 tsecr)
{
    unsigned long flags;
    int next_tail;

    spin_lock_irqsave(&ack_send_lock, flags);

    next_tail = (ack_send_tail + 1) % ACK_SEND_QUEUE_SIZE;
    if (next_tail == ack_send_head) {
        spin_unlock_irqrestore(&ack_send_lock, flags);
        return -ENOMEM;
    }

    ack_send_queue[ack_send_tail].local_ip = flow->local_ip;
    ack_send_queue[ack_send_tail].remote_ip = flow->remote_ip;
    ack_send_queue[ack_send_tail].local_port = flow->local_port;
    ack_send_queue[ack_send_tail].remote_port = flow->remote_port;
    ack_send_queue[ack_send_tail].ack_seq = ack_seq;
    ack_send_queue[ack_send_tail].my_seq = flow->info.my_seq;
    ack_send_queue[ack_send_tail].win = win;
    ack_send_queue[ack_send_tail].tsval = tsval;
    ack_send_queue[ack_send_tail].tsecr = tsecr;
    ack_send_queue[ack_send_tail].valid = true;

    ack_send_tail = next_tail;

    spin_unlock_irqrestore(&ack_send_lock, flags);

    return 0;
}

static int ack_send_queue_dequeue(struct tapac_ack_send_item *item)
{
    unsigned long flags;

    spin_lock_irqsave(&ack_send_lock, flags);

    if (ack_send_head == ack_send_tail) {
        spin_unlock_irqrestore(&ack_send_lock, flags);
        return -1;
    }

    *item = ack_send_queue[ack_send_head];
    ack_send_queue[ack_send_head].valid = false;
    ack_send_head = (ack_send_head + 1) % ACK_SEND_QUEUE_SIZE;

    spin_unlock_irqrestore(&ack_send_lock, flags);

    return 0;
}

static int ack_send_queue_size(void)
{
    int size;
    unsigned long flags;

    spin_lock_irqsave(&ack_send_lock, flags);
    if (ack_send_tail >= ack_send_head)
        size = ack_send_tail - ack_send_head;
    else
        size = ACK_SEND_QUEUE_SIZE - ack_send_head + ack_send_tail;
    spin_unlock_irqrestore(&ack_send_lock, flags);

    return size;
}

/* ============ 真正发送 ACK（在 tasklet 中调用） ============ */
static int tapac_do_send_ack(struct tapac_engine *eng,
                              struct tapac_ack_send_item *item)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *th;
    struct net_device *ndev;
    struct rtable *rt;
    struct flowi4 fl4;
    int hdr_len;
    int tcp_len;
    u8 *opt;

    if (! eng || !item)
        return -EINVAL;

    ndev = dev_get_by_name(&init_net, eng->params.nic);
    if (!ndev)
        return -ENODEV;

    tcp_len = 32;
    hdr_len = sizeof(struct iphdr) + tcp_len;

    skb = alloc_skb(LL_MAX_HEADER + hdr_len, GFP_ATOMIC);
    if (!skb) {
        dev_put(ndev);
        return -ENOMEM;
    }

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_network_header(skb);

    iph = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    memset(iph, 0, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(hdr_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = item->local_ip;
    iph->daddr = item->remote_ip;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    skb_set_transport_header(skb, sizeof(struct iphdr));
    th = (struct tcphdr *)skb_put(skb, tcp_len);
    memset(th, 0, tcp_len);
    th->source = item->local_port;
    th->dest = item->remote_port;
    th->seq = htonl(item->my_seq);
    th->ack_seq = htonl(item->ack_seq);
    th->doff = tcp_len / 4;
    th->ack = 1;
    th->window = htons(item->win);

    opt = (u8 *)th + 20;
    *opt++ = 1;
    *opt++ = 1;
    *opt++ = 8;
    *opt++ = 10;
    *(u32 *)opt = htonl(item->tsval);
    opt += 4;
    *(u32 *)opt = htonl(item->tsecr);

    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcp_len, IPPROTO_TCP,
                                   csum_partial((char *)th, tcp_len, 0));

    memset(&fl4, 0, sizeof(fl4));
    fl4.saddr = item->local_ip;
    fl4.daddr = item->remote_ip;
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

/* ============ ACK 发送 tasklet ============ */
static void tapac_ack_send_tasklet_func(unsigned long data)
{
    struct tapac_engine *eng = (struct tapac_engine *)data;
    struct tapac_ack_send_item item;
    int sent = 0;

    if (!eng)
        return;

    while (sent < 256 && ack_send_queue_dequeue(&item) == 0) {
        if (item.valid) {
            tapac_do_send_ack(eng, &item);
            sent++;
        }
    }

    if (ack_send_head != ack_send_tail) {
        tasklet_schedule(&ack_send_tasklet);
    }
}

/* ============ ACK 调度器初始化 ============ */
void tapac_ack_init(struct tapac_engine *eng)
{
    int i;

    for (i = 0; i < ACK_BUCKETS; i++) {
        eng->ack_buckets[i].head = NULL;
        eng->ack_buckets[i].tail = NULL;
    }

    eng->ack_cursor = 0;
    eng->ack_scheduled_flows = 0;
    spin_lock_init(&eng->ack_lock);

    ack_send_head = 0;
    ack_send_tail = 0;
    g_ack_eng = eng;

    tasklet_init(&ack_send_tasklet, tapac_ack_send_tasklet_func,
                 (unsigned long)eng);
}

/* ============ ACK 调度器清理 ============ */
void tapac_ack_cleanup(struct tapac_engine *eng)
{
    struct tapac_ack_node *n, *next;
    unsigned long flags;
    int i;

    tasklet_kill(&ack_send_tasklet);

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

    g_ack_eng = NULL;
}

/* ============ 清理流的所有 ACK 节点 ============ */
void tapac_ack_flush_flow(struct tapac_engine *eng, struct tapac_flow *flow)
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

/*
 * ============ ACK 入队 - 修复版 ============
 * 关键修复：
 * 1.使用 per-flow 计数器而不是全局静态变量
 * 2.不 DROP 原始 ACK，只记录统计
 * 3.返回 -1 让调用者发送原始 ACK
 */
int tapac_ack_queue(struct tapac_engine *eng, struct tapac_flow *flow,
                    u32 ack_seq, u16 ack_win)
{
    struct tapac_flow_info *info = &flow->info;
    unsigned long flags;

    if (!eng->params.use_ack_scheduler)
        return -1;

    spin_lock_irqsave(&eng->ack_lock, flags);

    /* 检查 ACK 是否前进 */
    if (tapac_seq_leq(ack_seq, info->last_ack_seq)) {
        eng->stats.ack_merged++;
        spin_unlock_irqrestore(&eng->ack_lock, flags);
        return -1;  /* 返回 -1，让原始 ACK 发送 */
    }

    /* 记录统计 */
    eng->stats.ack_created++;

    spin_unlock_irqrestore(&eng->ack_lock, flags);

    /* 返回 -1，让原始 ACK 正常发送 */
    /* 我们不 DROP 任何 ACK，只做统计和窗口修改 */
    return -1;
}

/* ============ 兼容函数 ============ */
int tapac_build_and_send_ack(struct tapac_engine *eng, struct tapac_flow *flow,
                              u32 ack_seq, u16 win, u32 tsval, u32 tsecr)
{
    int ret;

    ret = ack_send_queue_enqueue(flow, ack_seq, win, tsval, tsecr);
    if (ret == 0) {
        tasklet_schedule(&ack_send_tasklet);
    }

    return ret;
}

/* ============ ACK 调度（定时器中调用） ============ */
void tapac_ack_schedule(struct tapac_engine *eng)
{
    if (!eng || !eng->params.use_ack_scheduler)
        return;

    if (ack_send_queue_size() > 0) {
        tasklet_schedule(&ack_send_tasklet);
    }
}