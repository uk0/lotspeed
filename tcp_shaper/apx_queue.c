/*
 * APX 加速器 v6.0 - 多优先级队列模块
 * 实现QoS和智能调度
 */

#include "apx_core.h"

/**
 * apx_classify_packet - 对数据包进行分类
 * @skb: 数据包
 * 返回:  队列优先级
 */
static int apx_classify_packet(struct sk_buff *skb)
{
    struct tcphdr *th = tcp_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    u32 payload_len;

    /* 重传包最高优先级 */
    if (skb->mark & 0x80000000)
        return APX_QUEUE_CONTROL;

    /* 控制包最高优先级 */
    if (th->syn || th->fin || th->rst)
        return APX_QUEUE_CONTROL;

    /* 计算有效载荷长度 */
    payload_len = skb->len - (iph->ihl * 4) - (th->doff * 4);

    /* 纯ACK或小包进入交互队列 */
    if (payload_len == 0 || payload_len <= 100)
        return APX_QUEUE_INTERACTIVE;

    /* 大包进入批量队列 */
    return APX_QUEUE_BULK;
}

/**
 * apx_enqueue_priority - 按优先级入队
 * @ctx: 流上下文
 * @skb: 数据包
 * 返回: 0成功，负值失败
 */
int apx_enqueue_priority(struct apx_flow_context *ctx, struct sk_buff *skb)
{
    struct apx_priority_queues *pq = &ctx->priority_queues;
    int priority = apx_classify_packet(skb);
    int max_len = MAX_QUEUE_LEN / APX_NUM_QUEUES;

    /* 动态调整队列长度限制 */
    if (priority == APX_QUEUE_CONTROL) {
        max_len = MAX_QUEUE_LEN / 2; /* 控制队列可以更长 */
    }

    /* 检查队列长度 */
    if (atomic_read(&pq->queue_lens[priority]) >= max_len) {
        /* 队列满，尝试降级 */
        if (priority == APX_QUEUE_INTERACTIVE) {
            priority = APX_QUEUE_BULK;
        }

        if (atomic_read(&pq->queue_lens[priority]) >= max_len) {
            ctx->packets_dropped++;
            kfree_skb(skb);
            APX_DBG("队列满:  优先级=%d\n", priority);
            return -ENOSPC;
        }
    }

    /* 入队 */
    skb_queue_tail(&pq->queues[priority], skb);
    atomic_inc(&pq->queue_lens[priority]);

    APX_DBG("包入队: 优先级=%d, 长度=%d\n",
            priority, atomic_read(&pq->queue_lens[priority]));

    return 0;
}

/**
 * apx_dequeue_priority - 按优先级出队（WRR调度）
 * @ctx:  流上下文
 * 返回: SKB或NULL
 */
struct sk_buff *apx_dequeue_priority(struct apx_flow_context *ctx)
{
    struct apx_priority_queues *pq = &ctx->priority_queues;
    struct sk_buff *skb = NULL;
    int i;

    /* 绝对优先处理控制包 */
    if (!skb_queue_empty(&pq->queues[APX_QUEUE_CONTROL])) {
        skb = __skb_dequeue(&pq->queues[APX_QUEUE_CONTROL]);
        atomic_dec(&pq->queue_lens[APX_QUEUE_CONTROL]);
        return skb;
    }

    /* WRR调度其他队列 */
    for (i = APX_QUEUE_INTERACTIVE; i < APX_NUM_QUEUES; i++) {
        if (skb_queue_empty(&pq->queues[i]))
            continue;

        /* 检查信用 */
        if (pq->credits[i] > 0) {
            skb = __skb_dequeue(&pq->queues[i]);
            atomic_dec(&pq->queue_lens[i]);
            pq->credits[i]--;
            break;
        }
    }

    /* 如果没有可发送的包，重置信用 */
    if (!skb) {
        bool has_packets = false;

        for (i = APX_QUEUE_INTERACTIVE; i < APX_NUM_QUEUES; i++) {
            if (!skb_queue_empty(&pq->queues[i])) {
                has_packets = true;
                pq->credits[i] = pq->weights[i];
            }
        }

        /* 如果重置后有包，重试 */
        if (has_packets) {
            for (i = APX_QUEUE_INTERACTIVE; i < APX_NUM_QUEUES; i++) {
                if (!skb_queue_empty(&pq->queues[i]) && pq->credits[i] > 0) {
                    skb = __skb_dequeue(&pq->queues[i]);
                    atomic_dec(&pq->queue_lens[i]);
                    pq->credits[i]--;
                    break;
                }
            }
        }
    }

    return skb;
}

/**
 * apx_init_priority_queues - 初始化优先级队列
 * @ctx: 流上下文
 */
void apx_init_priority_queues(struct apx_flow_context *ctx)
{
    struct apx_priority_queues *pq = &ctx->priority_queues;
    int i;

    for (i = 0; i < APX_NUM_QUEUES; i++) {
        skb_queue_head_init(&pq->queues[i]);
        atomic_set(&pq->queue_lens[i], 0);
    }

    /* 设置权重（WRR调度） */
    pq->weights[APX_QUEUE_CONTROL] = 0;     /* 绝对优先，不参与WRR */
    pq->weights[APX_QUEUE_INTERACTIVE] = 10; /* 交互流量高权重 */
    pq->weights[APX_QUEUE_BULK] = 3;        /* 批量流量低权重 */

    /* 初始化信用 */
    for (i = 0; i < APX_NUM_QUEUES; i++) {
        pq->credits[i] = pq->weights[i];
    }
}

/**
 * apx_destroy_priority_queues - 销毁优先级队列
 * @ctx: 流上下文
 */
void apx_destroy_priority_queues(struct apx_flow_context *ctx)
{
    struct apx_priority_queues *pq = &ctx->priority_queues;
    int i;

    for (i = 0; i < APX_NUM_QUEUES; i++) {
        skb_queue_purge(&pq->queues[i]);
        atomic_set(&pq->queue_lens[i], 0);
    }
}

EXPORT_SYMBOL_GPL(apx_enqueue_priority);
EXPORT_SYMBOL_GPL(apx_dequeue_priority);
EXPORT_SYMBOL_GPL(apx_init_priority_queues);
EXPORT_SYMBOL_GPL(apx_destroy_priority_queues);