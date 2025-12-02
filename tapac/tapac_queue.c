/*
 * tapac_queue.c - 包队列管理
 */

#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <net/net_namespace.h>

#include "tapac.h"

/* ============ 队列初始化 ============ */
struct tapac_pkt_queue *tapac_queue_alloc(u32 capacity)
{
    struct tapac_pkt_queue *q;

    q = kzalloc(sizeof(*q), GFP_KERNEL);
    if (!q)
        return NULL;

    q->ring = vzalloc(capacity * sizeof(struct tapac_pkt_node));
    if (! q->ring) {
        kfree(q);
        return NULL;
    }

    q->head = 0;
    q->tail = 0;
    q->size = 0;
    q->capacity = capacity;
    spin_lock_init(&q->lock);

    return q;
}

/* ============ 队列释放 ============ */
void tapac_queue_free(struct tapac_pkt_queue *q)
{
    if (!q)
        return;

    if (q->ring)
        vfree(q->ring);

    kfree(q);
}

/* ============ 入队 ============ */
int tapac_queue_enqueue(struct tapac_pkt_queue *q, struct sk_buff *skb,
                         tapac_okfn_t okfn, u32 trigger, u32 enqueue_time)
{
    unsigned long flags;

    if (! q || !q->ring || ! skb)
        return 0;

    spin_lock_irqsave(&q->lock, flags);

    if (q->size >= q->capacity) {
        spin_unlock_irqrestore(&q->lock, flags);
        return 0;
    }

    q->ring[q->tail]. skb = skb;
    q->ring[q->tail].okfn = okfn;
    q->ring[q->tail].trigger = trigger;
    q->ring[q->tail].enqueue_time = enqueue_time;

    q->tail = (q->tail + 1) % q->capacity;
    q->size++;

    spin_unlock_irqrestore(&q->lock, flags);

    return 1;
}

/* ============ 出队（发送包） ============ */
int tapac_queue_dequeue(struct tapac_pkt_queue *q)
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

    /* 发送包 */
    if (okfn && skb) {
#if defined(TAPAC_OKFN_NEW_API)
        okfn(&init_net, NULL, skb);
#else
        okfn(skb);
#endif
    }

    return 1;
}

/* ============ 查看队头 ============ */
struct tapac_pkt_node *tapac_queue_peek(struct tapac_pkt_queue *q)
{
    if (!q || !q->ring || q->size == 0)
        return NULL;

    return &q->ring[q->head];
}

/* ============ 获取队列大小 ============ */
u32 tapac_queue_size(struct tapac_pkt_queue *q)
{
    if (!q)
        return 0;
    return q->size;
}

/* ============ 丢弃队头 ============ */
void tapac_queue_drop_head(struct tapac_pkt_queue *q)
{
    struct tapac_pkt_node *pkt;
    unsigned long flags;

    if (!q || !q->ring)
        return;

    spin_lock_irqsave(&q->lock, flags);

    if (q->size == 0) {
        spin_unlock_irqrestore(&q->lock, flags);
        return;
    }

    pkt = &q->ring[q->head];

    if (pkt->skb) {
        kfree_skb(pkt->skb);
        pkt->skb = NULL;
    }
    pkt->okfn = NULL;

    q->head = (q->head + 1) % q->capacity;
    q->size--;

    spin_unlock_irqrestore(&q->lock, flags);
}