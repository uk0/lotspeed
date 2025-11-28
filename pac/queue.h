#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/string.h>
#include <net/net_namespace.h>

// okfn 签名在 4.4+ 内核中改变
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    #define OKFN_NEW_API 1
    typedef int (*okfn_t)(struct net *, struct sock *, struct sk_buff *);
#else
    typedef int (*okfn_t)(struct sk_buff *);
#endif

// 队列大小：广域网需要更大的队列
#define QUEUE_SIZE 131072

struct Packet
{
    struct sk_buff *skb;
    okfn_t okfn;
    unsigned int trigger;       // 此包能触发的数据量
    unsigned int enqueue_time;  // 入队时间戳
};

struct PacketQueue
{
    struct Packet *packets;
    unsigned int head;
    unsigned int tail;
    unsigned int size;
    unsigned int capacity;
};

static void Init_PacketQueue(struct PacketQueue* q)
{
    if (!q) return;

    q->packets = vmalloc(QUEUE_SIZE * sizeof(struct Packet));
    if (!q->packets) {
        printk(KERN_ERR "PAC: Failed to allocate packet queue\n");
        return;
    }
    memset(q->packets, 0, QUEUE_SIZE * sizeof(struct Packet));
    q->head = 0;
    q->tail = 0;
    q->size = 0;
    q->capacity = QUEUE_SIZE;
}

static void Free_PacketQueue(struct PacketQueue* q)
{
    if (!q) return;
    if (q->packets) {
        vfree(q->packets);
        q->packets = NULL;
    }
    vfree(q);
}

static int Enqueue_PacketQueue(struct PacketQueue* q, struct sk_buff *skb,
                                okfn_t okfn, unsigned int trigger, unsigned int time)
{
    if (!q || ! q->packets || q->size >= q->capacity)
        return 0;

    q->packets[q->tail].skb = skb;
    q->packets[q->tail].okfn = okfn;
    q->packets[q->tail].trigger = trigger;
    q->packets[q->tail]. enqueue_time = time;

    q->tail = (q->tail + 1) % q->capacity;
    q->size++;

    return 1;
}

// 只获取包信息，不直接发送（用于 tasklet 方案）
static int Dequeue_PacketQueue_GetPacket(struct PacketQueue* q,
                                          struct sk_buff **skb_out,
                                          okfn_t *okfn_out)
{
    struct Packet *pkt;

    if (!q || ! q->packets || q->size == 0)
        return 0;

    pkt = &q->packets[q->head];

    *skb_out = pkt->skb;
    *okfn_out = pkt->okfn;

    // 清理
    pkt->skb = NULL;
    pkt->okfn = NULL;

    q->head = (q->head + 1) % q->capacity;
    q->size--;

    return 1;
}

// 获取队列中等待的包数量
static unsigned int Queue_Size(struct PacketQueue* q)
{
    if (!q) return 0;
    return q->size;
}

#endif /* __QUEUE_H__ */