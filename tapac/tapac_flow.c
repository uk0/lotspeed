/*
 * tapac_flow.c - 流表管理 v2.2
 * 更新：匹配新的 ACK 队列结构
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>

#include "tapac.h"

static inline u32 tapac_flow_hash(__be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport)
{
    u32 a = (__force u32)saddr ^ (__force u32)daddr;
    u32 b = ((__force u32)sport << 16) | (__force u32)dport;
    return jhash_2words(a, b, 0) & (FLOW_TABLE_SIZE - 1);
}

void tapac_flow_table_init(struct tapac_flow_table *ft)
{
    int i;

    for (i = 0; i < FLOW_TABLE_SIZE; i++)
        INIT_LIST_HEAD(&ft->buckets[i]);

    ft->count = 0;
    spin_lock_init(&ft->lock);
}

void tapac_flow_table_cleanup(struct tapac_flow_table *ft)
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

struct tapac_flow *tapac_flow_lookup(struct tapac_flow_table *ft,
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

struct tapac_flow *tapac_flow_create(struct tapac_flow_table *ft,
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
    flow->info.last_ack_seq = 0;
    flow->info.last_data_seq = 0;
    flow->info.my_seq = 0;
    flow->info.peer_tsval = 0;
    flow->info.bytes_sent_total = 0;
    flow->info.bytes_sent_latest = 0;
    flow->info.last_throughput = 0;
    flow->info.throughput_reduction_num = 0;

    /* 初始化 ACK 队列（新结构：使用指针而非 list_head） */
    flow->info.ackq.head = NULL;
    flow->info.ackq.tail = NULL;
    flow->info.ackq.depth = 0;
    flow->info.ackq.bucket_idx = ((__force u16)sport ^ (__force u16)dport) & (ACK_BUCKETS - 1);
    flow->info.ackq.scheduled = 0;

    hash = tapac_flow_hash(saddr, daddr, sport, dport);
    list_add(&flow->list, &ft->buckets[hash]);
    ft->count++;

    spin_unlock_irqrestore(&ft->lock, flags);

    return flow;
}

void tapac_flow_delete(struct tapac_flow_table *ft,
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

/* 清理超时的流 */
int tapac_flow_cleanup_timeout(struct tapac_flow_table *ft, u32 timeout_us)
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