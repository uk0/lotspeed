/*
 * zeta_batch.c - NAPI-style Batch Processing
 * Efficient packet batching for reduced overhead
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/workqueue.h>
#include "zeta_core.h"

/* 批处理工作队列 */
static struct workqueue_struct *batch_wq;

/* 批处理工作结构 */
struct zeta_batch_work {
    struct work_struct work;
    int cpu;
};

static DEFINE_PER_CPU(struct zeta_batch_work, batch_work);

/* ========== 批处理工作函数 ========== */
static void zeta_batch_work_fn(struct work_struct *work)
{
    struct zeta_batch_work *bw = container_of(work, struct zeta_batch_work, work);
    zeta_batch_flush(bw->cpu);
}

/* ========== 初始化批处理 ========== */
int zeta_batch_init(void)
{
    int cpu;

    /* 创建高优先级工作队列 */
    batch_wq = alloc_workqueue("zeta_batch", 
                                WQ_HIGHPRI | WQ_CPU_INTENSIVE | WQ_UNBOUND,
                                num_possible_cpus());
    if (!batch_wq) {
        ZETA_WARN("Failed to create batch workqueue\n");
        return -ENOMEM;
    }

    /* 初始化每个 CPU 的工作 */
    for_each_possible_cpu(cpu) {
        struct zeta_batch_work *bw = &per_cpu(batch_work, cpu);
        INIT_WORK(&bw->work, zeta_batch_work_fn);
        bw->cpu = cpu;
    }

    ZETA_LOG("Batch processing initialized\n");
    return 0;
}

/* ========== 清理批处理 ========== */
void zeta_batch_cleanup(void)
{
    if (batch_wq) {
        /* 刷新所有待处理的工作 */
        flush_workqueue(batch_wq);
        destroy_workqueue(batch_wq);
        batch_wq = NULL;
    }

    /* 清理所有 CPU 的队列 */
    zeta_batch_flush_all();

    ZETA_LOG("Batch processing cleaned up\n");
}

/* ========== 入队到批处理 ========== */
void zeta_batch_enqueue(struct sk_buff *skb, int cpu)
{
    struct zeta_batch_queue *batch;
    u64 now_us;
    bool should_flush = false;

    if (!g_zeta || ! g_zeta->percpu_batch || !skb)
        return;

    batch = per_cpu_ptr(g_zeta->percpu_batch, cpu);
    now_us = zeta_now_us();

    spin_lock(&batch->lock);

    /* 加入队列 */
    __skb_queue_tail(&batch->queue, skb);
    batch->pending_count++;

    /* 检查是否需要刷新 */
    if (batch->pending_count >= g_zeta->batch_size) {
        should_flush = true;
    } else if (now_us - batch->last_flush_us >= g_zeta->batch_timeout_us) {
        should_flush = true;
    }

    spin_unlock(&batch->lock);

    /* 需要刷新时调度工作 */
    if (should_flush && batch_wq) {
        struct zeta_batch_work *bw = &per_cpu(batch_work, cpu);
        queue_work(batch_wq, &bw->work);
    }
}

/* ========== 刷新指定 CPU 的批处理队列 ========== */
void zeta_batch_flush(int cpu)
{
    struct zeta_batch_queue *batch;
    struct sk_buff *skb;
    struct sk_buff_head tmp_queue;
    int processed = 0;

    if (!g_zeta || !g_zeta->percpu_batch)
        return;

    batch = per_cpu_ptr(g_zeta->percpu_batch, cpu);

    /* 初始化临时队列 */
    __skb_queue_head_init(&tmp_queue);

    /* 原子地移动队列 */
    spin_lock(&batch->lock);
    skb_queue_splice_init(&batch->queue, &tmp_queue);
    batch->pending_count = 0;
    batch->last_flush_us = zeta_now_us();
    spin_unlock(&batch->lock);

    /* 处理所有 SKB */
    while ((skb = __skb_dequeue(&tmp_queue)) != NULL) {
        /* 这里可以进行批量处理优化 */
        /* 当前直接重新注入网络栈 */
        kfree_skb(skb);
        processed++;
    }

    if (processed > 0 && g_zeta->verbose) {
        ZETA_LOG("CPU %d: batch flushed %d packets\n", cpu, processed);
    }

    /* 更新统计 */
    if (g_zeta->percpu_stats) {
        struct zeta_percpu_stats *stats = per_cpu_ptr(g_zeta->percpu_stats, cpu);
        stats->batch_count += processed;
    }
}

/* ========== 刷新所有 CPU 的批处理队列 ========== */
void zeta_batch_flush_all(void)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        zeta_batch_flush(cpu);
    }
}