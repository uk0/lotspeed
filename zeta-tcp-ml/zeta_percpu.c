/*
 * zeta_percpu.c - Per-CPU Data Management
 * High-performance per-CPU statistics and batch processing
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include "zeta_core.h"

/* ========== 初始化 Per-CPU 数据 ========== */
int zeta_percpu_init(void)
{
    int cpu;

    if (!g_zeta)
        return -EINVAL;

    /* 分配 per-CPU 统计 */
    g_zeta->percpu_stats = alloc_percpu(struct zeta_percpu_stats);
    if (!g_zeta->percpu_stats) {
        ZETA_WARN("Failed to alloc percpu stats\n");
        return -ENOMEM;
    }

    /* 分配 per-CPU 批处理队列 */
    g_zeta->percpu_batch = alloc_percpu(struct zeta_batch_queue);
    if (!g_zeta->percpu_batch) {
        ZETA_WARN("Failed to alloc percpu batch queues\n");
        free_percpu(g_zeta->percpu_stats);
        g_zeta->percpu_stats = NULL;
        return -ENOMEM;
    }

    /* 初始化每个 CPU 的数据 */
    for_each_possible_cpu(cpu) {
        struct zeta_percpu_stats *stats = per_cpu_ptr(g_zeta->percpu_stats, cpu);
        struct zeta_batch_queue *batch = per_cpu_ptr(g_zeta->percpu_batch, cpu);

        memset(stats, 0, sizeof(*stats));

        skb_queue_head_init(&batch->queue);
        spin_lock_init(&batch->lock);
        batch->last_flush_us = zeta_now_us();
        batch->pending_count = 0;
    }

    ZETA_LOG("Per-CPU data initialized for %d CPUs\n", num_possible_cpus());
    return 0;
}

/* ========== 清理 Per-CPU 数据 ========== */
void zeta_percpu_cleanup(void)
{
    int cpu;

    if (!g_zeta)
        return;

    /* 清理批处理队列 */
    if (g_zeta->percpu_batch) {
        for_each_possible_cpu(cpu) {
            struct zeta_batch_queue *batch = per_cpu_ptr(g_zeta->percpu_batch, cpu);
            skb_queue_purge(&batch->queue);
        }
        free_percpu(g_zeta->percpu_batch);
        g_zeta->percpu_batch = NULL;
    }

    /* 释放统计 */
    if (g_zeta->percpu_stats) {
        free_percpu(g_zeta->percpu_stats);
        g_zeta->percpu_stats = NULL;
    }

    ZETA_LOG("Per-CPU data cleaned up\n");
}

/* ========== 聚合所有 CPU 的统计 ========== */
void zeta_percpu_stats_aggregate(struct zeta_stats *total)
{
    int cpu;

    if (! g_zeta || !g_zeta->percpu_stats || !total)
        return;

    /* 重置聚合统计 */
    atomic64_set(&total->pkts_in, 0);
    atomic64_set(&total->pkts_out, 0);
    atomic64_set(&total->pkts_modified, 0);
    atomic64_set(&total->acks_delayed, 0);
    atomic64_set(&total->acks_suppressed, 0);
    atomic64_set(&total->acks_split, 0);
    atomic64_set(&total->learning_decisions, 0);

    /* 遍历所有 CPU 聚合 */
    for_each_possible_cpu(cpu) {
        struct zeta_percpu_stats *stats = per_cpu_ptr(g_zeta->percpu_stats, cpu);

        atomic64_add(stats->pkts_in, &total->pkts_in);
        atomic64_add(stats->pkts_out, &total->pkts_out);
        atomic64_add(stats->pkts_modified, &total->pkts_modified);
        atomic64_add(stats->acks_delayed, &total->acks_delayed);
        atomic64_add(stats->acks_suppressed, &total->acks_suppressed);
        atomic64_add(stats->acks_split, &total->acks_split);
        atomic64_add(stats->learning_decisions, &total->learning_decisions);
    }
}

/* ========== 获取当前 CPU 统计指针 ========== */
struct zeta_percpu_stats *zeta_this_cpu_stats(void)
{
    if (!g_zeta || ! g_zeta->percpu_stats)
        return NULL;
    return this_cpu_ptr(g_zeta->percpu_stats);
}

/* ========== 获取指定 CPU 统计指针 ========== */
struct zeta_percpu_stats *zeta_cpu_stats(int cpu)
{
    if (!g_zeta || !g_zeta->percpu_stats)
        return NULL;
    if (! cpu_possible(cpu))
        return NULL;
    return per_cpu_ptr(g_zeta->percpu_stats, cpu);
}