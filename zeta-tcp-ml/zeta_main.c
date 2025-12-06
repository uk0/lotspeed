/*
 * zeta_main.c - Zeta-TCP Main Module (High-Performance Version)
 * Author: uk0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include "zeta_core.h"

struct zeta_ctx *g_zeta = NULL;

/* 模块参数 */
static bool enable = true;
module_param(enable, bool, 0644);
MODULE_PARM_DESC(enable, "Enable Zeta-TCP (default: true)");

static bool verbose = false;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Enable verbose logging (default: false)");

static bool ack_split = true;
module_param(ack_split, bool, 0644);
MODULE_PARM_DESC(ack_split, "Enable ACK Splitting (default: true)");

static unsigned int max_rate = 125000000;
module_param(max_rate, uint, 0644);
MODULE_PARM_DESC(max_rate, "Max rate bytes/s (default: 1Gbps)");

static unsigned int start_rate = 6250000;
module_param(start_rate, uint, 0644);
MODULE_PARM_DESC(start_rate, "Start rate bytes/s (default: 50Mbps)");

static unsigned int batch_size = ZETA_BATCH_SIZE;
module_param(batch_size, uint, 0644);
MODULE_PARM_DESC(batch_size, "Batch size for processing");

/* ========== 初始化全局上下文 ========== */
static int zeta_ctx_init(void)
{
    g_zeta = kzalloc(sizeof(struct zeta_ctx), GFP_KERNEL);
    if (!g_zeta) {
        ZETA_WARN("Failed to allocate global context\n");
        return -ENOMEM;
    }

    hash_init(g_zeta->conn_table);
    spin_lock_init(&g_zeta->conn_lock);
    atomic_set(&g_zeta->conn_count, 0);

    g_zeta->enabled = enable;
    g_zeta->verbose = verbose;
    g_zeta->ack_split_enabled = ack_split;
    g_zeta->max_rate = max_rate;
    g_zeta->start_rate = start_rate;
    g_zeta->batch_size = batch_size;
    g_zeta->batch_timeout_us = ZETA_BATCH_TIMEOUT_US;

    /* 初始化统计 */
    atomic64_set(&g_zeta->stats.conns_total, 0);
    atomic64_set(&g_zeta->stats.conns_active, 0);
    atomic64_set(&g_zeta->stats.pkts_in, 0);
    atomic64_set(&g_zeta->stats.pkts_out, 0);
    atomic64_set(&g_zeta->stats.pkts_modified, 0);
    atomic64_set(&g_zeta->stats.acks_delayed, 0);
    atomic64_set(&g_zeta->stats.acks_suppressed, 0);
    atomic64_set(&g_zeta->stats.acks_split, 0);
    atomic64_set(&g_zeta->stats.cwnd_reductions, 0);
    atomic64_set(&g_zeta->stats.learning_decisions, 0);
    atomic64_set(&g_zeta->stats.batch_flushes, 0);

    return 0;
}

static void zeta_ctx_cleanup(void)
{
    if (g_zeta) {
        kfree(g_zeta);
        g_zeta = NULL;
    }
}

/* ========== 模块初始化 ========== */
static int __init zeta_module_init(void)
{
    int ret;

    ZETA_LOG("Zeta-TCP v%s initializing...\n", ZETA_VERSION);
    ZETA_LOG("High-Performance TCP Accelerator with per-CPU optimization\n");

    /* 1.初始化全局上下文 */
    ret = zeta_ctx_init();
    if (ret)
        goto err_ctx;

    /* 2.初始化 Per-CPU 数据 */
    ret = zeta_percpu_init();
    if (ret)
        goto err_percpu;

    /* 3.初始化批处理 */
    ret = zeta_batch_init();
    if (ret)
        goto err_batch;

    /* 4.初始化连接管理 */
    zeta_conn_init();

    /* 5.注册钩子 */
    ret = zeta_hooks_register();
    if (ret)
        goto err_hooks;

    /* 6.初始化 /proc */
    ret = zeta_proc_init();
    if (ret)
        goto err_proc;

    ZETA_LOG("Initialized successfully!\n");
    ZETA_LOG("  CPUs: %d\n", num_possible_cpus());
    ZETA_LOG("  Max Rate: %u Mbps\n", g_zeta->max_rate * 8 / 1000000);
    ZETA_LOG("  ACK Splitting: %s\n", g_zeta->ack_split_enabled ? "enabled" : "disabled");
    ZETA_LOG("  Batch Size: %u\n", g_zeta->batch_size);

    return 0;

err_proc:
    zeta_hooks_unregister();
err_hooks:
    zeta_conn_cleanup();
    zeta_batch_cleanup();
err_batch:
    zeta_percpu_cleanup();
err_percpu:
    zeta_ctx_cleanup();
err_ctx:
    return ret;
}

/* ========== 模块退出 ========== */
static void __exit zeta_module_exit(void)
{
    ZETA_LOG("Unloading...\n");

    /* 1.移除 /proc 接口 */
    zeta_proc_cleanup();

    /* 2.注销钩子 */
    zeta_hooks_unregister();

    /* 3.等待 RCU */
    synchronize_rcu();

    /* 4.清理连接 */
    zeta_conn_cleanup();

    /* 5.清理批处理 */
    zeta_batch_cleanup();

    /* 6.清理 Per-CPU */
    zeta_percpu_cleanup();

    /* 7.释放上下文 */
    zeta_ctx_cleanup();

    ZETA_LOG("Unloaded successfully.\n");
}

module_init(zeta_module_init);
module_exit(zeta_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0");
MODULE_DESCRIPTION("Zeta-TCP: High-Performance TCP Accelerator with per-CPU and ACK Splitting");
MODULE_VERSION(ZETA_VERSION);