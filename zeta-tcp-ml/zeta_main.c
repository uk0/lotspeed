/*
 * zeta_main.c - Zeta-TCP Main Module Entry
 * Learning-based TCP Accelerator via NetFilter
 * Author: uk0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include "zeta_core.h"

/* 全局上下文 */
struct zeta_ctx *g_zeta = NULL;

/* 模块参数 */
static bool enable = true;
module_param(enable, bool, 0644);
MODULE_PARM_DESC(enable, "Enable Zeta-TCP acceleration (default: true)");

static bool verbose = false;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Enable verbose logging (default: false)");

static unsigned int max_rate = 125000000;  /* 1Gbps */
module_param(max_rate, uint, 0644);
MODULE_PARM_DESC(max_rate, "Maximum rate in bytes/sec (default: 125MB/s = 1Gbps)");

static unsigned int start_rate = 6250000;  /* 50Mbps */
module_param(start_rate, uint, 0644);
MODULE_PARM_DESC(start_rate, "Initial rate for new connections (default: 6.25MB/s = 50Mbps)");

/* 初始化全局上下文 */
static int zeta_ctx_init(void)
{
    g_zeta = kzalloc(sizeof(struct zeta_ctx), GFP_KERNEL);
    if (!g_zeta) {
        ZETA_WARN("Failed to allocate global context\n");
        return -ENOMEM;
    }

    /* 初始化哈希表 */
    hash_init(g_zeta->conn_table);
    spin_lock_init(&g_zeta->conn_lock);
    atomic_set(&g_zeta->conn_count, 0);

    /* 配置 */
    g_zeta->enabled = enable;
    g_zeta->verbose = verbose;
    g_zeta->max_rate = max_rate;
    g_zeta->start_rate = start_rate;

    /* 统计初始化 */
    atomic64_set(&g_zeta->stats.conns_total, 0);
    atomic64_set(&g_zeta->stats.conns_active, 0);
    atomic64_set(&g_zeta->stats.pkts_in, 0);
    atomic64_set(&g_zeta->stats.pkts_out, 0);
    atomic64_set(&g_zeta->stats.pkts_modified, 0);
    atomic64_set(&g_zeta->stats.acks_delayed, 0);
    atomic64_set(&g_zeta->stats.acks_suppressed, 0);
    atomic64_set(&g_zeta->stats.cwnd_reductions, 0);
    atomic64_set(&g_zeta->stats.learning_decisions, 0);

    return 0;
}

static void zeta_ctx_cleanup(void)
{
    if (g_zeta) {
        kfree(g_zeta);
        g_zeta = NULL;
    }
}

/* 模块初始化 */
static int __init zeta_module_init(void)
{
    int ret;

    ZETA_LOG("Zeta-TCP v%s initializing...\n", ZETA_VERSION);
    ZETA_LOG("Learning-based TCP Accelerator via NetFilter\n");

    /* 1.初始化全局上下文 */
    ret = zeta_ctx_init();
    if (ret)
        goto err_ctx;

    /* 2.初始化连接管理 */
    zeta_conn_init();

    /* 3.注册 NetFilter 钩子 */
    ret = zeta_hooks_register();
    if (ret)
        goto err_hooks;

    /* 4.初始化 /proc 接口 */
    ret = zeta_proc_init();
    if (ret)
        goto err_proc;

    ZETA_LOG("Initialized successfully!\n");
    ZETA_LOG("  Max Rate: %u bytes/s (%u Mbps)\n",
             g_zeta->max_rate, g_zeta->max_rate * 8 / 1000000);
    ZETA_LOG("  Start Rate: %u bytes/s (%u Mbps)\n",
             g_zeta->start_rate, g_zeta->start_rate * 8 / 1000000);

    return 0;

err_proc:
    zeta_hooks_unregister();
err_hooks:
    zeta_conn_cleanup();
    zeta_ctx_cleanup();
err_ctx:
    return ret;
}

/* 模块退出 */
static void __exit zeta_module_exit(void)
{
    ZETA_LOG("Unloading...\n");

    /* 1.移除 /proc 接口 */
    zeta_proc_cleanup();

    /* 2.注销 NetFilter 钩子 */
    zeta_hooks_unregister();

    /* 3.等待所有 RCU 回调完成 */
    synchronize_rcu();

    /* 4.清理连接 */
    zeta_conn_cleanup();

    /* 5.释放全局上下文 */
    zeta_ctx_cleanup();

    ZETA_LOG("Unloaded successfully.\n");
}

module_init(zeta_module_init);
module_exit(zeta_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uk0");
MODULE_DESCRIPTION("Zeta-TCP: Learning-based TCP Accelerator via NetFilter");
MODULE_VERSION(ZETA_VERSION);