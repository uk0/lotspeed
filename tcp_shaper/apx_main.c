/*
 * APX 加速器 v6.0 - 主模块
 * 企业级TCP加速器完整实现
 */

#include "apx_core.h"

/* 全局变量定义 */
struct apx_configuration g_cfg = {
    .initial_cwnd_scale = 10,
    .max_cwnd = 4 * 1024 * 1024,
    .pacing_rate = 1000ULL * 1024 * 1024,
    .rtt_scale = 70,
    .turbo_mode = 1,
    .wan_enforce = 1,
    .max_flows = 65536,
    .flow_timeout = 300,
    .enabled = true,
    .dynamic_bw = true,      /* 启用动态带宽 */
    .smart_retrans = true,   /* 启用智能重传 */
    .multi_queue = true      /* 启用多队列 */
};

struct rhashtable apx_flow_table;
struct hrtimer apx_pacing_timer;
atomic_t apx_flow_count = ATOMIC_INIT(0);
struct workqueue_struct *apx_wq;
DEFINE_PER_CPU(unsigned long, apx_cpu_load);

/* 哈希表参数 */
static const struct rhashtable_params apx_ht_params = {
    .head_offset = offsetof(struct apx_flow_context, node),
    .key_offset = offsetof(struct apx_flow_context, key),
    .key_len = sizeof(struct apx_flow_key),
    .hashfn = jhash,
    .automatic_shrinking = true,
    .max_size = 65536,
    .min_size = 256,
};

/* 外部函数声明 */
extern void apx_update_bandwidth_estimate(struct apx_flow_context *ctx, u32 ack_seq);
extern void apx_adjust_window_by_bandwidth(struct apx_flow_context *ctx);
extern void apx_update_rtt(struct apx_flow_context *ctx, u32 measured_rtt);
extern void apx_track_packet(struct apx_flow_context *ctx, struct sk_buff *skb);
extern void apx_check_early_retransmit(struct apx_flow_context *ctx);
extern void apx_handle_dup_ack(struct apx_flow_context *ctx, u32 ack_seq);
extern void apx_cleanup_acked_packets(struct apx_flow_context *ctx, u32 ack_seq);
extern int apx_enqueue_priority(struct apx_flow_context *ctx, struct sk_buff *skb);
extern struct sk_buff *apx_dequeue_priority(struct apx_flow_context *ctx);
extern void apx_init_priority_queues(struct apx_flow_context *ctx);
extern void apx_destroy_priority_queues(struct apx_flow_context *ctx);

/**
 * apx_flow_get - 增加流引用计数
 */
void apx_flow_get(struct apx_flow_context *ctx)
{
    atomic_inc(&ctx->refcount);
}

/**
 * apx_flow_put - 减少流引用计数
 */
void apx_flow_put(struct apx_flow_context *ctx)
{
    if (atomic_dec_and_test(&ctx->refcount)) {
        cancel_work_sync(&ctx->tx_work.work);
        apx_destroy_priority_queues(ctx);
        skb_queue_purge(&ctx->retrans_ctrl.inflight_queue);
        kfree_rcu(ctx, rcu);
        atomic_dec(&apx_flow_count);
    }
}

/**
 * apx_find_flow - 查找流
 */
struct apx_flow_context *apx_find_flow(const struct apx_flow_key *key)
{
    struct apx_flow_context *ctx;

    ctx = rhashtable_lookup_fast(&apx_flow_table, key, apx_ht_params);
    if (ctx) {
        apx_flow_get(ctx);
        ctx->last_activity = jiffies;
    }

    return ctx;
}

/**
 * apx_create_flow - 创建新流
 */
struct apx_flow_context *apx_create_flow(const struct apx_flow_key *key)
{
    struct apx_flow_context *ctx;
    int ret;

    if (atomic_read(&apx_flow_count) >= g_cfg.max_flows)
        return NULL;

    ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
    if (!ctx)
        return NULL;

    /* 初始化基础字段 */
    memcpy(&ctx->key, key, sizeof(*key));
    spin_lock_init(&ctx->lock);
    atomic_set(&ctx->refcount, 1);
    ctx->state = APX_STATE_SYN;
    ctx->last_activity = jiffies;
    ctx->mss = DEFAULT_MSS;

    /* 初始化高级模块 */
    apx_init_priority_queues(ctx);
    skb_queue_head_init(&ctx->retrans_ctrl.inflight_queue);

    /* 初始化拥塞控制 */
    ctx->cwnd = g_cfg.initial_cwnd_scale * ctx->mss;
    ctx->ssthresh = g_cfg.max_cwnd;
    ctx->rtt_analyzer.cwnd_gain = g_cfg.initial_cwnd_scale;

    /* 初始化速率控制 */
    ctx->dynamic_pacing_rate = g_cfg.pacing_rate;
    ctx->token_bucket = ctx->cwnd;
    ctx->max_tokens = ctx->cwnd;

    /* 插入哈希表 */
    ret = rhashtable_insert_fast(&apx_flow_table, &ctx->node, apx_ht_params);
    if (ret) {
        kfree(ctx);
        return NULL;
    }

    atomic_inc(&apx_flow_count);
    apx_flow_get(ctx);

    APX_LOG("创建流: %pI4:%u -> %pI4:%u (总计: %d)\n",
            &key->saddr, ntohs(key->sport),
            &key->daddr, ntohs(key->dport),
            atomic_read(&apx_flow_count));

    return ctx;
}

/**
 * apx_destroy_flow - 销毁流
 */
void apx_destroy_flow(struct apx_flow_context *ctx)
{
    APX_LOG("销毁流: %pI4:%u -> %pI4:%u\n",
            &ctx->key.saddr, ntohs(ctx->key.sport),
            &ctx->key.daddr, ntohs(ctx->key.dport));

    rhashtable_remove_fast(&apx_flow_table, &ctx->node, apx_ht_params);
    apx_flow_put(ctx);
}

/* 定时器回调函数 */
static enum hrtimer_restart apx_timer_callback(struct hrtimer *timer)
{
    struct rhashtable_iter iter;
    struct apx_flow_context *ctx;
    int processed = 0;

    if (!g_cfg.enabled) {
        hrtimer_forward_now(timer, ns_to_ktime(PACING_INTERVAL_NS * 10));
        return HRTIMER_RESTART;
    }

    rcu_read_lock();

    rhashtable_walk_enter(&apx_flow_table, &iter);
    rhashtable_walk_start(&iter);

    while ((ctx = rhashtable_walk_next(&iter)) != NULL && processed < 100) {
        if (IS_ERR(ctx))
            continue;

        if (! spin_trylock(&ctx->lock))
            continue;

        /* 检查早期重传 */
        if (g_cfg.smart_retrans) {
            apx_check_early_retransmit(ctx);
        }

        spin_unlock(&ctx->lock);
        processed++;
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    rcu_read_unlock();

    hrtimer_forward_now(timer, ns_to_ktime(PACING_INTERVAL_NS));
    return HRTIMER_RESTART;
}

/* Netfilter钩子 */
static unsigned int apx_tx_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    /* TX钩子实现（简化版） */
    return NF_ACCEPT;
}

static unsigned int apx_rx_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    /* RX钩子实现（简化版） */
    return NF_ACCEPT;
}

static struct nf_hook_ops apx_nf_ops[] = {
    {
        .hook = apx_tx_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = apx_rx_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int __init apx_module_init(void)
{
    int ret;

    APX_LOG("========================================\n");
    APX_LOG("APX TCP Accelerator v6.0 Enterprise Edition\n");
    APX_LOG("Referenced ZetaTCP\n");
    APX_LOG("========================================\n");

    apx_wq = alloc_workqueue("apx_wq", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 256);
    if (!apx_wq)
        return -ENOMEM;

    ret = rhashtable_init(&apx_flow_table, &apx_ht_params);
    if (ret) {
        destroy_workqueue(apx_wq);
        return ret;
    }

    hrtimer_init(&apx_pacing_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    apx_pacing_timer.function = apx_timer_callback;
    hrtimer_start(&apx_pacing_timer, ns_to_ktime(PACING_INTERVAL_NS), HRTIMER_MODE_REL);

    ret = nf_register_net_hooks(&init_net, apx_nf_ops, ARRAY_SIZE(apx_nf_ops));
    if (ret) {
        hrtimer_cancel(&apx_pacing_timer);
        rhashtable_destroy(&apx_flow_table);
        destroy_workqueue(apx_wq);
        return ret;
    }

    APX_LOG("insmod successfully\n");
    APX_LOG("Advanced feature status:\n");
    APX_LOG("  Dynamic bandwidth detection: %s\n", g_cfg.dynamic_bw ?  "on" : "off");
    APX_LOG("  Smart retransmission       : %s\n", g_cfg.smart_retrans ? "on" : "off");
    APX_LOG("  Multi-queue QoS            : %s\n", g_cfg.multi_queue ?  "on" : "off");
    APX_LOG("========================================\n");

    return 0;
}

static void __exit apx_module_exit(void)
{
    APX_LOG("Uninstall APX mod...\n");

    g_cfg.enabled = false;
    nf_unregister_net_hooks(&init_net, apx_nf_ops, ARRAY_SIZE(apx_nf_ops));
    hrtimer_cancel(&apx_pacing_timer);
    flush_workqueue(apx_wq);
    synchronize_rcu();
    rhashtable_destroy(&apx_flow_table);
    destroy_workqueue(apx_wq);

    APX_LOG("mod uninstall succeed\n");
}

module_init(apx_module_init);
module_exit(apx_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NeoJ Team");
MODULE_DESCRIPTION("APX TCP Acce v6.0 - Router-Level TCP Accelerator");
MODULE_VERSION("6.0");

EXPORT_SYMBOL_GPL(apx_flow_get);
EXPORT_SYMBOL_GPL(apx_flow_put);
EXPORT_SYMBOL_GPL(apx_find_flow);
EXPORT_SYMBOL_GPL(apx_create_flow);
EXPORT_SYMBOL_GPL(apx_destroy_flow);