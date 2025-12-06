/*
 * zeta_conn.c - Connection Tracking with SLAB Cache
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include "zeta_core.h"

/* SLAB 缓存 */
static struct kmem_cache *zeta_conn_cachep = NULL;

/* ========== 初始化连接缓存 ========== */
int zeta_conn_cache_init(void)
{
    /* 创建专用 SLAB 缓存，提高分配效率 */
    zeta_conn_cachep = kmem_cache_create(
        "zeta_conn_cache",
        sizeof(struct zeta_conn),
        0,                              /* 对齐 */
        SLAB_HWCACHE_ALIGN | SLAB_PANIC,  /* 缓存行对齐 */
        NULL                            /* 构造函数 */
    );
    
    if (! zeta_conn_cachep) {
        ZETA_WARN("Failed to create connection cache\n");
        return -ENOMEM;
    }
    
    ZETA_LOG("Connection SLAB cache created (obj_size=%zu)\n",
             sizeof(struct zeta_conn));
    return 0;
}

void zeta_conn_cache_destroy(void)
{
    if (zeta_conn_cachep) {
        kmem_cache_destroy(zeta_conn_cachep);
        zeta_conn_cachep = NULL;
    }
}

/* ========== 哈希函数 ========== */
static inline u32 zeta_conn_hash(__be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport)
{
    u32 ports = ((u32)sport << 16) | (u32)dport;
    return jhash_3words((__force u32)saddr, (__force u32)daddr, ports, 0);
}

/* ========== RCU 释放回调 ========== */
static void zeta_conn_free_rcu(struct rcu_head *head)
{
    struct zeta_conn *conn = container_of(head, struct zeta_conn, rcu);
    
    if (zeta_conn_cachep)
        kmem_cache_free(zeta_conn_cachep, conn);
    else
        kfree(conn);
}

/* ========== 查找连接 ========== */
struct zeta_conn *zeta_conn_find(__be32 saddr, __be32 daddr,
                                  __be16 sport, __be16 dport)
{
    struct zeta_conn *conn;
    u32 hash;

    if (! g_zeta)
        return NULL;

    hash = zeta_conn_hash(saddr, daddr, sport, dport);

    rcu_read_lock();
    hash_for_each_possible_rcu(g_zeta->conn_table, conn, hnode, hash) {
        if (conn->saddr == saddr && conn->daddr == daddr &&
            conn->sport == sport && conn->dport == dport) {
            rcu_read_unlock();
            return conn;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/* ========== 创建连接（使用 SLAB 缓存）========== */
struct zeta_conn *zeta_conn_create(__be32 saddr, __be32 daddr,
                                    __be16 sport, __be16 dport)
{
    struct zeta_conn *conn;
    u32 hash;
    u64 now_us = zeta_now_us();

    if (!g_zeta)
        return NULL;

    if (atomic_read(&g_zeta->conn_count) >= ZETA_MAX_CONNECTIONS) {
        ZETA_WARN("Max connections reached (%d)\n", ZETA_MAX_CONNECTIONS);
        return NULL;
    }

    /* 使用 SLAB 缓存分配 */
    if (zeta_conn_cachep)
        conn = kmem_cache_zalloc(zeta_conn_cachep, GFP_ATOMIC);
    else
        conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
    
    if (! conn) {
        ZETA_WARN("Failed to allocate connection\n");
        return NULL;
    }

    /* 初始化连接 */
    conn->saddr = saddr;
    conn->daddr = daddr;
    conn->sport = sport;
    conn->dport = dport;
    conn->hash_key = zeta_conn_hash(saddr, daddr, sport, dport);

    spin_lock_init(&conn->lock);

    conn->state = ZETA_STATE_NORMAL;
    conn->loss_pattern = LOSS_NONE;

    conn->create_time_us = now_us;
    conn->last_active_us = now_us;
    conn->create_time = now_us / 1000;
    conn->last_active = conn->create_time;

    conn->ack_rwnd_scale = 100;
    conn->ack_dup_thresh = 3;

    zeta_ack_split_init(conn);

    conn->virtual_cwnd = 10;
    conn->target_rate = g_zeta->start_rate;
    conn->preferred_cpu = smp_processor_id();

    /* 加入哈希表 */
    hash = conn->hash_key;
    spin_lock_bh(&g_zeta->conn_lock);
    hash_add_rcu(g_zeta->conn_table, &conn->hnode, hash);
    atomic_inc(&g_zeta->conn_count);
    spin_unlock_bh(&g_zeta->conn_lock);

    atomic64_inc(&g_zeta->stats.conns_total);
    atomic64_inc(&g_zeta->stats.conns_active);

    return conn;
}

/* ========== 销毁连接 ========== */
void zeta_conn_destroy(struct zeta_conn *conn)
{
    if (!conn || !g_zeta)
        return;

    spin_lock_bh(&g_zeta->conn_lock);
    hash_del_rcu(&conn->hnode);
    atomic_dec(&g_zeta->conn_count);
    spin_unlock_bh(&g_zeta->conn_lock);

    atomic64_dec(&g_zeta->stats.conns_active);

    call_rcu(&conn->rcu, zeta_conn_free_rcu);
}

/* ========== 垃圾回收 ========== */
void zeta_conn_gc(struct timer_list *t)
{
    struct zeta_conn *conn;
    struct hlist_node *tmp;
    int bkt;
    u64 now_ms = zeta_now_ms();
    u64 timeout_ms = ZETA_CONN_TIMEOUT_SEC * 1000ULL;
    int cleaned = 0;

    if (!g_zeta)
        return;

    spin_lock_bh(&g_zeta->conn_lock);

    hash_for_each_safe(g_zeta->conn_table, bkt, tmp, conn, hnode) {
        if (now_ms - conn->last_active > timeout_ms) {
            hash_del_rcu(&conn->hnode);
            atomic_dec(&g_zeta->conn_count);
            atomic64_dec(&g_zeta->stats.conns_active);
            call_rcu(&conn->rcu, zeta_conn_free_rcu);
            cleaned++;
        }
    }

    spin_unlock_bh(&g_zeta->conn_lock);

    if (cleaned > 0 && g_zeta->verbose) {
        ZETA_LOG("GC: cleaned %d stale connections\n", cleaned);
    }

    mod_timer(&g_zeta->gc_timer, jiffies + msecs_to_jiffies(ZETA_GC_INTERVAL_MS));
}

/* ========== 初始化 ========== */
void zeta_conn_init(void)
{
    if (!g_zeta)
        return;

    /* 初始化 SLAB 缓存 */
    zeta_conn_cache_init();

    timer_setup(&g_zeta->gc_timer, zeta_conn_gc, 0);
    mod_timer(&g_zeta->gc_timer, jiffies + msecs_to_jiffies(ZETA_GC_INTERVAL_MS));

    ZETA_LOG("Connection manager initialized (hash=%d bits, max=%d)\n",
             ZETA_HASH_BITS, ZETA_MAX_CONNECTIONS);
}

/* ========== 清理 ========== */
void zeta_conn_cleanup(void)
{
    struct zeta_conn *conn;
    struct hlist_node *tmp;
    int bkt;

    if (!g_zeta)
        return;

    del_timer_sync(&g_zeta->gc_timer);

    spin_lock_bh(&g_zeta->conn_lock);
    hash_for_each_safe(g_zeta->conn_table, bkt, tmp, conn, hnode) {
        hash_del(&conn->hnode);
        if (zeta_conn_cachep)
            kmem_cache_free(zeta_conn_cachep, conn);
        else
            kfree(conn);
    }
    atomic_set(&g_zeta->conn_count, 0);
    spin_unlock_bh(&g_zeta->conn_lock);

    /* 销毁 SLAB 缓存 */
    zeta_conn_cache_destroy();

    ZETA_LOG("Connection manager cleaned up\n");
}