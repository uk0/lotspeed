/*
 * zeta_conn.c - Connection Tracking Management
 * Hash table based connection management with RCU
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include "zeta_core.h"

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

/* ========== 创建连接 ========== */
struct zeta_conn *zeta_conn_create(__be32 saddr, __be32 daddr,
                                    __be16 sport, __be16 dport)
{
    struct zeta_conn *conn;
    u32 hash;

    if (! g_zeta)
        return NULL;

    /* 检查连接数限制 */
    if (atomic_read(&g_zeta->conn_count) >= ZETA_MAX_CONNECTIONS) {
        ZETA_WARN("Max connections reached (%d)\n", ZETA_MAX_CONNECTIONS);
        return NULL;
    }

    /* 分配新连接 */
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

    conn->create_time = zeta_now_ms();
    conn->last_active = conn->create_time;

    /* 初始化 ACK 控制参数 */
    conn->ack_rwnd_scale = 100;
    conn->ack_dup_thresh = 3;

    /* 初始化虚拟窗口 */
    conn->virtual_cwnd = 10;
    conn->target_rate = g_zeta->start_rate;

    /* 初始化 RTT 特征 */
    conn->features.rtt_min = 0;
    conn->features.rtt_avg = 0;

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

    if (cleaned > 0) {
        ZETA_DBG("GC: cleaned %d stale connections\n", cleaned);
    }

    /* 重新调度 GC */
    mod_timer(&g_zeta->gc_timer, jiffies + msecs_to_jiffies(ZETA_GC_INTERVAL_MS));
}

/* ========== 初始化连接管理 ========== */
void zeta_conn_init(void)
{
    if (!g_zeta)
        return;

    /* 设置 GC 定时器 */
    timer_setup(&g_zeta->gc_timer, zeta_conn_gc, 0);
    mod_timer(&g_zeta->gc_timer, jiffies + msecs_to_jiffies(ZETA_GC_INTERVAL_MS));

    ZETA_LOG("Connection manager initialized\n");
}

/* ========== 清理连接管理 ========== */
void zeta_conn_cleanup(void)
{
    struct zeta_conn *conn;
    struct hlist_node *tmp;
    int bkt;

    if (!g_zeta)
        return;

    /* 停止 GC 定时器 */
    del_timer_sync(&g_zeta->gc_timer);

    /* 清理所有连接 */
    spin_lock_bh(&g_zeta->conn_lock);
    hash_for_each_safe(g_zeta->conn_table, bkt, tmp, conn, hnode) {
        hash_del(&conn->hnode);
        kfree(conn);
    }
    atomic_set(&g_zeta->conn_count, 0);
    spin_unlock_bh(&g_zeta->conn_lock);

    ZETA_LOG("Connection manager cleaned up\n");
}