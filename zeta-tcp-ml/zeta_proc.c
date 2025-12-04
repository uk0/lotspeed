/*
 * zeta_proc.c - /proc Interface for Configuration and Stats
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "zeta_core.h"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_stats;
static struct proc_dir_entry *proc_config;
static struct proc_dir_entry *proc_conns;

/* ========== 统计信息显示 ========== */
static int zeta_proc_stats_show(struct seq_file *m, void *v)
{
    if (!g_zeta)
        return -ENODEV;
    
    seq_printf(m, "=== Zeta-TCP Statistics ===\n\n");
    
    seq_printf(m, "Version: %s\n", ZETA_VERSION);
    seq_printf(m, "Enabled: %s\n", g_zeta->enabled ? "yes" : "no");
    seq_printf(m, "Verbose: %s\n", g_zeta->verbose ? "yes" : "no");
    seq_printf(m, "\n");
    
    seq_printf(m, "[Connections]\n");
    seq_printf(m, "  Active:     %d\n", atomic_read(&g_zeta->conn_count));
    seq_printf(m, "  Total:      %lld\n", atomic64_read(&g_zeta->stats.conns_total));
    seq_printf(m, "\n");
    
    seq_printf(m, "[Packets]\n");
    seq_printf(m, "  In:         %lld\n", atomic64_read(&g_zeta->stats.pkts_in));
    seq_printf(m, "  Out:        %lld\n", atomic64_read(&g_zeta->stats.pkts_out));
    seq_printf(m, "  Modified:   %lld\n", atomic64_read(&g_zeta->stats.pkts_modified));
    seq_printf(m, "\n");
    
    seq_printf(m, "[ACK Control]\n");
    seq_printf(m, "  Delayed:    %lld\n", atomic64_read(&g_zeta->stats.acks_delayed));
    seq_printf(m, "  Suppressed: %lld\n", atomic64_read(&g_zeta->stats.acks_suppressed));
    seq_printf(m, "  CWND Reductions: %lld\n", atomic64_read(&g_zeta->stats.cwnd_reductions));
    seq_printf(m, "\n");
    
    seq_printf(m, "[Learning Engine]\n");
    seq_printf(m, "  Decisions:  %lld\n", atomic64_read(&g_zeta->stats.learning_decisions));
    
    return 0;
}

static int zeta_proc_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_proc_stats_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops zeta_proc_stats_ops = {
    .proc_open    = zeta_proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zeta_proc_stats_ops = {
    .owner   = THIS_MODULE,
    .open    = zeta_proc_stats_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/* ========== 配置接口 ========== */
static int zeta_proc_config_show(struct seq_file *m, void *v)
{
    if (!g_zeta)
        return -ENODEV;
    
    seq_printf(m, "# Zeta-TCP Configuration\n");
    seq_printf(m, "# Write 'key=value' to modify\n\n");
    seq_printf(m, "enabled=%d\n", g_zeta->enabled ?  1 : 0);
    seq_printf(m, "verbose=%d\n", g_zeta->verbose ? 1 : 0);
    seq_printf(m, "max_rate=%u\n", g_zeta->max_rate);
    seq_printf(m, "start_rate=%u\n", g_zeta->start_rate);
    
    return 0;
}

static ssize_t zeta_proc_config_write(struct file *file, const char __user *buf,
                                       size_t count, loff_t *ppos)
{
    char kbuf[64];
    char *key, *val;
    size_t len;
    
    if (! g_zeta)
        return -ENODEV;
    
    len = min(count, sizeof(kbuf) - 1);
    if (copy_from_user(kbuf, buf, len))
        return -EFAULT;
    
    kbuf[len] = '\0';
    
    /* 去除换行符 */
    if (len > 0 && kbuf[len-1] == '\n')
        kbuf[len-1] = '\0';
    
    /* 解析 key=value */
    key = kbuf;
    val = strchr(kbuf, '=');
    if (! val)
        return -EINVAL;
    
    *val++ = '\0';
    
    if (strcmp(key, "enabled") == 0) {
        g_zeta->enabled = (simple_strtoul(val, NULL, 10) != 0);
        ZETA_LOG("enabled = %d\n", g_zeta->enabled);
    } else if (strcmp(key, "verbose") == 0) {
        g_zeta->verbose = (simple_strtoul(val, NULL, 10) != 0);
        ZETA_LOG("verbose = %d\n", g_zeta->verbose);
    } else if (strcmp(key, "max_rate") == 0) {
        g_zeta->max_rate = simple_strtoul(val, NULL, 10);
        ZETA_LOG("max_rate = %u\n", g_zeta->max_rate);
    } else if (strcmp(key, "start_rate") == 0) {
        g_zeta->start_rate = simple_strtoul(val, NULL, 10);
        ZETA_LOG("start_rate = %u\n", g_zeta->start_rate);
    } else {
        return -EINVAL;
    }
    
    return count;
}

static int zeta_proc_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_proc_config_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops zeta_proc_config_ops = {
    .proc_open    = zeta_proc_config_open,
    .proc_read    = seq_read,
    .proc_write   = zeta_proc_config_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zeta_proc_config_ops = {
    .owner   = THIS_MODULE,
    .open    = zeta_proc_config_open,
    .read    = seq_read,
    .write   = zeta_proc_config_write,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/* ========== 连接列表显示 ========== */
static int zeta_proc_conns_show(struct seq_file *m, void *v)
{
    struct zeta_conn *conn;
    int bkt;
    int count = 0;
    static const char *state_names[] = {
        "NORMAL", "RAND_LOSS", "DELAY_UP", "BURST", "STABLE", "RECOVER"
    };
    
    if (! g_zeta)
        return -ENODEV;
    
    seq_printf(m, "%-21s %-21s %-10s %-6s %-8s %-8s\n",
               "Source", "Destination", "State", "Score", "Sent", "Lost");
    seq_printf(m, "----------------------------------------------------------------------\n");
    
    rcu_read_lock();
    hash_for_each_rcu(g_zeta->conn_table, bkt, conn, hnode) {
        if (count++ >= 100) {
            seq_printf(m, "...(truncated, %d total)\n", 
                       atomic_read(&g_zeta->conn_count));
            break;
        }
        
        seq_printf(m, "%pI4:%-5u %pI4:%-5u %-10s %-6u %-8u %-8u\n",
                   &conn->saddr, ntohs(conn->sport),
                   &conn->daddr, ntohs(conn->dport),
                   state_names[conn->state],
                   conn->features.congestion_score,
                   conn->pkts_sent,
                   conn->pkts_lost);
    }
    rcu_read_unlock();
    
    return 0;
}

static int zeta_proc_conns_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_proc_conns_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops zeta_proc_conns_ops = {
    .proc_open    = zeta_proc_conns_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zeta_proc_conns_ops = {
    .owner   = THIS_MODULE,
    .open    = zeta_proc_conns_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/* ========== 初始化 /proc 接口 ========== */
int zeta_proc_init(void)
{
    proc_dir = proc_mkdir("zeta_tcp", NULL);
    if (!proc_dir) {
        ZETA_WARN("Failed to create /proc/zeta_tcp\n");
        return -ENOMEM;
    }
    
    proc_stats = proc_create("stats", 0444, proc_dir, &zeta_proc_stats_ops);
    proc_config = proc_create("config", 0644, proc_dir, &zeta_proc_config_ops);
    proc_conns = proc_create("connections", 0444, proc_dir, &zeta_proc_conns_ops);
    
    if (! proc_stats || !proc_config || !proc_conns) {
        ZETA_WARN("Failed to create /proc entries\n");
        zeta_proc_cleanup();
        return -ENOMEM;
    }
    
    ZETA_LOG("/proc/zeta_tcp interface created\n");
    return 0;
}

/* ========== 清理 /proc 接口 ========== */
void zeta_proc_cleanup(void)
{
    if (proc_conns)
        proc_remove(proc_conns);
    if (proc_config)
        proc_remove(proc_config);
    if (proc_stats)
        proc_remove(proc_stats);
    if (proc_dir)
        proc_remove(proc_dir);
    
    ZETA_LOG("/proc/zeta_tcp interface removed\n");
}