/*
 * zeta_proc.c - /proc Interface (Extended Stats)
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/percpu.h>
#include "zeta_core.h"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_stats;
static struct proc_dir_entry *proc_config;
static struct proc_dir_entry *proc_conns;
static struct proc_dir_entry *proc_percpu;

/* ========== 统计信息显示 ========== */
static int zeta_proc_stats_show(struct seq_file *m, void *v)
{
    int cpu;
    u64 total_in = 0, total_out = 0, total_modified = 0;
    u64 total_delayed = 0, total_suppressed = 0, total_split = 0;

    if (!g_zeta)
        return -ENODEV;

    /* 聚合 Per-CPU 统计 */
    if (g_zeta->percpu_stats) {
        for_each_possible_cpu(cpu) {
            struct zeta_percpu_stats *ps = per_cpu_ptr(g_zeta->percpu_stats, cpu);
            total_in += ps->pkts_in;
            total_out += ps->pkts_out;
            total_modified += ps->pkts_modified;
            total_delayed += ps->acks_delayed;
            total_suppressed += ps->acks_suppressed;
            total_split += ps->acks_split;
        }
    }

    seq_printf(m, "=== Zeta-TCP Statistics ===\n\n");

    seq_printf(m, "Version: %s\n", ZETA_VERSION);
    seq_printf(m, "Enabled: %s\n", g_zeta->enabled ? "yes" : "no");
    seq_printf(m, "Verbose: %s\n", g_zeta->verbose ? "yes" : "no");
    seq_printf(m, "ACK Splitting: %s\n", g_zeta->ack_split_enabled ? "yes" : "no");
    seq_printf(m, "CPUs: %d\n", num_possible_cpus());
    seq_printf(m, "\n");

    seq_printf(m, "[Connections]\n");
    seq_printf(m, "  Active:     %d\n", atomic_read(&g_zeta->conn_count));
    seq_printf(m, "  Total:      %lld\n", atomic64_read(&g_zeta->stats.conns_total));
    seq_printf(m, "\n");

    seq_printf(m, "[Packets - Per-CPU Aggregated]\n");
    seq_printf(m, "  In:         %llu\n", total_in);
    seq_printf(m, "  Out:        %llu\n", total_out);
    seq_printf(m, "  Modified:   %llu\n", total_modified);
    seq_printf(m, "\n");

    seq_printf(m, "[ACK Control]\n");
    seq_printf(m, "  Delayed:    %llu\n", total_delayed);
    seq_printf(m, "  Suppressed: %llu\n", total_suppressed);
    seq_printf(m, "  Split:      %llu\n", total_split);
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

/* ========== Per-CPU 详细统计 ========== */
static int zeta_proc_percpu_show(struct seq_file *m, void *v)
{
    int cpu;

    if (!g_zeta || !g_zeta->percpu_stats)
        return -ENODEV;

    seq_printf(m, "=== Per-CPU Statistics ===\n\n");
    seq_printf(m, "%-4s %12s %12s %12s %12s %12s\n",
               "CPU", "Pkts_In", "Pkts_Out", "Modified", "Delayed", "Split");
    seq_printf(m, "-------------------------------------------------------------------\n");

    for_each_possible_cpu(cpu) {
        struct zeta_percpu_stats *ps = per_cpu_ptr(g_zeta->percpu_stats, cpu);

        seq_printf(m, "%-4d %12llu %12llu %12llu %12llu %12llu\n",
                   cpu,
                   ps->pkts_in,
                   ps->pkts_out,
                   ps->pkts_modified,
                   ps->acks_delayed,
                   ps->acks_split);
    }

    return 0;
}

static int zeta_proc_percpu_open(struct inode *inode, struct file *file)
{
    return single_open(file, zeta_proc_percpu_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops zeta_proc_percpu_ops = {
    .proc_open    = zeta_proc_percpu_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations zeta_proc_percpu_ops = {
    .owner   = THIS_MODULE,
    .open    = zeta_proc_percpu_open,
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
    seq_printf(m, "ack_split=%d\n", g_zeta->ack_split_enabled ? 1 : 0);
    seq_printf(m, "max_rate=%u\n", g_zeta->max_rate);
    seq_printf(m, "start_rate=%u\n", g_zeta->start_rate);
    seq_printf(m, "batch_size=%u\n", g_zeta->batch_size);

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

    if (len > 0 && kbuf[len-1] == '\n')
        kbuf[len-1] = '\0';

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
    } else if (strcmp(key, "ack_split") == 0) {
        g_zeta->ack_split_enabled = (simple_strtoul(val, NULL, 10) != 0);
        ZETA_LOG("ack_split = %d\n", g_zeta->ack_split_enabled);
    } else if (strcmp(key, "max_rate") == 0) {
        g_zeta->max_rate = simple_strtoul(val, NULL, 10);
        ZETA_LOG("max_rate = %u\n", g_zeta->max_rate);
    } else if (strcmp(key, "start_rate") == 0) {
        g_zeta->start_rate = simple_strtoul(val, NULL, 10);
        ZETA_LOG("start_rate = %u\n", g_zeta->start_rate);
    } else if (strcmp(key, "batch_size") == 0) {
        g_zeta->batch_size = simple_strtoul(val, NULL, 10);
        ZETA_LOG("batch_size = %u\n", g_zeta->batch_size);
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

/* ========== 连接列表 ========== */
static int zeta_proc_conns_show(struct seq_file *m, void *v)
{
    struct zeta_conn *conn;
    int bkt;
    int count = 0;
    static const char *state_names[] = {
        "NORMAL", "RAND_LOSS", "DELAY_UP", "BURST", "STABLE", "RECOVER"
    };

    if (!g_zeta)
        return -ENODEV;

    seq_printf(m, "%-21s %-21s %-10s %-6s %-8s %-8s %-4s\n",
               "Source", "Destination", "State", "Score", "Sent", "Lost", "CPU");
    seq_printf(m, "--------------------------------------------------------------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(g_zeta->conn_table, bkt, conn, hnode) {
        if (count++ >= 100) {
            seq_printf(m, "...(truncated, %d total)\n",
                       atomic_read(&g_zeta->conn_count));
            break;
        }

        seq_printf(m, "%pI4:%-5u %pI4:%-5u %-10s %-6u %-8u %-8u %-4d\n",
                   &conn->saddr, ntohs(conn->sport),
                   &conn->daddr, ntohs(conn->dport),
                   state_names[conn->state],
                   conn->features.congestion_score,
                   conn->pkts_sent,
                   conn->pkts_lost,
                   conn->preferred_cpu);
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

/* ========== 初始化 ========== */
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
    proc_percpu = proc_create("percpu", 0444, proc_dir, &zeta_proc_percpu_ops);

    if (!proc_stats || !proc_config || !proc_conns || !proc_percpu) {
        ZETA_WARN("Failed to create /proc entries\n");
        zeta_proc_cleanup();
        return -ENOMEM;
    }

    ZETA_LOG("/proc/zeta_tcp interface created\n");
    return 0;
}

void zeta_proc_cleanup(void)
{
    if (proc_percpu)
        proc_remove(proc_percpu);
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