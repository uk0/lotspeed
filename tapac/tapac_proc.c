/*
 * tapac_proc.c - /proc 接口 v2.2
 */

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "tapac.h"

#define PROC_DIR_NAME "tapac"

enum {
    T_U32,
    T_U64,
    T_U16,
    T_STRING
};

struct tapac_param_map {
    const char *name;
    void *ptr;
    int type;
};

static struct tapac_engine *g_eng = NULL;
static struct proc_dir_entry *proc_dir = NULL;

static struct tapac_param_map param_maps[] = {
    {"debug", NULL, T_U32},
    {"nic", NULL, T_STRING},
    {"mss", NULL, T_U32},
    {"min_win", NULL, T_U32},
    {"timer_interval_us", NULL, T_U32},
    {"min_rtt", NULL, T_U32},
    {"max_rtt", NULL, T_U32},
    {"max_delay", NULL, T_U32},
    {"bucket_size", NULL, T_U32},
    {"min_pkt_len", NULL, T_U32},
    {"throughput_smooth", NULL, T_U32},
    {"rtt_smooth", NULL, T_U32},
    {"alpha", NULL, T_U32},
    {"reduction_thresh", NULL, T_U16},
    {"prio_thresh", NULL, T_U64},
    {"ss_thresh", NULL, T_U64},
    {"ack_delay_ms", NULL, T_U32},
    {"win_inflate_factor", NULL, T_U32},
    {"ack_every_n_packets", NULL, T_U32},
    {"upload_accel_thresh", NULL, T_U32},
    {"use_ack_scheduler", NULL, T_U32},
    {"generate_sack", NULL, T_U32},
    {"separate_buckets", NULL, T_U32},
    {"upload_bucket_size", NULL, T_U32},
    {NULL, NULL, 0}
};

static void tapac_proc_init_ptrs(struct tapac_engine *eng)
{
    param_maps[0].ptr = &eng->params.debug;
    param_maps[1].ptr = eng->params.nic;
    param_maps[2].ptr = &eng->params.mss;
    param_maps[3].ptr = &eng->params.min_win;
    param_maps[4].ptr = &eng->params.timer_interval_us;
    param_maps[5].ptr = &eng->params.min_rtt;
    param_maps[6].ptr = &eng->params.max_rtt;
    param_maps[7].ptr = &eng->params.max_delay;
    param_maps[8].ptr = &eng->params.bucket_size;
    param_maps[9].ptr = &eng->params.min_pkt_len;
    param_maps[10].ptr = &eng->params.throughput_smooth;
    param_maps[11].ptr = &eng->params.rtt_smooth;
    param_maps[12].ptr = &eng->params.alpha;
    param_maps[13].ptr = &eng->params.reduction_thresh;
    param_maps[14].ptr = &eng->params.prio_thresh;
    param_maps[15].ptr = &eng->params.ss_thresh;
    param_maps[16].ptr = &eng->params.ack_delay_ms;
    param_maps[17].ptr = &eng->params.win_inflate_factor;
    param_maps[18].ptr = &eng->params.ack_every_n_packets;
    param_maps[19].ptr = &eng->params.upload_accel_thresh;
    param_maps[20].ptr = &eng->params.use_ack_scheduler;
    param_maps[21].ptr = &eng->params.generate_sack;
    param_maps[22].ptr = &eng->params.separate_buckets;
    param_maps[23].ptr = &eng->params.upload_bucket_size;
}

static int tapac_param_show(struct seq_file *m, void *v)
{
    struct tapac_param_map *map = m->private;

    if (! map || !map->ptr)
        return 0;

    switch (map->type) {
    case T_U32:
        seq_printf(m, "%u\n", *(u32 *)map->ptr);
        break;
    case T_U64:
        seq_printf(m, "%llu\n", *(u64 *)map->ptr);
        break;
    case T_U16:
        seq_printf(m, "%u\n", *(u16 *)map->ptr);
        break;
    case T_STRING:
        seq_printf(m, "%s\n", (char *)map->ptr);
        break;
    }

    return 0;
}

static int tapac_param_open(struct inode *inode, struct file *file)
{
    return single_open(file, tapac_param_show, TAPAC_PDE_DATA(inode));
}

static ssize_t tapac_param_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *pos)
{
    struct seq_file *m = file->private_data;
    struct tapac_param_map *map = m->private;
    char kbuf[64];
    unsigned long val;
    char *p;
    int ret;

    if (! map || !map->ptr)
        return -EINVAL;

    if (count > sizeof(kbuf) - 1)
        count = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    p = strchr(kbuf, '\n');
    if (p)
        *p = '\0';

    if (map->type == T_STRING) {
        strncpy((char *)map->ptr, kbuf, 31);
        ((char *)map->ptr)[31] = '\0';
        return count;
    }

    ret = kstrtoul(kbuf, 10, &val);
    if (ret < 0)
        return ret;

    switch (map->type) {
    case T_U32:
        *(u32 *)map->ptr = (u32)val;
        break;
    case T_U64:
        *(u64 *)map->ptr = val;
        break;
    case T_U16:
        *(u16 *)map->ptr = (u16)val;
        break;
    }

    return count;
}

static int tapac_stats_show(struct seq_file *m, void *v)
{
    struct tapac_engine *eng = g_eng;
    u32 q_high_size = 0;
    u32 q_low_size = 0;

    if (!eng)
        return 0;

    if (eng->q_high)
        q_high_size = eng->q_high->size;
    if (eng->q_low)
        q_low_size = eng->q_low->size;

    seq_printf(m, "=== TAPAC Statistics v2.2 ===\n");
    seq_printf(m, "Flows: %u\n", eng->ft.count);
    seq_printf(m, "ACK scheduled flows: %u\n", eng->ack_scheduled_flows);

    seq_printf(m, "\n--- ACK Optimization ---\n");
    seq_printf(m, "Created: %llu\n", eng->stats.ack_created);
    seq_printf(m, "Merged: %llu\n", eng->stats.ack_merged);
    seq_printf(m, "Compressed: %llu\n", eng->stats.ack_compressed);
    seq_printf(m, "Scheduled: %llu\n", eng->stats.ack_scheduled);
    seq_printf(m, "Sent: %llu\n", eng->stats.ack_sent);
    seq_printf(m, "Real sent: %llu\n", eng->stats.ack_real_sent);
    seq_printf(m, "Queue full: %llu\n", eng->stats.ack_queue_full);

    seq_printf(m, "\n--- Loss Detection ---\n");
    seq_printf(m, "Loss detected: %llu\n", eng->stats.loss_detected);
    seq_printf(m, "Fast retransmit: %llu\n", eng->stats.fast_retransmit);
    seq_printf(m, "Fast path hits: %llu\n", eng->stats.fast_path_hits);
    seq_printf(m, "OOO packets: %llu\n", eng->stats.ooo_packets);

    seq_printf(m, "\n--- SACK ---\n");
    seq_printf(m, "SACK parsed: %llu\n", eng->stats.sack_parsed);
    seq_printf(m, "SACK generated: %llu\n", eng->stats.sack_generated);

    seq_printf(m, "\n--- Upload Acceleration ---\n");
    seq_printf(m, "Window inflated: %llu\n", eng->stats.win_inflated);
    seq_printf(m, "ACK accelerated: %llu\n", eng->stats.ack_accelerated);
    seq_printf(m, "Upload bytes accel: %llu\n", eng->stats.upload_bytes_accel);

    seq_printf(m, "\n--- RTT ---\n");
    seq_printf(m, "RTT samples: %llu\n", eng->stats.rtt_samples);
    seq_printf(m, "Avg RTT: %u us\n", eng->avg_rtt);

    seq_printf(m, "\n--- Flows ---\n");
    seq_printf(m, "Created: %llu\n", eng->stats.flows_created);
    seq_printf(m, "Destroyed: %llu\n", eng->stats.flows_destroyed);

    seq_printf(m, "\n--- Packets ---\n");
    seq_printf(m, "RX: %llu\n", eng->stats.pkts_rx);
    seq_printf(m, "TX: %llu\n", eng->stats.pkts_tx);
    seq_printf(m, "Queued: %llu\n", eng->stats.pkts_queued);
    seq_printf(m, "Dropped: %llu\n", eng->stats.pkts_dropped);

    seq_printf(m, "\n--- Traffic ---\n");
    seq_printf(m, "Bytes RX: %llu\n", eng->stats.bytes_rx);
    seq_printf(m, "Bytes TX: %llu\n", eng->stats.bytes_tx);

    seq_printf(m, "\n--- Queues ---\n");
    seq_printf(m, "High priority: %u\n", q_high_size);
    seq_printf(m, "Low priority: %u\n", q_low_size);

    seq_printf(m, "\n--- Token Buckets ---\n");
    seq_printf(m, "DL Tokens: %llu / %u\n", eng->dl_tokens, eng->params.bucket_size);
    seq_printf(m, "UL Tokens: %llu / %u\n", eng->ul_tokens, eng->params.upload_bucket_size);
    seq_printf(m, "Avg Throughput: %u Kbps\n", eng->avg_throughput);

    seq_printf(m, "\n--- Feature Flags ---\n");
    seq_printf(m, "ACK Scheduler: %s (no-drop mode)\n", eng->params.use_ack_scheduler ? "ON" : "OFF");
    seq_printf(m, "SACK Generation: %s\n", eng->params.generate_sack ? "ON" : "OFF");
    seq_printf(m, "Separate Buckets: %s\n", eng->params.separate_buckets ? "ON" : "OFF");

    seq_printf(m, "\n--- Parameters ---\n");
    seq_printf(m, "ACK delay: %u ms\n", eng->params.ack_delay_ms);
    seq_printf(m, "Win inflate factor: %u\n", eng->params.win_inflate_factor);
    seq_printf(m, "Max delay: %u us\n", eng->params.max_delay);

    return 0;
}

static int tapac_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, tapac_stats_show, NULL);
}

#if defined(TAPAC_USE_PROC_OPS)
static const struct proc_ops tapac_param_fops = {
    .proc_open = tapac_param_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = tapac_param_write,
};

static const struct proc_ops tapac_stats_fops = {
    .proc_open = tapac_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations tapac_param_fops = {
    .open = tapac_param_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = tapac_param_write,
};

static const struct file_operations tapac_stats_fops = {
    .open = tapac_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

int tapac_proc_init(struct tapac_engine *eng)
{
    struct tapac_param_map *map;

    g_eng = eng;
    tapac_proc_init_ptrs(eng);

    proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (! proc_dir) {
        TAPAC_ERR("Failed to create /proc/%s\n", PROC_DIR_NAME);
        return -ENOMEM;
    }

    for (map = param_maps; map->name; map++) {
        if (! proc_create_data(map->name, 0644, proc_dir, &tapac_param_fops, map)) {
            TAPAC_ERR("Failed to create /proc/%s/%s\n", PROC_DIR_NAME, map->name);
        }
    }

    if (! proc_create("stats", 0444, proc_dir, &tapac_stats_fops)) {
        TAPAC_ERR("Failed to create /proc/%s/stats\n", PROC_DIR_NAME);
    }

    TAPAC_INFO("Created /proc/%s\n", PROC_DIR_NAME);
    return 0;
}

void tapac_proc_cleanup(void)
{
    struct tapac_param_map *map;

    if (! proc_dir)
        return;

    for (map = param_maps; map->name; map++) {
        remove_proc_entry(map->name, proc_dir);
    }

    remove_proc_entry("stats", proc_dir);
    remove_proc_entry(PROC_DIR_NAME, NULL);

    proc_dir = NULL;
    g_eng = NULL;

    TAPAC_INFO("Removed /proc/%s\n", PROC_DIR_NAME);
}