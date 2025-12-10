/*
 * ACC BoostTCP Core Implementation - Optimized Version 4.0
 * 整合RTT测量、BDP计算、SACK支持、优化乱序处理
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/hrtimer.h>
#include <linux/rhashtable.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/ip.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/route.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <asm/unaligned.h>

/* =========================================================================
 * 调试开关和日志宏
 * ========================================================================= */
static int debug_level = 1;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0=off, 1=basic, 2=verbose, 3=all)");

static int auto_create = 1;
module_param(auto_create, int, 0644);
MODULE_PARM_DESC(auto_create, "Auto create flow for established connections");

static char *net_interface = "enp0s7";
module_param(net_interface, charp, 0644);
MODULE_PARM_DESC(net_interface, "Network interface to use (default: enp0s7)");

static int aggressive_mode = 1;
module_param(aggressive_mode, int, 0644);
MODULE_PARM_DESC(aggressive_mode, "Aggressive acceleration mode (1=on, 0=off)");

#define APX_LOG(level, fmt, ...) \
    do { \
        if (debug_level >= level) \
            printk(KERN_INFO "[ACC] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define LOG_BASIC(fmt, ...)   APX_LOG(1, fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) APX_LOG(2, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)   APX_LOG(3, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   printk(KERN_ERR "[ACC-ERR] " fmt "\n", ##__VA_ARGS__)

/* =========================================================================
 * 统计计数器 (增强版)
 * ========================================================================= */
struct apx_stats {
    atomic_t flows_created;
    atomic_t flows_destroyed;
    atomic_t packets_accelerated;
    atomic_t packets_bypassed;
    atomic_t acks_generated;
    atomic_t acks_advanced;
    atomic_t window_updates;
    atomic_t window_modified;
    atomic_t ooo_packets;
    atomic_t ooo_small_gaps;    // 新增：小间隙统计
    atomic_t ooo_medium_gaps;   // 新增：中间隙统计
    atomic_t ooo_large_gaps;    // 新增：大间隙统计
    atomic_t retransmits;
    atomic_t data_packets;
    atomic_t pure_acks;
    atomic_t ack_send_errors;
    atomic_t sack_blocks_sent;  // 新增：SACK块统计
    atomic_t rtt_updates;        // 新增：RTT更新统计
};

static struct apx_stats global_stats;

/* =========================================================================
 * 标志位定义
 * ========================================================================= */
#define FLAG_ACK_PENDING        0x01
#define FLAG_SACK_ADJUST        0x02
#define FLAG_ACK_TIMER_RUNNING  0x04
#define FLAG_ZERO_WINDOW        0x10
#define FLAG_TURBO_MODE         0x20
#define FLAG_ESTABLISHED        0x40
#define FLAG_SACK_ENABLED       0x80  // 新增：SACK支持标志

/* =========================================================================
 * 核心数据结构定义 (增强版)
 * ========================================================================= */

struct apx_config {
    u16 lan_init_win;
    u16 lan_max_win;
    u32 wan_init_win;
    u32 wan_max_win;
    u16 default_win_scale;
    u32 max_cwnd_packets;
    u32 turbo_flags;
    u8  ack_threshold_lan;
    u8  ack_threshold_wan;
    u32 advance_ack_delay;
    u32 window_boost_factor;
    u32 default_bandwidth;      // 新增：默认带宽 (bps)
    u32 min_rto;                // 新增：最小RTO (us)
    u32 max_rto;                // 新增：最大RTO (us)
};

static struct apx_config g_apx_cfg = {
    .lan_init_win = 32768,
    .lan_max_win = 65535,
    .wan_init_win = 65535,
    .wan_max_win = 1048576,
    .default_win_scale = 16,
    .max_cwnd_packets = 1000,
    .turbo_flags = 0x2140,
    .ack_threshold_lan = 1,     // 更激进
    .ack_threshold_wan = 2,     // 更激进
    .advance_ack_delay = 1,     // 更快的ACK
    .window_boost_factor = 3,   // 更大的boost
    .default_bandwidth = 1000000000,  // 100Mbps默认
    .min_rto = 200000,          // 200ms最小RTO
    .max_rto = 120000000,       // 120s最大RTO
};

struct apx_flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u8 protocol;
};

// SACK块结构
struct sack_block {
    u32 start_seq;
    u32 end_seq;
};

struct apx_tcp_flow {
    struct rhash_head node;
    struct apx_flow_key key;

    void *engine;
    u32 state;
    u32 last_seq_recv;
    u32 unack_edge;
    u8  flags;

    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;

    struct sk_buff_head recv_queue;
    struct sk_buff_head ooo_queue;
    struct sk_buff_head ack_queue;
    struct sk_buff_head retrans_queue;

    struct sk_buff *last_recv;
    struct sk_buff *next_ack;
    u32 next_seq;
    u32 ack_seq;
    u32 last_ack_seq;
    u32 last_sent_seq;
    u32 last_data_seq;

    u16 adv_win;
    u16 remote_win;
    u32 win_edge;
    u8  win_scale;

    u32 cwnd;
    u32 ssthresh;
    u16 mss;

    // RTT测量 (增强版)
    u32 srtt;           // 平滑RTT (us)
    u32 rttvar;         // RTT方差 (us)
    u32 rto;            // 重传超时 (us)
    u32 min_rtt;        // 最小RTT (us)
    u32 max_rtt;        // 最大RTT (us)
    u64 rtt_ts;         // RTT时间戳
    u32 rtt_seq;        // RTT序列号

    u32 bandwidth;      // 估算带宽 (bps)
    u64 last_bw_update; // 上次带宽更新时间

    u16 ack_count;
    u32 ack_accum;
    u16 ack_intervals[384];
    u16 ack_read_idx;
    u16 ack_write_idx;
    u32 last_ack_count;
    u8  ack_pending;
    u8  ack_scheduled;
    u32 pending_ack_count;

    // SACK支持
    struct sack_block sack_blocks[4];
    u8 sack_block_count;

    // Token bucket for pacing
    s64 token_bucket;
    u64 last_tx_time;
    u32 burst_size;

    struct timer_list ack_timer;
    struct timer_list retrans_timer;
    unsigned long last_ack_time;
    unsigned long last_activity;

    struct apx_tcp_flow *peer;
    struct apx_tcp_flow *peer_flow;

    u32 packets_sent;
    u32 packets_recv;
    u32 bytes_sent;
    u32 bytes_recv;
    u32 acks_sent;
    u32 acks_advanced;
    u32 data_packets;
    u32 pure_acks;
    u32 window_modified;

    atomic_t ip_id_counter;
    struct net_device *cached_dev;
    unsigned long cached_dev_time;

    spinlock_t lock;
};

/* =========================================================================
 * 全局变量
 * ========================================================================= */
static struct rhashtable apx_flow_table;
static const struct rhashtable_params apx_flow_ht_params = {
    .head_offset = offsetof(struct apx_tcp_flow, node),
    .key_offset = offsetof(struct apx_tcp_flow, key),
    .key_len = sizeof(struct apx_flow_key),
    .automatic_shrinking = true,
};

static struct proc_dir_entry *apx_proc_dir;
static struct proc_dir_entry *apx_proc_stats;
static struct net_device *default_netdev = NULL;

/* =========================================================================
 * 前向声明
 * ========================================================================= */
static void apx_tcp_send_flow_ack_packets(struct apx_tcp_flow *flow);
static void apx_ack_timer_callback(struct timer_list *t);
static void apx_retrans_timer_callback(struct timer_list *t);
static void apx_tcp_create_and_send_ack_only(struct apx_tcp_flow *flow);
static void apx_tcp_process_new_seq_packet(struct apx_tcp_flow *flow, struct sk_buff *skb);
static void apx_tcp_create_and_send_ack_only_lan(struct apx_tcp_flow *flow);
static void apx_tcp_send_duplicate_ack(struct apx_tcp_flow *flow, u32 seq);
static void apx_tcp_schedule_advance_ack_wan(struct apx_tcp_flow *flow, u32 new_seq);
static void apx_tcp_update_rto_advanced(struct apx_tcp_flow *flow, u32 measured_rtt);

/* =========================================================================
 * 辅助函数：包类型判断
 * ========================================================================= */

static inline bool is_pure_ack(struct sk_buff *skb, struct tcphdr *th)
{
    u32 data_len = skb->len - ip_hdrlen(skb) - (th->doff * 4);
    return (data_len == 0) && th->ack && !th->syn && !th->fin && !th->rst;
}

static inline u32 get_tcp_data_len(struct sk_buff *skb, struct tcphdr *th)
{
    return skb->len - ip_hdrlen(skb) - (th->doff * 4);
}

/* =========================================================================
 * RTT测量和RTO计算 (基于Van Jacobson算法)
 * ========================================================================= */
static void apx_tcp_update_rto_advanced(struct apx_tcp_flow *flow, u32 measured_rtt)
{
    s32 rtt_delta;

    // 更新最小/最大RTT
    if (flow->min_rtt == 0 || measured_rtt < flow->min_rtt)
        flow->min_rtt = measured_rtt;
    if (measured_rtt > flow->max_rtt)
        flow->max_rtt = measured_rtt;

    if (flow->srtt == 0) {
        // 初始RTT
        flow->srtt = measured_rtt;
        flow->rttvar = measured_rtt >> 1;  // RTT方差初始为RTT/2
    } else {
        // Van Jacobson算法
        rtt_delta = measured_rtt - flow->srtt;
        flow->srtt += rtt_delta >> 3;  // srtt = 7/8 * srtt + 1/8 * new_rtt

        if (rtt_delta < 0)
            rtt_delta = -rtt_delta;

        flow->rttvar -= flow->rttvar >> 2;
        flow->rttvar += rtt_delta >> 2;  // rttvar = 3/4 * rttvar + 1/4 * |delta|
    }

    // 计算RTO (RFC 6298)
    flow->rto = flow->srtt + (flow->rttvar << 2);  // RTO = srtt + 4 * rttvar

    // 激进模式：缩短RTO
    if (aggressive_mode) {
        flow->rto = flow->rto * 80 / 100;  // 缩短20%
    }

    // 限制RTO范围
    if (flow->rto < g_apx_cfg.min_rto)
        flow->rto = g_apx_cfg.min_rto;
    if (flow->rto > g_apx_cfg.max_rto)
        flow->rto = g_apx_cfg.max_rto;

    // 更新带宽估算 (简化版)
    if (flow->bytes_recv > 0 && flow->srtt > 0) {
        flow->bandwidth = (flow->bytes_recv * 8 * 1000000) / flow->srtt;
        flow->last_bw_update = ktime_to_us(ktime_get());
    }

    atomic_inc(&global_stats.rtt_updates);

    LOG_DEBUG("RTT Update: measured=%u us, srtt=%u, rttvar=%u, rto=%u us, bw=%u bps",
              measured_rtt, flow->srtt, flow->rttvar, flow->rto, flow->bandwidth);
}

/* =========================================================================
 * 从TCP选项中提取RTT
 * ========================================================================= */
static u32 apx_tcp_extract_rtt_from_options(struct tcphdr *th)
{
    const u8 *ptr;
    int length;
    u32 tsval = 0, tsecr = 0;
    static u32 last_tsval = 0;
    u64 now_us;

    length = (th->doff * 4) - sizeof(struct tcphdr);
    ptr = (const u8 *)(th + 1);

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;

        if (opcode == TCPOPT_EOL) break;
        if (opcode == TCPOPT_NOP) {
            length--;
            continue;
        }

        if (length < 2) break;
        opsize = *ptr++;
        if (opsize < 2 || opsize > length) break;

        if (opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP) {
            tsval = get_unaligned_be32(ptr);
            tsecr = get_unaligned_be32(ptr + 4);
            break;
        }

        ptr += opsize - 2;
        length -= opsize;
    }

    // 简化RTT计算：使用当前时间戳
    if (tsecr != 0 && tsecr == last_tsval) {
        now_us = ktime_to_us(ktime_get());
        return (u32)(now_us & 0xFFFFFFFF) - tsecr;
    }

    last_tsval = tsval;
    return 0;  // 无法计算RTT
}

/* =========================================================================
 * 高级窗口计算 (基于BDP和自适应调整)
 * ========================================================================= */
static u32 apx_tcp_compute_adv_win_advanced(struct apx_tcp_flow *flow)
{
    u32 target_win;
    u64 bdp;
    u32 in_flight;
    u32 max_win;
    bool is_lan;
    u32 utilization;

    is_lan = (flow->peer == flow);
    max_win = is_lan ? g_apx_cfg.lan_max_win : g_apx_cfg.wan_max_win;

    // 计算BDP (Bandwidth-Delay Product)
    if (flow->srtt > 0) {
        u32 effective_bw = flow->bandwidth ?  flow->bandwidth : g_apx_cfg.default_bandwidth;
        bdp = ((u64)effective_bw * flow->srtt) / 1000000;  // bits -> bytes
        bdp = bdp / 8;  // bits to bytes

        // 激进模式：更大的窗口倍数
        if (aggressive_mode) {
            target_win = is_lan ? (bdp * 3) : (bdp * 4);  // 3x/4x BDP
        } else {
            target_win = is_lan ? (bdp * 2) : (bdp * 3);  // 2x/3x BDP
        }

        LOG_VERBOSE("BDP calculation: bw=%u bps, rtt=%u us, bdp=%llu, target=%u",
                    effective_bw, flow->srtt, bdp, target_win);
    } else {
        // 无RTT信息，使用远端窗口倍数
        target_win = flow->remote_win * g_apx_cfg.window_boost_factor;
    }

    // 计算在途数据
    in_flight = flow->next_seq - flow->last_ack_seq;

    // 自适应调整
    if (target_win > 0 && in_flight > 0) {
        utilization = (in_flight * 100) / target_win;

        if (utilization > 90) {
            // 高利用率，激进增大窗口
            target_win = target_win * 150 / 100;  // +50%
            LOG_DEBUG("High utilization %u%%, boosting window to %u", utilization, target_win);
        } else if (utilization > 70) {
            // 中等利用率，适度增大
            target_win = target_win * 125 / 100;  // +25%
        } else if (utilization < 30 && flow->ooo_queue.qlen == 0) {
            // 低利用率且无乱序，可以更激进
            target_win = target_win * 200 / 100;  // +100%
            LOG_DEBUG("Low utilization %u%%, doubling window to %u", utilization, target_win);
        }
    }

    // 根据乱序情况调整
    if (flow->ooo_queue.qlen > 5) {
        // 大量乱序，减小窗口
        target_win = target_win * 80 / 100;  // -20%
        LOG_DEBUG("High OOO count %u, reducing window to %u", flow->ooo_queue.qlen, target_win);
    }

    // 限制最大值
    if (target_win > max_win)
        target_win = max_win;
    if (target_win > 65535)
        target_win = 65535;

    // 防止窗口过小
    if (target_win < flow->mss * 10)
        target_win = flow->mss * 10;

    // 记录窗口变化
    if (flow->adv_win != target_win) {
        LOG_VERBOSE("📊 ADV WINDOW: %u -> %u (bdp=%llu, util=%u%%, ooo=%u, mode=%s)",
                    flow->adv_win, target_win, bdp, utilization,
                    flow->ooo_queue.qlen, is_lan ? "LAN" :  "WAN");
        atomic_inc(&global_stats.window_updates);
    }

    flow->adv_win = target_win;
    return target_win;
}

/* =========================================================================
 * SACK支持
 * ========================================================================= */
static void apx_tcp_update_sack_blocks(struct apx_tcp_flow *flow, u32 start, u32 end)
{
    int i, j;

    // 检查是否可以合并到现有块
    for (i = 0; i < flow->sack_block_count; i++) {
        if (start == flow->sack_blocks[i].end_seq) {
            flow->sack_blocks[i].end_seq = end;
            return;
        }
        if (end == flow->sack_blocks[i].start_seq) {
            flow->sack_blocks[i].start_seq = start;
            return;
        }
    }

    // 添加新块（如果有空间）
    if (flow->sack_block_count < 4) {
        flow->sack_blocks[flow->sack_block_count].start_seq = start;
        flow->sack_blocks[flow->sack_block_count].end_seq = end;
        flow->sack_block_count++;

        // 按序列号排序
        for (i = flow->sack_block_count - 1; i > 0; i--) {
            if (flow->sack_blocks[i].start_seq < flow->sack_blocks[i-1].start_seq) {
                struct sack_block tmp = flow->sack_blocks[i];
                flow->sack_blocks[i] = flow->sack_blocks[i-1];
                flow->sack_blocks[i-1] = tmp;
            }
        }
    }
}

/* =========================================================================
 * 优化的乱序包处理
 * ========================================================================= */
static void apx_tcp_process_ooo_optimized(struct apx_tcp_flow *flow,
                                          struct sk_buff *skb,
                                          u32 seq, u32 end_seq)
{
    u32 gap = seq - flow->next_seq;
    struct sk_buff *ooo_copy;

    // 统计gap大小
    if (gap < flow->mss) {
        atomic_inc(&global_stats.ooo_small_gaps);
    } else if (gap < flow->mss * 10) {
        atomic_inc(&global_stats.ooo_medium_gaps);
    } else {
        atomic_inc(&global_stats.ooo_large_gaps);
    }

    // 根据gap大小决定处理策略
    if (gap <= flow->mss * 2) {
        // 小gap：网络抖动，立即发送重复ACK
        LOG_DEBUG("Small OOO gap %u bytes, immediate dup ACK", gap);
        apx_tcp_send_duplicate_ack(flow, flow->next_seq);
        atomic_inc(&global_stats.ooo_packets);

        // 更新SACK块
        apx_tcp_update_sack_blocks(flow, seq, end_seq);
        flow->flags |= FLAG_SACK_ENABLED;

    } else if (gap <= flow->mss * 10 && flow->ooo_queue.qlen < 8) {
        // 中等gap：保存并等待
        ooo_copy = skb_copy(skb, GFP_ATOMIC);
        if (ooo_copy) {
            __skb_queue_tail(&flow->ooo_queue, ooo_copy);
            atomic_inc(&global_stats.ooo_packets);

            // 更新SACK块
            apx_tcp_update_sack_blocks(flow, seq, end_seq);
            flow->flags |= FLAG_SACK_ENABLED;

            // 达到阈值触发快速重传
            if (flow->ooo_queue.qlen == 3 || flow->ooo_queue.qlen == 6) {
                LOG_VERBOSE("OOO threshold %u reached, triggering fast retransmit",
                           flow->ooo_queue.qlen);
                apx_tcp_send_duplicate_ack(flow, flow->next_seq);
            }
        }

    } else {
        // 大gap：严重丢包，立即触发3次重复ACK
        LOG_VERBOSE("Large OOO gap %u bytes, sending 3 dup ACKs", gap);
        apx_tcp_send_duplicate_ack(flow, flow->next_seq);
        apx_tcp_send_duplicate_ack(flow, flow->next_seq);
        apx_tcp_send_duplicate_ack(flow, flow->next_seq);
        atomic_inc(&global_stats.ooo_packets);

        // 更新SACK块
        apx_tcp_update_sack_blocks(flow, seq, end_seq);
        flow->flags |= FLAG_SACK_ENABLED;
    }
}

/* =========================================================================
 * 辅助函数：获取网络设备
 * ========================================================================= */

static struct net_device *apx_get_output_device(struct apx_tcp_flow *flow)
{
    struct rtable *rt;
    struct flowi4 fl4 = {};
    struct net_device *dev;
    unsigned long now = jiffies;

    if (flow->cached_dev && time_before(now, flow->cached_dev_time + HZ * 5)) {
        return flow->cached_dev;
    }

    if (default_netdev && (default_netdev->flags & IFF_UP)) {
        flow->cached_dev = default_netdev;
        flow->cached_dev_time = now;
        LOG_DEBUG("Using configured interface:  %s", default_netdev->name);
        return default_netdev;
    }

    fl4.daddr = flow->saddr;
    fl4.saddr = flow->daddr;
    fl4.flowi4_proto = IPPROTO_TCP;
    fl4.fl4_sport = flow->dport;
    fl4.fl4_dport = flow->sport;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt)) {
        LOG_ERROR("Failed to find route for %pI4 -> %pI4", &fl4.saddr, &fl4.daddr);
        return NULL;
    }

    dev = rt->dst.dev;
    if (dev) {
        flow->cached_dev = dev;
        flow->cached_dev_time = now;
        LOG_DEBUG("Using routed interface: %s", dev->name);
    }

    ip_rt_put(rt);
    return dev;
}

/* =========================================================================
 * 辅助函数：流管理
 * ========================================================================= */

static struct apx_tcp_flow *apx_find_flow(__be32 saddr, __be32 daddr,
                                          __be16 sport, __be16 dport)
{
    struct apx_flow_key key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .protocol = IPPROTO_TCP,
    };

    struct apx_tcp_flow *flow = rhashtable_lookup_fast(&apx_flow_table, &key, apx_flow_ht_params);

    if (flow) {
        flow->last_activity = jiffies;
        LOG_DEBUG("Found flow: %pI4:%u -> %pI4:%u (rx=%u, tx=%u, acks=%u)",
                  &saddr, ntohs(sport), &daddr, ntohs(dport),
                  flow->packets_recv, flow->packets_sent, flow->acks_sent);
    }

    return flow;
}

static struct apx_tcp_flow *apx_create_flow_ex(struct iphdr *iph, struct tcphdr *th, bool from_syn)
{
    struct apx_tcp_flow *flow;
    int ret;

    flow = apx_find_flow(iph->saddr, iph->daddr, th->source, th->dest);
    if (flow) {
        LOG_DEBUG("Flow already exists, not creating duplicate");
        return flow;
    }

    flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
    if (!flow) {
        LOG_ERROR("Failed to allocate flow memory");
        return NULL;
    }

    flow->key.saddr = iph->saddr;
    flow->key.daddr = iph->daddr;
    flow->key.sport = th->source;
    flow->key.dport = th->dest;
    flow->key.protocol = IPPROTO_TCP;

    flow->saddr = iph->saddr;
    flow->daddr = iph->daddr;
    flow->sport = th->source;
    flow->dport = th->dest;

    skb_queue_head_init(&flow->recv_queue);
    skb_queue_head_init(&flow->ooo_queue);
    skb_queue_head_init(&flow->ack_queue);
    skb_queue_head_init(&flow->retrans_queue);

    spin_lock_init(&flow->lock);

    timer_setup(&flow->ack_timer, apx_ack_timer_callback, 0);
    timer_setup(&flow->retrans_timer, apx_retrans_timer_callback, 0);

    atomic_set(&flow->ip_id_counter, 0);

    // 初始化参数（激进设置）
    flow->mss = 1460;
    flow->cwnd = g_apx_cfg.wan_init_win;  // 使用WAN初始窗口
    flow->ssthresh = 0x7FFFFFFF;
    flow->next_seq = ntohl(th->seq);
    flow->ack_seq = ntohl(th->ack_seq);
    flow->last_ack_seq = flow->ack_seq;
    flow->last_seq_recv = flow->next_seq;
    flow->last_data_seq = flow->next_seq;
    flow->peer = flow;
    flow->peer_flow = flow;
    flow->last_activity = jiffies;
    flow->remote_win = ntohs(th->window);

    // 初始化RTT和带宽
    flow->srtt = 0;
    flow->rttvar = 0;
    flow->rto = g_apx_cfg.min_rto;
    flow->bandwidth = g_apx_cfg.default_bandwidth;

    // 初始化token bucket
    flow->token_bucket = flow->mss * 10;
    flow->burst_size = flow->mss * 100;
    flow->last_tx_time = ktime_to_us(ktime_get());

    // 初始化SACK
    flow->sack_block_count = 0;

    if (! from_syn) {
        flow->state = TCP_ESTABLISHED;
        flow->flags |= FLAG_ESTABLISHED;
        if (aggressive_mode)
            flow->flags |= FLAG_TURBO_MODE;
        LOG_VERBOSE("Creating flow for ESTABLISHED connection (turbo=%d)", aggressive_mode);
    } else {
        flow->state = TCP_SYN_RECV;
        LOG_VERBOSE("Creating flow for NEW connection (SYN)");
    }

    ret = rhashtable_lookup_insert_fast(&apx_flow_table, &flow->node, apx_flow_ht_params);
    if (ret < 0) {
        if (ret == -EEXIST) {
            kfree(flow);
            flow = apx_find_flow(iph->saddr, iph->daddr, th->source, th->dest);
            LOG_DEBUG("Flow already exists in hash table");
            return flow;
        }
        LOG_ERROR("Failed to insert flow into hash table:  %d", ret);
        kfree(flow);
        return NULL;
    }

    atomic_inc(&global_stats.flows_created);

    LOG_BASIC("✅ %s FLOW:  %pI4:%u -> %pI4:%u (seq=%u, ack=%u, win=%u, mode=%s)",
              from_syn ? "NEW" : "AUTO",
              &flow->saddr, ntohs(flow->sport),
              &flow->daddr, ntohs(flow->dport),
              flow->next_seq, flow->ack_seq, flow->remote_win,
              aggressive_mode ? "TURBO" : "NORMAL");

    return flow;
}

static int apx_flow_hash_init(void)
{
    int ret = rhashtable_init(&apx_flow_table, &apx_flow_ht_params);
    if (ret == 0) {
        LOG_BASIC("Flow hash table initialized successfully");
    } else {
        LOG_ERROR("Failed to initialize flow hash table: %d", ret);
    }
    return ret;
}

static void apx_flow_destroy(void *ptr, void *arg)
{
    struct apx_tcp_flow *flow = ptr;
    struct sk_buff *skb;
    unsigned long lifetime_ms = jiffies_to_msecs(jiffies -
                                (flow->last_activity - msecs_to_jiffies(flow->packets_recv * 10)));

    LOG_BASIC("❌ DESTROY FLOW: %pI4:%u -> %pI4:%u (life=%lums, rx=%u/%uB, tx=%u/%uB, acks=%u, rtt=%u/%u/%u)",
              &flow->saddr, ntohs(flow->sport),
              &flow->daddr, ntohs(flow->dport),
              lifetime_ms,
              flow->packets_recv, flow->bytes_recv,
              flow->packets_sent, flow->bytes_sent,
              flow->acks_sent,
              flow->min_rtt, flow->srtt, flow->max_rtt);

    del_timer_sync(&flow->ack_timer);
    del_timer_sync(&flow->retrans_timer);

    while ((skb = __skb_dequeue(&flow->recv_queue)) != NULL)
        kfree_skb(skb);

    while ((skb = __skb_dequeue(&flow->ooo_queue)) != NULL)
        kfree_skb(skb);

    while ((skb = __skb_dequeue(&flow->ack_queue)) != NULL)
        kfree_skb(skb);

    while ((skb = __skb_dequeue(&flow->retrans_queue)) != NULL)
        kfree_skb(skb);

    atomic_inc(&global_stats.flows_destroyed);
    kfree(flow);
}

static void apx_flow_hash_destroy(void)
{
    LOG_BASIC("Destroying flow hash table...");
    rhashtable_free_and_destroy(&apx_flow_table, apx_flow_destroy, NULL);
}

/* =========================================================================
 * 定时器回调函数
 * ========================================================================= */

static void apx_ack_timer_callback(struct timer_list *t)
{
    struct apx_tcp_flow *flow = from_timer(flow, t, ack_timer);

    spin_lock_bh(&flow->lock);

    LOG_VERBOSE("⏰ ACK Timer fired for flow %pI4:%u -> %pI4:%u (pending=%u)",
                &flow->saddr, ntohs(flow->sport),
                &flow->daddr, ntohs(flow->dport),
                flow->pending_ack_count);

    if (flow->pending_ack_count > 0) {
        apx_tcp_send_flow_ack_packets(flow);
    }

    flow->flags &= ~FLAG_ACK_TIMER_RUNNING;

    spin_unlock_bh(&flow->lock);
}

static void apx_retrans_timer_callback(struct timer_list *t)
{
    struct apx_tcp_flow *flow = from_timer(flow, t, retrans_timer);

    spin_lock_bh(&flow->lock);

    LOG_VERBOSE("⏰ Retrans Timer fired for flow %pI4:%u -> %pI4:%u (RTO=%u us)",
                &flow->saddr, ntohs(flow->sport),
                &flow->daddr, ntohs(flow->dport),
                flow->rto);

    // 这里应该触发重传逻辑
    atomic_inc(&global_stats.retransmits);

    // 退出快速恢复，增大RTO
    flow->rto = min(flow->rto * 2, g_apx_cfg.max_rto);

    spin_unlock_bh(&flow->lock);
}

/* =========================================================================
 * 核心函数：创建和发送ACK（支持SACK）
 * ========================================================================= */

static void apx_tcp_create_and_send_ack_with_sack(struct apx_tcp_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *th;
    struct net_device *dev;
    struct rtable *rt;
    struct flowi4 fl4 = {};
    int tcp_hlen = sizeof(struct tcphdr);
    int ip_hlen = sizeof(struct iphdr);
    u16 window;
    u8 *ptr;
    int i;
    int ret;

    // 计算TCP头长度（包含SACK选项）
    if (flow->flags & FLAG_SACK_ENABLED && flow->sack_block_count > 0) {
        // NOP + NOP + SACK (2 + blocks * 8)
        tcp_hlen += 2 + 2 + flow->sack_block_count * 8;
        // 对齐到4字节
        tcp_hlen = (tcp_hlen + 3) & ~3;
    }

    dev = apx_get_output_device(flow);
    if (!dev) {
        LOG_ERROR("No output device found for ACK");
        atomic_inc(&global_stats.ack_send_errors);
        return;
    }

    fl4.daddr = flow->saddr;
    fl4.saddr = flow->daddr;
    fl4.flowi4_proto = IPPROTO_TCP;
    fl4.fl4_sport = flow->dport;
    fl4.fl4_dport = flow->sport;
    fl4.flowi4_oif = dev->ifindex;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt)) {
        LOG_ERROR("Failed to find route for ACK");
        atomic_inc(&global_stats.ack_send_errors);
        return;
    }

    skb = alloc_skb(LL_RESERVED_SPACE(dev) + ip_hlen + tcp_hlen + 32, GFP_ATOMIC);
    if (!skb) {
        LOG_ERROR("Failed to allocate SKB for ACK");
        ip_rt_put(rt);
        atomic_inc(&global_stats.ack_send_errors);
        return;
    }

    skb_reserve(skb, LL_RESERVED_SPACE(dev));

    skb_dst_set(skb, &rt->dst);
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->pkt_type = PACKET_OUTGOING;
    skb->priority = 0;

    skb_reset_network_header(skb);

    // 构建IP头
    iph = (struct iphdr *)skb_put(skb, ip_hlen);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(ip_hlen + tcp_hlen);
    iph->id = htons(atomic_inc_return(&flow->ip_id_counter));
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = flow->daddr;
    iph->daddr = flow->saddr;
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    skb_set_transport_header(skb, ip_hlen);

    // 构建TCP头
    th = (struct tcphdr *)skb_put(skb, tcp_hlen);
    memset(th, 0, tcp_hlen);
    th->source = flow->dport;
    th->dest = flow->sport;
    th->seq = htonl(flow->next_seq);
    th->ack_seq = htonl(flow->ack_seq);
    th->doff = tcp_hlen / 4;
    th->ack = 1;

    // 使用高级窗口计算
    window = apx_tcp_compute_adv_win_advanced(flow);
    th->window = htons(window);

    // 添加SACK选项
    if (flow->flags & FLAG_SACK_ENABLED && flow->sack_block_count > 0) {
        ptr = (u8 *)(th + 1);

        *ptr++ = TCPOPT_NOP;
        *ptr++ = TCPOPT_NOP;
        *ptr++ = TCPOPT_SACK;
        *ptr++ = 2 + flow->sack_block_count * 8;

        for (i = 0; i < flow->sack_block_count; i++) {
            put_unaligned_be32(flow->sack_blocks[i].start_seq, ptr);
            ptr += 4;
            put_unaligned_be32(flow->sack_blocks[i].end_seq, ptr);
            ptr += 4;
        }

        atomic_add(flow->sack_block_count, &global_stats.sack_blocks_sent);

        LOG_DEBUG("Added %d SACK blocks to ACK", flow->sack_block_count);

        // 清除SACK块
        flow->sack_block_count = 0;
        flow->flags &= ~FLAG_SACK_ENABLED;
    }

    // 计算校验和
    th->check = 0;
    th->check = tcp_v4_check(tcp_hlen, iph->saddr, iph->daddr,
                             csum_partial(th, tcp_hlen, 0));

    LOG_VERBOSE("📤 SEND ACK: seq=%u, ack=%u, win=%u -> %pI4:%u (dev=%s, sack=%d)",
                flow->next_seq, flow->ack_seq, window,
                &iph->daddr, ntohs(th->dest), dev->name,
                (flow->flags & FLAG_SACK_ENABLED) ? 1 : 0);

    flow->packets_sent++;
    flow->acks_sent++;
    flow->last_ack_seq = flow->ack_seq;
    flow->last_ack_time = jiffies;
    atomic_inc(&global_stats.acks_generated);

    ret = ip_local_out(&init_net, NULL, skb);
    if (ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN) {
        LOG_ERROR("Failed to send ACK: ret=%d", ret);
        atomic_inc(&global_stats.ack_send_errors);
    }
}

// 包装函数，保持接口兼容
static void apx_tcp_create_and_send_ack_only(struct apx_tcp_flow *flow)
{
    apx_tcp_create_and_send_ack_with_sack(flow);
}

static void apx_tcp_create_and_send_ack_only_lan(struct apx_tcp_flow *flow)
{
    LOG_VERBOSE("🚀 LAN FAST ACK triggered");
    apx_tcp_create_and_send_ack_with_sack(flow);
}

static void apx_tcp_send_duplicate_ack(struct apx_tcp_flow *flow, u32 seq)
{
    LOG_VERBOSE("⚠️ DUPLICATE ACK: seq=%u (OOO queue len=%u)",
                seq, flow->ooo_queue.qlen);
    flow->ack_seq = seq;
    apx_tcp_create_and_send_ack_with_sack(flow);
}

/* =========================================================================
 * 核心函数：发送累积的ACK包
 * ========================================================================= */

static void apx_tcp_send_flow_ack_packets(struct apx_tcp_flow *flow)
{
    u32 ack_seq;
    u16 interval;
    int sent = 0;
    int max_acks = 16;

    while (flow->ack_count > 0 && sent < max_acks) {
        if (flow->ack_count > 1) {
            interval = flow->ack_intervals[flow->ack_read_idx];
            ack_seq = flow->ack_accum + interval;

            flow->ack_read_idx = (flow->ack_read_idx + 1) % 384;
            flow->ack_count--;
            flow->ack_accum = ack_seq;
        } else {
            ack_seq = flow->ack_accum;
            flow->ack_count = 0;
        }

        flow->ack_seq = ack_seq;
        apx_tcp_create_and_send_ack_with_sack(flow);
        sent++;

        LOG_DEBUG("Sent ACK #%d: ack_seq=%u", sent, ack_seq);
    }

    flow->pending_ack_count = 0;

    LOG_VERBOSE("✅ Sent %d accumulated ACKs, remaining=%u", sent, flow->ack_count);
    atomic_add(sent, &global_stats.acks_advanced);
}

/* =========================================================================
 * 核心函数：调度提前ACK
 * ========================================================================= */

static void apx_tcp_schedule_advance_ack_wan(struct apx_tcp_flow *flow, u32 new_seq)
{
    u32 seq_delta;
    u16 interval;
    int slot_idx;

    seq_delta = new_seq - flow->last_seq_recv;

    LOG_VERBOSE("🔄 SCHEDULE ADVANCE ACK: new_seq=%u, delta=%u, count=%u",
                new_seq, seq_delta, flow->ack_count);

    skb_queue_purge(&flow->ack_queue);
    flow->ack_pending = 0;

    if (flow->ack_count == 0) {
        flow->last_seq_recv = new_seq;
        flow->ack_accum = new_seq;
        flow->ack_write_idx = 0;
        flow->ack_count = 1;
        flow->pending_ack_count = 1;
        LOG_DEBUG("ACK schedule init: accum=%u", flow->ack_accum);
    } else {
        interval = (u16)(new_seq - flow->last_seq_recv);

        if (flow->ack_count < 384) {
            slot_idx = (flow->ack_write_idx + flow->ack_count - 1) % 384;

            if (flow->ack_intervals[slot_idx] + interval < 4096) {
                flow->ack_intervals[slot_idx] += interval;
                LOG_DEBUG("ACK interval merged: slot=%d, total=%u",
                          slot_idx, flow->ack_intervals[slot_idx]);
            } else {
                flow->ack_intervals[flow->ack_count % 384] = interval;
                flow->ack_count++;
                LOG_DEBUG("ACK interval added:  slot=%d, interval=%u, total_count=%u",
                          flow->ack_count % 384, interval, flow->ack_count);
            }
        }

        flow->last_seq_recv = new_seq;
        flow->acks_advanced++;
        flow->pending_ack_count++;
        atomic_inc(&global_stats.acks_advanced);
    }

    if (!(flow->flags & FLAG_ACK_TIMER_RUNNING)) {
        mod_timer(&flow->ack_timer, jiffies + msecs_to_jiffies(g_apx_cfg.advance_ack_delay));
        flow->flags |= FLAG_ACK_TIMER_RUNNING;
        LOG_VERBOSE("⏰ ACK timer scheduled (%ums delay)", g_apx_cfg.advance_ack_delay);
    }
}

/* =========================================================================
 * 核心函数：处理新序列号包 (优化版)
 * ========================================================================= */

static void apx_tcp_process_new_seq_packet(struct apx_tcp_flow *flow, struct sk_buff *skb)
{
    struct tcphdr *th = tcp_hdr(skb);
    u32 seq = ntohl(th->seq);
    u32 data_len = get_tcp_data_len(skb, th);
    u32 end_seq = seq + data_len;
    u32 expected_seq = flow->next_seq;
    int ack_count;
    u32 rtt;

    LOG_VERBOSE("📥 NEW PACKET: seq=%u, len=%u, end=%u, expected=%u, flags=0x%02x",
                seq, data_len, end_seq, expected_seq,
                th->fin | (th->syn << 1) | (th->rst << 2) | (th->psh << 3) | (th->ack << 4));

    // 尝试从TCP选项提取RTT
    rtt = apx_tcp_extract_rtt_from_options(th);
    if (rtt > 0 && rtt < 1000000) {  // 合理范围检查
        apx_tcp_update_rto_advanced(flow, rtt);
    }

    if (data_len == 0 && ! th->syn && !th->fin) {
        LOG_DEBUG("Skipping non-data packet");
        return;
    }

    // 重复包处理
    if (before(seq, expected_seq)) {
        if (after(end_seq, expected_seq)) {
            LOG_DEBUG("Partial overlap: seq=%u < expected=%u < end=%u",
                      seq, expected_seq, end_seq);
            seq = expected_seq;
        } else {
            LOG_VERBOSE("⚠️ DUPLICATE packet: seq=%u, end=%u < expected=%u",
                        seq, end_seq, expected_seq);
            apx_tcp_create_and_send_ack_with_sack(flow);
            return;
        }
    }

    // 乱序包处理（优化版）
    if (after(seq, expected_seq)) {
        LOG_VERBOSE("🔀 OUT-OF-ORDER:  seq=%u > expected=%u (gap=%u)",
                    seq, expected_seq, seq - expected_seq);

        apx_tcp_process_ooo_optimized(flow, skb, seq, end_seq);
        return;
    }

    /* 顺序包处理 */
    flow->next_seq = end_seq;
    flow->last_data_seq = end_seq;

    flow->packets_recv++;
    flow->bytes_recv += skb->len;
    flow->data_packets++;
    atomic_inc(&global_stats.packets_accelerated);
    atomic_inc(&global_stats.data_packets);

    LOG_DEBUG("In-order packet: updated next_seq=%u", flow->next_seq);

    /* 处理乱序队列中已经可以确认的包 */
    while (!skb_queue_empty(&flow->ooo_queue)) {
        struct sk_buff *ooo_skb = skb_peek(&flow->ooo_queue);
        struct tcphdr *ooo_th = tcp_hdr(ooo_skb);
        u32 ooo_seq = ntohl(ooo_th->seq);

        if (ooo_seq == flow->next_seq) {
            u32 ooo_len = get_tcp_data_len(ooo_skb, ooo_th);
            __skb_unlink(ooo_skb, &flow->ooo_queue);
            flow->next_seq = ooo_seq + ooo_len;
            LOG_DEBUG("OOO packet reordered: seq=%u, new_next=%u", ooo_seq, flow->next_seq);
            kfree_skb(ooo_skb);
        } else {
            break;
        }
    }

    flow->ack_seq = flow->next_seq;

    // ACK触发逻辑（更激进）
    ack_count = flow->data_packets - flow->last_ack_count;

    if (flow->peer == flow) {
        // LAN模式：更激进的ACK
        if (ack_count >= g_apx_cfg.ack_threshold_lan) {
            LOG_VERBOSE("✅ LAN ACK THRESHOLD reached: %d >= %d",
                        ack_count, g_apx_cfg.ack_threshold_lan);
            apx_tcp_create_and_send_ack_only_lan(flow);
            flow->last_ack_count = flow->data_packets;
        }
    } else {
        // WAN模式：提前ACK
        if (ack_count >= g_apx_cfg.ack_threshold_wan) {
            LOG_VERBOSE("✅ WAN ACK THRESHOLD reached: %d >= %d",
                        ack_count, g_apx_cfg.ack_threshold_wan);
            apx_tcp_schedule_advance_ack_wan(flow, flow->next_seq);
            flow->last_ack_count = flow->data_packets;
        }
    }

    // FIN处理
    if (th->fin) {
        LOG_BASIC("🏁 FIN received on flow %pI4:%u -> %pI4:%u",
                  &flow->saddr, ntohs(flow->sport),
                  &flow->daddr, ntohs(flow->dport));
        flow->state = TCP_FIN_WAIT1;
        flow->next_seq++;
        flow->ack_seq = flow->next_seq;
        apx_tcp_create_and_send_ack_with_sack(flow);
    }
}

/* [保留其余未修改的函数...] */

/* =========================================================================
 * Netfilter钩子
 * ========================================================================= */

static unsigned int apx_nf_hook_rx(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct apx_tcp_flow *flow;
    u32 data_len;
    bool pure_ack;

    if (! pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    th = tcp_hdr(skb);
    data_len = get_tcp_data_len(skb, th);
    pure_ack = is_pure_ack(skb, th);

    LOG_DEBUG("RX: %pI4:%u -> %pI4:%u | SEQ=%u ACK=%u LEN=%u FLAGS=%s%s%s%s%s | %s",
              &iph->saddr, ntohs(th->source),
              &iph->daddr, ntohs(th->dest),
              ntohl(th->seq), ntohl(th->ack_seq),
              data_len,
              th->syn ? "S" : "", th->ack ? "A" : "",
              th->fin ? "F" : "", th->rst ? "R" : "", th->psh ? "P" : "",
              pure_ack ? "PURE_ACK" : (data_len > 0 ? "DATA" :  "CTRL"));

    rcu_read_lock();
    flow = apx_find_flow(iph->saddr, iph->daddr, th->source, th->dest);

    if (! flow) {
        if (th->syn && !th->ack) {
            LOG_BASIC("🔗 SYN detected, creating new flow");
            flow = apx_create_flow_ex(iph, th, true);
        } else if (auto_create && ! th->rst && !th->syn && (th->ack || data_len > 0)) {
            LOG_BASIC("🔄 Auto-creating flow for established connection");
            flow = apx_create_flow_ex(iph, th, false);
        }

        if (!flow) {
            rcu_read_unlock();
            atomic_inc(&global_stats.packets_bypassed);
            return NF_ACCEPT;
        }
    }

    if (! flow) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    spin_lock_bh(&flow->lock);
    rcu_read_unlock();

    flow->packets_recv++;
    flow->bytes_recv += skb->len;

    if (pure_ack) {
        u16 win = ntohs(th->window);
        if (win != flow->remote_win) {
            LOG_VERBOSE("📨 Remote window update: %u -> %u", flow->remote_win, win);
            flow->remote_win = win;
        }
        flow->pure_acks++;
        atomic_inc(&global_stats.pure_acks);
    } else if (data_len > 0) {
        LOG_VERBOSE("📦 DATA packet: %u bytes (total=%u packets)",
                    data_len, flow->data_packets + 1);
        apx_tcp_process_new_seq_packet(flow, skb);
    }

    if (th->fin || th->rst) {
        LOG_BASIC("🏁 Connection terminating: %s", th->fin ? "FIN" : "RST");
        flow->state = th->fin ? TCP_FIN_WAIT1 : TCP_CLOSE;
    }

    spin_unlock_bh(&flow->lock);

    return NF_ACCEPT;
}

static unsigned int apx_nf_hook_tx(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct apx_tcp_flow *flow;
    u32 data_len;
    u16 old_win, new_win;
    bool pure_ack;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr))) {
        return NF_ACCEPT;
    }

    th = tcp_hdr(skb);
    data_len = get_tcp_data_len(skb, th);
    pure_ack = is_pure_ack(skb, th);

    LOG_DEBUG("TX: %pI4:%u -> %pI4:%u | SEQ=%u ACK=%u LEN=%u FLAGS=%s%s%s%s%s | %s",
              &iph->saddr, ntohs(th->source),
              &iph->daddr, ntohs(th->dest),
              ntohl(th->seq), ntohl(th->ack_seq),
              data_len,
              th->syn ? "S" : "", th->ack ? "A" : "",
              th->fin ?  "F" : "", th->rst ? "R" : "", th->psh ? "P" : "",
              pure_ack ? "PURE_ACK" : (data_len > 0 ?  "DATA" : "CTRL"));

    flow = apx_find_flow(iph->saddr, iph->daddr, th->source, th->dest);

    if (! flow) {
        if (auto_create && !th->rst && !th->syn) {
            LOG_BASIC("🔄 Auto-creating flow for TX packet");
            flow = apx_create_flow_ex(iph, th, false);
        }

        if (!flow) {
            atomic_inc(&global_stats.packets_bypassed);
            return NF_ACCEPT;
        }
    }

    spin_lock_bh(&flow->lock);

    flow->packets_sent++;
    flow->bytes_sent += skb->len;

    if (th->ack && (flow->flags & FLAG_ESTABLISHED)) {
        old_win = ntohs(th->window);
        new_win = apx_tcp_compute_adv_win_advanced(flow);
		// 1. 修改窗口
        if (new_win > old_win) {
            th->window = htons(new_win);
            inet_proto_csum_replace2(&th->check, skb,
                                     htons(old_win), htons(new_win), false);

            flow->window_modified++;
            atomic_inc(&global_stats.window_modified);

            LOG_VERBOSE("🔧 WINDOW MODIFIED: %u -> %u (boost=%ux, rtt=%u, bw=%u)",
                        old_win, new_win, g_apx_cfg.window_boost_factor,
                        flow->srtt, flow->bandwidth);
        }

    }

    if (pure_ack) {
        flow->acks_sent++;
        atomic_inc(&global_stats.pure_acks);
    } else if (data_len > 0) {
        atomic_inc(&global_stats.data_packets);
    }

    spin_unlock_bh(&flow->lock);

    return NF_ACCEPT;
}

static struct nf_hook_ops apx_nf_ops[] = {
    {
        .hook = apx_nf_hook_rx,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = apx_nf_hook_tx,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
};

/* =========================================================================
 * proc文件系统接口（增强版）
 * ========================================================================= */

static int apx_proc_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "ACC BoostTCPCore Statistics (v4.0 Optimized)\n");
    seq_printf(m, "========================================\n");
    seq_printf(m, "Network Interface:        %s\n", net_interface);
    seq_printf(m, "Interface Status:       %s\n",
               default_netdev ?   ((default_netdev->flags & IFF_UP) ? "UP" : "DOWN") : "NOT FOUND");
    seq_printf(m, "Acceleration Mode:      %s\n", aggressive_mode ? "TURBO" : "NORMAL");
    seq_printf(m, "\nFlow Statistics:\n");
    seq_printf(m, "  Flows created:        %d\n", atomic_read(&global_stats.flows_created));
    seq_printf(m, "  Flows destroyed:      %d\n", atomic_read(&global_stats.flows_destroyed));
    seq_printf(m, "\nPacket Statistics:\n");
    seq_printf(m, "  Packets accelerated:  %d\n", atomic_read(&global_stats.packets_accelerated));
    seq_printf(m, "  Packets bypassed:     %d\n", atomic_read(&global_stats.packets_bypassed));
    seq_printf(m, "  Data packets:         %d\n", atomic_read(&global_stats.data_packets));
    seq_printf(m, "  Pure ACKs:             %d\n", atomic_read(&global_stats.pure_acks));
    seq_printf(m, "\nACK Statistics:\n");
    seq_printf(m, "  ACKs generated:       %d\n", atomic_read(&global_stats.acks_generated));
    seq_printf(m, "  ACKs advanced:        %d\n", atomic_read(&global_stats.acks_advanced));
    seq_printf(m, "  ACK send errors:      %d\n", atomic_read(&global_stats.ack_send_errors));
    seq_printf(m, "  SACK blocks sent:     %d\n", atomic_read(&global_stats.sack_blocks_sent));
    seq_printf(m, "\nWindow Statistics:\n");
    seq_printf(m, "  Window updates:       %d\n", atomic_read(&global_stats.window_updates));
    seq_printf(m, "  Window modified:      %d\n", atomic_read(&global_stats.window_modified));
    seq_printf(m, "\nOOO Statistics:\n");
    seq_printf(m, "  Total OOO packets:    %d\n", atomic_read(&global_stats.ooo_packets));
    seq_printf(m, "  Small gaps (<1 MSS):  %d\n", atomic_read(&global_stats.ooo_small_gaps));
    seq_printf(m, "  Medium gaps (1-10):   %d\n", atomic_read(&global_stats.ooo_medium_gaps));
    seq_printf(m, "  Large gaps (>10):     %d\n", atomic_read(&global_stats.ooo_large_gaps));
    seq_printf(m, "\nRTT/Performance:\n");
    seq_printf(m, "  RTT updates:          %d\n", atomic_read(&global_stats.rtt_updates));
    seq_printf(m, "  Retransmits:          %d\n", atomic_read(&global_stats.retransmits));
    seq_printf(m, "\nConfiguration:\n");
    seq_printf(m, "  Debug level:          %d\n", debug_level);
    seq_printf(m, "  Auto create:          %s\n", auto_create ? "Yes" : "No");
    seq_printf(m, "  Window boost:         %ux\n", g_apx_cfg.window_boost_factor);
    seq_printf(m, "  LAN ACK threshold:    %u\n", g_apx_cfg.ack_threshold_lan);
    seq_printf(m, "  WAN ACK threshold:    %u\n", g_apx_cfg.ack_threshold_wan);
    seq_printf(m, "  ACK delay:            %u ms\n", g_apx_cfg.advance_ack_delay);
    seq_printf(m, "  Default bandwidth:    %u Mbps\n", g_apx_cfg.default_bandwidth / 1000000);
    seq_printf(m, "  RTO range:            %u-%u ms\n",
               g_apx_cfg.min_rto / 1000, g_apx_cfg.max_rto / 1000);
    return 0;
}

static int apx_proc_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, apx_proc_stats_show, NULL);
}

static const struct proc_ops apx_proc_stats_ops = {
    .proc_open = apx_proc_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* =========================================================================
 * 统计信息显示
 * ========================================================================= */

static void apx_show_stats(void)
{
    LOG_BASIC("========== ACC Statistics ==========");
    LOG_BASIC("Mode:                  %s", aggressive_mode ? "TURBO" : "NORMAL");
    LOG_BASIC("Flows created:         %d", atomic_read(&global_stats.flows_created));
    LOG_BASIC("Flows destroyed:       %d", atomic_read(&global_stats.flows_destroyed));
    LOG_BASIC("Packets accelerated:   %d", atomic_read(&global_stats.packets_accelerated));
    LOG_BASIC("Packets bypassed:      %d", atomic_read(&global_stats.packets_bypassed));
    LOG_BASIC("Data packets:          %d", atomic_read(&global_stats.data_packets));
    LOG_BASIC("Pure ACKs:             %d", atomic_read(&global_stats.pure_acks));
    LOG_BASIC("ACKs generated:        %d", atomic_read(&global_stats.acks_generated));
    LOG_BASIC("ACKs advanced:         %d", atomic_read(&global_stats.acks_advanced));
    LOG_BASIC("SACK blocks:            %d", atomic_read(&global_stats.sack_blocks_sent));
    LOG_BASIC("Window updates:        %d", atomic_read(&global_stats.window_updates));
    LOG_BASIC("Window modified:       %d", atomic_read(&global_stats.window_modified));
    LOG_BASIC("OOO packets:           %d (S:%d/M:%d/L:%d)",
              atomic_read(&global_stats.ooo_packets),
              atomic_read(&global_stats.ooo_small_gaps),
              atomic_read(&global_stats.ooo_medium_gaps),
              atomic_read(&global_stats.ooo_large_gaps));
    LOG_BASIC("RTT updates:           %d", atomic_read(&global_stats.rtt_updates));
    LOG_BASIC("=====================================");
}

/* =========================================================================
 * 模块初始化
 * ========================================================================= */

static int __init apx_init(void)
{
    int ret;

    printk(KERN_INFO "\n");
    LOG_BASIC("================================================");
    LOG_BASIC("     ACC BoostTCPCore v4.0 Optimized");
    LOG_BASIC("     Loading with Enhanced Features...");
    LOG_BASIC("================================================");
    LOG_BASIC("Debug level:  %d", debug_level);
    LOG_BASIC("Auto-create flows: %s", auto_create ?  "YES" : "NO");
    LOG_BASIC("Acceleration mode: %s", aggressive_mode ? "TURBO" : "NORMAL");
    LOG_BASIC("Network interface: %s", net_interface);

    default_netdev = dev_get_by_name(&init_net, net_interface);
    if (default_netdev) {
        LOG_BASIC("✅ Found interface %s (index=%d, flags=0x%x)",
                  default_netdev->name, default_netdev->ifindex, default_netdev->flags);
        if (!(default_netdev->flags & IFF_UP)) {
            LOG_ERROR("⚠️ Interface %s is DOWN", net_interface);
        }
    } else {
        LOG_ERROR("❌ Interface %s not found, will use routing", net_interface);
    }

    memset(&global_stats, 0, sizeof(global_stats));

    ret = apx_flow_hash_init();
    if (ret)
        goto err_hash;

    ret = nf_register_net_hooks(&init_net, apx_nf_ops, ARRAY_SIZE(apx_nf_ops));
    if (ret) {
        LOG_ERROR("Failed to register netfilter hooks:   %d", ret);
        goto err_hooks;
    }

    apx_proc_dir = proc_mkdir("apx", NULL);
    if (apx_proc_dir) {
        apx_proc_stats = proc_create("stats", 0444, apx_proc_dir, &apx_proc_stats_ops);
    }

    LOG_BASIC("✅ Module loaded successfully");
    LOG_BASIC("Configuration:");
    LOG_BASIC("  - LAN Window:   %u-%u", g_apx_cfg.lan_init_win, g_apx_cfg.lan_max_win);
    LOG_BASIC("  - WAN Window:  %u-%u", g_apx_cfg.wan_init_win, g_apx_cfg.wan_max_win);
    LOG_BASIC("  - Window Boost: %ux", g_apx_cfg.window_boost_factor);
    LOG_BASIC("  - LAN ACK Threshold: %u packets", g_apx_cfg.ack_threshold_lan);
    LOG_BASIC("  - WAN ACK Threshold: %u packets", g_apx_cfg.ack_threshold_wan);
    LOG_BASIC("  - Advance ACK Delay: %u ms", g_apx_cfg.advance_ack_delay);
    LOG_BASIC("  - Default Bandwidth: %u Mbps", g_apx_cfg.default_bandwidth / 1000000);
    LOG_BASIC("  - RTO Range: %u-%u ms", g_apx_cfg.min_rto / 1000, g_apx_cfg.max_rto / 1000);
    LOG_BASIC("Enhanced Features:");
    LOG_BASIC("  ✓ RTT measurement and RTO calculation");
    LOG_BASIC("  ✓ BDP-based dynamic window sizing");
    LOG_BASIC("  ✓ SACK support for better recovery");
    LOG_BASIC("  ✓ Optimized OOO packet handling");
    LOG_BASIC("  ✓ Aggressive acceleration mode");
    LOG_BASIC("================================================\n");

    return 0;

err_hooks:
    apx_flow_hash_destroy();
err_hash:
    if (default_netdev)
        dev_put(default_netdev);
    return ret;
}

static void __exit apx_exit(void)
{
    LOG_BASIC("================================================");
    LOG_BASIC("     ACC BoostTCPCore Unloading...");
    LOG_BASIC("================================================");

    apx_show_stats();

    if (apx_proc_stats)
        proc_remove(apx_proc_stats);
    if (apx_proc_dir)
        proc_remove(apx_proc_dir);

    nf_unregister_net_hooks(&init_net, apx_nf_ops, ARRAY_SIZE(apx_nf_ops));
    apx_flow_hash_destroy();

    if (default_netdev)
        dev_put(default_netdev);

    LOG_BASIC("✅ Module unloaded successfully");
    LOG_BASIC("================================================\n");
}

module_init(apx_init);
module_exit(apx_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ACC Team");
MODULE_DESCRIPTION("BoostTCPTCP Acceleration Core v4.0 - Optimized with RTT/SACK/BDP");
MODULE_VERSION("4.0");
