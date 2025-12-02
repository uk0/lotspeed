/*
 * tapac_main.c - v2.7
 * 修复：令牌释放逻辑，确保令牌能正确下降
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <net/net_namespace.h>
#include <net/checksum.h>

#include "tapac.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TAPAC Project");
MODULE_VERSION("2.7");
MODULE_DESCRIPTION("TCP Acceleration + PAC v2.7 - Fixed token release");

static char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Network interface");
module_param(param_dev, charp, 0);

static struct tapac_engine *g_engine = NULL;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;
static struct tasklet_struct dequeue_tasklet;

static u32 cleanup_counter = 0;
#define CLEANUP_INTERVAL 20000
#define FLOW_TIMEOUT_US 60000000

/* 外部函数声明 */
extern void tapac_flow_table_init(struct tapac_flow_table *ft);
extern void tapac_flow_table_cleanup(struct tapac_flow_table *ft);
extern struct tapac_flow *tapac_flow_lookup(struct tapac_flow_table *ft,
                                            __be32 saddr, __be32 daddr,
                                            __be16 sport, __be16 dport);
extern struct tapac_flow *tapac_flow_create(struct tapac_flow_table *ft,
                                            __be32 saddr, __be32 daddr,
                                            __be16 sport, __be16 dport,
                                            u8 direction, u32 min_rtt);
extern void tapac_flow_delete(struct tapac_flow_table *ft,
                              __be32 saddr, __be32 daddr,
                              __be16 sport, __be16 dport);
extern int tapac_flow_cleanup_timeout(struct tapac_flow_table *ft, u32 timeout_us);

extern struct tapac_pkt_queue *tapac_queue_alloc(u32 capacity);
extern void tapac_queue_free(struct tapac_pkt_queue *q);
extern int tapac_queue_enqueue(struct tapac_pkt_queue *q, struct sk_buff *skb,
                               tapac_okfn_t okfn, u32 trigger, u32 enqueue_time);
extern int tapac_queue_dequeue(struct tapac_pkt_queue *q);
extern struct tapac_pkt_node *tapac_queue_peek(struct tapac_pkt_queue *q);
extern u32 tapac_queue_size(struct tapac_pkt_queue *q);

extern void tapac_fix_checksums_kernel(struct sk_buff *skb);
extern u32 tapac_measure_rtt_v2(struct sk_buff *skb, struct tapac_flow *flow,
                                struct tapac_engine *eng);
extern void tapac_stamp_tsval(struct sk_buff *skb, u32 tsval);
extern void tapac_record_tsval(struct tapac_flow_info *info, u32 tsval);

extern int tapac_proc_init(struct tapac_engine *eng);
extern void tapac_proc_cleanup(void);

extern void tapac_parse_win_scale(struct tcphdr *th, u32 tcp_hdr_len,
                                  struct tapac_win_info *win);
extern void tapac_modify_ack_window(struct sk_buff *skb, struct tapac_engine *eng,
                                    struct tapac_flow *flow);
extern int tapac_process_upload_data(struct tapac_engine *eng, struct sk_buff *skb,
                                     struct tapac_flow *flow);
extern int tapac_process_upload_ack(struct tapac_engine *eng, struct sk_buff *skb,
                                    struct tapac_flow *flow);

extern void tapac_update_sack_blocks(struct tapac_flow_info *info, u32 seq, u32 len);

/* 解析 TSval 和 TSecr */
static void tapac_parse_tcp_ts(struct tcphdr *th, u32 tcp_hdr_len, u32 *tsval, u32 *tsecr)
{
    u8 *opt, *end;
    u8 kind, len;

    *tsval = 0;
    *tsecr = 0;

    if (tcp_hdr_len <= 20)
        return;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)
            break;

        if (kind == 1) {
            opt++;
            continue;
        }

        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 8 && len == 10) {
            *tsval = ntohl(*(u32 *)(opt + 2));
            *tsecr = ntohl(*(u32 *)(opt + 6));
            return;
        }

        opt += len;
    }
}

static void tapac_params_default(struct tapac_params *p)
{
    p->debug = 0;
    strncpy(p->nic, "eth0", sizeof(p->nic) - 1);
    p->nic[sizeof(p->nic) - 1] = '\0';
    p->mss = 1460;
    p->min_win = 10;
    p->timer_interval_us = 1000;    /* 1ms 定时器 */
    p->min_rtt = 20000;
    p->max_rtt = 500000;
    p->max_delay = 50000;
    p->bucket_size = 32 * 1024 * 1024;
    p->min_pkt_len = 74;
    p->throughput_smooth = 800;
    p->rtt_smooth = 875;
    p->alpha = 600;
    p->reduction_thresh = 3;
    p->prio_thresh = 1ULL * 1024 * 1024;
    p->ss_thresh = 2ULL * 1024 * 1024;
    p->ack_delay_ms = 5;
    p->win_inflate_factor = 16;
    p->ack_every_n_packets = 2;
    p->upload_accel_thresh = 10 * 1024;
    p->use_ack_scheduler = 0;
    p->generate_sack = 1;
    p->separate_buckets = 1;
    p->upload_bucket_size = 16 * 1024 * 1024;
}

static inline u32 tapac_cumulative_ack(u32 ack1, u32 ack2)
{
    if (ack1 >= ack2)
        return ack1 - ack2;
    else
        return 0xFFFFFFFF - (ack2 - ack1);
}

/* ============ 下载令牌桶操作 ============ */
static bool tapac_dl_token_get(struct tapac_engine *eng, u32 amount)
{
    unsigned long flags;
    bool result = false;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    if (eng->params.bucket_size >= eng->dl_tokens &&
        eng->params.bucket_size - eng->dl_tokens >= amount) {
        eng->dl_tokens += amount;
        result = true;
    }

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
    return result;
}

static void tapac_dl_token_release(struct tapac_engine *eng, u32 amount)
{
    unsigned long flags;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    if (eng->dl_tokens >= amount)
        eng->dl_tokens -= amount;
    else
        eng->dl_tokens = 0;

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
}

/* 周期性令牌衰减 - 确保令牌不会一直满 */
static void tapac_dl_token_decay(struct tapac_engine *eng)
{
    unsigned long flags;
    u64 decay;

    spin_lock_irqsave(&eng->dl_token_lock, flags);

    /* 每次定时器回调，衰减令牌桶的 1%，最少 10KB */
    decay = eng->dl_tokens / 100;
    if (decay < 10 * 1024)
        decay = 10 * 1024;

    if (eng->dl_tokens >= decay)
        eng->dl_tokens -= decay;
    else
        eng->dl_tokens = 0;

    spin_unlock_irqrestore(&eng->dl_token_lock, flags);
}

/* ============ 上传令牌桶操作 ============ */
static void tapac_ul_token_release(struct tapac_engine *eng, u32 amount)
{
    unsigned long flags;

    if (! eng->params.separate_buckets)
        return;

    spin_lock_irqsave(&eng->ul_token_lock, flags);

    if (eng->ul_tokens >= amount)
        eng->ul_tokens -= amount;
    else
        eng->ul_tokens = 0;

    spin_unlock_irqrestore(&eng->ul_token_lock, flags);
}

/* Tasklet - 出队发送 */
static void tapac_dequeue_tasklet(unsigned long data)
{
    struct tapac_engine *eng = (struct tapac_engine *)data;
    struct tapac_pkt_node *pkt;
    u32 now;
    u32 len;
    int sent = 0;

    if (!eng || !eng->running)
        return;

    now = tapac_get_time_us();

    while (sent < 64) {
        if (tapac_queue_size(eng->q_high) == 0)
            break;

        pkt = tapac_queue_peek(eng->q_high);
        if (! pkt)
            break;

        len = pkt->trigger;

        if (tapac_dl_token_get(eng, len)) {
            tapac_queue_dequeue(eng->q_high);
            sent++;
        } else if (now - pkt->enqueue_time >= eng->params.max_delay) {
            tapac_queue_dequeue(eng->q_high);
            sent++;
        } else {
            break;
        }
    }

    if (tapac_queue_size(eng->q_high) == 0) {
        while (sent < 64) {
            if (tapac_queue_size(eng->q_low) == 0)
                break;

            pkt = tapac_queue_peek(eng->q_low);
            if (!pkt)
                break;

            len = pkt->trigger;

            if (tapac_dl_token_get(eng, len)) {
                tapac_queue_dequeue(eng->q_low);
                sent++;
            } else if (now - pkt->enqueue_time >= eng->params.max_delay) {
                tapac_queue_dequeue(eng->q_low);
                sent++;
            } else {
                break;
            }
        }
    }

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);
}

/* RX Hook */
#if defined(TAPAC_NF_NEW_HOOK_API)
static unsigned int tapac_hook_in(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    const struct net_device *in = state->in;
#else
static unsigned int tapac_hook_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
#endif
    struct tapac_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow *flow;
    struct tapac_flow_info *info;
    struct tapac_sack_info sack = {0};
    u32 rtt;
    u32 payload_len;
    u32 time_delta;
    u32 throughput;
    u32 now;
    u32 seq;
    u32 tsval, tsecr;
    unsigned long flags;

    if (!eng || !eng->running)
        return NF_ACCEPT;

    if (! in)
        return NF_ACCEPT;

    if (strcmp(in->name, eng->params.nic) != 0)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (! iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;
    seq = ntohl(th->seq);

    eng->stats.pkts_rx++;
    eng->stats.bytes_rx += skb->len;

    now = tapac_get_time_us();

    spin_lock_irqsave(&eng->ft.lock, flags);
    flow = tapac_flow_lookup(&eng->ft, iph->daddr, iph->saddr,
                             th->dest, th->source);
    spin_unlock_irqrestore(&eng->ft.lock, flags);

    if (!flow)
        return NF_ACCEPT;

    info = &flow->info;

    if (info->direction == FLOW_DIR_CLIENT)
        return NF_ACCEPT;

    tapac_parse_tcp_ts(th, th->doff * 4, &tsval, &tsecr);
    if (tsval != 0)
        info->peer_tsval = tsval;

    if (th->fin || th->rst) {
        tapac_ack_flush_flow(eng, flow);
        tapac_flow_delete(&eng->ft, iph->daddr, iph->saddr,
                          th->dest, th->source);
        eng->stats.flows_destroyed++;
        return NF_ACCEPT;
    }

    if (tapac_parse_sack(th, th->doff * 4, &sack) > 0) {
        eng->stats.sack_parsed++;
    }

    /*
     * 令牌释放逻辑 - 修复版
     * 使用 flags 标记是否已初始化，避免序号回绕问题
     */
    if (th->ack) {
        u32 ack_seq = ntohl(th->ack_seq);
        tapac_detect_loss(eng, info, ack_seq, &sack);

        /* 检查是否已初始化 */
        if (!(info->flags & FLOW_FLAG_WIN_SCALED)) {
            /* 首次收到 ACK，初始化跟踪变量 */
            info->dl_bucket.last_update = ack_seq;
            info->flags |= FLOW_FLAG_WIN_SCALED;  /* 复用这个 flag */
        } else {
            /* 后续 ACK，计算进展并释放令牌 */
            if (tapac_seq_gt(ack_seq, info->dl_bucket.last_update)) {
                u32 ack_advance = ack_seq - info->dl_bucket.last_update;
                
                /* 限制单次释放量，避免异常 */
                if (ack_advance > 10 * 1024 * 1024) {
                    ack_advance = 10 * 1024 * 1024;
                }
                
                u32 release = ack_advance * (eng->params.mss + 54) / eng->params.mss;
                tapac_dl_token_release(eng, release);
                info->dl_bucket.last_update = ack_seq;
            }
        }
    }

    tapac_check_fast_path(eng, info);
    if (info->flags & FLOW_FLAG_FAST_PATH)
        eng->stats.fast_path_hits++;

    if (payload_len > 0) {
        tapac_process_upload_data(eng, skb, flow);

        if (eng->params.generate_sack) {
            tapac_update_sack_blocks(info, seq, payload_len);
        }

        if (info->rcv_nxt != 0 && seq != info->rcv_nxt) {
            eng->stats.ooo_packets++;
        }
    }

    rtt = tapac_measure_rtt_v2(skb, flow, eng);
    if (rtt > 0 && rtt < 10000000) {
        spin_lock_irqsave(&eng->global_lock, flags);
        eng->total_rtt += rtt;
        eng->samples++;
        spin_unlock_irqrestore(&eng->global_lock, flags);
    }

    info->bytes_sent_latest += payload_len;

    if (info->bytes_sent_total <= 4294900000UL) {
        info->bytes_sent_total += payload_len;
        if (info->bytes_sent_total > eng->params.ss_thresh &&
            info->phase == PHASE_SLOW_START) {
            info->phase = PHASE_CONG_AVOID;
        }
    }

    if (payload_len > 0) {
        u32 seq_end = seq + payload_len - 1;
        if (tapac_seq_gt(seq_end, info->last_data_seq))
            info->last_data_seq = seq_end;
    }

    time_delta = now - info->last_update;
    if (time_delta > info->srtt && info->srtt > 0) {
        if (time_delta > 0)
            throughput = info->bytes_sent_latest * 8 / time_delta;
        else
            throughput = 0;

        info->bytes_sent_latest = 0;
        info->last_update = now;

        if (throughput <= info->last_throughput * eng->params.alpha / 1000) {
            info->throughput_reduction_num++;
            if (info->throughput_reduction_num >= eng->params.reduction_thresh &&
                info->phase == PHASE_SLOW_START) {
                info->phase = PHASE_CONG_AVOID;
            }
        } else {
            info->throughput_reduction_num = 0;
        }
        info->last_throughput = throughput;
    }

    spin_lock_irqsave(&eng->global_lock, flags);
    eng->traffic += skb->len;
    if (iph->tos == 0x03)
        eng->ecn_traffic += skb->len;
    spin_unlock_irqrestore(&eng->global_lock, flags);

    if (payload_len > 0) {
        tapac_ul_token_release(eng, payload_len);
    }

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);

    return NF_ACCEPT;
}

/* TX Hook */
#if defined(TAPAC_NF_NEW_HOOK_API)
static unsigned int tapac_hook_out(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    const struct net_device *out = state->out;
    tapac_okfn_t okfn = state->okfn;
#else
static unsigned int tapac_hook_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
#endif
    struct tapac_engine *eng = g_engine;
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow *flow = NULL;
    struct tapac_flow_info *info = NULL;
    struct tapac_sack_info sack = {0};
    u32 payload_len;
    u32 ack;
    u32 trigger = 0;
    u32 ack_delta = 0;
    u32 tsval;
    u8 prio = PRIO_HIGH;
    unsigned long flags;
    int result;

    if (!eng || !eng->running)
        return NF_ACCEPT;

    if (!out)
        return NF_ACCEPT;

    if (strcmp(out->name, eng->params.nic) != 0)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    if (skb_linearize(skb) != 0)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

    eng->stats.pkts_tx++;
    eng->stats.bytes_tx += skb->len;

    spin_lock_irqsave(&eng->global_lock, flags);
    eng->traffic += skb->len;
    spin_unlock_irqrestore(&eng->global_lock, flags);

    tsval = tapac_get_time_us();

    /* SYN 处理 */
    if (th->syn) {
        if (! th->ack) {
            flow = tapac_flow_create(&eng->ft, iph->saddr, iph->daddr,
                                     th->source, th->dest,
                                     FLOW_DIR_CLIENT, eng->params.min_rtt);
            if (flow) {
                flow->info.last_data_seq = ntohl(th->seq);
                flow->info.my_seq = ntohl(th->seq);
                flow->info.last_update = tapac_get_time_us();
                eng->stats.flows_created++;
            }
            return NF_ACCEPT;
        } else {
            flow = tapac_flow_create(&eng->ft, iph->saddr, iph->daddr,
                                     th->source, th->dest,
                                     FLOW_DIR_SERVER, eng->params.min_rtt);
            if (flow) {
                flow->info.last_ack_seq = ntohl(th->ack_seq);
                flow->info.my_seq = ntohl(th->seq);
                flow->info.last_update = tapac_get_time_us();
                tapac_parse_win_scale(th, th->doff * 4, &flow->info.win);
                eng->stats.flows_created++;
            }
            trigger = eng->params.min_pkt_len;
            prio = PRIO_HIGH;
            info = flow ?  &flow->info : NULL;
        }
    } else if (th->ack) {
        spin_lock_irqsave(&eng->ft.lock, flags);
        flow = tapac_flow_lookup(&eng->ft, iph->saddr, iph->daddr,
                                 th->source, th->dest);
        spin_unlock_irqrestore(&eng->ft.lock, flags);

        if (! flow || flow->info.direction == FLOW_DIR_CLIENT)
            return NF_ACCEPT;

        info = &flow->info;
        ack = ntohl(th->ack_seq);

        info->my_seq = ntohl(th->seq);

        /* 上传加速：修改 ACK 窗口 */
        if (payload_len == 0) {
            if (info->upload.bytes_received > eng->params.upload_accel_thresh) {
                info->flags |= FLOW_FLAG_UPLOAD_ACCEL;
            }

            if (info->flags & FLOW_FLAG_UPLOAD_ACCEL) {
                tapac_modify_ack_window(skb, eng, flow);
                tapac_process_upload_ack(eng, skb, flow);
            }

            if (tapac_seq_gt(ack, info->last_ack_seq)) {
                eng->stats.ack_created++;
            } else {
                eng->stats.ack_merged++;
            }
        }

        /* 快速路径 */
        if ((info->flags & FLOW_FLAG_FAST_PATH) && payload_len == 0) {
            tapac_stamp_tsval(skb, tsval);
            tapac_record_tsval(info, tsval);
            tapac_fix_checksums_kernel(skb);
            return NF_ACCEPT;
        }

        if (info->bytes_sent_total < eng->params.prio_thresh)
            prio = PRIO_HIGH;
        else
            prio = PRIO_LOW;

        if (info->last_ack_seq == 0) {
            info->last_ack_seq = ack;
            if (payload_len > 0)
                trigger = eng->params.min_win * (eng->params.mss + 54);
            else
                trigger = eng->params.min_pkt_len;
        } else {
            if (th->ece)
                info->phase = PHASE_CONG_AVOID;

            if (tapac_seq_gt(ack, info->last_ack_seq)) {
                ack_delta = tapac_cumulative_ack(ack, info->last_ack_seq);
                info->last_ack_seq = ack;
            }

            trigger = tapac_calc_optimized_trigger(eng, info, ack_delta,
                                                   payload_len, &sack);
        }
    } else {
        spin_lock_irqsave(&eng->ft.lock, flags);
        flow = tapac_flow_lookup(&eng->ft, iph->saddr, iph->daddr,
                                 th->source, th->dest);
        spin_unlock_irqrestore(&eng->ft.lock, flags);

        if (!flow || flow->info.direction == FLOW_DIR_CLIENT)
            return NF_ACCEPT;

        info = &flow->info;
        prio = PRIO_HIGH;
        trigger = eng->params.min_pkt_len;
    }

    /* FIN/RST */
    if (th->fin || th->rst) {
        if (flow) {
            tapac_ack_flush_flow(eng, flow);
            tapac_flow_delete(&eng->ft, iph->saddr, iph->daddr,
                              th->source, th->dest);
            eng->stats.flows_destroyed++;
        }
        tapac_stamp_tsval(skb, tsval);
        if (info)
            tapac_record_tsval(info, tsval);
        tapac_fix_checksums_kernel(skb);
        return NF_ACCEPT;
    }

    if (trigger >= eng->params.bucket_size) {
        tapac_stamp_tsval(skb, tsval);
        if (info)
            tapac_record_tsval(info, tsval);
        tapac_fix_checksums_kernel(skb);
        return NF_ACCEPT;
    }

    tapac_stamp_tsval(skb, tsval);
    if (info)
        tapac_record_tsval(info, tsval);
    tapac_fix_checksums_kernel(skb);

    /* 令牌检查 */
    if (tapac_dl_token_get(eng, trigger)) {
        if ((prio == PRIO_HIGH && tapac_queue_size(eng->q_high) == 0) ||
            (prio == PRIO_LOW && tapac_queue_size(eng->q_high) == 0 &&
             tapac_queue_size(eng->q_low) == 0)) {
            return NF_ACCEPT;
        }
        tapac_dl_token_release(eng, trigger);
    }

    /* 入队 */
    if (prio == PRIO_HIGH)
        result = tapac_queue_enqueue(eng->q_high, skb, okfn, trigger,
                                     tapac_get_time_us());
    else
        result = tapac_queue_enqueue(eng->q_low, skb, okfn, trigger,
                                     tapac_get_time_us());

    if (result == 1) {
        eng->stats.pkts_queued++;
        tasklet_schedule(&dequeue_tasklet);
        return NF_STOLEN;
    }

    eng->stats.pkts_dropped++;
    return NF_DROP;
}

/* 定时器回调 */
static enum hrtimer_restart tapac_timer_callback(struct hrtimer *timer)
{
    struct tapac_engine *eng = container_of(timer, struct tapac_engine, timer);
    ktime_t interval;
    unsigned long flags;
    u32 time_delta;
    u32 current_time;
    u64 throughput;
    int cleaned;
    static u32 decay_counter = 0;

    if (!eng || !eng->running)
        return HRTIMER_NORESTART;

    current_time = tapac_get_time_us();

    spin_lock_irqsave(&eng->global_lock, flags);

    time_delta = current_time - eng->last_global_update;

    /* 每 100ms 更新一次统计 */
    if (time_delta >= 100000) {
        eng->last_global_update = current_time;

        if (time_delta > 0) {
            throughput = (eng->traffic * 8000ULL) / time_delta;
        } else {
            throughput = 0;
        }

        if (eng->avg_throughput == 0) {
            eng->avg_throughput = (u32)throughput;
        } else {
            eng->avg_throughput = (eng->avg_throughput * 7 + (u32)throughput) / 8;
        }

        if (eng->samples > 0) {
            eng->avg_rtt = eng->total_rtt / eng->samples;
            if (eng->avg_rtt < eng->params.min_rtt)
                eng->avg_rtt = eng->params.min_rtt;
            if (eng->avg_rtt > eng->params.max_rtt)
                eng->avg_rtt = eng->params.max_rtt;
        }

        eng->traffic = 0;
        eng->ecn_traffic = 0;
        eng->total_rtt = 0;
        eng->samples = 0;
    }

    spin_unlock_irqrestore(&eng->global_lock, flags);

    /* 每 10ms 进行一次令牌衰减 */
    decay_counter++;
    if (decay_counter >= 10) {
        tapac_dl_token_decay(eng);
        decay_counter = 0;
    }

    tapac_dynamic_tuning(eng);
    tapac_ack_schedule(eng);

    if (tapac_queue_size(eng->q_high) > 0 || tapac_queue_size(eng->q_low) > 0)
        tasklet_schedule(&dequeue_tasklet);

    cleanup_counter++;
    if (cleanup_counter >= CLEANUP_INTERVAL) {
        cleaned = tapac_flow_cleanup_timeout(&eng->ft, FLOW_TIMEOUT_US);
        if (cleaned > 0)
            eng->stats.flows_destroyed += cleaned;
        cleanup_counter = 0;
    }

    interval = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_forward_now(timer, interval);

    return HRTIMER_RESTART;
}

static int tapac_engine_init(struct tapac_engine *eng)
{
    int i;
    ktime_t ktime;

    tapac_params_default(&eng->params);

    if (param_dev && strlen(param_dev) > 0) {
        strncpy(eng->params.nic, param_dev, sizeof(eng->params.nic) - 1);
        eng->params.nic[sizeof(eng->params.nic) - 1] = '\0';
    }

    for (i = 0; i < sizeof(eng->params.nic) && eng->params.nic[i]; i++) {
        if (eng->params.nic[i] == '\n') {
            eng->params.nic[i] = '\0';
            break;
        }
    }

    tapac_flow_table_init(&eng->ft);
    tapac_ack_init(eng);

    eng->dl_tokens = 0;
    spin_lock_init(&eng->dl_token_lock);
    eng->ul_tokens = 0;
    spin_lock_init(&eng->ul_token_lock);
    eng->tokens = 0;
    spin_lock_init(&eng->token_lock);

    eng->q_high = tapac_queue_alloc(PKT_QUEUE_SIZE);
    if (!eng->q_high) {
        TAPAC_ERR("Failed to allocate high priority queue\n");
        return -ENOMEM;
    }

    eng->q_low = tapac_queue_alloc(PKT_QUEUE_SIZE);
    if (!eng->q_low) {
        TAPAC_ERR("Failed to allocate low priority queue\n");
        tapac_queue_free(eng->q_high);
        return -ENOMEM;
    }

    eng->traffic = 0;
    eng->ecn_traffic = 0;
    eng->total_rtt = 0;
    eng->samples = 0;
    eng->avg_rtt = eng->params.min_rtt;
    eng->avg_throughput = 0;
    eng->last_global_update = tapac_get_time_us();
    spin_lock_init(&eng->global_lock);

    memset(&eng->stats, 0, sizeof(eng->stats));

    tasklet_init(&dequeue_tasklet, tapac_dequeue_tasklet, (unsigned long)eng);

    ktime = ktime_set(0, US_TO_NS(eng->params.timer_interval_us));
    hrtimer_init(&eng->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    eng->timer.function = tapac_timer_callback;

    eng->running = true;
    hrtimer_start(&eng->timer, ktime, HRTIMER_MODE_REL);

    return 0;
}

static void tapac_engine_cleanup(struct tapac_engine *eng)
{
    if (! eng)
        return;

    eng->running = false;
    hrtimer_cancel(&eng->timer);
    tasklet_kill(&dequeue_tasklet);
    tapac_ack_cleanup(eng);
    tapac_flow_table_cleanup(&eng->ft);

    if (eng->q_high) {
        tapac_queue_free(eng->q_high);
        eng->q_high = NULL;
    }
    if (eng->q_low) {
        tapac_queue_free(eng->q_low);
        eng->q_low = NULL;
    }
}

static int __init tapac_init(void)
{
    int ret;

    TAPAC_INFO("Loading module v2.7 - Token decay\n");

    g_engine = kzalloc(sizeof(struct tapac_engine), GFP_KERNEL);
    if (!g_engine) {
        TAPAC_ERR("Failed to allocate engine\n");
        return -ENOMEM;
    }

    ret = tapac_engine_init(g_engine);
    if (ret) {
        kfree(g_engine);
        return ret;
    }

    tapac_proc_init(g_engine);

    nfho_in.hook = tapac_hook_in;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;

    nfho_out.hook = tapac_hook_out;
    nfho_out.hooknum = NF_INET_POST_ROUTING;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

#if defined(TAPAC_NF_NEW_HOOK_API)
    ret = nf_register_net_hook(&init_net, &nfho_in);
    if (ret)
        goto err_hook_in;
    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret)
        goto err_hook_out;
#else
    ret = nf_register_hook(&nfho_in);
    if (ret)
        goto err_hook_in;
    ret = nf_register_hook(&nfho_out);
    if (ret)
        goto err_hook_out;
#endif

    TAPAC_INFO("Module loaded, interface: %s\n", g_engine->params.nic);
    TAPAC_INFO("Bucket size: %u MB, Token decay enabled\n", 
               g_engine->params.bucket_size / (1024 * 1024));
    return 0;

err_hook_out:
#if defined(TAPAC_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_in);
#endif
err_hook_in:
    tapac_proc_cleanup();
    tapac_engine_cleanup(g_engine);
    kfree(g_engine);
    g_engine = NULL;
    return ret;
}

static void __exit tapac_exit(void)
{
    TAPAC_INFO("Unloading module\n");

#if defined(TAPAC_NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);
#else
    nf_unregister_hook(&nfho_out);
    nf_unregister_hook(&nfho_in);
#endif

    tapac_proc_cleanup();

    if (g_engine) {
        tapac_engine_cleanup(g_engine);
        kfree(g_engine);
        g_engine = NULL;
    }

    TAPAC_INFO("Module unloaded\n");
}

module_init(tapac_init);
module_exit(tapac_exit);