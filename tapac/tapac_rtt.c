/*
 * tapac_rtt.c - RTT 测量模块（增强版）
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tapac.h"

/* ============ 查找 TCP Timestamp 选项 ============ */
static u8 *tapac_find_ts_option(struct tcphdr *th, u32 tcp_hdr_len)
{
    u8 *opt, *end;
    u8 kind, len;

    if (tcp_hdr_len < 32)
        return NULL;

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

        if (kind == 8 && len == 10)
            return opt;

        opt += len;
    }

    return NULL;
}

/* ============ 记录发送的 TSval ============ */
void tapac_record_tsval(struct tapac_flow_info *info, u32 tsval)
{
    if (! info)
        return;

    info->rtt.last_tsval = tsval;
    info->rtt.last_tsval_time = tapac_get_time_us();
}

/* ============ 更新 RTT 统计 ============ */
void tapac_update_rtt_stats(struct tapac_flow_info *info, u32 rtt)
{
    u32 idx;
    u32 sum = 0;
    u32 i, count;
    s32 diff;

    if (!info || rtt == 0 || rtt > 10000000)
        return;

    /* 更新历史 */
    idx = info->rtt.history_idx;
    info->rtt.history[idx] = rtt;
    info->rtt.history_idx = (idx + 1) % RTT_HISTORY_SIZE;

    if (info->rtt.history_count < RTT_HISTORY_SIZE)
        info->rtt.history_count++;

    /* 更新 min/max */
    if (rtt < info->rtt.min_rtt || info->rtt.min_rtt == 0)
        info->rtt.min_rtt = rtt;
    if (rtt > info->rtt.max_rtt)
        info->rtt.max_rtt = rtt;

    /* 计算平均和方差 */
    count = info->rtt.history_count;
    for (i = 0; i < count; i++)
        sum += info->rtt.history[i];

    if (count > 0) {
        u32 avg = sum / count;
        u32 var_sum = 0;

        for (i = 0; i < count; i++) {
            diff = (s32)info->rtt.history[i] - (s32)avg;
            var_sum += diff * diff;
        }
        info->rtt.var_rtt = var_sum / count;
    }
}

/* ============ 增强的 RTT 测量 ============ */
u32 tapac_measure_rtt_v2(struct sk_buff *skb, struct tapac_flow *flow,
                         struct tapac_engine *eng)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 tsval, tsecr;
    u32 rtt = 0;
    u32 tcp_hdr_len;
    struct tapac_flow_info *info;

    if (!skb || !flow || !eng)
        return 0;

    info = &flow->info;
    iph = ip_hdr(skb);

    if (! iph || iph->protocol != IPPROTO_TCP)
        return 0;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;

    ts_opt = tapac_find_ts_option(th, tcp_hdr_len);
    if (! ts_opt) {
        info->ts_enabled = 0;
        return 0;
    }

    info->ts_enabled = 1;
    info->flags |= FLOW_FLAG_TS_ENABLED;

    /* TSval 在 offset +2, TSecr 在 offset +6 */
    tsval = ntohl(*(u32 *)(ts_opt + 2));
    tsecr = ntohl(*(u32 *)(ts_opt + 6));

    /*
     * RTT 计算方法：
     * 1.如果 TSecr 匹配我们发送的 TSval，直接计算
     * 2.否则使用发送时间和当前时间的差值
     */
    if (tsecr != 0 && info->rtt.last_tsval != 0) {
        if (tsecr == info->rtt.last_tsval) {
            /* 精确匹配 */
            rtt = tapac_get_time_us() - info->rtt.last_tsval_time;
        } else {
            /* 使用 TSecr 作为发送时间（如果是我们的格式） */
            u32 now = tapac_get_time_us();
            if (tsecr < now && (now - tsecr) < 10000000) {
                rtt = now - tsecr;
            }
        }
    }

    if (rtt > 0 && rtt < 10000000) {
        /* 更新 per-flow RTT */
        tapac_update_rtt_stats(info, rtt);

        /* EWMA 更新 srtt */
        if (info->srtt == 0 || info->srtt == eng->params.min_rtt) {
            info->srtt = rtt;
        } else {
            info->srtt = (info->srtt * eng->params.rtt_smooth +
                         rtt * (1000 - eng->params.rtt_smooth)) / 1000;
        }

        eng->stats.rtt_samples++;
    }

    return rtt;
}

/* ============ 修改 TSval（出站包） ============ */
void tapac_stamp_tsval(struct sk_buff *skb, u32 tsval)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 *ts_val_ptr;
    u32 tcp_hdr_len;

    if (!skb)
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;

    ts_opt = tapac_find_ts_option(th, tcp_hdr_len);
    if (!ts_opt)
        return;

    ts_val_ptr = (u32 *)(ts_opt + 2);
    *ts_val_ptr = htonl(tsval);
}

/* ============ 获取 TSecr（入站包） ============ */
u32 tapac_get_tsecr(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 tcp_hdr_len;

    if (!skb)
        return 0;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return 0;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;

    ts_opt = tapac_find_ts_option(th, tcp_hdr_len);
    if (! ts_opt)
        return 0;

    return ntohl(*(u32 *)(ts_opt + 6));
}