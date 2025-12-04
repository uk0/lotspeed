/*
 * zeta_rtt.c - Zeta-TCP RTT 测量与反向控制
 */

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/checksum.h>

#include "zeta_tcp.h"

/*
 * 查找 TCP 时间戳选项
 */
static u8 *zeta_find_ts_option(struct tcphdr *th, u32 tcp_hdr_len)
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

/*
 * 更新 RTT 统计
 */
void zeta_update_rtt(struct zeta_rtt_info *rtt, u32 sample_rtt)
{
    s32 delta;

    if (sample_rtt == 0 || sample_rtt > ZETA_RTT_MAX_US)
        return;

    /* 记录到历史 */
    rtt->history[rtt->history_idx] = sample_rtt;
    rtt->history_idx = (rtt->history_idx + 1) % ZETA_RTT_HISTORY_SIZE;
    if (rtt->history_count < ZETA_RTT_HISTORY_SIZE)
        rtt->history_count++;

    rtt->latest_rtt = sample_rtt;

    /* 更新 min/max */
    if (sample_rtt < rtt->min_rtt || rtt->min_rtt == 0)
        rtt->min_rtt = sample_rtt;
    if (sample_rtt > rtt->max_rtt)
        rtt->max_rtt = sample_rtt;

    /* 更新 SRTT 和 RTTVAR (RFC 6298) */
    if (rtt->srtt == 0) {
        rtt->srtt = sample_rtt;
        rtt->rttvar = sample_rtt / 2;
    } else {
        delta = sample_rtt - rtt->srtt;
        if (delta < 0)
            delta = -delta;

        /* RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R| */
        rtt->rttvar = (rtt->rttvar * 3 + delta) / 4;

        /* SRTT = 7/8 * SRTT + 1/8 * R */
        rtt->srtt = (rtt->srtt * 7 + sample_rtt) / 8;
    }
}

/*
 * 测量入站包的 RTT
 */
u32 zeta_measure_rtt_incoming(struct sk_buff *skb, struct zeta_flow_info *info)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 tsval, tsecr;
    u32 rtt = 0;
    u32 now = zeta_get_time_us();

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return 0;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    ts_opt = zeta_find_ts_option(th, th->doff * 4);
    if (!ts_opt) {
        info->flags &= ~ZETA_FLAG_TS_OK;
        return 0;
    }

    info->flags |= ZETA_FLAG_TS_OK;

    tsval = ntohl(*(u32 *)(ts_opt + 2));
    tsecr = ntohl(*(u32 *)(ts_opt + 6));

    /* 记录对端的 TSval */
    info->rtt.ts_recent = tsval;
    info->rtt.ts_recent_time = now;

    /* 计算 RTT */
    if (tsecr != 0 && info->rtt.last_sent_ts != 0) {
        if (tsecr == info->rtt.last_sent_ts) {
            rtt = now - info->rtt.last_sent_time;
            zeta_update_rtt(&info->rtt, rtt);
        }
    }

    return rtt;
}

/*
 * 修改出站包的时间戳
 */
void zeta_stamp_outgoing(struct sk_buff *skb, struct zeta_flow_info *info)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 now = zeta_get_time_us();
    int tcplen;

    if (skb_cloned(skb)) {
        if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
            return;
    }

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    ts_opt = zeta_find_ts_option(th, th->doff * 4);
    if (! ts_opt)
        return;

    /* 修改 TSval */
    *(u32 *)(ts_opt + 2) = htonl(now);

    /* 记录发送的时间戳 */
    info->rtt.last_sent_ts = now;
    info->rtt.last_sent_time = now;

    /* 重算校验和 */
    tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcplen, IPPROTO_TCP,
                                   csum_partial((char *)th, tcplen, 0));
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/*
 * 反向路径控制：窗口放大
 * 用于加速上传（接收方向）
 */
u16 zeta_inflate_window(struct zeta_flow_info *info,
                         u16 orig_win,
                         struct zeta_params *params)
{
    struct zeta_win_ctrl *win = &info->win;
    struct zeta_cong_detector *cong = &info->cong;
    u32 real_win;
    u32 inflated_win;
    u32 factor;

    /* 计算实际窗口 */
    real_win = (u32)orig_win << win->rcv_wscale;

    /* 根据网络状态决定放大倍数 */
    switch (cong->quality) {
    case ZETA_NET_EXCELLENT:
        factor = params->win_inflate_factor;
        break;
    case ZETA_NET_GOOD:
        factor = params->win_inflate_factor * 3 / 4;
        break;
    case ZETA_NET_FAIR:
        factor = params->win_inflate_factor / 2;
        break;
    case ZETA_NET_POOR:
        factor = params->win_inflate_factor / 4;
        break;
    default:
        factor = 1;  /* 不放大 */
        break;
    }

    if (factor < 1)
        factor = 1;

    inflated_win = real_win * factor;

    /* 限制最大值 */
    if (inflated_win > (1U << 30))
        inflated_win = (1U << 30);

    win->win_inflate_factor = factor * 1000;
    win->advertised_win = inflated_win;

    /* 转回 16-bit */
    if (win->rcv_wscale > 0) {
        u16 new_win = inflated_win >> win->rcv_wscale;
        if (new_win == 0)
            new_win = 1;
        if (new_win < orig_win)
            new_win = orig_win;
        return new_win;
    }

    return (u16)(inflated_win > 65535 ? 65535 : inflated_win);
}

/*
 * 修改出站 ACK 的窗口
 */
void zeta_modify_ack_window(struct sk_buff *skb,
                             struct zeta_flow_info *info,
                             struct zeta_params *params)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u16 orig_win, new_win;
    int tcplen;

    if (!(info->flags & ZETA_FLAG_ACCELERATE))
        return;

    if (skb_cloned(skb)) {
        if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
            return;
    }

    iph = ip_hdr(skb);
    if (! iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (! th->ack)
        return;

    orig_win = ntohs(th->window);
    new_win = zeta_inflate_window(info, orig_win, params);

    if (new_win > orig_win) {
        th->window = htons(new_win);

        /* 重算校验和 */
        tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
        th->check = 0;
        th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       tcplen, IPPROTO_TCP,
                                       csum_partial((char *)th, tcplen, 0));
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
}

/*
 * 更新反向路径统计
 */
void zeta_update_reverse_stats(struct zeta_flow_info *info,
                                u32 seq, u32 len)
{
    struct zeta_reverse_ctrl *rev = &info->rev;
    u32 seq_end = seq + len;
    u32 now = zeta_get_time_us();

    rev->bytes_received += len;
    rev->last_rcv_time = now;

    /* 检测乱序 */
    if (rev->rcv_nxt != 0) {
        if (zeta_seq_gt(seq, rev->rcv_nxt)) {
            /* 乱序包 */
            rev->ooo_count++;
        } else if (seq == rev->rcv_nxt) {
            /* 顺序包 */
            if (rev->ooo_count > 0)
                rev->ooo_count--;
        }
    }

    /* 更新期望序号 */
    if (zeta_seq_gt(seq_end, rev->rcv_nxt))
        rev->rcv_nxt = seq_end;

    /* 启用加速 */
    if (rev->bytes_received > 10 * 1024) {
        info->flags |= ZETA_FLAG_ACCELERATE;
    }
}