/*
 * tapac_upload.c - 上传加速模块 v2.6
 * 修复：窗口放大倍数不再被限制
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/checksum.h>

#include "tapac.h"

/* ============ 解析窗口缩放选项 ============ */
void tapac_parse_win_scale(struct tcphdr *th, u32 tcp_hdr_len,
                           struct tapac_win_info *win)
{
    u8 *opt, *end;
    u8 kind, len;

    if (! th || ! win)
        return;

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

        if (kind == 3 && len == 3) {
            win->rcv_wscale = *(opt + 2);
            if (win->rcv_wscale > WIN_SCALE_MAX)
                win->rcv_wscale = WIN_SCALE_MAX;
            return;
        }

        opt += len;
    }
}

/* ============ 计算放大后的窗口 ============ */
u16 tapac_inflate_window(struct tapac_engine *eng,
                         struct tapac_flow_info *info,
                         u16 orig_win)
{
    u32 real_win;
    u32 inflated_win;
    u32 factor;

    if (!eng || !info)
        return orig_win;

    /* 计算实际窗口 */
    real_win = (u32)orig_win << info->win.rcv_wscale;

    /* 根据状态决定放大倍数 */
    if (info->flags & FLOW_FLAG_LOSS_DETECTED) {
        /* 丢包：不放大 */
        return orig_win;
    } else if (info->phase == PHASE_FAST_RECOVERY) {
        /* 快速恢复：保守 */
        factor = 2;
    } else {
        /* 正常和慢启动：使用配置的放大倍数 */
        factor = eng->params.win_inflate_factor;
    }

    /* 不再限制最大放大倍数，使用配置值 */
    inflated_win = real_win * factor;

    /* 限制最大值：不超过 1GB（TCP 最大窗口） */
    if (inflated_win > (1U << 30))
        inflated_win = (1U << 30);

    /* 转回 16-bit */
    if (info->win.rcv_wscale > 0) {
        u16 new_win = inflated_win >> info->win.rcv_wscale;
        if (new_win == 0)
            new_win = 1;
        if (new_win < orig_win)
            new_win = orig_win;
        return new_win;
    }

    return (u16)(inflated_win > 65535 ? 65535 : inflated_win);
}

/* ============ 修改 ACK 包的窗口字段 ============ */
void tapac_modify_ack_window(struct sk_buff *skb,
                             struct tapac_engine *eng,
                             struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u16 orig_win;
    u16 new_win;
    struct tapac_flow_info *info;

    if (!skb || !eng || ! flow)
        return;

    info = &flow->info;

    if (info->direction != FLOW_DIR_SERVER)
        return;

    /* 确保可写 */
    if (skb_cloned(skb)) {
        if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
            return;
    }

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (! th->ack)
        return;

    orig_win = ntohs(th->window);
    new_win = tapac_inflate_window(eng, info, orig_win);

    if (new_win <= orig_win)
        return;

    /* 修改窗口 */
    th->window = htons(new_win);

    info->win.advertised_win = new_win;
    info->win.last_win_update = tapac_get_time_us();
    eng->stats.win_inflated++;

    /* 注意：校验和会在 tapac_fix_checksums_kernel 中重新计算 */
}

/* ============ 判断是否应该加速 ACK ============ */
bool tapac_should_accelerate_ack(struct tapac_engine *eng,
                                 struct tapac_flow_info *info)
{
    u32 now;
    u32 elapsed;
    u32 pending_data;

    if (!eng || !info)
        return false;

    if (info->direction != FLOW_DIR_SERVER)
        return false;

    if (!(info->flags & FLOW_FLAG_UPLOAD_ACCEL))
        return false;

    now = tapac_get_time_us();
    elapsed = now - info->upload.last_ack_time;
    pending_data = info->upload.bytes_received - info->upload.bytes_acked;

    if (pending_data >= eng->params.mss * 4)
        return true;

    if (elapsed >= info->upload.ack_interval && pending_data > 0)
        return true;

    if (info->flags & FLOW_FLAG_LOSS_DETECTED)
        return true;

    return false;
}

/* ============ 更新上传统计 ============ */
void tapac_update_upload_stats(struct tapac_flow_info *info,
                               u32 payload_len, u32 seq)
{
    if (!info || payload_len == 0)
        return;

    info->upload.bytes_received += payload_len;

    if (info->upload.expected_seq != 0) {
        if (seq != info->upload.expected_seq) {
            info->upload.dup_ack_trigger++;
        } else {
            info->upload.dup_ack_trigger = 0;
        }
    }

    info->upload.expected_seq = seq + payload_len;

    /* 10KB 后启用加速（降低阈值） */
    if (info->upload.bytes_received > 10 * 1024) {
        info->flags |= FLOW_FLAG_UPLOAD_ACCEL;
    }
}

/* ============ 计算动态 ACK 间隔 ============ */
static u32 tapac_calc_ack_interval(struct tapac_engine *eng,
                                   struct tapac_flow_info *info)
{
    u32 interval;

    if (! eng || !info)
        return 10000;

    if (info->flags & FLOW_FLAG_LOSS_DETECTED) {
        interval = 2000;
    } else if (info->phase == PHASE_SLOW_START) {
        interval = info->srtt / 8;
        if (interval < 3000)
            interval = 3000;
    } else {
        interval = info->srtt / 4;
        if (interval < 5000)
            interval = 5000;
        if (interval > 50000)
            interval = 50000;
    }

    return interval;
}

/* ============ 处理入站数据（上传方向） ============ */
int tapac_process_upload_data(struct tapac_engine *eng,
                              struct sk_buff *skb,
                              struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow_info *info;
    u32 payload_len;
    u32 seq;

    if (!eng || !skb || ! flow)
        return 0;

    info = &flow->info;

    if (info->direction != FLOW_DIR_SERVER)
        return 0;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;
    seq = ntohl(th->seq);

    if (payload_len == 0)
        return 0;

    tapac_update_upload_stats(info, payload_len, seq);
    info->upload.ack_interval = tapac_calc_ack_interval(eng, info);

    if (tapac_should_accelerate_ack(eng, info)) {
        info->flags |= FLOW_FLAG_ACK_PENDING;
        info->upload.pending_acks++;
        eng->stats.ack_accelerated++;
    }

    return 0;
}

/* ============ 处理出站 ACK ============ */
int tapac_process_upload_ack(struct tapac_engine *eng,
                             struct sk_buff *skb,
                             struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct tapac_flow_info *info;
    u32 ack_seq;
    u32 payload_len;

    if (!eng || !skb || ! flow)
        return 0;

    info = &flow->info;

    if (info->direction != FLOW_DIR_SERVER)
        return 0;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);

    if (!th->ack)
        return 0;

    ack_seq = ntohl(th->ack_seq);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - th->doff * 4;

    if (payload_len == 0) {
        if (tapac_seq_gt(ack_seq, info->upload.bytes_acked)) {
            u32 acked = ack_seq - info->upload.bytes_acked;
            info->upload.bytes_acked = ack_seq;
            eng->stats.upload_bytes_accel += acked;
        }

        info->upload.last_ack_time = tapac_get_time_us();
        info->upload.pending_acks = 0;
        info->flags &= ~FLOW_FLAG_ACK_PENDING;
    }

    return 0;
}