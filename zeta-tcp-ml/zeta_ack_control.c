/*
 * zeta_ack_control.c - ACK Control with ACK Splitting
 * High-performance ACK manipulation
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/ip.h>
#include "zeta_core.h"

/* ========== 稳定性配置 ========== */
#define ZETA_SCALE_SMOOTH_UP    8
#define ZETA_SCALE_SMOOTH_DOWN  3

/* ========== 前向声明 ========== */
static void zeta_ack_update_dupack_thresh(struct zeta_conn *conn);
static u32 zeta_smooth_scale(struct zeta_conn *conn, u32 target_scale);

/* ========== ACK Splitting 初始化 ========== */
void zeta_ack_split_init(struct zeta_conn *conn)
{
    struct zeta_ack_split *split = &conn->ack_split;

    split->pending_acks = 0;
    split->last_ack_seq = 0;
    split->last_ack_time_us = 0;
    split->split_ratio = ZETA_ACK_SPLIT_RATIO;
    split->accumulated_bytes = 0;
    split->enabled = (g_zeta && g_zeta->ack_split_enabled);
}

/* ========== ACK Splitting 处理 ========== */
/*
 * ACK Splitting: 将多个小 ACK 合并成一个，或将一个大 ACK 分割成多个
 * 目的是更精细地控制发送端的发送速率
 * 
 * 返回值:
 *   0 - 继续正常处理
 *   1 - ACK 已被延迟/合并，不发送
 *   2 - 需要发送额外的 ACK
 */
int zeta_ack_split_process(struct zeta_conn *conn, struct sk_buff *skb,
                           struct tcphdr *th, int payload_len)
{
    struct zeta_ack_split *split = &conn->ack_split;
    u64 now_us = zeta_now_us();
    u32 ack_seq = ntohl(th->ack_seq);
    u32 bytes_acked;
    int result = 0;

    if (!split->enabled)
        return 0;

    /* 计算本次确认的字节数 */
    if (split->last_ack_seq != 0 && zeta_seq_after(ack_seq, split->last_ack_seq)) {
        bytes_acked = ack_seq - split->last_ack_seq;
    } else {
        bytes_acked = 0;
    }

    split->accumulated_bytes += bytes_acked;
    split->pending_acks++;

    /* 根据拥塞状态调整分割策略 */
    switch (conn->state) {
        case ZETA_STATE_NORMAL:
        case ZETA_STATE_STABLE_DELAY:
            /* 正常情况：允许较快的 ACK */
            split->split_ratio = 1;
            break;

        case ZETA_STATE_DELAY_RISING:
            /* 延迟上升：适度延迟 ACK */
            split->split_ratio = 2;
            break;

        case ZETA_STATE_BURST_LOSS:
        case ZETA_STATE_RANDOM_LOSS:
            /* 丢包情况：更多 ACK 帮助恢复 */
            split->split_ratio = 1;
            break;

        default:
            split->split_ratio = ZETA_ACK_SPLIT_RATIO;
    }

    /* 决定是否发送 ACK */
    if (split->pending_acks >= split->split_ratio) {
        /* 达到分割阈值，发送 ACK */
        split->pending_acks = 0;
        split->accumulated_bytes = 0;
        split->last_ack_seq = ack_seq;
        split->last_ack_time_us = now_us;
        result = 0;  /* 正常发送 */
        
        /* 更新统计 */
        if (g_zeta && g_zeta->percpu_stats) {
            struct zeta_percpu_stats *stats = this_cpu_ptr(g_zeta->percpu_stats);
            stats->acks_split++;
        }
    } else {
        /* 超时检查：即使没达到阈值，超时也要发送 */
        u64 elapsed_us = now_us - split->last_ack_time_us;
        
        if (elapsed_us > 50000) {  /* 50ms 超时 */
            split->pending_acks = 0;
            split->accumulated_bytes = 0;
            split->last_ack_seq = ack_seq;
            split->last_ack_time_us = now_us;
            result = 0;
        } else {
            /* 延迟此 ACK */
            result = 1;
        }
    }

    if (g_zeta && g_zeta->verbose && result == 1) {
        ZETA_LOG("[%pI4:%u] ACK SPLIT: delayed (pending=%u ratio=%u)\n",
                 &conn->daddr, ntohs(conn->dport),
                 split->pending_acks, split->split_ratio);
    }

    return result;
}

/* ========== 强制刷新 ACK ========== */
void zeta_ack_split_flush(struct zeta_conn *conn, struct sk_buff *skb)
{
    struct zeta_ack_split *split = &conn->ack_split;

    if (!split->enabled)
        return;

    /* 重置状态 */
    split->pending_acks = 0;
    split->accumulated_bytes = 0;
    split->last_ack_time_us = zeta_now_us();
}

/* ========== 平滑缩放计算 ========== */
static u32 zeta_smooth_scale(struct zeta_conn *conn, u32 target_scale)
{
    u32 cur_scale = conn->ack_rwnd_scale;

    if (cur_scale == 0)
        cur_scale = 100;

    if (target_scale > cur_scale) {
        u32 step = min_t(u32, target_scale - cur_scale, ZETA_SCALE_SMOOTH_UP);
        return cur_scale + step;
    } else if (target_scale < cur_scale) {
        u32 step = min_t(u32, cur_scale - target_scale, ZETA_SCALE_SMOOTH_DOWN);
        return cur_scale - step;
    }

    return cur_scale;
}

/* ========== RWND 修改策略 ========== */
void zeta_ack_modify_rwnd(struct zeta_conn *conn, struct tcphdr *th)
{
    u16 orig_rwnd = ntohs(th->window);
    u16 new_rwnd;
    u32 target_scale = 100;
    u32 smooth_scale_val;
    const char *reason = "default";

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] modify_rwnd: orig=%u state=%d score=%u loss=%u\n",
                 &conn->daddr, ntohs(conn->dport),
                 orig_rwnd, conn->state,
                 conn->features.congestion_score,
                 conn->features.loss_total);
    }

    switch (conn->state) {
        case ZETA_STATE_NORMAL:
            if (conn->features.loss_total > 5) {
                target_scale = 80;
                reason = "NORMAL+loss";
            } else if (conn->features.congestion_score > 40) {
                target_scale = 90;
                reason = "NORMAL+score";
            } else {
                target_scale = 100;
                reason = "NORMAL";
            }
            break;

        case ZETA_STATE_RANDOM_LOSS:
            if (conn->features.loss_total > 15) {
                target_scale = 65;
            } else if (conn->features.loss_total > 8) {
                target_scale = 75;
            } else if (conn->features.loss_total > 3) {
                target_scale = 85;
            } else {
                target_scale = 95;
            }
            reason = "RANDOM_LOSS";
            break;

        case ZETA_STATE_STABLE_DELAY:
            target_scale = (conn->features.congestion_score > 60) ? 80 : 90;
            reason = "STABLE_DELAY";
            break;

        case ZETA_STATE_DELAY_RISING:
            if (conn->features.congestion_score >= 90) {
                target_scale = 40;
            } else if (conn->features.congestion_score >= 70) {
                target_scale = 55;
            } else if (conn->features.congestion_score >= 50) {
                target_scale = 65;
            } else {
                target_scale = 80;
            }
            reason = "DELAY_RISING";
            break;

        case ZETA_STATE_BURST_LOSS:
            if (conn->features.congestion_score >= 95) {
                target_scale = 30;
            } else if (conn->features.congestion_score >= 80) {
                target_scale = 40;
            } else if (conn->features.congestion_score >= 60) {
                target_scale = 50;
            } else {
                target_scale = 60;
            }
            reason = "BURST_LOSS";
            break;

        case ZETA_STATE_RECOVERING:
            target_scale = 65;
            reason = "RECOVERING";
            break;

        default:
            target_scale = 100;
            reason = "UNKNOWN";
    }

    /* 额外检查 */
    if (conn->features.loss_total > 0 && conn->features.congestion_score > 70) {
        target_scale = min_t(u32, target_scale, 55);
        reason = "EXTRA_CHECK";
    }

    /* 应用平滑处理 */
    smooth_scale_val = zeta_smooth_scale(conn, target_scale);

    /* 计算新窗口 */
    new_rwnd = (u16)zeta_div32((u32)orig_rwnd * smooth_scale_val, 100);

    /* 保证最小窗口 */
    if (new_rwnd < ZETA_MIN_RWND)
        new_rwnd = ZETA_MIN_RWND;

    conn->ack_rwnd_scale = (u16)smooth_scale_val;

    if (new_rwnd != orig_rwnd) {
        th->window = htons(new_rwnd);

        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] RWND: %u -> %u (scale=%u%% reason=%s)\n",
                     &conn->daddr, ntohs(conn->dport),
                     orig_rwnd, new_rwnd, smooth_scale_val, reason);
        }
    }
}

/* ========== ACK 抑制判断 ========== */
bool zeta_ack_should_suppress(struct zeta_conn *conn)
{
    if (conn->state != ZETA_STATE_BURST_LOSS)
        return false;

    if (conn->ack_suppress_count >= 2)
        return false;

    if (conn->features.congestion_score >= 99) {
        conn->ack_suppress_count++;
        
        if (g_zeta && g_zeta->percpu_stats) {
            struct zeta_percpu_stats *stats = this_cpu_ptr(g_zeta->percpu_stats);
            stats->acks_suppressed++;
        }
        
        ZETA_LOG("[%pI4:%u] ACK SUPPRESSED count=%u\n",
                 &conn->daddr, ntohs(conn->dport),
                 conn->ack_suppress_count);
        return true;
    }

    return false;
}

/* ========== DupACK 阈值 ========== */
static void zeta_ack_update_dupack_thresh(struct zeta_conn *conn)
{
    switch (conn->state) {
        case ZETA_STATE_RANDOM_LOSS:
            conn->ack_dup_thresh = 5;
            break;
        case ZETA_STATE_BURST_LOSS:
            conn->ack_dup_thresh = 3;
            break;
        default:
            conn->ack_dup_thresh = 3;
    }
}

/* ========== 主 ACK 处理函数 ========== */
int zeta_ack_process(struct zeta_conn *conn, struct sk_buff *skb,
                     struct tcphdr *th)
{
    u16 orig_rwnd;
    u16 new_rwnd;
    int modified = 0;

    if (!conn || !th)
        return 0;

    /* 1.抑制检查 */
    if (zeta_ack_should_suppress(conn)) {
        return -1;
    }

    /* 2.更新阈值 */
    zeta_ack_update_dupack_thresh(conn);

    /* 3.保存原窗口 */
    orig_rwnd = ntohs(th->window);

    /* 4.修改窗口 */
    zeta_ack_modify_rwnd(conn, th);

    /* 5.检查修改 */
    new_rwnd = ntohs(th->window);

    if (new_rwnd != orig_rwnd) {
        modified = 1;
        
        /* 更新 per-CPU 统计 */
        if (g_zeta && g_zeta->percpu_stats) {
            struct zeta_percpu_stats *stats = this_cpu_ptr(g_zeta->percpu_stats);
            stats->pkts_modified++;
        }
    }

    /* 6.重置计数 */
    if (conn->state == ZETA_STATE_NORMAL) {
        conn->ack_suppress_count = 0;
    }

    /* 7.更新全局统计 */
    if (modified) {
        atomic64_inc(&g_zeta->stats.cwnd_reductions);
    }

    return modified;
}

/* ========== 生成 DupACK ========== */
void zeta_ack_generate_dupack(struct zeta_conn *conn, struct sk_buff *orig_skb)
{
    struct sk_buff *nskb;
    struct iphdr *iph, *orig_iph;
    struct tcphdr *th, *orig_th;
    int tcp_hdr_len;

    if (!orig_skb)
        return;

    orig_iph = ip_hdr(orig_skb);
    orig_th = tcp_hdr(orig_skb);

    if (! orig_iph || !orig_th)
        return;

    tcp_hdr_len = sizeof(struct tcphdr);

    nskb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + tcp_hdr_len,
                     GFP_ATOMIC);
    if (! nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    /* 构建 IP 头 */
    skb_reset_network_header(nskb);
    iph = skb_put(nskb, sizeof(struct iphdr));

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + tcp_hdr_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = orig_iph->daddr;
    iph->daddr = orig_iph->saddr;

    ip_send_check(iph);

    /* 构建 TCP 头 */
    skb_set_transport_header(nskb, sizeof(struct iphdr));
    th = skb_put(nskb, tcp_hdr_len);

    memset(th, 0, tcp_hdr_len);
    th->source = orig_th->dest;
    th->dest = orig_th->source;
    th->seq = htonl(conn->rcv_nxt);
    th->ack_seq = htonl(conn->snd_una);
    th->doff = tcp_hdr_len >> 2;
    th->ack = 1;
    th->window = htons(conn->ack_rwnd_scale * 65535 / 100);

    th->check = 0;
    th->check = tcp_v4_check(tcp_hdr_len, iph->saddr, iph->daddr,
                             csum_partial((char *)th, tcp_hdr_len, 0));

    nskb->protocol = htons(ETH_P_IP);
    skb_dst_set(nskb, dst_clone(skb_dst(orig_skb)));

    ip_local_out(&init_net, NULL, nskb);

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] DupACK generated\n",
                 &conn->daddr, ntohs(conn->dport));
    }
}

/* ========== ECN 处理 ========== */
void zeta_ack_handle_ecn(struct zeta_conn *conn, struct tcphdr *th,
                         struct iphdr *iph)
{
    u8 ecn = iph->tos & INET_ECN_MASK;

    if (ecn == INET_ECN_CE) {
        conn->features.congestion_score = min_t(u32,
            conn->features.congestion_score + 15, 100);
    }

    if (th->ece) {
        conn->features.congestion_score = min_t(u32,
            conn->features.congestion_score + 20, 100);
        if (conn->state == ZETA_STATE_NORMAL) {
            conn->state = ZETA_STATE_DELAY_RISING;
        }
    }
}

/* ========== 紧急制动 ========== */
void zeta_ack_emergency_brake(struct zeta_conn *conn, struct tcphdr *th)
{
    th->window = htons(ZETA_MIN_RWND);
    conn->ack_rwnd_scale = 30;
    conn->state = ZETA_STATE_BURST_LOSS;
    conn->features.congestion_score = 100;
    atomic64_inc(&g_zeta->stats.cwnd_reductions);

    ZETA_LOG("[%pI4:%u] EMERGENCY BRAKE!\n",
             &conn->daddr, ntohs(conn->dport));
}