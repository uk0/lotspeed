/*
 * zeta_ack_control.c - ACK Control (Stabilized Version)
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
#define ZETA_MIN_RWND           8760    /* 最小窗口: 6 MSS，防止卡住 */
#define ZETA_SCALE_SMOOTH_UP    8       /* 向上平滑步长 */
#define ZETA_SCALE_SMOOTH_DOWN  3       /* 向下平滑步长（更保守）*/

/* ========== 前向声明 ========== */
static void zeta_ack_update_dupack_thresh(struct zeta_conn *conn);
static u32 zeta_smooth_scale(struct zeta_conn *conn, u32 target_scale);

/* ========== 平滑缩放计算 ========== */
static u32 zeta_smooth_scale(struct zeta_conn *conn, u32 target_scale)
{
    u32 cur_scale = conn->ack_rwnd_scale;  /* 修复：不要用 current 作为变量名 */
    
    if (cur_scale == 0)
        cur_scale = 100;
    
    if (target_scale > cur_scale) {
        /* 向上恢复：较快 */
        u32 step = min_t(u32, target_scale - cur_scale, ZETA_SCALE_SMOOTH_UP);
        return cur_scale + step;
    } else if (target_scale < cur_scale) {
        /* 向下压缩：较慢，避免突变 */
        u32 step = min_t(u32, cur_scale - target_scale, ZETA_SCALE_SMOOTH_DOWN);
        return cur_scale - step;
    }
    
    return cur_scale;
}

/* ========== RWND 修改策略 (稳定版) ========== */
void zeta_ack_modify_rwnd(struct zeta_conn *conn, struct tcphdr *th)
{
    u16 orig_rwnd = ntohs(th->window);
    u16 new_rwnd;
    u32 target_scale = 100;
    u32 smooth_scale_val;
    const char *reason = "default";

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] modify_rwnd: orig=%u state=%d score=%u loss=%u cur_scale=%u\n",
                 &conn->daddr, ntohs(conn->dport),
                 orig_rwnd, conn->state,
                 conn->features.congestion_score,
                 conn->features.loss_total,
                 conn->ack_rwnd_scale);
    }

    /* 根据状态计算目标缩放因子 */
    switch (conn->state) {
        case ZETA_STATE_NORMAL:
            if (conn->features.loss_total > 5) {
                target_scale = 80;
                reason = "NORMAL+loss>5";
            } else if (conn->features.congestion_score > 40) {
                target_scale = 90;
                reason = "NORMAL+score>40";
            } else {
                target_scale = 100;
                reason = "NORMAL";
            }
            break;

        case ZETA_STATE_RANDOM_LOSS:
            /* 随机丢包：更保守处理 */
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
            if (conn->features.congestion_score > 60) {
                target_scale = 80;
            } else {
                target_scale = 90;
            }
            reason = "STABLE_DELAY";
            break;

        case ZETA_STATE_DELAY_RISING:
            /* 延迟上升：中等限制 */
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
            /* 阵发丢包：更保守（提高最低值）*/
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

    /* 额外检查：有丢包且高分数时进一步限制，但不要太激进 */
    if (conn->features.loss_total > 0 && conn->features.congestion_score > 70) {
        u32 old_scale = target_scale;
        target_scale = min_t(u32, target_scale, 55);
        if (target_scale != old_scale) {
            reason = "EXTRA_CHECK";
        }
    }

    /* 应用平滑处理 */
    smooth_scale_val = zeta_smooth_scale(conn, target_scale);

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] target=%u smooth=%u reason=%s\n",
                 &conn->daddr, ntohs(conn->dport),
                 target_scale, smooth_scale_val, reason);
    }

    /* 计算新窗口 */
    new_rwnd = (u16)zeta_div32((u32)orig_rwnd * smooth_scale_val, 100);

    /* 保证最小窗口（关键：防止传输卡住）*/
    if (new_rwnd < ZETA_MIN_RWND)
        new_rwnd = ZETA_MIN_RWND;

    /* 更新记录 */
    conn->ack_rwnd_scale = (u16)smooth_scale_val;

    /* 写入新窗口 */
    if (new_rwnd != orig_rwnd) {
        th->window = htons(new_rwnd);
        
        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] *** RWND CHANGED *** %u -> %u (smooth=%u%% reason=%s)\n",
                     &conn->daddr, ntohs(conn->dport),
                     orig_rwnd, new_rwnd, smooth_scale_val, reason);
        }
    } else {
        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] RWND unchanged: %u\n",
                     &conn->daddr, ntohs(conn->dport), orig_rwnd);
        }
    }
}

/* ========== ACK 抑制判断（更保守）========== */
bool zeta_ack_should_suppress(struct zeta_conn *conn)
{
    if (conn->state != ZETA_STATE_BURST_LOSS)
        return false;

    /* 限制抑制次数（减少抑制）*/
    if (conn->ack_suppress_count >= 2)
        return false;

    /* 只在极高拥塞分数时抑制 */
    if (conn->features.congestion_score >= 99) {
        conn->ack_suppress_count++;
        ZETA_LOG("[%pI4:%u] ACK SUPPRESSED!  count=%u score=%u\n",
                 &conn->daddr, ntohs(conn->dport),
                 conn->ack_suppress_count,
                 conn->features.congestion_score);
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

    if (! conn || !th) {
        ZETA_LOG("zeta_ack_process: NULL conn or th!\n");
        return 0;
    }

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] >>> zeta_ack_process START\n",
                 &conn->daddr, ntohs(conn->dport));
    }

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
    
    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] COMPARE: orig=%u new=%u\n",
                 &conn->daddr, ntohs(conn->dport),
                 orig_rwnd, new_rwnd);
    }
    
    if (new_rwnd != orig_rwnd) {
        modified = 1;
        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] >>> MODIFIED=1\n",
                     &conn->daddr, ntohs(conn->dport));
        }
    }

    /* 6.重置计数 */
    if (conn->state == ZETA_STATE_NORMAL) {
        conn->ack_suppress_count = 0;
    }

    /* 7.统计 */
    if (modified) {
        atomic64_inc(&g_zeta->stats.cwnd_reductions);
    }

    if (g_zeta && g_zeta->verbose) {
        ZETA_LOG("[%pI4:%u] <<< zeta_ack_process END, return %d\n",
                 &conn->daddr, ntohs(conn->dport), modified);
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
        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] ECN CE received, score=%u\n",
                     &conn->daddr, ntohs(conn->dport),
                     conn->features.congestion_score);
        }
    }
    
    if (th->ece) {
        conn->features.congestion_score = min_t(u32,
            conn->features.congestion_score + 20, 100);
        if (conn->state == ZETA_STATE_NORMAL) {
            conn->state = ZETA_STATE_DELAY_RISING;
        }
        if (g_zeta && g_zeta->verbose) {
            ZETA_LOG("[%pI4:%u] TCP ECE received, score=%u state=%d\n",
                     &conn->daddr, ntohs(conn->dport),
                     conn->features.congestion_score, conn->state);
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
    
    ZETA_LOG("[%pI4:%u] EMERGENCY BRAKE activated!\n",
             &conn->daddr, ntohs(conn->dport));
}