/*
 * zeta_hooks.c - NetFilter Hooks (Per-CPU Optimized)
 * Author: uk0
 */

#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include "zeta_core.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define zeta_skb_make_writable(skb, len) skb_try_make_writable(skb, len)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
#define zeta_skb_make_writable(skb, len) pskb_may_pull(skb, len)
#else
#define zeta_skb_make_writable(skb, len) skb_make_writable(skb, len)
#endif

/* 重新计算 TCP 校验和 */
static void zeta_update_tcp_checksum(struct sk_buff *skb, struct iphdr *iph,
                                      struct tcphdr *th)
{
    int tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);

    th->check = 0;
    th->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr,
                             csum_partial((char *)th, tcp_len, 0));
    skb->ip_summed = CHECKSUM_NONE;
}

/* ========== 出向钩子 ========== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static unsigned int zeta_hook_out(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
#else
static unsigned int zeta_hook_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
#endif
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct zeta_conn *conn;
    struct zeta_percpu_stats *pstats;
    int payload_len;
    int ip_hdr_len;
    bool should_modify = false;
    int ret;
    u64 now_us;

    if (!g_zeta || !g_zeta->enabled)
        return NF_ACCEPT;

    if (! skb)
        return NF_ACCEPT;

    if (! pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl << 2;

    if (! pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (!th)
        return NF_ACCEPT;

    /* Per-CPU 统计 */
    pstats = this_cpu_ptr(g_zeta->percpu_stats);
    pstats->pkts_out++;

    now_us = zeta_now_us();

    conn = zeta_conn_find(iph->saddr, iph->daddr, th->source, th->dest);

    if (! conn) {
        if (th->syn && !th->ack) {
            conn = zeta_conn_create(iph->saddr, iph->daddr,
                                    th->source, th->dest);
            if (! conn)
                return NF_ACCEPT;

            if (g_zeta->verbose) {
                ZETA_LOG("NEW conn: %pI4:%u -> %pI4:%u (CPU %d)\n",
                         &iph->saddr, ntohs(th->source),
                         &iph->daddr, ntohs(th->dest),
                         smp_processor_id());
            }
        } else {
            return NF_ACCEPT;
        }
    }

    spin_lock_bh(&conn->lock);

    conn->last_active_us = now_us;
    conn->last_active = now_us / 1000;

    payload_len = ntohs(iph->tot_len) - ip_hdr_len - (th->doff << 2);
    if (payload_len < 0)
        payload_len = 0;

    if (payload_len > 0 || th->syn || th->fin) {
        u32 seq_end = ntohl(th->seq) + payload_len;
        if (th->syn) seq_end++;
        if (th->fin) seq_end++;

        if (zeta_seq_after(seq_end, conn->snd_nxt))
            conn->snd_nxt = seq_end;

        conn->pkts_sent++;
        conn->bytes_sent += payload_len;
    }

    /* RTT 测量（微秒精度）*/
    if (payload_len > 0 && conn->rtt_measure_start == 0) {
        conn->rtt_measure_start = now_us;
        conn->rtt_measure_seq = ntohl(th->seq) + payload_len;
    }

    zeta_learn_update(conn, th, payload_len, false);

    /* ACK 处理 */
    if (th->ack) {
        /* 判断是否需要修改 */
        switch (conn->state) {
            case ZETA_STATE_BURST_LOSS:
            case ZETA_STATE_DELAY_RISING:
                should_modify = true;
                break;
            case ZETA_STATE_RANDOM_LOSS:
                should_modify = (conn->features.loss_total > 2);
                break;
            case ZETA_STATE_STABLE_DELAY:
                should_modify = (conn->features.congestion_score > 40);
                break;
            case ZETA_STATE_NORMAL:
                should_modify = (conn->features.congestion_score > 40 ||
                                conn->features.loss_total > 3);
                break;
            default:
                should_modify = false;
        }

        if (should_modify) {
            u16 orig_window = ntohs(th->window);

            if (g_zeta->verbose) {
                ZETA_LOG("[%pI4:%u] MODIFY: state=%d score=%u loss=%u win=%u\n",
                         &conn->daddr, ntohs(conn->dport),
                         conn->state, conn->features.congestion_score,
                         conn->features.loss_total, orig_window);
            }

            /* 处理 cloned SKB */
            if (skb_cloned(skb)) {
                if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
                    spin_unlock_bh(&conn->lock);
                    return NF_ACCEPT;
                }

                iph = ip_hdr(skb);
                th = (struct tcphdr *)((unsigned char *)iph + (iph->ihl << 2));
            }

            /* ACK Splitting 处理 */
            if (g_zeta->ack_split_enabled) {
                ret = zeta_ack_split_process(conn, skb, th, payload_len);
                if (ret == 1) {
                    /* ACK 被延迟 */
                    pstats->acks_delayed++;
                    spin_unlock_bh(&conn->lock);
                    return NF_ACCEPT;
                }
            }

            /* ACK 处理 */
            ret = zeta_ack_process(conn, skb, th);

            if (ret == 1) {
                zeta_update_tcp_checksum(skb, iph, th);
                pstats->pkts_modified++;

                if (g_zeta->verbose) {
                    ZETA_LOG("[%pI4:%u] MODIFIED: old=%u new=%u\n",
                             &conn->daddr, ntohs(conn->dport),
                             orig_window, ntohs(th->window));
                }
            } else if (ret == -1) {
                spin_unlock_bh(&conn->lock);
                pstats->acks_suppressed++;
                return NF_DROP;
            }
        }
    }

    spin_unlock_bh(&conn->lock);

    return NF_ACCEPT;
}

/* ========== 入向钩子 ========== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static unsigned int zeta_hook_in(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
#else
static unsigned int zeta_hook_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
#endif
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct zeta_conn *conn;
    struct zeta_percpu_stats *pstats;
    int ip_hdr_len;
    u64 now_us;

    if (! g_zeta || !g_zeta->enabled)
        return NF_ACCEPT;

    if (!skb)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl << 2;

    if (! pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (! th)
        return NF_ACCEPT;

    /* Per-CPU 统计 */
    pstats = this_cpu_ptr(g_zeta->percpu_stats);
    pstats->pkts_in++;

    now_us = zeta_now_us();

    conn = zeta_conn_find(iph->daddr, iph->saddr, th->dest, th->source);

    if (! conn)
        return NF_ACCEPT;

    spin_lock_bh(&conn->lock);

    conn->last_active_us = now_us;
    conn->last_active = now_us / 1000;

    if (th->ack) {
        u32 ack_seq = ntohl(th->ack_seq);

        /* RTT 测量（微秒精度）*/
        if (conn->rtt_measure_start > 0) {
            if (zeta_seq_after(ack_seq, conn->rtt_measure_seq) ||
                ack_seq == conn->rtt_measure_seq) {
                if (now_us > conn->rtt_measure_start) {
                    u32 rtt_us = (u32)(now_us - conn->rtt_measure_start);
                    if (rtt_us > 0 && rtt_us < 30000000) {
                        zeta_learn_rtt_sample(conn, rtt_us);
                    }
                }
                conn->rtt_measure_start = 0;
                conn->rtt_measure_seq = 0;
            }
        }

        /* 更新 snd_una */
        if (zeta_seq_after(ack_seq, conn->snd_una)) {
            conn->snd_una = ack_seq;
            conn->bytes_acked += ack_seq - conn->last_ack;
            conn->features.loss_burst_count = 0;
        }
        /* DupACK 检测 */
        else if (ack_seq == conn->last_ack && conn->last_ack != 0) {
            conn->features.loss_burst_count++;
            if (conn->features.loss_burst_count == 3) {
                conn->pkts_lost++;
                conn->features.loss_total++;
                conn->features.loss_recent++;
                conn->last_loss_time_us = now_us;
                conn->last_loss_time = now_us / 1000;

                if (g_zeta->verbose) {
                    ZETA_LOG("[%pI4:%u] LOSS total=%u\n",
                             &conn->daddr, ntohs(conn->dport),
                             conn->features.loss_total);
                }
            }
        }

        conn->last_ack = ack_seq;
        zeta_learn_update(conn, th, 0, true);
    }

    spin_unlock_bh(&conn->lock);

    return NF_ACCEPT;
}

/* ========== 注册钩子 ========== */
int zeta_hooks_register(void)
{
    int ret;

    g_zeta->hook_out.hook = zeta_hook_out;
    g_zeta->hook_out.pf = NFPROTO_IPV4;
    g_zeta->hook_out.hooknum = NF_INET_LOCAL_OUT;
    g_zeta->hook_out.priority = NF_IP_PRI_FIRST;

    g_zeta->hook_in.hook = zeta_hook_in;
    g_zeta->hook_in.pf = NFPROTO_IPV4;
    g_zeta->hook_in.hooknum = NF_INET_LOCAL_IN;
    g_zeta->hook_in.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    ret = nf_register_net_hook(&init_net, &g_zeta->hook_out);
    if (ret) {
        ZETA_WARN("Failed to register outbound hook: %d\n", ret);
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &g_zeta->hook_in);
    if (ret) {
        ZETA_WARN("Failed to register inbound hook: %d\n", ret);
        nf_unregister_net_hook(&init_net, &g_zeta->hook_out);
        return ret;
    }
#else
    ret = nf_register_hook(&g_zeta->hook_out);
    if (ret) {
        ZETA_WARN("Failed to register outbound hook: %d\n", ret);
        return ret;
    }

    ret = nf_register_hook(&g_zeta->hook_in);
    if (ret) {
        ZETA_WARN("Failed to register inbound hook: %d\n", ret);
        nf_unregister_hook(&g_zeta->hook_out);
        return ret;
    }
#endif

    ZETA_LOG("NetFilter hooks registered\n");
    return 0;
}

void zeta_hooks_unregister(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &g_zeta->hook_in);
    nf_unregister_net_hook(&init_net, &g_zeta->hook_out);
#else
    nf_unregister_hook(&g_zeta->hook_in);
    nf_unregister_hook(&g_zeta->hook_out);
#endif

    ZETA_LOG("NetFilter hooks unregistered\n");
}