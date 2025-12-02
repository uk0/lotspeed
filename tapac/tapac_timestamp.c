/*
 * tapac_timestamp.c - TCP 时间戳处理
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tapac.h"

/* ============ 查找 TCP Timestamp 选项 ============ */
static u8 *tapac_find_ts_option(struct tcphdr *th, u32 tcp_hdr_len)
{
    u8 *opt;
    u8 *end;
    u8 kind, len;

    if (tcp_hdr_len < 30)  /* 20 + 10 (timestamp) */
        return NULL;

    opt = (u8 *)th + 20;
    end = (u8 *)th + tcp_hdr_len;

    while (opt < end) {
        kind = *opt;

        if (kind == 0)  /* End of options */
            break;

        if (kind == 1) {  /* NOP */
            opt++;
            continue;
        }

        if (opt + 1 >= end)
            break;

        len = *(opt + 1);
        if (len < 2 || opt + len > end)
            break;

        if (kind == 8 && len == 10)  /* Timestamp */
            return opt;

        opt += len;
    }

    return NULL;
}

/* ============ 测量 RTT ============ */
u32 tapac_measure_rtt(struct sk_buff *skb, struct tapac_flow *flow)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 *tsecr;
    u32 rtt = 0;
    u32 tcp_hdr_len;

    if (!skb || !flow)
        return 0;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return 0;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;

    ts_opt = tapac_find_ts_option(th, tcp_hdr_len);
    if (!ts_opt)
        return 0;

    /* TSecr 在 offset +6 */
    tsecr = (u32 *)(ts_opt + 6);

    /* 计算 RTT */
    rtt = tapac_get_time_us() - ntohl(*tsecr);

    /* 修改 TSecr 为 jiffies，避免干扰 TCP 栈 */
    *tsecr = htonl(jiffies);

    return rtt;
}

/* ============ 修改 TSval ============ */
void tapac_stamp_tsval(struct sk_buff *skb, u32 tsval)
{
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *ts_opt;
    u32 *ts_val_ptr;
    u32 tcp_hdr_len;

    if (! skb)
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcp_hdr_len = th->doff * 4;

    ts_opt = tapac_find_ts_option(th, tcp_hdr_len);
    if (!ts_opt)
        return;

    /* TSval 在 offset +2 */
    ts_val_ptr = (u32 *)(ts_opt + 2);
    *ts_val_ptr = htonl(tsval);
}