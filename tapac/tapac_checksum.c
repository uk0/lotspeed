/*
 * tapac_checksum.c - 校验和计算
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/checksum.h>

#include "tapac.h"

/* ============ 16位累加 ============ */
static u32 tapac_sum16(const u8 *p, size_t len)
{
    u32 sum = 0;

    while (len > 1) {
        sum += ((u32)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len)
        sum += (u32)p[0] << 8;

    return sum;
}

/* ============ 折叠为16位 ============ */
static __sum16 tapac_fold32(u32 sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (__sum16)(~sum);
}

/* ============ IPv4 头校验和 ============ */
static __sum16 tapac_ip4_csum(const struct iphdr *iph)
{
    u32 sum = tapac_sum16((const u8 *)iph, iph->ihl * 4);
    return tapac_fold32(sum);
}

/* ============ L4 校验和（含伪首部） ============ */
static __sum16 tapac_l4_csum(const struct iphdr *iph, const void *l4,
                              size_t len, u8 proto)
{
    u32 sum = 0;

    /* 伪首部 */
    sum += (ntohl(iph->saddr) >> 16) & 0xFFFF;
    sum += ntohl(iph->saddr) & 0xFFFF;
    sum += (ntohl(iph->daddr) >> 16) & 0xFFFF;
    sum += ntohl(iph->daddr) & 0xFFFF;
    sum += proto;
    sum += len;

    /* L4 数据 */
    sum += tapac_sum16(l4, len);

    return tapac_fold32(sum);
}

/* ============ 修正校验和 ============ */
void tapac_fix_checksums(struct sk_buff *skb, bool force_sw)
{
    struct iphdr *iph;
    void *l4;
    u16 ip_tot_len;
    u16 ihl_bytes;
    u16 l4_len;

    if (!skb)
        return;

    if (! pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4)
        return;

    ihl_bytes = iph->ihl * 4;
    if (ihl_bytes < sizeof(struct iphdr))
        return;

    if (! pskb_may_pull(skb, ihl_bytes))
        return;

    ip_tot_len = ntohs(iph->tot_len);
    if (ip_tot_len < ihl_bytes)
        return;

    if (! pskb_may_pull(skb, ip_tot_len))
        return;

    /* 硬件校验和 */
    if (! force_sw && skb->ip_summed == CHECKSUM_PARTIAL)
        return;

    l4 = (u8 *)iph + ihl_bytes;
    l4_len = ip_tot_len - ihl_bytes;

    /* IP 校验和 */
    iph->check = 0;
    iph->check = tapac_ip4_csum(iph);

    /* TCP 校验和 */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4;

        if (l4_len < sizeof(struct tcphdr))
            return;

        th->check = 0;
        th->check = tapac_l4_csum(iph, th, l4_len, IPPROTO_TCP);
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
    /* UDP 校验和 */
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4;

        if (l4_len < sizeof(struct udphdr))
            return;

        uh->check = 0;
        uh->check = tapac_l4_csum(iph, uh, l4_len, IPPROTO_UDP);
        if (uh->check == 0)
            uh->check = CSUM_MANGLED_0;
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
}

/* ============ 使用内核 API 的校验和修正 ============ */
void tapac_fix_checksums_kernel(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *th;
    int tcplen;

    if (!skb)
        return;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return;

    iph = ip_hdr(skb);
    if (! iph || iph->version != 4)
        return;

    if (iph->protocol != IPPROTO_TCP)
        return;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return;

    th = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
    tcplen = skb->len - iph->ihl * 4;

    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcplen, IPPROTO_TCP,
                                   csum_partial((char *)th, tcplen, 0));

    skb->ip_summed = CHECKSUM_UNNECESSARY;
}