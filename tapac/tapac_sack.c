/*
 * tapac_sack.c - SACK 处理模块
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tapac.h"

/* ============ 解析 SACK 选项 ============ */
int tapac_parse_sack(struct tcphdr *th, u32 tcp_hdr_len,
                     struct tapac_sack_info *sack)
{
    u8 *opt, *end;
    u8 kind, len;
    int i;

    if (! th || ! sack)
        return 0;

    sack->num_blocks = 0;

    if (tcp_hdr_len <= 20)
        return 0;

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

        /* SACK Permitted: kind=4, len=2 */
        if (kind == 4 && len == 2) {
            /* 标记支持 SACK */
        }

        /* SACK: kind=5 */
        if (kind == 5 && len >= 10) {
            int num_blocks = (len - 2) / 8;
            u8 *block_ptr = opt + 2;

            for (i = 0; i < num_blocks && i < MAX_SACK_BLOCKS; i++) {
                sack->blocks[i].start = ntohl(*(u32 *)block_ptr);
                sack->blocks[i].end = ntohl(*(u32 *)(block_ptr + 4));
                block_ptr += 8;
            }
            sack->num_blocks = i;
            return i;
        }

        opt += len;
    }

    return 0;
}

/* ============ 更新接收到的 SACK 块 ============ */
void tapac_update_sack_blocks(struct tapac_flow_info *info, u32 seq, u32 len)
{
    struct tapac_sack_info *sack;
    int i, j;
    u32 end = seq + len;

    if (!info || len == 0)
        return;

    sack = &info->rcv_sack;

    /* 检查是否乱序 */
    if (seq != info->rcv_nxt) {
        /* 乱序数据，添加到 SACK 块 */
        if (sack->num_blocks < MAX_SACK_BLOCKS) {
            /* 尝试合并到现有块 */
            for (i = 0; i < sack->num_blocks; i++) {
                /* 可以合并到块的左边 */
                if (end == sack->blocks[i].start) {
                    sack->blocks[i].start = seq;
                    goto merge_check;
                }
                /* 可以合并到块的右边 */
                if (seq == sack->blocks[i].end) {
                    sack->blocks[i].end = end;
                    goto merge_check;
                }
            }

            /* 新块 */
            sack->blocks[sack->num_blocks].start = seq;
            sack->blocks[sack->num_blocks].end = end;
            sack->num_blocks++;
        }
    } else {
        /* 顺序数据，更新 rcv_nxt */
        info->rcv_nxt = end;

        /* 检查是否可以移除 SACK 块 */
        for (i = 0; i < sack->num_blocks; ) {
            if (tapac_seq_leq(sack->blocks[i].end, info->rcv_nxt)) {
                /* 这个块已经被确认，移除 */
                for (j = i; j < sack->num_blocks - 1; j++) {
                    sack->blocks[j] = sack->blocks[j + 1];
                }
                sack->num_blocks--;
            } else if (tapac_seq_lt(sack->blocks[i].start, info->rcv_nxt)) {
                /* 部分确认 */
                sack->blocks[i].start = info->rcv_nxt;
                i++;
            } else {
                i++;
            }
        }
    }
    return;

merge_check:
    /* 检查是否可以合并相邻块 */
    for (i = 0; i < sack->num_blocks - 1; i++) {
        for (j = i + 1; j < sack->num_blocks; j++) {
            if (sack->blocks[i].end == sack->blocks[j].start) {
                sack->blocks[i].end = sack->blocks[j].end;
                /* 移除块 j */
                for (; j < sack->num_blocks - 1; j++) {
                    sack->blocks[j] = sack->blocks[j + 1];
                }
                sack->num_blocks--;
                break;
            }
        }
    }
}

/* ============ 生成 SACK 选项 ============ */
int tapac_generate_sack(struct tapac_flow_info *info, u8 *opt_buf, int max_len)
{
    struct tapac_sack_info *sack;
    int i;
    int len;
    u8 *p;

    if (! info || ! opt_buf || max_len < 10)
        return 0;

    sack = &info->rcv_sack;

    if (sack->num_blocks == 0)
        return 0;

    /* 计算需要的长度: 2 (kind + len) + 8 * num_blocks */
    len = 2 + 8 * sack->num_blocks;
    if (len > max_len)
        len = 2 + 8 * ((max_len - 2) / 8);

    p = opt_buf;

    /* SACK 选项头 */
    *p++ = 5;  /* kind = SACK */
    *p++ = len;

    /* SACK 块 */
    for (i = 0; i < sack->num_blocks && (p - opt_buf + 8) <= len; i++) {
        *(u32 *)p = htonl(sack->blocks[i].start);
        p += 4;
        *(u32 *)p = htonl(sack->blocks[i].end);
        p += 4;
    }

    return len;
}

/* ============ 增强的丢包检测 ============ */
void tapac_detect_loss(struct tapac_engine *eng, struct tapac_flow_info *info,
                       u32 ack_seq, struct tapac_sack_info *sack)
{
    if (!info)
        return;

    /* 检测重复 ACK */
    if (ack_seq == info->last_ack_seq) {
        info->dup_ack_count++;

        /* 3 个重复 ACK = 快速重传 */
        if (info->dup_ack_count == 3) {
            info->flags |= FLOW_FLAG_LOSS_DETECTED;
            info->phase = PHASE_FAST_RECOVERY;
            if (eng)
                eng->stats.fast_retransmit++;
            TAPAC_LOG(eng, "Fast retransmit triggered, ack_seq=%u\n", ack_seq);
        }

        if (eng)
            eng->stats.loss_detected++;
    } else if (tapac_seq_gt(ack_seq, info->last_ack_seq)) {
        u32 advance = ack_seq - info->last_ack_seq;

        info->dup_ack_count = 0;

        /* 大幅前进表示恢复 */
        if (advance > 3 * 1460) {
            info->flags &= ~FLOW_FLAG_LOSS_DETECTED;
            if (info->phase == PHASE_FAST_RECOVERY)
                info->phase = PHASE_CONG_AVOID;
        }
    }

    /* SACK 处理 */
    if (sack && sack->num_blocks > 0) {
        info->flags |= FLOW_FLAG_HAS_SACK;
        info->sack_permitted = 1;

        if (eng)
            eng->stats.sack_parsed++;

        /* 有 SACK 块但 ACK 没前进 = hole */
        if (ack_seq == info->last_ack_seq && sack->num_blocks >= 1) {
            /* 计算 hole 大小 */
            u32 hole_start = ack_seq;
            u32 hole_end = sack->blocks[0].start;
            u32 hole_size = tapac_seq_diff(hole_end, hole_start);

            if (hole_size > 0 && hole_size < 100 * 1460) {
                info->flags |= FLOW_FLAG_LOSS_DETECTED;
            }
        }
    }
}