/*
 * zeta_loss.c - Zeta-TCP 概率丢包检测
 */

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>      /* 添加这行：struct tcphdr 定义 */

#include "zeta_tcp.h"

/*
 * 计算单个包的丢包概率
 */
u32 zeta_calc_packet_loss_prob(struct zeta_flow_info *info,
                                u32 seq, u32 len)
{
    struct zeta_rtt_info *rtt = &info->rtt;
    struct zeta_loss_detector *loss = &info->loss;
    u32 prob = 0;
    u32 seq_end = seq + len;
    u32 rtt_elapsed;
    u32 now = zeta_get_time_us();
    int i;

    /* 如果已经被 SACK 确认，概率为 0 */
    for (i = 0; i < loss->sack.num_blocks; i++) {
        if (zeta_seq_leq(loss->sack.blocks[i].start, seq) &&
            zeta_seq_geq(loss->sack.blocks[i].end, seq_end)) {
            return 0;
        }
    }

    /* 如果已经被累积 ACK 确认，概率为 0 */
    if (zeta_seq_leq(seq_end, loss->snd_una)) {
        return 0;
    }

    /*
     * 因素 1: 时间因素
     */
    if (rtt->srtt > 0) {
        rtt_elapsed = now - info->last_update;

        if (rtt_elapsed > rtt->srtt * 2) {
            prob += min_t(u32, (rtt_elapsed - rtt->srtt * 2) * 100 / rtt->srtt, 300);
        }
    }

    /*
     * 因素 2: SACK 空洞
     */
    for (i = 0; i < loss->sack.num_blocks; i++) {
        if (zeta_seq_lt(seq_end, loss->sack.blocks[i].start)) {
            u32 gap = zeta_seq_diff(loss->sack.blocks[i].start, seq_end);
            prob += min_t(u32, 200 + gap / info->mss * 50, 500);
            break;
        }
    }

    /*
     * 因素 3: 重复 ACK - 修复：使用 min_t
     */
    if (loss->dup_ack_count >= 3 && seq == loss->dup_ack_seq) {
        prob += min_t(u32, (u32)loss->dup_ack_count * 100, 400);
    }

    /*
     * 因素 4: 后续包数量
     */
    if (zeta_seq_gt(loss->high_seq, seq_end)) {
        u32 following = zeta_seq_diff(loss->high_seq, seq_end);
        u32 following_pkts = following / info->mss;

        if (following_pkts >= 3) {
            prob += min_t(u32, (following_pkts - 2) * 50, 300);
        }
    }

    /* 限制概率范围 */
    if (prob > 1000)
        prob = 1000;

    return prob;
}

/*
 * 检查是否应该重传某个包
 */
bool zeta_should_retransmit(struct zeta_flow_info *info,
                             u32 seq, u32 len,
                             struct zeta_params *params)
{
    u32 loss_prob;

    loss_prob = zeta_calc_packet_loss_prob(info, seq, len);

    return loss_prob >= params->loss_prob_thresh;
}

/*
 * 处理收到的 ACK
 */
void zeta_process_ack(struct zeta_flow_info *info,
                       u32 ack_seq,
                       struct zeta_sack_info *sack,
                       struct zeta_params *params,
                       struct zeta_stats *stats)
{
    struct zeta_loss_detector *loss = &info->loss;
    bool is_new_ack = false;
    int i;

    /* 检查是否是新的 ACK */
    if (zeta_seq_gt(ack_seq, loss->snd_una)) {
        u32 acked = zeta_seq_diff(ack_seq, loss->snd_una);

        is_new_ack = true;
        loss->snd_una = ack_seq;
        info->bytes_acked += acked;

        /* 清除重复 ACK 计数 */
        loss->dup_ack_count = 0;

        /* 更新丢包率 - 成功确认 */
        zeta_update_loss_rate(info, false);

        /* 如果在恢复状态，检查是否完全恢复 */
        if (info->cong.state == ZETA_STATE_RECOVERY) {
            if (zeta_seq_geq(ack_seq, loss->high_seq)) {
                info->cong.state = ZETA_STATE_OPEN;
                stats->recovery_events++;
            }
        }
    }
    /* 重复 ACK */
    else if (ack_seq == loss->snd_una) {
        if (loss->dup_ack_seq != ack_seq) {
            loss->dup_ack_seq = ack_seq;
            loss->dup_ack_count = 1;
        } else {
            loss->dup_ack_count++;
        }

        /* 3 个重复 ACK */
        if (loss->dup_ack_count == params->dup_ack_thresh) {
            info->flags |= ZETA_FLAG_LOSS_SEEN;
            stats->loss_events++;

            /* 更新丢包率 - 检测到丢包 */
            zeta_update_loss_rate(info, true);
        }
    }

    /* 更新 SACK 信息 */
    if (sack && sack->num_blocks > 0) {
        u32 sacked = 0;

        memcpy(&loss->sack, sack, sizeof(*sack));
        loss->sack_seq = ack_seq;

        /* 统计 SACK 确认的包数 */
        for (i = 0; i < sack->num_blocks; i++) {
            sacked += zeta_seq_diff(sack->blocks[i].end, sack->blocks[i].start);
        }
        loss->sacked_out = sacked / info->mss;
    }

    /* 重新计算拥塞概率 */
    zeta_calc_congestion_probability(info, params);

    /* 调整窗口 */
    if (is_new_ack) {
        zeta_adjust_cwnd(info, params);
    }
}

/*
 * 解析 SACK 选项
 */
int zeta_parse_sack(struct tcphdr *th, u32 tcp_hdr_len,
                     struct zeta_sack_info *sack)
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

        if (kind == 5 && len >= 10) {
            int num_blocks = (len - 2) / 8;
            u8 *block_ptr = opt + 2;

            for (i = 0; i < num_blocks && i < ZETA_SACK_BLOCKS_MAX; i++) {
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