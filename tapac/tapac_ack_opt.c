/*
 * tapac_ack_opt.c - ACK 优化模块 v2.5
 * 恢复稳定版本
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "tapac.h"

/* ============ 快速路径检测 ============ */
void tapac_check_fast_path(struct tapac_engine *eng,
                           struct tapac_flow_info *info)
{
    if (! eng || !info)
        return;

    if (info->bytes_sent_total > eng->params.prio_thresh &&
        !(info->flags & FLOW_FLAG_LOSS_DETECTED) &&
        info->throughput_reduction_num == 0 &&
        info->dup_ack_count == 0 &&
        info->phase != PHASE_FAST_RECOVERY &&
        info->rtt.var_rtt < info->srtt / 4) {
        info->flags |= FLOW_FLAG_FAST_PATH;
    } else {
        info->flags &= ~FLOW_FLAG_FAST_PATH;
    }
}

/* ============ ACK 压缩决策 ============ */
bool tapac_should_compress_ack(struct tapac_engine *eng,
                               struct tapac_flow_info *info,
                               u32 ack_seq, u32 payload_len)
{
    if (!eng || !info)
        return false;

    if (eng->params.use_ack_scheduler)
        return false;

    if (payload_len > 0)
        return false;

    if (info->flags & FLOW_FLAG_FAST_PATH)
        return false;

    if (info->flags & FLOW_FLAG_LOSS_DETECTED)
        return false;

    if (ack_seq == info->last_ack_seq)
        return false;

    if (info->phase == PHASE_FAST_RECOVERY)
        return false;

    if (tapac_seq_gt(ack_seq, info->last_ack_seq)) {
        u32 delta = ack_seq - info->last_ack_seq;
        if (delta > 2 * eng->params.mss)
            return false;
    }

    if (info->flags & FLOW_FLAG_UPLOAD_ACCEL)
        return false;

    return true;
}

/* ============ 计算动态 ACK 延迟 ============ */
u32 tapac_calc_ack_delay(struct tapac_engine *eng,
                         struct tapac_flow_info *info)
{
    u32 delay;

    if (!eng || !info)
        return ACK_DELAY_MIN_MS;

    if ((info->flags & FLOW_FLAG_LOSS_DETECTED) ||
        info->phase == PHASE_FAST_RECOVERY) {
        return 1;
    }

    if (info->flags & FLOW_FLAG_UPLOAD_ACCEL) {
        if (info->srtt > 100000) {
            return 2;
        }
        delay = info->srtt / 32000;
        if (delay < 2)
            delay = 2;
        if (delay > 5)
            delay = 5;
        return delay;
    }

    if (info->phase == PHASE_SLOW_START) {
        return 3;
    }

    if (info->rtt.min_rtt > 0) {
        delay = info->rtt.min_rtt / 20000;
    } else if (info->srtt > 0) {
        delay = info->srtt / 20000;
    } else {
        delay = eng->params.ack_delay_ms;
    }

    if (delay < ACK_DELAY_MIN_MS)
        delay = ACK_DELAY_MIN_MS;
    if (delay > 10)
        delay = 10;

    return delay;
}

/* ============ 计算优化的 trigger ============ */
u32 tapac_calc_optimized_trigger(struct tapac_engine *eng,
                                 struct tapac_flow_info *info,
                                 u32 ack_delta, u32 payload_len,
                                 struct tapac_sack_info *sack)
{
    u32 trigger;
    u32 mss;

    if (!eng || !info)
        return 54;

    mss = eng->params.mss;

    if (ack_delta > 0) {
        if (info->phase == PHASE_SLOW_START) {
            trigger = (ack_delta + mss) * (mss + 54) / mss;

            if ((info->flags & FLOW_FLAG_HAS_SACK) &&
                !(info->flags & FLOW_FLAG_LOSS_DETECTED)) {
                trigger = trigger * 12 / 10;
            }
        } else if (info->phase == PHASE_FAST_RECOVERY) {
            trigger = ack_delta * (mss + 54) / mss / 2;
        } else {
            trigger = ack_delta * (mss + 54) / mss;

            if (info->flags & FLOW_FLAG_LOSS_DETECTED) {
                trigger = trigger * 6 / 10;
            }
        }
    } else if (payload_len > 0) {
        trigger = eng->params.min_win * (mss + 54);
    } else {
        trigger = eng->params.min_pkt_len;
    }

    if (sack && sack->num_blocks > 0 && sack->num_blocks <= 4) {
        u32 reduction = 10 - sack->num_blocks * 2;
        if (reduction < 4)
            reduction = 4;
        trigger = trigger * reduction / 10;
    }

    if (trigger < eng->params.min_pkt_len)
        trigger = eng->params.min_pkt_len;

    return trigger;
}

/* ============ 动态调整参数 ============ */
void tapac_dynamic_tuning(struct tapac_engine *eng)
{
    u32 avg_rtt;
    u32 throughput;
    u64 bdp;

    if (!eng)
        return;

    avg_rtt = eng->avg_rtt;
    throughput = eng->avg_throughput;

    /* BDP 自适应 bucket_size */
    if (throughput > 100 && avg_rtt > eng->params.min_rtt) {
        bdp = (u64)throughput * avg_rtt / 8000;
        bdp = bdp * 2;

        if (bdp < 2 * 1024 * 1024)
            bdp = 2 * 1024 * 1024;
        if (bdp > 64 * 1024 * 1024)
            bdp = 64 * 1024 * 1024;

        if ((u32)bdp > eng->params.bucket_size) {
            eng->params.bucket_size = (eng->params.bucket_size * 7 + (u32)bdp) / 8;
        }

        if (eng->params.separate_buckets) {
            eng->params.upload_bucket_size = eng->params.bucket_size / 2;
            if (eng->params.upload_bucket_size < 2 * 1024 * 1024)
                eng->params.upload_bucket_size = 2 * 1024 * 1024;
        }
    }

    /* RTT 自适应 ACK 延迟 */
    if (avg_rtt > eng->params.min_rtt) {
        u32 new_delay;

        if (avg_rtt > 150000) {
            new_delay = 2;
        } else if (avg_rtt > 100000) {
            new_delay = 3;
        } else if (avg_rtt > 50000) {
            new_delay = 5;
        } else {
            new_delay = avg_rtt / 10000;
        }

        if (new_delay < 2)
            new_delay = 2;
        if (new_delay > 10)
            new_delay = 10;

        eng->params.ack_delay_ms = (eng->params.ack_delay_ms + new_delay) / 2;
    }

    /* max_delay 调整 */
    if (avg_rtt > 0) {
        u32 new_max = avg_rtt / 2;
        if (new_max < 50000)
            new_max = 50000;
        if (new_max > 500000)
            new_max = 500000;
        eng->params.max_delay = (eng->params.max_delay + new_max) / 2;
    }

    /* 窗口放大倍数 - 只增不减 */
    if (avg_rtt > 200000) {
        if (eng->params.win_inflate_factor < 16)
            eng->params.win_inflate_factor = 16;
    } else if (avg_rtt > 150000) {
        if (eng->params.win_inflate_factor < 12)
            eng->params.win_inflate_factor = 12;
    } else if (avg_rtt > 100000) {
        if (eng->params.win_inflate_factor < 8)
            eng->params.win_inflate_factor = 8;
    } else if (avg_rtt > 50000) {
        if (eng->params.win_inflate_factor < 6)
            eng->params.win_inflate_factor = 6;
    }
}