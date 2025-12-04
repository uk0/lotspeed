/*
 * zeta_cong.c - Zeta-TCP 混合拥塞检测
 *
 * 核心思想：
 * - 传统 TCP 仅依靠丢包检测拥塞（New Reno）
 * - 或仅依靠 RTT 变化检测（Vegas/FAST）
 * - Zeta-TCP 结合两者，计算拥塞概率
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include "zeta_tcp.h"

/*
 * 计算 RTT 梯度（趋势）
 * 正值表示 RTT 增加（可能拥塞）
 * 负值表示 RTT 减少（拥塞缓解）
 */
static s32 zeta_calc_rtt_gradient(struct zeta_rtt_info *rtt)
{
    u32 i, count;
    s64 sum_x = 0, sum_y = 0, sum_xy = 0, sum_xx = 0;
    s64 n, gradient;
    
    count = rtt->history_count;
    if (count < 4)
        return 0;
    
    /* 线性回归计算斜率 */
    for (i = 0; i < count; i++) {
        u32 idx = (rtt->history_idx + ZETA_RTT_HISTORY_SIZE - count + i) 
                  % ZETA_RTT_HISTORY_SIZE;
        s64 x = i;
        s64 y = rtt->history[idx];
        
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_xx += x * x;
    }
    
    n = count;
    /* gradient = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x * sum_x) */
    s64 denom = n * sum_xx - sum_x * sum_x;
    if (denom == 0)
        return 0;
    
    gradient = (n * sum_xy - sum_x * sum_y) * 1000 / denom;
    
    return (s32)gradient;
}

/*
 * 计算 RTT 基础的拥塞概率
 * 基于 TCP Vegas/FAST 的思想
 */
static u32 zeta_calc_rtt_cong_prob(struct zeta_rtt_info *rtt,
                                    struct zeta_cong_detector *cong)
{
    u32 prob = 0;
    u32 rtt_diff;
    u32 rtt_ratio;
    
    if (rtt->min_rtt == 0 || rtt->srtt == 0)
        return 0;
    
    /* 计算 RTT 膨胀率 */
    if (rtt->srtt > rtt->min_rtt) {
        rtt_diff = rtt->srtt - rtt->min_rtt;
        rtt_ratio = rtt_diff * 1000 / rtt->min_rtt;
    } else {
        rtt_ratio = 0;
    }
    
    /*
     * 拥塞概率计算：
     * - RTT 膨胀 < 10%: 概率 0-100
     * - RTT 膨胀 10-50%: 概率 100-500
     * - RTT 膨胀 50-100%: 概率 500-800
     * - RTT 膨胀 > 100%: 概率 800-1000
     */
    if (rtt_ratio < 100) {
        prob = rtt_ratio;
    } else if (rtt_ratio < 500) {
        prob = 100 + (rtt_ratio - 100) * 400 / 400;
    } else if (rtt_ratio < 1000) {
        prob = 500 + (rtt_ratio - 500) * 300 / 500;
    } else {
        prob = 800 + min_t(u32,rtt_ratio - 1000, 200U) * 200 / 200;
    }
    
    /* RTT 梯度修正：如果 RTT 在持续增加，增加概率 */
    if (cong->rtt_gradient > 0) {
        u32 gradient_factor = min_t(u32,(u32)cong->rtt_gradient / 10, 200U);
        prob = min_t(u32,prob + gradient_factor, 1000U);
    } else if (cong->rtt_gradient < 0) {
        /* RTT 在下降，降低概率 */
        u32 gradient_factor = min_t(u32,(u32)(-cong->rtt_gradient) / 10, 200U);
        prob = prob > gradient_factor ? prob - gradient_factor : 0;
    }
    
    return prob;
}

/*
 * 计算丢包基础的拥塞概率
 * 基于 TCP New Reno 的思想
 */
static u32 zeta_calc_loss_cong_prob(struct zeta_loss_detector *loss,
                                     struct zeta_cong_detector *cong)
{
    u32 prob = 0;
    
    /* 基于丢包率 */
    if (cong->loss_rate > 0) {
        /*
         * 丢包率 -> 拥塞概率：
         * - 丢包率 0-0.1%: 可能是随机丢包，概率低
         * - 丢包率 0.1-1%: 可能是轻微拥塞
         * - 丢包率 1-5%: 明显拥塞
         * - 丢包率 > 5%: 严重拥塞
         */
        if (cong->loss_rate < 1) {
            prob = cong->loss_rate * 100;
        } else if (cong->loss_rate < 10) {
            prob = 100 + (cong->loss_rate - 1) * 400 / 9;
        } else if (cong->loss_rate < 50) {
            prob = 500 + (cong->loss_rate - 10) * 300 / 40;
        } else {
            prob = 800 + min_t(u32,cong->loss_rate - 50, 200U) * 200 / 200;
        }
    }
    
    /* 重复 ACK 修正 */
    if (loss->dup_ack_count >= 3) {
        u32 dup_factor = min_t(u32,loss->dup_ack_count * 50, 300U);
        prob = min_t(u32,prob + dup_factor, 1000U);
    }
    
    /* ECN 修正 */
    if (cong->ecn_rate > 0) {
        u32 ecn_factor = min_t(u32,cong->ecn_rate * 2, 200U);
        prob = min_t(u32,prob + ecn_factor, 1000U);
    }
    
    return prob;
}

/*
 * Zeta-TCP 核心：混合拥塞概率计算
 * 综合 RTT 和丢包信息
 */
u32 zeta_calc_congestion_probability(struct zeta_flow_info *info,
                                      struct zeta_params *params)
{
    struct zeta_rtt_info *rtt = &info->rtt;
    struct zeta_loss_detector *loss = &info->loss;
    struct zeta_cong_detector *cong = &info->cong;
    
    u32 rtt_prob, loss_prob, final_prob;
    u32 alpha, beta;
    
    /* 计算 RTT 梯度 */
    cong->rtt_gradient = zeta_calc_rtt_gradient(rtt);
    
    /* 计算 RTT 基础的拥塞概率 */
    rtt_prob = zeta_calc_rtt_cong_prob(rtt, cong);
    
    /* 计算丢包基础的拥塞概率 */
    loss_prob = zeta_calc_loss_cong_prob(loss, cong);
    
    /*
     * 加权合并
     * alpha: RTT 权重
     * beta: 丢包权重
     * 
     * 在不同网络条件下动态调整权重：
     * - 无线网络（随机丢包多）：降低丢包权重
     * - 有线网络：两者权重相近
     * - 高延迟网络：增加 RTT 权重
     */
    alpha = params->cong_alpha;
    beta = params->cong_beta;
    
    /* 动态调整：如果丢包率很低但 RTT 膨胀明显，增加 RTT 权重 */
    if (cong->loss_rate < 5 && rtt_prob > 300) {
        alpha = alpha * 12 / 10;
        beta = beta * 8 / 10;
    }
    /* 如果丢包率高但 RTT 正常，增加丢包权重（可能是尾部丢包） */
    else if (cong->loss_rate > 10 && rtt_prob < 200) {
        alpha = alpha * 8 / 10;
        beta = beta * 12 / 10;
    }
    
    /* 归一化权重 */
    u32 total = alpha + beta;
    if (total == 0)
        total = 1000;
    
    final_prob = (rtt_prob * alpha + loss_prob * beta) / total;
    
    /* 限制范围 */
    if (final_prob > 1000)
        final_prob = 1000;
    
    cong->cong_probability = final_prob;
    
    /* 更新网络质量评估 */
    if (final_prob < ZETA_CONG_PROB_LOW) {
        cong->quality = ZETA_NET_EXCELLENT;
    } else if (final_prob < ZETA_CONG_PROB_MED) {
        cong->quality = ZETA_NET_GOOD;
    } else if (final_prob < ZETA_CONG_PROB_HIGH) {
        cong->quality = ZETA_NET_FAIR;
    } else if (final_prob < ZETA_CONG_PROB_CERTAIN) {
        cong->quality = ZETA_NET_POOR;
    } else {
        cong->quality = ZETA_NET_BAD;
    }
    
    return final_prob;
}

/*
 * 根据拥塞概率调整拥塞窗口
 */
void zeta_adjust_cwnd(struct zeta_flow_info *info, struct zeta_params *params)
{
    struct zeta_cong_detector *cong = &info->cong;
    struct zeta_win_ctrl *win = &info->win;
    u32 cong_prob = cong->cong_probability;
    u32 new_cwnd;
    
    /*
     * Zeta-TCP 窗口调整策略：
     * - 拥塞概率 < 10%: 激进增加（类似慢启动）
     * - 拥塞概率 10-30%: 缓慢增加
     * - 拥塞概率 30-60%: 保持不变
     * - 拥塞概率 60-90%: 缓慢减少
     * - 拥塞概率 > 90%: 快速减少（类似 New Reno）
     */
    
    new_cwnd = win->cwnd;
    
    if (cong_prob < ZETA_CONG_PROB_LOW) {
        /* 激进增加 */
        if (new_cwnd < win->ssthresh) {
            /* 慢启动：每个 RTT 翻倍 */
            new_cwnd = new_cwnd * 2;
        } else {
            /* 拥塞避免：每个 RTT 增加 1 MSS */
            new_cwnd = new_cwnd + info->mss;
        }
        cong->state = ZETA_STATE_OPEN;
    }
    else if (cong_prob < ZETA_CONG_PROB_MED) {
        /* 缓慢增加：每个 RTT 增加 0.5 MSS */
        new_cwnd = new_cwnd + info->mss / 2;
        cong->state = ZETA_STATE_OPEN;
    }
    else if (cong_prob < ZETA_CONG_PROB_HIGH) {
        /* 保持不变 */
        cong->state = ZETA_STATE_DISORDER;
    }
    else if (cong_prob < ZETA_CONG_PROB_CERTAIN) {
        /* 缓慢减少：减少 10% */
        new_cwnd = new_cwnd * 9 / 10;
        cong->state = ZETA_STATE_CWR;
    }
    else {
        /* 快速减少：减半（类似 New Reno） */
        new_cwnd = new_cwnd / 2;
        win->ssthresh = new_cwnd;
        cong->state = ZETA_STATE_RECOVERY;
    }
    
    /* 限制窗口大小 */
    if (new_cwnd < 2 * info->mss)
        new_cwnd = 2 * info->mss;
    if (new_cwnd > 1024 * 1024 * 1024)  /* 1GB */
        new_cwnd = 1024 * 1024 * 1024;
    
    win->cwnd = new_cwnd;
    
    /* 更新 pacing rate */
    if (params->enable_pacing && info->rtt.srtt > 0) {
        /* pacing_rate = cwnd / RTT * gain */
        win->pacing_rate = (u64)new_cwnd * 1000000 * params->pacing_gain / 
                           info->rtt.srtt / 1000;
    }
}

/*
 * 更新丢包率统计
 */
void zeta_update_loss_rate(struct zeta_flow_info *info, bool is_loss)
{
    struct zeta_loss_detector *loss = &info->loss;
    struct zeta_cong_detector *cong = &info->cong;
    u32 i, sum = 0;
    
    /* 记录到历史 */
    loss->loss_history[loss->loss_idx] = is_loss ?  1 : 0;
    loss->loss_idx = (loss->loss_idx + 1) % ZETA_LOSS_HISTORY_SIZE;
    if (loss->loss_count < ZETA_LOSS_HISTORY_SIZE)
        loss->loss_count++;
    
    /* 计算丢包率 */
    for (i = 0; i < loss->loss_count; i++) {
        sum += loss->loss_history[i];
    }
    
    if (loss->loss_count > 0) {
        cong->loss_rate = sum * 1000 / loss->loss_count;
    }
}