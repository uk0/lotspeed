/*
 * zeta_learning.c - Learning Engine Implementation (v2 - 防抖动)
 * Core intelligence for congestion classification
 * Author: uk0
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include "zeta_core.h"

/* 整数平方根 */
static u32 zeta_isqrt(u32 n)
{
    u32 x, x1;
    
    if (n == 0)
        return 0;
    
    x = n;
    x1 = (x + 1) / 2;
    
    while (x1 < x) {
        x = x1;
        x1 = (x + n / x) / 2;
    }
    
    return x;
}

/* ========== RTT 特征提取 (改进版 - 过滤异常值) ========== */
static void zeta_update_rtt_features(struct zeta_conn *conn, u32 rtt_us)
{
    struct zeta_features *f = &conn->features;
    int i, valid_count = 0;
    u64 sum = 0;
    u64 variance_sum = 0;
    s64 trend_sum = 0;
    int trend_count = 0;
    u32 prev_rtt = 0;
    int samples_to_check;
    u32 median_estimate;
    
    /* 过滤明显异常值 */
    if (rtt_us == 0 || rtt_us > 10000000)  /* 超过 10s 的丢弃 */
        return;
    
    /* 动态异常值过滤: 如果已有样本，过滤掉超过中位数 10 倍的值 */
    if (f->rtt_avg > 0 && rtt_us > f->rtt_avg * 10) {
        return;  /* 这是异常值，跳过 */
    }
    
    /* 更新历史环形缓冲区 */
    conn->rtt_history[conn->rtt_history_idx].rtt_us = rtt_us;
    conn->rtt_history[conn->rtt_history_idx].timestamp = zeta_now_us();
    conn->rtt_history_idx = (conn->rtt_history_idx + 1) % ZETA_HISTORY_SIZE;
    
    /* 更新 min RTT (使用 EWMA 避免噪声) */
    if (f->rtt_min == 0 || rtt_us < f->rtt_min) {
        f->rtt_min = rtt_us;
    } else {
        /* min RTT 缓慢上升，防止过时 */
        f->rtt_min = (f->rtt_min * 255 + rtt_us) / 256;
        if (rtt_us < f->rtt_min)
            f->rtt_min = rtt_us;
    }
    
    /* 更新 max RTT */
    if (rtt_us > f->rtt_max) {
        f->rtt_max = rtt_us;
    } else {
        /* max RTT 缓慢下降 */
        f->rtt_max = (f->rtt_max * 255 + rtt_us) / 256;
        if (rtt_us > f->rtt_max)
            f->rtt_max = rtt_us;
    }
    
    /* 计算平均值 (只统计有效样本) */
    for (i = 0; i < ZETA_HISTORY_SIZE; i++) {
        u32 sample = conn->rtt_history[i].rtt_us;
        if (sample > 0 && sample < f->rtt_avg * 5 + 100000) {  /* 过滤异常 */
            sum += sample;
            valid_count++;
        }
    }
    
    if (valid_count > 0) {
        f->rtt_avg = (u32)div64_u64(sum, (u64)valid_count);
    }
    
    /* 计算方差 (排除异常值) */
    median_estimate = f->rtt_avg;
    if (valid_count > 1 && median_estimate > 0) {
        variance_sum = 0;
        for (i = 0; i < ZETA_HISTORY_SIZE; i++) {
            u32 sample = conn->rtt_history[i].rtt_us;
            /* 只统计在合理范围内的样本 */
            if (sample > 0 && sample < median_estimate * 3) {
                s64 diff = (s64)sample - (s64)median_estimate;
                variance_sum += (u64)(diff * diff);
            }
        }
        f->rtt_variance = (u32)div64_u64(variance_sum, (u64)valid_count);
    }
    
    /* 计算趋势: 正值表示 RTT 在增加 */
    samples_to_check = min(valid_count, 8);
    if (samples_to_check >= 3) {
        trend_sum = 0;
        trend_count = 0;
        prev_rtt = 0;
        
        for (i = 0; i < samples_to_check; i++) {
            int idx = (conn->rtt_history_idx - 1 - i + ZETA_HISTORY_SIZE) % ZETA_HISTORY_SIZE;
            u32 curr_rtt = conn->rtt_history[idx].rtt_us;
            
            /* 跳过异常值 */
            if (curr_rtt == 0 || (f->rtt_avg > 0 && curr_rtt > f->rtt_avg * 3))
                continue;
            
            if (prev_rtt > 0) {
                trend_sum += (s64)prev_rtt - (s64)curr_rtt;
                trend_count++;
            }
            prev_rtt = curr_rtt;
        }
        
        if (trend_count > 0) {
            f->rtt_trend = (s32)div64_s64(trend_sum, (s64)trend_count);
        }
    }
}

/* ========== 丢包模式分类 ========== */
static zeta_loss_pattern_t zeta_classify_loss_pattern(struct zeta_conn *conn)
{
    struct zeta_features *f = &conn->features;
    u64 now_ms = zeta_now_ms();
    u32 time_since_last_loss;
    u32 loss_rate_permille;
    
    if (f->loss_total == 0)
        return LOSS_NONE;
    
    time_since_last_loss = (u32)(now_ms - conn->last_loss_time);
    
    /* 阵发丢包 */
    if (f->loss_burst_count >= ZETA_LOSS_BURST_THRESH) {
        return LOSS_BURST;
    }
    
    /* 计算丢包率 */
    if (conn->pkts_sent > 20) {
        loss_rate_permille = zeta_div32(f->loss_total * 1000, conn->pkts_sent);
        
        if (loss_rate_permille <= 20 && time_since_last_loss > 500) {
            return LOSS_RANDOM;
        }
    }
    
    if (f->rtt_trend > 0 && f->loss_recent > 0) {
        return LOSS_TAIL;
    }
    
    return LOSS_RANDOM;
}

/* ========== 核心拥塞分类 (带防抖动) ========== */
zeta_cong_state_t zeta_learn_classify(struct zeta_conn *conn)
{
    struct zeta_features *f = &conn->features;
    zeta_loss_pattern_t loss_pattern;
    u32 rtt_increase_pct;
    u32 rtt_jitter_pct;
    u32 std_dev;
    zeta_cong_state_t new_state;
    zeta_cong_state_t old_state = conn->state;
    static u32 state_hold_count = 0;  /* 状态保持计数 (防抖) */
    
    atomic64_inc(&g_zeta->stats.learning_decisions);
    
    /* 样本不足 */
    if (conn->pkts_sent < 5 || f->rtt_min == 0) {
        return ZETA_STATE_NORMAL;
    }
    
    /* 分析丢包 */
    loss_pattern = zeta_classify_loss_pattern(conn);
    conn->loss_pattern = loss_pattern;
    
    /* RTT 增长百分比 */
    if (f->rtt_min > 0 && f->rtt_avg > 0) {
        rtt_increase_pct = zeta_div32(f->rtt_avg * 100, f->rtt_min);
    } else {
        rtt_increase_pct = 100;
    }
    
    /* RTT 抖动百分比 */
    std_dev = zeta_isqrt(f->rtt_variance);
    if (f->rtt_avg > 0) {
        rtt_jitter_pct = zeta_div32(std_dev * 100, f->rtt_avg);
    } else {
        rtt_jitter_pct = 0;
    }
    
    /* ========== 拥塞判断 ========== */
    
    /* 阵发丢包 -> 严重拥塞 */
    if (loss_pattern == LOSS_BURST) {
        f->congestion_score = min_t(u32, f->congestion_score + 40, 100);
        new_state = ZETA_STATE_BURST_LOSS;
    }
    /* 延迟递增 (RTT 增长 > 50% 且有上升趋势) */
    else if (rtt_increase_pct >= 150 && f->rtt_trend > (s32)(f->rtt_min / 20)) {
        f->congestion_score = min_t(u32, f->congestion_score + 25, 100);
        new_state = ZETA_STATE_DELAY_RISING;
    }
    /* 尾部丢包 */
    else if (loss_pattern == LOSS_TAIL) {
        f->congestion_score = min_t(u32, f->congestion_score + 20, 100);
        new_state = ZETA_STATE_DELAY_RISING;
    }
    /* 随机丢包 + RTT 稳定 -> 非拥塞 */
    else if (loss_pattern == LOSS_RANDOM && rtt_increase_pct < 130) {
        if (f->congestion_score > 10)
            f->congestion_score -= 10;
        else
            f->congestion_score = 0;
        new_state = ZETA_STATE_RANDOM_LOSS;
    }
    /* RTT 高但稳定 (抖动 < 30%) -> 非拥塞 */
    else if (rtt_jitter_pct < 30 && f->rtt_trend >= -(s32)(f->rtt_min / 10) && 
             f->rtt_trend <= (s32)(f->rtt_min / 10)) {
        if (f->congestion_score > 8)
            f->congestion_score -= 8;
        else
            f->congestion_score = 0;
        new_state = ZETA_STATE_STABLE_DELAY;
    }
    /* 无丢包且 RTT 正常 */
    else if (loss_pattern == LOSS_NONE && rtt_increase_pct < 125) {
        if (f->congestion_score > 15)
            f->congestion_score -= 15;
        else
            f->congestion_score = 0;
        new_state = ZETA_STATE_NORMAL;
    }
    else {
        if (f->congestion_score > 5)
            f->congestion_score -= 5;
        new_state = old_state;  /* 保持当前状态 */
    }
    
    /* ========== 防抖动: 状态至少保持 5 个决策周期 ========== */
    if (new_state != old_state) {
        state_hold_count++;
        if (state_hold_count < 5) {
            /* 还没达到切换阈值，保持原状态 */
            new_state = old_state;
        } else {
            /* 达到阈值，允许切换 */
            state_hold_count = 0;
            
            /* 状态变化时记录日志 */
            if (g_zeta && g_zeta->verbose) {
                static const char *state_names[] = {
                    "NORMAL", "RAND_LOSS", "DELAY_UP", "BURST", "STABLE", "RECOVER"
                };
                ZETA_LOG("[%pI4:%u] STATE: %s -> %s | score=%u rtt=%u/%u/%u(+%u%%) trend=%d jitter=%u%% loss=%u\n",
                         &conn->daddr, ntohs(conn->dport),
                         state_names[old_state], state_names[new_state],
                         f->congestion_score,
                         f->rtt_min, f->rtt_avg, f->rtt_max, rtt_increase_pct,
                         f->rtt_trend, rtt_jitter_pct,
                         f->loss_total);
            }
        }
    } else {
        state_hold_count = 0;
    }
    
    return new_state;
}

/* ========== RTT 采样入口 ========== */
void zeta_learn_rtt_sample(struct zeta_conn *conn, u32 rtt_us)
{
    if (! conn || rtt_us == 0)
        return;
    
    zeta_update_rtt_features(conn, rtt_us);
}

/* ========== 主更新函数 ========== */
void zeta_learn_update(struct zeta_conn *conn, struct tcphdr *th, 
                       int payload_len, bool is_ack)
{
    zeta_cong_state_t new_state;
    
    if (!conn)
        return;
    
    /* 衰减丢包计数 */
    if (conn->pkts_sent > 0 && (conn->pkts_sent % 50) == 0) {
        if (conn->features.loss_recent > 0)
            conn->features.loss_recent = (conn->features.loss_recent * 3) / 4;
    }
    
    /* 带宽估计 */
    if (is_ack && conn->bytes_acked > 0 && conn->create_time > 0) {
        u64 elapsed_ms = zeta_now_ms() - conn->create_time;
        if (elapsed_ms > 100) {
            conn->features.bw_estimate = div64_u64(
                conn->bytes_acked * 1000ULL, elapsed_ms);
            if (conn->features.bw_estimate > conn->features.bw_max_seen) {
                conn->features.bw_max_seen = conn->features.bw_estimate;
            }
        }
    }
    
    /* 分类拥塞状态 */
    new_state = zeta_learn_classify(conn);
    conn->state = new_state;
}

/* ========== 获取建议的 CWND ========== */
u32 zeta_learn_get_cwnd(struct zeta_conn *conn)
{
    struct zeta_features *f = &conn->features;
    u32 bdp_pkts;
    u32 target_cwnd;
    
    if (f->bw_estimate > 0 && f->rtt_min > 0) {
        u64 bdp_bytes = div64_u64(f->bw_estimate * (u64)f->rtt_min, USEC_PER_SEC);
        bdp_pkts = (u32)div64_u64(bdp_bytes, 1460ULL);
        bdp_pkts = max_t(u32, bdp_pkts, 4);
    } else {
        bdp_pkts = 10;
    }
    
    switch (conn->state) {
        case ZETA_STATE_NORMAL:
        case ZETA_STATE_RANDOM_LOSS:
        case ZETA_STATE_STABLE_DELAY:
            target_cwnd = bdp_pkts * 2;
            break;
        case ZETA_STATE_DELAY_RISING:
            target_cwnd = (bdp_pkts * 7) / 10;
            break;
        case ZETA_STATE_BURST_LOSS:
            target_cwnd = bdp_pkts / 2;
            break;
        case ZETA_STATE_RECOVERING:
            target_cwnd = bdp_pkts;
            break;
        default:
            target_cwnd = bdp_pkts;
    }
    
    return clamp_t(u32, target_cwnd, ZETA_CWND_MIN, ZETA_CWND_MAX);
}

/* ========== 获取建议的速率 ========== */
u32 zeta_learn_get_rate(struct zeta_conn *conn)
{
    u32 cwnd = zeta_learn_get_cwnd(conn);
    u32 rtt_us = conn->features.rtt_avg;
    u64 rate;
    
    if (rtt_us == 0)
        rtt_us = 50000;
    
    rate = (u64)cwnd * 1460ULL * USEC_PER_SEC;
    rate = div64_u64(rate, (u64)rtt_us);
    
    if (g_zeta && rate > g_zeta->max_rate)
        rate = g_zeta->max_rate;
    
    return (u32)rate;
}