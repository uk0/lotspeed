/*
 * APX 加速器 v6.0 - RTT趋势分析模块
 * 实现拥塞检测和动态增益调整
 */

#include "apx_core.h"

/* 前向声明 */
static void apx_adjust_gain_by_congestion_internal(struct apx_flow_context *ctx);

/**
 * apx_analyze_rtt_trend - 分析RTT趋势和拥塞状态
 * @ctx: 流上下文
 * @new_rtt: 新的RTT测量值（微秒）
 */
void apx_analyze_rtt_trend(struct apx_flow_context *ctx, u32 new_rtt)
{
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    u32 avg_rtt = 0, deviation = 0;
    u32 recent_avg = 0, older_avg = 0;
    int i, count;

    /* 记录历史 */
    rta->history[rta->history_index] = new_rtt;
    rta->history_index = (rta->history_index + 1) % RTT_HISTORY_SIZE;
    if (rta->history_count < RTT_HISTORY_SIZE)
        rta->history_count++;

    /* 更新当前RTT */
    rta->current_rtt = new_rtt;

    /* 维护基线RTT（长期最小值） */
    if (rta->base_rtt == 0 || new_rtt < rta->base_rtt * 95 / 100) {
        rta->base_rtt = new_rtt;
        APX_DBG("基线RTT更新: %u us\n", rta->base_rtt);
    }

    /* 维护最小RTT */
    if (rta->min_rtt == 0 || new_rtt < rta->min_rtt) {
        rta->min_rtt = new_rtt;
    }

    /* 计算排队延迟 */
    rta->queue_delay = (s32)(rta->current_rtt - rta->base_rtt);

    /* 计算平均值和标准差 */
    count = min_t(u8, rta->history_count, RTT_HISTORY_SIZE);
    for (i = 0; i < count; i++) {
        avg_rtt += rta->history[i];
    }
    if (count > 0)
        avg_rtt /= count;

    /* 计算抖动（简化的标准差） */
    for (i = 0; i < count; i++) {
        u32 diff = abs((int)(rta->history[i] - avg_rtt));
        deviation += diff;
    }
    if (count > 0)
        deviation /= count;
    rta->jitter = deviation;

    /* 趋势分析（需要足够的样本） */
    if (count >= 8) {
        /* 计算最近4个和之前4个的平均值 */
        for (i = 0; i < 4; i++) {
            int idx = (rta->history_index - 1 - i + RTT_HISTORY_SIZE) % RTT_HISTORY_SIZE;
            recent_avg += rta->history[idx];
            idx = (rta->history_index - 5 - i + RTT_HISTORY_SIZE) % RTT_HISTORY_SIZE;
            older_avg += rta->history[idx];
        }
        recent_avg /= 4;
        older_avg /= 4;

        /* 判断趋势 */
        if (recent_avg > older_avg * 115 / 100) {
            rta->trend = 1;  /* 上升趋势 */
            APX_DBG("RTT上升:  %u -> %u us\n", older_avg, recent_avg);
        } else if (recent_avg < older_avg * 85 / 100) {
            rta->trend = 2;  /* 下降趋势 */
            APX_DBG("RTT下降: %u -> %u us\n", older_avg, recent_avg);
        } else {
            rta->trend = 0;  /* 稳定 */
        }
    }

    /* 尖峰检测 */
    if (new_rtt > avg_rtt * 2 && new_rtt > rta->base_rtt * 3) {
        rta->spike_count++;
        APX_DBG("RTT尖峰:  %u us (平均: %u us)\n", new_rtt, avg_rtt);
    }

    /* 拥塞检测和增益调整 */
    apx_adjust_gain_by_congestion_internal(ctx);
}

/**
 * apx_adjust_gain_by_congestion_internal - 内部函数：根据拥塞状态调整增益
 * @ctx: 流上下文
 */
static void apx_adjust_gain_by_congestion_internal(struct apx_flow_context *ctx)
{
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    s32 queue_ratio;

    /* 计算排队延迟比例 */
    if (rta->base_rtt > 0) {
        queue_ratio = (rta->queue_delay * 100) / rta->base_rtt;
    } else {
        queue_ratio = 0;
    }

    /* 根据排队延迟调整窗口增益 */
    if (queue_ratio > 50) {
        /* 严重拥塞：降低增益 */
        rta->cwnd_gain = 2;
        rta->congestion_detected = true;
        ctx->ssthresh = ctx->cwnd * 3 / 4;
        APX_DBG("拥塞检测: 排队延迟=%d%%, 降低增益\n", queue_ratio);
    } else if (queue_ratio > 25) {
        /* 轻度拥塞：保守增益 */
        rta->cwnd_gain = 4;
        rta->congestion_detected = false;
    } else {
        /* 链路空闲：激进增益 */
        rta->cwnd_gain = g_cfg.initial_cwnd_scale;
        rta->congestion_detected = false;
    }

    /* 根据趋势进一步调整 */
    if (rta->trend == 1 && rta->jitter > rta->base_rtt / 4) {
        /* RTT上升且抖动大：进一步降低增益 */
        rta->cwnd_gain = max_t(u32, rta->cwnd_gain / 2, 1);
    }
}

/**
 * apx_adjust_gain_by_congestion - 公共接口：根据拥塞状态调整增益
 * @ctx: 流上下文
 */
void apx_adjust_gain_by_congestion(struct apx_flow_context *ctx)
{
    apx_adjust_gain_by_congestion_internal(ctx);
}

/**
 * apx_update_rtt - 更新RTT统计
 * @ctx: 流上下文
 * @measured_rtt: 测量的RTT（微秒）
 */
void apx_update_rtt(struct apx_flow_context *ctx, u32 measured_rtt)
{
    /* 健全性检查 */
    if (measured_rtt == 0)
        measured_rtt = 1000; /* 最小1毫秒 */

    /* 调用趋势分析 */
    apx_analyze_rtt_trend(ctx, measured_rtt);

    /* 根据新的增益调整窗口 */
    apx_adjust_window_by_bandwidth(ctx);
}

EXPORT_SYMBOL_GPL(apx_analyze_rtt_trend);
EXPORT_SYMBOL_GPL(apx_adjust_gain_by_congestion);
EXPORT_SYMBOL_GPL(apx_update_rtt);