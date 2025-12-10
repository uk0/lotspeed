/*
 * APX 加速器 v6.0 - 动态带宽探测模块
 * 实现ACK Train分析和实时带宽估算
 */

#include "apx_core.h"

/**
 * apx_update_bandwidth_estimate - 基于ACK Train更新带宽估算
 * @ctx: 流上下文
 * @ack_seq: ACK序号
 */
void apx_update_bandwidth_estimate(struct apx_flow_context *ctx, u32 ack_seq)
{
    struct apx_bandwidth_estimator *bwe = &ctx->bw_estimator;
    u64 now = ktime_get_ns();
    u64 time_delta;
    u32 data_acked;
    u64 instant_bw;
    
    /* 记录ACK train */
    bwe->ack_train[bwe->ack_index] = now;
    bwe->ack_seq[bwe->ack_index] = ack_seq;
    
    /* 计算瞬时带宽 */
    if (bwe->last_ack_time && after(ack_seq, bwe->last_ack_seq)) {
        time_delta = now - bwe->last_ack_time;
        data_acked = ack_seq - bwe->last_ack_seq;
        
        if (time_delta > 0) {
            /* 带宽 = 数据量 / 时间 (转换为bps) */
            instant_bw = (u64)data_acked * 8 * NSEC_PER_SEC;
            do_div(instant_bw, time_delta);
            
            /* 检测应用层限制 */
            if (atomic_read(&ctx->priority_queues.queue_lens[APX_QUEUE_BULK]) == 0) {
                bwe->is_app_limited = true;
            } else {
                bwe->is_app_limited = false;
                
                /* 指数加权移动平均 */
                if (bwe->smooth_bw == 0) {
                    bwe->smooth_bw = instant_bw;
                } else {
                    bwe->smooth_bw = (bwe->smooth_bw * 7 + instant_bw) >> 3;
                }
                
                /* 维护最大带宽样本 */
                bwe->max_bw_sample = max_t(u64, bwe->max_bw_sample, instant_bw);
            }
            
            /* 使用多个ACK对计算更准确的带宽 */
            if (bwe->bw_samples >= 4) {
                u8 old_index = (bwe->ack_index + ACK_TRAIN_SIZE - 4) & (ACK_TRAIN_SIZE - 1);
                time_delta = now - bwe->ack_train[old_index];
                data_acked = ack_seq - bwe->ack_seq[old_index];
                
                if (time_delta > 0 && ! bwe->is_app_limited) {
                    instant_bw = (u64)data_acked * 8 * NSEC_PER_SEC;
                    do_div(instant_bw, time_delta);
                    
                    /* 更激进的带宽估算 */
                    bwe->estimated_bw = max_t(u64, bwe->smooth_bw, instant_bw);
                    
                    /* 动态调整pacing rate */
                    if (g_cfg.dynamic_bw) {
                        /* Gain为1.25，允许超发探测带宽 */
                        ctx->dynamic_pacing_rate = min_t(u64, 
                                                         (bwe->estimated_bw * 125) / 100,
                                                         g_cfg.pacing_rate);
                        
                        APX_DBG("带宽探测: %llu Mbps (平滑:  %llu Mbps)\n",
                                bwe->estimated_bw / (1024*1024),
                                bwe->smooth_bw / (1024*1024));
                    }
                }
            }
        }
    }
    
    bwe->last_ack_time = now;
    bwe->last_ack_seq = ack_seq;
    bwe->ack_index = (bwe->ack_index + 1) & (ACK_TRAIN_SIZE - 1);
    bwe->bw_samples++;
}

/**
 * apx_calculate_bdp - 计算带宽延迟积
 * @ctx: 流上下文
 * 返回: BDP（字节）
 */
u64 apx_calculate_bdp(struct apx_flow_context *ctx)
{
    struct apx_bandwidth_estimator *bwe = &ctx->bw_estimator;
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    u64 bdp;
    u64 rate;
    
    /* 使用动态探测的带宽或默认配置 */
    if (g_cfg.dynamic_bw && bwe->estimated_bw > 0) {
        rate = bwe->estimated_bw / 8;  /* 转换为字节/秒 */
    } else {
        rate = ctx->dynamic_pacing_rate ?: g_cfg.pacing_rate;
    }
    
    /* 使用基线RTT计算BDP */
    if (rta->base_rtt > 0) {
        bdp = rate * rta->base_rtt;
        do_div(bdp, 1000000ULL);  /* 微秒转秒 */
    } else if (rta->min_rtt > 0) {
        bdp = rate * rta->min_rtt;
        do_div(bdp, 1000000ULL);
    } else {
        /* 默认假设50ms RTT */
        bdp = rate / 20;
    }
    
    return bdp;
}

/**
 * apx_adjust_window_by_bandwidth - 根据带宽调整窗口
 * @ctx: 流上下文
 */
void apx_adjust_window_by_bandwidth(struct apx_flow_context *ctx)
{
    struct apx_bandwidth_estimator *bwe = &ctx->bw_estimator;
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    u64 bdp = apx_calculate_bdp(ctx);
    u32 target_cwnd;
    u32 min_cwnd;
    
    /* 基础窗口 = BDP * 增益系数 */
    target_cwnd = (u32)min_t(u64, bdp * rta->cwnd_gain, g_cfg.max_cwnd);
    
    /* 如果检测到应用受限，不要激进增长 */
    if (bwe->is_app_limited) {
        target_cwnd = min_t(u32, target_cwnd, ctx->cwnd + ctx->mss);
    }
    
    /* 平滑调整，避免剧烈变化 */
    if (target_cwnd > ctx->cwnd) {
        /* 增长时更保守 */
        u32 increment = (target_cwnd - ctx->cwnd) / 4;
        ctx->cwnd = min_t(u32, ctx->cwnd + increment, target_cwnd);
    } else if (target_cwnd < ctx->cwnd) {
        /* 降低时也要平滑 */
        u32 decrement = (ctx->cwnd - target_cwnd) / 8;
        ctx->cwnd = max_t(u32, ctx->cwnd - decrement, target_cwnd);
    }
    
    /* 确保最小窗口 - 修复类型问题 */
    min_cwnd = (u32)ctx->mss * 4;
    if (ctx->cwnd < min_cwnd)
        ctx->cwnd = min_cwnd;
}

EXPORT_SYMBOL_GPL(apx_update_bandwidth_estimate);
EXPORT_SYMBOL_GPL(apx_calculate_bdp);
EXPORT_SYMBOL_GPL(apx_adjust_window_by_bandwidth);