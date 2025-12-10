/*
 * APX 加速器 v6.0 - 智能重传模块
 * 实现启发式快速重传和突发丢包恢复
 */

#include "apx_core.h"

/**
 * apx_track_packet - 跟踪发送的数据包
 * @ctx: 流上下文
 * @skb: 数据包
 */
void apx_track_packet(struct apx_flow_context *ctx, struct sk_buff *skb)
{
    struct apx_retrans_controller *rtc = &ctx->retrans_ctrl;
    struct apx_packet_meta *meta;
    struct tcphdr *th = tcp_hdr(skb);
    struct sk_buff *track_skb;
    
    /* 在SKB控制块中存储元数据 */
    meta = (struct apx_packet_meta *)skb->cb;
    meta->seq = ntohl(th->seq);
    meta->tx_time = ktime_get_ns();
    meta->is_sacked = false;
    meta->is_retrans = false;
    meta->retrans_count = 0;
    
    /* 克隆并加入在途队列 */
    if (skb_queue_len(&rtc->inflight_queue) < MAX_QUEUE_LEN) {
        track_skb = skb_clone(skb, GFP_ATOMIC);
        if (track_skb) {
            skb_queue_tail(&rtc->inflight_queue, track_skb);
        }
    }
    
    /* 更新跟踪信息 */
    rtc->last_sent_seq = meta->seq + skb->len - (th->doff * 4);
    rtc->last_sent_time = meta->tx_time;
}

/**
 * apx_check_early_retransmit - 检查并触发早期重传
 * @ctx: 流上下文
 */
void apx_check_early_retransmit(struct apx_flow_context *ctx)
{
    struct apx_retrans_controller *rtc = &ctx->retrans_ctrl;
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    struct sk_buff *skb, *tmp;
    u64 now = ktime_get_ns();
    u32 rtt_us = rta->current_rtt ?: 50000; /* 默认50ms */
    u64 thresh_ns;
    
    /* 计算重传阈值 */
    if (rta->base_rtt < 10000) {
        /* 低延迟环境：1.5倍RTT */
        thresh_ns = (u64)rtt_us * 1500;
    } else {
        /* 高延迟环境：2倍RTT */
        thresh_ns = (u64)rtt_us * 2000;
    }
    
    /* 遍历在途队列 */
    skb_queue_walk_safe(&rtc->inflight_queue, skb, tmp) {
        struct apx_packet_meta *meta = (struct apx_packet_meta *)skb->cb;
        u64 age = now - meta->tx_time;
        
        /* 如果已确认，移除 */
        if (meta->is_sacked || before(meta->seq, ctx->last_ack)) {
            __skb_unlink(skb, &rtc->inflight_queue);
            kfree_skb(skb);
            continue;
        }
        
        /* 检查是否需要重传 */
        if (age > thresh_ns && meta->retrans_count < 3) {
            APX_DBG("⚡ 早期重传: seq=%u, 等待=%llu ns\n", meta->seq, age);
            
            /* 触发重传 */
            apx_trigger_fast_retransmit(ctx, skb);
            
            /* 更新元数据 */
            meta->is_retrans = true;
            meta->retrans_count++;
            meta->tx_time = now; /* 重置计时 */
            
            /* 统计 */
            rtc->early_retrans_count++;
        }
    }
}

/**
 * apx_trigger_fast_retransmit - 触发快速重传
 * @ctx: 流上下文
 * @orig_skb: 原始数据包
 */
void apx_trigger_fast_retransmit(struct apx_flow_context *ctx, struct sk_buff *orig_skb)
{
    struct apx_priority_queues *pq = &ctx->priority_queues;
    struct sk_buff *skb;
    u32 min_cwnd;
    
    /* 克隆数据包 */
    skb = skb_copy(orig_skb, GFP_ATOMIC);
    if (!skb) {
        APX_DBG("重传失败: 内存不足\n");
        return;
    }
    
    /* 标记为重传包，放入高优先级队列 */
    skb->mark = APX_MAGIC_MARK | 0x80000000; /* 高位标记重传 */
    
    /* 插入控制队列头部（最高优先级） */
    skb_queue_head(&pq->queues[APX_QUEUE_CONTROL], skb);
    atomic_inc(&pq->queue_lens[APX_QUEUE_CONTROL]);
    
    /* 统计 */
    ctx->packets_retransmitted++;
    ctx->retrans_ctrl.retrans_count++;
    
    /* 调整拥塞窗口 - 修复类型问题 */
    ctx->ssthresh = ctx->cwnd / 2;
    
    /* 确保类型一致：将 u16 转换为 u32 */
    min_cwnd = (u32)ctx->mss * 4;
    
    /* 使用 max_t 明确指定类型 */
    ctx->cwnd = max_t(u32, ctx->ssthresh, min_cwnd);
    
    APX_DBG("快速重传: cwnd=%u, ssthresh=%u\n", ctx->cwnd, ctx->ssthresh);
}

/**
 * apx_handle_dup_ack - 处理重复ACK
 * @ctx: 流上下文
 * @ack_seq: ACK序号
 */
void apx_handle_dup_ack(struct apx_flow_context *ctx, u32 ack_seq)
{
    struct apx_retrans_controller *rtc = &ctx->retrans_ctrl;
    struct apx_rtt_analyzer *rta = &ctx->rtt_analyzer;
    struct sk_buff *skb;
    
    if (ack_seq == rtc->last_ack) {
        rtc->dup_ack_count++;
        
        /* 根据网络状况调整重传阈值 */
        u8 dup_thresh = 3;
        if (rta->base_rtt < 10000) {
            dup_thresh = 2; /* 低延迟：2个重复ACK */
        } else if (rta->congestion_detected) {
            dup_thresh = 2; /* 拥塞时更敏感 */
        }
        
        if (rtc->dup_ack_count >= dup_thresh) {
            APX_DBG("检测到%u个重复ACK，触发重传\n", rtc->dup_ack_count);
            
            /* 查找并重传丢失的包 */
            skb_queue_walk(&rtc->inflight_queue, skb) {
                struct apx_packet_meta *meta = (struct apx_packet_meta *)skb->cb;
                if (meta->seq == ack_seq) {
                    apx_trigger_fast_retransmit(ctx, skb);
                    break;
                }
            }
            
            rtc->dup_ack_count = 0;
        }
    } else {
        rtc->dup_ack_count = 0;
        rtc->last_ack = ack_seq;
    }
}

/**
 * apx_cleanup_acked_packets - 清理已确认的数据包
 * @ctx:  流上下文
 * @ack_seq: ACK序号
 */
void apx_cleanup_acked_packets(struct apx_flow_context *ctx, u32 ack_seq)
{
    struct apx_retrans_controller *rtc = &ctx->retrans_ctrl;
    struct sk_buff *skb, *tmp;
    
    skb_queue_walk_safe(&rtc->inflight_queue, skb, tmp) {
        struct apx_packet_meta *meta = (struct apx_packet_meta *)skb->cb;
        
        if (before(meta->seq, ack_seq)) {
            __skb_unlink(skb, &rtc->inflight_queue);
            kfree_skb(skb);
        }
    }
}

EXPORT_SYMBOL_GPL(apx_track_packet);
EXPORT_SYMBOL_GPL(apx_check_early_retransmit);
EXPORT_SYMBOL_GPL(apx_trigger_fast_retransmit);
EXPORT_SYMBOL_GPL(apx_handle_dup_ack);
EXPORT_SYMBOL_GPL(apx_cleanup_acked_packets);