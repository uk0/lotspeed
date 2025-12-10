/* -*- indent-tabs-mode: t; tab-width: 8; c-basic-offset: 8; -*- */
/*
 * TCP Less C2 - 动态 AIMD 拥塞控制算法
 *
 * 改进点：
 * 1.动态计算 AIMD 参数，取代静态查表
 * 2.基于 RTT 梯度的拥塞预测
 * 3.带宽估计驱动的窗口调整
 * 4.自适应公平性因子
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>

/* ============== 内核版本兼容性 ============== */

/* inet_diag 相关头文件 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/inet_diag.h>
#define LESS_C2_HAS_GET_INFO 1
#else
#define LESS_C2_HAS_GET_INFO 0
#endif

/* pkts_acked 回调签名变化 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
#define LESS_C2_PKTS_ACKED_NEW 1
#else
#define LESS_C2_PKTS_ACKED_NEW 0
#endif

/* snd_cwnd 访问方式 (5.x+) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define CWND(tp)       tcp_snd_cwnd(tp)
#define CWND_SET(tp,v) tcp_snd_cwnd_set(tp, v)
#else
#define CWND(tp)       ((tp)->snd_cwnd)
#define CWND_SET(tp,v) ((tp)->snd_cwnd = (v))
#endif

/* ============== 可调参数 ============== */

/* 公平性因子 (0-100, 100=完全公平, 0=完全激进) */
static u32 fairness_factor __read_mostly = 50;
module_param(fairness_factor, uint, 0644);
MODULE_PARM_DESC(fairness_factor, "Fairness factor 0-100 (default: 50)");

/* 初始拥塞窗口 */
static u32 initial_cwnd __read_mostly = 10;
module_param(initial_cwnd, uint, 0644);
MODULE_PARM_DESC(initial_cwnd, "Initial cwnd (default: 10)");

/* RTT 拥塞阈值比例 (百分比) */
static u32 rtt_thresh_pct __read_mostly = 125;
module_param(rtt_thresh_pct, uint, 0644);
MODULE_PARM_DESC(rtt_thresh_pct, "RTT threshold percentage (default: 125)");

/* ============== 常量定义 ============== */

#define LESS_C2_SCALE		1024
#define LESS_C2_RTT_SCALE	8
#define LESS_C2_BW_SCALE	16
#define LESS_C2_MIN_CWND	2
#define LESS_C2_MAX_AI		100

#define HSTCP_LOW_WINDOW	38
#define HSTCP_HIGH_WINDOW	83000

/* ============== 数据结构 ============== */

struct less_c2 {
	/* RTT 测量 */
	u32	min_rtt;
	u32	avg_rtt;
	u32	prev_rtt;
	u32	max_rtt;
	
	/* RTT 梯度 */
	s32	rtt_gradient;
	u32	gradient_cnt;
	
	/* 带宽估计 */
	u64	bw_est;
	u32	delivered;
	u32	delivered_time;
	
	/* 动态 AIMD 参数 */
	u32	dynamic_ai;
	u32	dynamic_md;
	
	/* 状态跟踪 */
	u32	loss_cwnd;
	u8	in_slow_start;
	u8	congestion_level;
};

/* ============== 辅助函数 ============== */

static void less_c2_update_congestion_level(struct less_c2 *ca)
{
	u32 level = 0;
	u32 rtt_inflation;
	
	if (ca->min_rtt == 0 || ca->avg_rtt == 0)
		return;
	
	/* RTT 膨胀程度 (0-50分) */
	rtt_inflation = (ca->avg_rtt * 100) / ca->min_rtt;
	if (rtt_inflation > 100)
		level += min_t(u32, (rtt_inflation - 100) / 2, 50);
	
	/* RTT 梯度 (0-30分) */
	if (ca->rtt_gradient > 0) {
		u32 grad_pct = (ca->rtt_gradient * 100) / max_t(u32, ca->min_rtt, 1);
		level += min_t(u32, grad_pct, 30);
	}
	
	/* 缓冲区占用 (0-20分) */
	if (ca->max_rtt > ca->min_rtt) {
		u32 buffer_fill = ((ca->avg_rtt - ca->min_rtt) * 100) / 
				  (ca->max_rtt - ca->min_rtt);
		level += min_t(u32, buffer_fill / 5, 20);
	}
	
	ca->congestion_level = min_t(u32, level, 100);
}

static u32 less_c2_calc_ai(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 cwnd = CWND(tp);
	u32 ai;
	u32 cong_factor;
	
	if (cwnd <= HSTCP_LOW_WINDOW)
		return 1;
	
	ai = (cwnd * LESS_C2_SCALE) / (50 * LESS_C2_SCALE + cwnd * 5);
	ai = max_t(u32, ai, 1);
	ai = min_t(u32, ai, LESS_C2_MAX_AI);
	
	cong_factor = 100 - ca->congestion_level;
	ai = (ai * cong_factor) / 100;
	ai = (ai * (100 - fairness_factor) + fairness_factor) / 100;
	
	return max_t(u32, ai, 1);
}

static u32 less_c2_calc_md(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 cwnd = CWND(tp);
	u32 md;
	
	if (cwnd <= HSTCP_LOW_WINDOW)
		return 512;
	
	md = 512 + ((cwnd - HSTCP_LOW_WINDOW) * 410) / 
	     (HSTCP_HIGH_WINDOW - HSTCP_LOW_WINDOW);
	md = min_t(u32, md, 922);
	
	if (ca->congestion_level > 70)
		md = (md * 80) / 100;
	else if (ca->congestion_level < 30 && ca->rtt_gradient <= 0)
		md = min_t(u32, (md * 110) / 100, 922);
	
	return md;
}

static void less_c2_update_bw(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 now = tcp_jiffies32;
	u32 interval;
	u64 bw;
	
	ca->delivered += acked * tp->mss_cache;
	
	interval = now - ca->delivered_time;
	if (interval < msecs_to_jiffies(50))
		return;
	
	if (interval > 0) {
		bw = (u64)ca->delivered * HZ;
		do_div(bw, interval);
		
		if (ca->bw_est > 0)
			ca->bw_est = ca->bw_est - (ca->bw_est >> LESS_C2_BW_SCALE) 
				   + (bw >> LESS_C2_BW_SCALE);
		else
			ca->bw_est = bw;
	}
	
	ca->delivered = 0;
	ca->delivered_time = now;
}

/* ============== 核心回调函数 ============== */

static void tcp_less_c2_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);
	
	memset(ca, 0, sizeof(*ca));
	
	CWND_SET(tp, initial_cwnd);
	tp->snd_cwnd_clamp = min_t(u32, tp->snd_cwnd_clamp, 0xffffffff/128);
	
	ca->dynamic_ai = 1;
	ca->dynamic_md = 512;
	ca->in_slow_start = 1;
	ca->delivered_time = tcp_jiffies32;
}

/* RTT 计算 - 兼容不同内核版本 */
#if LESS_C2_PKTS_ACKED_NEW
static void tcp_less_c2_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 rtt;
	s32 gradient;
	s32 rtt_us = sample->rtt_us;
	u32 pkts_acked = sample->pkts_acked;
	
	if (rtt_us <= 0)
		return;
#else
static void tcp_less_c2_pkts_acked(struct sock *sk, u32 pkts_acked, s32 rtt_us)
{
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 rtt;
	s32 gradient;
	
	if (rtt_us <= 0)
		return;
#endif
	
	rtt = (u32)rtt_us;
	
	/* 更新 min/max RTT */
	if (ca->min_rtt == 0 || rtt < ca->min_rtt)
		ca->min_rtt = rtt;
	if (rtt > ca->max_rtt)
		ca->max_rtt = rtt;
	
	/* 更新平均 RTT */
	if (ca->avg_rtt > 0)
		ca->avg_rtt = ca->avg_rtt - (ca->avg_rtt >> LESS_C2_RTT_SCALE) 
			    + (rtt >> LESS_C2_RTT_SCALE);
	else
		ca->avg_rtt = rtt;
	
	/* 计算 RTT 梯度 */
	if (ca->prev_rtt > 0) {
		gradient = (s32)rtt - (s32)ca->prev_rtt;
		
		if (ca->gradient_cnt > 0)
			ca->rtt_gradient = ca->rtt_gradient - 
					   (ca->rtt_gradient >> 3) +
					   (gradient >> 3);
		else
			ca->rtt_gradient = gradient;
		
		ca->gradient_cnt++;
	}
	ca->prev_rtt = rtt;
	
	/* 更新拥塞程度和带宽 */
	less_c2_update_congestion_level(ca);
	less_c2_update_bw(sk, pkts_acked);
	
	/* 更新动态 AIMD 参数 */
	ca->dynamic_ai = less_c2_calc_ai(sk);
	ca->dynamic_md = less_c2_calc_md(sk);
}

static bool less_c2_should_exit_slow_start(struct sock *sk)
{
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 thresh;
	
	if (ca->min_rtt == 0)
		return false;
	
	thresh = (ca->min_rtt * rtt_thresh_pct) / 100;
	
	if (ca->avg_rtt > thresh)
		return true;
	
	if (ca->rtt_gradient > (s32)(ca->min_rtt >> 4) && ca->gradient_cnt > 3)
		return true;
	
	if (ca->congestion_level > 50)
		return true;
	
	return false;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
static void tcp_less_c2_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
#else
static void tcp_less_c2_cong_avoid(struct sock *sk, u32 ack, u32 acked)
#endif
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	if (! tcp_is_cwnd_limited(sk, in_flight))
#else
	if (!tcp_is_cwnd_limited(sk))
#endif
		return;
	
	/* 慢启动阶段 */
	if (CWND(tp) <= tp->snd_ssthresh) {
		ca->in_slow_start = 1;
		
		if (less_c2_should_exit_slow_start(sk)) {
			tp->snd_ssthresh = CWND(tp);
			ca->in_slow_start = 0;
			goto congestion_avoidance;
		}
		
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		tcp_slow_start(tp, acked);
#else
		tcp_slow_start(tp, acked);
#endif
		return;
	}
	
congestion_avoidance:
	ca->in_slow_start = 0;
	
	if (CWND(tp) < tp->snd_cwnd_clamp) {
		tp->snd_cwnd_cnt += ca->dynamic_ai;
		
		if (tp->snd_cwnd_cnt >= CWND(tp)) {
			tp->snd_cwnd_cnt -= CWND(tp);
			CWND_SET(tp, CWND(tp) + 1);
		}
	}
}

static u32 tcp_less_c2_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct less_c2 *ca = inet_csk_ca(sk);
	u32 new_cwnd;
	
	ca->loss_cwnd = CWND(tp);
	new_cwnd = (CWND(tp) * ca->dynamic_md) >> 10;
	
	return max_t(u32, new_cwnd, LESS_C2_MIN_CWND);
}

static u32 tcp_less_c2_undo_cwnd(struct sock *sk)
{
	struct less_c2 *ca = inet_csk_ca(sk);
	return ca->loss_cwnd;
}

static void tcp_less_c2_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct less_c2 *ca = inet_csk_ca(sk);
	
	switch (event) {
	case CA_EVENT_TX_START:
		ca->gradient_cnt = 0;
		break;
	case CA_EVENT_CWND_RESTART:
		ca->delivered = 0;
		ca->delivered_time = tcp_jiffies32;
		break;
	default:
		break;
	}
}

/* ============== 模块注册 ============== */

static struct tcp_congestion_ops tcp_less_c2 __read_mostly = {
	.init		= tcp_less_c2_init,
	.ssthresh	= tcp_less_c2_ssthresh,
	.cong_avoid	= tcp_less_c2_cong_avoid,
	.undo_cwnd	= tcp_less_c2_undo_cwnd,
	.cwnd_event	= tcp_less_c2_cwnd_event,
	.pkts_acked	= tcp_less_c2_pkts_acked,
	
	.owner		= THIS_MODULE,
	.name		= "less_c2",
};

static int __init tcp_less_c2_register(void)
{
	BUILD_BUG_ON(sizeof(struct less_c2) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_less_c2);
}

static void __exit tcp_less_c2_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_less_c2);
}

module_init(tcp_less_c2_register);
module_exit(tcp_less_c2_unregister);

MODULE_AUTHOR("Less");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Less C2 - Dynamic AIMD Congestion Control");
MODULE_VERSION("2.0");