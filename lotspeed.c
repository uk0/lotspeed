/*
 * LotSpeed v2 - Hybrid Congestion Control
 *
 * 整合 BBR v3 + FAST TCP 的混合拥塞控制算法
 * 仅支持 Linux Kernel 6.18.2+
 *
 * 核心设计:
 *   - 带宽估计: BBR 的 delivered/interval 方式
 *   - 延迟控制: FAST 的 alpha 队列目标
 *   - 状态机: 完整的 BBR v3 状态机
 *   - 历史学习: 连接历史缓存
 *   - 高延迟优化: Hybla 式 RTT^2 补偿
 *   - 抗抖动: 勇敢模式
 *   - 丢包/ECN: BBR 的上下界自适应
 *   - 诊断: get_info 接口
 *
 * sysctl 接口: /proc/sys/net/ipv4/lotspeed/
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/inet_diag.h>

/* ============== 版本和常量 ============== */

#define LS_VERSION              2
#define LS_VERSION_STR          "2.2.0"

#define BW_SCALE                24
#define BW_UNIT                 (1 << BW_SCALE)
#define LS_SCALE                8
#define LS_UNIT                 (1 << LS_SCALE)

#define LS_PROBE_RTT_MODE_MS    200
#define LS_PROBE_RTT_WIN_MS     5000
#define LS_MIN_RTT_WIN_SEC      10
#define LS_BW_PROBE_BASE_US     (2 * USEC_PER_SEC)
#define LS_BW_PROBE_RAND_US     (1 * USEC_PER_SEC)
#define LS_BW_PROBE_MAX_ROUNDS  63

/* RACK-TLP 常量 */
#define LS_RACK_REORD_THRESH    2       /* RACK 乱序阈值 */
#define LS_RACK_MIN_RTT_DIVISOR 8       /* RACK 最小 RTT 窗口 */
#define LS_TLP_MAX_PROBE_TIMEOUT 2      /* TLP 最大探测超时 (RTT 倍数) */

/* ============== sysctl 参数结构 ============== */

struct lotspeed_params {
	/* 基础参数 */
	unsigned int min_cwnd;
	unsigned int max_cwnd;
	unsigned int beta;              /* 丢包缩减: x/1024 */

	/* FAST 延迟控制参数 */
	unsigned int fast_alpha;        /* 目标队列长度 (packets) */
	unsigned int fast_gamma;        /* 平滑系数 (百分比) */

	/* 高延迟优化参数 */
	unsigned int hd_enable;
	unsigned int hd_thresh_us;      /* 高延迟阈值 */
	unsigned int hd_ref_us;         /* 参考 RTT */
	unsigned int hd_boost;          /* 高延迟提升百分比 */
	unsigned int hd_rho_max;        /* 最大 rho 系数 (百分比) */

	/* 勇敢模式参数 */
	unsigned int brave_enable;
	unsigned int brave_rtt_pct;     /* RTT 突增容忍度 */
	unsigned int brave_hold_ms;     /* 冻结时间 */
	unsigned int brave_floor_pct;   /* 冻结时窗口下限 */

	/* 历史缓存参数 */
	unsigned int hist_enable;
	unsigned int hist_ttl_sec;      /* TTL */
	unsigned int hist_max_entries;

	/* ECN 参数 */
	unsigned int ecn_enable;
	unsigned int ecn_factor;        /* ECN 缩减系数 (百分比) */
	unsigned int ecn_alpha_gain;    /* ECN alpha EWMA 增益 (1/16 = 6.25%) */
	unsigned int ecn_alpha_init;    /* ECN alpha 初始值 (256 = 1.0) */
	unsigned int ecn_thresh;        /* ECN 标记率阈值 (百分比) */
	unsigned int ecn_max_rtt_us;    /* 使用 ECN 的最大 RTT */
	unsigned int full_ecn_cnt;      /* STARTUP 退出的 ECN 轮次 */
	unsigned int ecn_reprobe_gain;  /* ECN 后重探增益 (百分比) */

	/* 启动优化参数 */
	unsigned int turbo_startup;
	unsigned int startup_gain;      /* 启动增益百分比 */
	unsigned int startup_min_rounds;/* 最少轮次 */

	/* ACK 聚合参数 */
	unsigned int ack_agg_enable;
	unsigned int extra_acked_max_us;

	/* 恢复优化参数 */
	unsigned int fast_recovery;
	unsigned int recovery_boost;

	/* pacing 参数 */
	unsigned int pacing_margin;     /* pacing 余量百分比 */
	unsigned int burst_mode;        /* 突发模式 */

	/* PROBE_RTT 参数 */
	unsigned int probe_rtt_cwnd_pct;/* PROBE_RTT 保留 cwnd */
	unsigned int probe_rtt_duration;/* PROBE_RTT 持续时间 */

	/* TSO 参数 */
	unsigned int tso_rtt_shift;

	/* 高延迟专用: 激进发包参数 */
	unsigned int hd_cwnd_gain;      /* 高延迟 cwnd 增益百分比 */
	unsigned int hd_pacing_gain;    /* 高延迟 pacing 增益百分比 */
	unsigned int hd_min_cwnd;       /* 高延迟最小 cwnd */
	unsigned int hd_startup_boost;  /* 高延迟启动额外增益 */

	/* 快速路径优化 */
	unsigned int fast_path;         /* 启用快速路径 */

	/* 丢包检测参数 */
	unsigned int loss_thresh;       /* 丢包率阈值 (百分比) */
	unsigned int full_loss_cnt;     /* STARTUP 退出的丢包事件数 */
	unsigned int inflight_headroom; /* inflight 安全余量 (百分比) */

	/* 带宽探测参数 */
	unsigned int bw_probe_max_rounds; /* 最大探测间隔轮次 */
	unsigned int bw_probe_base_us;  /* 探测基础间隔 (us) */
	unsigned int bw_probe_rand_us;  /* 探测随机间隔 (us) */
	unsigned int bw_probe_cwnd_gain;/* 探测时 cwnd 增益 */

	/* RACK-TLP 快速丢包检测参数 */
	unsigned int rack_enable;       /* 启用 RACK 检测 */
	unsigned int rack_reord_thresh; /* RACK 乱序阈值 (RTT 分数) */
	unsigned int rack_min_rtt_div;  /* RACK 最小 RTT 窗口 (除数) */
	unsigned int tlp_enable;        /* 启用 TLP 探测 */
	unsigned int tlp_timeout_div;   /* TLP 超时 (RTT 除数) */
	unsigned int tlp_max_probes;    /* 每轮最大 TLP 探测 */

	/* Hybla 增强参数 */
	unsigned int hybla_gain_exp;    /* Hybla 增益指数 (100=1.0, 150=1.5, 200=2.0) */
	unsigned int hybla_rtt_floor;   /* Hybla 最小 RTT 阈值 (us) */
};

/* 全局默认参数 */
static struct lotspeed_params ls_params = {
	.min_cwnd           = 64,
	.max_cwnd           = 15000,
	.beta               = 717,          /* 70% */

	.fast_alpha         = 20,
	.fast_gamma         = 50,

	.hd_enable          = 1,
	.hd_thresh_us       = 150000,       /* 150ms */
	.hd_ref_us          = 50000,        /* 50ms */
	.hd_boost           = 25,
	.hd_rho_max         = 400,          /* 4x */

	.brave_enable       = 1,
	.brave_rtt_pct      = 25,
	.brave_hold_ms      = 300,
	.brave_floor_pct    = 85,

	.hist_enable        = 1,
	.hist_ttl_sec       = 1200,         /* 20分钟 */
	.hist_max_entries   = 8192,

	.ecn_enable         = 1,
	.ecn_factor         = 85,

	.turbo_startup      = 1,
	.startup_gain       = 300,          /* 3x */
	.startup_min_rounds = 3,

	.ack_agg_enable     = 1,
	.extra_acked_max_us = 100000,       /* 100ms */

	.fast_recovery      = 1,
	.recovery_boost     = 20,

	.pacing_margin      = 2,
	.burst_mode         = 0,

	.probe_rtt_cwnd_pct = 50,
	.probe_rtt_duration = 150,

	.tso_rtt_shift      = 9,

	/* 高延迟专用参数 */
	.hd_cwnd_gain       = 150,          /* 1.5x cwnd */
	.hd_pacing_gain     = 130,          /* 1.3x pacing */
	.hd_min_cwnd        = 10,           /* 高延迟最小 cwnd */
	.hd_startup_boost   = 50,           /* 启动时额外 50% */

	/* ECN 高级参数 */
	.ecn_alpha_gain     = 16,           /* 1/16 = 6.25% EWMA */
	.ecn_alpha_init     = 256,          /* 1.0 初始值 */
	.ecn_thresh         = 50,           /* 50% ECN 标记率阈值 */
	.ecn_max_rtt_us     = 5000,         /* 5ms 以下使用 ECN */
	.full_ecn_cnt       = 2,            /* STARTUP 退出 ECN 轮次 */
	.ecn_reprobe_gain   = 50,           /* ECN 后重探增益 */

	/* 快速路径 */
	.fast_path          = 1,

	/* 丢包检测参数 */
	.loss_thresh        = 2,            /* 2% 丢包率阈值 */
	.full_loss_cnt      = 6,            /* STARTUP 退出丢包事件数 */
	.inflight_headroom  = 15,           /* 15% inflight 余量 */

	/* 带宽探测参数 */
	.bw_probe_max_rounds = 63,          /* 最大探测间隔轮次 */
	.bw_probe_base_us   = 2000000,      /* 2 秒基础间隔 */
	.bw_probe_rand_us   = 1000000,      /* 1 秒随机间隔 */
	.bw_probe_cwnd_gain = 1,            /* 探测 cwnd 增益 */

	/* RACK-TLP 快速丢包检测参数 */
	.rack_enable        = 1,            /* 启用 RACK */
	.rack_reord_thresh  = 4,            /* 1/4 RTT 乱序阈值 */
	.rack_min_rtt_div   = 8,            /* 最小 RTT 窗口 1/8 */
	.tlp_enable         = 1,            /* 启用 TLP */
	.tlp_timeout_div    = 2,            /* TLP 超时 = 2 * RTT */
	.tlp_max_probes     = 2,            /* 每轮最多 2 个 TLP */

	/* Hybla 增强参数 */
	.hybla_gain_exp     = 150,          /* rho^1.5 (150/100 = 1.5) */
	.hybla_rtt_floor    = 20000,        /* 20ms 最小 RTT 阈值 */
};

/* ============== sysctl 表定义 ============== */

static struct ctl_table_header *ls_sysctl_header;

static struct ctl_table ls_sysctl_table[] = {
	{
		.procname       = "min_cwnd",
		.data           = &ls_params.min_cwnd,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{
		.procname       = "max_cwnd",
		.data           = &ls_params.max_cwnd,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ONE,
		.extra2         = SYSCTL_INT_MAX,
	},
	{
		.procname       = "beta",
		.data           = &ls_params.beta,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "fast_alpha",
		.data           = &ls_params.fast_alpha,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "fast_gamma",
		.data           = &ls_params.fast_gamma,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_enable",
		.data           = &ls_params.hd_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "hd_thresh_us",
		.data           = &ls_params.hd_thresh_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_ref_us",
		.data           = &ls_params.hd_ref_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_boost",
		.data           = &ls_params.hd_boost,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_rho_max",
		.data           = &ls_params.hd_rho_max,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_cwnd_gain",
		.data           = &ls_params.hd_cwnd_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_pacing_gain",
		.data           = &ls_params.hd_pacing_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_min_cwnd",
		.data           = &ls_params.hd_min_cwnd,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hd_startup_boost",
		.data           = &ls_params.hd_startup_boost,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "brave_enable",
		.data           = &ls_params.brave_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "brave_rtt_pct",
		.data           = &ls_params.brave_rtt_pct,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "brave_hold_ms",
		.data           = &ls_params.brave_hold_ms,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "brave_floor_pct",
		.data           = &ls_params.brave_floor_pct,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hist_enable",
		.data           = &ls_params.hist_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "hist_ttl_sec",
		.data           = &ls_params.hist_ttl_sec,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hist_max_entries",
		.data           = &ls_params.hist_max_entries,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ecn_enable",
		.data           = &ls_params.ecn_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "ecn_factor",
		.data           = &ls_params.ecn_factor,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "turbo_startup",
		.data           = &ls_params.turbo_startup,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "startup_gain",
		.data           = &ls_params.startup_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "startup_min_rounds",
		.data           = &ls_params.startup_min_rounds,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ack_agg_enable",
		.data           = &ls_params.ack_agg_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "extra_acked_max_us",
		.data           = &ls_params.extra_acked_max_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "fast_recovery",
		.data           = &ls_params.fast_recovery,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "recovery_boost",
		.data           = &ls_params.recovery_boost,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "pacing_margin",
		.data           = &ls_params.pacing_margin,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "burst_mode",
		.data           = &ls_params.burst_mode,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "probe_rtt_cwnd_pct",
		.data           = &ls_params.probe_rtt_cwnd_pct,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "probe_rtt_duration",
		.data           = &ls_params.probe_rtt_duration,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "tso_rtt_shift",
		.data           = &ls_params.tso_rtt_shift,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* ECN 高级参数 */
	{
		.procname       = "ecn_alpha_gain",
		.data           = &ls_params.ecn_alpha_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ecn_alpha_init",
		.data           = &ls_params.ecn_alpha_init,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ecn_thresh",
		.data           = &ls_params.ecn_thresh,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ecn_max_rtt_us",
		.data           = &ls_params.ecn_max_rtt_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "full_ecn_cnt",
		.data           = &ls_params.full_ecn_cnt,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "ecn_reprobe_gain",
		.data           = &ls_params.ecn_reprobe_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* 快速路径 */
	{
		.procname       = "fast_path",
		.data           = &ls_params.fast_path,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	/* 丢包检测参数 */
	{
		.procname       = "loss_thresh",
		.data           = &ls_params.loss_thresh,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "full_loss_cnt",
		.data           = &ls_params.full_loss_cnt,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "inflight_headroom",
		.data           = &ls_params.inflight_headroom,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* 带宽探测参数 */
	{
		.procname       = "bw_probe_max_rounds",
		.data           = &ls_params.bw_probe_max_rounds,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "bw_probe_base_us",
		.data           = &ls_params.bw_probe_base_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "bw_probe_rand_us",
		.data           = &ls_params.bw_probe_rand_us,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "bw_probe_cwnd_gain",
		.data           = &ls_params.bw_probe_cwnd_gain,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* RACK-TLP 参数 */
	{
		.procname       = "rack_enable",
		.data           = &ls_params.rack_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "rack_reord_thresh",
		.data           = &ls_params.rack_reord_thresh,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "rack_min_rtt_div",
		.data           = &ls_params.rack_min_rtt_div,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "tlp_enable",
		.data           = &ls_params.tlp_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "tlp_timeout_div",
		.data           = &ls_params.tlp_timeout_div,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "tlp_max_probes",
		.data           = &ls_params.tlp_max_probes,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* Hybla 增强参数 */
	{
		.procname       = "hybla_gain_exp",
		.data           = &ls_params.hybla_gain_exp,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "hybla_rtt_floor",
		.data           = &ls_params.hybla_rtt_floor,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	/* 不再需要空终止符，使用 register_net_sysctl_sz */
};

/* ============== 状态机定义 ============== */

enum ls_mode {
	LS_STARTUP,
	LS_DRAIN,
	LS_PROBE_BW,
	LS_PROBE_RTT,
};

enum ls_bw_phase {
	LS_BW_CRUISE = 0,
	LS_BW_REFILL = 1,
	LS_BW_PROBE_UP = 2,
	LS_BW_PROBE_DOWN = 3,
};

static const int ls_pacing_gain[] = {
	LS_UNIT,                    /* CRUISE: 1.0 */
	LS_UNIT,                    /* REFILL: 1.0 */
	LS_UNIT * 5 / 4,            /* PROBE_UP: 1.25 */
	LS_UNIT * 3 / 4,            /* PROBE_DOWN: 0.75 */
};

/* ============== 核心数据结构 (扩展版 - 完整 BBR v3 功能) ============== */

/*
 * ICSK_CA_PRIV_SIZE = 16 * sizeof(u64) = 128 bytes (64-bit)
 * 扩展结构以支持完整的 BBR v3 功能
 */
struct lotspeed {
	/* === u64 字段区 (8 bytes) === */
	u64     ack_epoch_mstamp;       /* ACK 采样周期起点 */

	/* === u32 字段区 (80 bytes = 20 * 4) === */
	u32     min_rtt_us;             /* 最小 RTT */
	u32     min_rtt_stamp;          /* 最小 RTT 时间戳 */
	u32     probe_rtt_min_us;       /* 探测期最小 RTT */
	u32     probe_rtt_min_stamp;    /* 探测期 RTT 时间戳 */
	u32     bw_hi[2];               /* 带宽窗口最大值 */
	u32     bw_lo;                  /* 带宽下界 */
	u32     bw_latest;              /* 最新带宽样本 */
	u32     full_bw;                /* 最大带宽估计 */
	u32     inflight_lo;            /* inflight 下界 */
	u32     inflight_hi;            /* inflight 上界 */
	u32     inflight_latest;        /* 最新 inflight */
	u32     next_rtt_delivered;     /* 下一轮 delivered */
	u32     prior_cwnd;             /* 保存的 cwnd */
	u32     cycle_stamp;            /* 周期开始 (jiffies32) */
	u32     brave_freeze_until;     /* 勇敢模式冻结截止 */
	u32     loss_round_delivered;   /* 丢包轮 delivered */
	u32     ack_epoch_acked;        /* 采样期 ACK 数 */
	u32     alpha_last_delivered;   /* 上次 ECN alpha 计算时的 delivered */
	u32     alpha_last_delivered_ce;/* 上次 ECN alpha 计算时的 delivered_ce */

	/* === u16 字段区 (10 bytes) === */
	u16     pacing_gain;            /* 当前 pacing gain */
	u16     extra_acked[2];         /* ACK 聚合补偿窗口 */
	u16     ecn_alpha;              /* ECN 标记率 EWMA (0-256 scaled by BBR_UNIT) */
	u16     cwnd_gain;              /* 当前 cwnd gain */

	/* === u8 字段区 (8 bytes) === */
	u8      mode;                   /* ls_mode (0-3) */
	u8      cycle_idx;              /* ls_bw_phase (0-3) */
	u16     rho_scale;              /* 高延迟 rho (100=1.0x); u16 支持洲际 >2.55x 补偿 */
	u8      init_cwnd;              /* 初始 cwnd */
	u8      rounds_since_probe;     /* 距上次探测的轮次 */
	u8      startup_rounds;         /* 启动轮次计数 */
	u8      full_bw_cnt;            /* 带宽平台计数 */
	u8      extra_acked_win_rtts;   /* extra_acked 窗口 RTT 数 */

	/* === 标志位 byte 1 (8 bits) === */
	u8      full_bw_reached:1;      /* 达到满带宽 */
	u8      round_start:1;          /* 轮次开始 */
	u8      idle_restart:1;         /* 空闲重启 */
	u8      probe_rtt_round_done:1; /* PROBE_RTT 轮完成 */
	u8      loss_in_round:1;        /* 本轮有丢包 */
	u8      ecn_in_round:1;         /* 本轮有 ECN */
	u8      high_delay_path:1;      /* 高延迟路径 */
	u8      brave_active:1;         /* 勇敢模式激活 */

	/* === 标志位 byte 2 (8 bits) === */
	u8      initialized:1;          /* 已初始化 */
	u8      ecn_eligible:1;         /* 可使用 ECN */
	u8      in_recovery:1;          /* 处于恢复 */
	u8      recovery_started:1;     /* 恢复开始 */
	u8      extra_acked_win_idx:1;  /* extra_acked 窗口索引 */
	u8      probe_rtt_done:1;       /* PROBE_RTT 完成 */
	u8      loss_round_start:1;     /* 丢包轮开始 */
	u8      loss_in_cycle:1;        /* 周期内有丢包 */

	/* === 标志位 byte 3 (8 bits) === */
	u8      ecn_in_cycle:1;         /* 周期内有 ECN */
	u8      bw_probe_samples:1;     /* 正在收集带宽探测样本 */
	u8      prev_probe_too_high:1;  /* 上次探测过高 */
	u8      stopped_risky_probe:1;  /* 停止冒险探测 */
	u8      try_fast_path:1;        /* 尝试快速路径 */
	u8      full_bw_now:1;          /* 当前达到满带宽 */
	u8      has_seen_rtt:1;         /* 已观测到 RTT */
	u8      rack_detect_loss:1;     /* RACK 检测到丢包 */

	/* === 标志位 byte 4 (8 bits) - RACK-TLP === */
	u8      tlp_high_seq_set:1;     /* TLP high_seq 已设置 */
	u8      tlp_in_progress:1;      /* TLP 探测进行中 */
	u8      rack_reord_seen:1;      /* RACK 观察到乱序 */
	u8      unused:5;

	/* === RACK-TLP 状态 (8 bytes) === */
	u32     rack_rtt_us;            /* RACK 使用的 RTT */
	u32     rack_end_seq;           /* RACK 最高确认序列号 */
	u16     rack_xmit_ts;           /* RACK 传输时间戳 (相对) */
	u8      tlp_probes_out;         /* TLP 探测计数 */
	u8      startup_ecn_rounds;     /* 启动阶段 ECN 轮次 */

	/* 总计: 8 + 80 + 10 + 8 + 4 + 8 = 118 bytes
	 * 对齐到 120 bytes (满足 u64 对齐)
	 * 小于 ICSK_CA_PRIV_SIZE (128 bytes)
	 */
};

/* ============== 历史缓存 ============== */

struct ls_hist_entry {
	struct hlist_node   node;
	struct rcu_head     rcu;
	u32                 daddr;
	u64                 bw_bytes_sec;
	u32                 rtt_min_us;
	u32                 sample_cnt;
	u64                 last_update_jif;
};

#define LS_HIST_BITS 12
static DEFINE_HASHTABLE(ls_hist_table, LS_HIST_BITS);
static DEFINE_SPINLOCK(ls_hist_lock);
static struct kmem_cache *ls_hist_cache;
static atomic_t ls_hist_count = ATOMIC_INIT(0);

/* ============== 辅助函数 ============== */

#define SAFE_DIV(n, d) ((d) ? div64_u64((n), (d)) : 0)
#define SAFE_DIV32(n, d) ((d) ? (n) / (d) : 0)

static inline u32 ls_get_min_cwnd(void)
{
	return READ_ONCE(ls_params.min_cwnd);
}

static inline u32 ls_get_max_cwnd(void)
{
	return READ_ONCE(ls_params.max_cwnd);
}

static inline bool ls_can_use_ecn(const struct sock *sk)
{
	return READ_ONCE(ls_params.ecn_enable) &&
	       (tcp_sk(sk)->ecn_flags & TCP_ECN_OK);
}

/* ============== 带宽估计 ============== */

static u32 ls_max_bw(const struct sock *sk)
{
	const struct lotspeed *ls = inet_csk_ca(sk);
	return max(ls->bw_hi[0], ls->bw_hi[1]);
}

static u32 ls_bw(const struct sock *sk)
{
	const struct lotspeed *ls = inet_csk_ca(sk);
	return min(ls_max_bw(sk), ls->bw_lo);
}

static void ls_take_bw_sample(struct sock *sk, u32 bw)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls->bw_hi[1] = max(bw, ls->bw_hi[1]);
}

static void ls_advance_bw_filter(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	/* BBR v3 风格: 每个周期轮转窗口, 保持 1-2 个周期的最大值 */
	if (!ls->bw_hi[1])
		return;  /* 本窗口无样本，保留旧值 */
	ls->bw_hi[0] = ls->bw_hi[1];
	ls->bw_hi[1] = 0;
}

static u32 ls_calc_bw_sample(const struct rate_sample *rs)
{
	u64 bw;
	if (rs->interval_us <= 0 || rs->delivered <= 0)
		return 0;
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);
	return (u32)bw;
}

/* ============== Hybla 高延迟补偿 (增强版 rho^1.5) ============== */

/*
 * Hybla 核心思想: rho = max(rtt / rtt_ref, 1)
 *
 * v2.2.0 增强: 使用可配置的 rho 指数 (默认 1.5)
 * - rho^1.0: 线性补偿 (最保守)
 * - rho^1.5: 次线性补偿 (推荐, 平衡吞吐和公平性)
 * - rho^2.0: 二次补偿 (最激进, 可能不公平)
 *
 * rho^1.5 计算: sqrt(rho) * rho = rho * sqrt(rho)
 * 近似: (rho * isqrt(rho * 256)) >> 4
 */
static void ls_update_rho(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 ref_us = READ_ONCE(ls_params.hd_ref_us);
	u32 rho_max = READ_ONCE(ls_params.hd_rho_max);
	u32 rtt_floor = READ_ONCE(ls_params.hybla_rtt_floor);
	u64 rho;

	if (!READ_ONCE(ls_params.hd_enable) || ls->min_rtt_us == ~0U || ref_us == 0) {
		ls->rho_scale = 100;
		return;
	}

	/* 低于 rtt_floor 时不启用高延迟补偿 */
	if (ls->min_rtt_us < rtt_floor) {
		ls->rho_scale = 100;
		return;
	}

	/* rho = rtt / rtt_ref (以百分比表示, 100 = 1.0) */
	rho = (u64)ls->min_rtt_us * 100;
	do_div(rho, ref_us);
	rho = clamp_t(u64, rho, 100, rho_max);

	ls->rho_scale = (u16)rho;
}

/* 整数平方根近似 (用于 rho^0.5 计算) */
static u32 int_sqrt_approx(u32 x)
{
	u32 s, t;

	if (x < 2)
		return x;

	/* 牛顿法迭代 */
	s = x;
	t = x / 2 + 1;
	while (t < s) {
		s = t;
		t = (x / t + t) / 2;
	}
	return s;
}

/* 计算 Hybla 增强的 cwnd 增益 (支持 rho^1.5) */
static u32 ls_hybla_cwnd_gain(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 gain_exp = READ_ONCE(ls_params.hybla_gain_exp);
	u32 rho_max = READ_ONCE(ls_params.hd_rho_max);
	u64 gain;

	if (!ls->high_delay_path || ls->rho_scale <= 100)
		return 100;

	/*
	 * 根据配置的指数计算增益:
	 * - gain_exp = 100: rho^1.0 (线性)
	 * - gain_exp = 150: rho^1.5 (推荐)
	 * - gain_exp = 200: rho^2.0 (激进)
	 */
	if (gain_exp <= 100) {
		/* rho^1.0 - 线性补偿 */
		gain = ls->rho_scale;
	} else if (gain_exp <= 150) {
		/* rho^1.5 - sqrt(rho) * rho */
		u32 sqrt_rho = int_sqrt_approx(ls->rho_scale * 100);
		gain = (u64)ls->rho_scale * sqrt_rho;
		do_div(gain, 100);  /* 调整 sqrt 的缩放 */
	} else {
		/* rho^2.0 - 二次补偿 */
		gain = (u64)ls->rho_scale * ls->rho_scale;
		do_div(gain, 100);
	}

	/* 限制最大增益: 实测 rho^2(16x) 过冲增重传, 收敛到 rho_max(4x) */
	return min_t(u32, gain, rho_max);
}

/* 计算 Hybla 增强的 pacing 增益 */
static u32 ls_hybla_pacing_gain(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	if (!ls->high_delay_path || ls->rho_scale <= 100)
		return 100;

	/* 高延迟路径: pacing 增益 = rho */
	return min_t(u32, ls->rho_scale, READ_ONCE(ls_params.hd_pacing_gain));
}

/* ============== BDP 和 inflight ============== */

static u32 ls_bdp(struct sock *sk, u32 bw, int gain)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 bdp;
	u64 w;

	if (unlikely(ls->min_rtt_us == ~0U))
		return ls->init_cwnd;

	w = (u64)bw * ls->min_rtt_us;
	bdp = (((w * gain) >> LS_SCALE) + BW_UNIT - 1) / BW_UNIT;

	return bdp;
}

static u32 ls_inflight(struct sock *sk, u32 bw, int gain)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 inflight = ls_bdp(sk, bw, gain);
	u32 min_cwnd = ls_get_min_cwnd();

	/* 高延迟路径使用更高的最小 cwnd */
	if (ls->high_delay_path)
		min_cwnd = max(min_cwnd, READ_ONCE(ls_params.hd_min_cwnd));

	return max_t(u32, inflight, min_cwnd);
}

static u32 ls_inflight_with_headroom(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 headroom;

	if (ls->inflight_hi == ~0U)
		return ~0U;

	headroom = ls->inflight_hi >> 4;
	headroom = max(headroom, 1U);

	return max_t(s32, ls->inflight_hi - headroom, ls_get_min_cwnd());
}

/* ============== Pacing 速率 ============== */

static u64 ls_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 pacing_margin = READ_ONCE(ls_params.pacing_margin);
	u64 rate;

	rate = (u64)bw * tp->mss_cache;
	rate *= gain;
	rate >>= LS_SCALE;
	rate *= USEC_PER_SEC * (100 - pacing_margin) / 100;
	rate >>= BW_SCALE;
	rate = max(rate, 1ULL);

	/* 高延迟路径: 应用额外 pacing 增益 */
	if (ls->high_delay_path) {
		u32 hd_gain = ls_hybla_pacing_gain(sk);
		rate = rate * hd_gain / 100;
	}

	return min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
}

static void ls_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u64 rate = ls_bw_to_pacing_rate(sk, bw, gain);

	/* 高延迟路径: 额外提升 */
	if (ls->high_delay_path && READ_ONCE(ls_params.hd_enable)) {
		rate = rate * (100 + READ_ONCE(ls_params.hd_boost)) / 100;
	}

	/* 勇敢模式: 保持当前速率不降低 */
	if (ls->brave_active) {
		u64 cur_rate = READ_ONCE(sk->sk_pacing_rate);
		if (cur_rate > rate)
			rate = cur_rate;
	}

	if (ls->full_bw_reached || rate > READ_ONCE(sk->sk_pacing_rate))
		WRITE_ONCE(sk->sk_pacing_rate, rate);
}

/* ============== ACK 聚合补偿 ============== */

static u16 ls_extra_acked(const struct sock *sk)
{
	const struct lotspeed *ls = inet_csk_ca(sk);
	return max(ls->extra_acked[0], ls->extra_acked[1]);
}

static void ls_update_ack_aggregation(struct sock *sk, const struct rate_sample *rs)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 expected_acked, extra;
	u32 extra_acked_win_rtts_thresh = 5;

	if (!READ_ONCE(ls_params.ack_agg_enable) || rs->acked_sacked <= 0 ||
	    rs->delivered < 0 || rs->interval_us <= 0)
		return;

	if (ls->round_start) {
		ls->extra_acked_win_rtts = min_t(u32, 31, ls->extra_acked_win_rtts + 1);
		/* STARTUP 阶段更快轮转 */
		if (!ls->full_bw_reached)
			extra_acked_win_rtts_thresh = 1;
		if (ls->extra_acked_win_rtts >= extra_acked_win_rtts_thresh) {
			ls->extra_acked_win_rtts = 0;
			ls->extra_acked_win_idx = ls->extra_acked_win_idx ? 0 : 1;
			ls->extra_acked[ls->extra_acked_win_idx] = 0;
		}
	}

	/* 使用 interval_us 估算期望 ACK 数 */
	expected_acked = ((u64)ls_bw(sk) * rs->interval_us) / BW_UNIT;

	ls->ack_epoch_acked = min_t(u32, 0xFFFFF, ls->ack_epoch_acked + rs->acked_sacked);
	if (ls->ack_epoch_acked > expected_acked) {
		extra = ls->ack_epoch_acked - expected_acked;
		extra = min(extra, tcp_snd_cwnd(tp));
		if (extra > ls->extra_acked[ls->extra_acked_win_idx])
			ls->extra_acked[ls->extra_acked_win_idx] = min_t(u32, extra, 0xFFFF);
	}

	/* 定期重置采样周期 */
	if (ls->ack_epoch_acked >= (1U << 20)) {
		ls->ack_epoch_acked = 0;
		ls->ack_epoch_mstamp = tp->tcp_mstamp;
	}
}

static u32 ls_ack_aggregation_cwnd(struct sock *sk)
{
	u32 max_aggr_cwnd, aggr_cwnd = 0;

	if (!READ_ONCE(ls_params.ack_agg_enable))
		return 0;

	max_aggr_cwnd = ((u64)ls_bw(sk) * READ_ONCE(ls_params.extra_acked_max_us)) / BW_UNIT;
	aggr_cwnd = ls_extra_acked(sk);
	aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);

	return aggr_cwnd;
}

/* ============== 轮次跟踪 ============== */

static u32 ls_update_round_start(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 round_delivered = 0;

	ls->round_start = 0;

	if (rs->interval_us > 0 &&
	    !before(rs->prior_delivered, ls->next_rtt_delivered)) {
		round_delivered = tp->delivered - ls->next_rtt_delivered;
		ls->next_rtt_delivered = tp->delivered;
		ls->round_start = 1;
	}

	return round_delivered;
}

/* ============== 带宽平台检测 ============== */

static void ls_reset_full_bw(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls->full_bw = 0;
	ls->full_bw_cnt = 0;
}

static void ls_check_full_bw_reached(struct sock *sk, u32 bw_sample)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 bw_thresh;

	if (ls->full_bw_reached)
		return;

	if (ls->round_start && ls->mode == LS_STARTUP)
		ls->startup_rounds++;

	bw_thresh = (u64)ls->full_bw * LS_UNIT * 5 / 4 >> LS_SCALE;
	if (bw_sample >= bw_thresh) {
		ls_reset_full_bw(sk);
		ls->full_bw = bw_sample;
		return;
	}

	if (!ls->round_start)
		return;

	if (++ls->full_bw_cnt >= 3 &&
	    ls->startup_rounds >= READ_ONCE(ls_params.startup_min_rounds)) {
		ls->full_bw_reached = 1;
	}
}

/* ============== PROBE_RTT ============== */

static void ls_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	if (ls->mode != LS_PROBE_RTT)
		ls->prior_cwnd = tcp_snd_cwnd(tp);
	else
		ls->prior_cwnd = max(ls->prior_cwnd, tcp_snd_cwnd(tp));
}

static void ls_restore_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp), ls->prior_cwnd));
}

/* ============== 状态转换 ============== */

static void ls_enter_startup(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 startup_gain = READ_ONCE(ls_params.startup_gain);

	ls->mode = LS_STARTUP;
	ls->startup_rounds = 0;

	if (READ_ONCE(ls_params.turbo_startup)) {
		ls->pacing_gain = LS_UNIT * startup_gain / 100;
		/* 高延迟路径: 额外启动增益 */
		if (ls->high_delay_path) {
			u32 boost = READ_ONCE(ls_params.hd_startup_boost);
			ls->pacing_gain = ls->pacing_gain * (100 + boost) / 100;
		}
	} else {
		ls->pacing_gain = LS_UNIT * 277 / 100;  /* BBR 默认 */
	}
}

static void ls_enter_drain(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls->mode = LS_DRAIN;
	ls->pacing_gain = LS_UNIT * 35 / 100;
}

static void ls_enter_probe_bw(struct sock *sk, enum ls_bw_phase phase)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	ls->mode = LS_PROBE_BW;
	ls->cycle_idx = phase;
	ls->pacing_gain = ls_pacing_gain[phase];
	ls->cycle_stamp = tcp_jiffies32;

	/* 高延迟路径: 增强 pacing gain */
	if (ls->high_delay_path && phase == LS_BW_PROBE_UP) {
		ls->pacing_gain = ls->pacing_gain * ls_hybla_pacing_gain(sk) / 100;
	}

	if (phase == LS_BW_CRUISE || phase == LS_BW_PROBE_DOWN) {
		ls->loss_in_round = 0;
		ls->ecn_in_round = 0;
	}
}

static void ls_pick_probe_wait(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls->rounds_since_probe = get_random_u32_below(2);
	/* probe_wait 现在使用常量 LS_BW_PROBE_BASE_US */
}

static void ls_enter_probe_rtt(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	ls_save_cwnd(sk);
	ls->mode = LS_PROBE_RTT;
	ls->pacing_gain = LS_UNIT;
	ls->probe_rtt_done = 0;
	ls->cycle_stamp = tcp_jiffies32;  /* 复用 cycle_stamp 追踪 PROBE_RTT */
}

/* ============== min_rtt 更新 ============== */

static void ls_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	bool probe_rtt_expired, min_rtt_expired;
	u32 expire;

	/* 使用 min_rtt_stamp 追踪探测期 (简化) */
	expire = ls->min_rtt_stamp + msecs_to_jiffies(LS_PROBE_RTT_WIN_MS);
	probe_rtt_expired = after(tcp_jiffies32, expire);

	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us < ls->probe_rtt_min_us || probe_rtt_expired)) {
		ls->probe_rtt_min_us = rs->rtt_us;
	}

	/* 更新全局 min_rtt */
	expire = ls->min_rtt_stamp + LS_MIN_RTT_WIN_SEC * HZ;
	min_rtt_expired = after(tcp_jiffies32, expire);

	if (ls->probe_rtt_min_us <= ls->min_rtt_us || min_rtt_expired) {
		ls->min_rtt_us = ls->probe_rtt_min_us;
		ls->min_rtt_stamp = tcp_jiffies32;
		ls_update_rho(sk);
	}

	/* 检查是否需要进入 PROBE_RTT */
	if (probe_rtt_expired && !ls->idle_restart &&
	    ls->mode != LS_PROBE_RTT && LS_PROBE_RTT_MODE_MS > 0) {
		ls_enter_probe_rtt(sk);
	}

	/* PROBE_RTT 状态处理 */
	if (ls->mode == LS_PROBE_RTT) {
		u32 probe_cwnd = ls_get_min_cwnd();
		u32 elapsed;

		/* 优化: 保留部分 cwnd */
		if (READ_ONCE(ls_params.probe_rtt_cwnd_pct) > 0 && ls->prior_cwnd > 0) {
			probe_cwnd = max(probe_cwnd,
				ls->prior_cwnd * READ_ONCE(ls_params.probe_rtt_cwnd_pct) / 100);
		}

		tp->app_limited = (tp->delivered + tcp_packets_in_flight(tp)) ? : 1;

		/* 使用 cycle_stamp 追踪 PROBE_RTT 时间 */
		elapsed = tcp_jiffies32 - ls->cycle_stamp;

		if (!ls->probe_rtt_done &&
		    tcp_packets_in_flight(tp) <= probe_cwnd) {
			ls->probe_rtt_done = 1;
			ls->cycle_stamp = tcp_jiffies32;
			ls->probe_rtt_round_done = 0;
			ls->next_rtt_delivered = tp->delivered;
		} else if (ls->probe_rtt_done) {
			if (ls->round_start)
				ls->probe_rtt_round_done = 1;
			if (ls->probe_rtt_round_done &&
			    elapsed >= msecs_to_jiffies(READ_ONCE(ls_params.probe_rtt_duration))) {
				ls->min_rtt_stamp = tcp_jiffies32;
				ls_restore_cwnd(sk);
				if (ls->full_bw_reached) {
					ls_enter_probe_bw(sk, LS_BW_CRUISE);
					ls_pick_probe_wait(sk);
				} else {
					ls_enter_startup(sk);
				}
			}
		}
	}

	if (rs->delivered > 0)
		ls->idle_restart = 0;
}

/* ============== 勇敢模式 ============== */

static void ls_update_brave_mode(struct sock *sk, u32 rtt_us)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 rtt_thresh;

	if (!READ_ONCE(ls_params.brave_enable) || ls->min_rtt_us == 0)
		return;

	ls->brave_active = time_before((unsigned long)tcp_jiffies32,
	                               (unsigned long)ls->brave_freeze_until);

	rtt_thresh = ls->min_rtt_us +
	             (ls->min_rtt_us * READ_ONCE(ls_params.brave_rtt_pct)) / 100;

	if (rtt_us > rtt_thresh && tcp_snd_cwnd(tp) > ls_get_min_cwnd()) {
		ls->prior_cwnd = max(ls->prior_cwnd, tcp_snd_cwnd(tp));
		ls->brave_freeze_until = tcp_jiffies32 +
		                         msecs_to_jiffies(READ_ONCE(ls_params.brave_hold_ms));
		ls->brave_active = 1;
	}
}

/* ============== 高延迟路径检测 ============== */

static void ls_update_high_delay_path(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	bool was_high = ls->high_delay_path;

	ls->high_delay_path = READ_ONCE(ls_params.hd_enable) &&
	                      ls->min_rtt_us >= READ_ONCE(ls_params.hd_thresh_us);

	/* 高延迟状态变化时更新 rho */
	if (was_high != ls->high_delay_path)
		ls_update_rho(sk);
}

/* ============== 历史缓存 ============== */

static void ls_hist_lookup(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ls_hist_entry *entry;
	u32 daddr = sk->sk_daddr;

	if (!READ_ONCE(ls_params.hist_enable) || !daddr)
		return;

	rcu_read_lock();
	hash_for_each_possible_rcu(ls_hist_table, entry, node, daddr) {
		if (entry->daddr == daddr) {
			u64 age_ms = jiffies_to_msecs(get_jiffies_64() - entry->last_update_jif);
			if (age_ms < (u64)READ_ONCE(ls_params.hist_ttl_sec) * 1000 &&
			    entry->sample_cnt >= 3 &&
			    entry->rtt_min_us > 0) {
				ls->min_rtt_us = entry->rtt_min_us;
				ls->probe_rtt_min_us = entry->rtt_min_us;
				if (entry->bw_bytes_sec > 0 && tp->mss_cache > 0) {
					u32 cwnd = SAFE_DIV(entry->bw_bytes_sec * entry->rtt_min_us,
					                    (u64)tp->mss_cache * USEC_PER_SEC);
					tcp_snd_cwnd_set(tp, clamp_t(u32, cwnd,
						ls_get_min_cwnd(), ls_get_max_cwnd()));
					ls->full_bw_reached = 1;
					ls_update_high_delay_path(sk);
					ls_update_rho(sk);
					ls_enter_probe_bw(sk, LS_BW_CRUISE);
				}
			}
			break;
		}
	}
	rcu_read_unlock();
}

static void ls_hist_update(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ls_hist_entry *entry = NULL, *oldest = NULL;
	u32 daddr = sk->sk_daddr;
	u64 bw_bytes_sec = 0;
	u64 oldest_jif = ULLONG_MAX;
	int bkt;

	if (!READ_ONCE(ls_params.hist_enable) || !daddr || ls->min_rtt_us == 0)
		return;

	if (tcp_snd_cwnd(tp) > 0 && ls->min_rtt_us > 0 && tp->mss_cache > 0) {
		u64 bytes = (u64)tcp_snd_cwnd(tp) * tp->mss_cache;
		bw_bytes_sec = SAFE_DIV(bytes * USEC_PER_SEC, ls->min_rtt_us);
	}

	spin_lock_bh(&ls_hist_lock);

	hash_for_each_possible(ls_hist_table, entry, node, daddr) {
		if (entry->daddr == daddr) {
			entry->bw_bytes_sec = entry->bw_bytes_sec ?
				(entry->bw_bytes_sec * 7 + bw_bytes_sec * 3) / 10 : bw_bytes_sec;
			entry->rtt_min_us = entry->rtt_min_us ?
				min(entry->rtt_min_us, ls->min_rtt_us) : ls->min_rtt_us;
			entry->sample_cnt++;
			entry->last_update_jif = get_jiffies_64();
			goto out_unlock;
		}
	}

	if (atomic_read(&ls_hist_count) >= READ_ONCE(ls_params.hist_max_entries)) {
		struct ls_hist_entry *tmp;
		hash_for_each(ls_hist_table, bkt, tmp, node) {
			if (tmp->last_update_jif < oldest_jif) {
				oldest_jif = tmp->last_update_jif;
				oldest = tmp;
			}
		}
		if (oldest) {
			hash_del(&oldest->node);
			kmem_cache_free(ls_hist_cache, oldest);
			atomic_dec(&ls_hist_count);
		}
	}

	entry = kmem_cache_alloc(ls_hist_cache, GFP_ATOMIC);
	if (entry) {
		entry->daddr = daddr;
		entry->bw_bytes_sec = bw_bytes_sec;
		entry->rtt_min_us = ls->min_rtt_us;
		entry->sample_cnt = 1;
		entry->last_update_jif = get_jiffies_64();
		hash_add(ls_hist_table, &entry->node, daddr);
		atomic_inc(&ls_hist_count);
	}

out_unlock:
	spin_unlock_bh(&ls_hist_lock);
}

/* ============== FAST cwnd 计算 ============== */

static u32 ls_fast_cwnd(struct sock *sk, u32 cwnd, u32 rtt_us)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 base_rtt = ls->min_rtt_us;
	u32 alpha = READ_ONCE(ls_params.fast_alpha);
	u32 gamma = READ_ONCE(ls_params.fast_gamma);
	u64 cwnd_target;
	u32 new_cwnd;

	if (base_rtt == 0 || base_rtt == ~0U || rtt_us == 0)
		return cwnd;

	/* 高延迟路径: Hybla 式补偿 */
	if (ls->high_delay_path && READ_ONCE(ls_params.hd_enable)) {
		u32 hybla_gain = ls_hybla_cwnd_gain(sk);
		alpha = alpha * hybla_gain / 100;
		alpha += READ_ONCE(ls_params.hd_boost) / 5;
		gamma = min_t(u32, gamma + READ_ONCE(ls_params.hd_boost), 100);
	}

	/* FAST 核心公式 */
	cwnd_target = (u64)cwnd * base_rtt;
	do_div(cwnd_target, rtt_us);
	cwnd_target += alpha;

	new_cwnd = (cwnd * (100 - gamma) + cwnd_target * gamma) / 100;

	/* BBR 风格约束 */
	if (ls->inflight_hi != ~0U)
		new_cwnd = min(new_cwnd, ls->inflight_hi);
	if (ls->inflight_lo != ~0U)
		new_cwnd = min(new_cwnd, ls->inflight_lo);

	/* 勇敢模式 */
	if (ls->brave_active && ls->prior_cwnd > 0) {
		u32 floor = (ls->prior_cwnd * READ_ONCE(ls_params.brave_floor_pct)) / 100;
		new_cwnd = max(new_cwnd, floor);
	}

	/* 高延迟路径最小 cwnd */
	if (ls->high_delay_path) {
		new_cwnd = max(new_cwnd, READ_ONCE(ls_params.hd_min_cwnd));
	}

	return clamp_t(u32, new_cwnd, ls_get_min_cwnd(), ls_get_max_cwnd());
}

/* ============== cwnd 设置 ============== */

static void ls_set_cwnd(struct sock *sk, const struct rate_sample *rs,
                        u32 acked, u32 bw)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 cwnd = tcp_snd_cwnd(tp);
	u32 target_cwnd = 0;
	u32 rtt_us = rs->rtt_us > 0 ? rs->rtt_us : ls->min_rtt_us;
	u32 acked_boost = acked;

	/* 默认不启用快速路径 */
	ls->try_fast_path = 0;

	if (!acked)
		goto apply_cap;

	/* 高延迟路径: 增强 acked 增益 */
	if (ls->high_delay_path && ls->mode == LS_STARTUP) {
		u32 hybla_gain = ls_hybla_cwnd_gain(sk);
		acked_boost = acked * hybla_gain / 100;
	}

	switch (ls->mode) {
	case LS_STARTUP:
		if (READ_ONCE(ls_params.turbo_startup)) {
			cwnd += acked_boost + (acked_boost >> 1);
		} else {
			cwnd += acked_boost;
		}
		break;

	case LS_DRAIN:
		break;

	case LS_PROBE_BW:
		target_cwnd = ls_fast_cwnd(sk, cwnd, rtt_us);
		target_cwnd += ls_ack_aggregation_cwnd(sk);

		/* 高延迟路径: 应用 cwnd 增益 */
		if (ls->high_delay_path) {
			target_cwnd = target_cwnd *
				READ_ONCE(ls_params.hd_cwnd_gain) / 100;
		}

		switch (ls->cycle_idx) {
		case LS_BW_PROBE_UP:
			cwnd = max(cwnd, target_cwnd);
			if (ls->full_bw_reached && cwnd < target_cwnd)
				cwnd += acked;
			break;
		case LS_BW_PROBE_DOWN:
			cwnd = min(cwnd, target_cwnd);
			break;
		default:
			cwnd = target_cwnd;
			/* 达到目标 cwnd 时可启用快速路径 */
			if (ls->full_bw_reached)
				ls->try_fast_path = 1;
			break;
		}
		break;

	case LS_PROBE_RTT:
		if (READ_ONCE(ls_params.probe_rtt_cwnd_pct) > 0 && ls->prior_cwnd > 0) {
			u32 probe_cwnd = ls->prior_cwnd *
				READ_ONCE(ls_params.probe_rtt_cwnd_pct) / 100;
			cwnd = max_t(u32, probe_cwnd, ls_get_min_cwnd());
		} else {
			cwnd = ls_get_min_cwnd();
		}
		break;
	}

	/* 快速恢复优化 */
	if (READ_ONCE(ls_params.fast_recovery) && ls->in_recovery) {
		u32 recovery_target;
		if (ls->recovery_started) {
			ls->prior_cwnd = max(ls->prior_cwnd, cwnd);
			ls->recovery_started = 0;
		}
		recovery_target = ls->prior_cwnd *
			(100 + READ_ONCE(ls_params.recovery_boost)) / 100;
		cwnd = max(cwnd, recovery_target);
	}

apply_cap:
	cwnd = clamp_t(u32, cwnd, ls_get_min_cwnd(), ls_get_max_cwnd());

	if (ls->mode == LS_PROBE_BW && ls->cycle_idx == LS_BW_CRUISE) {
		cwnd = min(cwnd, ls_inflight_with_headroom(sk));
	}

	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));
}

/* ============== 丢包/ECN 响应 ============== */

/* BBR v3 风格: ECN alpha EWMA 更新 */
static int ls_update_ecn_alpha(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	s32 delivered, delivered_ce;
	u64 alpha, ce_ratio;
	u32 gain;

	/* 检查是否应该使用 ECN 逻辑 */
	if (!ls->ecn_eligible && ls_can_use_ecn(sk) &&
	    READ_ONCE(ls_params.ecn_factor) &&
	    (ls->min_rtt_us <= READ_ONCE(ls_params.ecn_max_rtt_us) ||
	     !READ_ONCE(ls_params.ecn_max_rtt_us)))
		ls->ecn_eligible = 1;

	if (!ls->ecn_eligible)
		return -1;

	delivered = tp->delivered - ls->alpha_last_delivered;
	delivered_ce = tp->delivered_ce - ls->alpha_last_delivered_ce;

	if (delivered == 0 || delivered < 0 || delivered_ce < 0)
		return -1;

	/* 计算 CE 比率 (0-256 scaled) */
	ce_ratio = (u64)delivered_ce << LS_SCALE;
	do_div(ce_ratio, delivered);

	/* EWMA 更新: alpha = (1 - gain) * alpha + gain * ce_ratio */
	gain = READ_ONCE(ls_params.ecn_alpha_gain);
	alpha = ((LS_UNIT - gain) * ls->ecn_alpha) >> LS_SCALE;
	alpha += (gain * ce_ratio) >> LS_SCALE;
	ls->ecn_alpha = min_t(u32, alpha, LS_UNIT);

	ls->alpha_last_delivered = tp->delivered;
	ls->alpha_last_delivered_ce = tp->delivered_ce;

	return (int)ce_ratio;
}

/* 检查 STARTUP 阶段 ECN 标记是否过高 */
static void ls_check_ecn_too_high_in_startup(struct sock *sk, u32 ce_ratio)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 ecn_thresh = READ_ONCE(ls_params.ecn_thresh);
	u32 full_ecn_cnt = READ_ONCE(ls_params.full_ecn_cnt);

	if (ls->full_bw_reached || !ls->ecn_eligible ||
	    !full_ecn_cnt || !ecn_thresh)
		return;

	/* ecn_thresh 是百分比, ce_ratio 是 0-256 */
	if (ce_ratio >= (ecn_thresh * LS_UNIT / 100))
		ls->startup_ecn_rounds++;
	else
		ls->startup_ecn_rounds = 0;

	if (ls->startup_ecn_rounds >= full_ecn_cnt) {
		ls->full_bw_reached = 1;
		ls->inflight_hi = max(ls_inflight(sk, ls_max_bw(sk), LS_UNIT),
		                       ls->inflight_latest);
	}
}

static void ls_init_lower_bounds(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	if (ls->bw_lo == ~0U)
		ls->bw_lo = ls_max_bw(sk);
	if (ls->inflight_lo == ~0U)
		ls->inflight_lo = tcp_snd_cwnd(tp);
}

static void ls_loss_lower_bounds(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 beta = READ_ONCE(ls_params.beta);

	ls_init_lower_bounds(sk);

	/* 使用 bw_latest 作为当前带宽样本 */
	ls->bw_lo = max_t(u32, ls->bw_latest,
	                  (u64)ls->bw_lo * beta >> 10);
	ls->inflight_lo = (u64)ls->inflight_lo * beta >> 10;
	ls->inflight_lo = max_t(u32, ls->inflight_lo, ls_get_min_cwnd());
}

static void ls_ecn_lower_bounds(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 ecn_cut;

	if (!ls->ecn_eligible)
		return;

	ls_init_lower_bounds(sk);

	ecn_cut = LS_UNIT * READ_ONCE(ls_params.ecn_factor) / 100;
	ls->inflight_lo = (u64)ls->inflight_lo * ecn_cut >> LS_SCALE;
}

static void ls_adapt_lower_bounds(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	if (ls->mode == LS_STARTUP ||
	    (ls->mode == LS_PROBE_BW && ls->cycle_idx == LS_BW_PROBE_UP))
		return;

	if (ls->ecn_in_round)
		ls_ecn_lower_bounds(sk);

	if (ls->loss_in_round)
		ls_loss_lower_bounds(sk);
}

static void ls_reset_lower_bounds(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls->bw_lo = ~0U;
	ls->inflight_lo = ~0U;
}

/* ============== RACK-TLP 快速丢包检测 ============== */

/*
 * RACK (Recent ACKnowledgment) 基于时间的丢包检测
 *
 * 核心思想: 如果一个包在发送后经过 min_rtt + reord_window 时间
 * 后仍未被 ACK，而较新的包已经被 ACK，则标记该包为丢失。
 *
 * 相比传统的 3-dupACK，RACK 可以:
 * - 更快检测尾部丢包
 * - 更好处理乱序
 * - 减少 RTO
 */

/* 更新 RACK 状态 */
static void ls_rack_update(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 rtt_us;

	if (!READ_ONCE(ls_params.rack_enable))
		return;

	/* 使用最新的 RTT 样本更新 RACK RTT */
	rtt_us = rs->rtt_us > 0 ? rs->rtt_us : ls->min_rtt_us;
	if (rtt_us > 0 && rtt_us != ~0U) {
		/* EWMA 平滑: 7/8 * old + 1/8 * new */
		if (ls->rack_rtt_us == 0)
			ls->rack_rtt_us = rtt_us;
		else
			ls->rack_rtt_us = (ls->rack_rtt_us * 7 + rtt_us) >> 3;
	}

	/* 更新 RACK 最高确认序列号 */
	if (after(tp->snd_una, ls->rack_end_seq))
		ls->rack_end_seq = tp->snd_una;
}

/* 计算 RACK 乱序窗口 */
static u32 ls_rack_reord_window(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 reord_thresh = READ_ONCE(ls_params.rack_reord_thresh);
	u32 min_rtt_div = READ_ONCE(ls_params.rack_min_rtt_div);
	u32 reord_window;

	if (ls->rack_rtt_us == 0)
		return 1000;  /* 默认 1ms */

	/* reord_window = RTT / reord_thresh */
	reord_window = ls->rack_rtt_us / reord_thresh;

	/* 至少是 min_rtt / min_rtt_div */
	if (ls->min_rtt_us != ~0U && min_rtt_div > 0) {
		u32 min_window = ls->min_rtt_us / min_rtt_div;
		reord_window = max(reord_window, min_window);
	}

	/* 最小 1ms，最大 200ms */
	return clamp_t(u32, reord_window, 1000, 200000);
}

/* RACK 检测丢包 */
static bool ls_rack_detect_loss(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 reord_window;
	bool loss_detected = false;

	if (!READ_ONCE(ls_params.rack_enable) || ls->rack_rtt_us == 0)
		return false;

	reord_window = ls_rack_reord_window(sk);

	/*
	 * 检测条件: 如果有未确认的数据，且距离最后一次 ACK 已经
	 * 超过 RTT + reord_window，则可能有丢包
	 */
	if (tp->packets_out > 0 && rs->interval_us > 0) {
		/* 检查是否超过乱序窗口 */
		if (rs->interval_us > ls->rack_rtt_us + reord_window) {
			loss_detected = true;
			ls->rack_detect_loss = 1;
		}
	}

	/* 观察到乱序时，增大乱序窗口容忍度 */
	if (rs->prior_delivered > 0 && tp->delivered > 0) {
		if (!ls->rack_reord_seen && rs->interval_us > ls->rack_rtt_us) {
			ls->rack_reord_seen = 1;
		}
	}

	return loss_detected;
}

/*
 * TLP (Tail Loss Probe) 尾部丢包探测
 *
 * 核心思想: 在 RTO 之前发送探测包，触发快速恢复
 * 比等待 RTO 快约 1.5-2 个 RTT
 */

/* 计算 TLP 超时时间 */
static u32 ls_tlp_timeout(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 timeout_div = READ_ONCE(ls_params.tlp_timeout_div);
	u32 tlp_timeout;

	if (!READ_ONCE(ls_params.tlp_enable))
		return 0;

	/* TLP 超时 = RTT * timeout_div */
	if (ls->min_rtt_us != ~0U && ls->min_rtt_us > 0) {
		tlp_timeout = ls->min_rtt_us * timeout_div;
	} else {
		/* 默认 100ms * 2 = 200ms */
		tlp_timeout = 200000;
	}

	/* 限制在 10ms - 2s */
	return clamp_t(u32, tlp_timeout, 10000, 2000000);
}

/* 检查是否需要 TLP */
static bool ls_should_tlp(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 max_probes = READ_ONCE(ls_params.tlp_max_probes);

	if (!READ_ONCE(ls_params.tlp_enable))
		return false;

	/* 已达到最大探测数 */
	if (ls->tlp_probes_out >= max_probes)
		return false;

	/* 需要有未确认数据 */
	if (tp->packets_out == 0)
		return false;

	/* 已经在恢复中，不需要 TLP */
	if (ls->in_recovery)
		return false;

	return true;
}

/* TLP 发送后更新状态 */
static void ls_tlp_sent(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	if (!READ_ONCE(ls_params.tlp_enable))
		return;

	ls->tlp_probes_out++;
	ls->tlp_in_progress = 1;
}

/* TLP 收到 ACK 后重置状态 */
static void ls_tlp_ack_received(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	if (ls->tlp_in_progress) {
		ls->tlp_in_progress = 0;
		/* TLP 成功，快速恢复比 RTO 好 */
	}
}

/* 综合 RACK-TLP 处理 */
static void ls_rack_tlp_main(struct sock *sk, const struct rate_sample *rs)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	/* 更新 RACK 状态 */
	ls_rack_update(sk, rs);

	/* RACK 丢包检测 */
	if (ls_rack_detect_loss(sk, rs)) {
		/* 检测到丢包，标记以便快速响应 */
		ls->loss_in_round = 1;
	}

	/* TLP ACK 处理 */
	if (rs->acked_sacked > 0 && ls->tlp_in_progress) {
		ls_tlp_ack_received(sk);
	}

	/* 每轮重置 TLP 计数 */
	if (ls->round_start) {
		ls->tlp_probes_out = 0;
		ls->rack_detect_loss = 0;
	}
}

/* ============== PROBE_BW 状态机 ============== */

static bool ls_has_elapsed_in_phase(struct sock *sk, u32 interval_ms)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 elapsed = tcp_jiffies32 - ls->cycle_stamp;
	return elapsed >= msecs_to_jiffies(interval_ms);
}

static bool ls_is_reno_coexist_probe_time(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 rounds = min_t(u32, LS_BW_PROBE_MAX_ROUNDS,
	                   ls_inflight(sk, ls_bw(sk), LS_UNIT));
	return ls->rounds_since_probe >= rounds;
}

/* BBR v3 风格: 基于丢包的 inflight_hi 计算 */
static void ls_inflight_hi_from_lost_skb(struct sock *sk,
                                          const struct rate_sample *rs,
                                          const struct sk_buff *skb)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 inflight_prev, lost_prefix, inflight_hi;

	inflight_prev = TCP_SKB_CB(skb)->tx.in_flight;
	lost_prefix = inflight_prev - TCP_SKB_CB(skb)->end_seq + tp->snd_una;

	if (lost_prefix == 0)
		return;

	/* 估算安全 inflight: 丢包点之前的 inflight */
	inflight_hi = inflight_prev;
	if (inflight_prev >= lost_prefix) {
		inflight_hi = inflight_prev - lost_prefix;
		/* 加入一些安全余量 */
		inflight_hi = max_t(u32, inflight_hi * 9 / 10, ls_get_min_cwnd());
	}

	if (ls->inflight_hi == ~0U || inflight_hi < ls->inflight_hi)
		ls->inflight_hi = inflight_hi;
}

static void ls_update_cycle_phase(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 inflight;

	if (ls->mode != LS_PROBE_BW)
		return;

	inflight = tcp_packets_in_flight(tp);

	switch (ls->cycle_idx) {
	case LS_BW_CRUISE:
		/* 使用固定 2 秒探测间隔 */
		if (ls_has_elapsed_in_phase(sk, 2000) ||
		    ls_is_reno_coexist_probe_time(sk)) {
			ls_reset_lower_bounds(sk);
			ls_enter_probe_bw(sk, LS_BW_REFILL);
		}
		break;

	case LS_BW_REFILL:
		if (ls->round_start) {
			ls_enter_probe_bw(sk, LS_BW_PROBE_UP);
			ls_reset_full_bw(sk);
		}
		break;

	case LS_BW_PROBE_UP:
		if (ls->full_bw_reached || ls->loss_in_round || ls->ecn_in_round) {
			if (ls->inflight_hi == ~0U || inflight > ls->inflight_hi)
				ls->inflight_hi = inflight;
			ls_enter_probe_bw(sk, LS_BW_PROBE_DOWN);
		}
		break;

	case LS_BW_PROBE_DOWN:
		if (inflight <= ls_inflight_with_headroom(sk)) {
			ls_advance_bw_filter(sk);
			ls_adapt_lower_bounds(sk);
			ls_enter_probe_bw(sk, LS_BW_CRUISE);
			ls_pick_probe_wait(sk);
		}
		break;
	}
}

/* ============== STARTUP/DRAIN ============== */

static void ls_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	if (ls->mode == LS_STARTUP && ls->full_bw_reached) {
		ls_enter_drain(sk);
		tp->snd_ssthresh = ls_inflight(sk, ls_max_bw(sk), LS_UNIT);
	}

	if (ls->mode == LS_DRAIN) {
		u32 target = ls_inflight(sk, ls_max_bw(sk), LS_UNIT);
		if (tcp_packets_in_flight(tp) <= target) {
			ls_enter_probe_bw(sk, LS_BW_CRUISE);
			ls_pick_probe_wait(sk);
		}
	}
}

/* ============== 主控制函数 ============== */

/* BBR v3 风格快速路径: 在 app-limited 且无拥塞信号时跳过部分更新 */
static bool ls_run_fast_path(struct sock *sk, const struct rate_sample *rs,
                              u32 bw_sample)
{
	struct lotspeed *ls = inet_csk_ca(sk);

	if (!READ_ONCE(ls_params.fast_path) || !ls->try_fast_path)
		return false;

	if (!rs->is_app_limited || bw_sample >= ls_max_bw(sk))
		return false;

	if (ls->loss_in_round || ls->ecn_in_round)
		return false;

	/* 快速路径: 只更新 min_rtt 和周期状态 */
	ls_check_drain(sk, rs);
	ls_update_cycle_phase(sk, rs);
	ls_update_min_rtt(sk, rs);

	return ls->try_fast_path;  /* 如果仍可快速路径，跳过其他更新 */
}

static void ls_main(struct sock *sk, const struct rate_sample *rs)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 bw_sample, bw;
	int ce_ratio = -1;

	if (!ls->initialized)
		return;

	ls_update_round_start(sk, rs);
	if (ls->round_start) {
		ls->rounds_since_probe = min_t(u32, ls->rounds_since_probe + 1, 255);
		/* 每轮更新 ECN alpha */
		ce_ratio = ls_update_ecn_alpha(sk);
		if (ce_ratio >= 0)
			ls_check_ecn_too_high_in_startup(sk, ce_ratio);
	}

	bw_sample = ls_calc_bw_sample(rs);

	/* 更新拥塞信号 */
	ls->loss_in_round |= (rs->losses > 0);
	ls->ecn_in_round |= (ls->ecn_eligible && rs->delivered_ce > 0);

	/* RACK-TLP 快速丢包检测 (在传统丢包信号之后) */
	ls_rack_tlp_main(sk, rs);

	/* 更新 bw_latest 和 inflight_latest */
	if (rs->interval_us > 0 && rs->acked_sacked > 0) {
		ls->bw_latest = max_t(u32, ls->bw_latest, bw_sample);
		ls->inflight_latest = max_t(u32, ls->inflight_latest, rs->delivered);
		if (!rs->is_app_limited || bw_sample >= ls_max_bw(sk))
			ls_take_bw_sample(sk, bw_sample);
	}

	/* 尝试快速路径 */
	if (ls_run_fast_path(sk, rs, bw_sample))
		goto out;

	ls_update_ack_aggregation(sk, rs);
	ls_update_high_delay_path(sk);

	if (rs->rtt_us > 0)
		ls_update_brave_mode(sk, rs->rtt_us);

	if (!ls->full_bw_reached)
		ls_check_full_bw_reached(sk, bw_sample);

	ls_check_drain(sk, rs);
	ls_update_cycle_phase(sk, rs);
	ls_update_min_rtt(sk, rs);

	bw = ls_bw(sk);

	ls_set_pacing_rate(sk, bw, ls->pacing_gain);
	ls_set_cwnd(sk, rs, rs->acked_sacked, bw);

out:
	/* 更新周期内拥塞标记 */
	ls->loss_in_cycle |= (rs->losses > 0);
	ls->ecn_in_cycle |= (rs->delivered_ce > 0);

	/* 每轮重置信号 */
	if (ls->round_start) {
		ls->bw_latest = bw_sample;
		ls->inflight_latest = rs->delivered;
		ls->loss_in_round = 0;
		ls->ecn_in_round = 0;
	}
}

/* ============== 回调函数 ============== */

static void ls_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	memset(ls, 0, sizeof(*ls));

	ls->initialized = 1;
	ls->init_cwnd = min(0x7FU, tcp_snd_cwnd(tp));
	ls->prior_cwnd = tp->prior_cwnd;
	ls->rho_scale = 100;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

	ls->min_rtt_us = tcp_min_rtt(tp) ? : ~0U;
	ls->min_rtt_stamp = tcp_jiffies32;
	ls->probe_rtt_min_us = ls->min_rtt_us;
	ls->probe_rtt_min_stamp = tcp_jiffies32;

	/* BBR v3 风格带宽窗口 */
	ls->bw_hi[0] = 0;
	ls->bw_hi[1] = 0;
	ls->bw_lo = ~0U;
	ls->bw_latest = 0;
	ls->inflight_lo = ~0U;
	ls->inflight_hi = ~0U;
	ls->inflight_latest = 0;

	/* ACK 聚合窗口 */
	ls->extra_acked[0] = 0;
	ls->extra_acked[1] = 0;
	ls->extra_acked_win_rtts = 0;
	ls->extra_acked_win_idx = 0;
	ls->ack_epoch_acked = 0;
	ls->ack_epoch_mstamp = tp->tcp_mstamp;

	/* ECN alpha EWMA */
	ls->ecn_alpha = READ_ONCE(ls_params.ecn_alpha_init);
	ls->ecn_eligible = 0;
	ls->alpha_last_delivered = tp->delivered;
	ls->alpha_last_delivered_ce = tp->delivered_ce;
	ls->startup_ecn_rounds = 0;

	/* 快速路径 */
	ls->try_fast_path = 0;
	ls->has_seen_rtt = 0;

	/* 丢包追踪 */
	ls->loss_round_delivered = tp->delivered + 1;

	/* RACK-TLP 初始化 */
	ls->rack_rtt_us = 0;
	ls->rack_end_seq = tp->snd_una;
	ls->rack_xmit_ts = 0;
	ls->tlp_probes_out = 0;
	ls->rack_detect_loss = 0;
	ls->tlp_high_seq_set = 0;
	ls->tlp_in_progress = 0;
	ls->rack_reord_seen = 0;

	/* 检测高延迟路径 */
	ls_update_high_delay_path(sk);
	ls_update_rho(sk);

	ls_enter_startup(sk);
	ls->next_rtt_delivered = tp->delivered;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	ls_hist_lookup(sk);
}

static void ls_release(struct sock *sk)
{
	ls_hist_update(sk);
}

static u32 ls_ssthresh(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls_save_cwnd(sk);
	return tcp_sk(sk)->snd_ssthresh;
}

static u32 ls_undo_cwnd(struct sock *sk)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	ls_reset_full_bw(sk);
	ls->loss_in_round = 0;
	return ls->prior_cwnd;
}

static void ls_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ls_reset_full_bw(sk);
		if (ls->inflight_lo == ~0U)
			ls->inflight_lo = max(tcp_snd_cwnd(tp), ls->prior_cwnd);
		ls->in_recovery = 0;
	} else if (new_state == TCP_CA_Recovery) {
		ls->in_recovery = 1;
		ls->recovery_started = 1;
		ls->prior_cwnd = max(ls->prior_cwnd, tcp_snd_cwnd(tp));
	} else if (new_state == TCP_CA_Open && ls->in_recovery) {
		ls->in_recovery = 0;
	}
}

static void ls_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lotspeed *ls = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_TX_START:
		if (!tp->app_limited)
			return;
		ls->idle_restart = 1;
		if (ls->mode == LS_PROBE_BW)
			ls_set_pacing_rate(sk, ls_bw(sk), LS_UNIT);
		break;
	case CA_EVENT_LOSS:
		ls->loss_in_round = 1;
		break;
	default:
		break;
	}
}

static void ls_skb_marked_lost(struct sock *sk, const struct sk_buff *skb)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct rate_sample rs = { 0 };

	ls->loss_in_round = 1;

	if (ls->mode == LS_PROBE_BW && ls->cycle_idx == LS_BW_PROBE_UP) {
		/* 精确计算 inflight_hi */
		ls_inflight_hi_from_lost_skb(sk, &rs, skb);
	}
}

static void ls_cong_control(struct sock *sk, u32 ack, int flag,
                            const struct rate_sample *rs)
{
	(void)ack;
	(void)flag;
	ls_main(sk, rs);
}

static u32 ls_sndbuf_expand(struct sock *sk)
{
	return 3;
}

static u32 ls_tso_segs(struct sock *sk, unsigned int mss_now)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	u32 segs, r;
	u64 bytes;

	bytes = READ_ONCE(sk->sk_pacing_rate) >> READ_ONCE(sk->sk_pacing_shift);

	if (READ_ONCE(ls_params.tso_rtt_shift) && ls->min_rtt_us != ~0U) {
		r = ls->min_rtt_us >> READ_ONCE(ls_params.tso_rtt_shift);
		if (r < BITS_PER_TYPE(u32))
			bytes += GSO_LEGACY_MAX_SIZE >> r;
	}

	bytes = min_t(u32, bytes, sk->sk_gso_max_size - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / mss_now,
	             sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);

	return segs;
}

/* ============== get_info 诊断回调 ============== */

/*
 * 使用 BBR info 格式输出诊断信息
 * 可通过 ss -ti 查看
 */
static size_t ls_get_info(struct sock *sk, u32 ext, int *attr,
                          union tcp_cc_info *info)
{
	struct lotspeed *ls = inet_csk_ca(sk);
	struct tcp_bbr_info *bi = &info->bbr;

	if (ext & (1 << (INET_DIAG_BBRINFO - 1))) {
		memset(bi, 0, sizeof(*bi));
		bi->bbr_bw_lo = ls_bw(sk);
		bi->bbr_bw_hi = ls_max_bw(sk);
		bi->bbr_min_rtt = ls->min_rtt_us;
		bi->bbr_pacing_gain = ls->pacing_gain;
		bi->bbr_cwnd_gain = ls->rho_scale;  /* 借用显示 rho */
		*attr = INET_DIAG_BBRINFO;
		return sizeof(*bi);
	}
	return 0;
}

/* ============== 模块注册 ============== */

static struct tcp_congestion_ops lotspeed_v2_ops __read_mostly = {
	.name           = "lotspeed",
	.owner          = THIS_MODULE,
	.flags          = TCP_CONG_NON_RESTRICTED | TCP_CONG_WANTS_CE_EVENTS,
	.init           = ls_init,
	.release        = ls_release,
	.cong_control   = ls_cong_control,
	.ssthresh       = ls_ssthresh,
	.undo_cwnd      = ls_undo_cwnd,
	.set_state      = ls_set_state,
	.cwnd_event     = ls_cwnd_event,
	.sndbuf_expand  = ls_sndbuf_expand,
	.skb_marked_lost = ls_skb_marked_lost,
	.tso_segs       = ls_tso_segs,
	.get_info       = ls_get_info,
};

static int __init lotspeed_v2_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct lotspeed) > ICSK_CA_PRIV_SIZE);

	/* 注册 sysctl (kernel 6.x 使用 _sz 版本避免空终止符问题) */
	ls_sysctl_header = register_net_sysctl_sz(&init_net,
		"net/ipv4/lotspeed", ls_sysctl_table,
		ARRAY_SIZE(ls_sysctl_table));
	if (!ls_sysctl_header) {
		pr_err("LotSpeed: failed to register sysctl\n");
		return -ENOMEM;
	}

	/* 初始化历史缓存 */
	if (READ_ONCE(ls_params.hist_enable)) {
		ls_hist_cache = kmem_cache_create("lotspeed_hist",
		                                  sizeof(struct ls_hist_entry),
		                                  0, SLAB_HWCACHE_ALIGN, NULL);
		if (!ls_hist_cache) {
			unregister_net_sysctl_table(ls_sysctl_header);
			return -ENOMEM;
		}
		hash_init(ls_hist_table);
	}

	ret = tcp_register_congestion_control(&lotspeed_v2_ops);
	if (ret) {
		if (ls_hist_cache)
			kmem_cache_destroy(ls_hist_cache);
		unregister_net_sysctl_table(ls_sysctl_header);
		return ret;
	}

	pr_info("LotSpeed v%s loaded: BBR+FAST+Hybla hybrid\n", LS_VERSION_STR);
	pr_info("  sysctl: /proc/sys/net/ipv4/lotspeed/\n");
	pr_info("  alpha=%u gamma=%u hd_thresh=%uus\n",
	        ls_params.fast_alpha, ls_params.fast_gamma, ls_params.hd_thresh_us);
	return 0;
}

static void __exit lotspeed_v2_exit(void)
{
	struct ls_hist_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	tcp_unregister_congestion_control(&lotspeed_v2_ops);

	if (ls_hist_cache) {
		spin_lock_bh(&ls_hist_lock);
		hash_for_each_safe(ls_hist_table, bkt, tmp, entry, node) {
			hash_del(&entry->node);
			kmem_cache_free(ls_hist_cache, entry);
		}
		spin_unlock_bh(&ls_hist_lock);
		kmem_cache_destroy(ls_hist_cache);
	}

	unregister_net_sysctl_table(ls_sysctl_header);

	pr_info("LotSpeed v%s unloaded\n", LS_VERSION_STR);
}

module_init(lotspeed_v2_init);
module_exit(lotspeed_v2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hybrid of BBR v3 + FAST TCP + Hybla");
MODULE_DESCRIPTION("LotSpeed v2.2 - Hybrid CC with RACK-TLP and Enhanced Hybla");
MODULE_VERSION(LS_VERSION_STR);
