package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type metrics struct {
	bwMbps  float64
	rttMs   float64
	lossPct float64 // 0..1

	// NeoQ experience signals, sampled in the SAME measure() window as bw/rtt/loss
	// so all signals share one observation window. nqOK=false when the new sch_neoq
	// qdisc isn't loaded (/proc/net/neoq_ml missing) — then the experience term is
	// skipped and score() is exactly the legacy formula (backward compat).
	nqOK           bool
	t0PeakDelayUs  float64 // Express recent-peak delay (reset-on-read) — experience signal
	t0DeltaPkts    uint64  // Express pkts THIS window (from a t0_pkts delta) — activity gate
	t3GoodputDelta uint64  // Bulk bytes THIS window (from a t3_bytes delta)
	bulkFlows      uint64  // concurrent bulk flows (mixed-workload gate for neoq_sparse_thresh)

	// ambientPct 是 qdisc 侧导出的 ambient_share (上一完整 1s 窗口的全链路重传占比,
	// 百分数 0-100) —— loss_thresh 闭环的首选环境丢包锚点。ambientOK=false 表示内核
	// 没导出这个键 (老模块), 闭环退回用 lossPct (ss/snmp 差分) 估。
	ambientPct float64
	ambientOK  bool
}

// tunable parameter with a safe range.
// path != "" => write that proc file directly (e.g. /proc/net/neoq_boost);
// path == "" => lotspeed sysctl by name.
type tunable struct {
	name                string
	path                string
	min, max, step, cur int
}

// optimizer keeps all state in memory across the loop.
type optimizer struct {
	iface       string
	target      string // --target IP: when set, measure() scopes ALL link signals to this peer's sockets (per-link). Empty => machine-wide.
	interval    time.Duration
	alpha, beta float64 // delay & loss penalty weights
	gamma       float64 // Express-delay (experience) penalty weight; 0 => term off
	tun         []tunable
	ti          int // current tunable index
	dir         int // probe direction +1/-1
	peakBw      float64
	minRtt      float64
	bestScore   float64
	phase       string
	exploreT    int
	// exploreWall 是 EXPLORE 的墙钟计数 (含 idle 拍), 与只数活跃拍的 exploreT 分开。
	exploreWall int
	prevBytes   uint64
	prevOut     uint64
	prevRetr    uint64
	// Per-target counter baselines (used only when o.target != ""). ss exposes
	// LIFETIME totals per socket; we sum them across the target's sockets and diff
	// against these to get per-cycle deltas, exactly like the machine-wide snmp/iface
	// counters above. tgtPrimed guards the first-cycle bogus delta. Sockets churn
	// (connections open/close between cycles), so when the summed lifetime totals
	// DECREASE — a tracked socket closed — measure() re-baselines instead of emitting
	// a negative delta (see ssTarget + the measureTarget() churn guard).
	prevTgtRetr  uint64
	prevTgtSegs  uint64
	prevTgtAcked uint64
	tgtPrimed    bool
	prevTgtLoss  float64 // last good loss value, returned on a churn re-baseline cycle
	prevT0Pkts   uint64  // NeoQ: cumulative Express pkts at last measure() (for delta)
	prevT3Bytes  uint64  // NeoQ: cumulative Bulk bytes at last measure() (for delta)
	nqPrimed     bool    // NeoQ: prev*T0/T3 counters baselined (skip first-cycle bogus delta)
	codelRtt     float64 // EWMA RTT (ms) driving NeoQ CoDel target/interval

	// sh is the shaper fast loop (nil when --shaper is off). The slow layer reads it
	// for the freeze gate (slowLayerReady) and the R-variance score term (rateCV),
	// and writes it through the shaper_headroom arm (apply). All its accessors are
	// nil-safe so every use site stays a plain call with no branch.
	sh *shaper

	// bwRing holds the last jitterRingLen per-cycle goodput samples (Mbps), pushed
	// on CLEAN cycles only (same hygiene as rttRing). score() penalizes its
	// MAD/median — 目标是"稳定的高速低延迟", 不是峰值吞吐: 一个平均值漂亮但每拍
	// 上下翻倍的配置, 交互体验比一个略慢但平稳的配置差得多。
	bwRing []float64

	// rttRing holds the last jitterRingLen per-cycle RTT samples (ms). Its MAD is
	// the jitter signal in score(). Only CLEAN cycles push here — bad-link cycles
	// (RTT spikes flagged by the link-weather gate) are skipped so a weather blip
	// can't poison the variance estimate (see the measure-site push in the loop).
	rttRing []float64

	smScore    float64 // EWMA-smoothed score — stable steering signal (抚平)
	bestKnown  float64 // best smoothed score seen — stability reference
	bestParams []int   // tunable values at bestKnown — snap-back target (纠正)
	unstableN  int     // consecutive cycles below the stability floor

	// B1 delta-credit: the index/value/score of the coordinate probed LAST cycle,
	// so this cycle's score can be differenced against it and credited to that one
	// arm only. probedTi<0 means "no probe outstanding" (first OPT cycle).
	probedTi  int
	probedVal int
	prevScore float64 // score under the config BEFORE the outstanding probe
	havePrev  bool

	// B2 sequential decision smoothing: a coordinate step is only accepted/reverted
	// once two consecutive cycles agree on its sign, to keep one noisy cycle from
	// committing a move. pendingSign is the sign seen last cycle for the probed param.
	pendingSign int

	// B4 effect-size freeze: params whose best/worst arm means barely differ are
	// frozen (skipped when advancing o.ti). Unfrozen on a minRtt regime shift.
	frozen       map[string]bool
	freezeMinRtt float64 // minRtt at the time the last freeze was decided

	// mixedWorkload (re-evaluated each OPT cycle from the live NeoQ stats) gates
	// which params nextTi may select. NeoQ-only params (neoq_sparse_thresh) are a
	// no-op unless the workload is genuinely mixed (bulk_flows>=1 AND Express active),
	// so on single-flow/idle traffic we skip them in the rotation rather than let
	// them absorb exploration credit — the neoq_boost lesson. Unlike frozen this is
	// transient: re-checked every cycle, never persisted.
	mixedWorkload bool

	// lt 是 loss_thresh 的机制闭环状态 (见 lossThreshLoop)。只在 coord 机制模式下
	// 驱动: --legacy-bandit 下 loss_thresh 回到 tun 表当臂, 闭环整个停用 —— 一个
	// 参数绝不允许有两个写者。
	lt lossThreshLoop

	// legacyBandit: --legacy-bandit 一键回到旧行为 (tun 表恢复、坐标上升照跑),
	// 整期可回退。为 false 时 tun 表在 coord 模式下是空的, 主循环退化为
	// "测量 -> 驱动机制 (applyCodel / loss_thresh 闭环) -> 记录遥测样本"。
	legacyBandit bool
	// ltAuto: 允许 loss_thresh 闭环**真的写** sysctl。默认 false —— 闭环照常测量、
	// 报告、打日志, 但只给建议。
	//
	// 为什么: ambient (无论取 qdisc 的 ambient_share 还是 ss/snmp 差分) 都是**重传
	// 占比**, 而 loss_thresh 正是决定 CC 遇到丢包退不退避的那个旋钮。抬高 lt -> 少
	// 退避 -> 发得更快 -> 重传占比上升 -> 公式据此给出更高的 lt。回归量与误差项相关,
	// 参数在观测数据上不可识别。实测棘轮: 真实 ambient 8% (正确答案 lt=12), 自致
	// 系数只要 >= 0.2pp / 单位 lt 就会越过正确答案, >= 0.5pp 直接钉死在 lossThreshMax。
	//
	// 两条防线都挡不住: nonBinding() 的 util 判据在本机恒真 (unit 不传
	// --shaper-max-mbps, R_max 兜底 10Gbps, 满载 100Mbps 时 util=0.01), 退化成只剩
	// eRemote 一个条件, 而 policer 型瓶颈丢包时**不堆驻留队列**; P25 只滤突发, 而
	// 自致污染是每拍恒定的。
	//
	// 打破内生性需要外生变异, 也就是随机化。abtest 的交替 A/B 就是那个实验 ——
	// 因果推断放在唯一能做对的地方, 闭环负责它做得对的那部分: 测量与检测。
	ltAuto bool
}

// neoqOnly reports whether a tunable only makes sense under a mixed (bulk +
// interactive) workload. Such params are skipped in the probe rotation when the
// current cycle isn't mixed (see nextTi). neoq_sparse_thresh demotes a flow from
// the Express-eligible sparse class to bulk once it exceeds the byte threshold —
// pure no-op when there's at most one flow or no Express traffic to protect.
func (t *tunable) neoqOnly() bool { return t.name == "neoq_sparse_thresh" }

// Experience-term constants (NeoQ Express-delay penalty).
const (
	// expressDelayBudgetUs is the Express (t0) recent-peak delay we treat as "fully
	// spent". Express measures ~1-5us under pure bulk load today, so any sustained
	// climb toward ms-scale means interactive traffic is queuing behind bulk. 5ms.
	expressDelayBudgetUs = 5000.0
	// expressActivityFloorPkts is the minimum Express pkts in a window for the delay
	// reading to be trusted. Below it the tier is essentially idle and a stray peak
	// is noise, not experience — so we neither score nor probe-gate on it (~50 pkts).
	expressActivityFloorPkts = 50
	// defaultGamma weights the Express-delay penalty in score(). 0 disables the term.
	defaultGamma = 0.3
	// jitterRingLen is how many recent per-cycle RTTs the optimizer keeps to
	// estimate jitter (MAD of the ring). 8 cycles is enough for a stable MAD
	// without lagging a genuine regime change too long.
	jitterRingLen = 8
	// jitterMinSamples is the minimum ring occupancy before the jitter penalty is
	// applied; below it the MAD is too noisy to trust and score() stays the
	// throughput+delay+loss formula (so an empty/short ring is a no-op).
	jitterMinSamples = 4
	// jitterDelta weights the jitter penalty in score(). The term subtracts
	// jitterDelta*clamp(jitterMs/rttMs, 0, 1): on a 250ms intercontinental path a
	// jitter/rtt ratio above ~0.1 already degrades interactive feel, so penalizing
	// RTT variance steers the search away from parameter sets that win mean
	// throughput by causing RTT oscillation (e.g. overly aggressive probing).
	// Hardcoded (no flag) to stay surgical; the gamma flag precedent exists if a
	// knob is wanted later.
	jitterDelta = 0.2
	// goodputVarDelta weights the goodput-variance penalty:
	// goodputVarDelta*clamp(MAD(bwRing)/median(bwRing), 0, 1). Same gate as the
	// jitter term (>=jitterMinSamples samples), so a short ring is a no-op.
	goodputVarDelta = 0.3
	// rateCVDelta weights the shaper-rate-variance penalty (CV of the shaper's R
	// ring). It penalizes the CONTROLLER for oscillating its own actuator: a slow
	// -layer config that keeps knocking the fast loop out of HOLD is worse than one
	// that lets it cruise, even at the same mean throughput. Only applies when the
	// shaper is running. CV is clamped to [0,1] — an unbounded CV (a rate that
	// swings 10x) would otherwise dominate every other term in the score.
	rateCVDelta = 0.1
	// idleBwFloorMbps 是"这一拍有没有真流量"的判据 (Mbps)。三处必须共用同一个阈值:
	// 主循环的 idle 门 (低于它 score 是纯噪声, hold 住参数不动)、参照系推进
	// (advanceRefs) 和 EXPLORE 计时。原来只有 idle 门用它, 于是出现了"idle 门认为
	// 没流量、参照系却照样在腐蚀"的错位 —— 见 advanceRefs 的注释。
	idleBwFloorMbps = 5.0

	// exploreWallMax: EXPLORE 相位的墙钟上限 (拍)。不管有没有流量, 到点必须转入
	// OPTIMIZE, 否则无流量的机器永远出不去 (见 exploreStep)。60 拍 @5s = 5 分钟,
	// 远大于有流量时的正常退出 (3-6 拍), 只在病态情形兜底。
	exploreWallMax = 60
	// delayPenaltyCap / lossPenaltyCap 给 score() 的两个惩罚项封顶。两项原来都没有
	// 上界: 一个 rtt≈3x min 的天气拍单独就能扣掉 1.0 以上, score 因此没有已知下界,
	// 而 bestKnown / STABILIZE 恰恰是在跨时间比较这些 score。封顶位置取在"再坏也
	// 区分不出更坏"的地方: 延迟项 2.0 正好是 badLink 的门槛 (rtt/minRtt-1 > 2 的那
	// 一拍本来就整拍跳过归因), 丢包项 0.3 已远超这条路 ~10% 的常态丢包。
	delayPenaltyCap = 2.0
	lossPenaltyCap  = 0.3
	// shaperHeadroomParam is the one tunable that does NOT land in a proc file:
	// it steers the fast loop's headroom in-process (see apply()). Stored as a
	// percent int because tunable is int-based; 95 => R = 0.95*C_hat.
	shaperHeadroomParam = "shaper_headroom"
)

// === 本轮冻结为常数的参数 ===
//
// 逐参数评估结论: 这几个量的"可观测量"根本不在 optimizer 的拍上, 或者它们是护栏
// 而不是学习对象。把它们钉成常数, 探索预算才不会被没有信噪比的臂吃掉。
const (
	// startup_gain: 只作用于流的前 ~10 轮。被动观测长活隧道永远采不到它的效应
	// (它的可观测量是"新流到满速时间", 只能主动测), 所以钉在最激进档。
	frozenStartupGain = 400
	// hd_rho_max: 防 rho^2 过冲重传风暴的**护栏**, 护栏应该是常数不是学习对象;
	// 且主要作用面在 STARTUP, optimizer 的拍观测不到。
	frozenHdRhoMax = 400
	// fast_alpha: 从 tun 表移除。这里保留旧 tun 表的启动值 (30), 行为与今天逐字一致;
	// 物理推导见 fastAlphaFor —— 那是 HYPOTHESIS 级, netem 台架验证前不接线上。
	frozenFastAlpha = 30
	// delay_cap_thresh: 永不进 bandit。人工交替配对 A/B 两轮都是"开了更差", 这条
	// 证据的优先级高于 UCB 学出来的 50 (内核默认也是 0)。
	// ★ 行为变更: 旧 tun 表在启动时会写 50, 现在写 0。
	frozenDelayCapThresh = 0
	// neoq_sparse_thresh: 冻结在内核默认 2*MTU。混流收益本身在这台机器上未证
	// (bandmap 判决 A3=0.0%), 现在投入探索预算不合算。
	frozenNeoqSparseThresh = 3028
	// shaper_headroom: R = h*C_hat 的前馈项。它想解决的问题 (留多少余量让 E_remote
	// 不涨) 正是 HOLD trim 环已经在闭环解决的 (按 E_remote 超预算逐步收 R)。反馈在跑
	// 的时候前馈只需要一个保守常数。setHeadroom 保留给人工运维, 只从 tun 表移除。
	frozenShaperHeadroom = 0.95
)

// === loss_thresh 机制闭环 (本轮把它从 bandit 臂改成可测量的机制) ===
//
// 物理锚点: K1 门控的语义就是"每轮丢包率低于 loss_thresh 不算拥塞、不退避", 所以
// loss_thresh 恒等于 环境丢包率 + 余量 —— 一个可直接测量的量, 不需要学。公式本体在
// model.go 的 lossThreshFor, 与 heuristicPlan 冷启动共用同一份边界。
//
// ★ ambient 的自指风险 (这条最关键): 朴素做法是直接用当拍测到的 loss, 但那会形成
// 正反馈棘轮 —— thresh↑ -> CC 更激进 -> 自致丢包↑ -> 测得 loss↑ -> thresh↑ ...
// 两条防线都上, 因为任何一条单独都有覆盖不到的情形:
//
// (a) 非绑定窗口筛选 (shaper.nonBinding): 只采 util<utilBind 且 E_remote 不超预算的
// 拍 —— 那种拍的丢包 by construction 不是我造成的。这是最强的一条, 但只有快环真的在
// 跑才判得了 (生产的 systemd unit 带 --shaper, 所以线上有它)。
//
// (b) 活跃拍读数的滚动 P25 (下四分位近似环境底) 而不是均值。它不依赖快环, 是
// --shaper 关闭时唯一的防线; 自致丢包是突发的、集中在推得最狠的那几拍上, 所以下
// 四分位比均值更接近"路本身有多脏"。
//
// 单靠 (b), 在"长时间满载、每拍都绑定"的情形下 P25 会跟着自致丢包一起抬 —— 那正是
// (a) 覆盖的洞; 单靠 (a), 快环关闭时完全失效 —— 那正是 (b) 覆盖的洞。最后还有一道
// 死兜底: lossThreshMax 把棘轮的终点封在 20。
const (
	// ambientRingLen 是 ambient 采样环的长度 (只数被采纳的活跃拍)。P25 要有分位数的
	// 意义就得有足够样本, 又不能长到跟不上小时级摆动 (实测 90 分钟内 ambient 从
	// 10.4% 漂到 18.2%, 近一倍)。
	ambientRingLen = 40
	// ambientMinSamples: 环里少于这么多样本时 P25 不可信, 闭环一律不动 loss_thresh
	// (保持冷启动种子值)。
	ambientMinSamples = 8
	// ambientP25 = 下四分位, 见上面的防法 (b)。
	ambientP25 = 0.25
	// ambientHalfLife: ambient EWMA 的半衰期。5-10 分钟这个量级是实测定的 —— 短于
	// 5 分钟跟着单窗噪声抖, 长于 10 分钟跟不上小时级摆动。取 7.5 分钟。
	// ★ 它的时间轴是**活跃拍折算**出来的, 不是墙钟: 每个活跃拍推进 o.interval,
	//   idle 拍一拍都不推进 (D1 纪律, 见 lossThreshLoop.step)。settle 让真实拍长略大
	//   于 interval, 所以有效半衰期比标称还长一点 —— 保守方向, 可以接受。
	ambientHalfLife = 450 * time.Second
	// ambientApplyInterval: 写 sysctl 的节流下限 (同样按活跃拍折算)。
	ambientApplyInterval = 5 * time.Minute
	// ambientHysteresis: 迟滞。|新值 - 在用值| >= 2 才真的写下去, 否则 ±1 的抖动会让
	// sysctl 每 5 分钟翻一次。硬边界 (lossThreshMin/Max) 上有一个例外, 见 step。
	ambientHysteresis = 2
)

// lossThreshLoop 是 loss_thresh 机制闭环的全部状态。
//
// ★ D1 纪律 (务必保持): 无流量窗口既不更新、也不遗忘 —— ring / ewma / 节流计时器
// 全部只在活跃拍推进。green1 有 96.8% 的拍是 idle 或被 shaper 冻结, idle 拍的 loss
// 读数是垃圾; 让它进 EWMA 会把 thresh 拖向噪声, 这与我们刚修完的参照系腐蚀
// (见 advanceRefs) 是同一族的口径污染。
type lossThreshLoop struct {
	ring    []float64     // 最近 ambientRingLen 个被采纳的 ambient 读数 (百分数 0-100)
	ewma    float64       // ring 的 P25 的 EWMA (百分数)
	primed  bool          // ewma 是否已经有第一份读数
	elapsed time.Duration // 距上次播报 (写 sysctl 或顶格心跳) 累计的**活跃拍**时长
	cur     int           // 当前生效的 loss_thresh (由冷启动种子初始化)
	saturN  int           // 顶格播报次数 (余量被 lossThreshMax 吃掉; 每个节流窗口最多 1 次)
}

// ltAction 是闭环一拍的产出。write 与 report 必须分开: "值变了" 和 "顶格这件事该让
// 运维看见" 是两回事 —— 顶格是个**驻留状态**而不是一次性事件, 阈值一旦被 clamp 钉在
// 20 上就再也不会"变化"了, 只按 write 播报的话运维只能看见一次然后永远失明。
type ltAction struct {
	val       int  // 目标 loss_thresh
	write     bool // 需要写 sysctl (值真的变了)
	saturated bool // 余量被 lossThreshMax 吃掉
	report    bool // 有事要打日志 (值变了, 或顶格状态走到了播报节流点)
}

// step 推进一个活跃拍。调用方必须自己保证这是活跃拍 (D1)。
//
//	sample  这一拍的 ambient 读数 (百分数 0-100)
//	admit   这一拍是否允许进 ambient 环 (防法 (a): 非绑定窗口才算数)
//	dt      本拍折算的时长 (= optimizer 的 interval)
//	rttMs   当前路径 RTT, 供 lossThreshFor 的高 RTT 地板用
func (l *lossThreshLoop) step(sample float64, admit bool, dt time.Duration, rttMs float64) ltAction {
	// 节流计时器只在活跃拍推进 —— 与 ring/ewma 同一纪律。
	l.elapsed += dt
	if admit && sample >= 0 {
		l.ring = append(l.ring, sample)
		if len(l.ring) > ambientRingLen {
			l.ring = l.ring[1:]
		}
		p25 := percentile(l.ring, ambientP25)
		if !l.primed {
			l.ewma, l.primed = p25, true
		} else {
			l.ewma += ewmaAlphaFor(dt, ambientHalfLife) * (p25 - l.ewma)
		}
	}
	if !l.primed || len(l.ring) < ambientMinSamples {
		return ltAction{}
	}
	amb := l.ewma / 100 // lossThreshFor 吃的是 0..1 的分数
	act := ltAction{val: lossThreshFor(amb, rttMs), saturated: lossThreshSaturated(amb)}
	if l.elapsed < ambientApplyInterval {
		return act
	}
	changed := act.val != l.cur
	// 迟滞: |Δ|>=2 才落盘。**硬边界例外**: want 贴到 lossThreshMin/Max 时只要与在用值
	// 不同就写 —— ambient 是以 2 为步长逼近上限的 (9->11->...->19), 严格的 |Δ|>=2 会
	// 让 19->20 永远差 1, 阈值被永久钉在顶格前一格, 而"顶格"恰恰是要让人看见的状态。
	atRail := act.val == lossThreshMin || act.val == lossThreshMax
	if changed && !atRail && absInt(act.val-l.cur) < ambientHysteresis {
		// 迟滞挡下的时候**不**重置节流计时器: 节流约束的是"两次写之间至少隔 5 分钟",
		// 不是"每 5 分钟只判一次"。重置会让 ±1 的抖动把写窗口无限往后推。
		return act
	}
	if !changed && !act.saturated {
		return act // 值没变也没顶格: 无事可做, 计时器保持, 变化一到就能立刻写
	}
	l.elapsed = 0
	if changed {
		l.cur = act.val
		act.write = true
	}
	if act.saturated {
		l.saturN++
	}
	act.report = true
	return act
}

// ewmaAlphaFor 把半衰期换算成 EWMA 系数: alpha = 1 - 2^(-dt/T_half)。
func ewmaAlphaFor(dt, halfLife time.Duration) float64 {
	if halfLife <= 0 || dt <= 0 {
		return 1
	}
	return 1 - math.Pow(2, -dt.Seconds()/halfLife.Seconds())
}

// ambientSample 给出这一拍的环境丢包读数 (百分数 0-100)。优先用 qdisc 侧导出的
// ambient_share —— 滚动 1s 窗、只数 >=128B 的包 (纯 ACK 不稀释分母)、排除哈希冲突包,
// 口径比 ss/snmp 差分干净。内核没导出这个键时退回 lossPct。ok=false = 无可用读数。
func ambientSample(m metrics) (float64, bool) {
	if m.nqOK && m.ambientOK {
		return m.ambientPct, true
	}
	if m.lossPct >= 0 {
		return m.lossPct * 100, true
	}
	return 0, false
}

// applyLossThresh 推进一拍闭环并落 sysctl。返回要打印的日志行 (空串 = 这一拍没有可
// 报告的动作)。--legacy-bandit 下 loss_thresh 回到 tun 表当臂, 闭环整个停用 —— 一个
// 参数绝不允许有两个写者。
//
// ★ active 的门在这里, 不在调用方: D1 纪律 (无流量窗口既不更新也不遗忘) 是这个机制
// 自己的不变式, 让它依赖"调用方记得先判一下"就是等着下一个人把它写丢。
func (o *optimizer) applyLossThresh(m metrics, active bool) string {
	if o.legacyBandit || !active {
		return ""
	}
	sample, ok := ambientSample(m)
	if !ok {
		return ""
	}
	// 防法 (a): 只有非绑定窗口的读数才进 ambient 环。快环没跑 / 内核不导出 shaper 键
	// 时判不了, 这时放行 —— 由防法 (b) 的 P25 独自兜底。
	admit := true
	if nb, known := o.sh.nonBinding(); known {
		admit = nb
	}
	act := o.lt.step(sample, admit, o.interval, m.rttMs)
	if !act.report {
		return ""
	}
	verb := "hold" // 值没变, 这是顶格驻留的心跳
	if act.write {
		if o.ltAuto {
			_ = writeSysctl("loss_thresh", strconv.Itoa(act.val))
			verb = "->"
		} else {
			// 默认只建议。见 optimizer.go 顶部 ltAuto 的说明: ambient 与 loss_thresh
			// 之间是内生的, 闭环自己写会形成棘轮。
			verb = "suggest"
		}
	}
	src := "ss-diff"
	if m.nqOK && m.ambientOK {
		src = "ambient_share"
	}
	line := fmt.Sprintf("LOSS-THRESH %s %d (ambient=%.1f%% src=%s p25ring=%d)",
		verb, act.val, o.lt.ewma, src, len(o.lt.ring))
	if act.saturated {
		// 顶格必须显式可见: 余量被 lossThreshMax 吃掉了。上限是否该提到 24 交给
		// abtest 裁决, 但运维得先看得见这件事正在发生。
		line += fmt.Sprintf(" [SATURATED #%d: ambient+%d=%d > cap %d, effective margin +%.1f]",
			o.lt.saturN, lossThreshMargin,
			int(math.Round(o.lt.ewma))+lossThreshMargin, lossThreshMax,
			float64(lossThreshMax)-o.lt.ewma)
	}
	return line
}

// === fast_alpha 的物理推导 (HYPOTHESIS 级, 未接入主循环) ===
//
// 物理含义: fast_alpha 是"瓶颈站立队列目标 = alpha 个包"。锚点是排队延迟
// E = srtt - min_rtt。队列预算沿用 shaper 那份 (eRemoteFloorMs / eRemoteRttFrac,
// 即 max(30ms, 0.2*min_rtt)) —— 同源, 不另立常数。于是
//
//	alpha_target = E_target * bw_pkts_per_s
//
// 纠缠点: 内核里 alpha 会被 hybla_gain 乘上去 (ls_fast_cwnd: alpha = alpha*gain/100),
// 所以推导要把主导档的典型 rho 除出去:
//
//	alpha_base = alpha_target / rho_typical,  rho_typical = clamp(min_rtt/50ms, 1, 4)
//
// 50ms = 内核的 hd_ref_us; 上限 4 = hd_rho_max/100 (内核 ls_update_rho 把 rho 夹在
// [1, rho_max], ls_hybla_cwnd_gain 再把 rho^1.5 封在 rho_max)。
//
// ★ 已知偏差 (留给台架裁决): 内核真正的乘子是 min(rho^1.5, 4), 不是 rho。两者在
// min_rtt >= 200ms 时都等于 4 (完全一致), 在 159ms 处是 4 vs 3.18 —— 也就是本函数在
// 主导档的低端最多高估 alpha 约 1.26x。要不要改成除以 min(rho^1.5, 4), 由 netem 台架
// 的实测决定, 不在这里凭直觉选边。
//
// ★ 状态: HYPOTHESIS。**不接进主循环**, 只有函数 + 表驱动单测。验收条件: netem 台架
// 上固定 bw/min_rtt/loss, 对比 fastAlphaFor 给出的值与人工扫描出的最优值, 在主导档
// (min_rtt 159-264ms) 上排队延迟 E 落在预算 ±30% 内、且吞吐不低于扫描最优的 95%。
// 台架不在本轮范围。
const (
	// fastAlphaMSS: 换算包速率用的典型 MSS (与 heuristicPlan 的 BDP 换算同值)。
	fastAlphaMSS = 1460.0
	// fastAlphaHdRefMs: 内核 hd_ref_us 的毫秒形式 (rho 的参考 RTT)。
	fastAlphaHdRefMs = 50.0
	// fastAlphaRhoMax: rho 的上限, = hd_rho_max/100。
	fastAlphaRhoMax = 4.0
	// fastAlphaMin/Max: 输出夹紧区间, 沿用旧 tun 表探索过的范围。
	fastAlphaMin = 4
	fastAlphaMax = 40
)

// fastAlphaFor 由带宽 (Mbps) 和无负载 RTT (ms) 推导 fast_alpha 的写入值。
// ok=false 表示输入不足以推导 (bw/rtt 非正)。
func fastAlphaFor(bwMbps, minRttMs float64) (int, bool) {
	if bwMbps <= 0 || minRttMs <= 0 {
		return 0, false
	}
	// 队列预算 (秒)。常量与 shaper 的 HOLD trim 环同源。
	eTargetSec := math.Max(eRemoteFloorMs, eRemoteRttFrac*minRttMs) / 1000
	pktsPerSec := bwMbps * 1e6 / 8 / fastAlphaMSS
	alphaTarget := eTargetSec * pktsPerSec
	rhoTypical := clampF(minRttMs/fastAlphaHdRefMs, 1, fastAlphaRhoMax)
	return clampInt(int(math.Round(alphaTarget/rhoTypical)), fastAlphaMin, fastAlphaMax), true
}

// legacyTunables 是 --legacy-bandit 下恢复的 tun 表 —— 逐字保留本轮之前的内容, 使那
// 个开关是一次真正的整期回退, 而不是一个"看起来像旧行为"的近似。
func legacyTunables() []tunable {
	return []tunable{
		{"startup_gain", "", 200, 400, 20, 400},
		{"fast_alpha", "", 4, 40, 4, 30},
		// loss_thresh 2..24 default 4: on a ~10%-ambient-loss link the per-link
		// optimum sits ~12-16 and was pressing the old max=16 ceiling, so the
		// range is widened to 24 (lt=30 still caused retrans storms; 24 gives
		// headroom above the 10%-ambient optimum without reaching that zone).
		// Start tight (4) — the per-link optimum is found by stepping up.
		{"loss_thresh", "", 2, 24, 2, 4},
		// hd_rho_max kept high (250..400): full Hybla high-delay rho keeps
		// high-RTT cwnd ramping aggressively. (Was observed stuck at 0 = boost off.)
		{"hd_rho_max", "", 250, 400, 25, 400},
		// neoq_sparse_thresh: CAKE-style sparse-gate byte threshold per 100ms
		// window; the window stays fixed at 100000us. See apply() for the write
		// format ("100000 <bytes>"). The 6 stepped arms cover 0.24-9.9 Mbps, which
		// is where the real sparse/bulk boundary lives (a 2MB web page burst must
		// stay Express; a sustained download must demote to Bulk). cur=3028 =
		// 2*MTU = the kernel default.
		{"neoq_sparse_thresh", neoqSparseProc, 3028, 123448, 24084, 3028},
		// delay_cap_thresh: 延迟门控封顶阈值 (%): srtt > min_rtt*(100+x)% 时把
		// cwnd 封到 BDP*1.25。30..80 的理由: 低于 30 会被正常 RTT 抖动误触发
		// (实测这条路 minRtt 159ms / 均值 468ms, 抖动本身就有 2-3x); 高于 80
		// 在同一条路上几乎等于不封顶。
		{"delay_cap_thresh", "", 30, 80, 10, 50},
	}
}

// applyFrozenConstants 写下本轮从 tun 表移除、转成常数的那几个参数。这里是它们唯一
// 的写入点 (loss_thresh 除外 —— 它之后由 lossThreshLoop 接管), 读者查"这些参数去哪
// 了"只需要看这一个函数。--legacy-bandit 下不调用: 那时它们仍是 tun 表的臂。
func (o *optimizer) applyFrozenConstants() {
	_ = writeSysctl("startup_gain", strconv.Itoa(frozenStartupGain))
	_ = writeSysctl("hd_rho_max", strconv.Itoa(frozenHdRhoMax))
	_ = writeSysctl("fast_alpha", strconv.Itoa(frozenFastAlpha))
	_ = writeSysctl("delay_cap_thresh", strconv.Itoa(frozenDelayCapThresh))
	// Sparse gate 的写入格式是 "<window_us> <thresh_bytes>" (内核 sscanf "%u %u"),
	// 与 apply() 里那一支保持一致。
	_ = os.WriteFile(neoqSparseProc,
		[]byte("100000 "+strconv.Itoa(frozenNeoqSparseThresh)), 0o644)
	o.sh.setHeadroom(frozenShaperHeadroom) // nil-safe
	// loss_thresh 的冷启动种子: **读当前内核值**, 不写。
	//
	// 早先这里用 lossThreshFor(0,0)=4 无条件覆盖, 那等于每次进程启动都断言"链路是
	// 干净的"。配合 unit 的 Restart=always, 任何一次崩溃都会把一条 18% ambient 的
	// 洲际链路打回 lt=4 —— 那正是 CC 退化成 bbr 的状态, 也就是这个参数存在的全部
	// 理由。旧 tun 表里 loss_thresh 是有 warm-start 的 (predict() 能恢复), 机制模式
	// 下 tun 表为空, 那条恢复路径消失了, 所以必须在这里补回来。
	//
	// 读不到 (模块没加载 / procfs 不可见) 才退到公式, 保持旧行为。
	seed := lossThreshFor(0, 0)
	if cur, err := readSysctl("loss_thresh"); err == nil {
		if v, err2 := strconv.Atoi(strings.TrimSpace(cur)); err2 == nil && v > 0 {
			seed = v
		}
	}
	o.lt.cur = seed
}

// paramsSnapshot 返回"这一拍真正生效的配置", 用于遥测样本。
//
// ★ 为什么不能直接遍历 tun 表: 机制模式下 tun 表是空的, 样本会带着空 params 进
// model.json —— `model show` 看不到东西, KNN predict 平均出空配置, cmdTune 于是一个
// 参数都不写。样本记的必须是"什么配置产生了这个分数", 而不是"优化器还在动哪几个
// 旋钮"。
func (o *optimizer) paramsSnapshot() paramSet {
	p := paramSet{}
	for i := range o.tun {
		p[o.tun[i].name] = o.tun[i].cur
	}
	if o.legacyBandit {
		return p
	}
	p["loss_thresh"] = o.lt.cur
	p["startup_gain"] = frozenStartupGain
	p["hd_rho_max"] = frozenHdRhoMax
	p["fast_alpha"] = frozenFastAlpha
	p["delay_cap_thresh"] = frozenDelayCapThresh
	return p
}

func newOptimizer(iface, target string, interval time.Duration, gamma float64, sh *shaper, legacyBandit bool) *optimizer {
	o := &optimizer{
		// beta=1.0 (goodput-accurate): the score measures wire throughput (iface
		// tx+rx, which includes retransmits). beta*loss discounts that by the
		// goodput actually lost to retransmission — no more. We do NOT punish
		// retransmits beyond their goodput cost: on a lossy intercontinental link
		// being aggressive (high retr) is the point, and the measured win is huge
		// (+186% vs bbr; bbr collapses to 2M on loss spikes, aggressive holds 36-87M).
		iface: iface, target: target, interval: interval, alpha: 0.5, beta: 1.0, gamma: gamma, sh: sh,
		dir: 1, phase: "EXPLORE", bestScore: -1e9,
		probedTi: -1, frozen: map[string]bool{}, legacyBandit: legacyBandit,
	}
	// === tun 表 ===
	//
	// 机制模式 (默认) 下 tun 表是**空的**: 本轮逐参数评估的结论是这条链路上没有一个
	// 参数具备可学的信噪比 (效应量 ~0.01 vs 相邻两拍 0.34 的噪声, 2σ 下每臂需要约
	// 4600 个平稳配对样本, 而实测有效学习拍只有 106 拍/天、链路容量在分钟级于
	// 6-59 Mbps 跳变)。于是 loss_thresh 转机制闭环, 其余的钉成常数或护栏,
	// 主循环退化为 "测量 -> 驱动机制 -> 记录遥测样本"。
	//
	// --legacy-bandit 一键恢复旧表 + 坐标上升, 整期可回退。
	if legacyBandit {
		o.tun = legacyTunables()
		// shaper_headroom 只在 --shaper 打开时才进轮转: 快环没跑的时候它连接收方都
		// 没有, 留在列表里只会白白吃掉探索预算 (neoq_boost 的教训)。
		if sh != nil {
			// 85..105 的理由: 低于 85 白扔 15% 带宽, 高于 105 等于故意超发。
			o.tun = append(o.tun, tunable{shaperHeadroomParam, "", 85, 105, 5, 95})
		}
	} else {
		o.applyFrozenConstants()
	}
	// Start every tunable at its AGGRESSIVE default and push it to the kernel.
	// We deliberately do NOT adopt the live sysctl value: a fresh module load has
	// conservative kernel defaults (e.g. loss_thresh=2) and adopting those would
	// make the optimizer start timid. Starting at the aggressive default also
	// overwrites any stale/garbage value from a prior run. Per-link learned optima
	// are recovered via the model warm-start (explicit-target mode) and the
	// model.json the optimizer keeps growing.
	// (机制模式下 tun 表为空, 这个循环是 no-op —— 基线由 applyFrozenConstants 写。)
	for i := range o.tun {
		o.apply(&o.tun[i])
	}
	return o
}

// ifaceBytes returns tx+rx so downstream gains (from neoq_boost) are rewarded.
func ifaceBytes(iface string) uint64 {
	tb, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/tx_bytes")
	rb, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
	tx, _ := strconv.ParseUint(strings.TrimSpace(string(tb)), 10, 64)
	rx, _ := strconv.ParseUint(strings.TrimSpace(string(rb)), 10, 64)
	return tx + rx
}

// autoDetectPeer picks the IP with the most ESTABLISHED connections right now.
// Used in PASSIVE mode (no --target) so each sample is tagged with the actual
// dominant peer. Falls back to "auto" if no connections.
func autoDetectPeer() string {
	out, err := exec.Command("ss", "-tn", "state", "established").Output()
	if err != nil {
		return "auto"
	}
	counts := map[string]int{}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		peer := f[3]
		if i := strings.LastIndex(peer, ":"); i > 0 {
			peer = peer[:i]
		}
		peer = strings.TrimPrefix(peer, "[")
		peer = strings.TrimSuffix(peer, "]")
		if peer == "" || strings.HasPrefix(peer, "127.") || strings.HasPrefix(peer, "::1") {
			continue
		}
		counts[peer]++
	}
	best, bestN := "auto", 0
	for ip, n := range counts {
		if n > bestN {
			best, bestN = ip, n
		}
	}
	return best
}

// ssField returns the RAW value token of a per-socket `ss` key formatted as
// `<key>:<value>` (e.g. "bytes_acked:1235" -> "1235", "rtt:3.5/1.75" -> "3.5/1.75",
// "retrans:5/12" -> "5/12") — i.e. the chars after the colon up to the next space,
// with NO "/" handling (the caller picks which side of an "X/Y" pair it needs: rtt
// wants X=srtt, retrans wants Y=lifetime total). ok=false when the key is absent.
// The key matches only as a WHOLE token (preceded by start-of-line or a space) so
// "rtt:" never matches inside "minrtt:" and "segs_out:" never inside
// "data_segs_out:". Defensive: a zero-loss socket omits "retrans:" entirely.
func ssField(line, key string) (string, bool) {
	probe := key + ":"
	from := 0
	for {
		k := strings.Index(line[from:], probe)
		if k < 0 {
			return "", false
		}
		k += from
		if k == 0 || line[k-1] == ' ' {
			s := line[k+len(probe):]
			if j := strings.IndexByte(s, ' '); j >= 0 {
				s = s[:j]
			}
			return s, true
		}
		from = k + len(probe)
	}
}

// ssFloatX parses key `key` and returns the X of an "X/Y" value (or the whole value
// if there's no "/") as a float. Used for rtt:srtt/rttvar — we want srtt (X). ok is
// false when the key is absent or X doesn't parse.
func ssFloatX(line, key string) (float64, bool) {
	s, ok := ssField(line, key)
	if !ok {
		return 0, false
	}
	if j := strings.IndexByte(s, '/'); j >= 0 {
		s = s[:j]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ssUintY parses key `key` and returns the Y of an "X/Y" value as a uint. Used for
// retrans:fastRetrans/lifetimeRetrans — we want the LIFETIME total (Y), which the
// optimizer diffs per cycle. If there's no "/" the whole value is parsed (a kernel
// that emits a bare count). ok is false when the key is absent or Y doesn't parse.
func ssUintY(line, key string) (uint64, bool) {
	s, ok := ssField(line, key)
	if !ok {
		return 0, false
	}
	if j := strings.IndexByte(s, '/'); j >= 0 {
		s = s[j+1:]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ssUint parses key `key` as a plain uint (no "/" form). Used for segs_out and
// bytes_acked. ok is false when absent or non-numeric.
func ssUint(line, key string) (uint64, bool) {
	s, ok := ssField(line, key)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// avgSrttMs averages srtt across established sockets (machine-wide; ss -ti). Used
// in PASSIVE mode. The srtt is the `rtt:X/Y` field's X (ms float).
func avgSrttMs() float64 {
	out, err := exec.Command("ss", "-ti", "state", "established").Output()
	if err != nil {
		return 0
	}
	var sum float64
	var n int
	for _, ln := range strings.Split(string(out), "\n") {
		v, ok := ssFloatX(ln, "rtt")
		if !ok || v <= 0 {
			continue
		}
		sum += v
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// ssTargetStat is the per-cycle aggregate over a single target's ESTABLISHED
// sockets, parsed from `ss -tin dst <target>`. rttMs is the mean srtt; the three
// counters are SUMMED LIFETIME totals across the target's sockets (the optimizer
// diffs them against the previous cycle). socks is how many sockets contributed —
// 0 means ss saw none this cycle (the caller then falls back to iface bytes).
type ssTargetStat struct {
	rttMs float64
	// minRttMs 是各 socket minrtt 的最小值 —— 全机口径的无负载底线。
	minRttMs float64
	// minRttP50Ms 是各 socket minrtt 的中位数, shaper 用它做 regime 分档
	// (minRtt 漂移 >=2x = 换路了) 和远端排队预算 (0.2*minRtt)。
	// ★ 为什么不能用上面那个全局 min: ssAll() 扫的是全机 established socket, 而这台
	// 机器上代理出口 (0.3-13ms) 和加速流 (50-264ms) 同时在跑。全局 min 由"这一拍恰好
	// 存在哪个本地 socket"决定 —— 一个短命的本地连接出现再消失, 就能让它在 0.3ms 和
	// 159ms 之间来回跳。shaper 拿它当 regime 判据, 于是每跳一次就是一次假换路:
	// C_hat 清零 + 强制回 SEEK + 慢层冻结 (实测 20 拍里触发 19 次)。即使本地 socket
	// 长期都在, band 也会被永久钉成 "lan", 把洲际链路的容量写进 <peer>|lan 缓存键。
	// 中位数跟 queueDelayMs 用的是同一个"每 socket 各自成立"的口径, 不会被单个
	// socket 拽走。
	minRttP50Ms float64
	// queueDelayMs 是各 socket (srtt - minrtt) 的中位数 = 排队延迟 E。
	// ★ 为什么是"每 socket 各减各的 minrtt 再取中位数", 而不是 mean(srtt)-min(minrtt):
	// 这台机器上是混合流量 (代理出口 0.3-13ms 和加速流 50-264ms 同时在跑), 全局的
	// srtt 均值减全局 minrtt 最小值算出来的是两个不同 regime 的差, 纯垃圾。每条流
	// 的 minrtt 是它自己那条路的底线, 所以 E_i 各自成立, 中位数才有物理意义。
	queueDelayMs float64
	retr         uint64 // sum of lifetime retrans:X/Y (Y = total retransmits)
	segs         uint64 // sum of lifetime segs_out:N
	acked        uint64 // sum of lifetime bytes_acked:N
	socks        int
}

// ssTarget runs `ss -tin dst <target>` (no -p: we don't need process info and
// omitting it is faster) and aggregates the per-socket fields for that peer only.
// This is the per-link replacement for the machine-wide avgSrttMs/snmp/iface
// signals: on a box carrying mixed traffic (proxy egress at 0.3-13ms alongside
// accelerated 50-264ms flows) the machine-wide floor is anchored by the wrong
// regime, poisoning the score. On exec error returns a zero stat (socks=0), which
// the caller treats as "no per-link signal this cycle".
func ssTarget(target string) ssTargetStat {
	out, err := exec.Command("ss", "-tin", "state", "established", "dst", target).Output()
	if err != nil {
		return ssTargetStat{}
	}
	return parseSSTarget(string(out))
}

// parseSSTarget aggregates the per-socket fields from `ss -tin` output: mean srtt,
// and the SUMMED LIFETIME retrans/segs_out/bytes_acked totals across all sockets
// in the output. socks counts the socket lines seen. Parsing is defensive — a
// socket missing a field (e.g. retrans: omitted when its lifetime count is zero)
// just contributes 0 for it. Split from ssTarget so it's unit-testable on a fixture
// (mirrors the readNeoqML/parseNeoqML split).
// ssRow 是一个 socket 的原始读数。拆出来是为了让"解析"和"聚合"分开: 同一次
// ss 输出要被按 RTT 档分组后各自聚合 (见 ssBands), 一次解析多次聚合。
type ssRow struct {
	// dst 是对端 "addr:port", 用于判定这条 socket 的流量是否真的经过被整形的网卡
	// (见 routecache.go)。ss 的地址行与统计行成对出现, 解析时由前者带给后者。
	dst    string
	minRtt float64
	srtt   float64
	retr   uint64
	segs   uint64
	acked  uint64
}

// ssMaxSocks 是单拍解析的 socket 上限。快环 2s 一拍, 而 ss 全量扫描在几百个
// socket 时是毫秒级 —— 上限存在的意义不是省 CPU, 而是给最坏情况 (连接风暴)
// 一个确定的代价上界, 免得控制器的一拍被 ss 拖成几百毫秒。
const ssMaxSocks = 1024

func parseSSRows(out string, maxRows int) []ssRow {
	var rows []ssRow
	pendingDst := ""
	for _, ln := range strings.Split(out, "\n") {
		// A socket's stats line is the one carrying the rtt field; the address line
		// (Local/Peer) has none. Use rtt presence to identify a real socket line.
		if _, ok := ssField(ln, "rtt"); !ok {
			// 地址行。`ss -tn state established` 在 state 已由过滤条件给定时**不打印
			// State 列**, 所以布局是 [0]=Recv-Q [1]=Send-Q [2]=Local [3]=Peer ——
			// 与 autoDetectPeer 取 f[3] 是同一个布局 (已在 green1 上核对过字段位置)。
			// 表头行也会落到这里, 但它的 f[3]="Address:Port" 不含 "." 或 "[", 被下面
			// 的形状检查挡掉; 即便漏过去, 紧随其后的真地址行也会把它覆盖。
			if f := strings.Fields(ln); len(f) >= 4 &&
				strings.Contains(f[3], ":") &&
				(strings.Contains(f[3], ".") || strings.HasPrefix(f[3], "[")) {
				pendingDst = f[3]
			}
			continue
		}
		if maxRows > 0 && len(rows) >= maxRows {
			break
		}
		var r ssRow
		r.dst = pendingDst
		pendingDst = ""
		if v, ok := ssFloatX(ln, "rtt"); ok && v > 0 { // srtt = X of rtt:X/Y
			r.srtt = v
		}
		// minrtt: 一个裸浮点 (无 X/Y), ssFloatX 直接给整值。ssField 的整词匹配保证
		// 它不会跟 rtt: 串味 (反之亦然)。
		if v, ok := ssFloatX(ln, "minrtt"); ok && v > 0 {
			r.minRtt = v
		}
		if v, ok := ssUintY(ln, "retrans"); ok { // lifetime total = Y of retrans:X/Y
			r.retr = v
		}
		if v, ok := ssUint(ln, "segs_out"); ok {
			r.segs = v
		}
		if v, ok := ssUint(ln, "bytes_acked"); ok {
			r.acked = v
		}
		rows = append(rows, r)
	}
	return rows
}

func aggregateRows(rows []ssRow) ssTargetStat {
	var st ssTargetStat
	var rttSum float64
	var rttN int
	var queueDelays []float64
	var minRtts []float64
	for _, r := range rows {
		st.socks++
		if r.srtt > 0 {
			rttSum += r.srtt
			rttN++
		}
		if r.minRtt > 0 {
			if st.minRttMs == 0 || r.minRtt < st.minRttMs {
				st.minRttMs = r.minRtt
			}
			minRtts = append(minRtts, r.minRtt)
			if r.srtt >= r.minRtt {
				queueDelays = append(queueDelays, r.srtt-r.minRtt)
			}
		}
		st.retr += r.retr
		st.segs += r.segs
		st.acked += r.acked
	}
	if rttN > 0 {
		st.rttMs = rttSum / float64(rttN)
	}
	st.queueDelayMs = percentile(queueDelays, 0.5)
	st.minRttP50Ms = percentile(minRtts, 0.5)
	return st
}

func parseSSTarget(out string) ssTargetStat {
	return aggregateRows(parseSSRows(out, 0))
}

// ssRowsAll 返回全机 established socket 的原始行, **不做任何过滤**。只给诊断用
// (bandmap): 控制信号必须过滤, 但取证不能 —— lo 和 docker bridge 的行正是判断
// "内层隧道 socket 能否代表外层路径"所需要的证据。
func ssRowsAll(maxSocks int) []ssRow {
	out, err := exec.Command("ss", "-tin", "state", "established").Output()
	if err != nil {
		return nil
	}
	return parseSSRows(string(out), maxSocks)
}

// ssBands 把全机 established socket 按 RTT 档分组, 每组各自聚合。
//
// 为什么必须分组再聚合, 而不是在全机总体上取某个统计量: 这台机器同一时刻并存
// 本地回环 (0.011ms)、同城 CDN (0.036ms)、docker 容器 (0.029/46ms) 和洲际
// (180/214/234/324ms) —— minRtt 跨五个数量级。在这样的总体上, 全局 min 由"这一拍
// 恰好存在哪个本地 socket"决定, 而中位数在样本少时同样不稳 (实测 n=2 时中位数就是
// 平均值, 跳得和 min 一样凶)。对错误的总体做任何统计量都救不回来 —— 总体本身要换。
// 档内的 socket 走物理上相近的路径, 它们的 minRtt/E 才有可比性, 中位数才有意义。
//
// 注意不能按地址段分类: 实测有 127.0.0.1 的 socket minrtt 是 234ms —— 那是 xray
// 的本地 socket 承载着洲际隧道流量。只有实测 RTT 能说明一个 socket 走的是哪条路。
func ssBands(rc *routeCache, maxSocks int) map[string]ssTargetStat {
	out, err := exec.Command("ss", "-tin", "state", "established").Output()
	if err != nil {
		return nil
	}
	byBand := map[string][]ssRow{}
	for _, r := range parseSSRows(string(out), maxSocks) {
		if r.minRtt <= 0 {
			continue // 没有 minrtt 就无法归档, 计入任何一档都是污染
		}
		// 只留真正经过被整形网卡的 socket。deficit 的分子 (shaper_sent) 只含这些
		// 字节, 分母混进别的网卡就是拿两批不相干的流量做差 —— 实测那会让 95% 的
		// acked 来自 docker bridge, 并已造成过一次错误的 C_hat 锁存。
		if rc != nil && !rc.via(r.dst) {
			continue
		}
		b := rttBand(r.minRtt)
		byBand[b] = append(byBand[b], r)
	}
	res := make(map[string]ssTargetStat, len(byBand))
	for b, rows := range byBand {
		res[b] = aggregateRows(rows)
	}
	return res
}

// ssAll 聚合本机全部 ESTABLISHED socket, 复用同一个解析器。
//
// shaper 的 deficit 分母是 Δshaper_sent —— 整个网卡出口的字节数, 所以分子那侧的
// Δbytes_acked 必须覆盖同一批流量, 只能是机器全量而不是某个对端。(minrtt/排队延迟
// 的 regime 混合问题由 parseSSTarget 里的"每 socket 各减各的 minrtt"解决。)
func ssAll() ssTargetStat {
	out, err := exec.Command("ss", "-tin", "state", "established").Output()
	if err != nil {
		return ssTargetStat{}
	}
	return parseSSTarget(string(out))
}

// isBadLink 是链路天气门: RTT 超过无负载底线的 3 倍, 说明是路径在抽风而不是我们的
// 参数在起作用。抽出来成函数是因为 shaper 快环要用同一个判据 (规格明确要求复用),
// 两处各写一遍迟早会漂移。
func isBadLink(rttMs, minRttMs float64) bool {
	return minRttMs > 0 && rttMs > 0 && (rttMs/minRttMs-1) > 2.0
}

// measureMachine derives bw/rtt/loss machine-wide: iface tx+rx bytes for bw,
// /proc/net/snmp OutSegs/RetransSegs for loss, ss -ti mean srtt for rtt. This is
// the PASSIVE/idle path and is byte-for-byte the original measure() behavior.
func (o *optimizer) measureMachine() metrics {
	cur := ifaceBytes(o.iface)
	dbytes := cur - o.prevBytes
	o.prevBytes = cur
	out, retr := readSnmpTcp()
	dout, dretr := out-o.prevOut, retr-o.prevRetr
	o.prevOut, o.prevRetr = out, retr
	var loss float64
	if dout > 0 {
		loss = float64(dretr) / float64(dout)
	}
	bw := float64(dbytes) * 8 / o.interval.Seconds() / 1e6
	return metrics{bwMbps: bw, rttMs: avgSrttMs(), lossPct: loss}
}

// measureTarget derives bw/rtt/loss scoped to o.target's sockets only (--target
// mode). rtt = mean srtt over those sockets; loss = Δretrans/Δsegs_out; bw =
// Δbytes_acked. The retrans/segs/acked counters are SUMMED LIFETIME totals, so we
// diff them against the previous cycle's sums (primed on the first cycle, whose
// delta is suppressed). CHURN: sockets open/close between cycles, so a summed
// lifetime total can DROP when a tracked socket closes — a naive delta would go
// negative (uint underflow). On any such drop we re-baseline this cycle (adopt the
// new lower totals) and return the previous good loss rather than a bogus delta;
// bw falls back to iface bytes for the cycle. When ss sees ZERO sockets this cycle
// (none established to the target right now) we also fall back to iface bytes for
// bw and leave rtt/loss at 0 (no per-link signal — score() guards rtt>0/loss>=0).
func (o *optimizer) measureTarget() metrics {
	st := ssTarget(o.target)
	// iface byte delta is always advanced so the counter never drifts, and is the
	// bw fallback when ss yields no usable per-link byte signal this cycle.
	cur := ifaceBytes(o.iface)
	dbytes := cur - o.prevBytes
	o.prevBytes = cur
	ifaceBw := float64(dbytes) * 8 / o.interval.Seconds() / 1e6
	return o.targetMetrics(st, ifaceBw)
}

// targetMetrics turns one per-target ss snapshot into metrics, advancing the
// optimizer's per-target counter baselines. ifaceBw is the iface tx+rx bw for this
// window, used as the bw fallback. Pure of I/O (the exec/iface reads happen in
// measureTarget) so the churn/re-baseline logic is unit-testable.
//
//   - socks==0: no sockets to the target this cycle. Keep the baselines (don't prime
//     off an empty read), fall back to iface bw, hold the last loss.
//   - rebased (first primed cycle OR any summed lifetime total DROPPED because a
//     tracked socket closed): adopt the new totals, emit NO delta this cycle —
//     iface bw + last loss — so a closed socket can't produce a negative delta.
//   - normal: loss = Δretrans/Δsegs_out (hold last loss if no new segments);
//     bw = Δbytes_acked (the target's acknowledged goodput; iface fallback if zero).
func (o *optimizer) targetMetrics(st ssTargetStat, ifaceBw float64) metrics {
	if st.socks == 0 {
		return metrics{bwMbps: ifaceBw, rttMs: st.rttMs, lossPct: o.lossFallback()}
	}
	rebased := !o.tgtPrimed ||
		st.retr < o.prevTgtRetr || st.segs < o.prevTgtSegs || st.acked < o.prevTgtAcked
	var loss, bw float64
	if rebased {
		loss = o.lossFallback()
		bw = ifaceBw
	} else {
		dretr := st.retr - o.prevTgtRetr
		dsegs := st.segs - o.prevTgtSegs
		dacked := st.acked - o.prevTgtAcked
		if dsegs > 0 {
			loss = float64(dretr) / float64(dsegs)
		} else {
			loss = o.lossFallback() // no new segments this cycle: hold last loss
		}
		// Δbytes_acked is the goodput actually acknowledged by the target; prefer it
		// over iface bytes (which include unrelated mixed traffic). If somehow zero
		// (no new acks despite live sockets), fall back to iface bytes.
		if dacked > 0 {
			bw = float64(dacked) * 8 / o.interval.Seconds() / 1e6
		} else {
			bw = ifaceBw
		}
		o.prevTgtLoss = loss
	}
	o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked, o.tgtPrimed = st.retr, st.segs, st.acked, true
	return metrics{bwMbps: bw, rttMs: st.rttMs, lossPct: loss}
}

// lossFallback is the loss value to report on a cycle where a fresh per-link loss
// delta can't be computed (churn re-baseline, no new segments, or no sockets):
// the last good per-link loss, which is 0 until the first real delta lands.
func (o *optimizer) lossFallback() float64 { return o.prevTgtLoss }

func (o *optimizer) measure() metrics {
	var m metrics
	if o.target != "" {
		m = o.measureTarget()
	} else {
		m = o.measureMachine()
	}
	// NeoQ experience signals, sampled in this same window so they line up with
	// bw/rtt/loss. Absent file (qdisc not loaded) => nqOK stays false and score()
	// falls back to the legacy formula. t0_pkts/t3_bytes are cumulative — diff them
	// against the previous reading exactly like the iface byte counters above. The
	// first primed cycle's delta is suppressed (counters could predate this run).
	if nq, ok := nqReader.read(true); ok {
		m.nqOK = true
		m.t0PeakDelayUs = float64(nq.t0PeakDelayUs)
		m.bulkFlows = nq.bulkFlows
		// ambient_share 必须在这里搬运, 否则 ambientSample 永远走 ss-diff 兜底, 而
		// 日志仍会打印 src=ss-diff —— 运维会读成"内核太老没导出这个键"。
		m.ambientPct, m.ambientOK = float64(nq.ambientShare), nq.ambientOK
		if o.nqPrimed {
			m.t0DeltaPkts = nq.t0Pkts - o.prevT0Pkts
			m.t3GoodputDelta = nq.t3Bytes - o.prevT3Bytes
		}
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq.t0Pkts, nq.t3Bytes, true
	}
	return m
}

// advanceRefs 推进 score() 的两个参照系 (peakBw 的 ratchet+衰减、minRtt 的
// ratchet+上漂)。调用方必须只在"活跃拍"(bwMbps >= idleBwFloorMbps) 调它。
//
// ★ 原来错在哪: 这两段长在 score() 里, 而 score() 在主循环中的位置早于 idle 门,
// 于是完全没有流量的拍也照样把 peakBw 乘 0.995、把 minRtt 乘 1.0005。green1 实测
// 一天有 3218 个 idle 拍, 0.995^3218 ≈ 1e-7 —— peakBw 被衰减到近零。流量一恢复,
// `bw > peakBw` 必然成立, peakBw 被 ratchet 拉平到当前 bw, 于是 bw/peakBw 恰好
// = 1.0: 一个 bw=0.4M 的拍拿到伪满分, 被记进 model.json 污染 KNN/UCB 的样本池,
// 还会被 EXPLORE 分支锁成 bestScore。生产日志的直接证据:
//
//	08:49:22 EXPLORE bw=0 rtt=32.9 loss=0.00% score=1.000
//	08:49:32 -> OPTIMIZE (peakBw=0Mbps minRtt=3.8ms)
//
// 冻结才是对的语义: idle 之后第一个活跃拍拿到"上一个活跃时代"的 peakBw —— 陈旧
// 但诚实, 而 ratchet 对真的新峰照常上调。
func (o *optimizer) advanceRefs(m metrics) {
	// C3: decaying reference. peakBw ratchets up on a new peak but decays
	// slowly otherwise, so a one-time lucky EXPLORE burst doesn't permanently
	// deflate every later score and make recorded samples incomparable over time.
	if m.bwMbps > o.peakBw {
		o.peakBw = m.bwMbps
	} else {
		o.peakBw *= 0.995 // ~12 min half-life at 5s cycles
	}
	if m.rttMs > 0 && (o.minRtt == 0 || m.rttMs < o.minRtt) {
		o.minRtt = m.rttMs
	} else if o.minRtt > 0 {
		o.minRtt *= 1.0005 // let the RTT floor drift up so the delay penalty isn't pinned on forever
	}
}

// observe 是主循环每拍对参照系做的全部动作: 先判"这一拍算不算活跃"(有没有真流量),
// 只有活跃才推进参照系, 然后打分。返回的 active 同时被 EXPLORE 计时 (exploreStep)
// 和 idle 门 (idleHold) 复用 —— 这三处必须是同一个判据, 各写各的正是本轮 bug 的成因。
func (o *optimizer) observe(m metrics) (sc float64, active bool) {
	active = m.bwMbps >= idleBwFloorMbps
	if active {
		o.advanceRefs(m)
	}
	return o.score(m), active
}

// score = bw/peakBw - alpha*clamp(rtt/minRtt-1, 0, delayPenaltyCap) - beta*clamp(loss, 0, lossPenaltyCap)
//
//	[ - gamma*clamp(t0_peak_delay_us/expressDelayBudgetUs, 0, 2.0) ]
//
// The bracketed Express-delay (experience) term is added ONLY when the NeoQ stats
// are available (nqOK) AND there was meaningful Express traffic this cycle
// (t0DeltaPkts > expressActivityFloorPkts). Without those — i.e. on a box with no
// new qdisc, or an idle Express tier — the score is EXACTLY the legacy formula, so
// gamma=0 (or stats-off) reproduces the prior behavior bit-for-bit.
//
// score() 本身是纯函数: 参照系 (peakBw/minRtt) 由 advanceRefs 单独推进, 且只在活跃
// 拍推进 —— 见那里的注释。
func (o *optimizer) score(m metrics) float64 {
	if o.peakBw <= 0 {
		return 0
	}
	s := m.bwMbps / o.peakBw
	// 延迟项和丢包项都封顶 (delayPenaltyCap / lossPenaltyCap): 原来两项都无上界,
	// 单个天气拍就能产出 < -1 的 score, 而 bestKnown/STABILIZE 是跨时间比较 score
	// 的 —— 一个没有下界的量做不了这种比较。封顶后 s 的下界是确定的。
	if o.minRtt > 0 && m.rttMs > 0 {
		if r := m.rttMs/o.minRtt - 1; r > 0 {
			s -= o.alpha * clampF(r, 0, delayPenaltyCap)
		}
	}
	s -= o.beta * clampF(m.lossPct, 0, lossPenaltyCap)
	// Experience term: penalize Express (interactive/ACK/retransmit) queuing delay.
	// Gated on stats availability + real Express activity so it never fires on a box
	// without the new qdisc or on an idle tier (where a stray peak is just noise).
	if o.gamma > 0 && m.nqOK && m.t0DeltaPkts > expressActivityFloorPkts {
		s -= o.gamma * clampF(m.t0PeakDelayUs/expressDelayBudgetUs, 0, 2.0)
	}
	// Jitter term: penalize RTT variance (network quality = throughput + delay +
	// variance). jitter = MAD of the recent-RTT ring; the penalty is
	// jitterDelta*clamp(jitter/rtt, 0, 1). Gated on a sufficiently full ring (so a
	// short/empty ring is a no-op and score() stays the legacy formula) and rtt>0.
	// The ring is fed only on clean cycles (bad-link cycles are skipped at the push
	// site), so a weather spike can't inflate the MAD.
	if len(o.rttRing) >= jitterMinSamples && m.rttMs > 0 {
		jitterMs := medianAbsDev(o.rttRing)
		s -= jitterDelta * clampF(jitterMs/m.rttMs, 0, 1)
	}
	// Goodput-variance term: 同样的均值下, 每拍上下翻倍的吞吐比平稳的吞吐体验差
	// 得多, 而 bw/peakBw 这一项对两者是无差别的。用 MAD/median (而不是 stddev/mean)
	// 是因为这条链路本来就带天气尖峰, MAD 容忍到 50% 离群点。Gated on ring
	// occupancy 所以空环/短环是彻底的 no-op (向后兼容旧 score)。
	if len(o.bwRing) >= jitterMinSamples {
		if med := percentile(o.bwRing, 0.5); med > 0 {
			s -= goodputVarDelta * clampF(medianAbsDev(o.bwRing)/med, 0, 1)
		}
	}
	// R-variance term: 惩罚控制器自己抖 R。nil shaper / 样本不足 -> ok=false -> no-op。
	if cv, ok := o.sh.rateCV(); ok {
		s -= rateCVDelta * clampF(cv, 0, 1)
	}
	return s
}

// exploreStep 推进 EXPLORE 相位, 返回是否转入了 OPTIMIZE。
//
// ★ 原来错在哪: exploreT 每拍无条件 ++, 且转相位的判据 bw >= peakBw*0.95 在 bw 和
// peakBw 都被 idle 压到近零时恒真 —— idle 中重启一次服务, 空转 3 拍 (15s) 就转
// OPTIMIZE, 紧接着的 `o.bestScore = sc` 把那一拍的伪满分 (见 advanceRefs) 锁成
// bestScore。之后所有正常 score 都比不过它, coordinate ascent 会持续判定"变差"而
// 回退。计时和相位判定因此都只认活跃拍。
func (o *optimizer) exploreStep(m metrics, sc float64, active bool) bool {
	// 墙钟兜底必须在活跃门**之前**: 只认活跃拍的话, 一台从不跑到 idleBwFloorMbps
	// 的机器会**永远停在 EXPLORE** —— 保持那套一次性激进基线、从不调参, 而且日志上
	// 完全看不出异常。green1 正是这种机器 (6.5 小时里只有 7.6% 的拍有实质流量)。
	// 旧代码 6 拍必转是靠 idle 拍也计数换来的, 拆掉活跃门时把这个性质一起弄丢了。
	//
	// 兜底转出去是安全的: OPTIMIZE 相位在 idle 拍照样被 idle 门挡住, 什么都不做。
	// 真正要防的只是"用 idle 拍的伪满分锁 bestScore", 所以 bestScore 仅在活跃拍采信。
	o.exploreWall++
	if o.exploreWall >= exploreWallMax && o.phase == "EXPLORE" {
		o.phase = "OPTIMIZE"
		if active {
			o.bestScore = sc
		}
		return true
	}
	if !active {
		return false
	}
	o.exploreT++
	if (m.bwMbps >= o.peakBw*0.95 && o.exploreT >= 3) || o.exploreT >= 6 {
		o.phase = "OPTIMIZE"
		o.bestScore = sc
		return true
	}
	return false
}

// idleHold 是慢层的 no-traffic guard: 流量太少时 score 是纯噪声, 拿它 steering 只会
// thrash 参数, 这一拍必须 hold 住。返回 true 表示"这一拍到此为止"。
//
// ★ 原来错在哪: 这个门直接 continue, 不像 badLink / SHAPER-BUSY 那两条 continue 那样
// 丢掉挂起的探测。后果: 探测在第 N 拍落下, 中间 idle 三小时, 流量恢复后
// delta = smScore(现在) - prevScore(三小时前), 一个横跨两个 regime 的差值被记到那个
// 参数头上。活跃拍必须原样放行, 否则 delta-credit 永远拿不到基线。
func (o *optimizer) idleHold(active bool) bool {
	if active {
		return false
	}
	o.havePrev = false
	o.pendingSign = 0
	return true
}

func (o *optimizer) apply(t *tunable) {
	v := strconv.Itoa(t.cur)
	switch {
	case t.name == shaperHeadroomParam:
		// 进程内参数, 不落 proc 文件: 直接推给快环 (百分数 -> 小数)。
		o.sh.setHeadroom(float64(t.cur) / headroomPctScale)
	case t.path == neoqSparseProc:
		// Sparse gate expects "<window_us> <thresh_bytes>" (kernel sscanf "%u %u").
		// Window is held fixed at 100000us; t.cur is the byte threshold.
		_ = os.WriteFile(t.path, []byte("100000 "+v), 0o644)
	case t.path != "":
		_ = os.WriteFile(t.path, []byte(v), 0o644)
	default:
		_ = writeSysctl(t.name, v)
	}
}

// applyCodel maps the measured path RTT to NeoQ CoDel target/interval and pushes
// them via /proc/net/neoq_codel. The egress qdisc can't measure RTT itself (it
// never sees the returning ACKs), so the CLI — which knows RTT from ss — drives
// RTT-adaptive AQM. Without this NeoQ runs a flat 5ms target/100ms interval that
// over-drops on high-RTT links: interval < RTT means CoDel re-drops before a
// drop's cwnd reduction has propagated back, collapsing throughput.
// target = max(15ms, RTT/8), interval = 2*RTT (must exceed 1 RTT).
//
// ★ 为什么从 clamp(RTT/4,5,60) 改成 clamp(max(15ms, RTT/8),5,60): 以前本机根本不
// 排队 (瓶颈在远端), CoDel 的 target 只能按"路径 RTT 的比例"猜。shaper 绑定之后本机
// 队列才是主队列, target 应该按"本机队列预算"定 —— 我愿意在本机容忍多少毫秒的驻留
// 队列, 这跟对端有多远无关。RTT/8 让高 RTT 路径仍有一点比例项 (468ms -> 58ms),
// 15ms 地板保证低 RTT 路径不会被一个过小的 target 打成过度丢包。注意 max(15ms,·)
// 之后 5ms 的下界已经够不着了, 保留 clamp 只是为了写死上下界的形状。
func applyCodel(rttMs float64) {
	target, interval, ok := codelParams(rttMs)
	if !ok {
		return
	}
	_ = os.WriteFile("/proc/net/neoq_codel",
		[]byte(fmt.Sprintf("%d %d", int(target), int(interval))), 0o644)
}

// codelParams is the pure formula half of applyCodel (target/interval in us),
// split out so the mapping is unit-testable without a writable /proc (mirrors the
// readNeoqML/parseNeoqML and ssTarget/parseSSTarget splits). ok=false for rttMs<=0.
func codelParams(rttMs float64) (target, interval float64, ok bool) {
	if rttMs <= 0 {
		return 0, 0, false
	}
	rttUs := rttMs * 1000
	return clampF(math.Max(15000, rttUs/8), 5000, 60000), clampF(rttUs*2, 100000, 600000), true
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// settle waits out the transient after a config change, then re-baselines the
// byte/segment counters so the NEXT measure() window covers only steady state
// (B5). Without this the window straddles the old config's tail and the new
// config's ramp-up, so the score is a blend of two configs and can't be
// attributed to the change. settle = clamp(8*RTT, 2s, 5s): 8 RTTs is enough for
// a cwnd/pacing change to propagate and re-stabilize, floored at 2s (so it's
// never shorter than a couple of measurement granularities) and capped at 5s (so
// a very high-RTT link doesn't stall the loop). rttMs<=0 falls back to the floor.
func (o *optimizer) settle(rttMs float64) {
	d := 2 * time.Second
	if rttMs > 0 {
		d = clampDur(time.Duration(8*rttMs)*time.Millisecond, 2*time.Second, 5*time.Second)
	}
	time.Sleep(d)
	o.prevBytes = ifaceBytes(o.iface)
	o.prevOut, o.prevRetr = readSnmpTcp()
	// Per-target mode: re-baseline the target's summed lifetime ss counters too, so
	// the next measure() window's loss/bw deltas cover only steady state (consistent
	// with the iface/snmp re-baseline above). Leave tgtPrimed/prevTgtLoss as-is when
	// no sockets are up right now, so we don't prime off an empty read or forget the
	// last good loss across a config change.
	if o.target != "" {
		if st := ssTarget(o.target); st.socks > 0 {
			o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked, o.tgtPrimed = st.retr, st.segs, st.acked, true
		}
	}
	// Re-baseline the NeoQ cumulative counters too, so the next measure() window's
	// t0_pkts/t3_bytes deltas cover only steady state (consistent with the iface/snmp
	// re-baseline above). This read also resets the kernel's reset-on-read Express
	// peak, so the peak the next measure() sees is the settled window's, not the
	// config-change transient's. Harmless no-op when the qdisc isn't loaded.
	if nq, ok := nqReader.read(true); ok {
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq.t0Pkts, nq.t3Bytes, true
	}
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// cmdOptimize runs the adaptive parameter search (upstream CC + downstream NeoQ boost).
//
//	lotspeedctl optimize --iface eth0 [--interval N]
func cmdOptimize(args []string) error {
	interval := 5 * time.Second
	iface := ""
	target := ""
	algo := "coord"       // "coord" (coordinate ascent) | "ucb" (UCB1 bandit per param)
	gamma := defaultGamma // Express-delay penalty weight; --gamma 0 disables the term
	shaperOn := false     // --shaper: 启用 2s 的整形速率快环 (独立于这里的慢环)
	shaperMaxMbps := 0.0  // --shaper-max-mbps: 覆盖 R_max (默认读网卡线速)
	// --legacy-bandit: 一键回到本轮之前的行为 (tun 表恢复、坐标上升/UCB 照跑,
	// loss_thresh 闭环停用)。整期可回退, 出事就加这个开关重启。
	legacyBandit := false
	ltAuto := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 < len(args) {
				if n, e := strconv.Atoi(args[i+1]); e == nil && n > 0 {
					interval = time.Duration(n) * time.Second
				}
				i++
			}
		case "--iface":
			if i+1 < len(args) {
				iface = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				target = args[i+1]
				i++
			}
		case "--algo":
			if i+1 < len(args) {
				algo = args[i+1]
				i++
			}
		case "--gamma":
			if i+1 < len(args) {
				if g, e := strconv.ParseFloat(args[i+1], 64); e == nil && g >= 0 {
					gamma = g
				}
				i++
			}
		case "--shaper":
			shaperOn = true
		case "--legacy-bandit":
			legacyBandit = true
		case "--auto-loss-thresh":
			ltAuto = true
		case "--shaper-max-mbps":
			if i+1 < len(args) {
				if v, e := strconv.ParseFloat(args[i+1], 64); e == nil && v > 0 {
					shaperMaxMbps = v
				}
				i++
			}
		}
	}
	if iface == "" {
		return fmt.Errorf("usage: optimize --iface <dev> [--interval N] [--target IP] [--algo coord|ucb] [--gamma G] [--shaper] [--shaper-max-mbps M] [--legacy-bandit]")
	}
	// Always record samples passively from whatever real traffic the kernel
	// is moving. --target is now purely informational — if set, it's stamped
	// onto sample.Feature.Target; if not, the dominant peer is detected from
	// `ss -tn` each cycle. This means systemd just runs `optimize --iface eth0`
	// with no human-supplied IP, and the model learns from production traffic.
	var feat linkFeature
	rttSamples := []float64{}
	bwSamples := []float64{}
	type windowBestT struct {
		score         float64
		params        paramSet
		loss          float64
		changedParam  string  // B1: the coordinate whose move reached this best score
		delta         float64 // B1: that move's score change (raw, pre-conditioning)
		badLink       bool    // B2: was this window-best captured during link weather?
		expressPeakUs float64 // NeoQ: Express recent-peak delay at the best cycle
		t3Goodput     uint64  // NeoQ: bulk bytes moved in the best cycle's window
		jitterMs      float64 // RTT-ring MAD (variance signal) at the best cycle
	}
	windowBest := windowBestT{score: -1e9}
	windowCycle := 0
	const recordEveryN = 5
	if target != "" {
		feat.Target = target
		fmt.Printf("optimize: explicit target=%s, model=%s\n", target, modelPath())
		fmt.Printf("measure scope: target=%s (per-link)\n", target)
	} else {
		fmt.Printf("optimize: PASSIVE mode (peer auto-detected per cycle), model=%s\n", modelPath())
		fmt.Printf("measure scope: machine-wide\n")
	}
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed (need root?): %w", err)
	}

	// 快环 (2s) 和慢环 (5s+settle) 是两个 goroutine: 速率有机制性的逐步反馈, 每个
	// 动作都能用自己的直接后果检验; sysctl 那些二阶参数只有统计归因, 必须慢慢来。
	// 两者的隔离由 slowLayerReady() 的闸门保证。
	var sh *shaper
	if shaperOn {
		sh = newShaper(iface, target, shaperMaxMbps)
		// 护栏 4 的进程内一半: 被 SIGTERM/SIGINT 打断时也把 rate 归零。systemd 的
		// ExecStopPost 覆盖服务路径, 这里覆盖手动调试路径 —— 无论哪条路, "控制器
		// 不在"都必须等于"完全无整形", 而不是"卡在最后一个速率上"。
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigc
			_ = writeNeoqRate(0)
			os.Exit(0)
		}()
		// stop=nil: nil channel 在 select 里永不就绪, 所以只有 ticker 分支会触发。
		go sh.run(nil)
	}

	o := newOptimizer(iface, target, interval, gamma, sh, legacyBandit)
	o.ltAuto = ltAuto
	// UCB bandit: pre-load it with all prior samples so a fresh process
	// inherits learning from previous runs (crucial for systemd auto-restart).
	// Instantiated in BOTH modes: in coord mode it backs delta-credit (B1) and the
	// effect-size freeze (B4); in ucb mode it also steers. The exploration constant
	// is unused in coord mode (we only read arm means/effect-size, never suggest()).
	ucb := newUCB(o.tun, math.Sqrt(2))
	prior := loadModel()
	// replayed < len(Samples) 时差额是被纪元门隔离掉的存量伪高分样本 (见
	// modelEpochTS) —— 报总数会骗人, 所以两个数都打出来。
	replayed := ucb.loadFromSamples(prior.Samples)
	fmt.Printf("UCB initialized from %d/%d prior samples (%d quarantined as pre-epoch)\n",
		replayed, len(prior.Samples), len(prior.Samples)-replayed)
	// EXPLORE: aggressive grab to discover peak (up+down) throughput.
	// Aggressive intercontinental baseline (non-tunable knobs set once): remove the
	// cwnd ceiling, max out high-delay Hybla compensation, shrink safety margins,
	// extend STARTUP for high-RTT ramp. Verified +186% vs bbr on a lossy link.
	_ = writeSysctl("turbo_startup", "1")
	_ = writeSysctl("startup_gain", "400")
	_ = writeSysctl("startup_min_rounds", "8") // more STARTUP rounds for high RTT
	_ = writeSysctl("max_cwnd", "524288")      // K2: remove ceiling; 524288 pkts ≈ 760MB inflight, ample for 1.5Gbps even at very high RTT
	_ = writeSysctl("min_cwnd", "100")         // higher cwnd floor
	_ = writeSysctl("hd_cwnd_gain", "200")     // high-delay cwnd 2x
	_ = writeSysctl("hd_pacing_gain", "160")   // high-delay pacing 1.6x
	_ = writeSysctl("inflight_headroom", "5")  // smaller safety margin = more aggressive
	// Warm-start from the model if we have samples & a target. This is the
	// "use what you've learned" half of the data loop — without it the model
	// only grows but never repays the cost of growing it.
	if target != "" {
		mdl := loadModel()
		if len(mdl.Samples) > 0 {
			// Build a coarse feature from any prior sample with this target
			// so KNN distance has a reasonable starting point; predict fills the rest.
			var seed linkFeature
			seed.Target = target
			for _, s := range mdl.Samples {
				if s.Feature.Target == target {
					seed = s.Feature
					break
				}
			}
			pred := mdl.predict(seed)
			applied := 0
			for i := range o.tun {
				if v, ok := pred[o.tun[i].name]; ok && v >= o.tun[i].min && v <= o.tun[i].max {
					o.tun[i].cur = v
					o.apply(&o.tun[i])
					applied++
				}
			}
			// 报**纪元后可用**的样本数, 不是文件里的总数。predict 会跳过
			// pre-epoch 样本 (见 modelEpochTS), 报总数会让运维以为那些样本参与了
			// 决策 —— 实际参与的可能是 0 条, 参数全来自 heuristicPlan 冷启动。
			usable := 0
			for _, sm := range mdl.Samples {
				if sm.TS >= modelEpochTS {
					usable++
				}
			}
			fmt.Printf("warm-start from model (k=%d/%d samples usable, %d pre-epoch): %d params applied\n",
				usable, len(mdl.Samples), len(mdl.Samples)-usable, applied)
		}
	}
	nq0, nqUp := nqReader.read(true)
	mode := "MECHANISM (tun table empty; loss_thresh closed-loop + frozen consts)"
	if legacyBandit {
		mode = fmt.Sprintf("LEGACY-BANDIT (%d tunables, loss_thresh closed-loop OFF)", len(o.tun))
	}
	fmt.Printf("optimize: iface=%s interval=%v gamma=%.2f neoq_ml=%v shaper=%v mode=%s phase=EXPLORE (aggressive grab, tx+rx)\n",
		iface, interval, gamma, nqUp, sh.running(), mode)
	o.prevBytes = ifaceBytes(iface)
	o.prevOut, o.prevRetr = readSnmpTcp()
	// Per-target mode: prime the target's summed lifetime ss counters alongside
	// iface/snmp so the first measure() yields a real delta. If no sockets are up
	// yet, leave it unprimed — the first measureTarget() with sockets self-primes
	// via its !tgtPrimed re-baseline branch.
	if target != "" {
		if st := ssTarget(target); st.socks > 0 {
			o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked, o.tgtPrimed = st.retr, st.segs, st.acked, true
		}
	}
	// Prime the NeoQ cumulative-counter baseline alongside iface/snmp so the first
	// measure() produces a real delta (not a suppressed first-cycle one).
	if nqUp {
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq0.t0Pkts, nq0.t3Bytes, true
	}

	for {
		time.Sleep(interval)
		m := o.measure()
		// 参照系推进、EXPLORE 计时 (exploreStep)、idle 门 (idleHold) 三件事共用
		// observe 判出来的这一个 active —— idle 拍照样推进参照系正是 peakBw 被衰减
		// 到近零、进而制造伪满分的根因 (见 advanceRefs)。
		sc, active := o.observe(m)
		ts := time.Now().Format("15:04:05")

		// Anti-noise gate for NeoQ-only params: a genuinely mixed workload needs
		// concurrent bulk flows AND live Express traffic this window. Re-evaluated
		// every cycle; consumed by nextTi to keep neoq_sparse_thresh out of the probe
		// rotation when it would be a no-op. Stays false when stats are unavailable.
		o.mixedWorkload = m.nqOK && m.bulkFlows >= 1 && m.t0DeltaPkts >= expressActivityFloorPkts

		// N3: drive RTT-adaptive CoDel for NeoQ from the measured RTT (smoothed).
		if m.rttMs > 0 {
			if o.codelRtt == 0 {
				o.codelRtt = m.rttMs
			} else {
				o.codelRtt = 0.8*o.codelRtt + 0.2*m.rttMs
			}
			applyCodel(o.codelRtt)
		}

		// loss_thresh 机制闭环 —— 与 applyCodel 并列的第二个"驱动机制"动作 (两者都是
		// 测量 -> 直接算 -> 写内核, 都不经过统计归因)。
		// ★ 只在活跃拍推进 (D1): idle 拍的 loss 读数是垃圾, 让它进 EWMA 会把 thresh
		//   拖向噪声。也**不遗忘** —— 门在 applyLossThresh 里, 见那里的注释。
		// ★ 放在 EXPLORE 分支之前, 所以两个相位都在跑: 它是机制不是搜索。
		if line := o.applyLossThresh(m, active); line != "" {
			fmt.Printf("%s %s\n", ts, line)
		}

		if o.phase == "EXPLORE" {
			if o.exploreStep(m, sc, active) {
				fmt.Printf("%s -> OPTIMIZE (peakBw=%.0fMbps minRtt=%.1fms)\n", ts, o.peakBw, o.minRtt)
			}
			fmt.Printf("%s EXPLORE bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f\n", ts, m.bwMbps, m.rttMs, m.lossPct*100, sc)
			continue
		}

		// B2 link-weather gate: an RTT spike >3x the unloaded floor is the path
		// misbehaving, not our params. score() already turns that into a deeply
		// negative number; attributing it to whatever coordinate we happen to be
		// probing teaches the optimizer the wrong lesson (this is exactly how a
		// real -0.909 sample came purely from an RTT spike). On such cycles we
		// still RECORD the sample (tagged BAD-LINK — bad-link data is useful to
		// the KNN), but we skip UCB credit and skip the accept/revert decision.
		badLink := o.minRtt > 0 && m.rttMs > 0 && (m.rttMs/o.minRtt-1) > 2.0

		// Jitter ring: push this cycle's RTT only on a CLEAN cycle (rtt>0, not
		// bad-link). A bad-link cycle's RTT is a weather spike, not steady-state
		// jitter — including it would poison the MAD that score() penalizes on. The
		// ring holds the last jitterRingLen clean RTTs; score() reads it next cycle.
		if !badLink && m.rttMs > 0 {
			o.rttRing = append(o.rttRing, m.rttMs)
			if len(o.rttRing) > jitterRingLen {
				o.rttRing = o.rttRing[1:]
			}
		}
		// 同样的卫生标准喂 goodput 环: 只有干净的一拍才进, 否则天气尖峰会把方差
		// 惩罚项灌爆, 让 score 去惩罚一个不是参数造成的抖动。
		// 活跃门必须与 advanceRefs/idle 门同一判据 (idleBwFloorMbps): 原来用的是
		// m.bwMbps > 0, 于是 idle 拍的近零吞吐照样进环, 把 MAD/median 灌成"idle 与
		// 活跃混排"的分布 —— goodput 方差惩罚项于是惩罚的是"这台机器有没有流量",
		// 而不是"这组参数稳不稳"。与参照系腐蚀是同一族的口径污染。
		if !badLink && m.bwMbps >= idleBwFloorMbps {
			o.bwRing = append(o.bwRing, m.bwMbps)
			if len(o.bwRing) > jitterRingLen {
				o.bwRing = o.bwRing[1:]
			}
		}

		// Live feature building: cap samples and use MAD-filtered medians so
		// occasional outliers don't poison what we persist to the model.
		if m.rttMs > 0 {
			rttSamples = append(rttSamples, m.rttMs)
			if len(rttSamples) > 20 {
				rttSamples = rttSamples[1:]
			}
		}
		if m.bwMbps > 0 {
			bwSamples = append(bwSamples, m.bwMbps)
			if len(bwSamples) > 20 {
				bwSamples = bwSamples[1:]
			}
		}
		// Window-best sampling: every recordEveryN OPT cycles, persist the
		// best-scoring (params, score) seen in that window. This guarantees
		// the model keeps growing even when EXPLORE captured the global best
		// and no later step exceeds it.
		// Always record (both explicit-target and PASSIVE mode). In PASSIVE
		// mode feat.Target is filled from the dominant peer at record time.
		if sc > windowBest.score {
			windowBest.score = sc
			windowBest.params = o.paramsSnapshot()
			windowBest.loss = m.lossPct
			// B1: tag this best with the coordinate that moved to reach it, so the
			// persisted sample can carry single-param credit (changedParam/delta).
			// havePrev means a probe is outstanding (probedTi/probedVal/prevScore set).
			if o.havePrev {
				windowBest.changedParam = o.tun[o.probedTi].name
				windowBest.delta = sc - o.prevScore
			} else {
				windowBest.changedParam = ""
				windowBest.delta = 0
			}
			windowBest.badLink = badLink
			windowBest.expressPeakUs = m.t0PeakDelayUs
			windowBest.t3Goodput = m.t3GoodputDelta
			// Jitter at the best cycle: MAD of the ring, matching what score() saw
			// (0 when the ring is too short for the jitter term to apply).
			if len(o.rttRing) >= jitterMinSamples {
				windowBest.jitterMs = medianAbsDev(o.rttRing)
			} else {
				windowBest.jitterMs = 0
			}
		}
		windowCycle++
		if windowCycle >= recordEveryN && len(rttSamples) >= 3 && len(bwSamples) >= 3 && windowBest.params != nil {
			clean := madFilter(rttSamples, 3.0)
			feat.RttMs = percentile(clean, 0.5)
			feat.RttMin = percentile(clean, 0.1)
			feat.Jitter = percentile(clean, 0.9) - feat.RttMin
			feat.BwMbps = trimmedMean(bwSamples, 0.2)
			feat.LossPct = windowBest.loss
			if target == "" {
				feat.Target = autoDetectPeer() // who's the dominant peer right now?
			}
			// Sanity gate: only filter samples with no real traffic (bw<5M).
			// Negative-score samples ARE valuable — they teach UCB which
			// params to avoid on bad-link states (high loss / RTT spike).
			if feat.BwMbps < 5 {
				fmt.Printf("    -> sample SKIPPED (no real traffic: bw=%.0fM)\n", feat.BwMbps)
			} else if n, err := recordSample(feat, windowBest.params, windowBest.score, windowBest.changedParam, windowBest.delta, windowBest.expressPeakUs, windowBest.t3Goodput, windowBest.jitterMs); err == nil {
				tag := "good"
				if windowBest.badLink || windowBest.score < 0 {
					tag = "BAD-LINK"
				}
				fmt.Printf("    -> sample recorded [%s] (model now has %d, score=%.3f, bw=%.0fM loss=%.1f%% changed=%s d=%.3f xpeak=%.0fus t3d=%dB)\n",
					tag, n, windowBest.score, feat.BwMbps, feat.LossPct*100, windowBest.changedParam, windowBest.delta, windowBest.expressPeakUs, windowBest.t3Goodput)
			}
			windowCycle = 0
			windowBest = windowBestT{score: -1e9}
		}
		// no-traffic guard (idleHold: hold 住参数并丢掉挂起的探测)。它必须排在 ucb
		// 分支之前 —— 原来排在之后, 于是 --algo ucb 下 idle 拍照样 suggest+apply
		// 步参数 (生产跑的是 coord, 所以没炸)。
		if o.idleHold(active) {
			fmt.Printf("%s OPT idle (bw=%.0fM<%.0f, no signal) — holding params\n", ts, m.bwMbps, idleBwFloorMbps)
			continue
		}
		// 机制模式: tun 表为空, 没有坐标可步进, 下面整段搜索逻辑 (UCB / 坐标上升 /
		// STABILIZE) 都不适用, 而且它们全都会索引 o.tun —— 空表下 nextTi 的 %n 会
		// panic。主循环到此就是完整的一拍: 测量 -> 驱动机制 (上面的 applyCodel /
		// loss_thresh 闭环) -> 记录遥测样本 (上面的 windowBest)。
		if len(o.tun) == 0 {
			fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f | mechanism-only (lt=%d)%s\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, sc, o.lt.cur, o.sh.statusLine())
			continue
		}
		// UCB mode: each cycle pick a fresh value per parameter (rotate which
		// param we update so coordinated effects stay observable). Credit the
		// arm we last steered with the delta vs the prior config (B1+B3), and
		// skip credit entirely on a bad-link cycle (B2).
		if algo == "ucb" {
			if o.havePrev && !badLink {
				ucb.update(o.tun[o.probedTi].name, o.probedVal, sc-o.prevScore)
			}
			o.prevScore = sc
			t := &o.tun[o.ti]
			next := ucb.suggest(t.name)
			t.cur = next
			o.apply(t)
			o.probedTi, o.probedVal, o.havePrev = o.ti, next, true
			o.ti = o.nextTi(o.ti)
			fmt.Printf("%s UCB bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f | %s -> %d (suggest)\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, sc, t.name, next)
			o.settle(m.rttMs) // B5: let the new config reach steady state before the next window
			continue
		}
		// OPTIMIZE: coordinate ascent with delta-credited revert-on-regression.
		// SMOOTH (抚平): EWMA the control signal so one noisy cycle (RTT/bw blip
		// on a jittery link) can't trigger a param change. Decisions use smScore.
		if o.smScore == 0 {
			o.smScore = sc
		} else {
			o.smScore = 0.6*o.smScore + 0.4*sc
		}
		// CORRECT (纠正, defensive): re-clamp every tunable into range each cycle so
		// no drift/garbage value (observed loss_thresh=224, hd_rho_max=1550) can
		// persist in memory or be re-applied to the kernel.
		for i := range o.tun {
			if c := clampInt(o.tun[i].cur, o.tun[i].min, o.tun[i].max); c != o.tun[i].cur {
				o.tun[i].cur = c
				o.apply(&o.tun[i])
			}
		}
		// B2 bad-link cycle: skip BOTH the UCB credit and the accept/revert
		// decision. Leave the current probe in place and drop the outstanding
		// probe bookkeeping so the next clean cycle re-baselines prevScore — we
		// don't want a weather-inflated delta to drive the next decision.
		if badLink {
			o.havePrev = false
			o.pendingSign = 0
			fmt.Printf("%s OPT BAD-LINK (rtt=%.1f/%.1fx min) — skip credit+decision, hold %s=%d\n",
				ts, m.rttMs, m.rttMs/o.minRtt, o.tun[o.ti].name, o.tun[o.ti].cur)
			continue
		}
		// 快慢两层隔离: shaper 不在稳定 HOLD 时 (SEEK/PROBE/BACKOFF/OBSERVE/YIELD,
		// 或刚进 HOLD 还没连续稳 3 拍), 这一拍的 score 变化主要由速率变化造成, 不是
		// 坐标步进造成的。跟 bad-link 一样整拍跳过 (既不记账也不做接受/回退) ——
		// 硬着头皮归因只会教会 bandit 错的东西。shaper 关闭 / 内核不支持时恒放行。
		if !o.sh.slowLayerReady() {
			o.havePrev = false
			o.pendingSign = 0
			fmt.Printf("%s OPT SHAPER-BUSY — slow layer frozen%s\n", ts, o.sh.statusLine())
			continue
		}
		// B1 delta-credit: the score change since the prior config is attributable
		// to the SINGLE coordinate we moved last cycle. Credit only that arm (the
		// conditioning into [0,1] happens inside ucb.update). This replaces the old
		// loop that smeared one scalar score onto all 5 params.
		var delta float64
		haveDelta := o.havePrev
		if haveDelta {
			delta = o.smScore - o.prevScore
			ucb.update(o.tun[o.probedTi].name, o.probedVal, delta)
		}
		// B4 effect-size freeze: once the just-credited param has ≥5 pulls, if its
		// best and worst arm means differ by <0.05 (conditioned-reward units) it has
		// no measurable effect on this link — freeze it (stop probing it). This is
		// the generic catch for inert params (what neoq_boost was on single flow).
		if haveDelta {
			name := o.tun[o.probedTi].name
			if spread, pulls := ucb.effectSize(name); pulls >= 5 && spread < 0.05 && !o.frozen[name] {
				o.frozen[name] = true
				o.freezeMinRtt = o.minRtt
				fmt.Printf("%s FREEZE %s (effect=%.3f over %d pulls < 0.05) — no measurable effect, parking it\n",
					ts, name, spread, pulls)
			}
		}
		// B4 unfreeze on regime change: if the unloaded RTT floor has shifted by ≥2x
		// since we froze (a different path/route — a param inert on one link may
		// matter on another), thaw everything and re-explore.
		if len(o.frozen) > 0 && o.freezeMinRtt > 0 && o.minRtt > 0 {
			if r := o.minRtt / o.freezeMinRtt; r >= 2 || r <= 0.5 {
				o.frozen = map[string]bool{}
				fmt.Printf("%s UNFREEZE all (minRtt regime %.1f->%.1fms) — re-exploring\n",
					ts, o.freezeMinRtt, o.minRtt)
			}
		}
		// Snapshot the best-known stable config (all params at the highest smScore).
		if o.bestParams == nil || o.smScore > o.bestKnown {
			o.bestKnown = o.smScore
			o.bestParams = make([]int, len(o.tun))
			for i := range o.tun {
				o.bestParams[i] = o.tun[i].cur
			}
		}
		// CORRECT+SMOOTH (纠正抚平): if smScore collapses well below best-known for
		// several consecutive cycles, the search wandered into an unstable region;
		// snap the WHOLE config back to the best-known-stable point.
		if o.bestKnown > 0 && o.smScore < 0.6*o.bestKnown {
			o.unstableN++
			if o.unstableN >= 3 {
				for i := range o.tun {
					o.tun[i].cur = o.bestParams[i]
					o.apply(&o.tun[i])
				}
				fmt.Printf("%s STABILIZE: smScore %.3f << best %.3f, reverted to best-known config\n",
					ts, o.smScore, o.bestKnown)
				o.unstableN, o.dir, o.havePrev, o.pendingSign = 0, 1, false, 0
				o.settle(m.rttMs)
				continue
			}
		} else {
			o.unstableN = 0
		}
		// Decay both references so a one-time high peak can't latch forever: if the
		// link's character permanently degrades, bestKnown drifts down to the new
		// achievable level and STABILIZE stops firing, letting exploration resume.
		o.bestScore *= 0.995
		o.bestKnown *= 0.999
		if o.smScore > o.bestScore {
			o.bestScore = o.smScore
		}
		// B2 decision smoothing (sequential variant) + coordinate advance, unified.
		//
		// We require TWO measurements of the SAME probed config to agree on the sign
		// of its delta-vs-baseline before committing accept/revert — the cheaper
		// sequential alternative to median-of-3 (the tradeoff: a clear verdict costs
		// one extra cycle, in exchange a single noisy cycle can never flip the search).
		// Vote 1 is this cycle's delta after the step; if it's non-zero we HOLD the
		// identical config one more cycle (no new step, no advance) for vote 2, keeping
		// the same baseline (o.prevScore) so the second delta is comparable. Only after
		// the verdict do we advance to the next coordinate.
		//
		// hold=true => re-measure the same config next cycle (confirmation pending);
		// hold=false => verdict reached (or nothing to judge) → step the next coord.
		hold := false
		if haveDelta {
			const eps = 0.01 // dead-band: |delta|<eps is "no measurable change"
			sign := 0
			if delta > eps {
				sign = 1
			} else if delta < -eps {
				sign = -1
			}
			t := &o.tun[o.probedTi]
			switch {
			case sign == 0:
				// Flat (incl. a clamped no-op at a range edge): no signal, move on.
				o.pendingSign = 0
			case o.pendingSign == 0:
				// Vote 1 → hold the same config one cycle to confirm the sign.
				o.pendingSign = sign
				hold = true
			case sign == o.pendingSign:
				// Vote 2 agrees → act on the probed coordinate.
				if sign < 0 {
					// Hurt twice: back the step out and flip this param's direction.
					t.cur = clampInt(t.cur-o.dir*t.step, t.min, t.max)
					o.apply(t)
					o.dir = -o.dir
				}
				// sign>0 (helped twice): accept — leave cur, keep o.dir for momentum.
				o.pendingSign = 0
			default:
				// Two cycles disagree (noise) → don't commit, move on.
				o.pendingSign = 0
			}
		}
		if hold {
			// Re-measure the identical config: do NOT step or advance, and keep
			// o.prevScore as the shared baseline. havePrev stays true so vote 2 is
			// credited/judged against probedTi next cycle.
			fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% sm=%.3f best=%.3f | confirm %s=%d (hold)\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, o.smScore, o.bestScore, o.tun[o.probedTi].name, o.probedVal)
			o.settle(m.rttMs)
			continue
		}
		// Verdict reached (or nothing to judge): advance to the next non-frozen
		// coordinate and step it. If the step would leave the range, flip this
		// param's direction and retry so we always apply a real change to credit.
		o.ti = o.nextTi(o.ti)
		t := &o.tun[o.ti]
		nv := clampInt(t.cur+o.dir*t.step, t.min, t.max)
		if nv == t.cur {
			o.dir = -o.dir
			nv = clampInt(t.cur+o.dir*t.step, t.min, t.max)
		}
		prev := t.cur
		t.cur = nv
		o.apply(t)
		// Record the outstanding probe for next cycle's delta-credit, then SETTLE
		// (B5) so the next measure() window covers only the new config's steady
		// state — not the old config's tail plus this one's ramp-up.
		o.probedTi, o.probedVal, o.prevScore, o.havePrev = o.ti, nv, o.smScore, (nv != prev)
		nqInfo := ""
		if m.nqOK {
			mix := ""
			if o.mixedWorkload {
				mix = " MIXED"
			}
			nqInfo = fmt.Sprintf(" | xpeak=%.0fus bulk=%d t0d=%d%s", m.t0PeakDelayUs, m.bulkFlows, m.t0DeltaPkts, mix)
		}
		fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% sm=%.3f best=%.3f | next %s=%d (settle)%s\n",
			ts, m.bwMbps, m.rttMs, m.lossPct*100, o.smScore, o.bestScore, t.name, nv, nqInfo)
		o.settle(m.rttMs)
	}
}

// nextTi returns the index of the next SELECTABLE tunable after i, wrapping
// around. A tunable is skipped when (a) it's frozen (B4 effect-size), or (b) it's
// a NeoQ-only param and the current cycle isn't a mixed workload (the anti-noise
// gate — neoqOnly params are no-ops on single-flow/idle traffic and must not
// absorb credit). If every tunable is skipped it returns the next index anyway so
// the loop never deadlocks — selection only steers which param we PROBE.
func (o *optimizer) nextTi(i int) int {
	n := len(o.tun)
	// 机制模式下 tun 表是空的。主循环在这之前就 continue 了, 但 %0 会 panic ——
	// 一个空表的不变式不该靠"调用点记得先判"来维持。
	if n == 0 {
		return i
	}
	for k := 1; k <= n; k++ {
		j := (i + k) % n
		if o.frozen[o.tun[j].name] {
			continue
		}
		if o.tun[j].neoqOnly() && !o.mixedWorkload {
			continue
		}
		// headroom 臂只有快环真的在跑才有接收方 (内核可能压根不导出 shaper 键)。
		if o.tun[j].name == shaperHeadroomParam && !o.sh.running() {
			continue
		}
		return j
	}
	return (i + 1) % n
}
