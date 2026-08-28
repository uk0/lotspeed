package main

// abtest.go —— 交替配对 A/B 判决器。
//
// ============================================================================
// 为什么需要它, 以及为什么它不是"把 UCB 的探索系数调大"
// ============================================================================
//
// 这条链路上 bandit 的问题是信噪比, 不是胆量:
//
//	单个参数步长的效应量  ~0.01 (score 单位)
//	相邻两拍 Δ(bw/peakBw) ~0.34 (纯噪声)
//	=> 单样本信噪比 1/34, 2σ 置信下每臂需要 ~4600 个平稳配对样本
//
// 而实测有效学习拍只有 106 拍/天 (96.8% 的拍是 idle 或被 shaper 冻结), tun 表
// 7 参数 × 6-13 臂 ≈ 60+ 臂 —— 需要数年平稳数据, 可链路容量在**分钟级**于
// 6-59 Mbps 之间跳变。硬证据: UCB 把 delay_cap_thresh 学成 50, 而人工交替配对
// A/B 两轮都判"开了更差"。
//
// 提高探索系数只会放大注入生产的方差, 分子分母同时变大, 归因的信噪比一点没动。
// 真正能改善"效应量/样本"的只有一件事: **加大步长**。loss_thresh 从 4→16 一跳的
// 效应量约是 4→6 的 5-6 倍, 而样本成本完全相同。
//
// 所以本文件把"激进"和"采纳"拆开:
//
//	探索侧激进 —— 一次跳到两个相隔很远的值, 而不是 ±1 step;
//	采纳侧严格 —— 用符号检验顶住, 默认不写入, 只有 --apply 才落盘。
//
// ============================================================================
// 为什么必须是交替配对 (A/B/A/B), 而不是"先测完 A 再测 B"
// ============================================================================
//
// green1 的 ambient loss 在 90 分钟内从 10.4% 漂到 18.2% —— 近一倍。任何顺序分块
// 对比 (block A, then block B) 测到的差异里, 天气的贡献比参数大一个数量级: 它测的
// 是时间, 不是参数。交替配对把 A 和 B 压到相隔一个窗 (~35s) 之内做差, 低频漂移在
// 配对差分里直接抵消。这是本项目产出过的全部可信数字唯一用过的方法。
//
// 残留的一阶偏置 (每对内 B 总是晚于 A 一个窗) 是可接受的: ambient 漂移
// ~0.087%/min, 35s 内约 0.05%, 相对每拍 34% 的噪声是二阶小量。所以这里不做
// ABBA 反配平, 保持 A/B/A/B 的最简形状。
//
// ============================================================================
// 为什么是符号检验而不是 t 检验
// ============================================================================
//
// 3-6 个配对差分。t 检验要求近似正态且用样本方差估计总体方差 —— n=3 时这个方差
// 估计本身的相对误差超过 50%, 算出来的 p 是装饰品。符号检验只用差分的**符号**,
// 对分布不做任何假设, 3 对全同号的单侧 p 恰好是 1/8 = 0.125, 是这个样本量下能拿到
// 的最强证据。判决门槛因此定在 α=0.125 —— 换句话说 "3 对必须全部同号"。

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// 安全约束 1: 参数白名单 (只允许范围已钳制、最差臂也无害的参数)
// ---------------------------------------------------------------------------

// abParam 是一个允许做 A/B 的参数及其钳制范围。
//
// ★ 这张表**故意**比 optimizer 的 tun 表窄, 不是它的副本。两者的准入判据不同:
//
//	tun 表   —— "bandit 可以在生产上探测它" (±1 step, 有 settle, 随时可回退)
//	abtest 表 —— "人可以把它按在一个值上几分钟而不出事" (最差臂持续生效)
//
// 后者更严, 于是有两条排除:
//
//   - shaper_headroom: 它不落 proc 文件, 是进程内直接推给快环的量 (见
//     optimizer.apply 的 shaperHeadroomParam 分支)。abtest 是独立进程, 根本
//     作动不了它 —— 收进白名单只会给出一个 A 与 A 相比的假判决。
//   - neoq_sparse_thresh: 写入格式是 "<window_us> <bytes>" 而非裸整数, 且它只在
//     混合负载 (bulk_flows>=1 且 Express 活跃) 下非 no-op。单流/idle 上测它必然
//     得到"没差别" —— 那是设计上的 no-op, 不是判决。要测它得先有 mixedWorkload
//     判据参与设计, 不在本轮范围。
//
// 于是白名单里全部是纯 sysctl 整数参数, restore 就是把 readSysctl 拿到的原始字符串
// 原样写回去 —— 中断恢复的正确性因此是平凡的。
type abParam struct {
	name           string
	min, max, step int
	note           string // 为什么最差臂无害
}

var abParams = []abParam{
	{"loss_thresh", 2, 24, 2,
		"丢包容忍阈值 (%): 最低 2 退化成 bbr 式的见丢就退, 最高 24 仍在实测未出现重传风暴的区间内"},
	{"startup_gain", 200, 400, 20,
		"STARTUP 增益 (%): 最低 200 只是起步慢, 最高 400 是当前生产值"},
	{"fast_alpha", 4, 40, 4,
		"快速恢复步长: 两端都只影响收敛速度, 不改变稳态"},
	{"hd_rho_max", 250, 400, 25,
		"Hybla 高延迟补偿上限: 最低 250 仍保留大部分补偿, 最高 400 是当前生产值"},
	{"delay_cap_thresh", 30, 80, 10,
		"延迟门控封顶阈值 (%): 最低 30 会被 RTT 抖动频繁误触发 (只是保守), 最高 80 近似等于不封顶"},
}

// lookupABParam 在白名单里找参数。找不到就明确说明拒绝理由 —— 静默失败或
// "不支持"三个字会让人以为是 CLI 没写完, 而实际是安全约束在起作用。
func lookupABParam(name string) (abParam, error) {
	for _, p := range abParams {
		if p.name == name {
			return p, nil
		}
	}
	var names []string
	for _, p := range abParams {
		names = append(names, p.name)
	}
	return abParam{}, fmt.Errorf(
		"参数 %q 不在 abtest 白名单里。白名单只收\"范围已钳制且最差臂持续生效也无害\"的纯 sysctl 参数, "+
			"因为 A/B 会把参数按在一个值上数分钟。可测: %s",
		name, strings.Join(names, ", "))
}

// validate 检查一个待测值是否落在钳制范围内。范围外一律拒绝 —— 这是安全约束的
// 全部内容: 只要两个臂都在范围内, 最坏情况就是"其中一个臂差一点", 不会出事。
func (p abParam) validate(v int) error {
	if v < p.min || v > p.max {
		return fmt.Errorf("%s=%d 超出钳制范围 [%d,%d] —— 拒绝测试。%s",
			p.name, v, p.min, p.max, p.note)
	}
	return nil
}

// aligned 报告 v 是否落在 bandit 的臂格点上。不对齐**不拒绝** (范围内的任意值做
// A/B 都是安全的, 而人有权测 21 vs 23), 但要提醒: 结果不会映射到任何一个 UCB 臂。
func (p abParam) aligned(v int) bool {
	return p.step > 0 && (v-p.min)%p.step == 0
}

// ---------------------------------------------------------------------------
// 纯统计层 (无 I/O, 全部可单测)
// ---------------------------------------------------------------------------

// abWindow 是一个测量窗的三个读数。
type abWindow struct {
	goodputMbps  float64
	queueDelayMs float64
	retransPct   float64
}

// abPair 是一对配对样本。同一对里的 A 与 B 相隔一个窗 + 一次 settle, 低频天气在
// 做差时抵消。
type abPair struct {
	idx  int
	a, b abWindow
}

// abMetric 是一个判决口径。higherBetter 决定"差分符号"如何映射到胜者。
type abMetric struct {
	name         string
	unit         string
	higherBetter bool
	get          func(abWindow) float64
}

// abMetrics[0] 是主指标 (判决由它给出), 其余是护栏 (报告但不单独定胜负)。
var abMetrics = []abMetric{
	{"goodput", "Mbps", true, func(w abWindow) float64 { return w.goodputMbps }},
	{"qdelay", "ms", false, func(w abWindow) float64 { return w.queueDelayMs }},
	{"retrans", "%", false, func(w abWindow) float64 { return w.retransPct }},
}

// abAlpha 是判决门槛 (单侧 p)。0.125 = 3 对全同号的精确二项尾概率, 也就是这个
// 样本量下能拿到的最强证据。它同时决定了更多对时的要求: 4 对仍需全同号
// (p=0.0625), 5 对仍需全同号 (0.031), 6 对起才允许 5:1 (7/64=0.109)。
const abAlpha = 0.125

// abMinPairs 是能产生判决的最少完整配对数。2 对的最好单侧 p 是 0.25 > α, 永远
// 达不到显著 —— 收下它只会浪费 4 个窗的流量再告诉你"未达显著"。
const abMinPairs = 3

// binomTailP 返回 P(X >= k), X ~ Binomial(n, 0.5) —— 符号检验的精确单侧 p。
// n 最多 20 对, C(n,i) 的递推在 float64 里是精确的, 不需要对数 Gamma。
func binomTailP(n, k int) float64 {
	if k <= 0 {
		return 1
	}
	if k > n {
		return 0
	}
	c, sum := 1.0, 0.0 // c = C(n,i)
	for i := 0; i <= n; i++ {
		if i >= k {
			sum += c
		}
		c = c * float64(n-i) / float64(i+1)
	}
	return sum / math.Pow(2, float64(n))
}

// pairedMedian 是配对差分的中位数 (效应量)。
//
// ★ 为什么不用 stat.go 的 percentile(xs, 0.5): 它对偶数 n 取的是下侧序位统计量
// (idx = int(0.5*(n-1))), 而 --pairs 4 是可达的, 那时真中位数是中间两个的均值。
// 效应量是要打印给人做决定的数, 这半个位置的偏差不该留着。
func pairedMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// signTestResult 是一次符号检验的完整输出。方向无关 —— 它只统计符号, 由调用方
// 结合 higherBetter 去解释谁赢。
type signTestResult struct {
	n      int     // 非零差分数 (符号检验按惯例丢弃 0 差, 并相应缩小 n)
	nPos   int     // Δ(B-A) > 0 的对数
	nNeg   int     // Δ(B-A) < 0 的对数
	nZero  int     // Δ == 0 的对数
	median float64 // Δ(B-A) 的中位数, 含 0 差 —— 这是效应量
	pOne   float64 // 观察到的优势方向上的单侧 p
	pTwo   float64 // 双侧 p = min(1, 2*pOne)
}

// signTest 对配对差分 delta = B - A 做符号检验。
//
// pOne 用的是 k = max(nPos, nNeg), 即"观察到的方向"上的单侧 p —— 规格要求的
// "3 对全同号 → p=0.125" 就是这个数。但方向是事后选的 (我们事先并不知道 20 和 24
// 哪个好), 所以 pTwo 也一并返回并打印, 免得有人拿单侧数字过度声称。
func signTest(deltas []float64) signTestResult {
	r := signTestResult{median: pairedMedian(deltas)}
	for _, d := range deltas {
		switch {
		case d > 0:
			r.nPos++
		case d < 0:
			r.nNeg++
		default:
			r.nZero++
		}
	}
	r.n = r.nPos + r.nNeg
	r.pOne = binomTailP(r.n, maxInt(r.nPos, r.nNeg))
	r.pTwo = math.Min(1, 2*r.pOne)
	return r
}

// abMetricVerdict 是单个口径上的判决。
type abMetricVerdict struct {
	metric  abMetric
	stat    signTestResult
	winner  string  // "A" | "B" | "" (未达显著)
	aMedian float64 // A 臂读数的中位数 (效应量的分母)
	relPct  float64 // median / aMedian * 100; aMedian==0 时为 0
}

// abSpec 是一次判决的输入参数 (与测量过程无关的那一半)。
type abSpec struct {
	param      string
	aVal, bVal int
	alpha      float64
	minPairs   int
}

// abReport 是判决的完整结果。它是纯数据 —— 打印在 lines() 里, 所以格式也可单测。
type abReport struct {
	spec      abSpec
	pairs     int
	discarded map[string]int // 作废窗的原因计数 (idle / badlink / nosocks)
	metrics   []abMetricVerdict

	insufficient bool   // 完整配对不足, 不产生判决
	whyInsuff    string //
	significant  bool   // 主指标达到显著
	winner       string // "A" | "B" | ""

	guardrails   []string // 护栏口径上"胜者反而更差"的警告
	applyBlocked bool     // --apply 是否被护栏否决
}

// abDecide 是整个判决逻辑的纯函数入口: 给定配对样本, 给出判决。
// 测量、施加、恢复全部在调用方 —— 这条分界线是这个文件可单测的原因。
func abDecide(pairs []abPair, spec abSpec, discarded map[string]int) abReport {
	rep := abReport{spec: spec, pairs: len(pairs), discarded: discarded}
	if spec.alpha <= 0 {
		rep.spec.alpha = abAlpha
	}
	if spec.minPairs <= 0 {
		rep.spec.minPairs = abMinPairs
	}
	if len(pairs) < rep.spec.minPairs {
		rep.insufficient = true
		rep.whyInsuff = fmt.Sprintf(
			"只拿到 %d 个完整配对 (需要 >= %d)。%d 对的最好单侧 p 也达不到 α=%.3f, 任何判决都是噪声。",
			len(pairs), rep.spec.minPairs, len(pairs), rep.spec.alpha)
		return rep
	}

	for _, m := range abMetrics {
		deltas := make([]float64, 0, len(pairs))
		aVals := make([]float64, 0, len(pairs))
		for _, p := range pairs {
			deltas = append(deltas, m.get(p.b)-m.get(p.a))
			aVals = append(aVals, m.get(p.a))
		}
		mv := abMetricVerdict{metric: m, stat: signTest(deltas), aMedian: pairedMedian(aVals)}
		if mv.aMedian != 0 {
			mv.relPct = mv.stat.median / mv.aMedian * 100
		}
		if mv.stat.n > 0 && mv.stat.pOne <= rep.spec.alpha && mv.stat.nPos != mv.stat.nNeg {
			// nPos>nNeg 表示 B 的读数更常偏大。对"越大越好"的口径这就是 B 赢;
			// 对"越小越好"的口径同一个符号意味着 B 更差, 于是 A 赢。
			if (mv.stat.nPos > mv.stat.nNeg) == m.higherBetter {
				mv.winner = "B"
			} else {
				mv.winner = "A"
			}
		}
		rep.metrics = append(rep.metrics, mv)
	}

	primary := rep.metrics[0]
	rep.winner = primary.winner
	rep.significant = primary.winner != ""

	// 护栏: 主指标的胜者若在某个次要口径上被显著判负, 说明这个"胜利"是拿延迟或
	// 重传换来的。这时不阻止人工采纳, 但阻止 --apply 自动写入 —— 这是取舍, 得由人做。
	if rep.significant {
		for _, mv := range rep.metrics[1:] {
			if mv.winner != "" && mv.winner != rep.winner {
				rep.guardrails = append(rep.guardrails, fmt.Sprintf(
					"%s: 胜者 %s 在这个口径上显著更差 (median Δ(B−A)=%+.2f %s, %d+/%d−, p单侧=%.3f)",
					mv.metric.name, rep.winner, mv.stat.median, mv.metric.unit,
					mv.stat.nPos, mv.stat.nNeg, mv.stat.pOne))
				rep.applyBlocked = true
			}
		}
	}
	return rep
}

// winnerValue 返回胜者对应的参数值。未达显著时返回 (0,false)。
func (r abReport) winnerValue() (int, bool) {
	switch r.winner {
	case "A":
		return r.spec.aVal, true
	case "B":
		return r.spec.bVal, true
	}
	return 0, false
}

// lines 渲染判决报告。纯函数 —— 判决措辞是这个工具的产品本体 (规格明确要求
// "未达显著时明确说未达, 不要含糊"), 所以它也归单测管。
func (r abReport) lines() []string {
	out := []string{
		fmt.Sprintf("== 判决: %s  A=%d  B=%d ==", r.spec.param, r.spec.aVal, r.spec.bVal),
	}
	if n := totalDiscarded(r.discarded); n > 0 {
		out = append(out, fmt.Sprintf("作废窗 %d 个: %s", n, formatDiscarded(r.discarded)))
	}
	if r.insufficient {
		out = append(out,
			"结论: 样本不足 —— 不产生判决。",
			"  "+r.whyInsuff,
			"  参数已恢复原值。这不是\"两者没差别\", 是\"这段时间没测出东西\"。")
		return out
	}
	out = append(out, fmt.Sprintf("完整配对 %d 对, α=%.3f (单侧)", r.pairs, r.spec.alpha))
	for i, mv := range r.metrics {
		tag := "护栏"
		if i == 0 {
			tag = "主指标"
		}
		dir := "越大越好"
		if !mv.metric.higherBetter {
			dir = "越小越好"
		}
		verdict := "未达显著"
		if mv.winner != "" {
			// 措辞刻意带上 pTwo: 判定用的 pOne 取 k=max(nPos,nNeg), 方向是**事后
			// 选**的, 所以"某个方向获胜"的真实一类错误率是 2α 而不是 α (α=0.125
			// 时是 0.25)。写成"占优 (单侧)"提醒读者这不是一个 0.125 的强断言。
			verdict = mv.winner + " 占优 (单侧)"
		}
		out = append(out, fmt.Sprintf(
			"  [%s] %-8s (%s)  median Δ(B−A)=%+8.3f %-4s (%+6.1f%%)  符号 %d+/%d−/%d=  p单侧=%.3f p双侧=%.3f  → %s",
			tag, mv.metric.name, dir, mv.stat.median, mv.metric.unit, mv.relPct,
			mv.stat.nPos, mv.stat.nNeg, mv.stat.nZero, mv.stat.pOne, mv.stat.pTwo, verdict))
	}
	if !r.significant {
		p := r.metrics[0].stat
		out = append(out,
			fmt.Sprintf("结论: 未达显著。主指标 goodput 的符号是 %d+/%d−, 单侧 p=%.3f > α=%.3f。",
				p.nPos, p.nNeg, p.pOne, r.spec.alpha),
			fmt.Sprintf("  %d 对样本区分不出 %d 与 %d —— 不要据此改参数。要么加 --pairs, 要么把两个值拉得更开。",
				r.pairs, r.spec.aVal, r.spec.bVal))
		out = append(out, "  注: 优势方向是事后选的, 故族一类错误率为 2α="+
			fmt.Sprintf("%.3f", 2*r.spec.alpha)+"; 判定看 p单侧, 强度看 p双侧。")
		return out
	}
	wv, _ := r.winnerValue()
	out = append(out, fmt.Sprintf(
		"结论: %s (%s=%d) 在主指标 goodput 上显著占优 (%d/%d 同号, 单侧 p=%.3f)。",
		r.winner, r.spec.param, wv, maxInt(r.metrics[0].stat.nPos, r.metrics[0].stat.nNeg),
		r.metrics[0].stat.n, r.metrics[0].stat.pOne))
	for _, g := range r.guardrails {
		out = append(out, "  护栏告警: "+g)
	}
	if r.applyBlocked {
		out = append(out, "  → --apply 已被护栏否决: 这个\"胜利\"是拿别的口径换来的, 取舍必须由人做。")
	}
	return out
}

func totalDiscarded(d map[string]int) int {
	n := 0
	for _, v := range d {
		n += v
	}
	return n
}

func formatDiscarded(d map[string]int) string {
	var keys []string
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, d[k]))
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// 安全约束 2/4: 天气门 与 预算估算 (纯函数)
// ---------------------------------------------------------------------------

// abBadLink 是测量窗的天气门, 复用 optimizer 的 isBadLink 判据。
//
// ★ 为什么不是直接 isBadLink(st.rttMs, st.minRttMs): 那是 mean(srtt) 除以
// min(minrtt), 在这台混合流量的机器上是跨 regime 相减 (本地代理 0.3ms 与洲际
// 264ms 同时在跑), 见 ssTargetStat 的注释。这里喂进去的是两个"每 socket 各自
// 成立再取中位数"的量。isBadLink 判的是 rtt/minRtt-1 > 2, 等价于 E/minRtt > 2,
// 所以传 (minRttP50 + E, minRttP50) 恰好就是"排队延迟超过基线 RTT 的两倍"。
// minRttP50==0 (没有可用 socket) 时 isBadLink 返回 false —— fail-open 是对的,
// 这一窗会被 nosocks 门先挡掉。
func abBadLink(st ssTargetStat) bool {
	return isBadLink(st.minRttP50Ms+st.queueDelayMs, st.minRttP50Ms)
}

// settle() 的 clamp 上下界 (见 optimizer.settle)。只用于预算估算, 不参与控制。
const (
	abSettleLo = 2 * time.Second
	abSettleHi = 5 * time.Second
)

// abBudget 估算一次判决要花掉多少活跃流量时间: 2 臂 × pairs 对, 每窗 = settle + 窗口。
func abBudget(pairs int, window time.Duration) (lo, hi time.Duration) {
	n := time.Duration(2 * pairs)
	return n * (window + abSettleLo), n * (window + abSettleHi)
}

// ---------------------------------------------------------------------------
// I/O 层: 测量 / 施加 / 恢复
// ---------------------------------------------------------------------------

// abRunner 持有测量面。
type abRunner struct {
	o       *optimizer
	target  string
	window  time.Duration
	lastRtt float64 // 上一窗的 srtt, 喂给 settle 算等待时长
}

// newABRunner 用**字面量**构造 optimizer, 刻意不走 newOptimizer。
//
// ★ newOptimizer 的末尾有一个 `for i := range o.tun { o.apply(&o.tun[i]) }` ——
// 它会把整张 tun 表的激进默认值写进内核。在 abtest 里调它, 等于在测试开始前就把
// 被测参数和另外 6 个参数一起改掉: 判决对象直接变成别的配置, 而且原值已经丢了。
// 这里只需要它的测量面 (measure / settle), 所以只填测量面用到的字段。
func newABRunner(iface, target string, window time.Duration) *abRunner {
	o := &optimizer{iface: iface, target: target, interval: window}
	o.prevBytes = ifaceBytes(iface)
	o.prevOut, o.prevRetr = readSnmpTcp()
	return &abRunner{o: o, target: target, window: window}
}

// ssStat 取本窗的 socket 聚合量。--target 时按对端限定 (单 regime, 最准),
// 否则全机 —— 两条路都走 aggregateRows, 口径一致。
func (r *abRunner) ssStat() ssTargetStat {
	if r.target != "" {
		return ssTarget(r.target)
	}
	return ssAll()
}

// measureWindow 睡满一个窗口再采样, 返回三个读数; reason != "" 表示这一窗作废。
//
// 三条作废判据全部复用现有阈值/判据, 不另立标准:
//
//	nosocks  —— 没有 established socket, 根本没有链路信号
//	idle     —— bw < idleBwFloorMbps (与 optimizer 的 idle 门同一个常量)
//	badlink  —— abBadLink (与 shaper/optimizer 同一个 isBadLink)
//
// 注意: 不在这里调 settle。settle 只在**切换参数之后**做一次; 一窗作废后参数没变,
// 直接重睡一窗即可 —— measure() 每次都会推进计数器基线, 所以下一窗是干净的。
func (r *abRunner) measureWindow() (abWindow, string) {
	time.Sleep(r.window)
	m := r.o.measure()
	st := r.ssStat()
	if st.rttMs > 0 {
		r.lastRtt = st.rttMs
	}
	switch {
	case st.socks == 0:
		return abWindow{}, "nosocks"
	case m.bwMbps < idleBwFloorMbps:
		return abWindow{}, "idle"
	case abBadLink(st):
		return abWindow{}, "badlink"
	}
	return abWindow{
		goodputMbps:  m.bwMbps,
		queueDelayMs: st.queueDelayMs,
		retransPct:   m.lossPct * 100,
	}, ""
}

// abMaxWindowAttempts 是单窗的重测上限。超了就整对作废 —— 配对设计里半对没有用。
const abMaxWindowAttempts = 3

// abMaxAbortedPairsInRow 是连续整对作废的容忍上限。连着两对都测不出来说明这段
// 时间的链路条件根本不允许判决, 继续耗下去只是白烧流量时间 (预算感)。
const abMaxAbortedPairsInRow = 2

// runArm 施加一个值, settle, 然后测到一个有效窗 (或耗尽重试)。
func (r *abRunner) runArm(param string, val int, label string, pair, pairs int,
	discarded map[string]int) (abWindow, bool) {

	if err := applyABValue(param, val); err != nil {
		fmt.Fprintf(os.Stderr, "abtest: 施加 %s=%d 失败: %v\n", param, val, err)
		return abWindow{}, false
	}
	// 每次切换后 settle: 吸收配置变更的瞬态, 并重置字节/段计数器基线, 这样接下来
	// 那一窗覆盖的只有稳态 —— 与 optimizer 的 B5 是同一段逻辑。
	r.o.settle(r.lastRtt)
	for attempt := 1; attempt <= abMaxWindowAttempts; attempt++ {
		w, reason := r.measureWindow()
		if reason == "" {
			fmt.Printf("  pair %d/%d  %s(%s=%d)  bw=%7.2f Mbps  qdelay=%6.2f ms  retr=%5.2f %%\n",
				pair, pairs, label, param, val, w.goodputMbps, w.queueDelayMs, w.retransPct)
			return w, true
		}
		discarded[reason]++
		fmt.Printf("  pair %d/%d  %s(%s=%d)  作废 (%s), 重测 %d/%d\n",
			pair, pairs, label, param, val, reason, attempt, abMaxWindowAttempts)
	}
	return abWindow{}, false
}

// applyABValue 写入并读回校验。读回必须一致 —— 否则内核对这个值另有钳制,
// 两个臂可能落到同一个实际值上, 那个"判决"就是 A 与 A 相比。
func applyABValue(param string, val int) error {
	want := strconv.Itoa(val)
	if err := writeSysctl(param, want); err != nil {
		return err
	}
	got, err := readSysctl(param)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("写入 %s 但读回 %s —— 内核另有钳制, 两个臂可能落在同一个实际值上", want, got)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 命令入口
// ---------------------------------------------------------------------------

// parseABValues 解析 --values "a,b"。必须恰好两个、且不相等。
func parseABValues(s string) (int, int, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("--values 需要恰好两个值 (如 20,24), 收到 %q", s)
	}
	a, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("--values 第一个值不是整数: %q", parts[0])
	}
	b, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("--values 第二个值不是整数: %q", parts[1])
	}
	if a == b {
		return 0, 0, fmt.Errorf("--values 两个值相同 (%d) —— 那测的是测量噪声本身, 不是参数", a)
	}
	return a, b, nil
}

// cmdABTest 跑一次交替配对 A/B 判决。
//
//	lotspeedctl abtest --param <name> --values <a,b> [--pairs 3] [--window 30s] [--apply]
func cmdABTest(args []string) error {
	param, values := "", ""
	iface, target := "eth0", ""
	pairs := abMinPairs
	window := 30 * time.Second
	apply := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--param":
			if i+1 < len(args) {
				param = args[i+1]
				i++
			}
		case "--values":
			if i+1 < len(args) {
				values = args[i+1]
				i++
			}
		case "--pairs":
			if i+1 < len(args) {
				if n, e := strconv.Atoi(args[i+1]); e == nil {
					pairs = n
				}
				i++
			}
		case "--window":
			if i+1 < len(args) {
				if d, e := time.ParseDuration(args[i+1]); e == nil {
					window = d
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
		case "--apply":
			apply = true
		default:
			return fmt.Errorf("未知参数 %q\n%s", args[i], abUsage)
		}
	}
	if param == "" || values == "" {
		return fmt.Errorf("%s", abUsage)
	}
	p, err := lookupABParam(param)
	if err != nil {
		return err
	}
	aVal, bVal, err := parseABValues(values)
	if err != nil {
		return err
	}
	if err := p.validate(aVal); err != nil {
		return err
	}
	if err := p.validate(bVal); err != nil {
		return err
	}
	if pairs < abMinPairs {
		return fmt.Errorf("--pairs %d 太少: %d 对的最好单侧 p 是 %.3f, 永远达不到 α=%.3f —— 至少 %d 对",
			pairs, pairs, binomTailP(pairs, pairs), abAlpha, abMinPairs)
	}
	if pairs > 20 {
		return fmt.Errorf("--pairs %d 太多: 那是 %d 个窗, 远超一次判决该占用的生产流量", pairs, 2*pairs)
	}
	if window < 5*time.Second || window > 5*time.Minute {
		return fmt.Errorf("--window %v 超出 [5s, 5m]: 太短则字节增量是噪声, 太长则天气会漂进配对内部", window)
	}

	// 原值必须先读到手, 否则中断时无从恢复 —— 读不到就不开始。
	orig, err := readSysctl(param)
	if err != nil {
		return fmt.Errorf("读不到 %s 的当前值 (lotspeed 模块没加载?): %w —— 读不到原值就无法保证恢复, 拒绝开始", param, err)
	}

	// 安全约束 3: 中断恢复。SIGINT/SIGTERM 与正常返回路径共用同一个 once, 无论
	// 从哪条路走, 参数都不会停在半途的臂上。
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := writeSysctl(param, orig); err != nil {
				fmt.Fprintf(os.Stderr,
					"abtest: !! 恢复 %s=%s 失败: %v —— 请立刻手动执行 `lotspeedctl set %s %s`\n",
					param, orig, err, param, orig)
				return
			}
			fmt.Printf("已恢复 %s=%s\n", param, orig)
		})
	}
	defer restore()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigc
		fmt.Fprintf(os.Stderr, "\nabtest: 收到 %v, 中止测试并恢复原值 (未产生判决)\n", s)
		restore()
		os.Exit(130)
	}()

	scope := "machine-wide"
	if target != "" {
		scope = "target=" + target
	}
	lo, hi := abBudget(pairs, window)
	fmt.Printf("== abtest %s: A=%d vs B=%d ==\n", param, aVal, bVal)
	fmt.Printf("iface=%s scope=%s pairs=%d window=%v α=%.3f (单侧符号检验)\n",
		iface, scope, pairs, window, abAlpha)
	fmt.Printf("预算: %d 窗 × (settle %v-%v + window %v) ≈ %v - %v 活跃流量\n",
		2*pairs, abSettleLo, abSettleHi, window, lo.Round(time.Second), hi.Round(time.Second))
	fmt.Printf("原值: %s=%s (测试结束或 Ctrl-C 都会恢复)\n", param, orig)
	if !p.aligned(aVal) || !p.aligned(bVal) {
		fmt.Printf("注意: %d/%d 不在 bandit 的臂格点上 (min=%d step=%d) —— 结果不会映射到任何一个 UCB 臂\n",
			aVal, bVal, p.min, p.step)
	}
	fmt.Printf("注意: 如果 `lotspeedctl optimize` 正在跑, 它会和本测试抢同一个参数 —— 先停掉它\n\n")

	r := newABRunner(iface, target, window)
	discarded := map[string]int{}
	var complete []abPair
	abortedInRow := 0
	for i := 1; i <= pairs; i++ {
		// 交替配对: 同一对里先 A 后 B, 相隔一个窗。见文件头关于残留次序偏置的说明。
		wa, okA := r.runArm(param, aVal, "A", i, pairs, discarded)
		var wb abWindow
		okB := false
		if okA {
			wb, okB = r.runArm(param, bVal, "B", i, pairs, discarded)
		}
		if okA && okB {
			complete = append(complete, abPair{idx: i, a: wa, b: wb})
			abortedInRow = 0
			continue
		}
		abortedInRow++
		fmt.Printf("  pair %d/%d 整对作废 (半对在配对设计里没有用)\n", i, pairs)
		if abortedInRow >= abMaxAbortedPairsInRow {
			fmt.Printf("连续 %d 对作废 —— 这段时间的链路条件不允许判决, 提前停止\n", abortedInRow)
			break
		}
	}

	// 先无条件回到原值, 再按判决决定要不要写入胜者。这样"未达显著"和"被中断"
	// 落在同一个已知状态上, 而不是停在最后一个臂。
	restore()

	rep := abDecide(complete, abSpec{param: param, aVal: aVal, bVal: bVal,
		alpha: abAlpha, minPairs: abMinPairs}, discarded)
	fmt.Println()
	for _, ln := range rep.lines() {
		fmt.Println(ln)
	}

	if !apply {
		if rep.significant {
			fmt.Printf("未采纳 (默认不自动写入)。要落盘请重跑并加 --apply, 或直接 `lotspeedctl set %s %d`\n",
				param, mustWinnerValue(rep))
		}
		return nil
	}
	if !rep.significant {
		fmt.Println("--apply 无操作: 没有达到显著的判决, 没有可采纳的值。")
		return nil
	}
	if rep.applyBlocked {
		fmt.Println("--apply 无操作: 见上面的护栏告警。")
		return nil
	}
	wv := mustWinnerValue(rep)
	if err := applyABValue(param, wv); err != nil {
		return fmt.Errorf("采纳 %s=%d 失败: %w", param, wv, err)
	}
	fmt.Printf("已采纳: %s=%d (原值 %s)。注意这只写了运行时 sysctl, 不会跨重启存活。\n", param, wv, orig)
	return nil
}

func mustWinnerValue(r abReport) int {
	v, _ := r.winnerValue()
	return v
}

const abUsage = `usage: lotspeedctl abtest --param <name> --values <a,b> [--pairs 3] [--window 30s] [--iface eth0] [--target IP] [--apply]

交替配对 A/B/A/B + 符号检验。默认不写入, 只有 --apply 才采纳。

例:
  # 实测 green1 ambient 达 18.2% 时 heuristic 给出的 20 是顶格值 (+4 余量被上限
  # 吃掉), 而另一处证据记录"24 留 headroom"。这个冲突正该由交替配对 A/B 裁决。
  lotspeedctl abtest --param loss_thresh --values 20,24

  # 更强的证据 (6 对, 允许 5:1) + 直接采纳
  lotspeedctl abtest --param loss_thresh --values 20,24 --pairs 6 --apply

  # UCB 把 delay_cap_thresh 学成 50, 人工配对两轮都判"开了更差" —— 复核
  lotspeedctl abtest --param delay_cap_thresh --values 30,80 --window 60s`
