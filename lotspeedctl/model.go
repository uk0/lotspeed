package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// paramSet is the writable subset of lotspeed sysctls the model tunes.
// Keys map to /proc/sys/net/ipv4/lotspeed/<key>.
type paramSet map[string]int

// sample is one (link, params, score) record.
//
// ChangedParam/Delta (B1 delta-credit): the optimizer probes ONE coordinate per
// cycle, so the score change is attributable to that single param, not the whole
// set. ChangedParam names it; Delta is sc-prevScore for it. Params is still the
// FULL config (the KNN planner needs the whole point), but UCB credit replays
// only ChangedParam. Legacy samples lack these fields (ChangedParam==""); UCB
// falls back to crediting the full set for those (see loadFromSamples).
type sample struct {
	Feature      linkFeature `json:"feature"`
	Params       paramSet    `json:"params"`
	Score        float64     `json:"score"`
	TS           int64       `json:"ts"`
	ChangedParam string      `json:"changed_param,omitempty"`
	Delta        float64     `json:"delta,omitempty"`
	// NeoQ experience signals captured alongside this sample (omitempty so legacy
	// model.json — which lacks them — still loads; zero is the natural "no NeoQ
	// data" value). ExpressPeakUs is the Express recent-peak delay (us) at the
	// window-best cycle; T3GoodputDelta is bulk bytes moved that window.
	ExpressPeakUs  float64 `json:"express_peak_us,omitempty"`
	T3GoodputDelta uint64  `json:"t3_goodput_delta,omitempty"`
	// JitterMs is the RTT jitter (MAD of the optimizer's recent-RTT ring, ms) at the
	// window-best cycle — the variance signal score() penalizes. omitempty so legacy
	// model.json still loads; zero is the natural "no jitter data" value.
	JitterMs float64 `json:"jitter_ms,omitempty"`
}

// modelEpochTS 是"可信样本"的起始时刻 (Unix 秒 = 2026-08-28T09:00:00Z)。早于它的
// 样本一律不参与 KNN 平均 (predict) 和 UCB 回放 (loadFromSamples)。
//
// ★ 为什么需要它: 在这个时刻之前, score() 的参照系会在没有流量的拍里被一路衰减到
// 近零 (见 optimizer.go 的 advanceRefs), 流量一恢复 peakBw 就被 ratchet 拉平到当前
// bw, 于是 bw/peakBw 恰好 = 1.0 —— model.json 里那批 1.0 / 0.99 / 0.94 的"高分"就是
// 这么来的。修掉根因不会让存量样本消失, 它们会继续喂 KNN 的参数平均和 UCB 的臂均值。
//
// ★ 为什么不用 `model clear`: 那是 os.Remove(modelPath()), 会连 ShaperCache 一起炸
// 掉 —— shaper 学到的三条链路容量是跨重启复用的真实成果, 与这个 bug 无关。按时间戳
// 过滤是非破坏的: 旧样本留在文件里, `model show` 的原始清单照常列出它们供分析
// (那条命令底部的 UCB 回放会跟着一起过滤, 这正是想要的 —— 它反映的就是优化器当下
// 真正在用的学习状态)。
//
// ★ 取值取在修复落地的时刻而不是当天零点: 这个常量只能早于部署、不能晚于部署,
// 否则会把修复后录的好样本一并丢掉、模型空转到时钟追上为止。代价是部署前几分钟的
// 坏样本可能残留, 它们会随 500 条 FIFO 自然淘汰。
const modelEpochTS int64 = 1787907600

// shaperCacheEntry 是一条 (对端|RTT 档) 的容量缓存。Kbps 存的是 C_hat (物理量:
// 这条路能跑多快), 不是 R (当前 headroom 策略下的投影) —— 换了 headroom 策略,
// 缓存仍然有效。TS 用来判过期 (shaperCacheMaxAge)。
type shaperCacheEntry struct {
	Kbps float64 `json:"kbps"`
	TS   int64   `json:"ts"`
}

type model struct {
	Samples []sample `json:"samples"`
	// ShaperCache 让 shaper 冷启动能跳过一次完整的 SEEK 上探 (键: "<ip>|<band>",
	// 见 shaper.cacheKey)。omitempty 保证老 model.json 原样可读、也不会因为没跑过
	// shaper 就多写一个空字段。
	ShaperCache map[string]shaperCacheEntry `json:"shaper_cache,omitempty"`
}

// modelMu 串行化 model.json 的 load->mutate->save。shaper 快环 (2s, 写
// ShaperCache) 和 optimizer 慢环 (写 Samples) 是两个 goroutine, 而 save() 是整文件
// 重写 —— 不串行化的话后写的一方会把另一方刚加的内容整块覆盖掉。
var modelMu sync.Mutex

// updateModel 是唯一安全的"读-改-写 model.json"入口。返回改完后的 model, 方便调用
// 方读回样本数之类的即时状态而不必再读一次盘。
func updateModel(mut func(*model)) (*model, error) {
	modelMu.Lock()
	defer modelMu.Unlock()
	m := loadModel()
	mut(m)
	return m, m.save()
}

// modelShaperCacheGet 读一条容量缓存 (kbps)。过期条目当未命中处理: 一周前的路径
// 容量对今天的洲际链路没有参考价值, 拿它播种还不如从头 SEEK。
func modelShaperCacheGet(key string) (float64, bool) {
	modelMu.Lock()
	defer modelMu.Unlock()
	m := loadModel()
	e, ok := m.ShaperCache[key]
	if !ok || e.Kbps <= 0 {
		return 0, false
	}
	if time.Since(time.Unix(e.TS, 0)) > shaperCacheMaxAge {
		return 0, false
	}
	return e.Kbps, true
}

// modelShaperCacheSet 回写一条容量缓存。
func modelShaperCacheSet(key string, kbps float64) {
	if key == "" || kbps <= 0 {
		return
	}
	_, _ = updateModel(func(m *model) {
		if m.ShaperCache == nil {
			m.ShaperCache = map[string]shaperCacheEntry{}
		}
		m.ShaperCache[key] = shaperCacheEntry{Kbps: kbps, TS: time.Now().Unix()}
	})
}

func modelPath() string {
	d, _ := os.UserHomeDir()
	return filepath.Join(d, ".lotspeedctl", "model.json")
}

func loadModel() *model {
	m := &model{}
	b, err := os.ReadFile(modelPath())
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, m)
	return m
}

func (m *model) save() error {
	p := modelPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// dist returns a normalized L2 distance between two link features.
// RTT and BW use log scale so 10ms vs 100ms ≈ 100ms vs 1000ms,
// preventing one dimension from dominating.
func dist(a, b linkFeature) float64 {
	logRtt := math.Log1p(a.RttMs) - math.Log1p(b.RttMs)
	logBw := math.Log1p(a.BwMbps) - math.Log1p(b.BwMbps)
	jit := (a.Jitter - b.Jitter) / 50 // 50ms = 1 unit
	loss := (a.LossPct - b.LossPct) * 20
	return math.Sqrt(logRtt*logRtt + logBw*logBw + jit*jit + loss*loss)
}

// predict returns score-weighted nearest-neighbor params for the given feature.
// Falls back to a heuristic plan if the model has no samples yet (cold start) or
// if too few in-regime neighbors survive the gate below.
func (m *model) predict(f linkFeature) paramSet {
	if len(m.Samples) == 0 {
		return heuristicPlan(f)
	}
	type ranked struct {
		s sample
		d float64
	}
	// Regime gate: multi-route links carry physically different paths (e.g. a
	// 13ms LAN regime vs a 264ms intercontinental regime). KNN across both
	// interpolates a config optimal for neither, so only samples whose RttMs is
	// within a factor of 2 of the query's (q/2 <= s <= q*2) participate. Within
	// the regime, only Score>0 samples contribute params — negative/bad-link
	// samples (RTT spikes, high loss) would otherwise drag the average toward
	// configs we know perform badly. Those samples remain in the model file for
	// UCB history; they're excluded from the planner average only.
	rs := make([]ranked, 0, len(m.Samples))
	for _, s := range m.Samples {
		// 参照系腐蚀纪元之前录的分数不可比 (见 modelEpochTS), 不进 KNN 平均。
		if s.TS < modelEpochTS {
			continue
		}
		if s.Score <= 0 {
			continue
		}
		if f.RttMs > 0 {
			if s.Feature.RttMs < f.RttMs/2 || s.Feature.RttMs > f.RttMs*2 {
				continue
			}
		}
		rs = append(rs, ranked{s, dist(f, s.Feature)})
	}
	// Too few in-regime neighbors to trust the average: fall back to the
	// heuristic plan (the caller — cmdTune / warm-start — gets a usable config).
	if len(rs) < 2 {
		return heuristicPlan(f)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].d < rs[j].d })
	k := 5
	if k > len(rs) {
		k = len(rs)
	}
	// score- and inverse-distance-weighted average per param. All survivors have
	// Score>0 (gated above), so the floor is unnecessary but kept harmless.
	out := paramSet{}
	wsum := map[string]float64{}
	for _, r := range rs[:k] {
		w := math.Max(0.01, r.s.Score) / (r.d + 0.1)
		for kk, vv := range r.s.Params {
			out[kk] += int(float64(vv) * w)
			wsum[kk] += w
		}
	}
	for kk := range out {
		if wsum[kk] > 0 {
			out[kk] = int(float64(out[kk]) / wsum[kk])
		}
	}
	return out
}

// === loss_thresh 的唯一公式 (冷启动与运行时闭环共用) ===
//
// K1 门控的语义就是"每轮丢包率低于 loss_thresh 不算拥塞、不退避", 所以这个阈值
// 恒等于 **环境丢包率 + 余量** —— 一个可直接测量的量, 不需要 bandit 去学 (参数效应量
// ~0.01 而相邻两拍 Δ(bw/peakBw) 噪声可达 0.34, 单样本信噪比 1/34)。
//
// ★ 为什么必须是一个函数: heuristicPlan (冷启动) 和 optimizer 的运行时闭环
// (lossThreshLoop) 都要算它。两处各写一遍就是第三套边界 —— 这个项目刚清理完
// neoq_codel 的"双真相", 不再造一个。
const (
	// lossThreshMargin: 环境丢包之上的余量, 覆盖测量噪声 (环境 10% 时门限 14%)。
	lossThreshMargin = 4
	// lossThreshMin/Max: 硬边界。max=20 沿用 heuristicPlan 现役冷启动的保守上限。
	//
	// ★ 已知冲突, 摊开写在这里而不是静默选边: tun 表附近记录的证据是"10% ambient
	//   最优 12-16; lt=30 引发重传风暴; 24 留 headroom", 而 green1 实测 ambient 到
	//   过 18.2% —— clamp(18+4, 4, 20) = 20 顶格, 于是 +4 的余量被上限压成 +1.8。
	//   本轮取 20 (heuristic 是现役冷启动、更保守), 但闭环会把每次顶格显式打进日志,
	//   让运维看得见"余量被上限吃掉了"。上限是否该提到 24 留给 abtest 裁决。
	lossThreshMin = 4
	lossThreshMax = 20
	// 高 RTT 地板: >150ms 的路径上单次丢包更常是瞬时乱序而不是拥塞, 门限不该低于 8。
	lossThreshHiRttMs    = 150
	lossThreshHiRttFloor = 8
)

// lossThreshFor 由环境丢包率 (lossPct 是 0..1 的分数) 和路径 RTT 给出 loss_thresh。
func lossThreshFor(lossPct, rttMs float64) int {
	lt := clampInt(int(math.Round(lossPct*100))+lossThreshMargin, lossThreshMin, lossThreshMax)
	if rttMs > lossThreshHiRttMs {
		lt = maxInt(lt, lossThreshHiRttFloor)
	}
	return lt
}

// lossThreshSaturated 报告"余量被上限吃掉了": 环境丢包 + 余量已经越过 lossThreshMax,
// 于是实际生效的余量小于 lossThreshMargin。闭环用它触发顶格日志。
func lossThreshSaturated(lossPct float64) bool {
	return int(math.Round(lossPct*100))+lossThreshMargin > lossThreshMax
}

// heuristicPlan is the cold-start fallback when the model is empty.
// All formulas are BDP-driven, the only knob the user reasoned about above.
func heuristicPlan(f linkFeature) paramSet {
	bdpPkts := 0
	if f.BwMbps > 0 && f.RttMs > 0 {
		bdpPkts = int(f.BwMbps * 1e6 / 8 * f.RttMs / 1000 / 1460)
	}
	if bdpPkts < 64 {
		bdpPkts = 64
	}
	startupGain := 200
	switch {
	case f.RttMs >= 200:
		startupGain = 450
	case f.RttMs >= 50:
		startupGain = 350
	}
	rhoMax := 100 + int(f.RttMs)
	if rhoMax > 800 {
		rhoMax = 800
	}
	// B6: cold-start loss_thresh. 公式本体已抽到 lossThreshFor —— 冷启动和运行时
	// 闭环 (optimizer 的 lossThreshLoop) 必须共用同一份边界, 见那个函数的注释。
	lossThresh := lossThreshFor(f.LossPct, f.RttMs)
	// TODO(param-table): unify this output set with the optimizer's tun list
	// (optimizer.go newOptimizer) and cmdTune's writer — heuristicPlan still emits
	// min_cwnd/max_cwnd/hist_min_cwnd_bound that the optimizer doesn't tune, while
	// the optimizer tunes fast_alpha that heuristicPlan doesn't emit. One shared
	// param table would remove this skew. Out of scope for the delta-credit fix.
	return paramSet{
		"min_cwnd":            maxInt(64, bdpPkts/10),
		"max_cwnd":            minInt(15000, bdpPkts*2),
		"startup_gain":        startupGain,
		"hd_rho_max":          rhoMax,
		"hist_min_cwnd_bound": maxInt(64, bdpPkts/4),
		"loss_thresh":         lossThresh,
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// record appends a new (feature, params, score) sample and persists.
// Called by optimize after convergence. changedParam/delta carry the B1
// single-coordinate credit (empty/zero is fine — UCB then falls back to
// full-set crediting for this sample). expressPeakUs/t3Goodput carry the NeoQ
// experience signals for the window-best cycle (zero when stats were unavailable);
// jitterMs is the RTT-ring MAD (variance signal) at that cycle.
func (m *model) record(f linkFeature, p paramSet, score float64, changedParam string, delta float64, expressPeakUs float64, t3Goodput uint64, jitterMs float64) error {
	m.Samples = append(m.Samples, sample{
		Feature: f, Params: p, Score: score, TS: time.Now().Unix(),
		ChangedParam: changedParam, Delta: delta,
		ExpressPeakUs: expressPeakUs, T3GoodputDelta: t3Goodput,
		JitterMs: jitterMs,
	})
	// cap at 500 samples (FIFO) — keep model lightweight.
	if len(m.Samples) > 500 {
		m.Samples = m.Samples[len(m.Samples)-500:]
	}
	return m.save()
}

// recordSample 是 optimizer 用的持久化入口: 在 modelMu 下完成一次完整的
// load->append->save, 并回报存完之后的样本总数。以前这里是
// `loadModel().record(...)` 再 `len(loadModel().Samples)` —— 两次独立读盘, 而且和
// shaper 快环的缓存回写会互相覆盖 (save 是整文件重写)。
func recordSample(f linkFeature, p paramSet, score float64, changedParam string, delta float64,
	expressPeakUs float64, t3Goodput uint64, jitterMs float64) (int, error) {
	var n int
	m, err := updateModel(func(m *model) {
		m.Samples = append(m.Samples, sample{
			Feature: f, Params: p, Score: score, TS: time.Now().Unix(),
			ChangedParam: changedParam, Delta: delta,
			ExpressPeakUs: expressPeakUs, T3GoodputDelta: t3Goodput,
			JitterMs: jitterMs,
		})
		if len(m.Samples) > 500 {
			m.Samples = m.Samples[len(m.Samples)-500:]
		}
	})
	if m != nil {
		n = len(m.Samples)
	}
	return n, err
}

// cmdModel — inspect the on-disk model.
//
//	lotspeedctl model [show | clear]
func cmdModel(args []string) error {
	m := loadModel()
	if len(args) == 0 || args[0] == "show" {
		fmt.Printf("model at %s\nsamples: %d\n", modelPath(), len(m.Samples))
		for i, s := range m.Samples {
			xp := ""
			if s.ExpressPeakUs > 0 || s.T3GoodputDelta > 0 {
				xp = fmt.Sprintf(" xpeak=%.0fus t3d=%dB", s.ExpressPeakUs, s.T3GoodputDelta)
			}
			fmt.Printf("  [%d] rtt=%.0fms bw=%.0fM loss=%.1f%% jitter=%.0fms score=%.3f%s params=%v\n",
				i, s.Feature.RttMs, s.Feature.BwMbps, s.Feature.LossPct*100, s.Feature.Jitter, s.Score, xp, s.Params)
		}
		// Also replay all samples through a fresh UCB bandit and show per-param
		// best arm + sample count — this is what UCB learned across all sessions.
		if len(m.Samples) > 0 {
			// Inspection replay —— 纯展示用, 不驱动任何写入。这张表是**历史口径**:
			// 机制模式下 tun 表已经是空的, 这些参数要么冻成常数, 要么 (loss_thresh)
			// 由 ambient 闭环给建议。范围只影响历史样本落到哪个 arm 上, 所以刻意保留
			// 旧的宽范围 —— 收窄会把老样本挤到边界 arm, 让 `model show` 的历史失真。
			// neoq_boost 同理: 早就不在优化器里了, 留着只为老样本仍能显示。
			tuns := []tunable{
				{"startup_gain", "", 200, 400, 20, 0},
				{"fast_alpha", "", 4, 40, 4, 0},
				{"loss_thresh", "", 2, 24, 2, 0},
				{"hd_rho_max", "", 250, 400, 25, 0},
				{"neoq_sparse_thresh", neoqSparseProc, 3028, 123448, 24084, 0},
				{"delay_cap_thresh", "", 30, 80, 10, 0},
				{shaperHeadroomParam, "", 85, 105, 5, 0},
				{"neoq_boost", "/proc/net/neoq_boost", 100, 400, 25, 0},
			}
			ucb := newUCB(tuns, 0)
			replayed := ucb.loadFromSamples(m.Samples)
			// 标题必须说清回放了多少条: loadFromSamples 会跳过 pre-epoch 样本, 而
			// "replayed from all samples" 的旧标题会让一片空臂看起来像 bandit 坏了,
			// 实际只是存量样本全在纪元前。
			fmt.Printf("UCB best arm per parameter (replayed %d/%d samples, %d pre-epoch):\n",
				replayed, len(m.Samples), len(m.Samples)-replayed)
			for _, line := range ucb.debug() {
				fmt.Printf("  %s\n", line)
			}
		}
		return nil
	}
	if args[0] == "clear" {
		_ = os.Remove(modelPath())
		fmt.Println("model cleared")
		return nil
	}
	return fmt.Errorf("usage: model [show | clear]")
}
