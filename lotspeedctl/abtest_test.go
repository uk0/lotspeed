package main

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 精确二项尾概率 —— 符号检验的全部数学
// ---------------------------------------------------------------------------

// binomTailP 必须给出精确值 (不是正态近似): 这个工具的整个判决门槛就是
// "3 对全同号 = 1/8"。近似在 n=3 上会错到没法用。
func TestBinomTailP(t *testing.T) {
	cases := []struct {
		n, k int
		want float64
	}{
		{3, 3, 0.125},         // 3 对全同号 —— 判决门槛本身
		{3, 2, 0.5},           // 2:1 —— (C(3,2)+C(3,3))/8 = 4/8
		{3, 0, 1},             // k<=0 恒真
		{4, 4, 0.0625},        // 1/16
		{4, 3, 5.0 / 16},      // (4+1)/16 —— 4 对的 3:1 仍达不到 α
		{5, 5, 1.0 / 32},      //
		{5, 4, 6.0 / 32},      // 5 对的 4:1 也达不到 α=0.125
		{6, 5, 7.0 / 64},      // 6 对起 5:1 才够 (0.109 <= 0.125)
		{6, 6, 1.0 / 64},      //
		{3, 4, 0},             // k>n 不可能
		{0, 0, 1},             // 空样本
		{10, 5, 638.0 / 1024}, // C(10,5..10)=252+210+120+45+10+1
	}
	for _, c := range cases {
		if got := binomTailP(c.n, c.k); !almost(got, c.want) {
			t.Errorf("binomTailP(%d,%d)=%.10f want %.10f", c.n, c.k, got, c.want)
		}
	}
}

// pairedMedian 对偶数 n 必须取中间两个的均值 —— 这正是它不复用 percentile(_,0.5)
// 的原因 (后者取下侧序位统计量), 而 --pairs 4 是可达的。
func TestPairedMedian(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{nil, 0},
		{[]float64{5}, 5},
		{[]float64{3, 1, 2}, 2},      // 奇数: 真中位
		{[]float64{4, 1, 3, 2}, 2.5}, // 偶数: (2+3)/2, percentile 会给 2
		{[]float64{-3, -1}, -2},      //
		{[]float64{1, 1, 1, 1}, 1},   //
	}
	for _, c := range cases {
		if got := pairedMedian(c.in); !almost(got, c.want) {
			t.Errorf("pairedMedian(%v)=%v want %v", c.in, got, c.want)
		}
	}
}

// signTest 只统计符号 (方向无关), 并按惯例丢弃 0 差且相应缩小 n。
func TestSignTest(t *testing.T) {
	cases := []struct {
		name                 string
		deltas               []float64
		nPos, nNeg, nZero, n int
		median, pOne, pTwo   float64
	}{
		{"3 对全正", []float64{1, 2, 3}, 3, 0, 0, 3, 2, 0.125, 0.25},
		{"3 对全负", []float64{-1, -2, -3}, 0, 3, 0, 3, -2, 0.125, 0.25},
		{"2:1", []float64{1, 2, -1}, 2, 1, 0, 3, 1, 0.5, 1},
		{"含 0 差, n 缩小", []float64{1, 2, 0}, 2, 0, 1, 2, 1, 0.25, 0.5},
		{"全 0 差", []float64{0, 0, 0}, 0, 0, 3, 0, 0, 1, 1},
		{"空", nil, 0, 0, 0, 0, 0, 1, 1},
		{"6 对 5:1", []float64{1, 1, 1, 1, 1, -1}, 5, 1, 0, 6, 1, 7.0 / 64, 7.0 / 32},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := signTest(c.deltas)
			if r.nPos != c.nPos || r.nNeg != c.nNeg || r.nZero != c.nZero || r.n != c.n {
				t.Errorf("counts = %d+/%d-/%d= n=%d, want %d+/%d-/%d= n=%d",
					r.nPos, r.nNeg, r.nZero, r.n, c.nPos, c.nNeg, c.nZero, c.n)
			}
			if !almost(r.median, c.median) {
				t.Errorf("median=%v want %v", r.median, c.median)
			}
			if !almost(r.pOne, c.pOne) || !almost(r.pTwo, c.pTwo) {
				t.Errorf("p = (%.6f, %.6f) want (%.6f, %.6f)", r.pOne, r.pTwo, c.pOne, c.pTwo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 判决
// ---------------------------------------------------------------------------

// abGoodputPairs 造出只在 goodput 上有差异的配对: qdelay/retrans 两臂完全相同,
// 所以那两个护栏口径的差分全是 0 (n=0 -> 永不显著), 判决只由主指标决定。
func abGoodputPairs(a, b []float64) []abPair {
	var out []abPair
	for i := range a {
		out = append(out, abPair{
			idx: i + 1,
			a:   abWindow{goodputMbps: a[i], queueDelayMs: 10, retransPct: 1},
			b:   abWindow{goodputMbps: b[i], queueDelayMs: 10, retransPct: 1},
		})
	}
	return out
}

func abSpecFor(t *testing.T) abSpec {
	t.Helper()
	return abSpec{param: "loss_thresh", aVal: 20, bVal: 24, alpha: abAlpha, minPairs: abMinPairs}
}

// 规格要求的核心表: 3 对全同号 / 2:1 / 全反号 各自的判决。
func TestABDecideSignTable(t *testing.T) {
	cases := []struct {
		name       string
		a, b       []float64
		wantWinner string
		wantSig    bool
		wantPOne   float64
	}{
		{
			// B 三次都更快 -> 3/3 同号 -> p=0.125 <= α -> B 显著占优
			name: "3 对全同号 -> B 显著", a: []float64{40, 42, 38}, b: []float64{45, 47, 44},
			wantWinner: "B", wantSig: true, wantPOne: 0.125,
		},
		{
			// 2 胜 1 负 -> p=0.5 -> 未达显著。这一格是这个工具存在的理由:
			// 均值上 B 明显更高 (+3.3 Mbps), 但符号不一致, 所以不许下结论。
			name: "2:1 -> 未达显著", a: []float64{40, 42, 38}, b: []float64{45, 47, 37},
			wantWinner: "", wantSig: false, wantPOne: 0.5,
		},
		{
			name: "3 对全反号 -> A 显著", a: []float64{45, 47, 44}, b: []float64{40, 42, 38},
			wantWinner: "A", wantSig: true, wantPOne: 0.125,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := abDecide(abGoodputPairs(c.a, c.b), abSpecFor(t), nil)
			if rep.insufficient {
				t.Fatalf("不该判样本不足 (3 个完整配对)")
			}
			if rep.winner != c.wantWinner || rep.significant != c.wantSig {
				t.Errorf("winner=%q significant=%v, want %q / %v",
					rep.winner, rep.significant, c.wantWinner, c.wantSig)
			}
			if !almost(rep.metrics[0].stat.pOne, c.wantPOne) {
				t.Errorf("主指标 pOne=%.4f want %.4f", rep.metrics[0].stat.pOne, c.wantPOne)
			}
			// 护栏两项两臂读数相同 -> 差分全 0 -> 必须没有胜者。
			for _, mv := range rep.metrics[1:] {
				if mv.winner != "" {
					t.Errorf("%s 两臂相同却判出胜者 %q", mv.metric.name, mv.winner)
				}
			}
		})
	}
}

// winnerValue 必须把 "A"/"B" 映射回真正的参数值 —— --apply 写的就是这个数。
func TestABDecideWinnerValue(t *testing.T) {
	rep := abDecide(abGoodputPairs([]float64{40, 42, 38}, []float64{45, 47, 44}), abSpecFor(t), nil)
	v, ok := rep.winnerValue()
	if !ok || v != 24 {
		t.Errorf("winnerValue=(%d,%v) want (24,true)", v, ok)
	}
	rep2 := abDecide(abGoodputPairs([]float64{45, 47, 44}, []float64{40, 42, 38}), abSpecFor(t), nil)
	if v, ok := rep2.winnerValue(); !ok || v != 20 {
		t.Errorf("winnerValue=(%d,%v) want (20,true)", v, ok)
	}
	rep3 := abDecide(abGoodputPairs([]float64{40, 42, 38}, []float64{45, 47, 37}), abSpecFor(t), nil)
	if _, ok := rep3.winnerValue(); ok {
		t.Errorf("未达显著时不该有胜者值")
	}
}

// 越小越好的口径 (qdelay/retrans) 必须把"B 的读数更常偏大"翻译成"A 赢"。
// 方向搞反是这类工具最容易出的错, 而且错了不会崩 —— 只会给出反的建议。
func TestABDecideLowerIsBetterDirection(t *testing.T) {
	// goodput 完全相同 (无主判决), qdelay 三次都是 B 更大 = B 更差。
	var pairs []abPair
	aQ := []float64{10, 11, 9}
	bQ := []float64{14, 16, 13}
	for i := range aQ {
		pairs = append(pairs, abPair{
			idx: i + 1,
			a:   abWindow{goodputMbps: 40, queueDelayMs: aQ[i], retransPct: 1},
			b:   abWindow{goodputMbps: 40, queueDelayMs: bQ[i], retransPct: 1},
		})
	}
	rep := abDecide(pairs, abSpecFor(t), nil)
	q := rep.metrics[1]
	if q.metric.name != "qdelay" || q.metric.higherBetter {
		t.Fatalf("metrics[1] 应该是越小越好的 qdelay, 得到 %+v", q.metric)
	}
	if q.stat.nPos != 3 || q.stat.nNeg != 0 {
		t.Fatalf("qdelay 符号应为 3+/0-, 得到 %d+/%d-", q.stat.nPos, q.stat.nNeg)
	}
	if q.winner != "A" {
		t.Errorf("qdelay 上 B 三次都更大 (更差) -> 胜者应为 A, 得到 %q", q.winner)
	}
	// 主指标无差异 -> 整体不显著, 也就不该有护栏告警。
	if rep.significant || len(rep.guardrails) != 0 {
		t.Errorf("主指标无差异时不该有整体判决/护栏告警: sig=%v guardrails=%v",
			rep.significant, rep.guardrails)
	}
}

// 主指标赢、护栏输 -> 必须告警并否决 --apply。这条是"采纳的严格"的落点:
// 用延迟换来的吞吐胜利, 取舍得由人做, 不能让脚本替人做。
func TestABDecideGuardrailBlocksApply(t *testing.T) {
	var pairs []abPair
	aBw, bBw := []float64{40, 42, 38}, []float64{45, 47, 44}
	aQ, bQ := []float64{10, 11, 9}, []float64{14, 16, 13}
	for i := range aBw {
		pairs = append(pairs, abPair{
			idx: i + 1,
			a:   abWindow{goodputMbps: aBw[i], queueDelayMs: aQ[i], retransPct: 1},
			b:   abWindow{goodputMbps: bBw[i], queueDelayMs: bQ[i], retransPct: 1},
		})
	}
	rep := abDecide(pairs, abSpecFor(t), nil)
	if !rep.significant || rep.winner != "B" {
		t.Fatalf("主指标应判 B 显著占优, 得到 sig=%v winner=%q", rep.significant, rep.winner)
	}
	if len(rep.guardrails) != 1 || !strings.Contains(rep.guardrails[0], "qdelay") {
		t.Errorf("应有 1 条 qdelay 护栏告警, 得到 %v", rep.guardrails)
	}
	if !rep.applyBlocked {
		t.Errorf("护栏显著变差时必须否决 --apply")
	}
	if !strings.Contains(strings.Join(rep.lines(), "\n"), "--apply 已被护栏否决") {
		t.Errorf("报告必须写明 --apply 被否决:\n%s", strings.Join(rep.lines(), "\n"))
	}
}

// 完整配对不足 -> 明确报"样本不足"而不是给一个基于空拍的判决。
func TestABDecideInsufficient(t *testing.T) {
	rep := abDecide(abGoodputPairs([]float64{40, 42}, []float64{45, 47}), abSpecFor(t),
		map[string]int{"idle": 4, "badlink": 1})
	if !rep.insufficient || rep.significant || rep.winner != "" {
		t.Fatalf("2 个配对必须判样本不足: %+v", rep)
	}
	if len(rep.metrics) != 0 {
		t.Errorf("样本不足时不该产出任何口径判决, 得到 %d 条", len(rep.metrics))
	}
	joined := strings.Join(rep.lines(), "\n")
	for _, want := range []string{"样本不足", "idle=4", "badlink=1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("报告缺少 %q:\n%s", want, joined)
		}
	}
	// 零配对同样走这条路 (而不是 panic / 除零)。
	if r0 := abDecide(nil, abSpecFor(t), nil); !r0.insufficient {
		t.Errorf("零配对必须判样本不足")
	}
}

// 规格明确要求: 未达显著时要说清楚"未达", 不许含糊。措辞是这个工具的产品本体,
// 所以它归单测管。
func TestABReportLinesSayNotSignificant(t *testing.T) {
	rep := abDecide(abGoodputPairs([]float64{40, 42, 38}, []float64{45, 47, 37}), abSpecFor(t), nil)
	joined := strings.Join(rep.lines(), "\n")
	for _, want := range []string{"未达显著", "不要据此改参数", "p单侧=0.500"} {
		if !strings.Contains(joined, want) {
			t.Errorf("报告缺少 %q:\n%s", want, joined)
		}
	}
	// 未达显著时绝不能出现"显著占优"的结论行。
	if strings.Contains(joined, "结论: B") || strings.Contains(joined, "结论: A") {
		t.Errorf("未达显著却给出了胜者结论:\n%s", joined)
	}
}

// 效应量必须以 A 臂中位数为分母给出相对百分比 —— 人是看这个数决定值不值得改的。
func TestABDecideEffectSize(t *testing.T) {
	// A 中位 40, Δ 恒 +4 -> median Δ=+4, relPct=+10%
	rep := abDecide(abGoodputPairs([]float64{38, 40, 42}, []float64{42, 44, 46}), abSpecFor(t), nil)
	p := rep.metrics[0]
	if !almost(p.aMedian, 40) || !almost(p.stat.median, 4) || !almost(p.relPct, 10) {
		t.Errorf("效应量 aMedian=%v median=%v relPct=%v, want 40 / 4 / 10",
			p.aMedian, p.stat.median, p.relPct)
	}
}

// ---------------------------------------------------------------------------
// 安全约束
// ---------------------------------------------------------------------------

// 白名单外的参数一律拒绝, 且错误信息要说明是安全约束在起作用 (而不是像"没实现")。
func TestLookupABParam(t *testing.T) {
	if _, err := lookupABParam("loss_thresh"); err != nil {
		t.Errorf("loss_thresh 应在白名单里: %v", err)
	}
	for _, name := range []string{"shaper_headroom", "neoq_sparse_thresh", "max_cwnd", ""} {
		_, err := lookupABParam(name)
		if err == nil {
			t.Fatalf("%q 不该被接受", name)
		}
		if !strings.Contains(err.Error(), "白名单") || !strings.Contains(err.Error(), "loss_thresh") {
			t.Errorf("%q 的拒绝理由要说明白名单并列出可测参数, 得到: %v", name, err)
		}
	}
}

// 范围外的值一律拒绝并说明范围 —— 这是"最差臂也无害"这条安全性质的唯一执行点。
func TestABParamValidate(t *testing.T) {
	p, err := lookupABParam("loss_thresh")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{2, 20, 24} {
		if err := p.validate(v); err != nil {
			t.Errorf("%d 在 [%d,%d] 内, 不该被拒: %v", v, p.min, p.max, err)
		}
	}
	for _, v := range []int{1, 0, -5, 25, 30} {
		err := p.validate(v)
		if err == nil {
			t.Fatalf("%d 超出 [%d,%d] 却被接受", v, p.min, p.max)
		}
		if !strings.Contains(err.Error(), "超出钳制范围") {
			t.Errorf("拒绝理由要点明超范围, 得到: %v", err)
		}
	}
}

// 不在臂格点上只提醒不拒绝: 范围内的任意值做 A/B 都安全, 人有权测 21 vs 23。
func TestABParamAligned(t *testing.T) {
	p, _ := lookupABParam("loss_thresh") // min=2 step=2
	for _, v := range []int{2, 4, 20, 24} {
		if !p.aligned(v) {
			t.Errorf("%d 应在格点上", v)
		}
	}
	for _, v := range []int{3, 21, 23} {
		if p.aligned(v) {
			t.Errorf("%d 不该被认为在格点上", v)
		}
		if err := p.validate(v); err != nil {
			t.Errorf("%d 不对齐但在范围内, 不该被拒: %v", v, err)
		}
	}
}

// 白名单里必须全是纯 sysctl 参数 (无 path 字段) 且范围自洽 —— restore 的正确性
// 建立在"原值就是 readSysctl 的字符串"之上。
func TestABParamsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range abParams {
		if seen[p.name] {
			t.Errorf("白名单里 %s 重复", p.name)
		}
		seen[p.name] = true
		if p.min >= p.max || p.step <= 0 {
			t.Errorf("%s 范围不自洽: min=%d max=%d step=%d", p.name, p.min, p.max, p.step)
		}
		if (p.max-p.min)%p.step != 0 {
			t.Errorf("%s 的 (max-min) 不是 step 的整数倍, 顶格臂落不到 max 上", p.name)
		}
		if p.note == "" {
			t.Errorf("%s 缺少\"最差臂为什么无害\"的说明 —— 这是入表的准入条件", p.name)
		}
	}
	// 两条明确排除必须保持排除 (理由见 abParam 的注释)。
	for _, banned := range []string{shaperHeadroomParam, "neoq_sparse_thresh"} {
		if seen[banned] {
			t.Errorf("%s 不该在 abtest 白名单里", banned)
		}
	}
}

func TestParseABValues(t *testing.T) {
	if a, b, err := parseABValues("20,24"); err != nil || a != 20 || b != 24 {
		t.Errorf("parseABValues(\"20,24\") = (%d,%d,%v)", a, b, err)
	}
	if a, b, err := parseABValues(" 20 , 24 "); err != nil || a != 20 || b != 24 {
		t.Errorf("应容忍空格: (%d,%d,%v)", a, b, err)
	}
	for _, bad := range []string{"20", "20,24,28", "a,24", "20,b", "", ","} {
		if _, _, err := parseABValues(bad); err == nil {
			t.Errorf("parseABValues(%q) 该报错", bad)
		}
	}
	// 相同的两个值测的是测量噪声本身, 不是参数 —— 必须拒绝。
	_, _, err := parseABValues("20,20")
	if err == nil || !strings.Contains(err.Error(), "相同") {
		t.Errorf("两值相同必须被拒绝并说明理由, 得到: %v", err)
	}
}

// 天气门必须复用 isBadLink, 并且喂给它的是两个"每 socket 各自成立"的中位数量。
// 阈值是 E/minRttP50 > 2。
func TestABBadLink(t *testing.T) {
	cases := []struct {
		name string
		st   ssTargetStat
		want bool
	}{
		{"排队 3x 基线 -> 天气", ssTargetStat{minRttP50Ms: 100, queueDelayMs: 300}, true},
		{"排队 2x 基线 -> 恰好不算 (>2 严格)", ssTargetStat{minRttP50Ms: 100, queueDelayMs: 200}, false},
		{"排队 0.2x 基线 -> 正常", ssTargetStat{minRttP50Ms: 159, queueDelayMs: 32}, false},
		{"无排队", ssTargetStat{minRttP50Ms: 159, queueDelayMs: 0}, false},
		{"没有可用 socket -> fail-open (由 nosocks 门先挡)", ssTargetStat{}, false},
	}
	for _, c := range cases {
		if got := abBadLink(c.st); got != c.want {
			t.Errorf("%s: abBadLink(%+v)=%v want %v", c.name, c.st, got, c.want)
		}
	}
	// 与 isBadLink 的等价性: rtt/minRtt-1 > 2 <=> E/minRtt > 2。
	st := ssTargetStat{minRttP50Ms: 50, queueDelayMs: 150}
	if abBadLink(st) != isBadLink(200, 50) {
		t.Errorf("abBadLink 必须与 isBadLink(minRttP50+E, minRttP50) 完全一致")
	}
}

// 预算估算: 2 臂 × pairs 对 × (settle + window)。规格说一次判决约 3-5 分钟,
// 默认 (3 对 / 30s) 必须落在那个量级 —— 否则"预算感"这条要求就没兑现。
func TestABBudget(t *testing.T) {
	lo, hi := abBudget(3, 30*time.Second)
	if lo != 6*32*time.Second || hi != 6*35*time.Second {
		t.Errorf("abBudget(3,30s)=(%v,%v) want (192s,210s)", lo, hi)
	}
	if lo < 3*time.Minute || hi > 5*time.Minute {
		t.Errorf("默认判决预算 %v-%v 不在规格说的 3-5 分钟量级", lo, hi)
	}
	if lo6, hi6 := abBudget(6, 30*time.Second); lo6 != 2*lo || hi6 != 2*hi {
		t.Errorf("预算应随对数线性: (%v,%v)", lo6, hi6)
	}
}
