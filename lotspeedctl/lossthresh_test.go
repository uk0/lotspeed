package main

import (
	"strings"
	"testing"
	"time"
)

// 本文件是 ① loss_thresh 机制闭环的回归测试。三条硬性覆盖:
//   (a) ambient 阶跃 5% -> 18% 时 thresh 经迟滞与节流推进到 20 顶格;
//   (b) 无流量窗口既不更新也不遗忘;
//   (c) 顶格事件被记录。
// 外加"公式只有一份"和"ambient 口径优先级"两条防回归。

const ltTestInterval = 5 * time.Second

// 冷启动种子 = lossThreshFor(0, 0) = 4, 与旧 tun 表的启动值逐字一致。
func newLTLoop() *lossThreshLoop { return &lossThreshLoop{cur: lossThreshFor(0, 0)} }

// 只有一份公式: heuristicPlan (冷启动) 必须与 lossThreshFor (闭环) 逐点一致。
// 这个项目刚清理完 neoq_codel 的"双真相", 不允许再出现第三套边界。
func TestLossThreshSingleSourceOfTruth(t *testing.T) {
	cases := []struct{ loss, rtt float64 }{
		{0.00, 30}, {0.00, 300}, {0.03, 300}, {0.05, 30},
		{0.10, 264}, {0.18, 264}, {0.30, 30}, {0.50, 500},
	}
	for _, c := range cases {
		want := lossThreshFor(c.loss, c.rtt)
		got := heuristicPlan(linkFeature{LossPct: c.loss, RttMs: c.rtt, BwMbps: 100})["loss_thresh"]
		if got != want {
			t.Errorf("loss=%.2f rtt=%.0f: heuristicPlan=%d lossThreshFor=%d — 两套边界漂移了", c.loss, c.rtt, got, want)
		}
	}
	// 边界本身也钉一下, 免得常量被人顺手改掉而没人发现。
	if lossThreshFor(0, 0) != lossThreshMin {
		t.Errorf("干净链路种子 %d want %d", lossThreshFor(0, 0), lossThreshMin)
	}
	if lossThreshFor(0.99, 264) != lossThreshMax {
		t.Errorf("极端丢包必须被 clamp 到 %d, got %d", lossThreshMax, lossThreshFor(0.99, 264))
	}
	if !lossThreshSaturated(0.18) {
		t.Error("ambient=18% 时 18+4=22 > 20, 必须判为顶格")
	}
	if lossThreshSaturated(0.15) {
		t.Error("ambient=15% 时 15+4=19 <= 20, 不该判顶格")
	}
}

// (a)+(c): ambient 从 5% 阶跃到 18%, 闭环必须经迟滞与节流一路推进到 20 顶格,
// 并且顶格事件被计数 + 被写进日志行。
func TestLossThreshStepTo20Saturates(t *testing.T) {
	l := newLTLoop()
	const rtt = 264.0 // 高 RTT 档, 地板 8 在低 ambient 段生效

	// 阶段 1: 稳定的 5% ambient。lossThreshFor(0.05, 264) = clamp(5+4)=9, 地板 8 -> 9。
	writes := 0
	for i := 0; i < 120; i++ { // 120 拍 @5s = 10 分钟活跃时间 -> 至少一次写
		if l.step(5.0, true, ltTestInterval, rtt).write {
			writes++
		}
	}
	if l.cur != 9 {
		t.Fatalf("5%% ambient 稳态下 loss_thresh=%d want 9 (= clamp(5+4) 且 >= 高RTT地板 8)", l.cur)
	}
	if writes == 0 {
		t.Fatal("10 分钟活跃时间内一次都没写 —— 闭环没在动")
	}
	// 节流: 10 分钟最多 2 次写。
	if writes > 2 {
		t.Errorf("120 拍(10min)内写了 %d 次, 节流 (%v/次) 失效", writes, ambientApplyInterval)
	}

	// 阶段 2: ambient 阶跃到 18%。P25 环先要换血 (>=31 拍), EWMA 再按半衰期爬,
	// 所以推进必然是渐进的 —— 这正是要验的行为, 不是一步到位。
	sawSaturatedReport := false
	seq := []int{l.cur}
	for i := 0; i < 2000; i++ {
		act := l.step(18.0, true, ltTestInterval, rtt)
		if !act.report {
			continue
		}
		if act.write {
			seq = append(seq, act.val)
		}
		if act.saturated {
			sawSaturatedReport = true
		}
	}
	if l.cur != lossThreshMax {
		t.Fatalf("ambient 稳在 18%% 之后 loss_thresh=%d, want 顶格 %d (ewma=%.2f seq=%v)", l.cur, lossThreshMax, l.ewma, seq)
	}
	if !sawSaturatedReport {
		t.Error("ambient 稳在 18%% 却一次顶格播报都没有 —— (c) 顶格事件必须被记录")
	}
	if l.saturN == 0 {
		t.Error("saturN=0 —— 顶格计数器没动")
	}
	// 顶格是**驻留状态**: 阈值被 clamp 钉死之后不会再"变化", 播报必须继续 (否则运维
	// 只看得见一次然后永远失明), 但仍受节流约束。
	if l.saturN < 2 {
		t.Errorf("saturN=%d —— 顶格驻留期间只播报了一次, 运维看不到它还在持续", l.saturN)
	}
	// 迟滞: 每一步的跨度必须 >= ambientHysteresis, 唯一的例外是落在硬边界上那一步。
	for i := 1; i < len(seq); i++ {
		d := absInt(seq[i] - seq[i-1])
		atRail := seq[i] == lossThreshMax || seq[i] == lossThreshMin
		if d < ambientHysteresis && !atRail {
			t.Errorf("seq=%v: %d -> %d 跨度只有 %d, 迟滞 (>=%d) 失效", seq, seq[i-1], seq[i], d, ambientHysteresis)
		}
	}
	// 不许一步跳到顶: 9 -> 20 中间必须经过中间值 (证明 EWMA/P25 的时间常数真的在起作用)。
	if len(seq) < 3 {
		t.Errorf("seq=%v —— 从 9 直接跳到顶格, EWMA/P25 的时间常数被旁路了", seq)
	}
}

// (b) 无流量窗口既不更新、也不遗忘。门在 applyLossThresh 里 (不是调用方的约定),
// 所以这里直接打 optimizer 级的入口。green1 有 96.8% 的拍是 idle, 这条不成立的话
// 闭环会在那些拍里重演我们刚修完的参照系腐蚀。
func TestLossThreshIdleNeitherUpdatesNorForgets(t *testing.T) {
	o := &optimizer{interval: ltTestInterval}
	act := metrics{bwMbps: 30, rttMs: 264, nqOK: true, ambientOK: true, ambientPct: 12}

	for i := 0; i < 20; i++ { // < ambientRingLen, 这样"再来一拍"能看出环有没有增长
		o.applyLossThresh(act, true)
	}
	ewma, elapsed, cur, ring, sat := o.lt.ewma, o.lt.elapsed, o.lt.cur, len(o.lt.ring), o.lt.saturN
	if ring == 0 || ewma == 0 {
		t.Fatal("活跃拍没喂进 ambient 环 —— 后面的对照就没有意义了")
	}

	// 5000 个 idle 拍: 读数是垃圾 (ambient=0 是因为没流量, 不是因为路干净)。
	idle := metrics{bwMbps: 0.3, rttMs: 30, nqOK: true, ambientOK: true, ambientPct: 0}
	for i := 0; i < 5000; i++ {
		if line := o.applyLossThresh(idle, false); line != "" {
			t.Fatalf("idle 拍 %d 写了 loss_thresh: %q", i, line)
		}
	}
	if o.lt.ewma != ewma {
		t.Errorf("5000 个 idle 拍把 ewma 从 %.6f 改成了 %.6f —— 无流量窗口更新了", ewma, o.lt.ewma)
	}
	if o.lt.elapsed != elapsed {
		t.Errorf("idle 拍推进了节流计时器: %v -> %v", elapsed, o.lt.elapsed)
	}
	if len(o.lt.ring) != ring || o.lt.cur != cur || o.lt.saturN != sat {
		t.Errorf("idle 拍动了闭环状态: ring %d->%d cur %d->%d saturN %d->%d",
			ring, len(o.lt.ring), cur, o.lt.cur, sat, o.lt.saturN)
	}

	// 恢复流量: 必须从冻结处**继续**, 而不是重新起步 (不遗忘)。
	o.applyLossThresh(act, true)
	if o.lt.elapsed != elapsed+ltTestInterval {
		t.Errorf("恢复后节流计时器 %v, want %v (从冻结处 +1 拍)", o.lt.elapsed, elapsed+ltTestInterval)
	}
	if len(o.lt.ring) != ring+1 {
		t.Errorf("恢复后 ring=%d want %d —— 断档把环清了", len(o.lt.ring), ring+1)
	}
}

// 自指防护 (a): 绑定窗口的读数不得进 ambient 环 —— 那种拍的丢包很可能是我自己造的。
// 节流计时器照常推进 (时间确实过去了, 且这是活跃拍)。
func TestLossThreshBindingBeatsNotAdmitted(t *testing.T) {
	l := newLTLoop()
	for i := 0; i < 50; i++ {
		l.step(40.0, false, ltTestInterval, 264) // 绑定窗口, 读数极脏
	}
	if len(l.ring) != 0 {
		t.Errorf("绑定窗口的 %d 个读数进了 ambient 环 —— 正反馈棘轮的入口", len(l.ring))
	}
	if l.primed {
		t.Error("绑定窗口的读数把 EWMA 播种了")
	}
	if l.elapsed != 50*ltTestInterval {
		t.Errorf("节流计时器 %v want %v (活跃拍就该走时钟, 只是读数不采纳)", l.elapsed, 50*ltTestInterval)
	}
	if l.cur != lossThreshFor(0, 0) {
		t.Errorf("样本不足时 loss_thresh 被改动了: %d", l.cur)
	}
}

// 样本不足时闭环不动: ring < ambientMinSamples 一律不写, 保持冷启动种子。
func TestLossThreshHoldsUntilRingIsUsable(t *testing.T) {
	l := newLTLoop()
	// 只喂 ambientMinSamples-1 个可采纳读数; 时间给足 (其余拍走绑定窗口, 只推时钟),
	// 所以唯一能挡住写入的只有样本数。
	admitted := 0
	for i := 0; i < 400; i++ {
		admit := admitted < ambientMinSamples-1
		if admit {
			admitted++
		}
		if act := l.step(18.0, admit, ltTestInterval, 264); act.report {
			t.Fatalf("环里只有 %d 个样本 (< %d) 就动了 loss_thresh", len(l.ring), ambientMinSamples)
		}
	}
	if l.cur != lossThreshFor(0, 0) {
		t.Errorf("loss_thresh=%d, 样本不足期间必须保持冷启动种子 %d", l.cur, lossThreshFor(0, 0))
	}
	// 补上第 ambientMinSamples 个读数 —— 这一拍起闭环才允许动手。
	if !l.step(18.0, true, ltTestInterval, 264).write {
		t.Errorf("样本够了 (%d) 且节流早已到期, 仍然没写", len(l.ring))
	}
}

// ambient 口径优先级: 内核导出 ambient_share 就用它 (滚动 1s 窗、只数 >=128B 的包、
// 排除哈希冲突包), 老内核没这个键才退回 ss/snmp 差分。
func TestAmbientSampleSourcePreference(t *testing.T) {
	m := metrics{nqOK: true, ambientOK: true, ambientPct: 7, lossPct: 0.19}
	if v, ok := ambientSample(m); !ok || v != 7 {
		t.Errorf("ambientSample=%v,%v want 7,true (必须优先用 ambient_share)", v, ok)
	}
	// ambient_share=0 是**合法读数**(干净链路), 不是"键缺失"。
	m0 := metrics{nqOK: true, ambientOK: true, ambientPct: 0, lossPct: 0.19}
	if v, ok := ambientSample(m0); !ok || v != 0 {
		t.Errorf("ambientSample=%v,%v want 0,true (ambient_share=0 是干净链路, 不是缺失)", v, ok)
	}
	// 老内核: 键不存在 -> 退回 ss 差分。
	mOld := metrics{nqOK: true, ambientOK: false, lossPct: 0.19}
	if v, ok := ambientSample(mOld); !ok || !almost(v, 19) {
		t.Errorf("ambientSample=%v,%v want 19,true (fallback 到 lossPct*100)", v, ok)
	}
}

// 内核刚导出的 ambient_share 必须被解析, 且"键不存在"要与"值是 0"区分开。
func TestParseNeoqMLAmbientShare(t *testing.T) {
	withKey := "qlen=3 t0_pkts=100 t3_bytes=900 retrans_seen=2 " +
		"rate_kbps=1000 backlog=0 shaper_sent=5 shaper_defer=0 ambient_share=18"
	s, ok := parseNeoqML(withKey)
	if !ok || !s.ambientOK || s.ambientShare != 18 {
		t.Errorf("parseNeoqML: ambientOK=%v share=%d want true/18", s.ambientOK, s.ambientShare)
	}
	zero, _ := parseNeoqML(strings.Replace(withKey, "ambient_share=18", "ambient_share=0", 1))
	if !zero.ambientOK || zero.ambientShare != 0 {
		t.Errorf("ambient_share=0 必须是 ok/0, got ok=%v v=%d", zero.ambientOK, zero.ambientShare)
	}
	// 老内核模块: 整个键不存在。前向兼容 —— 其余字段照常解析。
	old, ok := parseNeoqML("qlen=3 t0_pkts=100 t3_bytes=900 retrans_seen=2")
	if !ok {
		t.Fatal("老内核的行必须仍然解析成功")
	}
	if old.ambientOK {
		t.Error("键不存在时 ambientOK 必须为 false —— 否则闭环会把 0 当成干净链路")
	}
}

// EWMA 半衰期换算必须是真的半衰期: 走一个 halfLife 的时间, 距离目标正好剩一半。
func TestEWMAAlphaHalfLife(t *testing.T) {
	const half = 450 * time.Second
	const dt = 5 * time.Second
	a := ewmaAlphaFor(dt, half)
	v := 0.0
	for i := 0; i < int(half/dt); i++ {
		v += a * (1.0 - v)
	}
	if v < 0.49 || v > 0.51 {
		t.Errorf("走满一个半衰期后收敛到 %.4f, want ~0.5", v)
	}
	if got := ewmaAlphaFor(0, half); got != 1 {
		t.Errorf("dt=0 时 alpha=%v want 1 (退化为直接取样)", got)
	}
}

// 顶格日志行必须自解释: 值、ambient、来源、以及"余量被上限吃掉了多少"。
func TestSaturationIsLogged(t *testing.T) {
	o := &optimizer{interval: ltTestInterval}
	m := metrics{bwMbps: 30, rttMs: 264, nqOK: true, ambientOK: true, ambientPct: 25}
	line := ""
	for i := 0; i < 400 && line == ""; i++ {
		line = o.applyLossThresh(m, true)
	}
	if line == "" {
		t.Fatal("400 个活跃拍一次都没写 loss_thresh")
	}
	for _, want := range []string{"LOSS-THRESH", "SATURATED", "ambient_share", "effective margin"} {
		if !strings.Contains(line, want) {
			t.Errorf("日志行缺少 %q: %s", want, line)
		}
	}
	if o.lt.cur != lossThreshMax {
		t.Errorf("ambient=25%% 下 loss_thresh=%d want %d", o.lt.cur, lossThreshMax)
	}
}

// --legacy-bandit 下闭环必须整个停用 —— loss_thresh 回到 tun 表当臂, 一个参数绝不
// 允许有两个写者。
func TestLossThreshLoopDisabledUnderLegacyBandit(t *testing.T) {
	o := &optimizer{interval: ltTestInterval, legacyBandit: true}
	m := metrics{bwMbps: 30, rttMs: 264, nqOK: true, ambientOK: true, ambientPct: 25}
	for i := 0; i < 400; i++ {
		if line := o.applyLossThresh(m, true); line != "" {
			t.Fatalf("--legacy-bandit 下闭环仍在写: %s", line)
		}
	}
	if len(o.lt.ring) != 0 || o.lt.primed {
		t.Error("--legacy-bandit 下闭环仍在累积状态")
	}
}
