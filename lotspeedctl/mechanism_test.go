package main

import (
	"testing"
	"time"
)

// 本文件是 ② "冻结常数 + 清空 tun 表" 的回归测试。要钉住的是三件事:
//   - 默认 (机制) 模式下 tun 表为空, 主循环没有坐标可步进;
//   - --legacy-bandit 是一次**逐字**的整期回退, 不是"看起来像旧行为"的近似;
//   - 被移除的参数确实以常数形式写下去了, 没有变成"谁也不写"的悬空状态。

func mechOptimizer(sh *shaper, legacy bool) *optimizer {
	return newOptimizer("eth0", "", 5*time.Second, defaultGamma, sh, legacy)
}

// 机制模式: tun 表清空, 主循环退化为"测量 -> 驱动机制 -> 记录遥测样本"。
func TestMechanismModeEmptiesTunTable(t *testing.T) {
	o := mechOptimizer(&shaper{headroom: 0.5}, false)
	if len(o.tun) != 0 {
		names := make([]string, 0, len(o.tun))
		for i := range o.tun {
			names = append(names, o.tun[i].name)
		}
		t.Fatalf("机制模式下 tun 表非空: %v", names)
	}
	// loss_thresh 的冷启动种子必须与 heuristicPlan 同源, 且等于旧 tun 表的启动值 4。
	if o.lt.cur != lossThreshFor(0, 0) || o.lt.cur != 4 {
		t.Errorf("冷启动种子 loss_thresh=%d want %d (= 旧 tun 表启动值)", o.lt.cur, lossThreshFor(0, 0))
	}
	// 空表下 nextTi 绝不能 panic (%0) —— 主循环虽然提前 continue 了, 但不变式不该靠
	// 调用点维持。
	if got := o.nextTi(0); got != 0 {
		t.Errorf("nextTi(0)=%d on empty tun, want 0 (no-op)", got)
	}
	// 前馈 headroom 冻结在 0.95: R=h*C_hat 想解决的问题正是 HOLD trim 环在闭环解决的。
	if o.sh.headroom != frozenShaperHeadroom {
		t.Errorf("shaper headroom=%.2f want %.2f", o.sh.headroom, frozenShaperHeadroom)
	}
}

// --legacy-bandit 必须**逐字**恢复旧表 —— 否则那个开关不是回退, 是第三种行为。
func TestLegacyBanditRestoresTunTable(t *testing.T) {
	want := map[string][4]int{ // name -> {min, max, step, cur}
		"startup_gain":       {200, 400, 20, 400},
		"fast_alpha":         {4, 40, 4, 30},
		"loss_thresh":        {2, 24, 2, 4},
		"hd_rho_max":         {250, 400, 25, 400},
		"neoq_sparse_thresh": {3028, 123448, 24084, 3028},
		"delay_cap_thresh":   {30, 80, 10, 50},
	}
	o := mechOptimizer(nil, true)
	if len(o.tun) != len(want) {
		t.Fatalf("--legacy-bandit 下 %d 个 tunable, want %d", len(o.tun), len(want))
	}
	for i := range o.tun {
		tn := o.tun[i]
		w, ok := want[tn.name]
		if !ok {
			t.Errorf("旧表里没有的参数出现了: %s", tn.name)
			continue
		}
		if [4]int{tn.min, tn.max, tn.step, tn.cur} != w {
			t.Errorf("%s = {min:%d max:%d step:%d cur:%d} want %v", tn.name, tn.min, tn.max, tn.step, tn.cur, w)
		}
	}
	// shaper_headroom 只在 --shaper 打开时进轮转 (旧行为)。
	if o2 := mechOptimizer(&shaper{}, true); len(o2.tun) != len(want)+1 {
		t.Errorf("带 shaper 时 %d 个 tunable, want %d (含 shaper_headroom)", len(o2.tun), len(want)+1)
	}
	// 闭环在这个模式下必须整个停用 —— 一个参数绝不允许有两个写者。
	if !o.legacyBandit {
		t.Error("legacyBandit 标志没传下去")
	}
}

// 被移除的参数不能变成"谁也不写"的悬空状态: 冻结常数必须与它们在旧表里的启动值
// 一致 —— delay_cap_thresh 是**故意**的例外。
func TestFrozenConstantsMatchRemovedArms(t *testing.T) {
	legacy := map[string]int{}
	for _, tn := range legacyTunables() {
		legacy[tn.name] = tn.cur
	}
	same := map[string]int{
		"startup_gain":       frozenStartupGain,
		"hd_rho_max":         frozenHdRhoMax,
		"fast_alpha":         frozenFastAlpha,
		"neoq_sparse_thresh": frozenNeoqSparseThresh,
	}
	for name, frozen := range same {
		if legacy[name] != frozen {
			t.Errorf("%s 冻结值 %d != 旧表启动值 %d —— 这不是冻结, 是顺手改了个默认值", name, frozen, legacy[name])
		}
	}
	// ★ 唯一故意的行为变更: 旧表启动时写 50, 现在写 0。人工交替配对 A/B 两轮都是
	//   "开了更差", 这条证据的优先级高于 UCB 学出来的 50; 内核默认也是 0。
	if frozenDelayCapThresh != 0 {
		t.Errorf("delay_cap_thresh 冻结值 %d want 0 (永不进 bandit, 且 A/B 证据是开了更差)", frozenDelayCapThresh)
	}
	if legacy["delay_cap_thresh"] == frozenDelayCapThresh {
		t.Error("这条断言本来是为了记录一次故意的行为变更, 现在两边一样了 —— 请更新注释")
	}
}

// 遥测样本必须记下"什么配置产生了这个分数"。机制模式下 tun 表是空的, 直接遍历它会
// 让 model.json 里全是空 params —— model show 看不到东西, KNN 平均出空配置,
// cmdTune 一个参数都不写。
func TestParamsSnapshotCarriesMechanismConfig(t *testing.T) {
	o := mechOptimizer(&shaper{}, false)
	o.lt.cur = 14
	p := o.paramsSnapshot()
	want := paramSet{
		"loss_thresh":      14,
		"startup_gain":     frozenStartupGain,
		"hd_rho_max":       frozenHdRhoMax,
		"fast_alpha":       frozenFastAlpha,
		"delay_cap_thresh": frozenDelayCapThresh,
	}
	if len(p) != len(want) {
		t.Errorf("snapshot=%v want %v", p, want)
	}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("snapshot[%s]=%d want %d", k, p[k], v)
		}
	}
	// legacy 模式: 快照就是 tun 表本身, 一个不多一个不少。
	ol := mechOptimizer(nil, true)
	pl := ol.paramsSnapshot()
	if len(pl) != len(ol.tun) {
		t.Errorf("legacy snapshot 有 %d 项, tun 表 %d 项", len(pl), len(ol.tun))
	}
	for i := range ol.tun {
		if pl[ol.tun[i].name] != ol.tun[i].cur {
			t.Errorf("legacy snapshot[%s]=%d want %d", ol.tun[i].name, pl[ol.tun[i].name], ol.tun[i].cur)
		}
	}
}

// 生产上 fast_alpha 仍是冻结常数: 推导函数 fastAlphaFor 是 HYPOTHESIS 级, 没有接进
// 主循环。这条断言的作用是, 谁哪天把它接上线, 这个测试会先失败, 逼他先去读那个函数
// 注释里的 netem 台架验收条件。
func TestFastAlphaNotWiredToProduction(t *testing.T) {
	o := mechOptimizer(&shaper{}, false)
	if v := o.paramsSnapshot()["fast_alpha"]; v != frozenFastAlpha {
		t.Errorf("fast_alpha=%d, 生产上应当仍是冻结常数 %d —— 若确实要上线 fastAlphaFor, "+
			"先跑 netem 台架并更新该函数注释里的验收条件", v, frozenFastAlpha)
	}
}
