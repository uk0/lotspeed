package main

import (
	"math"
	"testing"
)

// 本文件是 ③ fast_alpha 物理推导的表驱动单测。
//
// ★ 状态提醒: fastAlphaFor 是 HYPOTHESIS 级, **没有**接进主循环 (生产上 fast_alpha
//   由 frozenFastAlpha 钉住)。这些用例锁的是推导本身的算术和边界, 不是"上线后会
//   怎样" —— 那要等 netem 台架, 验收条件写在 fastAlphaFor 的注释里。

func TestFastAlphaForTable(t *testing.T) {
	cases := []struct {
		name       string
		bwMbps     float64
		minRttMs   float64
		want       int
		wantOk     bool
		budgetNote string
	}{
		// 队列预算 = max(30ms, 0.2*min_rtt), 与 shaper 的 HOLD trim 环同源。
		{"主导档 6M/264ms", 6, 264, 7, true, "比例项 52.8ms"},
		{"主导档 20M/264ms", 20, 264, 23, true, "比例项 52.8ms"},
		{"主导档低端 59M/159ms", 59, 159, fastAlphaMax, true, "比例项 31.8ms, 撞上限"},
		{"主导档低端 3M/159ms", 3, 159, fastAlphaMin, true, "比例项 31.8ms, 撞下限"},
		{"10M/200ms", 10, 200, 9, true, "比例项 40ms, rho 恰好封顶 4"},
		{"10M/100ms 走地板", 10, 100, 13, true, "0.2*100=20 < 30ms 地板"},
		{"1M/50ms 走地板+rho=1", 1, 50, fastAlphaMin, true, "地板 30ms, rho=1"},
		{"100M/200ms 撞上限", 100, 200, fastAlphaMax, true, ""},
		{"无带宽", 0, 264, 0, false, ""},
		{"无 RTT", 10, 0, 0, false, ""},
		{"负输入", -1, -1, 0, false, ""},
	}
	for _, c := range cases {
		got, ok := fastAlphaFor(c.bwMbps, c.minRttMs)
		if ok != c.wantOk || got != c.want {
			t.Errorf("%s: fastAlphaFor(%.0f, %.0f)=(%d,%v) want (%d,%v) [%s]",
				c.name, c.bwMbps, c.minRttMs, got, ok, c.want, c.wantOk, c.budgetNote)
		}
	}
}

// 队列预算必须真的来自 shaper 的那两个常量 (max(30ms, 0.2*min_rtt)), 不是另立的
// 数字 —— 规格明确要求同源。用"地板段 vs 比例段"的分界点来验: 150ms 以下预算恒为
// 30ms, 之上按比例涨。
func TestFastAlphaSharesShaperQueueBudget(t *testing.T) {
	const bw = 10.0
	// 地板段: 0.2*rtt < 30ms 时预算不随 rtt 变, alpha 只被 rho 除。
	// rtt=100 -> rho=2 -> alpha = E*pkts/2; rtt=150 -> rho=3 -> alpha = E*pkts/3。
	pkts := bw * 1e6 / 8 / fastAlphaMSS
	floorSec := eRemoteFloorMs / 1000
	for _, rtt := range []float64{60, 100, 150} {
		want := clampInt(int(math.Round(floorSec*pkts/clampF(rtt/fastAlphaHdRefMs, 1, fastAlphaRhoMax))),
			fastAlphaMin, fastAlphaMax)
		if got, _ := fastAlphaFor(bw, rtt); got != want {
			t.Errorf("rtt=%.0f 处 alpha=%d want %d —— 地板段没在用 eRemoteFloorMs=%.0fms", rtt, got, want, eRemoteFloorMs)
		}
	}
	// 比例段: rtt=264 -> 0.2*264=52.8ms > 30ms 地板。
	ratioSec := eRemoteRttFrac * 264 / 1000
	want := clampInt(int(math.Round(ratioSec*pkts/fastAlphaRhoMax)), fastAlphaMin, fastAlphaMax)
	if got, _ := fastAlphaFor(bw, 264); got != want {
		t.Errorf("rtt=264 处 alpha=%d want %d —— 比例段没在用 eRemoteRttFrac=%.2f", got, want, eRemoteRttFrac)
	}
}

// rho 的除法必须与内核对齐: rho 在 ls_update_rho 里被夹在 [1, hd_rho_max/100] = [1,4],
// 参考 RTT 是 hd_ref_us=50ms。所以 200ms 以上 rho 恒为 4, 再涨 RTT 只让预算变大。
func TestFastAlphaRhoClamp(t *testing.T) {
	// 内核 lotspeed.c: hd_rho_max 默认 400 (= 4x), ls_update_rho 把 rho 夹在
	// [100, rho_max]。这里的 4.0 就是那个上界, 改内核默认值时两边要一起改。
	if fastAlphaRhoMax != 4.0 {
		t.Errorf("fastAlphaRhoMax=%.1f 与内核 hd_rho_max/100=4.0 脱钩了", fastAlphaRhoMax)
	}
	// rho 封顶之后, alpha 只随队列预算 (比例项) 增长, 且必须单调不减。
	prev := 0
	for _, rtt := range []float64{200, 250, 300, 400} {
		got, ok := fastAlphaFor(5, rtt)
		if !ok {
			t.Fatalf("rtt=%.0f 推导失败", rtt)
		}
		if got < prev {
			t.Errorf("rtt=%.0f alpha=%d 比上一档 %d 还小 —— rho 封顶后应当单调不减", rtt, got, prev)
		}
		prev = got
	}
	// 低于 hd_ref 的 RTT 上 rho 不得小于 1 (内核 clamp 的下界), 否则 alpha 会被放大。
	lo, _ := fastAlphaFor(10, 10)
	ref, _ := fastAlphaFor(10, fastAlphaHdRefMs)
	if lo != ref {
		t.Errorf("rtt=10ms 与 rtt=50ms 的 alpha 不同 (%d vs %d) —— rho 的下界 1 没生效", lo, ref)
	}
}

// 固定 RTT 时 alpha 必须随带宽单调不减 (站立队列目标 = E * 包速率)。
func TestFastAlphaMonotoneInBandwidth(t *testing.T) {
	prev := 0
	for _, bw := range []float64{1, 3, 6, 12, 25, 50, 100} {
		got, ok := fastAlphaFor(bw, 264)
		if !ok {
			t.Fatalf("bw=%.0f 推导失败", bw)
		}
		if got < prev {
			t.Errorf("bw=%.0fM alpha=%d 比上一档 %d 小 —— 包速率涨了队列目标却缩了", bw, got, prev)
		}
		if got < fastAlphaMin || got > fastAlphaMax {
			t.Errorf("bw=%.0fM alpha=%d 越出 [%d,%d]", bw, got, fastAlphaMin, fastAlphaMax)
		}
		prev = got
	}
}
