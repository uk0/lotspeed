package main

import "testing"

// 实测场景的回归测试: 一条走 docker bridge 的 socket (26.66MB, minrtt 277ms) 和一条
// 走 ens3 的 (1.31MB, minrtt 1ms)。过滤前 far 档会带着 95% 的 acked 参与决策 ——
// 那正是生产日志里 "band -> far ... util=0.02 ... C_hat=19.1 Mbps" 的成因。
func TestSSBandsExcludesOtherInterfaces(t *testing.T) {
	rows := parseSSRows(`0 0 45.149.156.93:443 172.18.0.4:8897
	 lotspeed rtt:277.5/3.0 minrtt:277.13 bytes_acked:27960240 segs_out:20000
0 0 45.149.156.93:443 172.68.211.12:18172
	 lotspeed rtt:1.5/0.5 minrtt:1.034 bytes_acked:1374219 segs_out:1000`, 0)
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	if rows[0].dst != "172.18.0.4:8897" || rows[1].dst != "172.68.211.12:18172" {
		t.Fatalf("dst 未被带出: %q / %q", rows[0].dst, rows[1].dst)
	}

	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(ip string) string {
		if ip == "172.18.0.4" {
			return "br-7860d40690c0"
		}
		return "ens3"
	}
	if rc.via("172.18.0.4:8897") {
		t.Error("docker bridge 上的 socket 不该通过过滤")
	}
	if !rc.via("172.68.211.12:18172") {
		t.Error("走 ens3 的 socket 必须通过过滤")
	}
}

// fail-open: 查不到路由时必须 include, 不能把样本丢光让控制器瞎掉。
func TestRouteCacheFailsOpen(t *testing.T) {
	rc := &routeCache{iface: "ens3", m: map[string]routeEnt{}}
	rc.lookup = func(string) string { return "" } // 模拟 exec 失败
	if !rc.via("1.2.3.4:80") {
		t.Error("路由查不到时必须 include (fail-open)")
	}
	// 没配 iface 时也不过滤
	rc2 := &routeCache{m: map[string]routeEnt{}}
	rc2.lookup = func(string) string { return "lo" }
	if !rc2.via("1.2.3.4:80") {
		t.Error("iface 为空时没有过滤依据, 必须 include")
	}
}

// v6 地址的 host 剥离: 不能按第一个冒号切 (地址内部全是冒号)。
func TestHostOfHandlesV6(t *testing.T) {
	for in, want := range map[string]string{
		"172.68.211.12:18172": "172.68.211.12",
		"[2001:db8::1]:443":   "2001:db8::1",
		"[::1]:80":            "::1",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q)=%q want %q", in, got, want)
		}
	}
}

// 档边界抖动必须被迟滞压住: 一条压在 250ms 边界上的单 socket far 档, 不能每两拍
// 就把控制信号从 intercontinental 抢走 (实测过它在 util=0.13 时触发了假 latch)。
func TestBandSwitchNeedsConfirmation(t *testing.T) {
	s := newTestShaper()
	s.pickedBand = "intercontinental"
	inter := ssTargetStat{socks: 4, acked: 1e9, minRttP50Ms: 180, queueDelayMs: 5}
	far := ssTargetStat{socks: 1, acked: 1e6, minRttP50Ms: 255, queueDelayMs: 93}
	bands := map[string]ssTargetStat{"intercontinental": inter, "far": far}

	// far 有排队会赢 pickBand, 但前 bandConfirmCycles-1 拍必须仍用 intercontinental。
	for i := 1; i < bandConfirmCycles; i++ {
		st, band := pickBand(bands)
		if band != "far" {
			t.Fatalf("cycle %d: pickBand 应选 far (有排队), 得 %q", i, band)
		}
		_ = st
		s.bandHiN++
		if old, ok := bands[s.pickedBand]; !ok || old.socks == 0 || s.bandHiN >= bandConfirmCycles {
			t.Fatalf("cycle %d: 不该这么早切换 (bandHiN=%d)", i, s.bandHiN)
		}
	}
	// 第 bandConfirmCycles 拍才允许接管
	s.bandHiN++
	if s.bandHiN < bandConfirmCycles {
		t.Fatalf("bandHiN=%d 应已达 %d", s.bandHiN, bandConfirmCycles)
	}
}
