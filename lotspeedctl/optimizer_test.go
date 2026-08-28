package main

import (
	"math"
	"testing"
	"time"
)

// ssTargetFixture is a realistic two-socket `ss -tin dst <ip>` capture (the header
// line + per-socket address line + per-socket stats line, as the real tool emits).
// Socket A carries retrans:5/12 (12 lifetime retransmits); socket B OMITS retrans:
// entirely (its lifetime retransmit count is zero, which ss elides) — exercising the
// defensive "field absent -> contributes 0" path. The stats lines also carry the
// lookalike keys minrtt: and data_segs_out: so the whole-token match in ssField is
// exercised (rtt: must not match minrtt:, segs_out: must not match data_segs_out:).
const ssTargetFixture = `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0      0          10.0.0.2:51514      203.0.113.9:443
	 cubic wscale:7,7 rto:312 rtt:55.0/4.0 ato:40 mss:1448 pmtu:1500 rcvmss:536 advmss:1448 cwnd:64 bytes_sent:9000000 bytes_acked:8000000 bytes_received:5678 segs_out:6000 segs_in:5800 data_segs_out:5900 send 134Mbps lastsnd:8 lastrcv:4 lastack:4 pacing_rate 200Mbps delivery_rate 103Mbps delivered:5900 busy:120ms retrans:5/12 dsack_dups:1 rcv_space:14600 rcv_ssthresh:64076 minrtt:50.0
ESTAB 0      0          10.0.0.2:51520      203.0.113.9:443
	 cubic wscale:7,7 rto:300 rtt:51.0/3.0 ato:40 mss:1448 pmtu:1500 rcvmss:536 advmss:1448 cwnd:48 bytes_sent:4000000 bytes_acked:4000000 bytes_received:1200 segs_out:3000 segs_in:2900 data_segs_out:2950 send 90Mbps lastsnd:8 lastrcv:4 lastack:4 pacing_rate 150Mbps delivery_rate 88Mbps delivered:2950 rcv_space:14600 rcv_ssthresh:64076 minrtt:49.0`

// ssField returns the RAW value token (no "/" handling) and must match the key only
// as a WHOLE token (preceded by space or BOL) so rtt: never matches inside minrtt:
// and segs_out: never inside data_segs_out:.
func TestSSField(t *testing.T) {
	line := "rtt:55.0/4.0 segs_out:6000 data_segs_out:5900 retrans:5/12 minrtt:50.0 bytes_acked:8000000"
	cases := []struct {
		key    string
		want   string
		wantOk bool
	}{
		{"rtt", "55.0/4.0", true},        // raw X/Y (caller splits)
		{"minrtt", "50.0", true},         // distinct token, not shadowed by rtt:
		{"segs_out", "6000", true},       // must NOT pick up data_segs_out:'s 5900
		{"data_segs_out", "5900", true},  // the lookalike resolves on its own
		{"retrans", "5/12", true},        // raw X/Y (caller takes Y=lifetime)
		{"bytes_acked", "8000000", true}, // last token (no trailing space)
		{"cwnd", "", false},              // absent
	}
	for _, c := range cases {
		got, ok := ssField(line, c.key)
		if ok != c.wantOk || got != c.want {
			t.Errorf("ssField(%q)=(%q,%v) want (%q,%v)", c.key, got, ok, c.want, c.wantOk)
		}
	}
	// A key that exists ONLY as a substring of a longer key must report absent.
	if v, ok := ssField("data_segs_out:5900", "segs_out"); ok {
		t.Errorf("ssField saw segs_out inside data_segs_out -> %q (whole-token match broken)", v)
	}
}

// The typed accessors split "X/Y" correctly: rtt -> X (srtt), retrans -> Y (lifetime
// total). segs_out/bytes_acked are plain uints. Absent keys report ok=false.
func TestSSTypedAccessors(t *testing.T) {
	line := "rtt:55.0/4.0 segs_out:6000 retrans:5/12 bytes_acked:8000000 minrtt:50.0"
	if v, ok := ssFloatX(line, "rtt"); !ok || !almost(v, 55.0) {
		t.Errorf("ssFloatX(rtt)=(%v,%v) want (55.0,true) — must take X (srtt)", v, ok)
	}
	if v, ok := ssUintY(line, "retrans"); !ok || v != 12 {
		t.Errorf("ssUintY(retrans)=(%d,%v) want (12,true) — must take Y (lifetime total)", v, ok)
	}
	if v, ok := ssUint(line, "segs_out"); !ok || v != 6000 {
		t.Errorf("ssUint(segs_out)=(%d,%v) want (6000,true)", v, ok)
	}
	if v, ok := ssUint(line, "bytes_acked"); !ok || v != 8_000_000 {
		t.Errorf("ssUint(bytes_acked)=(%d,%v) want (8000000,true)", v, ok)
	}
	// retrans absent (zero-loss socket): ssUintY reports not-ok -> contributes 0.
	if v, ok := ssUintY("rtt:10.0/2.0 segs_out:5", "retrans"); ok {
		t.Errorf("ssUintY(absent retrans)=(%d,true) want ok=false", v)
	}
	// A bare count with no "/" (kernel variant): ssUintY parses the whole value.
	if v, ok := ssUintY("retrans:7", "retrans"); !ok || v != 7 {
		t.Errorf("ssUintY(bare retrans:7)=(%d,%v) want (7,true)", v, ok)
	}
}

// parseSSTarget must aggregate the multi-socket fixture: count both sockets, sum the
// lifetime retrans/segs_out/bytes_acked across them (socket B's absent retrans = 0),
// and average srtt. The lookalike keys (minrtt/data_segs_out) must not contaminate.
func TestParseSSTargetFixture(t *testing.T) {
	st := parseSSTarget(ssTargetFixture)
	if st.socks != 2 {
		t.Fatalf("socks=%d want 2", st.socks)
	}
	// retrans: 12 (A) + 0 (B absent) = 12.
	if st.retr != 12 {
		t.Errorf("retr=%d want 12 (12 from A + 0 from B-absent)", st.retr)
	}
	// segs_out: 6000 + 3000 = 9000 (NOT data_segs_out 5900+2950).
	if st.segs != 9000 {
		t.Errorf("segs=%d want 9000 (must use segs_out, not data_segs_out)", st.segs)
	}
	// bytes_acked: 8_000_000 + 4_000_000 = 12_000_000.
	if st.acked != 12_000_000 {
		t.Errorf("acked=%d want 12000000", st.acked)
	}
	// rtt: mean(55.0, 51.0) = 53.0 (the rtt: X field, not minrtt:).
	if !almost(st.rttMs, 53.0) {
		t.Errorf("rttMs=%.3f want 53.0 (mean of 55.0 and 51.0; minrtt must be ignored)", st.rttMs)
	}
}

// parseSSTarget on output with no socket lines (header only / empty) yields socks=0
// and zero counters — the "no per-link signal this cycle" state.
func TestParseSSTargetNoSockets(t *testing.T) {
	for _, in := range []string{
		"",
		"State Recv-Q Send-Q Local Address:Port Peer Address:Port\n",
	} {
		st := parseSSTarget(in)
		if st.socks != 0 || st.retr != 0 || st.segs != 0 || st.acked != 0 || st.rttMs != 0 {
			t.Errorf("parseSSTarget(%q)=%+v want zero stat", in, st)
		}
	}
}

// newTargetOptForTest builds an optimizer in --target mode with interval=1s so the
// bw arithmetic is simply bytes*8/1e6 Mbps (delta bytes -> Mbps with no scaling).
func newTargetOptForTest() *optimizer {
	return &optimizer{target: "203.0.113.9", interval: time.Second, alpha: 0.5, beta: 1.0}
}

// targetMetrics over a sequence of snapshots must:
//   - suppress the first (priming) cycle's delta (loss=0, bw=iface fallback),
//   - on the next cycle emit loss=Δretrans/Δsegs and bw=Δbytes_acked,
//   - hold the per-link signal scoped to the target (mean srtt passes through).
func TestTargetMetricsDelta(t *testing.T) {
	o := newTargetOptForTest()
	// Cycle 1 (prime): totals adopted, no delta. bw falls back to ifaceBw=7.
	m1 := o.targetMetrics(ssTargetStat{rttMs: 53, retr: 12, segs: 9000, acked: 12_000_000, socks: 2}, 7)
	if m1.lossPct != 0 || m1.bwMbps != 7 || !almost(m1.rttMs, 53) {
		t.Fatalf("prime cycle = %+v want loss 0 bw 7 rtt 53", m1)
	}
	if !o.tgtPrimed {
		t.Fatal("optimizer not primed after first targetMetrics")
	}
	// Cycle 2: +20 retrans over +2000 segs -> loss 0.01; +12_875_000 bytes_acked over
	// 1s -> 103 Mbps. iface bw (999) must be ignored in favor of Δbytes_acked.
	m2 := o.targetMetrics(ssTargetStat{rttMs: 50, retr: 32, segs: 11000, acked: 24_875_000, socks: 2}, 999)
	if !almost(m2.lossPct, 0.01) {
		t.Errorf("loss=%.5f want 0.01 (Δretr 20 / Δsegs 2000)", m2.lossPct)
	}
	if !almost(m2.bwMbps, 103) {
		t.Errorf("bw=%.3f want 103 (Δbytes_acked 12.875e6 *8 /1e6 over 1s)", m2.bwMbps)
	}
	if !almost(m2.rttMs, 50) {
		t.Errorf("rtt=%.3f want 50", m2.rttMs)
	}
	if o.prevTgtLoss != m2.lossPct {
		t.Errorf("prevTgtLoss=%.5f not updated to last good loss %.5f", o.prevTgtLoss, m2.lossPct)
	}
}

// Churn: when a tracked socket closes the summed LIFETIME totals DROP. targetMetrics
// must re-baseline that cycle (adopt the lower totals, NO negative delta) and return
// the PREVIOUS good loss — never a negative loss, never a uint-underflow huge value.
func TestTargetMetricsChurnRebase(t *testing.T) {
	o := newTargetOptForTest()
	// Prime high, then establish a real good loss on cycle 2.
	o.targetMetrics(ssTargetStat{retr: 100, segs: 50_000, acked: 500_000_000, socks: 3}, 5)
	good := o.targetMetrics(ssTargetStat{rttMs: 60, retr: 110, segs: 52_000, acked: 510_000_000, socks: 3}, 5)
	if !almost(good.lossPct, 10.0/2000.0) {
		t.Fatalf("setup loss=%.6f want %.6f", good.lossPct, 10.0/2000.0)
	}
	prevRetr, prevSegs, prevAcked := o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked
	// Cycle 3: a socket closed — every summed lifetime total dropped below the prev.
	churn := o.targetMetrics(ssTargetStat{rttMs: 58, retr: 40, segs: 20_000, acked: 200_000_000, socks: 2}, 42)
	if churn.lossPct < 0 {
		t.Errorf("churn produced NEGATIVE loss %.6f — re-baseline failed", churn.lossPct)
	}
	if !almost(churn.lossPct, good.lossPct) {
		t.Errorf("churn loss=%.6f want previous good %.6f (held across re-baseline)", churn.lossPct, good.lossPct)
	}
	if churn.bwMbps != 42 {
		t.Errorf("churn bw=%.3f want iface fallback 42 (Δbytes_acked unusable on re-baseline)", churn.bwMbps)
	}
	// Baselines must have been re-adopted to the NEW lower totals (so the NEXT cycle
	// diffs against the post-churn floor, not the stale higher one).
	if o.prevTgtRetr != 40 || o.prevTgtSegs != 20_000 || o.prevTgtAcked != 200_000_000 {
		t.Errorf("baselines not re-adopted after churn: retr=%d segs=%d acked=%d (was %d/%d/%d)",
			o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked, prevRetr, prevSegs, prevAcked)
	}
	// Cycle 4 (post-churn, counters grow again): a clean delta off the new floor.
	post := o.targetMetrics(ssTargetStat{rttMs: 57, retr: 45, segs: 21_000, acked: 213_500_000, socks: 2}, 1)
	if !almost(post.lossPct, 5.0/1000.0) {
		t.Errorf("post-churn loss=%.6f want %.6f (Δretr 5 / Δsegs 1000 off new baseline)", post.lossPct, 5.0/1000.0)
	}
	if !almost(post.bwMbps, 108) { // 13.5e6 *8 /1e6 = 108
		t.Errorf("post-churn bw=%.3f want 108", post.bwMbps)
	}
}

// No sockets this cycle: targetMetrics must NOT prime off the empty read (baselines
// untouched), fall back to iface bw, and hold the last loss — so a momentary gap in
// the target's connections doesn't reset the per-link counter baseline.
func TestTargetMetricsNoSockets(t *testing.T) {
	o := newTargetOptForTest()
	o.targetMetrics(ssTargetStat{retr: 10, segs: 1000, acked: 1_000_000, socks: 1}, 1) // prime
	o.targetMetrics(ssTargetStat{retr: 30, segs: 3000, acked: 3_000_000, socks: 1}, 1) // loss=0.01
	savedRetr, savedSegs, savedAcked := o.prevTgtRetr, o.prevTgtSegs, o.prevTgtAcked
	gap := o.targetMetrics(ssTargetStat{socks: 0}, 77)
	if gap.bwMbps != 77 {
		t.Errorf("no-socket bw=%.3f want iface fallback 77", gap.bwMbps)
	}
	if !almost(gap.lossPct, 0.01) {
		t.Errorf("no-socket loss=%.5f want held last loss 0.01", gap.lossPct)
	}
	if o.prevTgtRetr != savedRetr || o.prevTgtSegs != savedSegs || o.prevTgtAcked != savedAcked {
		t.Error("no-socket cycle clobbered the per-target baselines (should be untouched)")
	}
}

// measure() must dispatch machine-wide when target=="" (unchanged path) and
// per-link when target is set. We can't exercise the real ss/iface reads on this
// host, but we can assert the dispatch + that an empty target keeps the machine-wide
// branch (which on a host with no /sys iface just yields zeros, not a panic).
func TestMeasureDispatchMachineWide(t *testing.T) {
	o := &optimizer{target: "", interval: time.Second, alpha: 0.5, beta: 1.0}
	// No panic, and with no real iface the machine-wide branch yields a finite metric.
	m := o.measure()
	if m.bwMbps < 0 {
		t.Errorf("machine-wide measure returned negative bw %.3f", m.bwMbps)
	}
}

// C3: parseSSTarget now also extracts the unloaded floor and the queueing delay
// the shaper's E_remote decomposition needs.
//
//	minRttMs     = MIN of the per-socket minrtt (the path's unloaded floor)
//	queueDelayMs = MEDIAN of the per-socket (srtt - minrtt)
//
// Per-socket subtraction is the whole point: this box carries mixed regimes
// (0.3-13ms proxy egress next to 50-264ms accelerated flows), so a global
// mean(srtt) - min(minrtt) would be the difference between two unrelated paths.
func TestParseSSTargetMinRttAndQueueDelay(t *testing.T) {
	st := parseSSTarget(ssTargetFixture)
	// minrtt: min(50.0, 49.0) = 49.0.
	if !almost(st.minRttMs, 49.0) {
		t.Errorf("minRttMs=%.3f want 49.0 (min across sockets)", st.minRttMs)
	}
	// per-socket E: 55.0-50.0=5.0 and 51.0-49.0=2.0; the package's
	// no-interpolation percentile picks element[int(0.5*1)=0] of {2,5} = 2.
	if !almost(st.queueDelayMs, 2.0) {
		t.Errorf("queueDelayMs=%.3f want 2.0 (median of per-socket srtt-minrtt)", st.queueDelayMs)
	}
	// The pre-existing aggregates must be unchanged by the additions.
	if st.socks != 2 || st.acked != 12_000_000 || !almost(st.rttMs, 53.0) {
		t.Errorf("legacy aggregates changed: %+v", st)
	}
}

// A socket line with no minrtt: contributes neither a floor nor a queue-delay
// sample (defensive parse, same policy as the absent retrans: field).
func TestParseSSTargetMissingMinRtt(t *testing.T) {
	out := "ESTAB 0 0 10.0.0.2:1 10.0.0.3:443\n" +
		"     cubic rtt:80.0/5.0 segs_out:10 bytes_acked:1000\n"
	st := parseSSTarget(out)
	if st.socks != 1 {
		t.Fatalf("socks=%d want 1", st.socks)
	}
	if st.minRttMs != 0 || st.queueDelayMs != 0 {
		t.Errorf("minRttMs=%.3f queueDelayMs=%.3f want 0/0 with minrtt absent", st.minRttMs, st.queueDelayMs)
	}
}

// isBadLink is the shared link-weather criterion (RTT > 3x the unloaded floor),
// used by both the optimizer's credit gate and the shaper's logging.
func TestIsBadLink(t *testing.T) {
	cases := []struct {
		rtt, minRtt float64
		want        bool
	}{
		{165, 160, false},
		{480, 160, false}, // exactly 3x -> ratio-1 == 2.0, not > 2.0
		{481, 160, true},
		{1180, 160, true},
		{500, 0, false}, // no floor yet -> never flag
		{0, 160, false}, // no measurement -> never flag
	}
	for _, c := range cases {
		if got := isBadLink(c.rtt, c.minRtt); got != c.want {
			t.Errorf("isBadLink(%.0f, %.0f)=%v want %v", c.rtt, c.minRtt, got, c.want)
		}
	}
}

// ① 参照系 (peakBw/minRtt) 不得在没有流量的拍里腐蚀。
//
// 复现的就是生产上那条日志: score() 的参照系推进原来在主循环里排在 idle 门之前,
// 于是空转的拍也照样把 peakBw 乘 0.995。green1 一天 3218 个 idle 拍, 0.995^3218 ≈
// 1e-7 —— peakBw 被衰减到近零, 流量一恢复 ratchet 就把它拉平到当前 bw, bw/peakBw
// 恰好 = 1.0, 一个 bw=8M 的拍拿到满分并被记进 model.json / 锁进 bestScore。
//
// 序列: 活跃 bw=30 x10 -> idle x500 -> 活跃 bw=8 x5。
func TestRefsFrozenAcrossIdleGap(t *testing.T) {
	o := &optimizer{alpha: 0.5, beta: 1.0}

	act := metrics{bwMbps: 30, rttMs: 100}
	for i := 0; i < 10; i++ {
		if _, active := o.observe(act); !active {
			t.Fatalf("cycle %d: bw=30M 必须判为活跃拍", i)
		}
	}
	peakAfterActive, minRttAfterActive := o.peakBw, o.minRtt
	if peakAfterActive <= 28 || peakAfterActive > 30 {
		t.Fatalf("活跃期后 peakBw=%.3f, 期望 ~30 (只被 ratchet 后的常规衰减磨掉一点)", peakAfterActive)
	}
	// 这个序列必须真的能复现旧 bug, 否则测试是空的: 旧行为下 500 个 idle 拍把
	// peakBw 衰减到 30*0.995^500 ≈ 2.45, 低于随后的 bw=8 —— ratchet 会把它拉平到
	// 8, score 恰好 = 1.0。
	if decayed := peakAfterActive * math.Pow(0.995, 500); decayed >= 8 {
		t.Fatalf("序列失效: 按旧行为衰减 500 拍后 peakBw 仍有 %.3f >= 8M, 复现不了伪满分", decayed)
	}

	idle := metrics{bwMbps: 0.4, rttMs: 30} // < idleBwFloorMbps
	for i := 0; i < 500; i++ {
		sc, active := o.observe(idle)
		if active {
			t.Fatalf("idle cycle %d: bw=0.4M 不该判为活跃拍", i)
		}
		if sc > 0.5 {
			t.Fatalf("idle cycle %d: score=%.3f —— 空转的拍不该拿高分", i, sc)
		}
	}
	// 冻结语义: 参照系一位都不许动 (陈旧但诚实), 而不是被衰减/被 idle 的低 RTT
	// 拉低。minRtt 尤其重要 —— idle 时 rtt=30ms 是"没排队"而不是"路变短了"。
	if o.peakBw != peakAfterActive {
		t.Errorf("500 拍 idle 把 peakBw 从 %.6f 改成了 %.6f (参照系在 idle 中腐蚀)", peakAfterActive, o.peakBw)
	}
	if o.minRtt != minRttAfterActive {
		t.Errorf("500 拍 idle 把 minRtt 从 %.6f 改成了 %.6f", minRttAfterActive, o.minRtt)
	}

	// 恢复流量, 但只有 8M: 分数必须诚实地反映 8/30 这个比例, 而不是伪满分。
	back := metrics{bwMbps: 8, rttMs: 100}
	sc, active := o.observe(back)
	if !active {
		t.Fatal("bw=8M 必须判为活跃拍")
	}
	want := 8.0 / (peakAfterActive * 0.995) // 这一拍照常衰减一次, 无延迟/丢包惩罚
	if !almost(sc, want) {
		t.Errorf("恢复后首拍 score=%.6f want %.6f (= 8 / 冻结的 peakBw)", sc, want)
	}
	if sc > 0.5 {
		t.Errorf("恢复后首拍 score=%.3f —— 伪满分回来了 (期望 ~%.3f)", sc, want)
	}
	// 最关键的一条, 直接盯住机制本身: bw/peakBw 不得因为参照系被拉平到当前 bw 而
	// 逼近 1.0 —— 生产日志里那行 "EXPLORE bw=0 ... score=1.000" 就是这个比值。
	// (单看最终 score 会被同样腐蚀的 minRtt 带来的延迟惩罚掩盖掉。)
	if ratio := back.bwMbps / o.peakBw; ratio > 0.5 {
		t.Errorf("bw/peakBw=%.3f —— 参照系被拉平到当前 bw 了, 这就是伪满分的来源", ratio)
	}
	for i := 0; i < 4; i++ {
		o.observe(back)
	}
	if o.peakBw < 25 {
		t.Errorf("peakBw=%.3f —— 被拉平到 8M 这个时代了, ratchet 只该对真的新峰上调", o.peakBw)
	}
}

// ② EXPLORE 的计时和相位判定同样只认活跃拍: 否则 idle 中重启服务, 空转 3 拍就转
// OPTIMIZE, 并把那一拍的伪满分锁成 bestScore (之后所有真实分数都比不过它)。
func TestExploreStepIgnoresIdleBeats(t *testing.T) {
	o := &optimizer{alpha: 0.5, beta: 1.0, phase: "EXPLORE", bestScore: -1e9}

	idle := metrics{bwMbps: 0.4, rttMs: 30}
	for i := 0; i < 20; i++ {
		sc, active := o.observe(idle)
		if o.exploreStep(idle, sc, active) {
			t.Fatalf("第 %d 个 idle 拍转进了 OPTIMIZE (bestScore=%.3f)", i, o.bestScore)
		}
	}
	if o.exploreT != 0 {
		t.Errorf("exploreT=%d —— idle 拍不该计时", o.exploreT)
	}
	if o.phase != "EXPLORE" {
		t.Errorf("phase=%s —— 20 个 idle 拍之后仍应停在 EXPLORE", o.phase)
	}
	if o.bestScore != -1e9 {
		t.Errorf("bestScore=%.6f —— 被 idle 拍写进去了", o.bestScore)
	}

	// 真流量来了: 计时照常, 第 3 拍达标转 OPTIMIZE, bestScore 取的是那一拍的真分数。
	act := metrics{bwMbps: 30, rttMs: 100}
	moved, movedAt, movedScore := false, 0, 0.0
	for i := 1; i <= 3; i++ {
		sc, active := o.observe(act)
		if o.exploreStep(act, sc, active) {
			moved, movedAt, movedScore = true, i, sc
			break
		}
	}
	if !moved || movedAt != 3 {
		t.Fatalf("活跃拍未在第 3 拍转 OPTIMIZE (moved=%v at=%d phase=%s exploreT=%d)", moved, movedAt, o.phase, o.exploreT)
	}
	if o.phase != "OPTIMIZE" || o.exploreT != 3 {
		t.Errorf("phase=%s exploreT=%d want OPTIMIZE/3", o.phase, o.exploreT)
	}
	if !almost(o.bestScore, movedScore) {
		t.Errorf("bestScore=%.6f want %.6f (转相位那一拍的分数)", o.bestScore, movedScore)
	}
}

// ③ idle 拍必须像 badLink / SHAPER-BUSY 那两条 continue 一样丢掉挂起的探测, 否则
// 探测落下后隔了一段 idle 断档, 下一个活跃拍的 delta = smScore(现在) - prevScore
// (断档之前), 一个横跨两个 regime 的差值会被记到那个参数头上。
func TestIdleHoldDropsOutstandingProbe(t *testing.T) {
	o := &optimizer{alpha: 0.5, beta: 1.0}
	o.probedTi, o.probedVal, o.prevScore, o.havePrev, o.pendingSign = 1, 300, 0.92, true, 1

	if !o.idleHold(false) {
		t.Fatal("idle 拍必须 hold 住这一拍")
	}
	if o.havePrev {
		t.Error("idle 分支没有丢掉挂起的探测 (havePrev 仍为 true) —— 下一个活跃拍会跨断档记账")
	}
	if o.pendingSign != 0 {
		t.Errorf("pendingSign=%d —— 断档前的那一票必须作废", o.pendingSign)
	}

	// 反向: 活跃拍必须原样放行, 一位都不许清 —— 否则每拍都重新取基线,
	// delta-credit 永远拿不到信号。
	o.havePrev, o.pendingSign = true, -1
	if o.idleHold(true) {
		t.Fatal("活跃拍不该被 hold")
	}
	if !o.havePrev || o.pendingSign != -1 {
		t.Errorf("活跃拍被误清了探测记账: havePrev=%v pendingSign=%d", o.havePrev, o.pendingSign)
	}
}

// EXPLORE 必须有墙钟兜底: 只认活跃拍的话, 一台从不跑到 idleBwFloorMbps 的机器会
// 永远停在 EXPLORE —— 保持一次性激进基线、从不调参, 且日志上看不出异常。
// green1 正是这种机器(6.5 小时里只有 7.6% 的拍有实质流量)。
func TestExploreWallClockEscapesIdleOnlyLink(t *testing.T) {
	o := &optimizer{phase: "EXPLORE", alpha: 0.5, beta: 1.0}
	idle := metrics{bwMbps: 0.3, rttMs: 180, lossPct: 0}
	for i := 0; i < exploreWallMax-1; i++ {
		sc, active := o.observe(idle)
		if o.exploreStep(idle, sc, active) {
			t.Fatalf("第 %d 拍就转出了 EXPLORE, 墙钟上限是 %d", i+1, exploreWallMax)
		}
		if o.phase != "EXPLORE" {
			t.Fatalf("第 %d 拍相位已变成 %s", i+1, o.phase)
		}
	}
	sc, active := o.observe(idle)
	if !o.exploreStep(idle, sc, active) {
		t.Fatalf("第 %d 拍(墙钟上限)仍未转出 EXPLORE — idle 链路会被永久困住", exploreWallMax)
	}
	if o.phase != "OPTIMIZE" {
		t.Errorf("phase=%s want OPTIMIZE", o.phase)
	}
	// 关键: 墙钟转出时不得用 idle 拍的伪分数锁 bestScore —— 那正是要防的事。
	if o.bestScore != 0 {
		t.Errorf("bestScore=%.3f want 0 — 墙钟转出不该采信 idle 拍的分数", o.bestScore)
	}
}

// 有真实流量时仍按原路径快速转出(3-6 拍), 墙钟不该延后它。
func TestExploreStillExitsFastWithTraffic(t *testing.T) {
	o := &optimizer{phase: "EXPLORE", alpha: 0.5, beta: 1.0}
	m := metrics{bwMbps: 40, rttMs: 180, lossPct: 0}
	n := 0
	for i := 0; i < 10; i++ {
		n++
		sc, active := o.observe(m)
		if o.exploreStep(m, sc, active) {
			break
		}
	}
	if n > 6 {
		t.Errorf("有流量时用了 %d 拍才转出, 应 <=6", n)
	}
	if o.phase != "OPTIMIZE" || o.bestScore == 0 {
		t.Errorf("phase=%s bestScore=%.3f — 有流量转出时应采信该拍分数", o.phase, o.bestScore)
	}
}
