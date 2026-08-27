package main

import (
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
