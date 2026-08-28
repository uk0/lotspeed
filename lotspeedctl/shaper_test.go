package main

import (
	"math"
	"testing"
)

// nearly compares with a RELATIVE tolerance — the control law is float rate math
// (bit/s at 1e8 scale), so the package's absolute 1e-9 `almost` is useless here.
func nearly(a, b, rel float64) bool {
	if b == 0 {
		return math.Abs(a) < rel
	}
	return math.Abs(a-b)/math.Abs(b) < rel
}

// newTestShaper builds a controller with I/O stubbed out (no logging, no model.json)
// so step() can be driven directly. Defaults: HOLD, 1 Gbps ceiling, 160ms regime —
// the green1->CN path's measured minRtt band.
func newTestShaper() *shaper {
	s := &shaper{
		state:         stShaperHold,
		headroom:      0.95,
		probeInterval: probeIntervalBase,
		// probeCountdown high enough that HOLD tests never trip into PROBE by
		// accident; the PROBE tests set it explicitly.
		probeCountdown: 1000,
		regimeMinRtt:   160,
		band:           rttBand(160),
		logf:           func(string, ...any) {},
		detectPeer:     func() string { return "203.0.113.9" },
		cacheLookup:    func(string) (float64, bool) { return 0, false },
		cacheStore:     func(string, float64) {},
	}
	s.rateMax = 1000e6
	s.rateMin = rateFloorBps
	return s
}

// sampleAt builds one cycle's observation for a given rate:
//
//	util    -> Δshaper_sent = util * R * T / 8
//	deficit -> Δbytes_acked = Δshaper_sent * (1-deficit)
//
// qlen/backlog/minRtt/queueDelay are passed through for the watchdog, the
// L_local subtraction and the regime/weather gates.
func sampleAt(rate, util, deficit float64, qlen, backlog uint64, minRtt, srtt, qDelay float64) shaperSample {
	dt := shaperTick.Seconds()
	sent := uint64(util * rate * dt / 8)
	return shaperSample{
		dt:           dt,
		sentBytes:    sent,
		ackedBytes:   uint64(float64(sent) * (1 - deficit)),
		backlogBytes: backlog,
		qlen:         qlen,
		minRttMs:     minRtt,
		srttMs:       srtt,
		queueDelayMs: qDelay,
		haveLink:     true,
	}
}

// healthy is the common "shaper bound, path fine" cycle at the current rate.
func healthy(s *shaper) shaperSample {
	return sampleAt(s.rate, 1.0, 0.02, 0, 0, 160, 165, 5)
}

// ---------------------------------------------------------------------------
// SEEK
// ---------------------------------------------------------------------------

// SEEK ramps R by 1.5x per cycle while nothing pushes back, and on the first cycle
// that shows (util>=0.95 AND deficit>5%) it latches C_hat = goodput, sets
// R = headroom*C_hat and hands over to HOLD.
func TestSeekRampThenHandoffToHold(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperSeek
	s.rate = 10e6

	// Demand-limited cycles (util 0.5): the ramp continues, nothing latches.
	for i := 0; i < 3; i++ {
		before := s.rate
		s.step(sampleAt(s.rate, 0.5, 0.0, 0, 0, 160, 165, 5))
		if s.state != stShaperSeek {
			t.Fatalf("cycle %d: left SEEK early (state=%s)", i, s.state)
		}
		if !nearly(s.rate, before*seekGain, 1e-9) {
			t.Fatalf("cycle %d: R=%.0f want %.0f (x%.2f ramp)", i, s.rate, before*seekGain, seekGain)
		}
	}

	// The wall: bound (util 1.0) AND losing 20% of what we send.
	rBefore := s.rate
	s.step(sampleAt(rBefore, 1.0, 0.20, 0, 0, 160, 165, 5))
	if s.state != stShaperHold {
		t.Fatalf("state=%s want HOLD after the binding+deficit cycle", s.state)
	}
	wantC := 0.80 * rBefore // goodput = (1-deficit)*R
	if !nearly(s.cHat, wantC, 1e-3) {
		t.Errorf("C_hat=%.3f Mbps want %.3f (= goodput)", s.cHat/1e6, wantC/1e6)
	}
	if !nearly(s.rate, s.headroom*wantC, 1e-3) {
		t.Errorf("R=%.3f Mbps want %.3f (= headroom*C_hat)", s.rate/1e6, s.headroom*wantC/1e6)
	}
	if !nearly(s.cHatRegime, s.cHat, 1e-9) {
		t.Errorf("cHatRegime=%.3f not latched to C_hat=%.3f (R_min floor would be wrong)", s.cHatRegime, s.cHat)
	}
}

// SEEK also stops on the DELAY signal alone (E_remote > 50ms) even when the
// deficit is clean — a path that answers extra rate with queue instead of loss.
func TestSeekStopsOnRemoteDelay(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperSeek
	s.rate = 100e6
	// queueDelay 90ms with no local backlog => E_remote = 90ms > 50ms.
	s.step(sampleAt(s.rate, 1.0, 0.0, 0, 0, 160, 250, 90))
	if s.state != stShaperHold {
		t.Fatalf("state=%s want HOLD (E_remote=%.0fms should stop the ramp)", s.state, s.eRemote)
	}
}

// A SEEK that reaches the ceiling without ever binding means the shaper simply is
// not the constraint: park at R_max with no capacity estimate (= shaping off).
func TestSeekReachesRateMaxParksIdle(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperSeek
	s.rate = 900e6
	s.step(sampleAt(s.rate, 0.3, 0, 0, 0, 160, 165, 5))
	if s.rate != s.rateMax {
		t.Fatalf("R=%.0f want clamped to R_max=%.0f", s.rate, s.rateMax)
	}
	s.step(sampleAt(s.rate, 0.3, 0, 0, 0, 160, 165, 5))
	if s.state != stShaperHold || s.cHat != 0 {
		t.Fatalf("state=%s C_hat=%.0f want HOLD with C_hat=0 (idle park at R_max)", s.state, s.cHat)
	}
	if s.rate != s.rateMax {
		t.Errorf("idle HOLD R=%.0f want R_max=%.0f (shaper must be effectively off)", s.rate, s.rateMax)
	}
}

// ---------------------------------------------------------------------------
// HOLD cruise — the C_hat filter must not leak
// ---------------------------------------------------------------------------

// REGRESSION: HOLD cruises at R = headroom*C_hat, so goodput ~= headroom*C_hat.
// Feeding that raw goodput into the max filter would shave one headroom off C_hat
// EVERY cycle and collapse R geometrically (0.95^n). feedCHat therefore feeds
// R/headroom on a bound+healthy cycle. 40 cycles must leave R essentially where it
// started, not at 0.95^40 (~13%) of it.
func TestHoldCruiseDoesNotCollapseRate(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	start := s.rate
	for i := 0; i < 40; i++ {
		s.step(healthy(s))
		if s.state != stShaperHold {
			t.Fatalf("cycle %d: left HOLD (state=%s)", i, s.state)
		}
	}
	if !nearly(s.rate, start, 0.01) {
		t.Fatalf("R drifted %.3f -> %.3f Mbps over 40 cruise cycles (headroom leak: 0.95^40=%.3f)",
			start/1e6, s.rate/1e6, math.Pow(0.95, 40))
	}
}

// The other half of the anti-collapse fix: it must not make the filter DEAF.
// On a bound cycle whose deficit is high, feedCHat samples the delivered goodput
// (not R/headroom), so once the 3-window ring has rolled over, C_hat decays toward
// the lower reality at cHatDecay per cycle.
func TestFeedCHatTracksCapacityLoss(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	s.util = 1.0
	s.deficitEMA = 0.30 // > deficitBackoff => sample the goodput, not R/headroom
	s.goodput = 50e6
	for i := 0; i < cWindowLen+2; i++ {
		s.feedCHat()
	}
	if s.cHat >= 100e6 {
		t.Errorf("C_hat=%.1f Mbps unchanged after the ring filled with 50 Mbps — filter is deaf", s.cHat/1e6)
	}

	// And the mirror image: a demand-limited cycle says nothing about capacity, so
	// C_hat must NOT be dragged down by an application that simply stopped sending.
	q := newTestShaper()
	q.setCHat(100e6)
	q.rate = q.headroom * q.cHat
	q.util = 0.2
	q.goodput = 5e6
	for i := 0; i < 10; i++ {
		q.feedCHat()
	}
	if !nearly(q.cHat, 100e6, 1e-9) {
		t.Errorf("C_hat=%.1f Mbps — demand-limited cycles must not be treated as capacity", q.cHat/1e6)
	}
}

// ---------------------------------------------------------------------------
// BACKOFF
// ---------------------------------------------------------------------------

// HOLD -> BACKOFF needs BOTH util>=0.95 (it's my rate, not the weather) AND a
// deficit above 10%, confirmed over 2 consecutive cycles. One cycle must not move.
func TestBackoffNeedsBoundAndConfirmedDeficit(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat

	s.step(sampleAt(s.rate, 1.0, 0.20, 0, 0, 160, 165, 5))
	if s.state != stShaperHold {
		t.Fatalf("one high-deficit cycle already flipped to %s — confirmation gate missing", s.state)
	}
	if s.deficitHiN != 1 {
		t.Fatalf("deficitHiN=%d want 1 after the first confirming cycle", s.deficitHiN)
	}
	s.step(sampleAt(s.rate, 1.0, 0.20, 0, 0, 160, 165, 5))
	if s.state != stShaperBackoff {
		t.Fatalf("state=%s want BACKOFF after %d confirming cycles", s.state, shaperConfirmCycles)
	}

	// In BACKOFF R falls 15% per cycle while the deficit persists.
	before := s.rate
	s.step(sampleAt(s.rate, 1.0, 0.20, 0, 0, 160, 165, 5))
	if !nearly(s.rate, before*backoffGain, 1e-9) {
		t.Errorf("BACKOFF R=%.3f want %.3f (x%.2f)", s.rate/1e6, before*backoffGain/1e6, backoffGain)
	}

	// Once the deficit clears, C_hat re-latches on the delivered goodput and we
	// return to HOLD.
	s.deficitEMA = 0.01
	s.step(sampleAt(s.rate, 1.0, 0.0, 0, 0, 160, 165, 5))
	if s.state != stShaperHold {
		t.Fatalf("state=%s want HOLD once deficit<%.0f%%", s.state, deficitClear*100)
	}
	if !nearly(s.rate, s.headroom*s.cHat, 1e-6) {
		t.Errorf("R=%.3f want headroom*C_hat=%.3f on BACKOFF exit", s.rate/1e6, s.headroom*s.cHat/1e6)
	}
	// BACKOFF is what actually walks capacity down: C_hat re-latches on the goodput
	// the reduced rate delivered, well below where it started.
	if s.cHat >= 100e6 {
		t.Errorf("C_hat=%.1f Mbps not reduced by the BACKOFF episode", s.cHat/1e6)
	}
}

// A deficit that is not physically credible (>=50%) is a broken measurement, not
// evidence: on this box a lot of egress is forwarded/tunneled traffic with no local
// socket, so Δbytes_acked simply doesn't cover all of Δshaper_sent. Backing off on
// that would strangle the link for a bookkeeping artifact.
func TestImplausibleDeficitIsIgnored(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	for i := 0; i < 5; i++ {
		// 90% "loss": far past deficitImplausible.
		s.step(sampleAt(s.rate, 1.0, 0.90, 0, 0, 160, 165, 5))
	}
	if s.state == stShaperBackoff {
		t.Fatalf("an implausible 90%% deficit drove the controller into BACKOFF")
	}
	if s.deficitEMA != 0 {
		t.Errorf("deficitEMA=%.3f — implausible samples must not enter the EMA at all", s.deficitEMA)
	}
}

// ---------------------------------------------------------------------------
// 天气门
// ---------------------------------------------------------------------------

// util<0.9 means the shaper isn't binding, so loss/RTT spikes are the path's
// weather, not our doing — R must not move. The second half of the test feeds the
// IDENTICAL loss/delay with util=1.0 to prove the gate is what's holding it (not
// some other condition silently swallowing the signal).
func TestWeatherGateHoldsRate(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	rate0, cHat0 := s.rate, s.cHat

	// Weather: heavy loss + a 400ms remote queue, but only 50% utilisation.
	for i := 0; i < 4; i++ {
		s.step(sampleAt(s.rate, 0.5, 0.40, 0, 0, 160, 700, 400))
	}
	if s.state != stShaperHold {
		t.Fatalf("state=%s want HOLD — util<%.2f must veto every downward action", s.state, utilWeather)
	}
	if s.deficitHiN != 0 || s.delayHiN != 0 {
		t.Errorf("confirm counters advanced under weather (deficitHiN=%d delayHiN=%d)", s.deficitHiN, s.delayHiN)
	}
	if !nearly(s.rate, rate0, 1e-9) || !nearly(s.cHat, cHat0, 1e-9) {
		t.Errorf("weather moved R %.3f->%.3f / C_hat %.3f->%.3f Mbps",
			rate0/1e6, s.rate/1e6, cHat0/1e6, s.cHat/1e6)
	}

	// Same numbers, but now we ARE the load: the controller must act.
	s2 := newTestShaper()
	s2.setCHat(100e6)
	s2.cHatRegime = 100e6
	s2.rate = s2.headroom * s2.cHat
	for i := 0; i < 2; i++ {
		s2.step(sampleAt(s2.rate, 1.0, 0.40, 0, 0, 160, 700, 400))
	}
	if s2.state != stShaperBackoff {
		t.Fatalf("state=%s want BACKOFF at util=1.0 — the weather gate would be vacuous otherwise", s2.state)
	}
}

// The E_remote trim only counts the queue we did NOT put in our own qdisc:
// L_local = backlog*8/R is CoDel's problem, only the remainder is R's. A backlog
// that explains the whole srtt inflation must therefore trigger nothing.
func TestLocalBacklogIsNotChargedToRate(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat // 95 Mbps
	// 95 Mbps * 200ms = 2.375 MB of local backlog explains a 200ms queue exactly.
	backlog := uint64(s.rate * 0.200 / 8)
	for i := 0; i < 4; i++ {
		s.step(sampleAt(s.rate, 1.0, 0.02, 0, backlog, 160, 360, 200))
	}
	if s.eRemote > 1 {
		t.Errorf("E_remote=%.1fms — local backlog should have absorbed the whole 200ms", s.eRemote)
	}
	if s.delayHiN != 0 {
		t.Errorf("delayHiN=%d — trim armed on delay that belongs to the local queue", s.delayHiN)
	}
}

// Remote queue above the budget (max(30ms, 0.2*minRtt)) trims C_hat by 2% once
// confirmed over 2 cycles.
func TestRemoteDelayTrimsCHat(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	// budget = max(30, 0.2*160) = 32ms; feed 300ms of purely remote queue.
	s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, 160, 460, 300))
	if !nearly(s.cHat, 100e6, 1e-9) {
		t.Fatalf("C_hat trimmed after one cycle (%.3f) — needs %d-cycle confirmation", s.cHat/1e6, shaperConfirmCycles)
	}
	s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, 160, 460, 300))
	if !nearly(s.cHat, 100e6*trimGain, 1e-6) {
		t.Errorf("C_hat=%.4f Mbps want %.4f (one %.2f trim)", s.cHat/1e6, 100e6*trimGain/1e6, trimGain)
	}
}

// ---------------------------------------------------------------------------
// PROBE
// ---------------------------------------------------------------------------

// A probe that buys at least half its own amplitude in goodput is adopted:
// C_hat jumps to the measured goodput and the probe interval resets to base.
// A probe that buys nothing is reverted, C_hat is marked confirmed and the
// interval backs off exponentially (6 -> 12 -> 24).
func TestProbeAcceptAndReject(t *testing.T) {
	// --- accept ---
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	s.probeCountdown = 1
	s.step(healthy(s)) // countdown 1 -> 0 => enter PROBE
	if s.state != stShaperProbe {
		t.Fatalf("state=%s want PROBE once the countdown expires", s.state)
	}
	if !nearly(s.rate, s.probeFromRate*probeGain, 1e-9) {
		t.Fatalf("probe R=%.3f want %.3f (x%.2f)", s.rate/1e6, s.probeFromRate*probeGain/1e6, probeGain)
	}
	s.step(healthy(s)) // the probe rate is actually delivered => big goodput gain
	if s.state != stShaperHold {
		t.Fatalf("PROBE lasted more than one cycle (state=%s)", s.state)
	}
	if s.cHat <= 100e6 {
		t.Errorf("C_hat=%.1f Mbps not raised by an accepted probe", s.cHat/1e6)
	}
	if s.probeInterval != probeIntervalBase {
		t.Errorf("probeInterval=%d want %d after an accept", s.probeInterval, probeIntervalBase)
	}

	// --- reject ---
	r := newTestShaper()
	r.setCHat(100e6)
	r.rate = r.headroom * r.cHat
	r.probeCountdown = 1
	r.step(healthy(r))
	from := r.probeFromRate
	// The extra rate buys nothing: goodput stays at the pre-probe level.
	flat := sampleAt(from, 1.0, 0.02, 0, 0, 160, 165, 5)
	flat.sentBytes = uint64(r.rate * flat.dt / 8) // still bound at the probe rate
	r.step(flat)
	if r.state != stShaperHold {
		t.Fatalf("state=%s want HOLD after a rejected probe", r.state)
	}
	if !nearly(r.rate, from, 1e-6) {
		t.Errorf("R=%.3f want reverted to %.3f Mbps", r.rate/1e6, from/1e6)
	}
	if !r.cHatConfirmed {
		t.Error("a rejected probe must mark C_hat confirmed")
	}
	if r.probeInterval != probeIntervalBase*2 {
		t.Errorf("probeInterval=%d want %d (exponential backoff)", r.probeInterval, probeIntervalBase*2)
	}
}

// ---------------------------------------------------------------------------
// 四层护栏
// ---------------------------------------------------------------------------

// Guardrail 1: R_min = max(2Mbps, 0.3*C_hat_regime). BACKOFF must bottom out there
// and stay — 绝不把链路勒死.
func TestRateMinFloor(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperBackoff
	s.cHatRegime = 100e6 // floor = 30 Mbps
	s.rate = 31e6
	s.deficitEMA = 0.30
	// 必须停在 backoffMaxCycles 以内: 超过它 BACKOFF 会走"证伪"出口回 HOLD, 而本用例
	// 人为构造的 cHat=0 (真实运行中进 BACKOFF 必从 HOLD 来, HOLD 要求 cHat>0) 会让它
	// 落进 idle HOLD 分支并把 R 抬到 R_max —— 那时测的已经不是本用例声称的
	// "BACKOFF 压到地板并停住"了。第 1 拍即触底, 余下几拍验证它停在那里。
	for i := 0; i < backoffMaxCycles-2; i++ {
		s.step(sampleAt(s.rate, 1.0, 0.30, 0, 0, 160, 165, 5))
	}
	if !nearly(s.rate, 0.3*100e6, 1e-9) {
		t.Fatalf("R=%.3f Mbps want the %.0f Mbps floor (0.3*C_hat_regime)", s.rate/1e6, 0.3*100e6/1e6)
	}

	// With no regime capacity yet, the absolute 2 Mbps floor applies.
	b := newTestShaper()
	b.state = stShaperBackoff
	b.rate = 2.1e6
	b.deficitEMA = 0.30
	for i := 0; i < backoffMaxCycles-2; i++ { // 同上: 不越过证伪出口
		b.step(sampleAt(b.rate, 1.0, 0.30, 0, 0, 160, 165, 5))
	}
	if !nearly(b.rate, rateFloorBps, 1e-9) {
		t.Errorf("R=%.3f Mbps want the absolute %.0f Mbps floor", b.rate/1e6, rateFloorBps/1e6)
	}
}

// Guardrail 2: R never exceeds R_max, and R_min can never push it above R_max
// either (clampF returns lo when lo>hi — a fail-CLOSED trap in the wrong order).
func TestRateMaxCeilingWinsOverFloor(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperSeek
	s.rate = 900e6
	s.step(sampleAt(s.rate, 0.5, 0, 0, 0, 160, 165, 5))
	if s.rate != s.rateMax {
		t.Fatalf("R=%.0f want clamped to R_max=%.0f", s.rate, s.rateMax)
	}

	// A stale-high cHatRegime would compute R_min=30 Mbps on a 10 Mbps ceiling.
	c := newTestShaper()
	c.rateMax = 10e6
	c.cHatRegime = 100e6
	c.state = stShaperBackoff
	c.rate = 8e6
	c.deficitEMA = 0.30
	c.step(sampleAt(c.rate, 1.0, 0.30, 0, 0, 160, 165, 5))
	if c.rate > c.rateMax {
		t.Errorf("R=%.3f Mbps exceeded R_max=%.3f — R_min was applied above the ceiling",
			c.rate/1e6, c.rateMax/1e6)
	}
}

// Guardrail 3: demand present (qlen>0) but essentially no goodput for 3 cycles =>
// the controller declares itself broken, yields to R_max and logs. It then re-arms
// only after the link looks healthy again for several cycles.
func TestWatchdogYieldsAndRecovers(t *testing.T) {
	var warned int
	s := newTestShaper()
	s.logf = func(string, ...any) { warned++ }
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat

	dead := func() shaperSample {
		sm := sampleAt(s.rate, 1.0, 0, 5, 4096, 160, 900, 700)
		sm.ackedBytes = 0 // nothing is getting through
		return sm
	}
	for i := 0; i < watchdogCycles-1; i++ {
		s.step(dead())
		if s.state == stShaperYield {
			t.Fatalf("watchdog fired after %d cycles, want %d", i+1, watchdogCycles)
		}
	}
	s.step(dead())
	if s.state != stShaperYield {
		t.Fatalf("state=%s want YIELD after %d dead cycles", s.state, watchdogCycles)
	}
	if s.rate != s.rateMax {
		t.Errorf("R=%.0f want R_max=%.0f — yielding must be fail-OPEN", s.rate, s.rateMax)
	}
	if warned == 0 {
		t.Error("watchdog fired without writing a warning")
	}

	// Recovery: healthy cycles bring the controller back to SEEK.
	for i := 0; i < watchdogRecoverCycles; i++ {
		s.step(sampleAt(s.rate, 0.2, 0.01, 0, 0, 160, 165, 5))
	}
	if s.state != stShaperSeek {
		t.Errorf("state=%s want SEEK after %d recovered cycles", s.state, watchdogRecoverCycles)
	}
}

// ---------------------------------------------------------------------------
// regime / 缓存 / 慢层闸门
// ---------------------------------------------------------------------------

// A minRtt drift of >=2x (the same criterion the optimizer's B4 unfreeze uses) is a
// different physical path: C_hat is void, R is re-seeded from that regime's cache
// at 0.7x and we go back to SEEK.
func TestRegimeSwitchResetsAndReseeds(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	s.peer = "203.0.113.9"
	s.cacheLookup = func(key string) (float64, bool) {
		if key == "203.0.113.9|regional" {
			return 400_000, true // 400 Mbps in kbps
		}
		return 0, false
	}
	// minRtt 160 -> 40ms: ratio 0.25 <= 0.5 => regime change, but only after
	// regimeConfirmCycles consecutive cycles say so (a single noisy cycle must not
	// cost a C_hat reset — see the regime block in step()).
	for i := 0; i < regimeConfirmCycles-1; i++ {
		s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, 40, 45, 5))
		if s.state != stShaperHold {
			t.Fatalf("cycle %d: regime switched after %d cycles, want %d", i+1, i+1, regimeConfirmCycles)
		}
	}
	s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, 40, 45, 5))
	if s.state != stShaperSeek {
		t.Fatalf("state=%s want SEEK after a regime switch", s.state)
	}
	if s.cHat != 0 || s.cHatRegime != 0 {
		t.Errorf("C_hat=%.1f regime=%.1f — both must be cleared on a regime switch", s.cHat, s.cHatRegime)
	}
	if s.band != "regional" {
		t.Errorf("band=%q want %q", s.band, "regional")
	}
	if !nearly(s.rate, cacheSeedFrac*400e6, 1e-6) {
		t.Errorf("R=%.1f Mbps want %.1f (0.7 * cached 400 Mbps)", s.rate/1e6, cacheSeedFrac*400e6/1e6)
	}
}

// Small minRtt wobble inside the band must NOT count as a regime change — otherwise
// the cache never accumulates anything and SEEK restarts forever.
func TestRegimeStableUnderWobble(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	for _, mr := range []float64{159, 167, 162, 175, 158} {
		s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, mr, mr+5, 5))
		if s.state != stShaperHold {
			t.Fatalf("minRtt=%.0f knocked the controller out of HOLD (state=%s)", mr, s.state)
		}
	}
}

// The capacity cache is written only after HOLD has been stable long enough, and it
// stores C_hat (a physical property of the path), not R (a headroom-policy artifact).
func TestCacheWriteAfterStableHold(t *testing.T) {
	got := map[string]float64{}
	s := newTestShaper()
	s.peer = "203.0.113.9"
	s.cacheStore = func(k string, kbps float64) { got[k] = kbps }
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat

	s.cacheAge = cacheWriteCycles - 1
	s.maybeWriteCache()
	if len(got) != 0 {
		t.Fatalf("cache written at %d HOLD cycles, want >=%d", cacheWriteCycles-1, cacheWriteCycles)
	}
	s.cacheAge = cacheWriteCycles
	s.maybeWriteCache()
	if v, ok := got["203.0.113.9|intercontinental"]; !ok || !nearly(v, 100e6/1000, 1e-9) {
		t.Errorf("cache=%v want {203.0.113.9|intercontinental: %.0f kbps}", got, 100e6/1000)
	}
	if s.cacheAge != 0 {
		t.Errorf("cacheAge=%d not reset after a cache write", s.cacheAge)
	}
}

// REGRESSION: the cache timer must not share a counter with the slow-layer gate.
// The routine PROBE (every probeIntervalBase=6 cycles) resets holdStable, and
// 6 < cacheWriteCycles(30) — so a shared counter would make the cache write dead
// code. Drive a real HOLD cruise (probes and all) and assert it still fires.
func TestCacheWriteSurvivesRoutineProbes(t *testing.T) {
	got := map[string]float64{}
	s := newTestShaper()
	s.peer = "203.0.113.9"
	s.cacheStore = func(k string, kbps float64) { got[k] = kbps }
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	s.probeCountdown = probeIntervalBase
	for i := 0; i < cacheWriteCycles*2; i++ {
		s.step(healthy(s))
	}
	if len(got) == 0 {
		t.Fatalf("no cache write after %d HOLD cycles — the write path is dead code", cacheWriteCycles*2)
	}
}

func TestRttBandBoundaries(t *testing.T) {
	cases := []struct {
		ms   float64
		want string
	}{
		{0, "unknown"}, {-1, "unknown"},
		{5, "lan"}, {19.9, "lan"},
		{20, "regional"}, {59, "regional"},
		{60, "continental"}, {119, "continental"},
		{120, "intercontinental"}, {165, "intercontinental"}, {249, "intercontinental"},
		{250, "far"}, {800, "far"},
	}
	for _, c := range cases {
		if got := rttBand(c.ms); got != c.want {
			t.Errorf("rttBand(%.1f)=%q want %q", c.ms, got, c.want)
		}
	}
}

// The slow layer may only step a coordinate while the fast loop is cruising:
// during SEEK/PROBE/BACKOFF the rate itself is moving, so any score delta is
// unattributable to the coordinate. A nil (or kernel-unsupported) shaper is
// always open — the gate must never freeze the slow layer on a box without one.
func TestSlowLayerGate(t *testing.T) {
	var nilShaper *shaper
	if !nilShaper.slowLayerReady() {
		t.Error("nil shaper must leave the slow layer open")
	}
	s := newTestShaper()
	s.unsupported = true
	if !s.slowLayerReady() {
		t.Error("kernel-unsupported shaper must leave the slow layer open")
	}
	s.unsupported = false
	for _, st := range []string{stShaperSeek, stShaperProbe, stShaperBackoff, stShaperObserve, stShaperYield} {
		s.state = st
		s.holdStable = 99
		if s.slowLayerReady() {
			t.Errorf("slow layer open while shaper is in %s", st)
		}
	}
	s.state = stShaperHold
	s.holdStable = holdStableForSlowLayer - 1
	if s.slowLayerReady() {
		t.Errorf("slow layer open at holdStable=%d, want >=%d", s.holdStable, holdStableForSlowLayer)
	}
	s.holdStable = holdStableForSlowLayer
	if !s.slowLayerReady() {
		t.Error("slow layer still frozen at a stable HOLD")
	}
}

// rateCV feeds score()'s "don't let the controller oscillate its own actuator"
// penalty. It must report not-ok on a short ring (so score stays the legacy
// formula) and a real coefficient of variation once the ring fills.
func TestRateCV(t *testing.T) {
	var nilShaper *shaper
	if _, ok := nilShaper.rateCV(); ok {
		t.Error("nil shaper reported a CV")
	}
	s := newTestShaper()
	s.rRing = []float64{100e6, 100e6}
	if _, ok := s.rateCV(); ok {
		t.Errorf("short ring (%d) reported a CV, want ok=false", len(s.rRing))
	}
	s.rRing = []float64{100e6, 100e6, 100e6, 100e6}
	if cv, ok := s.rateCV(); !ok || !almost(cv, 0) {
		t.Errorf("flat ring CV=(%v,%v) want (0,true)", cv, ok)
	}
	s.rRing = []float64{50e6, 150e6, 50e6, 150e6}
	cv, ok := s.rateCV()
	if !ok || !almost(cv, 0.5) { // mean 100, stddev 50
		t.Errorf("swinging ring CV=(%v,%v) want (0.5,true)", cv, ok)
	}
}

// setHeadroom is the slow layer's only write into the fast loop; the percent->
// fraction conversion is what the shaper_headroom arm relies on.
func TestSetHeadroomChangesRate(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.rate = s.headroom * s.cHat
	s.setHeadroom(85.0 / headroomPctScale)
	s.step(healthy(s))
	if !nearly(s.rate, 0.85*s.cHat, 1e-6) {
		t.Errorf("R=%.3f Mbps want %.3f (headroom 0.85 * C_hat)", s.rate/1e6, 0.85*s.cHat/1e6)
	}
	// A bogus value must be ignored rather than zeroing the rate.
	s.setHeadroom(0)
	if s.headroom != 0.85 {
		t.Errorf("headroom=%v — a non-positive value must be rejected", s.headroom)
	}
}

// ---------------------------------------------------------------------------
// CoDel target mapping (C3)
// ---------------------------------------------------------------------------

// target = clamp(max(15ms, RTT/8), 5, 60)ms, interval = clamp(2*RTT, 100, 600)ms.
// Once the shaper binds, the LOCAL queue is the main queue, so the target is a
// local queue budget, not a fraction of the path RTT.
func TestCodelParams(t *testing.T) {
	if _, _, ok := codelParams(0); ok {
		t.Error("codelParams(0) ok=true, want false")
	}
	cases := []struct {
		rttMs, target, interval float64
	}{
		{40, 15000, 100000},   // RTT/8=5ms -> 15ms floor; 2*RTT=80ms -> 100ms floor
		{160, 20000, 320000},  // RTT/8=20ms; 2*RTT=320ms
		{468, 58500, 600000},  // RTT/8=58.5ms; 2*RTT=936ms -> 600ms cap
		{1000, 60000, 600000}, // RTT/8=125ms -> 60ms cap
	}
	for _, c := range cases {
		tg, iv, ok := codelParams(c.rttMs)
		if !ok || !almost(tg, c.target) || !almost(iv, c.interval) {
			t.Errorf("codelParams(%.0f)=(%.0f,%.0f,%v) want (%.0f,%.0f,true)",
				c.rttMs, tg, iv, ok, c.target, c.interval)
		}
	}
}

// ---------------------------------------------------------------------------
// 对抗性审查的六个缺陷 —— 每个都用 step() 复现原场景, 断言修复后的行为。
// 共同的模式: 某个状态的退出条件依赖的量, 在该状态里可能永远不更新/不可达。
// ---------------------------------------------------------------------------

// REGRESSION (缺陷 1a): BACKOFF 曾经是吸收态。唯一出口是 deficitEMA < deficitClear(5%),
// 而 deficit 有结构性底噪 (线路头开销 + 重传, 而"高重传是常态"正是这条链路的设计前提)。
// 进要 >10%, 出要 <5% —— 底噪落在中间时进得去出不来。
// 实测: cHat=100M 持续喂 util=1.0/deficit=0.15 四百拍 (800s) 之后
//
//	state=BACKOFF R=30.00 Mbps (=0.3*C_hat_regime 地板) watchdogN=0
//
// 吞吐掉 70%, 看门狗够不着 (goodput 25Mbps >> 1Mbps 门槛), 慢层同时被永久冻结。
func TestBackoffIsNotAbsorbing(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	start := s.rate

	backoffCycles, everReady := 0, false
	for i := 0; i < 400; i++ {
		s.step(sampleAt(s.rate, 1.0, 0.15, 0, 0, 160, 165, 5))
		if s.state == stShaperBackoff {
			backoffCycles++
		}
		if i > 20 && s.slowLayerReady() {
			everReady = true
		}
	}
	if backoffCycles == 0 {
		t.Fatal("the 15% deficit never entered BACKOFF — this repro is not exercising the bug")
	}
	if s.state == stShaperBackoff {
		t.Fatalf("still in BACKOFF after 400 cycles (R=%.1f Mbps) — no termination condition", s.rate/1e6)
	}
	// 压满 backoffMaxCycles 就必须放弃; 加上 2 拍确认和一点余量。
	if backoffCycles > backoffMaxCycles+shaperConfirmCycles+2 {
		t.Errorf("%d cycles spent in BACKOFF, want <=%d — it kept re-entering on the same structural deficit",
			backoffCycles, backoffMaxCycles+shaperConfirmCycles+2)
	}
	floor := rateMinFrac * s.cHatRegime
	if s.rate <= floor*1.05 {
		t.Fatalf("R=%.1f Mbps parked on the %.1f Mbps floor — the rate cut was never undone", s.rate/1e6, floor/1e6)
	}
	if s.rate < start {
		t.Errorf("R=%.1f Mbps below the pre-BACKOFF %.1f Mbps — a deficit that does not respond to rate cuts must not cost throughput",
			s.rate/1e6, start/1e6)
	}
	if s.deficitBias <= 0 {
		t.Errorf("deficitBias=%.3f — giving up must raise this regime's threshold, else the next cycle re-enters",
			s.deficitBias)
	}
	if !everReady {
		t.Error("slowLayerReady() never became true — BACKOFF also froze the whole slow layer")
	}
}

// REGRESSION (缺陷 1b): deficit 的分母必须先扣掉线路头开销。shaper_sent 是线路字节,
// bytes_acked 是净荷字节 —— 一个零丢包的满 MSS 流 1514/1448 天生就有 4.4% 的"缺口",
// 它是记账口径差不是丢包。不扣掉的话 deficitClear(5%) 语义上几乎不可达。
func TestDeficitDiscountsHeaderOverhead(t *testing.T) {
	const segs = 15687 // 挑一个让 util≈1.0 的包数, 免得顺带触发别的门
	clean := shaperSample{
		dt:           shaperTick.Seconds(),
		sentBytes:    segs * 1514, // 线路字节
		ackedBytes:   segs * 1448, // 净荷字节 —— 一个包都没丢
		segsOut:      segs,
		minRttMs:     160,
		srttMs:       165,
		queueDelayMs: 5,
		haveLink:     true,
	}

	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	for i := 0; i < 5; i++ {
		s.step(clean)
	}
	if s.deficitEMA > 0.005 {
		t.Errorf("deficitEMA=%.4f on a lossless full-MSS stream — the 66/1514 header overhead is being read as loss",
			s.deficitEMA)
	}

	// 对照组: 同样的字节但拿不到 segs_out (= 修复前的口径) 就是 4.4% 的假 deficit。
	// 这是为了钉住上面那条断言真的在测头开销修正, 而不是碰巧为 0。
	q := newTestShaper()
	q.setCHat(100e6)
	q.cHatRegime = 100e6
	q.rate = q.headroom * q.cHat
	noSegs := clean
	noSegs.segsOut = 0
	for i := 0; i < 5; i++ {
		q.step(noSegs)
	}
	if !nearly(q.deficitEMA, 1-1448.0/1514.0, 0.05) {
		t.Errorf("control group deficitEMA=%.4f want ~%.4f — the fixture is not what the test assumes",
			q.deficitEMA, 1-1448.0/1514.0)
	}
}

// REGRESSION (缺陷 2a): shaper 用的 minRtt 必须是"各 socket minrtt 的中位数", 不是
// 全机最小值。ssAll() 扫的是全机 established socket, 这台机器上代理出口 (0.3ms) 和
// 加速流 (159ms) 同时在跑 —— 全局 min 是代理那条路的, 拿它做 regime/band/预算等于
// 在用另一条链路的物理量。band 也会被永久钉成 "lan", 把洲际容量写进 <peer>|lan 键。
func TestShaperMinRttIsMedianNotGlobalMin(t *testing.T) {
	out := "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"ESTAB 0 0 10.0.0.2:51514 203.0.113.9:443\n" +
		"\t cubic rtt:165.0/4.0 mss:1448 segs_out:6000 bytes_acked:8000000 minrtt:159.0\n" +
		"ESTAB 0 0 10.0.0.2:51520 203.0.113.9:443\n" +
		"\t cubic rtt:170.0/3.0 mss:1448 segs_out:3000 bytes_acked:4000000 minrtt:161.0\n" +
		"ESTAB 0 0 10.0.0.2:44012 10.0.0.9:8080\n" +
		"\t cubic rtt:0.5/0.2 mss:1448 segs_out:120 bytes_acked:90000 minrtt:0.3\n"
	st := parseSSTarget(out)
	if !almost(st.minRttMs, 0.3) {
		t.Fatalf("minRttMs=%.3f want 0.3 (the legacy global-min field must not change)", st.minRttMs)
	}
	if !almost(st.minRttP50Ms, 159.0) {
		t.Errorf("minRttP50Ms=%.3f want 159.0 (median of {0.3,159,161})", st.minRttP50Ms)
	}
	if !almost(shaperMinRtt(st), 159.0) {
		t.Errorf("shaperMinRtt=%.3f want 159.0 — the shaper must not see the proxy socket's floor", shaperMinRtt(st))
	}
	if b := rttBand(shaperMinRtt(st)); b != "intercontinental" {
		t.Errorf("band=%q want %q — the global min would have cached this path under %q",
			b, "intercontinental", rttBand(st.minRttMs))
	}
	// minrtt 一个都没有时退回全局 min (两者都是 0, 只是不引入新分支)。
	if got := shaperMinRtt(ssTargetStat{}); got != 0 {
		t.Errorf("shaperMinRtt(empty)=%.3f want 0", got)
	}
}

// REGRESSION (缺陷 2b): regime 切换必须连续确认。原来是单拍立即触发, 而一个本地
// socket 隔拍出现一次就能让 minRtt 在 0.3ms 和 159ms 之间跳 —— 实测 20 拍里触发 19 次
// regime 切换 (每次 C_hat 清零 + 强制回 SEEK), 永远到不了 HOLD, 慢层永久冻结。
func TestRegimeSwitchNeedsConfirmation(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat

	switches := 0
	for i := 0; i < 20; i++ {
		mr := 160.0
		if i%2 == 1 {
			mr = 0.3 // 本地代理 socket 这一拍存在
		}
		before := s.state
		s.step(sampleAt(s.rate, 1.0, 0.02, 0, 0, mr, mr+5, 5))
		if before != stShaperSeek && s.state == stShaperSeek {
			switches++
		}
	}
	if switches != 0 {
		t.Fatalf("%d regime switches from an alternating minRtt — a single noisy cycle must not void C_hat", switches)
	}
	if s.state != stShaperHold {
		t.Errorf("state=%s want HOLD — the wobble knocked the controller off cruise", s.state)
	}
	if s.cHat <= 0 || s.band != "intercontinental" {
		t.Errorf("C_hat=%.1f band=%q — regime state was reset by the wobble", s.cHat/1e6, s.band)
	}
	if !s.slowLayerReady() {
		t.Errorf("slow layer frozen after 20 wobble cycles (state=%s holdStable=%d)", s.state, s.holdStable)
	}
}

// REGRESSION (缺陷 3): 空载 HOLD 曾经是吸收态。出口是 util >= utilBind, 而
// util = Δsent*8/(R_max*T) —— 在虚拟网卡上 ifaceLineRateBps 读到 -1 就退到
// defaultRateMaxMbps(10Gbps), 那是策略常数不是物理量。目标机器就是 virtio VPS:
// 满载 100Mbps 时 util=0.01, 永远够不到 0.95。
// 后果两层: 整形器变成死代码; 而且这个分支每拍 holdStable=0, slowLayerReady() 恒为
// false —— 打开 --shaper 反而把整个 optimizer 永久冻结了。
func TestIdleHoldIsNotAbsorbing(t *testing.T) {
	// 100 Mbps 真实流量, 远端 300ms 常驻队列 (这条链路存在的全部理由)。
	load := func(qDelay float64) shaperSample {
		dt := shaperTick.Seconds()
		sent := uint64(100e6 * dt / 8)
		return shaperSample{
			dt:           dt,
			sentBytes:    sent,
			ackedBytes:   uint64(float64(sent) * 0.98),
			minRttMs:     160,
			srttMs:       160 + qDelay,
			queueDelayMs: qDelay,
			haveLink:     true,
		}
	}

	// (a) 远端有队列 -> 必须开始整形。
	s := newTestShaper()
	s.rateMax = defaultRateMaxMbps * 1e6 // 兜底 R_max, 就是生产上的情况
	s.rate = s.rateMax
	s.setCHat(0)
	cycles := 0
	for ; cycles < 200 && s.cHat <= 0; cycles++ {
		s.step(load(300))
	}
	if s.cHat <= 0 {
		t.Fatalf("200 cycles of 100 Mbps behind a 300ms remote queue and C_hat is still 0 "+
			"(state=%s util=%.4f R=%.0f Mbps) — the shaper is dead code", s.state, s.util, s.rate/1e6)
	}
	if cycles > 5 {
		t.Errorf("took %d cycles to start shaping, want <=5", cycles)
	}
	if s.rate > s.rateMax/10 {
		t.Errorf("R=%.1f Mbps still near R_max=%.0f — the queue was never pulled home", s.rate/1e6, s.rateMax/1e6)
	}

	// (b) 没有远端队列 -> 停在 R_max 是对的 (R_max 本来就不是约束), 但绝不能顺带
	// 冻结慢层, 也不能在 SEEK 和 R_max 之间来回抖。
	q := newTestShaper()
	q.rateMax = defaultRateMaxMbps * 1e6
	q.rate = q.rateMax
	q.setCHat(0)
	for i := 0; i < 30; i++ {
		q.step(load(3))
		if q.state != stShaperHold {
			t.Fatalf("cycle %d: state=%s — no remote queue means nothing to shape, R_max is the right park",
				i, q.state)
		}
	}
	if q.rate != q.rateMax {
		t.Errorf("R=%.1f Mbps want R_max=%.0f (shaping must be effectively off)", q.rate/1e6, q.rateMax/1e6)
	}
	if !q.slowLayerReady() {
		t.Errorf("slow layer frozen by an idle-parked shaper (holdStable=%d) — enabling --shaper must not disable the optimizer",
			q.holdStable)
	}
}

// REGRESSION (缺陷 4): goodput 被无条件当成容量观测锁存, 却没有任何可信度门 (deficit
// 有 deficitImplausible, goodput 一道都没有)。这台机器上大量出口是转发/隧道流量, 没有
// 本地 socket, Δbytes_acked 覆盖不了 Δshaper_sent。
// 实测: SEEK 在 R=200Mbps、util=1.0, 远端 300ms 触发 delayed, ss 只看得见 1.5Mbps 的
// acked -> 一拍之内 R 从 200Mbps 掉到 2Mbps 地板; 而看门狗判据是 goodput<1Mbps, 测到
// 的 1.5Mbps 恰好骑在门槛之上, 护栏永不触发。
func TestGoodputAccountingGapDoesNotLatchCapacity(t *testing.T) {
	s := newTestShaper()
	s.state = stShaperSeek
	s.rate = 200e6
	dt := shaperTick.Seconds()
	gap := shaperSample{
		dt:           dt,
		sentBytes:    uint64(200e6 * dt / 8), // 整形器满额放行 200 Mbps
		ackedBytes:   uint64(1.5e6 * dt / 8), // ss 只看得见 1.5 Mbps
		minRttMs:     160,
		srttMs:       460,
		queueDelayMs: 300,
		haveLink:     true,
	}

	s.step(gap)
	if s.state != stShaperHold {
		t.Fatalf("state=%s want HOLD (E_remote=300ms must stop the ramp)", s.state)
	}
	if s.cHat < 100e6 {
		t.Fatalf("C_hat=%.1f Mbps latched from a 1.5 Mbps accounting gap at R=200 Mbps", s.cHat/1e6)
	}
	if s.rate < 100e6 {
		t.Fatalf("R collapsed 200.0 -> %.1f Mbps in one cycle on an acked-side accounting gap", s.rate/1e6)
	}

	// 再跑 300 拍确认它不会慢慢走到地板 (原缺陷里它稳稳停在 2 Mbps)。
	minRate := s.rate
	for i := 0; i < 300; i++ {
		s.step(gap)
		if s.rate < minRate {
			minRate = s.rate
		}
	}
	if minRate <= 10*rateFloorBps {
		t.Errorf("R walked down to %.1f Mbps — the accounting gap is still being treated as capacity", minRate/1e6)
	}
}

// REGRESSION (缺陷 5): YIELD <-> SEEK 的极限环 (缺陷 3 和 4 的组合)。
// 低估的 goodput -> 看门狗 3 拍 -> YIELD(R=R_max) -> R_max 下队列排空 -> 3 拍恢复 ->
// SEEK -> 同一个低估 goodput 再次锁存 C_hat -> R 塌回地板 -> 队列又堆起来 -> 再响。
// 实测 240s 里 17 次 YIELD / 17 次 SEEK, 链路每 ~14 秒在 R_max 和 2 Mbps 之间来回一次。
// 断掉环的是缺陷 4 的修复; 这里另外验证复出门槛的指数退避 (反复 yield 必须涨代价)。
func TestNoYieldSeekLimitCycle(t *testing.T) {
	dt := shaperTick.Seconds()
	// 记账缺口: 无论 R 多少, ss 只看得见 0.9 Mbps (在看门狗门槛之下, 所以它会响)。
	// R 掉到 500 Mbps 以下时本机开始堆队列 —— 看门狗的"有需求"判据。
	load := func(s *shaper) shaperSample {
		sm := shaperSample{
			dt:           dt,
			sentBytes:    uint64(s.rate * dt / 8),
			ackedBytes:   uint64(0.9e6 * dt / 8),
			minRttMs:     160,
			srttMs:       460,
			queueDelayMs: 300,
			haveLink:     true,
		}
		if s.rate < 500e6 {
			sm.qlen, sm.backlogBytes = 8, 1<<20
		}
		return sm
	}

	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	yields, minRate := 0, s.rate
	for i := 0; i < 120; i++ { // 240s, 审查者用的同一个窗口
		before := s.state
		s.step(load(s))
		if before != stShaperYield && s.state == stShaperYield {
			yields++
		}
		if s.rate < minRate {
			minRate = s.rate
		}
	}
	if yields > 4 {
		t.Errorf("%d watchdog yields in 120 cycles (was 17) — the YIELD<->SEEK limit cycle is still there", yields)
	}
	if minRate <= 10*rateFloorBps {
		t.Errorf("R reached %.1f Mbps — the link still collapses to the floor between yields", minRate/1e6)
	}

	// 复出门槛的指数退避, 单独驱动一遍确认它真的翻倍。
	y := newTestShaper()
	y.setCHat(100e6)
	y.cHatRegime = 100e6
	y.rate = y.headroom * y.cHat
	dead := func() shaperSample {
		sm := sampleAt(y.rate, 1.0, 0, 5, 4096, 160, 900, 700)
		sm.ackedBytes = 0
		return sm
	}
	clean := func() shaperSample { return sampleAt(y.rate, 0.2, 0.01, 0, 0, 160, 165, 5) }
	for i := 0; i < watchdogCycles; i++ {
		y.step(dead())
	}
	if y.state != stShaperYield || y.recoverNeed != watchdogRecoverCycles {
		t.Fatalf("state=%s recoverNeed=%d want YIELD/%d on the first yield", y.state, y.recoverNeed, watchdogRecoverCycles)
	}
	for i := 0; i < watchdogRecoverCycles; i++ {
		y.step(clean())
	}
	if y.state != stShaperSeek {
		t.Fatalf("state=%s want SEEK after the first recovery", y.state)
	}
	y.state = stShaperHold // 回到巡航前再挨一次看门狗
	for i := 0; i < watchdogCycles; i++ {
		y.step(dead())
	}
	if y.recoverNeed != 2*watchdogRecoverCycles {
		t.Fatalf("recoverNeed=%d want %d — repeated yields must cost more", y.recoverNeed, 2*watchdogRecoverCycles)
	}
	for i := 0; i < watchdogRecoverCycles; i++ {
		y.step(clean())
	}
	if y.state != stShaperYield {
		t.Errorf("state=%s — %d clean cycles were enough again, the backoff is not applied",
			y.state, watchdogRecoverCycles)
	}
}

// REGRESSION (缺陷 6): 需求消失后 BACKOFF 拿冻结的 deficit 继续压 R。
// deficitEMA 只在 haveLink && sentBytes>0 时更新, BACKOFF 却无条件读它, 而且内部的
// 每拍下压没有 util/需求门 (HOLD->BACKOFF 的入口有, 内部没有)。
// 实测: 进 BACKOFF 后喂 60 拍完全零流量 -> R 95.00 -> 30.00 Mbps (地板),
// deficitEMA=0.200 冻结。零流量的 120 秒里, 依据是 120 秒前的陈旧读数。
// 看门狗帮不上忙: qlen==0 每拍把 watchdogN 清零。
func TestBackoffFreezesRateWithoutDemand(t *testing.T) {
	s := newTestShaper()
	s.setCHat(100e6)
	s.cHatRegime = 100e6
	s.rate = s.headroom * s.cHat
	for i := 0; i < shaperConfirmCycles; i++ {
		s.step(sampleAt(s.rate, 1.0, 0.20, 0, 0, 160, 165, 5))
	}
	if s.state != stShaperBackoff {
		t.Fatalf("state=%s want BACKOFF before the idle phase", s.state)
	}
	rIn := s.rate

	idle := shaperSample{ // 完全零流量: sentBytes=0 => deficit 不刷新
		dt:           shaperTick.Seconds(),
		minRttMs:     160,
		srttMs:       165,
		queueDelayMs: 5,
		haveLink:     true,
	}
	minRate := s.rate
	for i := 0; i < 60; i++ {
		s.step(idle)
		if s.rate < minRate {
			minRate = s.rate
		}
	}
	if minRate < rIn {
		t.Errorf("R fell %.1f -> %.1f Mbps over 120s of ZERO traffic, on a deficit measured before the traffic stopped",
			rIn/1e6, minRate/1e6)
	}
	if s.state == stShaperBackoff {
		t.Errorf("still in BACKOFF after 60 demand-free cycles — no exit when the evidence stops arriving")
	}
	if !nearly(s.deficitEMA, 0.20, 1e-9) {
		t.Errorf("deficitEMA=%.3f — it is SUPPOSED to stay frozen at 0.20 with no traffic; "+
			"that is exactly why acting on it is wrong", s.deficitEMA)
	}
}

// ---------------------------------------------------------------------------
// 自动选档 (target 默认覆盖全部连接)
// ---------------------------------------------------------------------------

// 有远端排队的档必须优先于字节量更大但没排队的档 —— 整形只对"有队列可搬回来"的
// 路径有意义, 对没排队的档限速纯粹是白扔带宽。
func TestPickBandPrefersQueuedOverBusier(t *testing.T) {
	got, band := pickBand(map[string]ssTargetStat{
		// 字节量大 10 倍, 但几乎不排队
		"lan": {socks: 40, acked: 10e9, minRttP50Ms: 0.5, queueDelayMs: 1},
		// 字节量小, 但远端排了 80ms
		"intercontinental": {socks: 4, acked: 1e9, minRttP50Ms: 160, queueDelayMs: 80},
	})
	if band != "intercontinental" {
		t.Fatalf("band=%q want intercontinental (queued beats busier)", band)
	}
	if got.minRttP50Ms != 160 {
		t.Errorf("minRttP50Ms=%.0f want 160 — 控制信号必须整组取自被选中的档", got.minRttP50Ms)
	}
}

// 都没排队时退回按字节选: R 这时会停在 R_max (不整形), 选谁都一样, 选字节大的
// 只是让 util 判据有个合理的分母。
func TestPickBandFallsBackToBytes(t *testing.T) {
	_, band := pickBand(map[string]ssTargetStat{
		"lan":              {socks: 40, acked: 10e9, minRttP50Ms: 0.5, queueDelayMs: 1},
		"intercontinental": {socks: 4, acked: 1e9, minRttP50Ms: 160, queueDelayMs: 2},
	})
	if band != "lan" {
		t.Fatalf("band=%q want lan (no queue anywhere -> busiest)", band)
	}
}

// 空档位不能被选中 (socks==0 的条目没有任何可用信号)。
func TestPickBandSkipsEmpty(t *testing.T) {
	_, band := pickBand(map[string]ssTargetStat{
		"far": {socks: 0, acked: 99e9, queueDelayMs: 999},
	})
	if band != "" {
		t.Fatalf("band=%q want empty — socks==0 的档没有可用信号", band)
	}
	if _, b := pickBand(nil); b != "" {
		t.Fatalf("band=%q want empty for nil map", b)
	}
}

// 分档聚合: 同一次 ss 输出里的本地与洲际 socket 必须落进不同的档, 各自算各自的
// 中位数。这是"对错误的总体做统计救不回来"那个教训的回归测试。
func TestSSBandsSeparatesLocalFromIntercontinental(t *testing.T) {
	rows := parseSSRows(`ESTAB 0 0 10.0.0.1:22 10.0.0.2:1
	 cubic rtt:0.05/0.03 minrtt:0.011 bytes_acked:500 segs_out:5
ESTAB 0 0 10.0.0.1:443 9.9.9.9:2
	 cubic rtt:180.5/7.7 minrtt:180 bytes_acked:900000 segs_out:900
ESTAB 0 0 10.0.0.1:443 9.9.9.8:3
	 cubic rtt:220.1/9.0 minrtt:214 bytes_acked:800000 segs_out:800`, 0)
	if len(rows) != 3 {
		t.Fatalf("rows=%d want 3", len(rows))
	}
	byBand := map[string][]ssRow{}
	for _, r := range rows {
		byBand[rttBand(r.minRtt)] = append(byBand[rttBand(r.minRtt)], r)
	}
	if n := len(byBand["lan"]); n != 1 {
		t.Errorf("lan rows=%d want 1", n)
	}
	if n := len(byBand["intercontinental"]); n != 2 {
		t.Errorf("intercontinental rows=%d want 2", n)
	}
	ic := aggregateRows(byBand["intercontinental"])
	if ic.minRttP50Ms < 180 || ic.minRttP50Ms > 214 {
		t.Errorf("minRttP50Ms=%.0f want within [180,214] — 档内中位数, 不含 0.011 的本地流",
			ic.minRttP50Ms)
	}
}
