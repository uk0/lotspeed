package main

import (
	"os"
	"testing"
)

// A real-shaped neoq_ml line (kernel format: one space-separated key=value line,
// t0=Express..t3=Bulk, then retrans counters). Express has live traffic with a
// 4200us recent peak; Bulk has moved bytes; one bulk + two sparse flows.
const sampleNeoqLine = "qlen=12 mem=34816 flows=3 sparse_flows=2 bulk_flows=1 " +
	"t0_pkts=900 t0_bytes=72000 t0_drops=0 t0_marks=1 t0_avg_delay_us=120 t0_peak_delay_us=4200 " +
	"t1_pkts=10 t1_bytes=800 t1_drops=0 t1_marks=0 t1_avg_delay_us=50 t1_peak_delay_us=90 " +
	"t2_pkts=5 t2_bytes=400 t2_drops=0 t2_marks=0 t2_avg_delay_us=40 t2_peak_delay_us=80 " +
	"t3_pkts=5000 t3_bytes=7340032 t3_drops=12 t3_marks=3 t3_avg_delay_us=8000 t3_peak_delay_us=42000 " +
	"retrans_seen=44 retrans_protected=40"

// Parser: a real sample line must populate exactly the fields the tuner consumes.
func TestParseNeoqMLSampleLine(t *testing.T) {
	s, ok := parseNeoqML(sampleNeoqLine)
	if !ok {
		t.Fatal("parseNeoqML(sample) ok=false, want true")
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"qlen", s.qlen, 12},
		{"sparse_flows", s.sparseFlows, 2},
		{"bulk_flows", s.bulkFlows, 1},
		{"t0_pkts", s.t0Pkts, 900},
		{"t0_avg_delay_us", s.t0AvgDelayUs, 120},
		{"t0_peak_delay_us", s.t0PeakDelayUs, 4200},
		{"t3_bytes", s.t3Bytes, 7340032},
		{"retrans_seen", s.retransSeen, 44},
		{"retrans_protected", s.retransProtected, 40},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s=%d want %d", c.name, c.got, c.want)
		}
	}
}

// Parser: the kernel's all-zero line (no active qdisc instance) still parses ok
// (so the tuner needs no special-case for an idle-but-present file).
func TestParseNeoqMLZeroLine(t *testing.T) {
	zero := "qlen=0 mem=0 flows=0 sparse_flows=0 bulk_flows=0 " +
		"t0_pkts=0 t0_bytes=0 t0_drops=0 t0_marks=0 t0_avg_delay_us=0 t0_peak_delay_us=0 " +
		"retrans_seen=0 retrans_protected=0"
	s, ok := parseNeoqML(zero)
	if !ok {
		t.Fatal("zero line ok=false, want true (present file parses)")
	}
	if s.t0Pkts != 0 || s.bulkFlows != 0 || s.t0PeakDelayUs != 0 {
		t.Errorf("zero line not all-zero: %+v", s)
	}
}

// Parser: garbage / empty input yields ok=false (treated as "feature off").
func TestParseNeoqMLAbsence(t *testing.T) {
	for _, in := range []string{"", "   \n\t ", "not a kv line at all"} {
		if _, ok := parseNeoqML(in); ok {
			t.Errorf("parseNeoqML(%q) ok=true, want false", in)
		}
	}
}

// readNeoqML on a box without the qdisc (file missing) must return ok=false.
// /proc/net/neoq_ml does not exist on the test host (darwin/CI), so this also
// exercises the real read path.
func TestReadNeoqMLMissingFile(t *testing.T) {
	if _, err := os.Stat(neoqMLProc); err == nil {
		t.Skipf("%s unexpectedly present on this host; skip", neoqMLProc)
	}
	if _, ok := readNeoqML(); ok {
		t.Errorf("readNeoqML() ok=true with %s absent, want false", neoqMLProc)
	}
}

// Score: with gamma=0 (or stats unavailable / Express idle), the experience term
// must NOT change the score — byte-for-byte equal to the legacy formula. This is
// the backward-compat guarantee for boxes without the new qdisc.
func TestScoreGammaZeroEquivalence(t *testing.T) {
	// Two optimizers sharing identical refs; only gamma differs. peakBw/minRtt are
	// preset so score() is deterministic (no ratchet side effects between calls).
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}
	withDelay := base
	withDelay.nqOK = true
	withDelay.t0DeltaPkts = 1000 // well above the activity floor
	withDelay.t0PeakDelayUs = 4000

	// gamma=0: the penalty branch is disabled regardless of stats.
	o0 := newOptimizerForTest(0)
	s0a := o0.score(base)
	o0b := newOptimizerForTest(0)
	s0b := o0b.score(withDelay)
	if !almost(s0a, s0b) {
		t.Errorf("gamma=0: score changed by stats (%.6f vs %.6f) — must be legacy formula", s0a, s0b)
	}

	// gamma>0 but stats unavailable (nqOK=false): also unchanged from legacy.
	og := newOptimizerForTest(0.3)
	legacy := og.score(base)
	og2 := newOptimizerForTest(0.3)
	noStats := base
	noStats.nqOK = false
	noStats.t0PeakDelayUs = 9999
	noStatsScore := og2.score(noStats)
	if !almost(legacy, noStatsScore) {
		t.Errorf("gamma>0 but nqOK=false: penalty leaked (%.6f vs %.6f)", legacy, noStatsScore)
	}

	// gamma>0, stats available, but Express idle (delta pkts <= floor): unchanged.
	og3 := newOptimizerForTest(0.3)
	idle := base
	idle.nqOK = true
	idle.t0DeltaPkts = expressActivityFloorPkts // not strictly greater than floor
	idle.t0PeakDelayUs = 9999
	idleScore := og3.score(idle)
	if !almost(legacy, idleScore) {
		t.Errorf("gamma>0 but Express idle: penalty leaked (%.6f vs %.6f)", legacy, idleScore)
	}
}

// Score: with gamma>0, stats available, and live Express traffic, a Express-delay
// peak must subtract exactly gamma*clamp(peak/budget,0,2). Verify the magnitude
// and the clamp ceiling.
func TestScoreExperiencePenaltyActivates(t *testing.T) {
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}

	legacyO := newOptimizerForTest(0.3)
	legacy := legacyO.score(base)

	// Peak = half the budget -> penalty = gamma * 0.5 = 0.15.
	o := newOptimizerForTest(0.3)
	half := base
	half.nqOK = true
	half.t0DeltaPkts = 1000
	half.t0PeakDelayUs = expressDelayBudgetUs * 0.5
	got := o.score(half)
	if want := legacy - 0.3*0.5; !almost(got, want) {
		t.Errorf("half-budget penalty: score=%.6f want %.6f", got, want)
	}

	// Peak = 5x budget -> clamp caps the factor at 2.0 -> penalty = gamma*2.0 = 0.6.
	o2 := newOptimizerForTest(0.3)
	over := base
	over.nqOK = true
	over.t0DeltaPkts = 1000
	over.t0PeakDelayUs = expressDelayBudgetUs * 5
	got2 := o2.score(over)
	if want := legacy - 0.3*2.0; !almost(got2, want) {
		t.Errorf("clamped penalty: score=%.6f want %.6f", got2, want)
	}
}

// newOptimizerForTest builds an optimizer with fixed refs so score() is a pure
// function of the metrics (no ratchet drift between TestScore* calls). interval
// is irrelevant to score(); iface is unused.
func newOptimizerForTest(gamma float64) *optimizer {
	o := &optimizer{alpha: 0.5, beta: 1.0, gamma: gamma}
	o.peakBw = 100 // m.bwMbps==100 -> bw/peakBw==1 (no decay since not strictly greater)
	o.minRtt = 250 // m.rttMs==250 -> delay penalty 0
	return o
}

// Change 2: with a SHORT RTT ring (< jitterMinSamples) the jitter term must NOT
// fire — score() stays the throughput+delay+loss formula. This is the no-op
// guarantee for the warm-up cycles before the ring fills.
func TestScoreJitterShortRingNoOp(t *testing.T) {
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}
	legacy := newOptimizerForTest(0).score(base)

	o := newOptimizerForTest(0)
	o.rttRing = []float64{250, 260, 250} // len 3 < jitterMinSamples(4) -> no penalty
	got := o.score(base)
	if !almost(got, legacy) {
		t.Errorf("short ring leaked a jitter penalty: %.6f vs legacy %.6f", got, legacy)
	}
}

// Change 2: with a FULL ring the jitter penalty must equal exactly
// jitterDelta*clamp(MAD(ring)/rtt, 0, 1). Verify both the linear band and the
// clamp ceiling, and that a bad-link-style spike that was NEVER pushed (the ring
// holds only clean RTTs) is therefore absent from the MAD.
func TestScoreJitterPenaltyAndClamp(t *testing.T) {
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}

	// Linear band: clean ring, MAD=3 over rtt=250 -> ratio 0.012, penalty 0.2*0.012.
	clean := []float64{200, 210, 205, 215, 208, 212, 203, 209}
	legacyA := newOptimizerForTest(0).score(base)
	oa := newOptimizerForTest(0)
	oa.rttRing = append([]float64(nil), clean...)
	wantA := legacyA - jitterDelta*clampF(medianAbsDev(clean)/base.rttMs, 0, 1)
	if got := oa.score(base); !almost(got, wantA) {
		t.Errorf("linear jitter penalty: score=%.6f want %.6f (MAD=%.0f)", got, wantA, medianAbsDev(clean))
	}

	// Clamp ceiling: wide ring, MAD=300 >= rtt=250 -> ratio clamps to 1, penalty
	// exactly jitterDelta (0.2), no more.
	ceil := []float64{0, 100, 200, 300, 700, 800, 900, 1000}
	legacyB := newOptimizerForTest(0).score(base)
	ob := newOptimizerForTest(0)
	ob.rttRing = append([]float64(nil), ceil...)
	wantB := legacyB - jitterDelta*1.0
	if got := ob.score(base); !almost(got, wantB) {
		t.Errorf("clamped jitter penalty: score=%.6f want %.6f (MAD=%.0f, must cap at delta)", got, wantB, medianAbsDev(ceil))
	}
}

// Change 2 (ring hygiene): the bad-link skip is the caller's responsibility —
// score() only consumes whatever is in the ring, so the loop must keep weather
// spikes OUT of it. This test documents the contract: a ring of CLEAN samples has
// a small MAD; the same ring with a run of bad-link weather spikes (distinct large
// RTTs, as real weather produces) has a strictly larger MAD and thus a heavier
// jitter penalty. Skipping the push on bad-link cycles is therefore load-bearing —
// without it, link weather (which the bad-link gate already excludes from credit
// and decisions) would also inflate the variance penalty.
func TestJitterRingSkipBadLinkContract(t *testing.T) {
	clean := []float64{248, 250, 252, 249, 251, 250, 253, 247}
	cleanMAD := medianAbsDev(clean)
	// What the ring would hold if a sustained-weather run had been pushed instead
	// of skipped: four clean cycles displaced by four distinct bad-link RTTs.
	poisoned := []float64{248, 250, 252, 249, 800, 950, 1100, 1300}
	poisonedMAD := medianAbsDev(poisoned)
	if !(poisonedMAD > cleanMAD) {
		t.Fatalf("weather-poisoned ring MAD=%v not greater than clean MAD=%v — skip guard would be a no-op", poisonedMAD, cleanMAD)
	}
}

// C2: the four shaper keys parse, and shaperOK reports the COMPLETE set. The line
// below is the sample line plus the shaper block, as the shaper-capable module
// emits it.
func TestParseNeoqMLShaperKeys(t *testing.T) {
	line := sampleNeoqLine + " rate_kbps=95000 backlog=131072 shaper_sent=8388608 shaper_defer=17"
	s, ok := parseNeoqML(line)
	if !ok {
		t.Fatal("parseNeoqML ok=false")
	}
	if !s.shaperOK {
		t.Fatal("shaperOK=false with all four shaper keys present")
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"rate_kbps", s.rateKbps, 95000},
		{"backlog", s.backlog, 131072},
		{"shaper_sent", s.shaperSent, 8388608},
		{"shaper_defer", s.shaperDefer, 17},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s=%d want %d", c.name, c.got, c.want)
		}
	}
	// The pre-existing fields must be untouched by the additions.
	if s.qlen != 12 || s.t3Bytes != 7340032 || s.t0PeakDelayUs != 4200 {
		t.Errorf("shaper keys disturbed the legacy fields: %+v", s)
	}
}

// C2 backward compat: today's kernel emits NONE of the shaper keys. The line must
// still parse (ok=true, legacy fields intact) and shaperOK must be false so the
// whole fast loop stays disabled — behavior falls back to today's exactly.
func TestParseNeoqMLShaperAbsentIsCompatible(t *testing.T) {
	s, ok := parseNeoqML(sampleNeoqLine)
	if !ok {
		t.Fatal("legacy line stopped parsing after the shaper keys were added")
	}
	if s.shaperOK {
		t.Error("shaperOK=true on a line with no shaper keys")
	}
	if s.qlen != 12 || s.bulkFlows != 1 {
		t.Errorf("legacy parse changed: %+v", s)
	}
}

// C2 forward compat: a PARTIAL shaper key set (a half-upgraded module, or a future
// rename) must report shaperOK=false. A control law that can compute util but not
// deficit is more dangerous than one that is simply off.
func TestParseNeoqMLPartialShaperKeysDisableTheLoop(t *testing.T) {
	partials := []string{
		sampleNeoqLine + " rate_kbps=95000",
		sampleNeoqLine + " rate_kbps=95000 backlog=131072",
		sampleNeoqLine + " rate_kbps=95000 backlog=131072 shaper_sent=8388608",
		sampleNeoqLine + " backlog=0 shaper_sent=0 shaper_defer=0",
	}
	for i, in := range partials {
		s, ok := parseNeoqML(in)
		if !ok {
			t.Fatalf("partial %d: ok=false", i)
		}
		if s.shaperOK {
			t.Errorf("partial %d: shaperOK=true with an incomplete key set", i)
		}
	}
}

// An all-zero shaper block (shaping present but off) is a valid, complete reading:
// shaperOK must be true so the controller takes over rather than staying disabled.
func TestParseNeoqMLShaperZerosAreValid(t *testing.T) {
	s, ok := parseNeoqML(sampleNeoqLine + " rate_kbps=0 backlog=0 shaper_sent=0 shaper_defer=0")
	if !ok || !s.shaperOK {
		t.Errorf("zeroed shaper block: ok=%v shaperOK=%v want true/true", ok, s.shaperOK)
	}
}

// Change (C3): score() gains two variance penalties. With an EMPTY goodput ring and
// NO shaper both must be exact no-ops — the backward-compat guarantee for every box
// that doesn't run --shaper.
func TestScoreVarianceTermsNoOpByDefault(t *testing.T) {
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}
	legacy := newOptimizerForTest(0).score(base)

	o := newOptimizerForTest(0)
	o.bwRing = []float64{100, 120, 80} // len 3 < jitterMinSamples -> no penalty
	if got := o.score(base); !almost(got, legacy) {
		t.Errorf("short goodput ring leaked a penalty: %.6f vs %.6f", got, legacy)
	}
	// nil shaper -> rateCV reports not-ok -> no penalty.
	if o.sh != nil {
		t.Fatal("test optimizer unexpectedly has a shaper")
	}
}

// With a full ring the goodput-variance penalty is exactly
// goodputVarDelta*clamp(MAD/median, 0, 1), and the R-CV penalty is
// rateCVDelta*clamp(CV, 0, 1).
func TestScoreVarianceTerms(t *testing.T) {
	base := metrics{bwMbps: 100, rttMs: 250, lossPct: 0.02}
	ring := []float64{100, 104, 96, 102, 98, 103, 97, 101}

	legacy := newOptimizerForTest(0).score(base)
	o := newOptimizerForTest(0)
	o.bwRing = append([]float64(nil), ring...)
	want := legacy - goodputVarDelta*clampF(medianAbsDev(ring)/percentile(ring, 0.5), 0, 1)
	if got := o.score(base); !almost(got, want) {
		t.Errorf("goodput-variance penalty: score=%.6f want %.6f", got, want)
	}

	// Add a shaper whose R ring swings 50/150 -> CV 0.5.
	sh := &shaper{rRing: []float64{50e6, 150e6, 50e6, 150e6}}
	o2 := newOptimizerForTest(0)
	o2.bwRing = append([]float64(nil), ring...)
	o2.sh = sh
	want2 := want - rateCVDelta*0.5
	if got := o2.score(base); !almost(got, want2) {
		t.Errorf("R-CV penalty: score=%.6f want %.6f", got, want2)
	}
}
