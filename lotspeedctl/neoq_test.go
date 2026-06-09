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
