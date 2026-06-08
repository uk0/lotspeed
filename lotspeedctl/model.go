package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// paramSet is the writable subset of lotspeed sysctls the model tunes.
// Keys map to /proc/sys/net/ipv4/lotspeed/<key>.
type paramSet map[string]int

// sample is one (link, params, score) record.
type sample struct {
	Feature linkFeature `json:"feature"`
	Params  paramSet    `json:"params"`
	Score   float64     `json:"score"`
	TS      int64       `json:"ts"`
}

type model struct {
	Samples []sample `json:"samples"`
}

func modelPath() string {
	d, _ := os.UserHomeDir()
	return filepath.Join(d, ".lotspeedctl", "model.json")
}

func loadModel() *model {
	m := &model{}
	b, err := os.ReadFile(modelPath())
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, m)
	return m
}

func (m *model) save() error {
	p := modelPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// dist returns a normalized L2 distance between two link features.
// RTT and BW use log scale so 10ms vs 100ms ≈ 100ms vs 1000ms,
// preventing one dimension from dominating.
func dist(a, b linkFeature) float64 {
	logRtt := math.Log1p(a.RttMs) - math.Log1p(b.RttMs)
	logBw := math.Log1p(a.BwMbps) - math.Log1p(b.BwMbps)
	jit := (a.Jitter - b.Jitter) / 50 // 50ms = 1 unit
	loss := (a.LossPct - b.LossPct) * 20
	return math.Sqrt(logRtt*logRtt + logBw*logBw + jit*jit + loss*loss)
}

// predict returns score-weighted nearest-neighbor params for the given feature.
// Falls back to a heuristic plan if the model has no samples yet (cold start).
func (m *model) predict(f linkFeature) paramSet {
	if len(m.Samples) == 0 {
		return heuristicPlan(f)
	}
	type ranked struct {
		s sample
		d float64
	}
	rs := make([]ranked, len(m.Samples))
	for i, s := range m.Samples {
		rs[i] = ranked{s, dist(f, s.Feature)}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].d < rs[j].d })
	k := 5
	if k > len(rs) {
		k = len(rs)
	}
	// score- and inverse-distance-weighted average per param.
	out := paramSet{}
	wsum := map[string]float64{}
	for _, r := range rs[:k] {
		w := math.Max(0.01, r.s.Score) / (r.d + 0.1)
		for kk, vv := range r.s.Params {
			out[kk] += int(float64(vv) * w)
			wsum[kk] += w
		}
	}
	for kk := range out {
		if wsum[kk] > 0 {
			out[kk] = int(float64(out[kk]) / wsum[kk])
		}
	}
	return out
}

// heuristicPlan is the cold-start fallback when the model is empty.
// All formulas are BDP-driven, the only knob the user reasoned about above.
func heuristicPlan(f linkFeature) paramSet {
	bdpPkts := 0
	if f.BwMbps > 0 && f.RttMs > 0 {
		bdpPkts = int(f.BwMbps * 1e6 / 8 * f.RttMs / 1000 / 1460)
	}
	if bdpPkts < 64 {
		bdpPkts = 64
	}
	startupGain := 200
	switch {
	case f.RttMs >= 200:
		startupGain = 450
	case f.RttMs >= 50:
		startupGain = 350
	}
	rhoMax := 100 + int(f.RttMs)
	if rhoMax > 800 {
		rhoMax = 800
	}
	return paramSet{
		"min_cwnd":            maxInt(64, bdpPkts/10),
		"max_cwnd":            minInt(15000, bdpPkts*2),
		"startup_gain":        startupGain,
		"hd_rho_max":          rhoMax,
		"hist_min_cwnd_bound": maxInt(64, bdpPkts/4),
	}
}

func minInt(a, b int) int { if a < b { return a }; return b }
func maxInt(a, b int) int { if a > b { return a }; return b }

// record appends a new (feature, params, score) sample and persists.
// Called by optimize after convergence.
func (m *model) record(f linkFeature, p paramSet, score float64) error {
	m.Samples = append(m.Samples, sample{Feature: f, Params: p, Score: score, TS: time.Now().Unix()})
	// cap at 500 samples (FIFO) — keep model lightweight.
	if len(m.Samples) > 500 {
		m.Samples = m.Samples[len(m.Samples)-500:]
	}
	return m.save()
}

// cmdModel — inspect the on-disk model.
//
//	lotspeedctl model [show | clear]
func cmdModel(args []string) error {
	m := loadModel()
	if len(args) == 0 || args[0] == "show" {
		fmt.Printf("model at %s\nsamples: %d\n", modelPath(), len(m.Samples))
		for i, s := range m.Samples {
			fmt.Printf("  [%d] rtt=%.0fms bw=%.0fM loss=%.1f%% jitter=%.0fms score=%.3f params=%v\n",
				i, s.Feature.RttMs, s.Feature.BwMbps, s.Feature.LossPct*100, s.Feature.Jitter, s.Score, s.Params)
		}
		// Also replay all samples through a fresh UCB bandit and show per-param
		// best arm + sample count — this is what UCB learned across all sessions.
		if len(m.Samples) > 0 {
			tuns := []tunable{
				{"startup_gain", "", 200, 400, 20, 0},
				{"fast_alpha", "", 4, 40, 4, 0},
				{"loss_thresh", "", 2, 30, 4, 0},
				{"hd_rho_max", "", 250, 400, 25, 0},
				{"neoq_boost", "/proc/net/neoq_boost", 100, 400, 25, 0},
			}
			ucb := newUCB(tuns, 0)
			ucb.loadFromSamples(m.Samples)
			fmt.Println("UCB best arm per parameter (replayed from all samples):")
			for _, line := range ucb.debug() {
				fmt.Printf("  %s\n", line)
			}
		}
		return nil
	}
	if args[0] == "clear" {
		_ = os.Remove(modelPath())
		fmt.Println("model cleared")
		return nil
	}
	return fmt.Errorf("usage: model [show | clear]")
}
