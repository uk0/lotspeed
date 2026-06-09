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
//
// ChangedParam/Delta (B1 delta-credit): the optimizer probes ONE coordinate per
// cycle, so the score change is attributable to that single param, not the whole
// set. ChangedParam names it; Delta is sc-prevScore for it. Params is still the
// FULL config (the KNN planner needs the whole point), but UCB credit replays
// only ChangedParam. Legacy samples lack these fields (ChangedParam==""); UCB
// falls back to crediting the full set for those (see loadFromSamples).
type sample struct {
	Feature      linkFeature `json:"feature"`
	Params       paramSet    `json:"params"`
	Score        float64     `json:"score"`
	TS           int64       `json:"ts"`
	ChangedParam string      `json:"changed_param,omitempty"`
	Delta        float64     `json:"delta,omitempty"`
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
// Falls back to a heuristic plan if the model has no samples yet (cold start) or
// if too few in-regime neighbors survive the gate below.
func (m *model) predict(f linkFeature) paramSet {
	if len(m.Samples) == 0 {
		return heuristicPlan(f)
	}
	type ranked struct {
		s sample
		d float64
	}
	// Regime gate: multi-route links carry physically different paths (e.g. a
	// 13ms LAN regime vs a 264ms intercontinental regime). KNN across both
	// interpolates a config optimal for neither, so only samples whose RttMs is
	// within a factor of 2 of the query's (q/2 <= s <= q*2) participate. Within
	// the regime, only Score>0 samples contribute params — negative/bad-link
	// samples (RTT spikes, high loss) would otherwise drag the average toward
	// configs we know perform badly. Those samples remain in the model file for
	// UCB history; they're excluded from the planner average only.
	rs := make([]ranked, 0, len(m.Samples))
	for _, s := range m.Samples {
		if s.Score <= 0 {
			continue
		}
		if f.RttMs > 0 {
			if s.Feature.RttMs < f.RttMs/2 || s.Feature.RttMs > f.RttMs*2 {
				continue
			}
		}
		rs = append(rs, ranked{s, dist(f, s.Feature)})
	}
	// Too few in-regime neighbors to trust the average: fall back to the
	// heuristic plan (the caller — cmdTune / warm-start — gets a usable config).
	if len(rs) < 2 {
		return heuristicPlan(f)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].d < rs[j].d })
	k := 5
	if k > len(rs) {
		k = len(rs)
	}
	// score- and inverse-distance-weighted average per param. All survivors have
	// Score>0 (gated above), so the floor is unnecessary but kept harmless.
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
	// B6: cold-start loss_thresh. This is the single most impactful knob and was
	// previously never set on cold start (the optimizer tunes it but heuristicPlan
	// didn't emit it). Loss-aware seed: ambient loss below loss_thresh must not
	// trigger backoff or the CC degenerates to bbr behavior; +4 margin covers
	// measurement noise. f.LossPct is a fraction (0..1), so *100 -> percent.
	lossThresh := clampInt(int(math.Round(f.LossPct*100))+4, 4, 20)
	// Keep the high-RTT floor of 8 (single losses on >150ms paths are more often
	// transient reordering than congestion): take the max of the two heuristics.
	if f.RttMs > 150 {
		lossThresh = maxInt(lossThresh, 8)
	}
	// TODO(param-table): unify this output set with the optimizer's tun list
	// (optimizer.go newOptimizer) and cmdTune's writer — heuristicPlan still emits
	// min_cwnd/max_cwnd/hist_min_cwnd_bound that the optimizer doesn't tune, while
	// the optimizer tunes fast_alpha that heuristicPlan doesn't emit. One shared
	// param table would remove this skew. Out of scope for the delta-credit fix.
	return paramSet{
		"min_cwnd":            maxInt(64, bdpPkts/10),
		"max_cwnd":            minInt(15000, bdpPkts*2),
		"startup_gain":        startupGain,
		"hd_rho_max":          rhoMax,
		"hist_min_cwnd_bound": maxInt(64, bdpPkts/4),
		"loss_thresh":         lossThresh,
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// record appends a new (feature, params, score) sample and persists.
// Called by optimize after convergence. changedParam/delta carry the B1
// single-coordinate credit (empty/zero is fine — UCB then falls back to
// full-set crediting for this sample).
func (m *model) record(f linkFeature, p paramSet, score float64, changedParam string, delta float64) error {
	m.Samples = append(m.Samples, sample{
		Feature: f, Params: p, Score: score, TS: time.Now().Unix(),
		ChangedParam: changedParam, Delta: delta,
	})
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
			// Inspection replay. loss_thresh uses the CURRENT optimizer range
			// {2,24,2} so new samples bucket onto real arms. neoq_boost is kept
			// here (not in the optimizer's tun list anymore) only so legacy
			// samples that still carry it remain visible in `model show`.
			tuns := []tunable{
				{"startup_gain", "", 200, 400, 20, 0},
				{"fast_alpha", "", 4, 40, 4, 0},
				{"loss_thresh", "", 2, 24, 2, 0},
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
