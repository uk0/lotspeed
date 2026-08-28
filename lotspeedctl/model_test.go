package main

import (
	"os"
	"path/filepath"
	"testing"
)

// hist_min_cwnd_bound is emitted ONLY by heuristicPlan, never by optimizer
// samples — its presence in predict() output therefore means the heuristic
// fallback fired, its absence means the KNN average ran.
const fallbackMarker = "hist_min_cwnd_bound"

func didFallback(p paramSet) bool { _, ok := p[fallbackMarker]; return ok }

func knnSample(rttMs, score float64, lossThresh int) sample {
	return sample{
		Feature: linkFeature{RttMs: rttMs, BwMbps: 100},
		Params:  paramSet{"startup_gain": 400, "loss_thresh": lossThresh, "hd_rho_max": 400},
		Score:   score,
		TS:      modelEpochTS, // 本纪元的样本, 才会被 predict 的纪元门放行
	}
}

// Change 3a+3c: only same-regime (RttMs within 2x of the query) samples count;
// out-of-regime neighbors are ignored, and with <2 in-regime survivors predict
// falls back to heuristicPlan.
func TestPredictRegimeGate(t *testing.T) {
	m := &model{Samples: []sample{
		knnSample(13, 0.8, 4), // LAN regime — far from a 264ms query (264/2=132 > 13)
		knnSample(20, 0.8, 6), // LAN regime — also out of the high-RTT band
		knnSample(260, 0.8, 14),
		knnSample(264, 0.8, 16),
	}}
	// Query in the 264ms regime: only the two ~260ms samples are eligible.
	got := m.predict(linkFeature{RttMs: 264, BwMbps: 100})
	if didFallback(got) {
		t.Fatalf("expected KNN (2 in-regime neighbors), got heuristic fallback: %v", got)
	}
	// The averaged loss_thresh must come from the high-RTT samples (14,16 -> ~15),
	// NOT be pulled down toward the 13/20ms-regime values (4,6).
	if lt := got["loss_thresh"]; lt < 12 {
		t.Errorf("loss_thresh=%d pulled out of high-RTT regime (want ~15 from {14,16})", lt)
	}

	// A query in the LAN regime with only ONE in-regime sample (13ms; 20ms is
	// outside 13/2..13*2 = 6.5..26? 20 is inside) -> craft <2 explicitly.
	lan := &model{Samples: []sample{
		knnSample(13, 0.8, 4),   // in regime for a 13ms query
		knnSample(300, 0.8, 18), // far out of regime
	}}
	gotLan := lan.predict(linkFeature{RttMs: 13, BwMbps: 100})
	if !didFallback(gotLan) {
		t.Errorf("expected heuristic fallback with <2 in-regime neighbors, got KNN: %v", gotLan)
	}
}

// Change 3b: Score<=0 samples are excluded from the params average (they stay in
// the model for UCB history, but must not drag the planner toward bad configs).
func TestPredictExcludesNonPositiveScore(t *testing.T) {
	// Three same-regime samples: two good (loss_thresh 14,16) and one bad-link
	// (Score=-0.9, loss_thresh=2). If the bad one leaked into the average it would
	// pull loss_thresh down sharply.
	m := &model{Samples: []sample{
		knnSample(260, 0.8, 14),
		knnSample(264, 0.8, 16),
		knnSample(262, -0.9, 2), // bad-link: must be excluded from the average
	}}
	got := m.predict(linkFeature{RttMs: 262, BwMbps: 100})
	if didFallback(got) {
		t.Fatalf("expected KNN over the 2 positive samples, got fallback: %v", got)
	}
	if lt := got["loss_thresh"]; lt < 12 {
		t.Errorf("loss_thresh=%d — negative-score sample leaked into the average", lt)
	}

	// With only ONE positive in-regime sample left after the Score>0 filter,
	// predict must fall back (the negative one doesn't count toward the >=2 quorum).
	m2 := &model{Samples: []sample{
		knnSample(260, 0.8, 14),
		knnSample(262, -0.5, 2),
		knnSample(264, -0.7, 2),
	}}
	if got2 := m2.predict(linkFeature{RttMs: 262, BwMbps: 100}); !didFallback(got2) {
		t.Errorf("expected fallback with only 1 positive in-regime sample, got KNN: %v", got2)
	}
}

// Change 2: loss-aware cold start. heuristicPlan seeds loss_thresh from the
// ambient loss fraction: clamp(round(lossPct)+4, 4, 20), with a >150ms RTT floor
// of 8 (max of the two).
func TestHeuristicPlanLossAware(t *testing.T) {
	cases := []struct {
		name       string
		lossFrac   float64 // 0..1
		rttMs      float64
		wantThresh int
	}{
		{"10pct ambient high-RTT", 0.10, 264, 14},  // round(10)+4=14, floor8 -> 14
		{"clean low-RTT", 0.0, 30, 4},              // round(0)+4=4
		{"clean high-RTT floor", 0.0, 300, 8},      // 4 vs floor 8 -> 8
		{"5pct low-RTT", 0.05, 30, 9},              // round(5)+4=9
		{"saturate high loss", 0.30, 30, 20},       // round(30)+4=34 -> clamp 20
		{"3pct high-RTT floor wins", 0.03, 300, 8}, // round(3)+4=7 vs floor 8 -> 8
	}
	for _, c := range cases {
		p := heuristicPlan(linkFeature{LossPct: c.lossFrac, RttMs: c.rttMs, BwMbps: 100})
		if got := p["loss_thresh"]; got != c.wantThresh {
			t.Errorf("%s: loss_thresh=%d want %d", c.name, got, c.wantThresh)
		}
	}
}

// TestModelPathNeverRelative 钉住一条: modelPath 在任何环境下都必须是绝对路径。
//
// 回归来源: systemd 服务没有 User= 时 $HOME 未设, 旧实现 `d, _ := os.UserHomeDir()`
// 忽略错误后得到相对路径, 样本库于是落在 WorkingDirectory 下 (systemd 默认 /)。
// 服务写 /.lotspeedctl/model.json, 人读 ~/.lotspeedctl/model.json, 两边永远看不见
// 对方, 且不报错。
func TestModelPathNeverRelative(t *testing.T) {
	orig, had := os.LookupEnv("HOME")
	t.Cleanup(func() {
		if had {
			os.Setenv("HOME", orig)
		} else {
			os.Unsetenv("HOME")
		}
	})

	for _, tc := range []struct{ name, home string }{
		{"HOME 正常", "/root"},
		{"HOME 为空", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.home == "" {
				os.Unsetenv("HOME")
			} else {
				os.Setenv("HOME", tc.home)
			}
			p := modelPath()
			if !filepath.IsAbs(p) {
				t.Fatalf("modelPath()=%q 不是绝对路径 —— 样本库会跟着 cwd 走", p)
			}
		})
	}
}
