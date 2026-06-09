package main

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// conditionReward must map raw signed deltas into [0,1] with delta=0 -> 0.5 and
// saturate at the +/-rewardScale*0.5 edges (B3).
func TestConditionReward(t *testing.T) {
	cases := []struct {
		delta, want float64
	}{
		{0, 0.5},
		{rewardScale * 0.5, 1.0},  // +0.25 -> 1.0 at scale 0.5
		{-rewardScale * 0.5, 0.0}, // -0.25 -> 0.0
		{10, 1.0},                 // saturates high
		{-10, 0.0},                // saturates low
	}
	for _, c := range cases {
		if got := conditionReward(c.delta); !almost(got, c.want) {
			t.Errorf("conditionReward(%v)=%v want %v", c.delta, got, c.want)
		}
		if got := conditionReward(c.delta); got < 0 || got > 1 {
			t.Errorf("conditionReward(%v)=%v out of [0,1]", c.delta, got)
		}
	}
}

// B1: a new-style sample (ChangedParam set) must credit ONLY that arm; the other
// params in the same set must stay untouched.
func TestLoadFromSamplesDeltaCreditOnlyChangedParam(t *testing.T) {
	tuns := []tunable{
		{"startup_gain", "", 200, 400, 20, 0},
		{"loss_thresh", "", 2, 16, 2, 0},
	}
	u := newUCB(tuns, 0)
	u.loadFromSamples([]sample{{
		Params:       paramSet{"startup_gain": 300, "loss_thresh": 4},
		Score:        0.9, // must be IGNORED for credit when ChangedParam is set
		ChangedParam: "loss_thresh",
		Delta:        rewardScale * 0.5, // -> conditioned reward 1.0
	}})

	// loss_thresh@4 got one pull with conditioned reward 1.0.
	if _, pulls := u.effectSize("loss_thresh"); pulls != 1 {
		t.Fatalf("loss_thresh pulls=%d want 1", pulls)
	}
	gotV, ok := u.bestArm("loss_thresh")
	if !ok || gotV != 4 {
		t.Fatalf("loss_thresh bestArm=%d ok=%v want 4", gotV, ok)
	}
	for _, a := range u.arms["loss_thresh"] {
		if a.value == 4 && !almost(a.mean, 1.0) {
			t.Errorf("loss_thresh@4 mean=%v want 1.0", a.mean)
		}
	}
	// startup_gain must have received NO credit (B1: no smearing).
	if _, pulls := u.effectSize("startup_gain"); pulls != 0 {
		t.Errorf("startup_gain pulls=%d want 0 (changed-param credit must not smear)", pulls)
	}
}

// Backwards-compat: a legacy sample (no ChangedParam) must fall back to crediting
// every param in the set with the absolute Score.
func TestLoadFromSamplesLegacyFallback(t *testing.T) {
	tuns := []tunable{
		{"startup_gain", "", 200, 400, 20, 0},
		{"loss_thresh", "", 2, 16, 2, 0},
	}
	u := newUCB(tuns, 0)
	u.loadFromSamples([]sample{{
		Params: paramSet{"startup_gain": 300, "loss_thresh": 4},
		Score:  0.2,
		// ChangedParam == "" -> legacy path
	}})
	if _, p1 := u.effectSize("startup_gain"); p1 != 1 {
		t.Errorf("legacy: startup_gain pulls=%d want 1", p1)
	}
	if _, p2 := u.effectSize("loss_thresh"); p2 != 1 {
		t.Errorf("legacy: loss_thresh pulls=%d want 1", p2)
	}
}

// B3: the arm mean must behave like a moving average — once past effCountCap a
// long run of a new reward pulls the mean toward it instead of being frozen by
// thousands of old observations.
func TestUpdateCappedMeanForgets(t *testing.T) {
	u := newUCB([]tunable{{"loss_thresh", "", 2, 16, 2, 0}}, 0)
	// Saturate @4 with reward 0 (delta well below -scale) many times.
	for i := 0; i < 200; i++ {
		u.update("loss_thresh", 4, -10)
	}
	var arm *armStats
	for _, a := range u.arms["loss_thresh"] {
		if a.value == 4 {
			arm = a
		}
	}
	if arm == nil {
		t.Fatal("arm @4 missing")
	}
	if !almost(arm.mean, 0.0) {
		t.Fatalf("after 200x reward 0, mean=%v want ~0", arm.mean)
	}
	// Now feed reward 1 (delta above +scale). With a true cumulative mean over 200
	// samples a single +1 would barely move it (<0.005). With the cap=25 window it
	// must move by ~1/25 = 0.04.
	u.update("loss_thresh", 4, 10)
	if arm.mean < 0.03 {
		t.Errorf("capped mean did not forget: moved to %v after one reward 1 (want >=~0.04)", arm.mean)
	}
}

// B4: effectSize is (max-min arm mean, total pulls) over pulled arms.
func TestEffectSize(t *testing.T) {
	u := newUCB([]tunable{{"loss_thresh", "", 2, 16, 2, 0}}, 0)
	// @2 -> high reward, @4 -> low reward.
	u.update("loss_thresh", 2, 10)  // reward 1.0
	u.update("loss_thresh", 4, -10) // reward 0.0
	spread, pulls := u.effectSize("loss_thresh")
	if pulls != 2 {
		t.Fatalf("pulls=%d want 2", pulls)
	}
	if !almost(spread, 1.0) {
		t.Errorf("spread=%v want 1.0", spread)
	}

	// An untouched param has zero spread and zero pulls (won't trip the freeze gate).
	u2 := newUCB([]tunable{{"hd_rho_max", "", 250, 400, 25, 0}}, 0)
	if s, p := u2.effectSize("hd_rho_max"); s != 0 || p != 0 {
		t.Errorf("untouched effectSize=(%v,%v) want (0,0)", s, p)
	}
}
