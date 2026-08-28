package main

import (
	"fmt"
	"math"
	"sort"
)

// armStats tracks one (param_name, value) arm's history.
type armStats struct {
	value int
	mean  float64 // running mean of CONDITIONED reward in [0,1] (see conditionReward)
	count int     // pulls (capped via effCount for the UCB bonus / recency)
}

// rewardScale maps a raw delta to the conditioned-reward band. B3: UCB1 assumes
// rewards in [0,1]; our raw signal is a SIGNED score delta (a probe step's effect)
// that can be tiny or, on link weather, large and negative. We squash it:
//
//	reward = 0.5 + clamp(delta/rewardScale, -0.5, +0.5)
//
// scale=0.5 means a +0.5 score gain saturates to reward 1.0 and a -0.5 loss to
// 0.0, with delta=0 (a neutral step) sitting at 0.5. 0.5 is roughly the span of a
// "clearly better/worse" coordinate step in this score's units (bw/peakBw minus
// penalties), so most informative steps land inside the linear band rather than
// pinned at an extreme.
const rewardScale = 0.5

// effCountCap bounds an arm's effective sample count (B3). UCB1's lifetime
// cumulative mean never forgets; on hour-scale link-regime changes that's wrong.
// Capping the effective count makes the incremental update behave like a moving
// average with window ~effCountCap, so old regimes decay out instead of latching.
const effCountCap = 25

// conditionReward squashes a raw signed delta into UCB1's expected [0,1] band.
func conditionReward(delta float64) float64 {
	r := delta / rewardScale
	if r > 0.5 {
		r = 0.5
	} else if r < -0.5 {
		r = -0.5
	}
	return 0.5 + r
}

// ucbSelector implements multi-armed bandit per tunable parameter:
// each parameter has discrete arms (its allowed values stepped from min..max),
// UCB1 picks the next arm balancing explore/exploit.
//
// Why per-parameter independent: full joint space (5 params × ~20 vals each)
// is ~3M arms — too sparse for any real sample budget. Independent assumes
// parameters are separable enough that learning each marginal is useful,
// which matches our coordinate-ascent empirical experience.
type ucbSelector struct {
	arms map[string][]*armStats // param name -> arms by value
	c    float64                // exploration constant (sqrt(2) is classic)
}

func newUCB(tuns []tunable, exploration float64) *ucbSelector {
	s := &ucbSelector{arms: make(map[string][]*armStats), c: exploration}
	for _, t := range tuns {
		var arms []*armStats
		for v := t.min; v <= t.max; v += t.step {
			arms = append(arms, &armStats{value: v})
		}
		s.arms[t.name] = arms
	}
	return s
}

// effCount returns an arm's count capped at effCountCap — the value used in the
// UCB exploration bonus so the bonus tracks the windowed (forgetting) mean rather
// than a lifetime count that would drive exploration to zero (B3).
func effCount(c int) int {
	if c > effCountCap {
		return effCountCap
	}
	return c
}

// totalPulls returns the sum of EFFECTIVE (capped) counts for a parameter, so
// the log(total) term in the UCB bonus stays bounded as regimes turn over.
func (s *ucbSelector) totalPulls(name string) int {
	n := 0
	for _, a := range s.arms[name] {
		n += effCount(a.count)
	}
	return n
}

// update folds a new observation into the arm's mean. `delta` is the RAW signed
// score change attributable to this param's step (B1); it is conditioned into
// [0,1] (B3) before folding. The effective count is capped at effCountCap so the
// mean acts as a moving average and forgets stale link regimes.
func (s *ucbSelector) update(name string, value int, delta float64) {
	r := conditionReward(delta)
	for _, a := range s.arms[name] {
		if a.value == value {
			a.count++
			n := a.count
			if n > effCountCap {
				n = effCountCap
			}
			// μ_n = μ_{n-1} + (r - μ_{n-1})/min(count, cap)
			a.mean += (r - a.mean) / float64(n)
			return
		}
	}
}

// suggest returns the UCB1-chosen next value for `name`.
// Untried arms get +∞ score so they're tried first (forced exploration).
func (s *ucbSelector) suggest(name string) int {
	arms := s.arms[name]
	if len(arms) == 0 {
		return 0
	}
	total := s.totalPulls(name)
	bestIdx, bestUCB := 0, math.Inf(-1)
	for i, a := range arms {
		var u float64
		if a.count == 0 {
			u = math.Inf(1)
		} else {
			// B3: use capped effective count so the bonus doesn't vanish as
			// lifetime pulls grow — keeps exploration alive across regime turns.
			u = a.mean + s.c*math.Sqrt(math.Log(float64(total+1))/float64(effCount(a.count)))
		}
		if u > bestUCB {
			bestUCB = u
			bestIdx = i
		}
	}
	return arms[bestIdx].value
}

// bestArm returns the highest-mean value (pure exploit, no exploration term).
// Used by `predict` and warm-start when the user wants the model's current best guess.
func (s *ucbSelector) bestArm(name string) (int, bool) {
	arms := s.arms[name]
	if len(arms) == 0 {
		return 0, false
	}
	bestIdx, bestMean := -1, math.Inf(-1)
	for i, a := range arms {
		if a.count > 0 && a.mean > bestMean {
			bestMean = a.mean
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		return 0, false
	}
	return arms[bestIdx].value, true
}

// loadFromSamples replays all model samples into the bandit so that
// a fresh process gets the benefit of prior runs' learning.
//
// B1 credit assignment:
//   - New samples carry ChangedParam (the one coordinate that moved) + Delta
//     (its score change). We credit ONLY that arm, with that delta — this is
//     what stops a scalar score from being smeared onto provably no-op params.
//   - Legacy samples predate those fields (ChangedParam==""): fall back to the
//     old behavior — credit every param in the set with the sample's absolute
//     Score. They stay loadable; their credit is just coarser.
//
// 返回实际回放的条数 (纪元过滤之后它可能远小于 len(samples))。
func (s *ucbSelector) loadFromSamples(samples []sample) int {
	n := 0
	for _, smp := range samples {
		// 参照系腐蚀纪元之前录的分数/delta 不可比 (见 modelEpochTS), 不回放。
		if smp.TS < modelEpochTS {
			continue
		}
		n++
		if smp.ChangedParam != "" {
			if v, ok := smp.Params[smp.ChangedParam]; ok {
				s.update(smp.ChangedParam, v, smp.Delta)
			}
			continue
		}
		for name, v := range smp.Params {
			s.update(name, v, smp.Score)
		}
	}
	return n
}

// effectSize returns (max arm mean - min arm mean, total raw pulls) over the
// arms of `name` that have at least one pull. B4 uses it to freeze a parameter
// whose best and worst values barely differ in conditioned-reward terms — i.e.
// the param has no measurable effect on the current link, so probing it wastes
// the exploration budget (this is how neoq_boost-style no-ops are caught
// generically rather than by hardcoding which param is inert).
func (s *ucbSelector) effectSize(name string) (spread float64, totalPulls int) {
	lo, hi := math.Inf(1), math.Inf(-1)
	seen := false
	for _, a := range s.arms[name] {
		totalPulls += a.count
		if a.count == 0 {
			continue
		}
		seen = true
		if a.mean < lo {
			lo = a.mean
		}
		if a.mean > hi {
			hi = a.mean
		}
	}
	if !seen {
		return 0, totalPulls
	}
	return hi - lo, totalPulls
}

// debug returns a sorted summary string for inspection (`lotspeedctl model show`).
func (s *ucbSelector) debug() []string {
	var names []string
	for n := range s.arms {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		var bestV int
		var bestM float64 = math.Inf(-1)
		total := 0
		for _, a := range s.arms[n] {
			total += a.count
			if a.count > 0 && a.mean > bestM {
				bestM = a.mean
				bestV = a.value
			}
		}
		if total > 0 {
			out = append(out, formatArm(n, bestV, bestM, total))
		}
	}
	return out
}

func formatArm(name string, bestV int, bestM float64, total int) string {
	return fmt.Sprintf("%-22s best=%-6d score=%6.3f pulls=%d", name, bestV, bestM, total)
}
