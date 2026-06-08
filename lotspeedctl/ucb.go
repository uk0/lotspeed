package main

import (
	"fmt"
	"math"
	"sort"
)

// armStats tracks one (param_name, value) arm's history.
type armStats struct {
	value int
	mean  float64 // running mean of score
	count int     // pulls
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

// totalPulls returns total samples observed for a parameter (Σ count).
func (s *ucbSelector) totalPulls(name string) int {
	n := 0
	for _, a := range s.arms[name] {
		n += a.count
	}
	return n
}

// update folds a new observation (param=value got score=sc) into the arm's mean.
func (s *ucbSelector) update(name string, value int, sc float64) {
	for _, a := range s.arms[name] {
		if a.value == value {
			// incremental mean: μ_n = μ_{n-1} + (x - μ_{n-1})/n
			a.count++
			a.mean += (sc - a.mean) / float64(a.count)
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
			u = a.mean + s.c*math.Sqrt(math.Log(float64(total+1))/float64(a.count))
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
func (s *ucbSelector) loadFromSamples(samples []sample) {
	for _, smp := range samples {
		for name, v := range smp.Params {
			s.update(name, v, smp.Score)
		}
	}
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
