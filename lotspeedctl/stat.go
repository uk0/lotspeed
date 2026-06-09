package main

import "sort"

// trimmedMean drops the lowest and highest `trim` fraction of samples
// (e.g. trim=0.1 drops top/bottom 10%) then averages — robust to outliers.
func trimmedMean(xs []float64, trim float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	k := int(float64(len(s)) * trim)
	if 2*k >= len(s) {
		k = 0
	}
	sum := 0.0
	for _, v := range s[k : len(s)-k] {
		sum += v
	}
	return sum / float64(len(s)-2*k)
}

// percentile returns the p-th percentile (0..1) of xs.
func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(p * float64(len(s)-1))
	if idx < 0 {
		idx = 0
	} else if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// medianAbsDev returns the median absolute deviation from the median (MAD) — the
// same robust spread madFilter computes internally, but returned as a value rather
// than used as a filter cutoff. Used as the jitter estimate over the RTT ring.
func medianAbsDev(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	med := percentile(xs, 0.5)
	devs := make([]float64, len(xs))
	for i, v := range xs {
		d := v - med
		if d < 0 {
			d = -d
		}
		devs[i] = d
	}
	return percentile(devs, 0.5)
}

// madFilter keeps samples within k*MAD of the median (default k=3 — Hampel filter).
// MAD = median absolute deviation. Tolerates up to 50% outliers, unlike stddev.
func madFilter(xs []float64, k float64) []float64 {
	if len(xs) < 3 {
		return xs
	}
	med := percentile(xs, 0.5)
	devs := make([]float64, len(xs))
	for i, v := range xs {
		d := v - med
		if d < 0 {
			d = -d
		}
		devs[i] = d
	}
	mad := percentile(devs, 0.5)
	if mad == 0 {
		return xs
	}
	out := xs[:0:0]
	for _, v := range xs {
		d := v - med
		if d < 0 {
			d = -d
		}
		if d <= k*mad {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return xs
	}
	return out
}
