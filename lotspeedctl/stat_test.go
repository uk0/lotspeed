package main

import "testing"

// medianAbsDev returns the median absolute deviation from the median — the jitter
// estimate over the RTT ring. It uses the package's no-interpolation percentile
// (idx = int(p*(n-1))), so the expected values below are computed against THAT,
// not a textbook interpolated median.
func TestMedianAbsDev(t *testing.T) {
	cases := []struct {
		name string
		xs   []float64
		want float64
	}{
		// Empty/degenerate: zero spread (jitter term becomes a no-op).
		{"empty", nil, 0},
		{"single", []float64{250}, 0},
		// Flat ring: no variance -> MAD 0.
		{"flat", []float64{250, 250, 250, 250}, 0},
		// median(sorted{200,203,205,208,209,210,212,215}) = element[int(0.5*7)=3] = 208.
		// |dev| = {8,2,3,7,0,4,5,1} -> sorted{0,1,2,3,4,5,7,8}, MAD = element[3] = 3.
		{"clean spread", []float64{200, 210, 205, 215, 208, 212, 203, 209}, 3},
	}
	for _, c := range cases {
		if got := medianAbsDev(c.xs); !almost(got, c.want) {
			t.Errorf("%s: medianAbsDev(%v)=%v want %v", c.name, c.xs, got, c.want)
		}
	}
}
