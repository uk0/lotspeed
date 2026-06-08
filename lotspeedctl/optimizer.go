package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type metrics struct {
	bwMbps  float64
	rttMs   float64
	lossPct float64 // 0..1
}

// tunable parameter with a safe range.
// path != "" => write that proc file directly (e.g. /proc/net/neoq_boost);
// path == "" => lotspeed sysctl by name.
type tunable struct {
	name                string
	path                string
	min, max, step, cur int
}

// optimizer keeps all state in memory across the loop.
type optimizer struct {
	iface       string
	interval    time.Duration
	alpha, beta float64 // delay & loss penalty weights
	tun         []tunable
	ti          int // current tunable index
	dir         int // probe direction +1/-1
	peakBw      float64
	minRtt      float64
	bestScore   float64
	phase       string
	exploreT    int
	prevBytes   uint64
	prevOut     uint64
	prevRetr    uint64
}

func newOptimizer(iface string, interval time.Duration) *optimizer {
	o := &optimizer{
		iface: iface, interval: interval, alpha: 0.5, beta: 5.0,
		dir: 1, phase: "EXPLORE", bestScore: -1e9,
		tun: []tunable{
			{"startup_gain", "", 200, 400, 20, 300},
			{"fast_alpha", "", 4, 40, 4, 20},
			{"loss_thresh", "", 2, 50, 4, 5},
			{"hd_rho_max", "", 150, 400, 25, 400},
			// downstream window deception strength (NeoQ), part of the same system
			{"neoq_boost", "/proc/net/neoq_boost", 100, 400, 25, 100},
		},
	}
	for i := range o.tun {
		var s string
		if o.tun[i].path != "" {
			if b, err := os.ReadFile(o.tun[i].path); err == nil {
				s = strings.TrimSpace(string(b))
			}
		} else if v, err := readSysctl(o.tun[i].name); err == nil {
			s = v
		}
		if n, err := strconv.Atoi(s); err == nil {
			o.tun[i].cur = n
		}
	}
	return o
}

// ifaceBytes returns tx+rx so downstream gains (from neoq_boost) are rewarded.
func ifaceBytes(iface string) uint64 {
	tb, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/tx_bytes")
	rb, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
	tx, _ := strconv.ParseUint(strings.TrimSpace(string(tb)), 10, 64)
	rx, _ := strconv.ParseUint(strings.TrimSpace(string(rb)), 10, 64)
	return tx + rx
}

// autoDetectPeer picks the IP with the most ESTABLISHED connections right now.
// Used in PASSIVE mode (no --target) so each sample is tagged with the actual
// dominant peer. Falls back to "auto" if no connections.
func autoDetectPeer() string {
	out, err := exec.Command("ss", "-tn", "state", "established").Output()
	if err != nil {
		return "auto"
	}
	counts := map[string]int{}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		peer := f[3]
		if i := strings.LastIndex(peer, ":"); i > 0 {
			peer = peer[:i]
		}
		peer = strings.TrimPrefix(peer, "[")
		peer = strings.TrimSuffix(peer, "]")
		if peer == "" || strings.HasPrefix(peer, "127.") || strings.HasPrefix(peer, "::1") {
			continue
		}
		counts[peer]++
	}
	best, bestN := "auto", 0
	for ip, n := range counts {
		if n > bestN {
			best, bestN = ip, n
		}
	}
	return best
}

// avgSrttMs averages srtt across established sockets (ss -ti).
func avgSrttMs() float64 {
	out, err := exec.Command("ss", "-ti", "state", "established").Output()
	if err != nil {
		return 0
	}
	var sum float64
	var n int
	for _, ln := range strings.Split(string(out), "\n") {
		k := strings.Index(ln, "rtt:")
		if k < 0 {
			continue
		}
		s := ln[k+4:]
		if j := strings.IndexAny(s, "/ "); j > 0 {
			s = s[:j]
		}
		if v, err := strconv.ParseFloat(s, 64); err == nil && v > 0 {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func (o *optimizer) measure() metrics {
	cur := ifaceBytes(o.iface)
	dbytes := cur - o.prevBytes
	o.prevBytes = cur
	out, retr := readSnmpTcp()
	dout, dretr := out-o.prevOut, retr-o.prevRetr
	o.prevOut, o.prevRetr = out, retr
	var loss float64
	if dout > 0 {
		loss = float64(dretr) / float64(dout)
	}
	bw := float64(dbytes) * 8 / o.interval.Seconds() / 1e6
	return metrics{bwMbps: bw, rttMs: avgSrttMs(), lossPct: loss}
}

// score = bw/peakBw - alpha*max(0, rtt/minRtt-1) - beta*loss
func (o *optimizer) score(m metrics) float64 {
	if m.bwMbps > o.peakBw {
		o.peakBw = m.bwMbps
	}
	if m.rttMs > 0 && (o.minRtt == 0 || m.rttMs < o.minRtt) {
		o.minRtt = m.rttMs
	}
	if o.peakBw <= 0 {
		return 0
	}
	s := m.bwMbps / o.peakBw
	if o.minRtt > 0 && m.rttMs > 0 {
		if r := m.rttMs/o.minRtt - 1; r > 0 {
			s -= o.alpha * r
		}
	}
	s -= o.beta * m.lossPct
	return s
}

func (o *optimizer) apply(t *tunable) {
	v := strconv.Itoa(t.cur)
	if t.path != "" {
		_ = os.WriteFile(t.path, []byte(v), 0o644)
	} else {
		_ = writeSysctl(t.name, v)
	}
}

// cmdOptimize runs the adaptive parameter search (upstream CC + downstream NeoQ boost).
//
//	lotspeedctl optimize --iface eth0 [--interval N]
func cmdOptimize(args []string) error {
	interval := 5 * time.Second
	iface := ""
	target := ""
	algo := "coord" // "coord" (coordinate ascent) | "ucb" (UCB1 bandit per param)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 < len(args) {
				if n, e := strconv.Atoi(args[i+1]); e == nil && n > 0 {
					interval = time.Duration(n) * time.Second
				}
				i++
			}
		case "--iface":
			if i+1 < len(args) {
				iface = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				target = args[i+1]
				i++
			}
		case "--algo":
			if i+1 < len(args) {
				algo = args[i+1]
				i++
			}
		}
	}
	if iface == "" {
		return fmt.Errorf("usage: optimize --iface <dev> [--interval N] [--target IP] [--algo coord|ucb]")
	}
	// Always record samples passively from whatever real traffic the kernel
	// is moving. --target is now purely informational — if set, it's stamped
	// onto sample.Feature.Target; if not, the dominant peer is detected from
	// `ss -tn` each cycle. This means systemd just runs `optimize --iface eth0`
	// with no human-supplied IP, and the model learns from production traffic.
	var feat linkFeature
	rttSamples := []float64{}
	bwSamples := []float64{}
	type windowBestT struct {
		score  float64
		params paramSet
		loss   float64
	}
	windowBest := windowBestT{score: -1e9}
	windowCycle := 0
	const recordEveryN = 5
	if target != "" {
		feat.Target = target
		fmt.Printf("optimize: explicit target=%s, model=%s\n", target, modelPath())
	} else {
		fmt.Printf("optimize: PASSIVE mode (peer auto-detected per cycle), model=%s\n", modelPath())
	}
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed (need root?): %w", err)
	}

	o := newOptimizer(iface, interval)
	// UCB bandit: pre-load it with all prior samples so a fresh process
	// inherits learning from previous runs (crucial for systemd auto-restart).
	var ucb *ucbSelector
	if algo == "ucb" {
		ucb = newUCB(o.tun, math.Sqrt(2))
		prior := loadModel()
		ucb.loadFromSamples(prior.Samples)
		fmt.Printf("UCB initialized from %d prior samples\n", len(prior.Samples))
	}
	// EXPLORE: aggressive grab to discover peak (up+down) throughput.
	_ = writeSysctl("turbo_startup", "1")
	_ = writeSysctl("startup_gain", "400")
	// Warm-start from the model if we have samples & a target. This is the
	// "use what you've learned" half of the data loop — without it the model
	// only grows but never repays the cost of growing it.
	if target != "" {
		mdl := loadModel()
		if len(mdl.Samples) > 0 {
			// Build a coarse feature from any prior sample with this target
			// so KNN distance has a reasonable starting point; predict fills the rest.
			var seed linkFeature
			seed.Target = target
			for _, s := range mdl.Samples {
				if s.Feature.Target == target {
					seed = s.Feature
					break
				}
			}
			pred := mdl.predict(seed)
			applied := 0
			for i := range o.tun {
				if v, ok := pred[o.tun[i].name]; ok && v >= o.tun[i].min && v <= o.tun[i].max {
					o.tun[i].cur = v
					o.apply(&o.tun[i])
					applied++
				}
			}
			fmt.Printf("warm-start from model (k=%d samples): %d params applied\n", len(mdl.Samples), applied)
		}
	}
	fmt.Printf("optimize: iface=%s interval=%v phase=EXPLORE (aggressive grab, tx+rx)\n", iface, interval)
	o.prevBytes = ifaceBytes(iface)
	o.prevOut, o.prevRetr = readSnmpTcp()

	for {
		time.Sleep(interval)
		m := o.measure()
		sc := o.score(m)
		ts := time.Now().Format("15:04:05")

		if o.phase == "EXPLORE" {
			o.exploreT++
			if (m.bwMbps >= o.peakBw*0.95 && o.exploreT >= 3) || o.exploreT >= 6 {
				o.phase = "OPTIMIZE"
				o.bestScore = sc
				fmt.Printf("%s -> OPTIMIZE (peakBw=%.0fMbps minRtt=%.1fms)\n", ts, o.peakBw, o.minRtt)
			}
			fmt.Printf("%s EXPLORE bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f\n", ts, m.bwMbps, m.rttMs, m.lossPct*100, sc)
			continue
		}

		// Live feature building: cap samples and use MAD-filtered medians so
		// occasional outliers don't poison what we persist to the model.
		if m.rttMs > 0 {
			rttSamples = append(rttSamples, m.rttMs)
			if len(rttSamples) > 20 {
				rttSamples = rttSamples[1:]
			}
		}
		if m.bwMbps > 0 {
			bwSamples = append(bwSamples, m.bwMbps)
			if len(bwSamples) > 20 {
				bwSamples = bwSamples[1:]
			}
		}
		// Window-best sampling: every recordEveryN OPT cycles, persist the
		// best-scoring (params, score) seen in that window. This guarantees
		// the model keeps growing even when EXPLORE captured the global best
		// and no later step exceeds it.
		if target != "" {
			if sc > windowBest.score {
				windowBest.score = sc
				windowBest.params = paramSet{}
				for i := range o.tun {
					windowBest.params[o.tun[i].name] = o.tun[i].cur
				}
				windowBest.loss = m.lossPct
			}
			windowCycle++
			if windowCycle >= recordEveryN && len(rttSamples) >= 3 && len(bwSamples) >= 3 && windowBest.params != nil {
				clean := madFilter(rttSamples, 3.0)
				feat.RttMs = percentile(clean, 0.5)
				feat.RttMin = percentile(clean, 0.1)
				feat.Jitter = percentile(clean, 0.9) - feat.RttMin
				feat.BwMbps = trimmedMean(bwSamples, 0.2)
				feat.LossPct = windowBest.loss
				if target == "" {
					feat.Target = autoDetectPeer() // who's the dominant peer right now?
				}
				// Sanity gate: only filter samples with no real traffic (bw<5M).
				// Negative-score samples ARE valuable — they teach UCB which
				// params to avoid on bad-link states (high loss / RTT spike).
				if feat.BwMbps < 5 {
					fmt.Printf("    -> sample SKIPPED (no real traffic: bw=%.0fM)\n", feat.BwMbps)
				} else if err := loadModel().record(feat, windowBest.params, windowBest.score); err == nil {
					tag := "good"
					if windowBest.score < 0 {
						tag = "BAD-LINK"
					}
					fmt.Printf("    -> sample recorded [%s] (model now has %d, score=%.3f, bw=%.0fM loss=%.1f%%)\n",
						tag, len(loadModel().Samples), windowBest.score, feat.BwMbps, feat.LossPct*100)
				}
				windowCycle = 0
				windowBest = windowBestT{score: -1e9}
			}
		}
		// Feed the bandit too (regardless of which algo currently steers,
		// so we can A/B compare later without losing data).
		if ucb != nil {
			for i := range o.tun {
				ucb.update(o.tun[i].name, o.tun[i].cur, sc)
			}
		}
		// UCB mode: each cycle pick a fresh value per parameter (rotate which
		// param we update so coordinated effects stay observable).
		if algo == "ucb" && ucb != nil {
			t := &o.tun[o.ti]
			next := ucb.suggest(t.name)
			t.cur = next
			o.apply(t)
			o.ti = (o.ti + 1) % len(o.tun)
			fmt.Printf("%s UCB bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f | %s -> %d (suggest)\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, sc, t.name, next)
			continue
		}
		// OPTIMIZE: coordinate ascent with revert-on-regression.
		if sc > o.bestScore {
			o.bestScore = sc
		} else {
			t := &o.tun[o.ti]
			t.cur -= o.dir * t.step
			o.apply(t)
			o.dir = -o.dir
			if o.dir == 1 {
				o.ti = (o.ti + 1) % len(o.tun)
			}
		}
		t := &o.tun[o.ti]
		nv := t.cur + o.dir*t.step
		if nv >= t.min && nv <= t.max {
			t.cur = nv
			o.apply(t)
		} else {
			o.dir = -o.dir
			o.ti = (o.ti + 1) % len(o.tun)
		}
		fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f best=%.3f | next %s=%d\n",
			ts, m.bwMbps, m.rttMs, m.lossPct*100, sc, o.bestScore, o.tun[o.ti].name, o.tun[o.ti].cur)
	}
}
