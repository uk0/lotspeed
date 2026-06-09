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
	codelRtt    float64 // EWMA RTT (ms) driving NeoQ CoDel target/interval
	smScore     float64 // EWMA-smoothed score — stable steering signal (抚平)
	bestKnown   float64 // best smoothed score seen — stability reference
	bestParams  []int   // tunable values at bestKnown — snap-back target (纠正)
	unstableN   int     // consecutive cycles below the stability floor
}

func newOptimizer(iface string, interval time.Duration) *optimizer {
	o := &optimizer{
		// beta=1.0 (goodput-accurate): the score measures wire throughput (iface
		// tx+rx, which includes retransmits). beta*loss discounts that by the
		// goodput actually lost to retransmission — no more. We do NOT punish
		// retransmits beyond their goodput cost: on a lossy intercontinental link
		// being aggressive (high retr) is the point, and the measured win is huge
		// (+186% vs bbr; bbr collapses to 2M on loss spikes, aggressive holds 36-87M).
		iface: iface, interval: interval, alpha: 0.5, beta: 1.0,
		dir: 1, phase: "EXPLORE", bestScore: -1e9,
		tun: []tunable{
			{"startup_gain", "", 200, 400, 20, 400},
			{"fast_alpha", "", 4, 40, 4, 30},
			// loss_thresh 2..30 default 20: aggressive loss tolerance — don't back
			// off on intercontinental loss. The goodput score (beta=1) lets the
			// optimizer settle where throughput actually peaks per-link.
			{"loss_thresh", "", 2, 30, 4, 20},
			// hd_rho_max kept high (250..400): full Hybla high-delay rho keeps
			// high-RTT cwnd ramping aggressively. (Was observed stuck at 0 = boost off.)
			{"hd_rho_max", "", 250, 400, 25, 400},
			// downstream window deception strength (NeoQ), part of the same system
			{"neoq_boost", "/proc/net/neoq_boost", 100, 400, 25, 100},
		},
	}
	// Start every tunable at its AGGRESSIVE default and push it to the kernel.
	// We deliberately do NOT adopt the live sysctl value: a fresh module load has
	// conservative kernel defaults (e.g. loss_thresh=2) and adopting those would
	// make the optimizer start timid. Starting at the aggressive default also
	// overwrites any stale/garbage value from a prior run. Per-link learned optima
	// are recovered via the model warm-start (explicit-target mode) and the
	// model.json the optimizer keeps growing.
	for i := range o.tun {
		o.apply(&o.tun[i])
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
	// C3: decaying reference. peakBw ratchets up on a new peak but decays
	// slowly otherwise, so a one-time lucky EXPLORE burst doesn't permanently
	// deflate every later score and make recorded samples incomparable over time.
	if m.bwMbps > o.peakBw {
		o.peakBw = m.bwMbps
	} else {
		o.peakBw *= 0.995 // ~12 min half-life at 5s cycles
	}
	if m.rttMs > 0 && (o.minRtt == 0 || m.rttMs < o.minRtt) {
		o.minRtt = m.rttMs
	} else if o.minRtt > 0 {
		o.minRtt *= 1.0005 // let the RTT floor drift up so the delay penalty isn't pinned on forever
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

// applyCodel maps the measured path RTT to NeoQ CoDel target/interval and pushes
// them via /proc/net/neoq_codel. The egress qdisc can't measure RTT itself (it
// never sees the returning ACKs), so the CLI — which knows RTT from ss — drives
// RTT-adaptive AQM. Without this NeoQ runs a flat 5ms target/100ms interval that
// over-drops on high-RTT links: interval < RTT means CoDel re-drops before a
// drop's cwnd reduction has propagated back, collapsing throughput.
// target = RTT/4 (standing queue tolerated), interval = 2*RTT (must exceed 1 RTT).
func applyCodel(rttMs float64) {
	if rttMs <= 0 {
		return
	}
	rttUs := rttMs * 1000
	target := clampF(rttUs/4, 5000, 60000)
	interval := clampF(rttUs*2, 100000, 600000)
	_ = os.WriteFile("/proc/net/neoq_codel",
		[]byte(fmt.Sprintf("%d %d", int(target), int(interval))), 0o644)
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
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
	// Aggressive intercontinental baseline (non-tunable knobs set once): remove the
	// cwnd ceiling, max out high-delay Hybla compensation, shrink safety margins,
	// extend STARTUP for high-RTT ramp. Verified +186% vs bbr on a lossy link.
	_ = writeSysctl("turbo_startup", "1")
	_ = writeSysctl("startup_gain", "400")
	_ = writeSysctl("startup_min_rounds", "8") // more STARTUP rounds for high RTT
	_ = writeSysctl("max_cwnd", "524288")      // K2: remove ceiling; 524288 pkts ≈ 760MB inflight, ample for 1.5Gbps even at very high RTT
	_ = writeSysctl("min_cwnd", "100")         // higher cwnd floor
	_ = writeSysctl("hd_cwnd_gain", "200")     // high-delay cwnd 2x
	_ = writeSysctl("hd_pacing_gain", "160")   // high-delay pacing 1.6x
	_ = writeSysctl("inflight_headroom", "5")  // smaller safety margin = more aggressive
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

		// N3: drive RTT-adaptive CoDel for NeoQ from the measured RTT (smoothed).
		if m.rttMs > 0 {
			if o.codelRtt == 0 {
				o.codelRtt = m.rttMs
			} else {
				o.codelRtt = 0.8*o.codelRtt + 0.2*m.rttMs
			}
			applyCodel(o.codelRtt)
		}

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
		// Always record (both explicit-target and PASSIVE mode). In PASSIVE
		// mode feat.Target is filled from the dominant peer at record time.
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
		// No-traffic guard: with little/no real traffic the score is pure noise,
		// so steering on it only thrashes params. Hold and wait for traffic.
		if m.bwMbps < 5 {
			fmt.Printf("%s OPT idle (bw=%.0fM<5, no signal) — holding params\n", ts, m.bwMbps)
			continue
		}
		// SMOOTH (抚平): EWMA the control signal so one noisy cycle (RTT/bw blip
		// on a jittery link) can't trigger a param change. Decisions use smScore.
		if o.smScore == 0 {
			o.smScore = sc
		} else {
			o.smScore = 0.6*o.smScore + 0.4*sc
		}
		// CORRECT (纠正, defensive): re-clamp every tunable into range each cycle so
		// no drift/garbage value (observed loss_thresh=224, hd_rho_max=1550) can
		// persist in memory or be re-applied to the kernel.
		for i := range o.tun {
			if c := clampInt(o.tun[i].cur, o.tun[i].min, o.tun[i].max); c != o.tun[i].cur {
				o.tun[i].cur = c
				o.apply(&o.tun[i])
			}
		}
		// Snapshot the best-known stable config (all params at the highest smScore).
		if o.bestParams == nil || o.smScore > o.bestKnown {
			o.bestKnown = o.smScore
			o.bestParams = make([]int, len(o.tun))
			for i := range o.tun {
				o.bestParams[i] = o.tun[i].cur
			}
		}
		// CORRECT+SMOOTH (纠正抚平): if smScore collapses well below best-known for
		// several consecutive cycles, the search wandered into an unstable region;
		// snap the WHOLE config back to the best-known-stable point.
		if o.bestKnown > 0 && o.smScore < 0.6*o.bestKnown {
			o.unstableN++
			if o.unstableN >= 3 {
				for i := range o.tun {
					o.tun[i].cur = o.bestParams[i]
					o.apply(&o.tun[i])
				}
				fmt.Printf("%s STABILIZE: smScore %.3f << best %.3f, reverted to best-known config\n",
					ts, o.smScore, o.bestKnown)
				o.unstableN, o.dir = 0, 1
				continue
			}
		} else {
			o.unstableN = 0
		}
		// Decay both references so a one-time high peak can't latch forever: if the
		// link's character permanently degrades, bestKnown drifts down to the new
		// achievable level and STABILIZE stops firing, letting exploration resume.
		o.bestScore *= 0.995
		o.bestKnown *= 0.999
		if o.smScore > o.bestScore {
			o.bestScore = o.smScore
		} else {
			// Revert last probe, CLAMPED so cur can never leave [min,max].
			t := &o.tun[o.ti]
			t.cur = clampInt(t.cur-o.dir*t.step, t.min, t.max)
			o.apply(t)
			o.dir = -o.dir
			if o.dir == 1 {
				o.ti = (o.ti + 1) % len(o.tun)
			}
		}
		// Next probe, clamped. If the step would leave the range, flip & advance.
		t := &o.tun[o.ti]
		nv := clampInt(t.cur+o.dir*t.step, t.min, t.max)
		if nv != t.cur {
			t.cur = nv
			o.apply(t)
		} else {
			o.dir = -o.dir
			o.ti = (o.ti + 1) % len(o.tun)
		}
		fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% sm=%.3f best=%.3f | next %s=%d\n",
			ts, m.bwMbps, m.rttMs, m.lossPct*100, o.smScore, o.bestScore, o.tun[o.ti].name, o.tun[o.ti].cur)
	}
}
