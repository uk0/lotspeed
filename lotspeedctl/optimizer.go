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

	// NeoQ experience signals, sampled in the SAME measure() window as bw/rtt/loss
	// so all signals share one observation window. nqOK=false when the new sch_neoq
	// qdisc isn't loaded (/proc/net/neoq_ml missing) — then the experience term is
	// skipped and score() is exactly the legacy formula (backward compat).
	nqOK           bool
	t0PeakDelayUs  float64 // Express recent-peak delay (reset-on-read) — experience signal
	t0DeltaPkts    uint64  // Express pkts THIS window (from a t0_pkts delta) — activity gate
	t3GoodputDelta uint64  // Bulk bytes THIS window (from a t3_bytes delta)
	bulkFlows      uint64  // concurrent bulk flows (mixed-workload gate for neoq_sparse_thresh)
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
	gamma       float64 // Express-delay (experience) penalty weight; 0 => term off
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
	prevT0Pkts  uint64  // NeoQ: cumulative Express pkts at last measure() (for delta)
	prevT3Bytes uint64  // NeoQ: cumulative Bulk bytes at last measure() (for delta)
	nqPrimed    bool    // NeoQ: prev*T0/T3 counters baselined (skip first-cycle bogus delta)
	codelRtt    float64 // EWMA RTT (ms) driving NeoQ CoDel target/interval

	// rttRing holds the last jitterRingLen per-cycle RTT samples (ms). Its MAD is
	// the jitter signal in score(). Only CLEAN cycles push here — bad-link cycles
	// (RTT spikes flagged by the link-weather gate) are skipped so a weather blip
	// can't poison the variance estimate (see the measure-site push in the loop).
	rttRing []float64

	smScore    float64 // EWMA-smoothed score — stable steering signal (抚平)
	bestKnown  float64 // best smoothed score seen — stability reference
	bestParams []int   // tunable values at bestKnown — snap-back target (纠正)
	unstableN  int     // consecutive cycles below the stability floor

	// B1 delta-credit: the index/value/score of the coordinate probed LAST cycle,
	// so this cycle's score can be differenced against it and credited to that one
	// arm only. probedTi<0 means "no probe outstanding" (first OPT cycle).
	probedTi  int
	probedVal int
	prevScore float64 // score under the config BEFORE the outstanding probe
	havePrev  bool

	// B2 sequential decision smoothing: a coordinate step is only accepted/reverted
	// once two consecutive cycles agree on its sign, to keep one noisy cycle from
	// committing a move. pendingSign is the sign seen last cycle for the probed param.
	pendingSign int

	// B4 effect-size freeze: params whose best/worst arm means barely differ are
	// frozen (skipped when advancing o.ti). Unfrozen on a minRtt regime shift.
	frozen       map[string]bool
	freezeMinRtt float64 // minRtt at the time the last freeze was decided

	// mixedWorkload (re-evaluated each OPT cycle from the live NeoQ stats) gates
	// which params nextTi may select. NeoQ-only params (neoq_sparse_thresh) are a
	// no-op unless the workload is genuinely mixed (bulk_flows>=1 AND Express active),
	// so on single-flow/idle traffic we skip them in the rotation rather than let
	// them absorb exploration credit — the neoq_boost lesson. Unlike frozen this is
	// transient: re-checked every cycle, never persisted.
	mixedWorkload bool
}

// neoqOnly reports whether a tunable only makes sense under a mixed (bulk +
// interactive) workload. Such params are skipped in the probe rotation when the
// current cycle isn't mixed (see nextTi). neoq_sparse_thresh demotes a flow from
// the Express-eligible sparse class to bulk once it exceeds the byte threshold —
// pure no-op when there's at most one flow or no Express traffic to protect.
func (t *tunable) neoqOnly() bool { return t.name == "neoq_sparse_thresh" }

// Experience-term constants (NeoQ Express-delay penalty).
const (
	// expressDelayBudgetUs is the Express (t0) recent-peak delay we treat as "fully
	// spent". Express measures ~1-5us under pure bulk load today, so any sustained
	// climb toward ms-scale means interactive traffic is queuing behind bulk. 5ms.
	expressDelayBudgetUs = 5000.0
	// expressActivityFloorPkts is the minimum Express pkts in a window for the delay
	// reading to be trusted. Below it the tier is essentially idle and a stray peak
	// is noise, not experience — so we neither score nor probe-gate on it (~50 pkts).
	expressActivityFloorPkts = 50
	// defaultGamma weights the Express-delay penalty in score(). 0 disables the term.
	defaultGamma = 0.3
	// jitterRingLen is how many recent per-cycle RTTs the optimizer keeps to
	// estimate jitter (MAD of the ring). 8 cycles is enough for a stable MAD
	// without lagging a genuine regime change too long.
	jitterRingLen = 8
	// jitterMinSamples is the minimum ring occupancy before the jitter penalty is
	// applied; below it the MAD is too noisy to trust and score() stays the
	// throughput+delay+loss formula (so an empty/short ring is a no-op).
	jitterMinSamples = 4
	// jitterDelta weights the jitter penalty in score(). The term subtracts
	// jitterDelta*clamp(jitterMs/rttMs, 0, 1): on a 250ms intercontinental path a
	// jitter/rtt ratio above ~0.1 already degrades interactive feel, so penalizing
	// RTT variance steers the search away from parameter sets that win mean
	// throughput by causing RTT oscillation (e.g. overly aggressive probing).
	// Hardcoded (no flag) to stay surgical; the gamma flag precedent exists if a
	// knob is wanted later.
	jitterDelta = 0.2
)

func newOptimizer(iface string, interval time.Duration, gamma float64) *optimizer {
	o := &optimizer{
		// beta=1.0 (goodput-accurate): the score measures wire throughput (iface
		// tx+rx, which includes retransmits). beta*loss discounts that by the
		// goodput actually lost to retransmission — no more. We do NOT punish
		// retransmits beyond their goodput cost: on a lossy intercontinental link
		// being aggressive (high retr) is the point, and the measured win is huge
		// (+186% vs bbr; bbr collapses to 2M on loss spikes, aggressive holds 36-87M).
		iface: iface, interval: interval, alpha: 0.5, beta: 1.0, gamma: gamma,
		dir: 1, phase: "EXPLORE", bestScore: -1e9,
		probedTi: -1, frozen: map[string]bool{},
		tun: []tunable{
			{"startup_gain", "", 200, 400, 20, 400},
			{"fast_alpha", "", 4, 40, 4, 30},
			// loss_thresh 2..24 default 4: on a ~10%-ambient-loss link the per-link
			// optimum sits ~12-16 and was pressing the old max=16 ceiling, so the
			// range is widened to 24 (lt=30 still caused retrans storms; 24 gives
			// headroom above the 10%-ambient optimum without reaching that zone).
			// Start tight (4) — the per-link optimum is found by stepping up.
			{"loss_thresh", "", 2, 24, 2, 4},
			// hd_rho_max kept high (250..400): full Hybla high-delay rho keeps
			// high-RTT cwnd ramping aggressively. (Was observed stuck at 0 = boost off.)
			{"hd_rho_max", "", 250, 400, 25, 400},
			// neoq_sparse_thresh: CAKE-style sparse-gate byte threshold per 100ms
			// window; the window stays fixed at 100000us. A flow under this many
			// bytes/window stays "sparse" (Express-eligible); above it it's demoted to
			// bulk. Written as "100000 <bytes>" (see apply()). bytes/100ms map to a
			// rate as bytes*8/0.1/1e6 Mbps = bytes*80/1e6, so the 6 stepped arms
			// {3028,27112,51196,75280,99364,123448} cover {0.24, 2.2, 4.1, 6.0, 7.9,
			// 9.9} Mbps. RANGE RATIONALE: the real sparse/bulk boundary is between a
			// "web page burst" (a 2MB page loading at 5-20 Mbps for 1-2s — must stay
			// Express/fast) and a "sustained download" (50+ Mbps for minutes — must
			// demote to Bulk), which sits in the 1-10 Mbps band. The old max of
			// 12112B/100ms (~0.97 Mbps) topped out an order of magnitude below that
			// boundary, so the optimizer could never explore where the answer lives.
			// (max-min) is an exact multiple of step (120420/24084=5) so the top arm
			// lands exactly at 123448. cur=3028 = 2*MTU = the kernel default
			// (conservative start). ANTI-NOISE: this arm is only SELECTED for probing
			// when the cycle shows a genuinely mixed workload (see nextTi +
			// mixedWorkload) — on single-flow/idle traffic it's a no-op and would
			// otherwise absorb exploration credit (the neoq_boost lesson).
			{"neoq_sparse_thresh", neoqSparseProc, 3028, 123448, 24084, 3028},
			// NOTE: neoq_boost was REMOVED from the tun list (B4) — it is a no-op on
			// single-flow traffic (it only reshapes the downstream rwnd across
			// concurrent flows) so probing it (~28% of the old exploration budget)
			// just added noise. The sysctl/proc writer (cmdBoost in prio.go,
			// neoqBoostProc) is kept; reintroduce this arm here if/when a
			// multi-flow optimization mode is added.
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
	m := metrics{bwMbps: bw, rttMs: avgSrttMs(), lossPct: loss}
	// NeoQ experience signals, sampled in this same window so they line up with
	// bw/rtt/loss. Absent file (qdisc not loaded) => nqOK stays false and score()
	// falls back to the legacy formula. t0_pkts/t3_bytes are cumulative — diff them
	// against the previous reading exactly like the iface byte counters above. The
	// first primed cycle's delta is suppressed (counters could predate this run).
	if nq, ok := readNeoqML(); ok {
		m.nqOK = true
		m.t0PeakDelayUs = float64(nq.t0PeakDelayUs)
		m.bulkFlows = nq.bulkFlows
		if o.nqPrimed {
			m.t0DeltaPkts = nq.t0Pkts - o.prevT0Pkts
			m.t3GoodputDelta = nq.t3Bytes - o.prevT3Bytes
		}
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq.t0Pkts, nq.t3Bytes, true
	}
	return m
}

// score = bw/peakBw - alpha*max(0, rtt/minRtt-1) - beta*loss
//
//	[ - gamma*clamp(t0_peak_delay_us/expressDelayBudgetUs, 0, 2.0) ]
//
// The bracketed Express-delay (experience) term is added ONLY when the NeoQ stats
// are available (nqOK) AND there was meaningful Express traffic this cycle
// (t0DeltaPkts > expressActivityFloorPkts). Without those — i.e. on a box with no
// new qdisc, or an idle Express tier — the score is EXACTLY the legacy formula, so
// gamma=0 (or stats-off) reproduces the prior behavior bit-for-bit.
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
	// Experience term: penalize Express (interactive/ACK/retransmit) queuing delay.
	// Gated on stats availability + real Express activity so it never fires on a box
	// without the new qdisc or on an idle tier (where a stray peak is just noise).
	if o.gamma > 0 && m.nqOK && m.t0DeltaPkts > expressActivityFloorPkts {
		s -= o.gamma * clampF(m.t0PeakDelayUs/expressDelayBudgetUs, 0, 2.0)
	}
	// Jitter term: penalize RTT variance (network quality = throughput + delay +
	// variance). jitter = MAD of the recent-RTT ring; the penalty is
	// jitterDelta*clamp(jitter/rtt, 0, 1). Gated on a sufficiently full ring (so a
	// short/empty ring is a no-op and score() stays the legacy formula) and rtt>0.
	// The ring is fed only on clean cycles (bad-link cycles are skipped at the push
	// site), so a weather spike can't inflate the MAD.
	if len(o.rttRing) >= jitterMinSamples && m.rttMs > 0 {
		jitterMs := medianAbsDev(o.rttRing)
		s -= jitterDelta * clampF(jitterMs/m.rttMs, 0, 1)
	}
	return s
}

func (o *optimizer) apply(t *tunable) {
	v := strconv.Itoa(t.cur)
	switch {
	case t.path == neoqSparseProc:
		// Sparse gate expects "<window_us> <thresh_bytes>" (kernel sscanf "%u %u").
		// Window is held fixed at 100000us; t.cur is the byte threshold.
		_ = os.WriteFile(t.path, []byte("100000 "+v), 0o644)
	case t.path != "":
		_ = os.WriteFile(t.path, []byte(v), 0o644)
	default:
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

// settle waits out the transient after a config change, then re-baselines the
// byte/segment counters so the NEXT measure() window covers only steady state
// (B5). Without this the window straddles the old config's tail and the new
// config's ramp-up, so the score is a blend of two configs and can't be
// attributed to the change. settle = clamp(8*RTT, 2s, 5s): 8 RTTs is enough for
// a cwnd/pacing change to propagate and re-stabilize, floored at 2s (so it's
// never shorter than a couple of measurement granularities) and capped at 5s (so
// a very high-RTT link doesn't stall the loop). rttMs<=0 falls back to the floor.
func (o *optimizer) settle(rttMs float64) {
	d := 2 * time.Second
	if rttMs > 0 {
		d = clampDur(time.Duration(8*rttMs)*time.Millisecond, 2*time.Second, 5*time.Second)
	}
	time.Sleep(d)
	o.prevBytes = ifaceBytes(o.iface)
	o.prevOut, o.prevRetr = readSnmpTcp()
	// Re-baseline the NeoQ cumulative counters too, so the next measure() window's
	// t0_pkts/t3_bytes deltas cover only steady state (consistent with the iface/snmp
	// re-baseline above). This read also resets the kernel's reset-on-read Express
	// peak, so the peak the next measure() sees is the settled window's, not the
	// config-change transient's. Harmless no-op when the qdisc isn't loaded.
	if nq, ok := readNeoqML(); ok {
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq.t0Pkts, nq.t3Bytes, true
	}
}

func clampDur(v, lo, hi time.Duration) time.Duration {
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
	algo := "coord"       // "coord" (coordinate ascent) | "ucb" (UCB1 bandit per param)
	gamma := defaultGamma // Express-delay penalty weight; --gamma 0 disables the term
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
		case "--gamma":
			if i+1 < len(args) {
				if g, e := strconv.ParseFloat(args[i+1], 64); e == nil && g >= 0 {
					gamma = g
				}
				i++
			}
		}
	}
	if iface == "" {
		return fmt.Errorf("usage: optimize --iface <dev> [--interval N] [--target IP] [--algo coord|ucb] [--gamma G]")
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
		score         float64
		params        paramSet
		loss          float64
		changedParam  string  // B1: the coordinate whose move reached this best score
		delta         float64 // B1: that move's score change (raw, pre-conditioning)
		badLink       bool    // B2: was this window-best captured during link weather?
		expressPeakUs float64 // NeoQ: Express recent-peak delay at the best cycle
		t3Goodput     uint64  // NeoQ: bulk bytes moved in the best cycle's window
		jitterMs      float64 // RTT-ring MAD (variance signal) at the best cycle
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

	o := newOptimizer(iface, interval, gamma)
	// UCB bandit: pre-load it with all prior samples so a fresh process
	// inherits learning from previous runs (crucial for systemd auto-restart).
	// Instantiated in BOTH modes: in coord mode it backs delta-credit (B1) and the
	// effect-size freeze (B4); in ucb mode it also steers. The exploration constant
	// is unused in coord mode (we only read arm means/effect-size, never suggest()).
	ucb := newUCB(o.tun, math.Sqrt(2))
	prior := loadModel()
	ucb.loadFromSamples(prior.Samples)
	fmt.Printf("UCB initialized from %d prior samples\n", len(prior.Samples))
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
	nq0, nqUp := readNeoqML()
	fmt.Printf("optimize: iface=%s interval=%v gamma=%.2f neoq_ml=%v phase=EXPLORE (aggressive grab, tx+rx)\n",
		iface, interval, gamma, nqUp)
	o.prevBytes = ifaceBytes(iface)
	o.prevOut, o.prevRetr = readSnmpTcp()
	// Prime the NeoQ cumulative-counter baseline alongside iface/snmp so the first
	// measure() produces a real delta (not a suppressed first-cycle one).
	if nqUp {
		o.prevT0Pkts, o.prevT3Bytes, o.nqPrimed = nq0.t0Pkts, nq0.t3Bytes, true
	}

	for {
		time.Sleep(interval)
		m := o.measure()
		sc := o.score(m)
		ts := time.Now().Format("15:04:05")

		// Anti-noise gate for NeoQ-only params: a genuinely mixed workload needs
		// concurrent bulk flows AND live Express traffic this window. Re-evaluated
		// every cycle; consumed by nextTi to keep neoq_sparse_thresh out of the probe
		// rotation when it would be a no-op. Stays false when stats are unavailable.
		o.mixedWorkload = m.nqOK && m.bulkFlows >= 1 && m.t0DeltaPkts >= expressActivityFloorPkts

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

		// B2 link-weather gate: an RTT spike >3x the unloaded floor is the path
		// misbehaving, not our params. score() already turns that into a deeply
		// negative number; attributing it to whatever coordinate we happen to be
		// probing teaches the optimizer the wrong lesson (this is exactly how a
		// real -0.909 sample came purely from an RTT spike). On such cycles we
		// still RECORD the sample (tagged BAD-LINK — bad-link data is useful to
		// the KNN), but we skip UCB credit and skip the accept/revert decision.
		badLink := o.minRtt > 0 && m.rttMs > 0 && (m.rttMs/o.minRtt-1) > 2.0

		// Jitter ring: push this cycle's RTT only on a CLEAN cycle (rtt>0, not
		// bad-link). A bad-link cycle's RTT is a weather spike, not steady-state
		// jitter — including it would poison the MAD that score() penalizes on. The
		// ring holds the last jitterRingLen clean RTTs; score() reads it next cycle.
		if !badLink && m.rttMs > 0 {
			o.rttRing = append(o.rttRing, m.rttMs)
			if len(o.rttRing) > jitterRingLen {
				o.rttRing = o.rttRing[1:]
			}
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
			// B1: tag this best with the coordinate that moved to reach it, so the
			// persisted sample can carry single-param credit (changedParam/delta).
			// havePrev means a probe is outstanding (probedTi/probedVal/prevScore set).
			if o.havePrev {
				windowBest.changedParam = o.tun[o.probedTi].name
				windowBest.delta = sc - o.prevScore
			} else {
				windowBest.changedParam = ""
				windowBest.delta = 0
			}
			windowBest.badLink = badLink
			windowBest.expressPeakUs = m.t0PeakDelayUs
			windowBest.t3Goodput = m.t3GoodputDelta
			// Jitter at the best cycle: MAD of the ring, matching what score() saw
			// (0 when the ring is too short for the jitter term to apply).
			if len(o.rttRing) >= jitterMinSamples {
				windowBest.jitterMs = medianAbsDev(o.rttRing)
			} else {
				windowBest.jitterMs = 0
			}
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
			} else if err := loadModel().record(feat, windowBest.params, windowBest.score, windowBest.changedParam, windowBest.delta, windowBest.expressPeakUs, windowBest.t3Goodput, windowBest.jitterMs); err == nil {
				tag := "good"
				if windowBest.badLink || windowBest.score < 0 {
					tag = "BAD-LINK"
				}
				fmt.Printf("    -> sample recorded [%s] (model now has %d, score=%.3f, bw=%.0fM loss=%.1f%% changed=%s d=%.3f xpeak=%.0fus t3d=%dB)\n",
					tag, len(loadModel().Samples), windowBest.score, feat.BwMbps, feat.LossPct*100, windowBest.changedParam, windowBest.delta, windowBest.expressPeakUs, windowBest.t3Goodput)
			}
			windowCycle = 0
			windowBest = windowBestT{score: -1e9}
		}
		// UCB mode: each cycle pick a fresh value per parameter (rotate which
		// param we update so coordinated effects stay observable). Credit the
		// arm we last steered with the delta vs the prior config (B1+B3), and
		// skip credit entirely on a bad-link cycle (B2).
		if algo == "ucb" {
			if o.havePrev && !badLink {
				ucb.update(o.tun[o.probedTi].name, o.probedVal, sc-o.prevScore)
			}
			o.prevScore = sc
			t := &o.tun[o.ti]
			next := ucb.suggest(t.name)
			t.cur = next
			o.apply(t)
			o.probedTi, o.probedVal, o.havePrev = o.ti, next, true
			o.ti = o.nextTi(o.ti)
			fmt.Printf("%s UCB bw=%.0f rtt=%.1f loss=%.2f%% score=%.3f | %s -> %d (suggest)\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, sc, t.name, next)
			o.settle(m.rttMs) // B5: let the new config reach steady state before the next window
			continue
		}
		// OPTIMIZE: coordinate ascent with delta-credited revert-on-regression.
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
		// B2 bad-link cycle: skip BOTH the UCB credit and the accept/revert
		// decision. Leave the current probe in place and drop the outstanding
		// probe bookkeeping so the next clean cycle re-baselines prevScore — we
		// don't want a weather-inflated delta to drive the next decision.
		if badLink {
			o.havePrev = false
			o.pendingSign = 0
			fmt.Printf("%s OPT BAD-LINK (rtt=%.1f/%.1fx min) — skip credit+decision, hold %s=%d\n",
				ts, m.rttMs, m.rttMs/o.minRtt, o.tun[o.ti].name, o.tun[o.ti].cur)
			continue
		}
		// B1 delta-credit: the score change since the prior config is attributable
		// to the SINGLE coordinate we moved last cycle. Credit only that arm (the
		// conditioning into [0,1] happens inside ucb.update). This replaces the old
		// loop that smeared one scalar score onto all 5 params.
		var delta float64
		haveDelta := o.havePrev
		if haveDelta {
			delta = o.smScore - o.prevScore
			ucb.update(o.tun[o.probedTi].name, o.probedVal, delta)
		}
		// B4 effect-size freeze: once the just-credited param has ≥5 pulls, if its
		// best and worst arm means differ by <0.05 (conditioned-reward units) it has
		// no measurable effect on this link — freeze it (stop probing it). This is
		// the generic catch for inert params (what neoq_boost was on single flow).
		if haveDelta {
			name := o.tun[o.probedTi].name
			if spread, pulls := ucb.effectSize(name); pulls >= 5 && spread < 0.05 && !o.frozen[name] {
				o.frozen[name] = true
				o.freezeMinRtt = o.minRtt
				fmt.Printf("%s FREEZE %s (effect=%.3f over %d pulls < 0.05) — no measurable effect, parking it\n",
					ts, name, spread, pulls)
			}
		}
		// B4 unfreeze on regime change: if the unloaded RTT floor has shifted by ≥2x
		// since we froze (a different path/route — a param inert on one link may
		// matter on another), thaw everything and re-explore.
		if len(o.frozen) > 0 && o.freezeMinRtt > 0 && o.minRtt > 0 {
			if r := o.minRtt / o.freezeMinRtt; r >= 2 || r <= 0.5 {
				o.frozen = map[string]bool{}
				fmt.Printf("%s UNFREEZE all (minRtt regime %.1f->%.1fms) — re-exploring\n",
					ts, o.freezeMinRtt, o.minRtt)
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
				o.unstableN, o.dir, o.havePrev, o.pendingSign = 0, 1, false, 0
				o.settle(m.rttMs)
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
		}
		// B2 decision smoothing (sequential variant) + coordinate advance, unified.
		//
		// We require TWO measurements of the SAME probed config to agree on the sign
		// of its delta-vs-baseline before committing accept/revert — the cheaper
		// sequential alternative to median-of-3 (the tradeoff: a clear verdict costs
		// one extra cycle, in exchange a single noisy cycle can never flip the search).
		// Vote 1 is this cycle's delta after the step; if it's non-zero we HOLD the
		// identical config one more cycle (no new step, no advance) for vote 2, keeping
		// the same baseline (o.prevScore) so the second delta is comparable. Only after
		// the verdict do we advance to the next coordinate.
		//
		// hold=true => re-measure the same config next cycle (confirmation pending);
		// hold=false => verdict reached (or nothing to judge) → step the next coord.
		hold := false
		if haveDelta {
			const eps = 0.01 // dead-band: |delta|<eps is "no measurable change"
			sign := 0
			if delta > eps {
				sign = 1
			} else if delta < -eps {
				sign = -1
			}
			t := &o.tun[o.probedTi]
			switch {
			case sign == 0:
				// Flat (incl. a clamped no-op at a range edge): no signal, move on.
				o.pendingSign = 0
			case o.pendingSign == 0:
				// Vote 1 → hold the same config one cycle to confirm the sign.
				o.pendingSign = sign
				hold = true
			case sign == o.pendingSign:
				// Vote 2 agrees → act on the probed coordinate.
				if sign < 0 {
					// Hurt twice: back the step out and flip this param's direction.
					t.cur = clampInt(t.cur-o.dir*t.step, t.min, t.max)
					o.apply(t)
					o.dir = -o.dir
				}
				// sign>0 (helped twice): accept — leave cur, keep o.dir for momentum.
				o.pendingSign = 0
			default:
				// Two cycles disagree (noise) → don't commit, move on.
				o.pendingSign = 0
			}
		}
		if hold {
			// Re-measure the identical config: do NOT step or advance, and keep
			// o.prevScore as the shared baseline. havePrev stays true so vote 2 is
			// credited/judged against probedTi next cycle.
			fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% sm=%.3f best=%.3f | confirm %s=%d (hold)\n",
				ts, m.bwMbps, m.rttMs, m.lossPct*100, o.smScore, o.bestScore, o.tun[o.probedTi].name, o.probedVal)
			o.settle(m.rttMs)
			continue
		}
		// Verdict reached (or nothing to judge): advance to the next non-frozen
		// coordinate and step it. If the step would leave the range, flip this
		// param's direction and retry so we always apply a real change to credit.
		o.ti = o.nextTi(o.ti)
		t := &o.tun[o.ti]
		nv := clampInt(t.cur+o.dir*t.step, t.min, t.max)
		if nv == t.cur {
			o.dir = -o.dir
			nv = clampInt(t.cur+o.dir*t.step, t.min, t.max)
		}
		prev := t.cur
		t.cur = nv
		o.apply(t)
		// Record the outstanding probe for next cycle's delta-credit, then SETTLE
		// (B5) so the next measure() window covers only the new config's steady
		// state — not the old config's tail plus this one's ramp-up.
		o.probedTi, o.probedVal, o.prevScore, o.havePrev = o.ti, nv, o.smScore, (nv != prev)
		nqInfo := ""
		if m.nqOK {
			mix := ""
			if o.mixedWorkload {
				mix = " MIXED"
			}
			nqInfo = fmt.Sprintf(" | xpeak=%.0fus bulk=%d t0d=%d%s", m.t0PeakDelayUs, m.bulkFlows, m.t0DeltaPkts, mix)
		}
		fmt.Printf("%s OPT bw=%.0f rtt=%.1f loss=%.2f%% sm=%.3f best=%.3f | next %s=%d (settle)%s\n",
			ts, m.bwMbps, m.rttMs, m.lossPct*100, o.smScore, o.bestScore, t.name, nv, nqInfo)
		o.settle(m.rttMs)
	}
}

// nextTi returns the index of the next SELECTABLE tunable after i, wrapping
// around. A tunable is skipped when (a) it's frozen (B4 effect-size), or (b) it's
// a NeoQ-only param and the current cycle isn't a mixed workload (the anti-noise
// gate — neoqOnly params are no-ops on single-flow/idle traffic and must not
// absorb credit). If every tunable is skipped it returns the next index anyway so
// the loop never deadlocks — selection only steers which param we PROBE.
func (o *optimizer) nextTi(i int) int {
	n := len(o.tun)
	for k := 1; k <= n; k++ {
		j := (i + k) % n
		if o.frozen[o.tun[j].name] {
			continue
		}
		if o.tun[j].neoqOnly() && !o.mixedWorkload {
			continue
		}
		return j
	}
	return (i + 1) % n
}
