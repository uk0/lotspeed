package main

import (
	"fmt"
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
type tunable struct {
	name                string
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
	prevTx      uint64
	prevOut     uint64
	prevRetr    uint64
}

func newOptimizer(iface string, interval time.Duration) *optimizer {
	o := &optimizer{
		iface: iface, interval: interval, alpha: 0.5, beta: 5.0,
		dir: 1, phase: "EXPLORE", bestScore: -1e9,
		tun: []tunable{
			{"startup_gain", 200, 400, 20, 300},
			{"fast_alpha", 4, 40, 4, 20},
			{"loss_thresh", 2, 50, 4, 5},
			{"hd_rho_max", 150, 400, 25, 400},
		},
	}
	for i := range o.tun {
		if v, err := readSysctl(o.tun[i].name); err == nil {
			if n, err := strconv.Atoi(v); err == nil {
				o.tun[i].cur = n
			}
		}
	}
	return o
}

func ifaceTxBytes(iface string) uint64 {
	b, _ := os.ReadFile("/sys/class/net/" + iface + "/statistics/tx_bytes")
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
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
	tx := ifaceTxBytes(o.iface)
	dtx := tx - o.prevTx
	o.prevTx = tx
	out, retr := readSnmpTcp()
	dout, dretr := out-o.prevOut, retr-o.prevRetr
	o.prevOut, o.prevRetr = out, retr
	var loss float64
	if dout > 0 {
		loss = float64(dretr) / float64(dout)
	}
	bw := float64(dtx) * 8 / o.interval.Seconds() / 1e6
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

func (o *optimizer) apply(t *tunable) { _ = writeSysctl(t.name, strconv.Itoa(t.cur)) }

// cmdOptimize runs the adaptive parameter search.
//
//	lotspeedctl optimize --iface eth0 [--interval N]
func cmdOptimize(args []string) error {
	interval := 5 * time.Second
	iface := ""
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
		}
	}
	if iface == "" {
		return fmt.Errorf("usage: optimize --iface <dev> [--interval N]")
	}
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed (need root?): %w", err)
	}

	o := newOptimizer(iface, interval)
	// EXPLORE phase: aggressive grab to discover peak bandwidth.
	_ = writeSysctl("turbo_startup", "1")
	_ = writeSysctl("startup_gain", "400")
	fmt.Printf("optimize: iface=%s interval=%v phase=EXPLORE (aggressive grab)\n", iface, interval)
	o.prevTx = ifaceTxBytes(iface)
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

		// OPTIMIZE: coordinate ascent with revert-on-regression.
		if sc > o.bestScore {
			o.bestScore = sc // last probe improved -> keep going same dir
		} else {
			t := &o.tun[o.ti] // revert last probe
			t.cur -= o.dir * t.step
			o.apply(t)
			o.dir = -o.dir
			if o.dir == 1 {
				o.ti = (o.ti + 1) % len(o.tun) // both dirs tried -> next param
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
