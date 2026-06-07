package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// linkFeature is the smoothed measurement of a path used by both
// the model (lookup key) and the planner (parameter formulas).
type linkFeature struct {
	target  string  // peer IP (for logging only, not a model dimension)
	rttMs   float64 // P50 RTT, MAD-filtered, multi-sample
	rttMin  float64 // P10 RTT — proxy for unloaded floor
	jitter  float64 // P90-P10, captures bufferbloat/variance
	bwMbps  float64 // trimmed-mean throughput, multi-sample
	lossPct float64 // ping loss fraction
}

var rttRe = regexp.MustCompile(`time=([0-9.]+) ms`)

// probePing fires N pings with 0.2s spacing and returns per-packet RTTs (ms)
// plus loss fraction. Outliers are not filtered here — caller decides.
// If ICMP is blocked (common on NAT'd peers) and tcpPort > 0, falls back to
// TCP connect timing — works through firewalls that drop ICMP.
func probePing(ip string, count int, tcpPort int) (rtts []float64, loss float64, err error) {
	out, perr := exec.Command("ping", "-c", strconv.Itoa(count), "-i", "0.2", "-W", "3", ip).Output()
	if perr == nil {
		for _, m := range rttRe.FindAllStringSubmatch(string(out), -1) {
			if v, e := strconv.ParseFloat(m[1], 64); e == nil {
				rtts = append(rtts, v)
			}
		}
		if len(rtts) > 0 {
			loss = 1 - float64(len(rtts))/float64(count)
			return
		}
	}
	if tcpPort <= 0 {
		return nil, 1, fmt.Errorf("ping %s failed and no tcp port for fallback", ip)
	}
	// TCP fallback: time successive nc connects.
	for i := 0; i < count; i++ {
		t0 := time.Now()
		cmd := exec.Command("nc", "-z", "-w", "3", ip, strconv.Itoa(tcpPort))
		if err := cmd.Run(); err == nil {
			rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000.0)
		}
		time.Sleep(200 * time.Millisecond)
	}
	loss = 1 - float64(len(rtts))/float64(count)
	if len(rtts) == 0 {
		return nil, 1, fmt.Errorf("both icmp and tcp %d failed to %s", tcpPort, ip)
	}
	return
}

// probeIperf runs an iperf3 -R against the target for `secs` seconds
// (server side must be running) and returns Mbps.
func probeIperf(ip string, port, secs int) (float64, error) {
	out, err := exec.Command("iperf3", "-c", ip, "-p", strconv.Itoa(port),
		"-R", "-t", strconv.Itoa(secs), "-J").Output()
	if err != nil {
		return 0, fmt.Errorf("iperf3: %w", err)
	}
	// Lightweight JSON scan to avoid encoding/json dep
	i := strings.Index(string(out), `"sum_received"`)
	if i < 0 {
		return 0, fmt.Errorf("no sum_received in iperf3 output")
	}
	j := strings.Index(string(out)[i:], `"bits_per_second":`)
	if j < 0 {
		return 0, fmt.Errorf("no bits_per_second")
	}
	rest := string(out)[i+j+len(`"bits_per_second":`):]
	k := strings.IndexAny(rest, ",}")
	v, err := strconv.ParseFloat(strings.TrimSpace(rest[:k]), 64)
	if err != nil {
		return 0, err
	}
	return v / 1e6, nil
}

// probeLink does full probing: 20-ping with MAD filtering + 3x5s iperf trimmed mean.
// Returns a linkFeature with smoothed signal robust to a few outlier samples.
func probeLink(ip string, port int) (linkFeature, error) {
	f := linkFeature{target: ip}
	rtts, loss, err := probePing(ip, 20, port)
	if err != nil {
		return f, err
	}
	f.lossPct = loss
	clean := madFilter(rtts, 3.0) // Hampel: drop >3*MAD outliers
	f.rttMs = percentile(clean, 0.5)
	f.rttMin = percentile(clean, 0.1)
	f.jitter = percentile(clean, 0.9) - f.rttMin
	if port > 0 {
		var bws []float64
		for i := 0; i < 3; i++ {
			if v, err := probeIperf(ip, port, 5); err == nil && v > 0 {
				bws = append(bws, v)
			}
			time.Sleep(500 * time.Millisecond)
		}
		f.bwMbps = trimmedMean(bws, 0.34) // drop the outlier of 3 samples
	}
	return f, nil
}

// cmdProbe — measures and prints, doesn't write any sysctl.
//
//	lotspeedctl probe <ip> [port]
func cmdProbe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: probe <ip> [iperf3_port]")
	}
	port := 0
	if len(args) > 1 {
		port, _ = strconv.Atoi(args[1])
	}
	f, err := probeLink(args[0], port)
	if err != nil {
		return err
	}
	fmt.Printf("link to %s:\n", f.target)
	fmt.Printf("  RTT  P50 = %6.1f ms  P10 = %6.1f ms  jitter = %5.1f ms\n", f.rttMs, f.rttMin, f.jitter)
	fmt.Printf("  loss      = %.2f%%\n", f.lossPct*100)
	if port > 0 {
		fmt.Printf("  BW (trimmed-mean, 3x5s) = %.1f Mbps\n", f.bwMbps)
		bdp := f.bwMbps * 1e6 / 8 * f.rttMs / 1000 / 1460
		fmt.Printf("  BDP = %.0f packets\n", bdp)
	}
	return nil
}
