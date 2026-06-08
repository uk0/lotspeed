package main

import (
	"fmt"
	"os"
	"strconv"
)

const histClearProc = "/proc/sys/net/ipv4/lotspeed/hist_clear"

// cmdTune does: probe → model.predict → write sysctls → hist_clear.
// This is the one-shot "make this link fast" entry point for ops.
//
//	lotspeedctl tune <ip> [iperf3_port]
func cmdTune(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tune <ip> [iperf3_port]")
	}
	port := 0
	if len(args) > 1 {
		port, _ = strconv.Atoi(args[1])
	}
	fmt.Printf("probing %s (this takes ~20s)...\n", args[0])
	f, err := probeLink(args[0], port)
	if err != nil {
		return err
	}
	fmt.Printf("link: RTT=%.0fms (P10=%.0fms jit=%.0fms) loss=%.2f%% bw=%.0fM\n",
		f.RttMs, f.RttMin, f.Jitter, f.LossPct*100, f.BwMbps)

	m := loadModel()
	src := "heuristic"
	if len(m.Samples) > 0 {
		src = fmt.Sprintf("model (k=%d samples)", len(m.Samples))
	}
	p := m.predict(f)
	fmt.Printf("planned params (%s):\n", src)
	for k, v := range p {
		fmt.Printf("  %-22s = %d\n", k, v)
	}

	// Nuke poisoned hist entries before applying new plan.
	if err := os.WriteFile(histClearProc, []byte("1"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warn: hist_clear failed (%v)\n", err)
	} else {
		fmt.Println("hist_clear: flushed old per-IP cache")
	}
	// Engage lotspeed CC.
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed: %w", err)
	}
	// Write all planned params.
	for k, v := range p {
		if err := writeSysctl(k, strconv.Itoa(v)); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s (%v)\n", k, err)
		}
	}
	fmt.Println("tuned: CC=lotspeed + params applied")
	return nil
}

// cmdHistClear — manual trigger for ops to flush a poisoned cache.
func cmdHistClear(args []string) error {
	if err := os.WriteFile(histClearProc, []byte("1"), 0o644); err != nil {
		return err
	}
	fmt.Println("hist_clear OK")
	return nil
}
