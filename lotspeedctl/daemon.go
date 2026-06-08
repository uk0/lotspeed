package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// readSnmpTcp parses /proc/net/snmp and returns (OutSegs, RetransSegs).
func readSnmpTcp() (out, retr uint64) {
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var hdr []string
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line)
		if hdr == nil { // first "Tcp:" line is the header
			hdr = fields
			continue
		}
		idx := map[string]int{}
		for i, name := range hdr {
			idx[name] = i
		}
		get := func(k string) uint64 {
			if i, ok := idx[k]; ok && i < len(fields) {
				v, _ := strconv.ParseUint(fields[i], 10, 64)
				return v
			}
			return 0
		}
		return get("OutSegs"), get("RetransSegs")
	}
	return
}

// cmdDaemon runs the collect -> decide -> actuate loop.
//
//	lotspeedctl daemon [--interval N] [--iface eth0]
func cmdDaemon(args []string) error {
	interval := 5 * time.Second
	iface := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
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

	// Ensure the data plane is engaged.
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed (need root?): %w", err)
	}
	if iface != "" {
		if err := run("tc", "qdisc", "replace", "dev", iface, "root", "neoq"); err != nil {
			fmt.Fprintf(os.Stderr, "warn: attach neoq to %s failed: %v\n", iface, err)
		}
	}
	fmt.Printf("lotspeedctl daemon started: interval=%v iface=%q CC=lotspeed\n", interval, iface)

	prevOut, prevRetr := readSnmpTcp()
	for {
		time.Sleep(interval)
		out, retr := readSnmpTcp()
		dOut, dRetr := out-prevOut, retr-prevRetr
		prevOut, prevRetr = out, retr

		var loss float64
		if dOut > 0 {
			loss = float64(dRetr) / float64(dOut) * 100
		}
		action := tuneForLoss(loss)
		fmt.Printf("%s loss=%.2f%% (retr=%d/out=%d) -> %s\n",
			time.Now().Format("15:04:05"), loss, dRetr, dOut, action)
		if iface != "" { // auto game/web prioritization into NeoQ
			web, game := scanActivePorts()
			for _, p := range web {
				_ = setPrioPort(p, true)
			}
			for _, p := range game {
				_ = setPrioPort(p, true)
			}
		}
	}
}

// tuneForLoss adjusts lotspeed params based on observed retransmit ratio.
// Higher loss -> tolerate loss harder (don't collapse cwnd), keep Hybla
// compensation and anti-jitter on; low loss -> relax for efficiency.
func tuneForLoss(lossPct float64) string {
	set := func(k, v string) { _ = writeSysctl(k, v) }
	switch {
	case lossPct > 5: // severe (intercontinental / lossy)
		set("loss_thresh", "50")
		set("fast_recovery", "1")
		set("brave_enable", "1")
		set("hd_rho_max", "400")
		return "SEVERE-LOSS: loss_thresh=50 fast_recovery=1 brave=1 hd_rho_max=400"
	case lossPct > 1: // moderate
		set("loss_thresh", "20")
		set("fast_recovery", "1")
		return "MODERATE-LOSS: loss_thresh=20 fast_recovery=1"
	default: // clean link
		set("loss_thresh", "5")
		return "LOW-LOSS: loss_thresh=5"
	}
}
