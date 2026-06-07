// lotspeedctl - control & monitor for LotSpeed CC + NeoQ qdisc.
//
// Goals: combat intercontinental packet loss, fix slow TCP start-up,
// and prioritize game/web traffic via NeoQ. The `daemon` subcommand
// (added next) closes the loop: collect metrics -> decide -> actuate.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	sysctlDir = "/proc/sys/net/ipv4/lotspeed"
	ccPath    = "/proc/sys/net/ipv4/tcp_congestion_control"
	availPath = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	neoqProc  = "/proc/net/neoq"
)

// Presets tuned per scenario. Keys are real lotspeed sysctl names.
var presets = map[string]map[string]string{
	// Intercontinental high-loss/high-RTT: aggressive start, Hybla on,
	// anti-jitter (brave), tolerate loss instead of collapsing cwnd.
	"intercontinental": {
		"turbo_startup": "1",
		"startup_gain":  "320",
		"brave_enable":  "1",
		"hd_enable":     "1",
		"hd_rho_max":    "400",
		"loss_thresh":   "30",
		"fast_recovery": "1",
	},
	// Game: latency-first, small target queue, fast reaction.
	"game": {
		"turbo_startup":      "1",
		"brave_enable":       "1",
		"fast_alpha":         "8",
		"probe_rtt_cwnd_pct": "75",
	},
	// Web: quick ramp for short flows, reuse per-IP history cache.
	"web": {
		"turbo_startup": "1",
		"startup_gain":  "300",
		"hist_enable":   "1",
		"fast_path":     "1",
	},
	// Balanced default.
	"balanced": {
		"startup_gain": "277",
		"brave_enable": "1",
		"hd_enable":    "1",
	},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "status":
		err = cmdStatus()
	case "enable":
		err = cmdEnable(os.Args[2:])
	case "disable":
		err = cmdDisable(os.Args[2:])
	case "set":
		err = cmdSet(os.Args[2:])
	case "get":
		err = cmdGet(os.Args[2:])
	case "preset":
		err = cmdPreset(os.Args[2:])
	case "monitor":
		err = cmdMonitor(os.Args[2:])
	case "daemon":
		err = cmdDaemon(os.Args[2:])
	case "optimize":
		err = cmdOptimize(os.Args[2:])
	case "prio":
		err = cmdPrio(os.Args[2:])
	case "boost":
		err = cmdBoost(os.Args[2:])
	case "probe":
		err = cmdProbe(os.Args[2:])
	case "tune":
		err = cmdTune(os.Args[2:])
	case "hist-clear":
		err = cmdHistClear(os.Args[2:])
	case "model":
		err = cmdModel(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`lotspeedctl - LotSpeed CC + NeoQ control

Usage:
  lotspeedctl status                 show CC, qdisc, key params, NeoQ stats
  lotspeedctl enable [iface]         set CC=lotspeed (+ attach neoq to iface)
  lotspeedctl disable [iface]        revert CC=bbr (+ remove neoq from iface)
  lotspeedctl set <param> <value>    write /proc/sys/net/ipv4/lotspeed/<param>
  lotspeedctl get [param]            read one param, or dump all
  lotspeedctl preset <name>          apply a preset (intercontinental|game|web|balanced)
  lotspeedctl preset                 list presets
  lotspeedctl monitor [sec]          live refresh of CC + NeoQ stats (default 2s)
  lotspeedctl daemon [--interval N] [--iface eth0]
                                     collect loss -> auto-tune anti-loss params
  lotspeedctl optimize --iface eth0 [--interval N]
                                     adaptive search: EXPLORE peak bw -> OPTIMIZE score
  lotspeedctl prio [list|add P..|del P..|clear|auto]
                                     manage NeoQ priority ports (auto = detect game/web)
  lotspeedctl boost [N]              get/set NeoQ downstream rwnd boost (percent, 100=off)
  lotspeedctl probe <ip> [port]      measure RTT/BW/loss (MAD-filtered, multi-sample)
  lotspeedctl tune <ip> [port]       probe -> model.predict -> apply sysctls + hist_clear
  lotspeedctl hist-clear             flush poisoned per-IP hist cache
  lotspeedctl model [show|clear]     inspect KNN sample store (~/.lotspeedctl/model.json)
`)
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func readSysctl(name string) (string, error) {
	b, err := os.ReadFile(sysctlDir + "/" + name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysctl(name, val string) error {
	return os.WriteFile(sysctlDir+"/"+name, []byte(val), 0o644)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdStatus() error {
	fmt.Println("== LotSpeed / NeoQ status ==")
	fmt.Printf("current CC    : %s\n", readTrim(ccPath))
	fmt.Printf("available CC  : %s\n", readTrim(availPath))
	if _, err := os.Stat(sysctlDir); err != nil {
		fmt.Println("lotspeed mod  : NOT loaded")
	} else {
		fmt.Println("lotspeed mod  : loaded")
		for _, k := range []string{"turbo_startup", "startup_gain", "brave_enable", "hd_enable", "hd_rho_max", "loss_thresh", "fast_alpha", "hist_enable"} {
			if v, err := readSysctl(k); err == nil {
				fmt.Printf("  %-14s = %s\n", k, v)
			}
		}
	}
	if b, err := os.ReadFile(neoqProc); err == nil {
		fmt.Println("-- NeoQ (/proc/net/neoq) --")
		fmt.Print(string(b))
	} else {
		fmt.Println("neoq          : not active")
	}
	return nil
}

func cmdEnable(args []string) error {
	if err := os.WriteFile(ccPath, []byte("lotspeed"), 0o644); err != nil {
		return fmt.Errorf("set CC=lotspeed (need root?): %w", err)
	}
	fmt.Println("CC -> lotspeed")
	if len(args) > 0 {
		if err := run("tc", "qdisc", "replace", "dev", args[0], "root", "neoq"); err != nil {
			return fmt.Errorf("attach neoq to %s: %w", args[0], err)
		}
		fmt.Printf("neoq -> %s\n", args[0])
	}
	return nil
}

func cmdDisable(args []string) error {
	if err := os.WriteFile(ccPath, []byte("bbr"), 0o644); err != nil {
		return fmt.Errorf("revert CC: %w", err)
	}
	fmt.Println("CC -> bbr")
	if len(args) > 0 {
		_ = run("tc", "qdisc", "del", "dev", args[0], "root")
		fmt.Printf("neoq removed from %s\n", args[0])
	}
	return nil
}

func cmdSet(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: set <param> <value>")
	}
	if err := writeSysctl(args[0], args[1]); err != nil {
		return err
	}
	fmt.Printf("%s = %s\n", args[0], args[1])
	return nil
}

func cmdGet(args []string) error {
	if len(args) == 0 {
		entries, err := os.ReadDir(sysctlDir)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, n := range names {
			v, _ := readSysctl(n)
			fmt.Printf("%-22s = %s\n", n, v)
		}
		return nil
	}
	v, err := readSysctl(args[0])
	if err != nil {
		return err
	}
	fmt.Println(v)
	return nil
}

func cmdPreset(args []string) error {
	if len(args) == 0 {
		names := make([]string, 0, len(presets))
		for k := range presets {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Printf("presets: %s\n", strings.Join(names, ", "))
		return nil
	}
	p, ok := presets[args[0]]
	if !ok {
		return fmt.Errorf("unknown preset: %s", args[0])
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	applied := 0
	for _, k := range keys {
		if err := writeSysctl(k, p[k]); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s (%v)\n", k, err)
			continue
		}
		fmt.Printf("  %s = %s\n", k, p[k])
		applied++
	}
	fmt.Printf("preset %q applied (%d/%d params)\n", args[0], applied, len(p))
	return nil
}

func cmdMonitor(args []string) error {
	interval := 2 * time.Second
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("lotspeedctl monitor  %s   CC=%s\n", time.Now().Format("15:04:05"), readTrim(ccPath))
		if b, err := os.ReadFile(neoqProc); err == nil {
			fmt.Print(string(b))
		} else {
			fmt.Println("(neoq not active)")
		}
		time.Sleep(interval)
	}
}
