package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

const neoqPrioProc = "/proc/net/neoq_prio"

// Latency-sensitive web ports always prioritized.
var webPorts = []int{80, 443, 8080, 8443}

// Well-known game server ports (Steam, console, common UDP games).
var gamePortsKnown = []int{27015, 27016, 27017, 3074, 3478, 3479, 7777, 7778, 25565, 9987}

func setPrioPort(port int, add bool) error {
	sign := "+"
	if !add {
		sign = "-"
	}
	return os.WriteFile(neoqPrioProc, []byte(fmt.Sprintf("%s%d", sign, port)), 0o644)
}

func clearPrio() error { return os.WriteFile(neoqPrioProc, []byte("clear"), 0o644) }

// scanActivePorts parses `ss` for web (TCP 80/443) and game (active UDP
// remote ports in known/heuristic ranges) traffic to prioritize.
func scanActivePorts() (web, game []int) {
	known := map[int]bool{}
	for _, p := range gamePortsKnown {
		known[p] = true
	}
	seen := map[int]bool{}

	// UDP sockets -> game candidates (peer port).
	if out, err := exec.Command("ss", "-uan").Output(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			peer := f[len(f)-1]
			i := strings.LastIndex(peer, ":")
			if i < 0 {
				continue
			}
			p, err := strconv.Atoi(peer[i+1:])
			if err != nil || p <= 0 || p >= 65536 {
				continue
			}
			// known game port, or common UDP game ranges
			if known[p] || (p >= 27000 && p <= 27100) || (p >= 3000 && p <= 4100) {
				if !seen[p] {
					game = append(game, p)
					seen[p] = true
				}
			}
		}
	}
	web = append(web, webPorts...)
	sort.Ints(web)
	sort.Ints(game)
	return
}

// cmdPrio manages NeoQ priority ports.
//
//	lotspeedctl prio [list | add P... | del P... | clear | auto]
func cmdPrio(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		b, err := os.ReadFile(neoqPrioProc)
		if err != nil {
			return fmt.Errorf("read %s (neoq loaded?): %w", neoqPrioProc, err)
		}
		fmt.Print(string(b))
		return nil
	}
	switch args[0] {
	case "add":
		for _, a := range args[1:] {
			if p, err := strconv.Atoi(a); err == nil {
				if err := setPrioPort(p, true); err != nil {
					return err
				}
				fmt.Printf("+%d\n", p)
			}
		}
	case "del":
		for _, a := range args[1:] {
			if p, err := strconv.Atoi(a); err == nil {
				if err := setPrioPort(p, false); err != nil {
					return err
				}
				fmt.Printf("-%d\n", p)
			}
		}
	case "clear":
		if err := clearPrio(); err != nil {
			return err
		}
		fmt.Println("cleared")
	case "auto":
		web, game := scanActivePorts()
		for _, p := range web {
			_ = setPrioPort(p, true)
		}
		for _, p := range game {
			_ = setPrioPort(p, true)
		}
		fmt.Printf("auto: web=%v game=%v -> %s\n", web, game, neoqPrioProc)
	default:
		return fmt.Errorf("usage: prio [list | add P... | del P... | clear | auto]")
	}
	return nil
}
