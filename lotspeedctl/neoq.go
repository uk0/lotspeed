package main

import (
	"os"
	"strconv"
	"strings"
)

// neoqMLProc is the machine-readable single-line stats file exported by the new
// sch_neoq qdisc. It exists only when that qdisc is loaded; absence => the
// experience-aware features stay off (see readNeoqML's ok=false return).
const neoqMLProc = "/proc/net/neoq_ml"

// neoqSparseProc is the runtime knob for the CAKE-style sparse gate. Write format
// (kernel sscanf "%u %u"): `<window_us> <thresh_bytes>`. We keep the window fixed
// at 100000us and only tune thresh_bytes (see the neoq_sparse_thresh tunable).
const neoqSparseProc = "/proc/net/neoq_sparse"

// neoqML is the subset of /proc/net/neoq_ml the tuner consumes. The kernel emits
// one space-separated line of key=value pairs (qlen=N mem=N ... t0_..t3_..
// retrans_seen=N retrans_protected=N). We parse only the fields the optimizer
// scores on; unknown keys are ignored so kernel-side additions don't break us.
//
// t0 = Express tier (interactive/ACK/retransmit) — its delay is the ground-truth
// experience signal. t3 = Bulk tier (downloads). t0Pkts and t3Bytes are CUMULATIVE
// counters (the optimizer differences them per cycle, like the iface byte
// counters); t0PeakDelayUs is reset-on-read (peak since the last read).
type neoqML struct {
	qlen             uint64
	sparseFlows      uint64
	bulkFlows        uint64
	t0Pkts           uint64 // cumulative — for the Express-activity floor (delta pkts)
	t0AvgDelayUs     uint64
	t0PeakDelayUs    uint64 // reset-on-read: recent peak since last read
	t3Bytes          uint64 // cumulative — bulk goodput (delta per cycle)
	retransSeen      uint64
	retransProtected uint64
}

// readNeoqML reads and parses /proc/net/neoq_ml. ok=false when the file is absent
// (qdisc not loaded) or unparseable; callers then keep behavior identical to a box
// without the new qdisc. The kernel emits a zero-valued line even with no active
// qdisc instance, so a present-but-idle file parses fine (ok=true, zero fields).
func readNeoqML() (neoqML, bool) {
	b, err := os.ReadFile(neoqMLProc)
	if err != nil {
		return neoqML{}, false
	}
	return parseNeoqML(string(b))
}

// parseNeoqML parses one neoq_ml line (space-separated key=value). ok=false when
// no recognizable key=value token is present (empty/garbage). Unknown keys and
// non-numeric values are ignored so kernel-side key additions never break us.
func parseNeoqML(line string) (neoqML, bool) {
	var s neoqML
	any := false
	for _, tok := range strings.Fields(line) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		n, perr := strconv.ParseUint(val, 10, 64)
		if perr != nil {
			continue
		}
		any = true
		switch key {
		case "qlen":
			s.qlen = n
		case "sparse_flows":
			s.sparseFlows = n
		case "bulk_flows":
			s.bulkFlows = n
		case "t0_pkts":
			s.t0Pkts = n
		case "t0_avg_delay_us":
			s.t0AvgDelayUs = n
		case "t0_peak_delay_us":
			s.t0PeakDelayUs = n
		case "t3_bytes":
			s.t3Bytes = n
		case "retrans_seen":
			s.retransSeen = n
		case "retrans_protected":
			s.retransProtected = n
		}
	}
	if !any {
		return neoqML{}, false
	}
	return s, true
}
