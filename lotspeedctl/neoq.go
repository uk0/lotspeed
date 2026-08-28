package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

// neoqMLProc is the machine-readable single-line stats file exported by the new
// sch_neoq qdisc. It exists only when that qdisc is loaded; absence => the
// experience-aware features stay off (see readNeoqML's ok=false return).
const neoqMLProc = "/proc/net/neoq_ml"

// neoqSparseProc is the runtime knob for the CAKE-style sparse gate. Write format
// (kernel sscanf "%u %u"): `<window_us> <thresh_bytes>`. We keep the window fixed
// at 100000us and only tune thresh_bytes (see the neoq_sparse_thresh tunable).
const neoqSparseProc = "/proc/net/neoq_sparse"

// neoqRateProc is the shaper's rate knob (kbit/s, 0 = shaping OFF). The kernel
// default is 0, so a box where nothing writes this file behaves exactly like
// today: no shaper at all. That is the fail-open direction the whole shaper
// design leans on — 控制器进程死了 = 完全无整形, 而不是"卡在某个错的速率上"。
const neoqRateProc = "/proc/net/neoq_rate"

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

	// === shaper 环 (只有带整形器的新版 sch_neoq 才导出这四个键) ===
	// rateKbps  : 内核当前生效的整形速率 (kbit/s, 0=关)
	// backlog   : 瞬时排队字节数 —— 本机队列, L_local 的分子
	// shaperSent: 整形器已放行的累计字节 (CUMULATIVE, 逐拍差分)
	// shaperDefer: 因限速被推迟的累计次数 (诊断用, 不进控制律)
	rateKbps    uint64
	backlog     uint64
	shaperSent  uint64
	shaperDefer uint64

	// ambientShare: qdisc 侧上一完整 1s 窗口的全链路重传占比 (0-100)。它比用户态用
	// ss/snmp 差分估出来的环境丢包干净得多 —— 滚动窗口、只数 >=128B 的包 (纯 ACK 不
	// 稀释分母)、排除哈希冲突包。loss_thresh 闭环优先用它, ss 差分只作 fallback。
	// ambientOK 必须与值分开: "键不存在"(老内核模块) 和"键在、值是 0"(干净链路) 是
	// 两件完全不同的事, 后者是合法读数, 不能当缺失处理。
	ambientShare uint64
	ambientOK    bool
	// shaperOK 只有四个 shaper 键全部出现时才为 true。老内核模块 (今天的
	// sch_neoq) 一个都不导出, 于是整个 shaper 快环禁用, 行为退回今天 —— 沿用
	// nqOK 那套"文件缺失=特性关闭"的兼容模式。要求"全部齐全"而不是"任意一个"是
	// 故意的: 缺任何一个键控制律都算不出来, 半开状态比彻底关掉更危险。
	shaperOK bool
}

// shaper 键的到齐位掩码 (rate_kbps|backlog|shaper_sent|shaper_defer)。
const shaperKeysAll = 0x0F

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
	var shaperSeen uint8
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
		case "rate_kbps":
			s.rateKbps = n
			shaperSeen |= 1
		case "backlog":
			s.backlog = n
			shaperSeen |= 2
		case "shaper_sent":
			s.shaperSent = n
			shaperSeen |= 4
		case "shaper_defer":
			s.shaperDefer = n
			shaperSeen |= 8
		case "ambient_share":
			s.ambientShare = n
			s.ambientOK = true
		}
	}
	if !any {
		return neoqML{}, false
	}
	s.shaperOK = shaperSeen == shaperKeysAll
	return s, true
}

// nqReader 是全进程唯一的 /proc/net/neoq_ml 读取器。
//
// 为什么需要它: t0_peak_delay_us 在内核侧是 read-on-reset —— 谁读走谁清零。
// shaper 快环 (2s) 和 optimizer 慢环 (5s+settle) 是两个 goroutine, 如果各读各的,
// 快环会在慢环之前把 Express 峰值读走清零, score() 的体验项 (gamma) 就静默失效了
// —— 一个不会报错、只会让调参悄悄变笨的坑。这里保留一个"自上次被消费以来的峰值"
// 累加器: 每次读都把内核报的峰值 max 进去, 只有 consumePeak 的调用方才清零。
//
// 其余字段要么是累计计数器 (t0_pkts/t3_bytes/shaper_sent, 各自差分互不干扰),
// 要么是瞬时值 (qlen/backlog), 多读者本来就安全。
type neoqReader struct {
	mu      sync.Mutex
	peakAcc uint64
}

var nqReader neoqReader

// read 读一次 neoq_ml。consumePeak=true 的调用方 (optimizer 的 measure/settle)
// 取走累积峰值并清零; consumePeak=false 的调用方 (shaper 快环) 只是顺带看一眼,
// 不影响慢环下一次读到的峰值。
func (r *neoqReader) read(consumePeak bool) (neoqML, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := readNeoqML()
	if !ok {
		return neoqML{}, false
	}
	if s.t0PeakDelayUs > r.peakAcc {
		r.peakAcc = s.t0PeakDelayUs
	}
	s.t0PeakDelayUs = r.peakAcc
	if consumePeak {
		r.peakAcc = 0
	}
	return s, true
}

// writeNeoqRate 写整形速率到 /proc/net/neoq_rate。kbps=0 = 关闭整形 (内核默认值),
// 也是所有失效路径 (进程退出 / 看门狗 / 内核不支持) 的兜底写入值。
func writeNeoqRate(kbps uint64) error {
	return os.WriteFile(neoqRateProc, []byte(strconv.FormatUint(kbps, 10)), 0o644)
}
