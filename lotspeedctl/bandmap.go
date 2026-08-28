package main

// bandmap.go —— P0 取证工具。只读, 零行为变更。
//
// 目的: 在动内核之前, 用数据回答"NeoQ 多 rate class 值不值得做"。三个待验证的量:
//
//	A2 覆盖率  = 经本网卡的 socket 的 Δacked / 本网卡 Δ发送。低于 60% 说明 deficit
//	             信号在这台机器上不可用, 多 class 之前得先解决测量面。
//	A3 并发占比 = "≥2 个 RTT 档同时有流量, 且其中一个远端排队 >30ms" 的拍占比。
//	             这是多 class 全部收益的前提: 低于 5% 就不值 1000 行改动。
//	A1 表稳定性 = 单个 dst 的档归属迁移频率。抖得太厉害的话迟滞也压不住。
//
// 为什么是 Go 子命令而不是 shell 脚本: 第一版用 awk + `paste - -` 做 ss 的地址行/
// 统计行配对, 实测错位 —— 同一份统计 (acked=1.7MB minrtt=0.945) 在相邻两拍分别被
// 归给两个不同的 dst, 凭空造出 1.7MB 的假增量。`paste - -` 假设输出严格 2N 行, 这个
// 假设不成立。这里直接复用 parseSSRows (同样的状态机, 但有单测覆盖), 顺便避免同一
// 份解析逻辑存在两个版本 —— 这个项目刚清理过一次"双真相"。
//
// 输出 JSONL, 每拍一行。**不做任何过滤**: lo 和 docker bridge 的行必须留在数据里,
// 判断"内层隧道 socket 的排队能否代表外层路径"全靠它们。过滤只发生在控制信号装配处。

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type bandmapRow struct {
	Dst     string  `json:"dst"`
	Dev     string  `json:"dev"`
	Band    string  `json:"band"`
	MinRtt  float64 `json:"minrtt"`
	Srtt    float64 `json:"srtt"`
	Acked   uint64  `json:"acked"`
	Segs    uint64  `json:"segs"`
	Retrans uint64  `json:"retrans"`
}

type bandmapSample struct {
	TS         int64        `json:"ts"`
	Iface      string       `json:"iface"`
	Tx         uint64       `json:"tx"`
	Rx         uint64       `json:"rx"`
	ShaperSent uint64       `json:"shaper_sent"`
	RateKbps   uint64       `json:"rate_kbps"`
	Rows       []bandmapRow `json:"rows"`
}

func cmdBandmap(args []string) error {
	iface := "eth0"
	out := "/tmp/bandmap.jsonl"
	period := 5 * time.Second
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--iface":
			if i+1 < len(args) {
				iface = args[i+1]
				i++
			}
		case "--out":
			if i+1 < len(args) {
				out = args[i+1]
				i++
			}
		case "--period":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil && v > 0 {
					period = time.Duration(v) * time.Second
				}
				i++
			}
		}
	}

	f, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// routeCache 在这里只用来给每行**打标**, 不用来过滤 —— 见文件头。
	rc := newRouteCache(iface, func(string, ...any) {})
	enc := json.NewEncoder(f)
	fmt.Printf("bandmap: iface=%s out=%s period=%s — Ctrl-C 停止\n", iface, out, period)

	for {
		s := bandmapSample{
			TS:    time.Now().Unix(),
			Iface: iface,
			Tx:    readCounter("/sys/class/net/" + iface + "/statistics/tx_bytes"),
			Rx:    readCounter("/sys/class/net/" + iface + "/statistics/rx_bytes"),
		}
		if nq, ok := readNeoqML(); ok {
			s.ShaperSent, s.RateKbps = nq.shaperSent, nq.rateKbps
		}
		for _, r := range ssRowsAll(ssMaxSocks) {
			if r.minRtt <= 0 {
				continue
			}
			// via() 的副作用是填缓存; 这里要的是 dev 本身, 所以直接查。
			s.Rows = append(s.Rows, bandmapRow{
				Dst: r.dst, Dev: rc.devOf(r.dst), Band: rttBand(r.minRtt),
				MinRtt: r.minRtt, Srtt: r.srtt,
				Acked: r.acked, Segs: r.segs, Retrans: r.retr,
			})
		}
		if err := enc.Encode(&s); err != nil {
			fmt.Fprintf(os.Stderr, "bandmap: write failed: %v\n", err)
		}
		time.Sleep(period)
	}
}

func readCounter(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}
