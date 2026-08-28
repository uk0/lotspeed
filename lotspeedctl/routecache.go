package main

// routecache.go —— 判定一个对端地址的流量是否真的从被整形的那张网卡出去。
//
// 为什么需要它: 控制器的 deficit = (Δshaper_sent − Δbytes_acked)/Δshaper_sent。
// 分子来自 NeoQ 的 shaper_sent, 只含**经过被整形网卡**的字节; 分母以前来自全机
// ss 求和。green1 实测这两侧根本不是同一批流量:
//
//	dst                  minrtt     bytes_acked   ip route get
//	172.18.0.4:8897      277.13ms   26.66 MB      dev br-7860d40690c0   <- 95%, 不过 ens3
//	172.68.211.12:18172    1.03ms    1.31 MB      dev ens3
//	127.0.0.1:43642      176.46ms    0.00 MB      dev lo
//
// 那 26.66MB 走 docker bridge, NeoQ 永远看不见, 却被 ssBands 按 minrtt 277ms 归进
// far 档并计入该档的 acked。后果在生产日志里抓到了实证:
//
//	10:06:41 band -> far (minRtt=380ms E=39ms socks=1)
//	10:06:47 SEEK->HOLD (util=0.02 deficit=3.2% E_remote=52ms) C_hat=19.1 Mbps R=18.1 Mbps
//
// util=0.02 —— 几乎没有流量绑定, 却 latch 了 19.1 Mbps 的容量并把 R 设成 18.1 Mbps。
// 一条不经 ens3 的 socket 直接造成了错误决策。(它是靠 E_remote 分支退出 SEEK 的,
// 而那个 E 来自一条 380ms 的无关 socket。)
//
// 为什么判据是路由出接口而不是地址段: 上表里 172.68.211.12 是公网地址却该保留,
// 而 VPN/隧道场景下私网地址走被整形网卡同样该保留 —— 按 127/8 + RFC1918 分类
// 两个方向都会判错。只有内核的转发决策是真相。
//
// 为什么不自己读路由表做最长前缀匹配: 要做对就得复刻 FIB 的全部语义 (多表、
// ip rule、metric、scope、src)。让内核回答, 结果永远和转发面一致。
//
// 已知限制: `ip route get` 不带 fwmark 查询, 若流量靠 ip rule + fwmark 走别的表
// 会判错。green1 的 docker 走 NAT 不走策略路由, 不受影响。

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

// 路由是准静态的, 但不是永不变 (anycast 出口漂移是实测存在的)。300s 的陈旧上界
// 是可接受的: 判错的两个方向都只退化到"过滤前的行为", 不引入新的故障类别。
const routeCacheTTL = 300 * time.Second

type routeEnt struct {
	dev string
	at  time.Time
}

// routeCache 把 dst -> 出接口 的判定结果缓存起来。dst 集合是几十个量级, 首拍一次性
// 付 N 次 exec (每次 2-3ms), 稳态每拍 0 次。
type routeCache struct {
	iface string
	mu    sync.Mutex
	m     map[string]routeEnt
	// warned 保证"查不到路由"这类降级只打一次日志, 不刷屏。
	warned bool
	logf   func(string, ...any)
	// lookup 可注入, 供单测替换掉真实的 exec。
	lookup func(dst string) string
}

func newRouteCache(iface string, logf func(string, ...any)) *routeCache {
	rc := &routeCache{iface: iface, m: map[string]routeEnt{}, logf: logf}
	rc.lookup = routeDev
	return rc
}

// via 报告 dst 的流量是否从 rc.iface 出去。
//
// 失败一律返回 true (include): 查不到路由时保持过滤前的行为, 与整个项目的
// fail-open 方向一致 —— 宁可信号里多一点噪声, 也不要因为一次 exec 失败就把
// 整条链路的样本丢光, 那会让控制器瞎掉。
func (rc *routeCache) via(dst string) bool {
	if dst == "" {
		return true
	}
	if rc.iface == "" {
		return true // 没指定网卡就没有过滤依据
	}
	ip := hostOf(dst)
	if ip == "" {
		return true
	}

	rc.mu.Lock()
	ent, ok := rc.m[ip]
	fresh := ok && time.Since(ent.at) < routeCacheTTL
	rc.mu.Unlock()

	if !fresh {
		dev := rc.lookup(ip)
		if dev == "" && !rc.warned {
			rc.warned = true
			if rc.logf != nil {
				rc.logf("route lookup failed for %s — 该 dst 按 include 处理 (fail-open)", ip)
			}
		}
		ent = routeEnt{dev: dev, at: time.Now()}
		rc.mu.Lock()
		rc.m[ip] = ent
		rc.mu.Unlock()
	}

	if ent.dev == "" {
		return true // 判不出来就不排除
	}
	return ent.dev == rc.iface
}

// routeDev 问内核: 去 ip 的包从哪张网卡出去。
// `ip route get 1.2.3.4` -> "1.2.3.4 via 10.0.0.1 dev ens3 src ... uid 0"
func routeDev(ip string) string {
	args := []string{"route", "get", ip}
	if strings.Contains(ip, ":") {
		args = []string{"-6", "route", "get", ip}
	}
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

// hostOf 从 "addr:port" 里剥出地址。v6 是 "[::1]:80" 的形式, 所以先按最后一个冒号
// 切端口再脱方括号 —— 不能直接按第一个冒号切, v6 地址内部全是冒号。
func hostOf(addr string) string {
	s := addr
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return s
}
