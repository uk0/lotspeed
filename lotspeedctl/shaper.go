package main

// shaper.go —— NeoQ 出口整形速率 R 的反馈控制器 (快环, 2s 一拍)。
//
// 为什么这里是反馈控制而不是 bandit:
// 现有 UCB/坐标上升调的是 loss_thresh / neoq_sparse_thresh 这类二阶参数, 效应量百分
// 之几, 淹没在链路天气噪声里 —— 实测同一配置交替 A/B 四轮, 组内方差 55-71%, 组间
// 差异根本分辨不出来。shaper rate 完全不同: 它有机制性、可证伪的逐步反馈, 每个动作
// 都能用自己的直接后果检验 (我把 R 抬了 25%, goodput 涨没涨?), 不需要从全局 score
// 里做统计归因。所以主控制律是测量驱动的 probe-and-hold (BBR 同构), 随机探索只保留
// 一个受控的向上 probe。
//
// 为什么要做整形: 实测本机上联远快于洲际路径, NeoQ 全程空转 (qlen=0, t3_drops=0,
// t3_peak_delay_us=5) —— 瓶颈和 ~300ms 常驻队列都在远端路由器。不在本机限速, 本机
// 的 AQM 就永远没有队列可管。R 的作用是把队列从"远端路由器 (管不着)"搬到"本机
// (CoDel 管得着)"。

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 快环节拍。2s 足够让一次速率变更在 468ms 均值 RTT 的路径上产生可测后果 (>4 个
// RTT), 又不至于慢到跟不上链路天气。
const shaperTick = 2 * time.Second

// 状态机的状态名。OBSERVE/YIELD 不在原始规格里, 是两个必要的补充:
//
//	OBSERVE —— 冷启动无缓存时的纯观测窗 (规格里的"前 10s R=R_max 纯观测")
//	YIELD   —— 看门狗触发后的让位态 (规格只说"R=R_max+告警", 但没说之后怎么办;
//	           让它停在一个显式状态里, 比让控制律继续在失效前提上做决策安全)
const (
	stShaperObserve = "OBSERVE"
	stShaperSeek    = "SEEK"
	stShaperHold    = "HOLD"
	stShaperProbe   = "PROBE"
	stShaperBackoff = "BACKOFF"
	stShaperYield   = "YIELD"
)

const (
	// === 三个因果分离信号的判据 ===
	// utilBind: shaper 是否"绑定"。>=0.95 说明发出去的量顶到了 R, 我在控制;
	// <0.95 且没排队说明需求受限或墙在别处 (例如接收端 rwnd), R 不背锅。
	utilBind = 0.95
	// utilWeather: 天气门。低于此值的丢包/RTT 尖峰一律不动 R —— 降 R 治不了
	// 非自致的天气, 只会白扔带宽。
	utilWeather = 0.90

	// deficit 的 3 拍 EMA 窗口。ACK 相对发送滞后约 1 个 RTT (这条路径 0.16-1.2s),
	// 单拍 deficit 会随 ACK 到达抖动, 3 拍平滑掉。
	deficitEMAWin = 3.0
	// SEEK 期间"开始见底"的判据 (比 HOLD 的 10% 松, 因为 SEEK 就是要找墙)。
	deficitSeekStop = 0.05
	// HOLD 期间判定 R>C 的判据。
	deficitBackoff = 0.10
	// BACKOFF 的退出判据。
	deficitClear = 0.05
	// deficit 高到这个程度基本不可能是"真丢了这么多" —— 更可能是 Δbytes_acked
	// 根本没覆盖 Δshaper_sent 的那部分流量 (转发/隧道流量没有本地 socket, ss 看
	// 不到)。这种情况下 deficit 不是证据而是噪声, 当"没有 deficit 信号"处理。
	// 真·50% 丢包会先把 goodput 打到地板, 由看门狗兜底。
	deficitImplausible = 0.50

	// === deficit 的结构性底噪修正 ===
	// shaper_sent 是线路字节 (含 IP+TCP 头), bytes_acked 是净荷字节: 一个满 MSS 的包
	// 1514B 里有 66B 是头 —— 4.4% 的 deficit 是记账口径差, 不是丢包。
	// ★ 不扣掉它, deficitClear(5%) 在语义上就几乎不可达: 底噪 4.4% 再叠一点点重传
	// (而这条链路的设计意图就是"高重传是常态") 就永远跨不过去, BACKOFF 于是变成一个
	// 锁存器 —— 进要 deficit>10%, 出要 <5%, 重传率落在中间时进得去出不来。
	headerBytesPerSeg = 66.0
	// 头开销修正的上限。segs_out 只覆盖有本地 socket 的流量, shaper_sent 覆盖全部
	// 出口 (含转发/隧道), 两边分母本来就不同口径; 修正量必须夹住, 否则一次口径错位
	// 就能把 deficit 抹成 0, 把丢包信号整个吃掉。
	deficitHeaderCapFrac = 0.25
	// 判定"deficit 不是 R 造成的"之后, 本 regime 的 deficit 门限整体上抬的上限。
	// 上抬后的 BACKOFF 门限不能超过 deficitImplausible —— 超过那条线的采样根本不会
	// 进 EMA, 门限设在它之上等于又造一个不可达的出口。
	deficitBiasMax = deficitImplausible - deficitBackoff
	// 底噪偏置的衰减: 一旦重新看到绝对干净的 deficit, 说明结构性底噪没了, 偏置要收
	// 回去。只上不下的偏置本身就是另一个单向棘轮。
	deficitBiasDecay = 0.9

	// 降 R 类动作的连续确认拍数 (规格: "连续 2 周期确认")。
	shaperConfirmCycles = 2

	// === SEEK ===
	seekGain        = 1.5  // 每拍 R *= 1.5
	seekStopDelayMs = 50.0 // E_remote 超过它就停止上探

	// === HOLD 的 E_remote trim ===
	trimGain       = 0.98 // 逐步 trim, 不是一刀切
	eRemoteFloorMs = 30.0 // 远端排队预算的绝对地板
	eRemoteRttFrac = 0.2  // 以及 minRtt 的比例项, 取两者较大

	// === PROBE ===
	probeGain         = 1.25 // 上探幅度
	probeAcceptFrac   = 0.5  // goodput 增量 >= probe 幅度一半才采纳
	probeIntervalBase = 6    // 基础间隔 (拍)
	probeIntervalMax  = 24   // 指数退避上限 6->12->24

	// === BACKOFF ===
	backoffGain = 0.85 // 每拍 R *= 0.85
	// BACKOFF 的硬上限。R *= 0.85 连压 8 拍 = 0.27, 早就撞上 0.3*C_hat_regime 的地板;
	// 还没清零就说明 deficit 根本不是 R 造成的, 继续压是纯粹的吞吐损失。
	backoffMaxCycles = 8
	// BACKOFF 里连续这么多拍拿不到新鲜 deficit (无流量, 或口径不可信) 就冻结 R 复出。
	backoffIdleCycles = 5

	// === C_hat 滤波器 (与 BBR 的 bw filter 同构) ===
	cWindowLen = 3
	cHatDecay  = 0.98

	// === 四层护栏 ===
	// 护栏 1: 绝不把链路勒死。R_min = max(2Mbps, 0.3*C_hat_regime)。
	rateFloorBps = 2e6
	rateMinFrac  = 0.3
	// 护栏 2: 读不到网卡线速时的 R_max 兜底。取一个高到"等价于整形关闭"的值 ——
	// 失败方向必须是 fail-open (R=R_max = 今天的现状), 绝不能是 fail-closed。
	defaultRateMaxMbps = 10000
	// 护栏 3: 看门狗。有需求 (qlen>0) 却几乎没有 goodput, 连续 3 拍 -> 控制器
	// 自认失效, 让位到 R_max。
	watchdogCycles        = 3
	watchdogGoodputBps    = 1e6
	watchdogRecoverCycles = 3
	// 复出所需的干净拍数按 yield 次数指数退避 (3->6->12->24)。固定 3 拍的话, 反复
	// yield 不涨代价, YIELD<->SEEK 之间可以无限对撞。
	watchdogRecoverMax = 24

	// band 切换的确认拍数。pickBand 原本每拍无状态重选, 而 RTT 档边界 (如 far/
	// intercontinental 的 250ms) 上的 minRtt 抖动会让选择每两拍翻一次: 实测
	// minRtt 在 251-255ms 之间摆, 一条 socks=1 的 far 档反复夺走控制信号, 并在
	// util=0.13 时靠它的 E 触发了 SEEK->HOLD 的 latch。候选档必须连续赢下这么多拍
	// 才真正接管, 期间继续用旧档 (旧档还活着的话)。
	bandConfirmCycles = 3

	// regime 切换的确认拍数。一次 regime 切换的代价是 C_hat 清零 + 强制回 SEEK +
	// 慢层冻结, 换路又是低频事件, 不能被单拍噪声触发 (原来就是单拍立即触发)。
	regimeConfirmCycles = 3

	// === 冷启动 / 缓存 ===
	observeCycles     = 5 // 10s / 2s
	cacheSeedFrac     = 0.7
	cacheWriteCycles  = 30 // HOLD 连续稳定 60s / 2s 回写一次
	shaperCacheMaxAge = 7 * 24 * time.Hour

	// 慢层步进闸门: shaper 必须在 HOLD 且连续稳定这么多拍。
	holdStableForSlowLayer = 3

	// R 的历史环长度, 供 score() 的 CV 惩罚 (惩罚控制器自己抖 R)。
	rRingLen = 8

	// 慢层 headroom 臂是以百分数存的整数 (tunable 是 int 的), 换算回小数用。
	headroomPctScale = 100.0

	// ackedSentSanityRatio: 确认字节 / 本网卡发出字节 的物理上界。acked 是净荷、
	// sent 是线路字节, 正常方向恒是 acked < sent; 反过来超这个比例只可能是采样口径
	// 错 (混进别的网卡, 或 socket churn 把 lifetime 值当成了增量), 不可能是噪声。
	ackedSentSanityRatio = 1.5
)

// shaperSample 是一拍的全部原始观测。step() 只吃这个结构 —— 所有 I/O 都在
// tick() 里做完, 控制律本身是纯函数, 可以直接跑单测。
type shaperSample struct {
	dt           float64 // 本拍实际时长 (s)
	sentBytes    uint64  // Δshaper_sent —— 整形器实际放行的字节 (线路字节, 含头)
	ackedBytes   uint64  // Δbytes_acked —— 被对端确认的字节 (机器全量, 净荷)
	segsOut      uint64  // Δsegs_out —— 用来把线路头开销从 deficit 里扣掉
	backlogBytes uint64  // 瞬时本机排队字节
	qlen         uint64  // 瞬时排队包数 (看门狗的"有需求"判据)
	// minRttMs 是各 socket minrtt 的 **中位数** (ssTargetStat.minRttP50Ms), 不是全局
	// 最小值 —— 全局 min 在混合流量的机器上会被短命的本地 socket 拽着跳, 每跳一次就
	// 是一次假 regime 切换。口径与 queueDelayMs 一致 (都是每 socket 各自成立后取中位)。
	minRttMs     float64
	srttMs       float64 // 各 socket srtt 均值
	queueDelayMs float64 // 各 socket (srtt-minrtt) 的中位数 = E
	haveLink     bool    // 本拍拿到了可用的 ss 信号 (否则 deficit 不更新)
}

// shaper 是快环控制器。跨 goroutine 被 optimizer 读 (慢层闸门 / score 的 CV 项)
// 和写 (headroom 臂), 所有共享字段都在 mu 下。
type shaper struct {
	mu sync.Mutex

	iface string
	// target: --target 指定的对端 IP。非空时所有 ss 采样只看这条链路的 socket ——
	// 快环的 minRtt/srtt/queueDelay 必须同源, 否则 regime 判定拿的是别人的 RTT。
	target string
	state  string

	rate     float64 // 当前 R (bit/s)
	rateMin  float64 // 护栏 1
	rateMax  float64 // 护栏 2
	headroom float64 // R = headroom * C_hat, 慢层可调 (0.85..1.05)

	// C_hat: 容量估计。cWin 是 3 窗口 max-filter 的环, cHatRegime 是本 regime 里
	// 确认过的容量 (只用来算 R_min 地板, 所以 BACKOFF 不下调它 —— 那正是地板存在
	// 的意义)。
	cHat          float64
	cWin          []float64
	cHatRegime    float64
	cHatConfirmed bool

	// 派生信号 (每拍重算, 也供日志和 optimizer 观察)
	util       float64
	goodput    float64
	deficitEMA float64
	eRemote    float64

	deficitPrimed bool
	// deficitBias 是本 regime 里已经被证伪为"不是 R 造成的"那部分 deficit —— 所有
	// deficit 判据都相对它抬高。BACKOFF 压满还清不掉的时候写入, 重新看到干净 deficit
	// 时衰减回去, regime 切换清零。
	deficitBias float64
	deficitHiN  int
	delayHiN    int
	watchdogN   int
	recoverN    int
	// recoverNeed 是 YIELD 复出所需的干净拍数, 每次 yield 翻倍 (护栏 3 的指数退避)。
	recoverNeed int
	// backoffN/backoffIdleN 是 BACKOFF 的两个终止计数器 (见 stShaperBackoff)。
	backoffN     int
	backoffIdleN int
	// regimeHiN 是 regime 切换的连续确认拍数。
	regimeHiN int

	probeCountdown   int
	probeInterval    int
	probeFromRate    float64
	probeBaseGoodput float64

	obsGoodputs []float64

	regimeMinRtt float64
	peer         string
	band         string
	// pickedBand 是当前在用的 RTT 档; bandHiN 是候选档连续胜出的拍数 (迟滞)。
	pickedBand string
	bandHiN    int
	// rc 判定一个 socket 的流量是否真的经过被整形的网卡 (见 routecache.go)。
	rc *routeCache

	// holdStable 是慢层闸门用的"连续稳定拍数": PROBE/trim/BACKOFF 都会把它清零,
	// 因为那几拍速率在动, 慢层这时候步进就归因不了。
	holdStable int
	// cacheAge 是缓存回写计时器, 必须跟 holdStable 分开: 每 6 拍就来一次的例行
	// PROBE 会把 holdStable 清零, 而 probeIntervalBase(6) < cacheWriteCycles(30),
	// 共用一个计数器的话缓存永远写不出去 —— 一条"看起来在跑其实是死代码"的路径。
	// cacheAge 只在真正换了容量前提的时候清零 (regime 切换 / BACKOFF / 写完)。
	cacheAge int

	rRing []float64

	// 累计计数器基线 (tick() 里差分用)
	prevSent  uint64
	prevAcked uint64
	prevSegs  uint64
	primed    bool

	// 依赖注入, 让 step() 保持纯净且可测。
	logf        func(string, ...any)
	detectPeer  func() string
	cacheLookup func(key string) (float64, bool) // -> kbps
	cacheStore  func(key string, kbps float64)
	lastTick    time.Time
	unsupported bool // 内核不导出 shaper 键 -> 整个快环禁用
}

// newShaper 建控制器并做冷启动决策。rateMaxMbps<=0 时从网卡线速推断。
//
// 冷启动三条路 (规格 C1):
//  1. model.json 的 shaper_cache 命中 -> R = 0.7*缓存值, 进 SEEK
//  2. 无缓存 -> 前 10s R=R_max 纯观测, 取 goodput 中位数 g0, R = 1.2*g0 进 SEEK
//  3. 完全无流量 -> HOLD at R_max, 等 util 信号 (在 OBSERVE 结束时分流)
func newShaper(iface, target string, rateMaxMbps float64) *shaper {
	s := &shaper{
		target:        target,
		iface:         iface,
		state:         stShaperObserve,
		headroom:      0.95,
		probeInterval: probeIntervalBase,
		logf: func(f string, a ...any) {
			fmt.Printf("%s SHAPER "+f+"\n", append([]any{time.Now().Format("15:04:05")}, a...)...)
		},
		detectPeer:  autoDetectPeer,
		cacheLookup: modelShaperCacheGet,
		cacheStore:  modelShaperCacheSet,
		lastTick:    time.Now(),
	}
	// 路由判定缓存: 控制信号只能来自真正经过 iface 的 socket, 否则 deficit 的
	// 分子 (shaper_sent, 只含本网卡) 和分母 (acked) 是两批不相干的流量。
	s.rc = newRouteCache(iface, s.logf)
	s.rateMax = rateMaxMbps * 1e6
	if s.rateMax <= 0 {
		bps, known := ifaceLineRateBps(iface)
		s.rateMax = bps
		if !known {
			// 静默用 10Gbps 兜底是有害的: 之后所有"相对 R_max"的判据 (尤其 util =
			// Δsent/(R_max*T)) 都在拿一个策略常数当物理量比。virtio 网卡上 100Mbps
			// 满载算出来的 util 是 0.01, 永远够不到 utilBind —— 必须让人看见。
			s.logf("WARNING: %s reports no line rate (virtual NIC) — R_max falls back to %d Mbps, "+
				"which is a policy constant, NOT the physical ceiling. Pass --shaper-max-mbps "+
				"with the real uplink so util/R_max judgements mean something.",
				iface, defaultRateMaxMbps)
		}
	}
	s.rate = s.rateMax
	s.rateMin = rateFloorBps

	// 内核支持探测。用 nqReader (而不是裸 readNeoqML) 是必须的: 裸读会把内核那个
	// read-on-reset 的 Express 峰值清掉, 慢环的体验项就白丢一次采样。
	if nq, ok := nqReader.read(false); !ok || !nq.shaperOK {
		s.unsupported = true
		s.logf("kernel does not export the shaper keys — fast loop idle, behavior stays exactly as today (no shaping)")
		_ = writeNeoqRate(0)
		return s
	}

	// 冷启动 1: 缓存命中。band 需要 minRtt, 此刻还没有测量, 所以先用当前链路的
	// 一次性快照探一下; 探不到就走 OBSERVE (路 2/3)。
	st := s.sampleStat()
	s.peer = s.detectPeer()
	if mr := shaperMinRtt(st); mr > 0 {
		s.regimeMinRtt = mr
		s.band = rttBand(mr)
		if kbps, ok := s.cacheLookup(s.cacheKey()); ok && kbps > 0 {
			s.rate = clampF(cacheSeedFrac*kbps*1000, s.rateMin, s.rateMax)
			s.state = stShaperSeek
			s.logf("cold start from cache %s: %.0f kbps -> R=%.1f Mbps, SEEK",
				s.cacheKey(), kbps, s.rate/1e6)
		}
	}
	if s.state == stShaperObserve {
		s.logf("cold start: no cache, observing %v at R_max=%.0f Mbps",
			time.Duration(observeCycles)*shaperTick, s.rateMax/1e6)
	}
	return s
}

// ifaceLineRateBps 读 /sys/class/net/<iface>/speed (Mbps)。虚拟网卡常常报 -1 或
// "Unknown!" —— 那时候用 defaultRateMaxMbps 兜底, 因为 R_max 的唯一职责是"永远
// 存在一条退回今天行为的路", 宁可高到形同虚设, 也绝不能猜低把链路勒死。
// known=false 就是"这个 R_max 是兜底常数"的标记, 调用方必须告警: 目标机器就是
// virtio VPS, 静默兜底会让所有相对 R_max 的判据在生产上默默失效。
func ifaceLineRateBps(iface string) (float64, bool) {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/speed")
	if err == nil {
		if v, e := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); e == nil && v > 0 {
			return v * 1e6, true
		}
	}
	return defaultRateMaxMbps * 1e6, false
}

// sampleStat 取本拍的 ss 统计。有 --target 就只看那条链路 —— 快环的 minRtt 决定
// regime 分档, 而 regime 一切换 C_hat 就清零; 用全机口径的话, 这台机器上并存的
// 近端 socket (实测 0.9ms) 和洲际 socket (169ms) 会让它在两个档之间反复横跳,
// 控制器永远到不了 HOLD。实测: 全机口径下 10 秒内切换两次, C_hat 反复归零。
// 注意样本量小的时候中位数救不了这件事 —— n=2 时中位数就是平均值, 一样跳。
func (s *shaper) sampleStat() ssTargetStat {
	if s.target != "" {
		return ssTarget(s.target) // 显式指定一条链路时不做自动选档
	}
	bands := ssBands(s.rc, ssMaxSocks)
	st, band := pickBand(bands)
	if band == "" || band == s.pickedBand {
		s.bandHiN = 0
		return st
	}
	// 候选档与在用档不同: 先攒确认拍数, 期间继续用旧档 —— 只要旧档还有 socket。
	// 旧档整个消失时立即切换 (没有可继续的选择, 攒拍数只会让控制器盲一段)。
	s.bandHiN++
	if old, ok := bands[s.pickedBand]; ok && old.socks > 0 && s.bandHiN < bandConfirmCycles {
		return old
	}
	s.logf("band -> %s (minRtt=%.0fms E=%.0fms socks=%d) — 控制信号改取此档",
		band, st.minRttP50Ms, st.queueDelayMs, st.socks)
	s.pickedBand = band
	s.bandHiN = 0
	return st
}

// pickBand 从各 RTT 档里选出该驱动 R 的那一档。
//
// 判据不是"哪档流量大", 而是"哪档有远端排队" —— 整形的全部作用是把队列从够不着
// 的远端搬回本机, 一个档如果 E 很小, 它根本没有队列可搬, 对它限速纯粹是白扔带宽。
// 只有都没排队时才退回按字节选, 那种情况下 R 会停在 R_max (= 不整形), 选谁都一样,
// 选字节大的只是让 util 判据有个合理的分母。
//
// 这是"target 默认覆盖全部连接"的实现: 不需要手工指定 IP, 每拍自动认出当前真正
// 需要整形的那一类路径。代价是 shaper 仍然只有一个全局 rate, 所以被选中档的限速
// 会同时作用于其它档 —— 在洲际流量占主导的出口上可接受, 彻底解决要靠 NeoQ 侧的
// 多 rate class (按目的地分类整形)。
func pickBand(bands map[string]ssTargetStat) (ssTargetStat, string) {
	var best ssTargetStat
	var bestBand string
	var bestQueued bool
	for b, st := range bands {
		if st.socks == 0 {
			continue
		}
		queued := st.queueDelayMs > eRemoteFloorMs
		switch {
		case bestBand == "":
		case queued && !bestQueued: // 有排队的档一律优先于没排队的
		case queued == bestQueued && st.acked > best.acked:
		default:
			continue
		}
		best, bestBand, bestQueued = st, b, queued
	}
	return best, bestBand
}

// shaperMinRtt 取 shaper 该用的那个 minRtt: 各 socket minrtt 的中位数。只有在
// 中位数拿不到 (没有一个 socket 报 minrtt) 时才退回全局 min —— 那种情况下两者
// 都是 0, 退回只是保持旧行为不引入新分支。
func shaperMinRtt(st ssTargetStat) float64 {
	if st.minRttP50Ms > 0 {
		return st.minRttP50Ms
	}
	return st.minRttMs
}

// rttBand 把 minRtt 分成粗粒度的路径档。缓存键的一半 (另一半是对端 IP): 同一个
// 对端在不同时段可能走不同路由 (159ms 的直连 vs 绕行), 那是两条物理上不同的路,
// 容量不能混用。分档边界故意粗 —— 细了每次抖动都算换 regime, 缓存永远命中不了。
func rttBand(minRttMs float64) string {
	switch {
	case minRttMs <= 0:
		return "unknown"
	case minRttMs < 20:
		return "lan"
	case minRttMs < 60:
		return "regional"
	case minRttMs < 120:
		return "continental"
	case minRttMs < 250:
		return "intercontinental"
	default:
		return "far"
	}
}

func (s *shaper) cacheKey() string { return s.peer + "|" + s.band }

// setCHat 是"权威重估": 除了改 C_hat 本身, 还必须把 max-filter 的环清空重播种。
// 否则环里 3 拍前的旧高值会在下一拍把刚 trim/backoff 下去的估计原样顶回来 ——
// 这是本控制律最容易踩的一个坑。
func (s *shaper) setCHat(v float64) {
	if v < 0 {
		v = 0
	}
	s.cHat = v
	s.cWin = []float64{v}
}

// deficitThresh 把一个 deficit 判据抬到本 regime 的结构性底噪之上。所有 deficit
// 门限 (SEEK 停止 / BACKOFF 进入 / BACKOFF 退出 / feedCHat 的取样选择) 都必须走
// 这里, 否则"抬高门限"只抬了一半, 状态机会在两套坐标系之间打架。
func (s *shaper) deficitThresh(base float64) float64 { return base + s.deficitBias }

// latchCHat 把一拍的 goodput 当"权威容量观测"锁存 —— 但先做记账一致性检查。
//
// ★ 原来是无条件 setCHat(s.goodput)。deficit 有 deficitImplausible 这道可信度门,
// goodput 却一道都没有, 而它才是被直接锁存成容量的那个量。这台机器上大量出口是
// 转发/隧道流量, 没有本地 socket, Δbytes_acked 根本覆盖不了 Δshaper_sent。实测:
// SEEK 在 R=200Mbps、util=1.0, 远端排队 300ms 触发 delayed, 但 ss 只看得见 1.5Mbps
// 的 acked —— 一拍之内 R 从 200Mbps 塌到 2Mbps 地板, 而看门狗的门槛是 goodput<1Mbps,
// 测到的 1.5Mbps 恰好骑在门槛之上, 护栏永不触发。
//
// 判据与 deficit 的可信度门同源: 绑定 (util>=utilBind) 时若 goodput 连 R 的
// (1-deficitImplausible) 都不到, 那不是"路径只送到了这么多", 而是 acked 侧没覆盖
// sent 侧。这时候退回 R*(1-deficitEMA) —— 用同样被可信度门过滤过的 deficit 去折算,
// 而不是把一个记账缺口锁存成容量。
func (s *shaper) latchCHat(g float64) {
	if s.util >= utilBind && g < (1-deficitImplausible)*s.rate {
		fallback := s.rate * (1 - s.deficitEMA)
		s.logf("goodput %.1f Mbps not credible at R=%.1f Mbps util=%.2f (acked side does not cover sent side) "+
			"— C_hat falls back to R*(1-deficit)=%.1f Mbps instead of latching",
			g/1e6, s.rate/1e6, s.util, fallback/1e6)
		s.setCHat(fallback)
		return
	}
	s.setCHat(g)
}

// feedCHat 把一拍的"容量观测"折进 3 窗口 max-filter (+ 每拍 0.98 衰减)。
//
// 关键点 —— 什么样的一拍才算容量观测:
//   - util < utilBind: 不算。需求受限时 goodput 说的是"应用发了多少", 跟路径容量
//     无关, 喂进去只会让 C_hat 跟着需求塌下去。
//   - util >= utilBind 且 deficit 低: R 全额送达且没造成丢失 => 容量 >= R。与当前
//     headroom 策略自洽的估计是 R/headroom (≈ C_hat 本身), 喂它等于给滤波器续期。
//     ★ 这里绝不能喂原始 goodput: HOLD 期间 goodput≈R=headroom*C_hat < C_hat,
//     喂它会让 C_hat 每拍掉一个 headroom, R 几何级坍缩 (0.95^n) —— 规格字面实现
//     会踩的一个真 bug。
//   - util >= utilBind 且 deficit 高: R 超过了路径能承载的量, 那实际送达的 goodput
//     就是容量观测本身。
//
// 衰减也只在绑定的拍上生效: 衰减的职责是让"过期的高估计"老化, 而只有我们真的在往
// 上顶的时候, 这个估计才被检验到 —— 需求低于 R 时估计根本没被测试, 安全的做法是
// 保持而不是缩向一个与容量无关的需求水平。
func (s *shaper) feedCHat() {
	if s.util < utilBind {
		return
	}
	sample := s.goodput
	if s.deficitEMA <= s.deficitThresh(deficitBackoff) && s.headroom > 0 {
		sample = s.rate / s.headroom
	}
	s.cWin = append(s.cWin, sample)
	if len(s.cWin) > cWindowLen {
		s.cWin = s.cWin[1:]
	}
	mx := 0.0
	for _, v := range s.cWin {
		if v > mx {
			mx = v
		}
	}
	if decayed := s.cHat * cHatDecay; mx > decayed {
		s.cHat = mx
	} else {
		s.cHat = decayed
	}
}

// step 是控制律本体 —— 纯函数 (只读 sm, 只写 s), 单测直接驱动它。
// 调用方负责持有 s.mu。
func (s *shaper) step(sm shaperSample) {
	dt := sm.dt
	if dt <= 0 {
		dt = shaperTick.Seconds()
	}

	// ---- 三个因果分离信号 ----
	sentBits := float64(sm.sentBytes) * 8
	ackedBits := float64(sm.ackedBytes) * 8
	s.goodput = ackedBits / dt

	// util = Δshaper_sent*8 / (R*T): shaper 是否绑定。
	s.util = 0
	if s.rate > 0 {
		s.util = sentBits / (s.rate * dt)
	}

	// canary: 确认过的字节不可能显著多于本网卡发出的字节。超了就说明采样口径漏了
	// —— acked 侧混进了不经本网卡的流量。实测踩过一次: 95% 的 acked 来自 docker
	// bridge, 让控制器在 util=0.02 时锁存了 19.1 Mbps 的假容量。
	// latchCHat 的可信度门只防 goodput 偏**低** (记账缺口), 这里补的是偏**高**的另一半。
	// 1.5 的余量: acked 是净荷、sent 是线路字节, 正常方向是 acked < sent, 反过来超
	// 50% 只可能是口径错, 不可能是测量噪声。
	if sentBits > 0 && ackedBits > ackedSentSanityRatio*sentBits {
		s.logf("acked (%.1f Mb) 远超本网卡 sent (%.1f Mb) — 采样口径漏了, "+
			"检查 %s 的路由过滤", ackedBits/1e6, sentBits/1e6, s.iface)
	}

	// deficit = (Δsent_净荷 - Δacked)/Δsent_净荷, 3 拍 EMA。
	//
	// ★ 分母必须先扣掉线路头开销。原来直接拿线路字节当分母, 于是满 MSS 包 66/1514 =
	// 4.4% 的头开销被算成"丢了 4.4%"。这条链路的设计意图又是"高重传是常态", 底噪常年
	// 骑在 deficitClear(5%) / deficitBackoff(10%) 这条滞环中间 —— BACKOFF 一旦进去,
	// 出口条件在语义上就不可达了 (实测 400 拍后 R 永久停在 0.3*C_hat_regime 地板)。
	// 扣掉头开销之后, 阈值对着的才是真实丢失。
	//
	// deficitFresh 记录"本拍 deficit 真的被刷新了"。所有依赖 deficit 的下压动作都必须
	// 看它: 原来 BACKOFF 无条件读 deficitEMA, 需求消失 (sentBytes=0) 时 EMA 冻结在
	// 120 秒前的读数上, 却还在每拍砍 15% 一路砍到地板。ACK 滞后 1 RTT 的抖动仍由
	// 3 拍 EMA 吸收。
	deficitFresh := false
	if sm.haveLink && sm.sentBytes > 0 {
		overheadBits := float64(sm.segsOut) * headerBytesPerSeg * 8
		if maxOv := sentBits * deficitHeaderCapFrac; overheadBits > maxOv {
			overheadBits = maxOv
		}
		if payloadBits := sentBits - overheadBits; payloadBits > 0 {
			d := clampF((payloadBits-ackedBits)/payloadBits, 0, 1)
			if d < deficitImplausible {
				if !s.deficitPrimed {
					s.deficitEMA, s.deficitPrimed = d, true
				} else {
					s.deficitEMA += (d - s.deficitEMA) / deficitEMAWin
				}
				deficitFresh = true
			}
		}
	}

	// 延迟分解: E = srtt - minrtt; L_local = backlog*8/R; E_remote = E - L_local。
	// L_local 归 CoDel 管 (本机队列, AQM 够得着), 只有 E_remote 才是 R 的责任域。
	lLocal := 0.0
	if s.rate > 0 {
		lLocal = float64(sm.backlogBytes) * 8 / s.rate * 1000
	}
	s.eRemote = sm.queueDelayMs - lLocal
	if s.eRemote < 0 {
		s.eRemote = 0
	}

	// 天气门: util<0.9 时的丢包/RTT 尖峰一律不动 R。badLink 复用 optimizer 的
	// 3x minRtt 判据, 只进日志 —— 真正的闸门是 util, 因为"我没在控制"才是"这不是
	// 我造成的"的充分证据。
	weatherHold := s.util < utilWeather
	badLink := isBadLink(sm.srttMs, sm.minRttMs)

	// ---- regime 切换 (与 optimizer B4 unfreeze 同一判据: minRtt 漂移 >= 2x) ----
	// ★ 必须连续 regimeConfirmCycles 拍确认。原来是单拍立即触发, 而 sm.minRttMs 在
	// 混合流量的机器上抖得很凶 (这也是它改用 p50 而不是全局 min 的原因) —— 一拍噪声
	// 就换一次 regime, 代价是 C_hat 清零 + 强制回 SEEK + 慢层冻结, 实测 20 拍里触发
	// 19 次, 永远到不了 HOLD。真换路是持续性的, 3 拍确认对它毫无损失。
	if sm.minRttMs > 0 {
		if s.regimeMinRtt <= 0 {
			s.regimeMinRtt = sm.minRttMs
			s.band = rttBand(sm.minRttMs)
			s.regimeHiN = 0
		} else if r := sm.minRttMs / s.regimeMinRtt; r >= 2 || r <= 0.5 {
			s.regimeHiN++
			if s.regimeHiN >= regimeConfirmCycles {
				s.enterRegime(sm.minRttMs)
				s.clampRate()
				s.pushRRing()
				return
			}
		} else {
			s.regimeHiN = 0
		}
	}

	// ---- 护栏 3: 看门狗 ----
	// 有需求 (qlen>0) 却几乎没 goodput, 连续 3 拍 => 控制器自认失效, 主动让位。
	if sm.qlen > 0 && s.goodput < watchdogGoodputBps {
		s.watchdogN++
		if s.watchdogN >= watchdogCycles && s.state != stShaperYield {
			// 复出门槛指数退避 3->6->12->24。固定 3 拍时反复 yield 不涨代价, 于是
			// YIELD 和 SEEK 可以无限对撞 (实测 240s 里来回 17 次)。
			need := s.recoverNeed * 2
			if need < watchdogRecoverCycles {
				need = watchdogRecoverCycles
			}
			s.recoverNeed = minInt(need, watchdogRecoverMax)
			s.logf("WATCHDOG: qlen=%d goodput=%.2f Mbps for %d cycles — controller yields, R=R_max=%.0f Mbps "+
				"(re-arm needs %d clean cycles)",
				sm.qlen, s.goodput/1e6, s.watchdogN, s.rateMax/1e6, s.recoverNeed)
			s.state = stShaperYield
			s.rate = s.rateMax
			s.setCHat(0)
			s.cHatRegime = 0
			s.recoverN = 0
			s.holdStable = 0
			s.clampRate()
			s.pushRRing()
			return
		}
	} else {
		s.watchdogN = 0
	}

	switch s.state {
	case stShaperYield:
		// 让位态: 停在 R_max (等价于整形关闭 = 今天的行为)。连续几拍看起来恢复
		// 正常才重新接管 —— 永久让位对一次瞬时天气过于严厉, 立刻重试又会来回抖。
		s.rate = s.rateMax
		need := s.recoverNeed
		if need <= 0 {
			need = watchdogRecoverCycles
		}
		if sm.qlen == 0 || s.goodput >= watchdogGoodputBps {
			s.recoverN++
			if s.recoverN >= need {
				s.logf("watchdog recovered (%d clean cycles) — re-arming SEEK", s.recoverN)
				s.state = stShaperSeek
				s.recoverN = 0
				s.deficitPrimed = false
			}
		} else {
			s.recoverN = 0
		}

	case stShaperObserve:
		// 冷启动路 2/3: R=R_max 纯观测, 不做任何控制。
		s.rate = s.rateMax
		s.obsGoodputs = append(s.obsGoodputs, s.goodput)
		if len(s.obsGoodputs) >= observeCycles {
			g0 := percentile(s.obsGoodputs, 0.5)
			s.obsGoodputs = nil
			if g0 <= 0 {
				// 路 3: 完全无流量 —— HOLD 在 R_max 等 util 信号。
				s.setCHat(0)
				s.state = stShaperHold
				s.logf("observe done: no traffic (median goodput 0) — HOLD at R_max, waiting for util")
			} else {
				s.rate = 1.2 * g0
				s.state = stShaperSeek
				s.logf("observe done: g0=%.1f Mbps -> R=%.1f Mbps, SEEK", g0/1e6, s.rate/1e6)
			}
		}

	case stShaperSeek:
		// 冷启动/regime 切换: 每拍 *1.5 上探, 直到顶到墙。
		bound := s.util >= utilBind && s.deficitEMA > s.deficitThresh(deficitSeekStop)
		delayed := s.eRemote > seekStopDelayMs
		switch {
		case bound || delayed:
			why := "deficit"
			if delayed {
				why = "E_remote"
			}
			s.latchCHat(s.goodput)
			s.cHatRegime = s.cHat
			s.cHatConfirmed = false
			s.rate = s.headroom * s.cHat
			s.state = stShaperHold
			s.probeCountdown = s.probeInterval
			s.holdStable = 0
			s.logf("SEEK->HOLD (%s: util=%.2f deficit=%.1f%% E_remote=%.0fms) C_hat=%.1f Mbps R=%.1f Mbps",
				why, s.util, s.deficitEMA*100, s.eRemote, s.cHat/1e6, s.rate/1e6)
		case s.rate >= s.rateMax:
			// 一路顶到线速都没找到墙 => shaper 不是约束, 停在 R_max 空转。
			s.setCHat(0)
			s.state = stShaperHold
			s.logf("SEEK reached R_max=%.0f Mbps without binding — HOLD at R_max (shaper not the constraint)", s.rateMax/1e6)
		default:
			s.rate *= seekGain
		}

	case stShaperHold:
		if s.cHat <= 0 {
			// 空载 HOLD: 没有容量估计, 停在 R_max (= 整形事实关闭)。
			s.rate = s.rateMax
			// ★ holdStable 必须照常累加。原来这里每拍清零, 于是 slowLayerReady() 恒为
			// false —— 打开 --shaper 反而把整个慢环 optimizer 永久冻结了。这个分支里
			// 整形事实上是关的 (R=R_max), 对慢层的归因没有任何污染, 没有理由冻结它。
			s.holdStable++
			// ★ 出口判据不能用 util。util = Δsent*8/(R_max*T), 而 R_max 在虚拟网卡上
			// 读不到线速时是 defaultRateMaxMbps 的兜底常数 —— 不是物理量。目标机器就是
			// virtio VPS: 100Mbps 满载算出来的 util = 0.01, 永远够不到 utilBind(0.95),
			// 这个状态于是成了吸收态, 整形器变成死代码 (三条进入路径都可达)。
			//
			// 换成"整形能不能改善什么"的绝对判据: 远端排队超过 SEEK 自己的停止门限,
			// 说明队列堆在够不着的远端路由器上 —— 那正是 R 存在的全部理由; 或者 util
			// 真的绑定了 (R_max 是真线速的情况, 老判据继续有效)。
			// 故意不用 qlen>0 / goodput>0 这类纯需求判据: 在 R_max 本来就不是约束的
			// 链路上, 那会造出 SEEK->顶到 R_max->空载 HOLD->再 SEEK 的极限环, R 每十
			// 几秒抖一遍, 而且半数时间不在 HOLD, 慢层照样被冻。用 SEEK 的同一个停止
			// 门限当入口, 保证进去的第一拍就能锁存, 不会来回。
			//
			// util 那一支必须**逐字**对齐 SEEK 的 bound (连 deficit 一起), 不能只写
			// util >= utilBind: 出口条件一旦弱于 SEEK 的停止条件, 就是"出得去、停不下",
			// 于是 idle HOLD -> SEEK -> 每拍 *1.5 顶到 R_max -> setCHat(0) -> 回 idle HOLD,
			// 周期 2 的极限环, holdStable 每拍被清零 -> slowLayerReady() 恒 false, 慢层
			// 照样被永久冻结 —— 正是上面那段注释想消灭的后果, 只是换了一支进来。
			// 复现条件: R_max 是真线速 (裸金属/e1000, 或运维按 WARNING 加了
			// --shaper-max-mbps) + 链路能顶满 + 丢包 <=5% + 远端排队 <=50ms。
			// 洲际高丢包路径上 bound 第一拍就成立, 碰不到; 干净的洲内路径会踩中。
			if s.goodput > 0 && (s.eRemote > seekStopDelayMs ||
				(s.util >= utilBind && s.deficitEMA > s.deficitThresh(deficitSeekStop))) {
				s.rate = 1.2 * s.goodput // 重新播种, 否则 SEEK 从 R_max 起步会立刻弹回来
				s.state = stShaperSeek
				s.holdStable = 0
				s.logf("idle HOLD saw a queue worth pulling home (E_remote=%.0fms util=%.2f goodput=%.1f Mbps) "+
					"— SEEK from R=%.1f Mbps", s.eRemote, s.util, s.goodput/1e6, s.rate/1e6)
			}
			break
		}
		s.cacheAge++
		moved := false
		// 底噪偏置的回收: 重新看到绝对干净的 deficit 就说明当初那份结构性缺口没了。
		if s.deficitBias > 0 && deficitFresh && s.deficitEMA < deficitClear {
			if s.deficitBias *= deficitBiasDecay; s.deficitBias < 0.005 {
				s.deficitBias = 0
			}
		}
		// R>C 确认 -> BACKOFF。三个必要前提:
		//   util>=0.95  —— 只有绑定的时候 deficit 才是"我造成的路径丢失", 否则是天气
		//   deficitFresh —— ★ 本拍 deficit 真的被刷新过。少了它, haveLink 掉线时
		//                   deficitEMA 冻结在旧读数上, 却还能把状态机推进 BACKOFF
		//   超过底噪偏置 —— 已经被证伪为"不是 R 造成的"那部分不能重复计入
		if !weatherHold && deficitFresh && s.util >= utilBind && s.deficitEMA > s.deficitThresh(deficitBackoff) {
			s.deficitHiN++
			if s.deficitHiN >= shaperConfirmCycles {
				s.logf("HOLD->BACKOFF (util=%.2f deficit=%.1f%% > %.1f%% confirmed %dx) R=%.1f Mbps",
					s.util, s.deficitEMA*100, s.deficitThresh(deficitBackoff)*100, s.deficitHiN, s.rate/1e6)
				s.state = stShaperBackoff
				s.deficitHiN = 0
				s.backoffN, s.backoffIdleN = 0, 0
				s.holdStable, s.cacheAge = 0, 0
				s.clampRate()
				s.pushRRing()
				return
			}
		} else {
			s.deficitHiN = 0
		}
		// 远端排队超预算 -> 逐步 trim。预算 = max(30ms, 0.2*minRtt)。
		budget := math.Max(eRemoteFloorMs, eRemoteRttFrac*sm.minRttMs)
		if !weatherHold && s.eRemote > budget {
			s.delayHiN++
			if s.delayHiN >= shaperConfirmCycles {
				s.setCHat(s.cHat * trimGain)
				s.delayHiN = 0
				s.holdStable = 0
				moved = true
				s.logf("HOLD trim (E_remote=%.0fms > budget %.0fms confirmed) C_hat=%.1f Mbps",
					s.eRemote, budget, s.cHat/1e6)
			}
		} else {
			s.delayHiN = 0
		}
		if !moved {
			s.feedCHat()
		}
		s.rate = s.headroom * s.cHat
		// probe 计时。probe 是唯一保留的随机探索, 且方向永远向上 —— 向下的动作全部
		// 由测量驱动 (deficit/E_remote), 不靠猜。
		s.probeCountdown--
		if s.probeCountdown <= 0 {
			s.probeFromRate = s.rate
			s.probeBaseGoodput = s.goodput
			s.rate *= probeGain
			s.state = stShaperProbe
			s.holdStable = 0
			s.logf("HOLD->PROBE R %.1f -> %.1f Mbps (interval=%d)", s.probeFromRate/1e6, s.rate/1e6, s.probeInterval)
		} else if !moved {
			s.holdStable++
			// 巡航稳定 = 控制器确实在工作 -> 把 YIELD 复出的指数退避收回基础值。
			if s.holdStable >= holdStableForSlowLayer {
				s.recoverNeed = watchdogRecoverCycles
			}
		}

	case stShaperProbe:
		// PROBE 只持续 1 拍: 上一拍抬了 R, 本拍判定它换来了多少 goodput。
		// ★ amp 必须按"实际抬上去的幅度"算 (s.rate 此刻仍是上一拍 clamp 之后的探测
		// 速率), 而不是 probeFromRate*(1.25-1): 当探测速率被 R_max 削掉时, 后者会
		// 高估门槛, 让一次本来成功的探测被判失败并触发无谓的指数退避。
		gain := s.goodput - s.probeBaseGoodput
		amp := s.rate - s.probeFromRate
		if amp <= 0 {
			// R 已经顶在 R_max, 根本没探出去 —— 不是"墙已确认", 只是没得探。
			s.rate = s.probeFromRate
			s.probeInterval = minInt(s.probeInterval*2, probeIntervalMax)
			s.state = stShaperHold
			s.probeCountdown = s.probeInterval
			s.holdStable = 0
			s.logf("PROBE skipped: no headroom below R_max=%.0f Mbps, next probe in %d cycles",
				s.rateMax/1e6, s.probeInterval)
			break
		}
		if gain >= amp*probeAcceptFrac {
			s.setCHat(s.goodput)
			if s.cHat > s.cHatRegime {
				s.cHatRegime = s.cHat
			}
			s.cHatConfirmed = false
			s.probeInterval = probeIntervalBase
			s.rate = s.headroom * s.cHat
			s.logf("PROBE ACCEPT (+%.1f Mbps >= %.1f) C_hat=%.1f Mbps R=%.1f Mbps",
				gain/1e6, amp*probeAcceptFrac/1e6, s.cHat/1e6, s.rate/1e6)
		} else {
			// 没换来吞吐 => 当前 C_hat 就是墙, 标记 confirmed 并指数退避探测频率。
			s.rate = s.probeFromRate
			s.cHatConfirmed = true
			s.probeInterval = minInt(s.probeInterval*2, probeIntervalMax)
			s.logf("PROBE REJECT (+%.1f Mbps < %.1f) C_hat=%.1f Mbps confirmed, next probe in %d cycles",
				gain/1e6, amp*probeAcceptFrac/1e6, s.cHat/1e6, s.probeInterval)
		}
		s.state = stShaperHold
		s.probeCountdown = s.probeInterval
		s.holdStable = 0

	case stShaperBackoff:
		// ★ BACKOFF 原来只有一个出口 (deficit 清零), 没有周期上限、没有超时、也没有
		// "降了 R 但 deficit 不响应"的证伪 —— 它是一个吸收态:
		//   进要 deficit > 10%, 出要 deficit < 5%, 而 deficit 有结构性底噪 (头开销 +
		//   重传, 而这条链路的设计意图就是"高重传是常态")。底噪落在滞环中间时, BACKOFF
		//   进得去出不来: 实测持续喂 util=1.0/deficit=0.15 四百拍, R 永久停在
		//   0.3*C_hat_regime 地板 (吞吐 -70%), 看门狗还够不着 (goodput 25Mbps 远高于
		//   1Mbps 门槛), 顺带把 slowLayerReady() 永久钉死在 false。
		// 现在有三个出口, 缺一不可:
		switch {
		case !deficitFresh:
			// 出口 3 —— 没有新鲜证据就不许继续下压。原来 BACKOFF 无条件读 deficitEMA,
			// 而 EMA 只在 haveLink && sentBytes>0 时更新: 需求消失后 (实测喂 60 拍零
			// 流量) R 被按 120 秒前的陈旧读数一路砍到地板, 看门狗还帮不上忙 (qlen==0
			// 每拍清零 watchdogN)。无需求时冻结 R, 连续多拍就带着原封不动的 C_hat
			// 回 HOLD —— BACKOFF 从不改 C_hat, 所以 R=headroom*C_hat 正好回到进来前。
			s.backoffIdleN++
			if s.backoffIdleN >= backoffIdleCycles {
				s.restoreFromBackoff(fmt.Sprintf("no fresh deficit for %d cycles (demand gone)", backoffIdleCycles))
			}
		case s.deficitEMA < s.deficitThresh(deficitClear):
			// 出口 1 —— 正常复出。
			s.exitBackoff(fmt.Sprintf("deficit=%.1f%% cleared", s.deficitEMA*100))
		case s.backoffN >= backoffMaxCycles:
			// 出口 2 —— 证伪。压了 backoffMaxCycles 拍 (R 早就撞上地板) deficit 还在,
			// 说明它根本不是 R 造成的。把观测到的水平记成本 regime 的结构性底噪, 之后
			// 所有 deficit 判据都相对它抬高, 否则下一拍立刻又被同一份底噪推回来。
			s.deficitBias = math.Min(s.deficitEMA, deficitBiasMax)
			s.logf("BACKOFF gave up after %d cycles at R=%.1f Mbps: deficit=%.1f%% did not respond to rate cuts "+
				"— treating it as this regime's structural floor (thresholds now %.1f%%/%.1f%%)",
				s.backoffN, s.rate/1e6, s.deficitEMA*100,
				s.deficitThresh(deficitClear)*100, s.deficitThresh(deficitBackoff)*100)
			s.restoreFromBackoff("deficit did not respond to rate cuts")
		default:
			s.backoffIdleN = 0
			s.backoffN++
			s.rate *= backoffGain
		}
	}

	if badLink && weatherHold {
		s.logf("weather (srtt=%.0f/%.0fms util=%.2f) — R held at %.1f Mbps",
			sm.srttMs, sm.minRttMs, s.util, s.rate/1e6)
	}
	s.clampRate()
	s.pushRRing()
	s.maybeWriteCache()
}

// exitBackoff 是 BACKOFF 的正常复出 (出口 1: deficit 真的被降下去了)。这一拍的
// goodput 是"降到这个 R 之后全额送达"的观测, 是真容量证据, 所以锁存它 —— 但走
// latchCHat 而不是裸 setCHat: 它同样可能只是一个记账缺口 (见 latchCHat)。
func (s *shaper) exitBackoff(why string) {
	s.latchCHat(s.goodput)
	s.cHatConfirmed = false
	s.rate = s.headroom * s.cHat
	s.state = stShaperHold
	s.probeCountdown = s.probeInterval
	s.backoffN, s.backoffIdleN, s.holdStable = 0, 0, 0
	s.logf("BACKOFF->HOLD (%s) C_hat=%.1f Mbps R=%.1f Mbps", why, s.cHat/1e6, s.rate/1e6)
}

// restoreFromBackoff 是 BACKOFF 的"证伪"复出 (出口 2/3): 下压的前提 (R > C) 被推翻
// 了 —— deficit 对降 R 毫无反应, 或者需求早就没了。
//
// ★ 这里绝不能像正常复出那样锁存 goodput: 此刻的 goodput 是在我们自己压到地板的那个
// R 上测出来的, 它是需求受限观测而不是容量观测 (跟 feedCHat 里 util<utilBind 不喂的
// 是同一条道理)。锁存它等于把这次误判固化成永久的容量下调 —— 实测那样做 R 只能靠每
// 6 拍 +1% 的 PROBE 往回爬, 二十分钟才回得到原位, 等于缺陷 1 没修干净。BACKOFF 从头
// 到尾没动过 C_hat, 所以 R=headroom*C_hat 就是精确地回到进来之前。
func (s *shaper) restoreFromBackoff(why string) {
	if s.cHat > 0 {
		s.rate = s.headroom * s.cHat
	}
	s.state = stShaperHold
	s.probeCountdown = s.probeInterval
	s.backoffN, s.backoffIdleN, s.holdStable = 0, 0, 0
	s.logf("BACKOFF->HOLD (%s) — rate cut undone, R=%.1f Mbps", why, s.rate/1e6)
}

// clampRate 应用护栏 1+2。R_min 先被 R_max 夹住: clampF 在 lo>hi 时会返回 lo,
// 一个反过来把 R 顶到线速以上的坑。
func (s *shaper) clampRate() {
	s.rateMin = math.Max(rateFloorBps, rateMinFrac*s.cHatRegime)
	if s.rateMin > s.rateMax {
		s.rateMin = s.rateMax
	}
	s.rate = clampF(s.rate, s.rateMin, s.rateMax)
}

func (s *shaper) pushRRing() {
	s.rRing = append(s.rRing, s.rate)
	if len(s.rRing) > rRingLen {
		s.rRing = s.rRing[1:]
	}
}

// enterRegime: minRtt 带漂移 >= 2x -> C_hat 清零, R 取新 regime 缓存值*0.7, SEEK。
// 新 regime 没有缓存时保持当前 R —— 让 SEEK 从这里继续上探。这是 fail-open 方向:
// 若新路更慢, deficit/E_remote 会立刻叫停并交给 BACKOFF; 若从一个很低的地板重新
// 爬 (1.5^n), 反而要白白慢十几秒。
func (s *shaper) enterRegime(minRttMs float64) {
	old := s.band
	s.regimeMinRtt = minRttMs
	s.band = rttBand(minRttMs)
	s.peer = s.detectPeer()
	s.setCHat(0)
	s.cHatRegime = 0
	s.cHatConfirmed = false
	s.deficitPrimed = false
	s.deficitEMA = 0
	// deficitBias 是"这条路的结构性底噪", 换路了就得重新测 —— 带着旧路的偏置会让新
	// 路上真正的丢包被当成底噪吃掉。regimeHiN/backoff 计数器同理。
	s.deficitBias = 0
	s.deficitHiN, s.delayHiN, s.holdStable, s.cacheAge = 0, 0, 0, 0
	s.regimeHiN, s.backoffN, s.backoffIdleN = 0, 0, 0
	s.probeInterval = probeIntervalBase
	seeded := "kept current R"
	if kbps, ok := s.cacheLookup(s.cacheKey()); ok && kbps > 0 {
		s.rate = cacheSeedFrac * kbps * 1000
		seeded = fmt.Sprintf("seeded %.1f Mbps from cache", s.rate/1e6)
	}
	s.state = stShaperSeek
	s.logf("REGIME %s -> %s (minRtt=%.0fms): C_hat cleared, %s, SEEK", old, s.band, minRttMs, seeded)
}

// maybeWriteCache: HOLD 连续稳定 >=60s 回写一次容量估计。存的是 C_hat 而不是 R ——
// C_hat 是物理量 (这条路能跑多快), R 只是当前 headroom 策略下的一个投影。
func (s *shaper) maybeWriteCache() {
	if s.state != stShaperHold || s.cHat <= 0 || s.cacheAge < cacheWriteCycles {
		return
	}
	s.cacheAge = 0
	if s.cacheStore != nil && s.band != "" {
		s.cacheStore(s.cacheKey(), s.cHat/1000)
	}
}

// ---- 跨 goroutine 的访问器 (optimizer 慢环调用) ----

// running 报告快环是否真的能作动 (存在 + 内核导出了 shaper 键)。nil 安全。
func (s *shaper) running() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.unsupported
}

// slowLayerReady 是慢层的步进闸门: 只有 shaper 在 HOLD 且连续稳定 >=3 拍才放行。
// SEEK/PROBE/BACKOFF/OBSERVE/YIELD 期间速率本身在动, 慢层这时候步进一个坐标, 得到
// 的 score 变化根本分不清是谁造成的 —— 冻结慢层是防止快慢两层互相污染归因。
func (s *shaper) slowLayerReady() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsupported {
		return true // 快环没跑, 谈不上污染
	}
	return s.state == stShaperHold && s.holdStable >= holdStableForSlowLayer
}

// rateCV 返回 R 环的变异系数 (stddev/mean)。ok=false 表示样本不足或均值为 0。
// score() 用它惩罚"控制器自己抖 R" —— 目标是稳定的高速低延迟, 不是峰值吞吐。
func (s *shaper) rateCV() (float64, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rRing) < jitterMinSamples {
		return 0, false
	}
	mean := 0.0
	for _, v := range s.rRing {
		mean += v
	}
	mean /= float64(len(s.rRing))
	if mean <= 0 {
		return 0, false
	}
	varSum := 0.0
	for _, v := range s.rRing {
		d := v - mean
		varSum += d * d
	}
	return math.Sqrt(varSum/float64(len(s.rRing))) / mean, true
}

// setHeadroom 由慢层的 shaper_headroom 臂驱动 (0.85..1.05)。它是策略参数不是速率
// 本体 —— 效应慢、方向单调, 适合 bandit; 速率本体永远走反馈控制。
func (s *shaper) setHeadroom(h float64) {
	if s == nil || h <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headroom = h
}

// statusLine 是一行可读快照, 给 optimizer 的日志用。
func (s *shaper) statusLine() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsupported {
		return " | shaper=OFF(kernel)"
	}
	return fmt.Sprintf(" | shaper=%s R=%.1fM C=%.1fM util=%.2f def=%.0f%% Erem=%.0fms",
		s.state, s.rate/1e6, s.cHat/1e6, s.util, s.deficitEMA*100, s.eRemote)
}

// ---- I/O 层 ----

// tick 采一拍, 跑控制律, 把新的 R 写给内核。
func (s *shaper) tick() {
	nq, ok := nqReader.read(false)
	if !ok || !nq.shaperOK {
		s.mu.Lock()
		first := !s.unsupported
		s.unsupported = true
		s.mu.Unlock()
		if first {
			s.logf("kernel does not export the shaper keys (rate_kbps/backlog/shaper_sent/shaper_defer) — fast loop disabled, behavior falls back to today's (no shaping)")
			_ = writeNeoqRate(0)
		}
		return
	}
	s.mu.Lock()
	back := s.unsupported
	s.unsupported = false
	s.mu.Unlock()
	if back {
		// 模块热重载后 shaper 键出现了: 从冷启动重新来一遍, 而不是拿一堆过期状态
		// 继续算 (prevSent 的基线已经跟新实例对不上了)。
		s.logf("shaper keys appeared — re-arming from OBSERVE")
		s.mu.Lock()
		s.state, s.primed, s.deficitPrimed = stShaperObserve, false, false
		s.obsGoodputs, s.cWin, s.rRing = nil, nil, nil
		s.setCHat(0)
		s.cHatRegime, s.holdStable = 0, 0
		// 冷启动就要冷到底: 底噪偏置和各个确认计数器都是上一实例的前提, 一起清掉。
		s.deficitEMA, s.deficitBias = 0, 0
		s.deficitHiN, s.delayHiN, s.regimeHiN, s.backoffN, s.backoffIdleN = 0, 0, 0, 0, 0
		s.mu.Unlock()
	}
	now := time.Now()
	dt := now.Sub(s.lastTick).Seconds()
	s.lastTick = now

	st := s.sampleStat()
	sm := shaperSample{
		dt:           dt,
		backlogBytes: nq.backlog,
		qlen:         nq.qlen,
		minRttMs:     shaperMinRtt(st), // p50, 不是全局 min —— 见 shaperSample.minRttMs
		srttMs:       st.rttMs,
		queueDelayMs: st.queueDelayMs,
		haveLink:     st.socks > 0,
	}
	// 累计计数器差分 + churn 保护: socket 关闭会让 bytes_acked 的求和下降, 天真的
	// 差分会 uint 下溢成天文数字 (targetMetrics 里踩过同一个坑)。下降就当本拍没有
	// acked 信号, 只重新基线。
	if s.primed {
		if nq.shaperSent >= s.prevSent {
			sm.sentBytes = nq.shaperSent - s.prevSent
		}
		if sm.haveLink && st.acked >= s.prevAcked {
			sm.ackedBytes = st.acked - s.prevAcked
			// segs_out 跟 acked 是同一批 socket 的同一批统计, 必须一起差分才自洽 ——
			// deficit 用它扣头开销, 分子分母来自不同拍就没意义了。
			if st.segs >= s.prevSegs {
				sm.segsOut = st.segs - s.prevSegs
			}
			// ★ churn 的**上升**方向也要挡。下面那个 else 分支只处理求和下降 (socket
			// 关闭), 但反方向同样会炸: 一条新 socket 进入采样集合时, 带进来的是它的
			// **lifetime** bytes_acked, 会被整个计进本拍差分。实测一条跑了 95 秒的流
			// 被首次纳入时, 单拍 acked 冲到 1253.6 Mb 而同拍本网卡只发了 103.8 Mb ——
			// 12 倍。这一拍的 goodput/deficit 全是垃圾: goodput 虚高会让 latchCHat 锁存
			// 假容量 (它的可信度门只防偏低), deficit 变负被 clamp 成 0 又让 BACKOFF
			// 进不去。
			//
			// 判据复用 canary 的物理上界: 确认的字节不可能显著多于本网卡发出的字节。
			// 越界就当本拍没有 link 信号, 只重新基线 —— 与下降方向的处理对称。
			if sentB := float64(sm.sentBytes); sentB > 0 &&
				float64(sm.ackedBytes) > ackedSentSanityRatio*sentB {
				sm.haveLink = false
				sm.ackedBytes, sm.segsOut = 0, 0
			}
		} else if sm.haveLink {
			sm.haveLink = false
		}
	} else {
		sm.haveLink = false
	}
	s.prevSent = nq.shaperSent
	if st.socks > 0 {
		s.prevAcked = st.acked
		s.prevSegs = st.segs
	}
	s.primed = true

	s.mu.Lock()
	s.step(sm)
	rate := s.rate
	s.mu.Unlock()

	_ = writeNeoqRate(uint64(rate / 1000))
}

// run 驱动快环直到 stop 关闭。退出时把 rate 归零 —— 与 systemd 的 ExecStopPost
// 同一个兜底 (护栏 4): 控制器不在 = 完全无整形, 而不是卡在最后一个速率上。
func (s *shaper) run(stop <-chan struct{}) {
	t := time.NewTicker(shaperTick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			_ = writeNeoqRate(0)
			return
		case <-t.C:
			s.tick()
		}
	}
}
