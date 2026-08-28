### lotspeed adaptive-accel — 自适应加速分支

> CC 抗丢包 + NeoQ 行为化调度 + lotspeedctl 学习闭环 + hist 短流加速。全部特性在真实洲际链路上 A/B 验证（见 [CHANGELOG](CHANGELOG.md) 与下方测试报告）。

* 前置条件 `kernel 6.18.2-bbrv3 or later`


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/adaptive-accel/logo.png" width="400" height="400" />
</div>



### supported kernel

* kernel_version:
    - "6.18.2-bbrv3-patch" # LTS



### lotspeed helper

> 速度起不来执行： /usr/local/bin/lotspeed-autotune restart

```

root@dev-kernel:~# lotspeed help
╔════════════════════════════════════════════════════════════════════╗
║                 LotSpeed v2.2 + NeoQ v3.1 Commands                 ║
╟────────────────────────────────────────────────────────────────────╢
║ Basic Commands                                                     ║
║ lotspeed                                          Interactive menu ║
║ lotspeed start                                  Enable LotSpeed CC ║
║ lotspeed stop                                  Disable LotSpeed CC ║
║ lotspeed restart                                  Restart LotSpeed ║
║ lotspeed status                                    Show all status ║
╟────────────────────────────────────────────────────────────────────╢
║ NeoQ Qdisc                                                         ║
║ lotspeed neoq-start [iface]                      Enable NeoQ qdisc ║
║ lotspeed neoq-stop [iface]                      Disable NeoQ qdisc ║
║ lotspeed neoq-stats                           Show NeoQ statistics ║
╟────────────────────────────────────────────────────────────────────╢
║ Parameter Management                                               ║
║ lotspeed params                                Show all parameters ║
║ lotspeed set <k> <v>                          Set single parameter ║
║ lotspeed preset <name>                         Apply preset config ║
║ lotspeed save                                  Save current config ║
║ lotspeed load                                    Load saved config ║
║ lotspeed edit                                     Edit config file ║
╟────────────────────────────────────────────────────────────────────╢
║ Other                                                              ║
║ lotspeed log                                      Show kernel logs ║
║ lotspeed monitor                               Live log monitoring ║
║ lotspeed autotune                         Auto-tune network params ║
║ lotspeed uninstall                               Remove everything ║
╟────────────────────────────────────────────────────────────────────╢
║ Presets: conservative, balanced, aggressive,                       ║
║          highdelay, datacenter                                     ║
╚════════════════════════════════════════════════════════════════════╝


root@dev-kernel:~# lotspeed autotune help
LotSpeed Auto-Tune Daemon v2.1

Commands:
  (none)    Analyze network and suggest preset
  status    Show current status and metrics
  daemon    Start background daemon
  stop      Stop background daemon
  restart   Restart daemon
  aggressive    Apply anti_loss preset immediately
  ultra         Apply ultra_aggressive preset

Presets (use with '<name>'):
  normal        Balanced settings (default)
  anti_loss     Aggressive loss recovery, fast retransmit
  ultra_aggressive  Maximum throughput, large queues
  loss_recovery Optimized for active loss conditions
  datacenter    Ultra-low latency, ECN-focused
  satellite     Very high delay (300+ ms)
  highdelay     High delay WAN (100-300ms)
  lossy         Moderate packet loss (1-5%)
  lossy_severe  Severe packet loss (>5%)
  jittery       High RTT variance (mobile/WiFi)
  congested     High ECN marks

Environment:
  DEBUG=1   Enable debug output

Files:
  Log:    /var/log/lotspeed-autotune.log
  PID:    /var/run/lotspeed-autotune.pid
  State:  /tmp/lotspeed-autotune.state

```



### branch explanation

* `merge_bl`: lotspeed merge_bl 基于学习历史记录的模式进行加速，并且洲际场景抖动不会降速避让,并且整合了BBRv3的优点。

* `adaptive-accel`: 在 merge_bl 之上的行为化调度 + 学习闭环分支:
  - **CC**: min_rtt 双窗口修复(过期窗/PROBE_RTT 重新生效, BBRv3 式浅排空), CRUISE headroom 按 loss 压力门控, loss_thresh 丢包率门控(实测最优 lt=2)
  - **NeoQ**: CAKE 式 sparse/bulk 行为分类(临界点按流速率自适应, 不依赖端口), 全局 5-tuple flow 表, 跨档 WRR 8:4:2:1 防饿死, 满队列从最低档驱逐, **重传包 CoDel 免疫**(丢恢复包在 250ms 链路 = 恢复时间翻倍), `/proc/net/neoq_ml` 机器可读统计
  - **lotspeedctl**: 每参数 Δ 信用分配(因果归因, 不再拟合链路噪声), 体验感知 score(`--gamma`, Express 排队延迟惩罚), bad-link 周期跳过, apply 后 settle, KNN 同 regime 邻居门控


* auto install


```bash
# 1. install lotspeed module and helper script
curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/refs/heads/adaptive-accel/install.sh | sudo bash
#   or
wget -qO- https://raw.githubusercontent.com/uk0/lotspeed/refs/heads/adaptive-accel/install.sh | sudo bash

```




* manual compile and load

```bash

# 下载代码/编译

git clone -b adaptive-accel https://github.com/uk0/lotspeed.git

cd lotspeed && make

# 加载模块
sudo insmod lotspeed.ko

# 设置为当前拥塞控制算法
sudo sysctl -w net.ipv4.tcp_congestion_control=lotspeed
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1

# 查看是否生效
sysctl net.ipv4.tcp_congestion_control

# 查看日志
dmesg -w

# 查看链接
ss -nOi | grep lotspeed


# 查看诊断信息
ss -ti
  #bbr_bw_lo: 当前带宽
  #bbr_bw_hi: 最大带宽
  #bbr_min_rtt: 最小 RTT
  #bbr_pacing_gain: pacing 增益
  #bbr_cwnd_gain: rho 系数 (高延迟指标)

```



> 这是一个混合拥塞控制算法，整合了 BBR v3 + FAST TCP + Hybla 三种算法的优点。

---
核心架构

| 模块       | 来源     | 功能                                   |
|------------|----------|----------------------------------------|
| 带宽估计   | BBR v3   | delivered/interval 方式测量带宽        |
| 延迟控制   | FAST TCP | alpha 目标队列长度                     |
| 状态机     | BBR v3   | STARTUP → DRAIN → PROBE_BW → PROBE_RTT |
| 高延迟补偿 | Hybla    | RTT² 补偿，让高延迟链路获得公平吞吐    |

  ---
主要功能

1. BBR v3 状态机
   STARTUP (快速启动) → DRAIN (排空队列) → PROBE_BW (稳态探测) → PROBE_RTT (探测最小RTT)
   ↓
   4个子阶段: CRUISE/REFILL/PROBE_UP/PROBE_DOWN

2. FAST TCP 延迟控制
- 目标队列长度 alpha (默认 20 包)
- 平滑系数 gamma (默认 50%)
- 公式: cwnd = (1-γ)×cwnd + γ×(base_rtt/rtt×cwnd + α)

3. Hybla 高延迟优化
- 当 RTT > 150ms 自动激活
- rho = RTT / RTT_ref 补偿系数
- cwnd 和 pacing 按 rho² 放大

4. ECN 支持 (BBR v3 风格)
- ecn_alpha EWMA 跟踪 ECN 标记率
- 根据 ECN 信号调整 inflight_lo
- STARTUP 阶段 ECN 过高时提前退出

5. 勇敢模式 (抗抖动)
- RTT 突增时冻结窗口/速率
- 防止瞬时抖动导致吞吐下滑
- 冻结期保持 85% 窗口下限

6. 历史缓存 (hist v3 — 短流加速)
- 按目标 IP 缓存带宽，新连接直接种 bw 滤波器 (×0.7 折扣) 并立即设置 pacing rate — 跳过慢启动
- 长连接每 10s 周期写入 (隧道场景也能填充缓存)，连接关闭时最终落盘
- 实测: 256KB 短流完成时间中位 -19%、尾延迟 -49% (暖缓存, 100% 命中)
- TTL 20 分钟，最多 8192 条目; 可观测: `cat /proc/net/lotspeed_hist` (hits/seeds 计数 + 全表)

7. 快速路径优化
- app-limited 且无拥塞信号时跳过模型更新
- 减少 CPU 开销

8. ACK 聚合补偿
- 检测 ACK 聚合/延迟 ACK
- 增加 extra_acked 余量防止 underflow

  ---
sysctl 可调参数 (/proc/sys/net/ipv4/lotspeed/)

| 类别     | 参数           | 默认值 | 说明               |
  |----------|----------------|--------|--------------------|
| 基础     | min_cwnd       | 4      | 最小拥塞窗口       |
|          | max_cwnd       | 15000  | 最大拥塞窗口       |
|          | beta           | 717    | 丢包缩减 (~70%)    |
| FAST     | fast_alpha     | 20     | 目标队列长度       |
|          | fast_gamma     | 50     | 平滑系数 (%)       |
| 高延迟   | hd_enable      | 1      | 启用高延迟优化     |
|          | hd_thresh_us   | 150000 | 高延迟阈值 (150ms) |
|          | hd_cwnd_gain   | 150    | 高延迟 cwnd 增益   |
| 勇敢     | brave_enable   | 1      | 启用抗抖动         |
|          | brave_hold_ms  | 300    | 冻结时间           |
| ECN      | ecn_enable     | 1      | 启用 ECN           |
|          | ecn_alpha_gain | 16     | EWMA 增益 (1/16)   |
|          | ecn_thresh     | 50     | ECN 阈值 (%)       |
| 快速路径 | fast_path      | 1      | 启用快速路径       |
| 抗丢包   | loss_thresh    | 2      | 丢包率门控 (%): 实测丢包低于该值不退避 — 洲际抗丢包核心 |
| 启动     | startup_gain   | 300    | STARTUP 增益 (3x)  |
| 历史     | hist_enable    | 1      | 启用历史缓存 (v3 种 bw+pacing) |
|          | hist_ttl_sec   | 1200   | 缓存 TTL (20分钟)  |
|          | hist_min_cwnd_bound | 64 | hist 种子 cwnd 兜底下界 |

  ---
适用场景

- 高延迟链路 (跨国、卫星) - Hybla 补偿
- 低延迟数据中心 - ECN + FAST 延迟控制
- 不稳定网络 - 勇敢模式抗抖动
- 短连接密集 - 历史缓存加速
- 混合流量 - BBR v3 状态机公平性

---


### test youtube


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/adaptive-accel/zeta-tcp.png" width="1024" height="768" />
</div>


### test iperf3 loss

```bash
# disable lro
ethtool -K eth0 lro off
# 丢包16%
sudo tc qdisc add dev ens3 root netem loss 16%
sudo tc qdisc add dev eth0 root netem loss 16%

#取消丢包
sudo tc qdisc del dev ens3 root netem 
sudo tc qdisc del dev eth0 root netem 

# test command
iperf3 -4 -s -p 35201
iperf3 -c green1 -p 35201 -R -t 30
```


### speedtest 测试结果

* 用之前

![b058ec2ebdb2a095d396cea05dccf499.png](img/b058ec2ebdb2a095d396cea05dccf499.png)

* 用之后

![f7525becdae16659ddfd54d99efe0f66.png](img/f7525becdae16659ddfd54d99efe0f66.png)


### 真实洲际链路测试报告 — lotspeed vs BBR v3 (adaptive-accel, 2026-06)

#### 测试环境

| 项 | 值 |
|---|---|
| 加速端 | 美东 VPS, kernel `6.18.2-bbrv3`, 仅加速端部署 lotspeed + sch_neoq + lotspeedctl |
| 接收端 | 国内测试机 (NAT 出口), 标准 bbr 客户端, **什么都不装** (单边加速) |
| 链路 | RTT 13↔264ms 跨时段漂移, 丢包 0.8%↔10%, 国际链路常态抖动 |
| 方向 | `iperf3 -R` 接收端拉加速端 (下载方向), 30s/轮, 交替轮换抵消链路漂移 |
| 对照 | 同内核系统自带 `bbr` (即 BBR v3), 切 `sysctl` 即换, 其余全同 |

#### 单流 (P1) — 干净时段打平, 丢包高峰拉开

| 场景 | lotspeed | BBR v3 | Δ |
|---|---|---|---|
| 干净时段 (重传 <150/30s), 4 轮均值 | 111M | 112M | ≈0 |
| 跨时段 6 轮均值 (历史) | 93M | 87M | **+7%** |
| 丢包高峰 (loss_thresh=2) | **67M** | 35M | **+91%** |
| 丢包高峰崩溃轮 | 稳定 45-78M | **崩至 7-9M** | — |

> 单流结论: 干净链路两者贴着 per-flow 上限走, 差异在噪声内; **差距全部来自丢包时段** — BBR v3 把随机丢包当拥塞退避, lotspeed 按实测丢包率门控 (`loss_thresh`) 顶住不退。

#### 多流 (P8) — 持续优势 + 稳定性差异

| 轮 | lotspeed | BBR v3 |
|---|---|---|
| R1 | 380M (rt 86k) | 276M (rt 18) |
| R2 | 352M (rt 29k) | **104M** (rt 12) |
| 均值 | **366M** | 190M (**+93%**) |

> BBR v3 两轮波动 2.6× (撞上丢包期即崩), lotspeed 两轮稳定。lotspeed 的高重传是激进策略的成本 (~7% 发送量), 换取链路被持续打满。

#### 并发扩展性 (lt=2)

| 并发 | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| 吞吐 | 118M | 194M | 361M | 380M | **442M** |

> P4 前接近线性 → 单流 ~118M 是 ISP per-flow 限制而非链路容量 (≥442M); 多连接是免费杠杆。`loss_thresh=2` 在 P1 与 P8 同为最优 (P8 下 lt6=359M / lt12=352M 反而更低)。

#### 混合负载 — NeoQ 的"临界点" (bulk 满速 + 交互不卡)

P8 bulk 满载同时以 0.2s 间隔 ping ×248 模拟交互小包 (<128B → Express 档):

| | NeoQ | fq_codel |
|---|---|---|
| bulk 吞吐 | **356M** | 340M |
| ping p50 / p99 / max | 244 / **257** / 263 ms | 244 / 262 / 271 ms |
| Express 档内排队 | avg **1us** / peak 514us, 0 drop | — |

行为分类实证 (两轮 iperf 期间的 tier 分布): 880MB bulk 数据全部自动降入 Bulk 档; Express 档仅 2009 包 (均 92B = ACK/控制/重传), 排队延迟微秒级 — **同一条连接的数据包满速、控制包零排队**, 临界点按流速率自适应, 不依赖端口 (隧道内混合流量同样生效)。

#### 结论

1. **单流**: 与 BBR v3 的差距 = 丢包时段的差距 (+91%); 干净时段打平 (per-flow 限制)
2. **多流**: +93%, 且方差远小于 BBR v3 (不随丢包期崩溃)
3. **体验**: bulk 满载下交互小包 Express 旁路, 本地排队微秒级; 重传包免疫 CoDel 丢弃, 高丢包链路恢复不被本地拖累
4. 全部参数可由 `lotspeedctl optimize` 在线学习 (每参数 Δ 信用 + Express 延迟惩罚进 score)

PAC (Proactive ACK Control) for TCP Incast Congestion
==========================================

* https://github.com/uk0/TCP-Incast/tree/zeta-tcp 



### Qdisc `neoq`


[QDISC_DOC](QDISC_DOC.md)


-----------------------------------

## lotspeedctl — Go 控制 CLI + 自适应参数寻优

`lotspeedctl/` 下的 Go CLI 是**整套体系的大脑**:统一控制 lotspeed CC + NeoQ qdisc + 下行诱骗,自动测量真实链路、从历史 sample 学习、动态规划参数。三件套构成完整闭环:

```
┌─────────────────── lotspeedctl (Go) ────────────────────┐
│  collect  →  measure (ss/snmp/ifstat)  →  EWMA / MAD    │
│      ↓                                                   │
│  model.json (KNN samples)  ← record (feature,params,score)│
│      ↓                                                   │
│  predict (k=5 inverse-distance + score weighted)         │
│      ↓                                                   │
│  apply  →  /proc/sys/net/ipv4/lotspeed/*                │
│         →  /proc/net/neoq_{prio,boost,codel}             │
└──────────────────────────────────────────────────────────┘
```

### 编译

`lotspeedctl` 是纯 Go,本地交叉编译即可:

```bash
cd lotspeedctl
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lotspeedctl .
scp lotspeedctl root@加速端:/usr/local/bin/
```

### 部署模型(单边加速)

加速端(海外大带宽 VPS)装 lotspeed + sch_neoq + lotspeedctl,下游客户端(国内/弱网)**什么都不用装**,标准 bbr 即可。这就是单边加速的本质。

```bash
# 加速端
modprobe lotspeed          # 或 insmod lotspeed.ko
modprobe sch_neoq
lotspeedctl enable eth0    # 切 CC=lotspeed + 给 eth0 挂 neoq
```

### 命令全集

| 命令 | 说明 |
|------|------|
| `status` | 当前 CC + 可用 CC + lotspeed 关键参数 + NeoQ 统计 |
| `enable <iface>` | 切 `CC=lotspeed` + 给 iface 挂 `neoq` qdisc |
| `disable <iface>` | 还原 `CC=bbr` + 移除 iface 的 neoq |
| `set <param> <val>` / `get [param]` | 读写 `/proc/sys/net/ipv4/lotspeed/<param>` |
| `preset <name>` | `intercontinental` / `game` / `web` / `balanced` |
| `monitor [sec]` | 实时刷新 CC + NeoQ 统计 |
| `prio [list\|add P\|del P\|clear\|auto]` | NeoQ 优先端口(`auto` 自动识别游戏/网页) |
| `boost [N]` | NeoQ 下行 rwnd 诱骗强度(percent,100=off) |
| `hist-clear` | 强制清空 lotspeed 的 per-IP 历史缓存(诊断/重置用) |
| `probe <ip> [port]` | 测量 RTT/BW/loss(MAD 异常值滤波) |
| `tune <ip> [port]` | probe → model.predict → 写参数(一键调优) |
| `daemon --iface X` | 抗丢包闭环 + 自动游戏/网页优先级 |
| `optimize --iface X --target IP` | 自适应寻优:warm-start → EXPLORE → OPTIMIZE,持续 record sample 训练模型 |
| `model [show\|clear]` | 查看/清空 KNN 样本库(`~/.lotspeedctl/model.json`) |

### 动态调参的工作原理

**1. 测量层(异常值抚平)**

洲际链路抖动大,单次测量不可靠。`probe` 默认行为:

- 20 次 ping,**Hampel filter (MAD>3)** 剔除离群值,取 P10/P50/P90
- 3×5s iperf3,**trimmed mean** 去掉最高最低
- ICMP 被 NAT 阻断时自动 fallback 到 TCP-connect 计时
- 输出 `linkFeature` 向量:`{rtt_p50, rtt_p10, jitter, bw_mbps, loss}`

**2. 模型层(KNN 样本库)**

`~/.lotspeedctl/model.json` 是 JSON 持久化的 sample 列表,每条记录 `(feature, params, score)`。`predict()` 流程:

- 对新链路特征 `f`,计算与每个历史 sample 的归一化 L2 距离(RTT/BW 用 log scale)
- 取 K=5 最近邻
- 按 `score / (距离 + 0.1)` 加权平均每个参数 → 推荐参数

冷启动(无 sample)走 `heuristicPlan` BDP 公式作 fallback。

**3. 数据收集(自动闭环)**

`optimize --iface X --target IP` 是收集训练数据的入口:

- **warm-start**:如果 model 已有 sample,先用 `predict` 作为初始参数(避免每次从默认值摸索)
- **EXPLORE**:几个周期激进抢带宽,记录 `peakBw`/`minRtt`
- **OPTIMIZE**:coordinate ascent 逐参数 `±step` 探索;score = `bw/peakBw − α·delay_inflation − β·loss`
- **window-best record**:每 N 个 OPT 周期,把窗口内最高分的 `(feature, params, score)` 持久化到 `model.json`
- 长跑越久,model 样本越多,后续 warm-start + tune 越准

**4. 一键调优**

```bash
# 第一次:冷启动用 heuristic
lotspeedctl tune <downstream_client_ip> <iperf3_port>

# 后台跑寻优收集 sample
lotspeedctl optimize --iface eth0 --target <client_ip>

# 再次 tune:已用 model.predict 出推荐参数
lotspeedctl tune <client_ip> <port>
lotspeedctl model show          # 查看学到了什么
```

### systemd 常驻

安装器会装好模板单元 `lotspeedctl@.service` 并检测网卡,直接按网卡名启用即可:

```bash
systemctl enable --now lotspeedctl@ens3     # 网卡名由 install.sh 写在 /etc/lotspeed/env
```

模板单元见 `lotspeedctl/lotspeedctl@.service`。**不要手写一份**——里面有一条
必须原样保留的护栏:

```ini
ExecStopPost=/bin/sh -c 'echo 0 > /proc/net/neoq_rate || true'
```

它是四层护栏的最外层:无论进程是正常退出、崩溃还是被 kill,都把整形速率写回 0。
内核默认 `rate=0` 等于完全不整形,所以"控制器不在"退化成今天的行为,而不是
"卡在最后一个速率上把链路勒死"。这是唯一一条不依赖控制器自身还活着的失效路径,
早期文档里那份手写单元恰恰缺了它。

### NeoQ 配套接口(运行时可调)

体系的另一半在 NeoQ qdisc 侧,都通过 `/proc/net/` 接口运行时可调,daemon/optimize 会自动用上:

```bash
# 端口提示 (仅对小包 <256B 提速; 大包按行为分类, 端口提示不再放行 bulk)
echo "+27015 +443 +5201" > /proc/net/neoq_prio
echo "clear" > /proc/net/neoq_prio
cat /proc/net/neoq_prio

# sparse/bulk 行为门控: 窗口内速率低于阈值的流保持 Express/High (网页/交互),
# 持续超阈值自动降级 Bulk (下载) — 临界点按流自适应, 与端口无关
echo "100000 3028" > /proc/net/neoq_sparse     # 100ms 窗口, 3028B 阈值 (≈0.24Mbps)

# Express 防滥用: 上一窗口重传占比超过该值的 bulk 流, 其重传不再升 Express (0=关)
echo 15 > /proc/net/neoq_retrans

# 下行 rwnd 诱骗 — 默认 100=off。egress-only qdisc 无法获知对端 window scaling,
# 该改写无法做对, 仅留作显式实验开关, 不建议开启
cat /proc/net/neoq_boost

# CoDel target/interval (高 RTT 链路需要放大 target,默认 5ms 适合 LAN)
echo "150000 300000" > /proc/net/neoq_codel    # 150ms target, 300ms interval

# 机器可读统计 (lotspeedctl 体验闭环消费; 每档 pkts/bytes/drops/延迟 + 重传计数)
cat /proc/net/neoq_ml
# CC 侧 hist 缓存可观测 (hits/seeds + 全表)
cat /proc/net/lotspeed_hist
```

### lotspeed CC 注意事项

- **`hist_enable`**:per-IP 历史缓存,v3 后建议开启(短流加速实测有效)。早期毒化 bug 已由 `hist_min_cwnd_bound` 兜底 + 写入 sanity check + 种子自愈(错误种子一个滤波窗内被真实样本覆盖)三重防护;诊断/重置用 `echo 1 > /proc/sys/net/ipv4/lotspeed/hist_clear`,行为可由 `cat /proc/net/lotspeed_hist` 实时观测
- **`optimize --target <ip>`**:强烈建议带上目标 IP — 混合出口(近端 CDN 几 ms + 洲际数百 ms 并存)下全机测量会被近端连接污染 minRtt,学习信号失真;per-target 模式下 rtt/loss/bw 全部来自该目标的 socket 增量
- **卸载顺序**:务必先 `sysctl -w net.ipv4.tcp_congestion_control=bbr` 再 `rmmod`。注意三类隐蔽引用持有者:执行 rmmod 的 ssh 会话自己(需在切换 CC 之后新建会话)、LISTEN socket(服务在 CC=lotspeed 时段启动则其 listener 持引用,如 iperf3/代理面板)、容器 netns 的默认 CC。`ss -K` 清理时要覆盖全部 connected 状态而非仅 established

### 设计原则

- **内核做机制,CLI 做策略**:`/proc` 接口暴露,CLI 周期性下发,符合 Unix 哲学
- **数据驱动 > 启发式**:KNN 样本库可后续平滑替换为 Thompson sampling / Bayesian optimization / 小 MLP,而不动 record→predict 接口
- **真实抚平 > 单次测量**:洲际抖动下,任何"测一次写一组参数"的方案都是噪声驱动;必须多次采样 + 异常值剔除
- **单边部署**:加速端装,客户端不装,符合实际运维边界

-----------------------------------


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=uk0/lotspeed&type=timeline&logscale&legend=top-left)](https://www.star-history.com/#uk0/lotspeed&type=timeline&logscale&legend=top-left)