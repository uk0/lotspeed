### lotspeed adaptive-accel — 自适应加速分支

> CC 抗丢包 + NeoQ 行为化调度 + lotspeedctl 学习闭环 + hist 短流加速。全部特性在真实洲际链路上 A/B 验证（见 [CHANGELOG](CHANGELOG.md) 与下方测试报告）。

* 前置条件 `kernel 6.18.2-bbrv3 or later`


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/adaptive-accel/logo.png" width="400" height="400" />
</div>



### supported kernel

* kernel_version:
    - "6.18.2-bbrv3-patch" # LTS



### 一键部署

> 完整部署手册见 **[INSTALL.md](INSTALL.md)** —— 内核要求的编译期理由、DKMS、
> **对端要求**(只装本机只解决一半)、卸载纪律、从手工部署迁移,都在那里。
> 这一节只讲最短路径。

```bash
curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/refs/heads/adaptive-accel/install.sh | sudo bash
```

脚本只做引导:依赖检查 → 取源码 → 编译 → 安装 → sysctl → systemd。日常运维全部交给
`lotspeedctl`。它需要 **kernel 6.6+ 且内核树带 BBRv3 补丁**和内核头文件;网卡默认取
默认路由的出接口。

```bash
sudo bash install.sh [options]

  --iface <name>          指定加速网卡 (默认自动检测)
  --force-kernel          跳过 6.6+ 内核硬门, 仅供测试
  --with-legacy-autotune  额外装老的 lotspeed-autotune.sh (默认不装, 见下)
  --full, -f              非交互, 直接完整安装
  --help, -h              用法
```

装完后会有:

| 路径 | 作用 |
|---|---|
| `/opt/lotspeed/` | 源码与编译好的 `.ko` |
| `/usr/local/bin/lotspeedctl` | Go 控制器,**日常运维都用它** |
| `/usr/local/bin/lotspeed` | 薄包装,只做模块装卸和卸载 |
| `/etc/systemd/system/lotspeedctl@.service` | 模板单元 |
| `/etc/sysctl.d/99-lotspeed.conf` | 参数持久化(唯一入口) |
| `/etc/modules-load.d/lotspeed.conf` | 开机加载模块 |
| `/etc/lotspeed/env` | 安装时检测到的网卡名 |

启用与验证:

```bash
sudo systemctl enable --now lotspeedctl@ens3   # 网卡名见 /etc/lotspeed/env
lotspeedctl status
```

**DKMS 已由 `install.sh` 自动接好**(内建 `install_dkms()`,装不上才回退到一次性
`make`)。这一步近乎必选:不接的话内核一升级 `.ko` 就不匹配了,重启后 CC 静默回落到
内建算法。确认它生效:

```bash
dkms status                 # lotspeed/2.2, <kver>, x86_64: installed
```

手工部署的机器要自己补,见 [INSTALL.md §2.1](INSTALL.md)。无论哪种方式,都要确认
`modprobe` 解析到的就是运行中的那份:

```bash
modinfo -F srcversion lotspeed          # 应与 cat /sys/module/lotspeed/srcversion 一致
```

两者不一致,说明 `modprobe` 会去加载另一份旧 `.ko` —— 用 `insmod` 手工装过的机器
特别容易这样。

### 两个命令入口

`lotspeedctl` 是主入口(Go,117 个测试);`lotspeed` 只保留 `lotspeedctl` 做不到的事 ——
内核模块装卸和卸载纪律,其余子命令原样转发。

```bash
lotspeed modload            # modprobe lotspeed + sch_neoq
lotspeed unload             # 完整卸载序列 (见下), 不用 rmmod -f
lotspeed uninstall          # 卸载序列 + 删文件
lotspeed <其他>             # 转发给 lotspeedctl
```

> **注意**:旧版本的 `lotspeed start/stop/restart/params/save/load/edit/autotune` 已全部移除。
> 参数持久化统一走 `/etc/sysctl.d/99-lotspeed.conf`,单个参数用 `lotspeedctl get/set`。
> `lotspeed load` 在旧版是"恢复配置"而不是"加载模块",所以它现在会**大声失败**而不是
> 静默改变行为 —— 装模块请用 `lotspeed modload`。

### 卸载

CC 模块的引用计数由 **socket 创建时**绑定,改 `sysctl` 不影响存量连接 —— 包括你当前
这条 SSH。所以卸载分两步是正常的,不是错误:

```bash
sudo lotspeed uninstall          # 走完 6 步序列; 存量连接仍持引用时会提示
# 重新登录后
sudo lotspeed uninstall --finish
```

六步序列:停控制器 → 关整形(`rate=0` 即内核默认不整形)→ 新 socket 切回 bbr →
摘掉 neoq qdisc → `rmmod sch_neoq` → `rmmod lotspeed`。为什么 SSH 会把自己 pin 住、
容器 netns 为什么查不到,见 [INSTALL.md §4.1](INSTALL.md)。

**这里绝不用 `rmmod -f`。** 强卸一个仍被 socket 引用的 CC 模块,那些 socket 的
`icsk_ca_ops` 立刻指向已释放内存,下一个包就是 use-after-free → panic。卸不掉可以接受,
panic 不行。卸不掉时脚本会打印真实 refcount 和内核原话,并给出定位持有者的命令
(已建立连接 / LISTEN socket / 容器 netns 各查一遍)。

### legacy autotune

`lotspeed-autotune.sh` 是早期的 shell 自调优,**默认不再安装**:它与
`lotspeedctl optimize` 写同一批 `/proc/sys/net/ipv4/lotspeed/*`,两个都跑会互相打架。
只有明确要用旧行为时才 `--with-legacy-autotune`。

### branch explanation

* `merge_bl`: lotspeed merge_bl 基于学习历史记录的模式进行加速，并且洲际场景抖动不会降速避让,并且整合了BBRv3的优点。

* `adaptive-accel`: 在 merge_bl 之上的行为化调度 + 学习闭环分支:
  - **CC**: min_rtt 双窗口修复(过期窗/PROBE_RTT 重新生效, BBRv3 式浅排空), CRUISE headroom 按 loss 压力门控, loss_thresh 丢包率门控(内核默认 2; 高丢包链路应设为 `环境丢包率 + 4`, 见下)
  - **NeoQ**: CAKE 式 sparse/bulk 行为分类(临界点按流速率自适应, 不依赖端口), 全局 5-tuple flow 表, 跨档 WRR 8:4:2:1 防饿死, 满队列从最低档驱逐, **重传包 CoDel 免疫**(丢恢复包在 250ms 链路 = 恢复时间翻倍), `/proc/net/neoq_ml` 机器可读统计
  - **lotspeedctl**: 整形速率反馈环(probe-and-hold, 把瓶颈从对端拉回本机), 体验感知 score(`--gamma`, Express 排队延迟惩罚), KNN 同 regime 邻居门控。**参数搜索已于 2026-08 退役** —— 人工 A/B 定下来的参数冻结为常数, `loss_thresh` 由可测量的机制闭环给建议, 因果判断交给 `abtest` 的随机化 A/B(理由见 [CHANGELOG](CHANGELOG.md#2026-08-28-mechanism))


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
| 延迟封顶 | delay_cap_thresh | 0 | srtt > min_rtt*(100+x)% 时把 cwnd 封到 BDP*1.25;**0=关**(见下) |
|          | headroom_loss_gain | — | CRUISE headroom 随 loss 压力的增益 |
| 启动     | turbo_startup  | 1      | STARTUP 加速 |
|          | startup_min_rounds | — | STARTUP 最少轮数 |
| 高延迟   | hd_rho_max     | 400    | rho 上限**护栏**,防 rho² 过冲引发重传风暴 |
|          | hd_ref_us      | —      | Hybla 参考 RTT |
| 恢复     | fast_recovery  | 1      | 快速恢复 |
|          | recovery_boost | —      | 恢复期窗口提升 |
| PROBE_RTT| probe_rtt_cwnd_pct | — | PROBE_RTT 排空深度(BBRv3 式浅排空) |
|          | probe_rtt_duration | — | PROBE_RTT 持续时间 |

> 上表是常用子集。内核实际导出 **50 个**,完整列表:`lotspeedctl get`(或 `ls /proc/sys/net/ipv4/lotspeed/`)。

**高丢包链路怎么设 `loss_thresh`**

`loss_thresh` 的语义是"每轮丢包率低于此值不算拥塞、不退避",所以它恒等于
**环境丢包率 + 余量**,是一个可直接测量的量,不需要搜索:

```bash
# 读环境重传占比 (qdisc 侧 1s 滚动窗, 0-100)
grep -o 'ambient_share=[0-9]*' /proc/net/neoq_ml

# loss_thresh = clamp(ambient + 4, 4, 20)
lotspeedctl set loss_thresh 20        # 例: ambient 实测 18-20% 的洲际链路
```

设低了(比如在 20% 丢包的链路上留着默认 2)会让 CC 把常态丢包全当拥塞信号持续退避 ——
这正是 BBR 在这类链路上崩到 7-9 Mbps 的机制。设高了会引发重传风暴(实测 30 就会)。
要在两个候选值之间做判断,用 `lotspeedctl abtest`,不要靠观测数据相关性 —— 见下。

**`delay_cap_thresh` 的现状**

它在延迟维度上有过正面验证(netem 下 cwnd 封到 ~2055,生产尾延迟 4309→3799ms,
健康流 p50 227ms 前后无变化),但后来的人工配对 A/B 两轮都是"开了更差",于是
`lotspeedctl optimize` 现在把它冻结为 **0(关)**。两组证据可能测的不是同一个指标
(A/B 的 score 是吞吐加权的),**这个冲突尚未裁决**。在乎尾延迟的话自己跑一次:
`lotspeedctl abtest --param delay_cap_thresh --values 0,50`。


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
| `optimize --iface X [--shaper]` | 常驻控制器:整形速率反馈环 + `loss_thresh` 机制闭环 + 样本记录。`--legacy-bandit` 回到旧的参数搜索 |
| `abtest --param P --values A,B` | **交替配对 A/B + 符号检验**,本工具里唯一能对参数下因果判断的路径 |
| `bandmap --iface X` | 只读取证:把全量 socket(含 lo/docker)连同出接口/RTT 档/累计计数写成 JSONL |
| `model [show\|clear]` | 查看/清空 KNN 样本库 |
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

- **EXPLORE**:几个周期激进抢带宽,记录 `peakBw`/`minRtt` 作为 score 的参照系
- **OPTIMIZE**:score = `bw/peakBw − α·delay_inflation − β·loss`,窗口内最高分的
  `(feature, params, score)` 持久化到 `model.json`,供 `tune` 的 KNN 使用
- **参照系只在活跃拍推进**:`bw >= 5 Mbps` 才动 `peakBw`/`minRtt`。空闲拍也衰减的话,
  一台 96.8% 空闲的机器每天 3218 个空闲拍会把 `peakBw` 衰减到 ~1e-7,流量一回来
  `bw/peakBw` 恰好落在 1.0 —— 那不是好配置,是分母塌了,而它会毒化 `bestKnown` 和样本池

> **参数搜索已退役(2026-08)。** 默认的**机制模式**里 `optimize` 不再做 coordinate ascent:
> 在 SNR ≈ 1/34 的信号上分辨相邻臂需要每臂约 4600 个样本,而一台机器一天只产出约 106 个
> 学习拍,不可能收敛。人工 A/B 定下的参数冻结为常数,`loss_thresh` 由可测量的机制闭环
> 给**建议**(默认不自动写,因为它的输入 `ambient_share` 正是被它自己影响的量),
> 因果判断交给 `abtest` 的随机化交替。`--legacy-bandit` 可逐字回到旧行为。

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

**5. 判断一个参数到底有没有用 —— `abtest`**

观测数据上的相关性不足以判断参数效果:控制器自己在调参,链路自己在漂移,而很多参数
(最典型的是 `loss_thresh`)会影响它自己的输入。要下因果判断,唯一的办法是**随机化**。

```bash
lotspeedctl abtest --param loss_thresh --values 20,24 --pairs 3 --iface ens3
```

它交替跑 A/B/A/B…,每对配成一个样本,对配对差做**精确符号检验**:

- 3 对同向 → 单侧 p=0.125;默认 α=0.125,所以 3 对全同向是能过的最小样本量
- 优势方向是**事后选**的,所以族一类错误率是 2α=0.25 —— 判定看 p 单侧,强度看 p 双侧
- 未达显著时明确说"未达显著",不会含糊成"两者没差别"
- 默认**不写入**,加 `--apply` 才采纳胜者
- 主指标的胜者若在某个次要口径(延迟、丢包)上被显著判负,会给出护栏警告

判决前无条件恢复原值;Ctrl-C / SIGTERM 也会恢复。**SIGKILL 不会** —— 那会把内核停在
当时那个臂上,直到下次 `optimize` 重新播种。

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