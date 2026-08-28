# LotSpeed 安装与部署

LotSpeed = 三个组件, 三者可独立存在:

| 组件 | 产物 | 作用 |
|---|---|---|
| CC 模块 | `lotspeed.ko` (源 `lotspeed.c`) | 拥塞控制算法, BBRv3 + FAST + Hybla 混合 |
| qdisc 模块 | `sch_neoq.ko` (源 **`qdisc_newneo.c`**) | 多档队列 + CAKE 式虚拟时钟整形器 |
| 用户态控制器 | `lotspeedctl` (Go) | 自适应调参 + 整形速率反馈环 |

---

## 1. 内核要求

**硬门: 6.6+, 且内核树必须带 BBRv3 补丁。** 这不是建议值, 是编译期事实:

| 依赖 | 引入位置 | 缺了会怎样 |
|---|---|---|
| `register_net_sysctl_sz()` | 主线 6.6 | 符号找不到, 链接失败 |
| `cong_control(sk, ack, flag, rs)` 四参数签名 | 主线 6.6 | 函数指针类型不匹配, 编译失败 |
| `TCP_CONG_WANTS_CE_EVENTS`、`.skb_marked_lost` | **BBRv3 补丁集, 不在主线** | 结构体没有该成员, 编译失败 |

源码里**没有任何 `#ifdef` 向下兼容分支** —— 这是刻意的: 这些字段决定算法行为, 用兼容
垫片"编过去"会得到一个静默降级的 CC, 比编不过糟得多。

- 验证过的目标内核: `6.18.2-bbrv3`
- `sch_neoq.ko` 自身的门槛低得多 (源码里有 4.12 / 5.2 / 6.5 的兼容分支), 所以
  **6.6 这条门是 `lotspeed.ko` 的**。只装 NeoQ 不装 CC 时不受此限制。

检查:

```bash
uname -r                                    # 期望形如 6.18.2-bbrv3
ls /lib/modules/$(uname -r)/build           # 必须存在: 内核头 / 构建树
```

---

## 2. 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/adaptive-accel/install.sh | sudo bash
```

装完的落点:

```
/opt/lotspeed/                      源码 + 构建目录
/usr/local/bin/lotspeed             管理脚本 (start/stop/status/uninstall)
/usr/local/bin/lotspeedctl          控制器
/etc/sysctl.d/99-lotspeed.conf      sysctl 持久化
/etc/modules-load.d/{lotspeed,sch_neoq}.conf   开机加载模块
```

启用控制器 (模板 unit, 实例名 = 网卡名):

```bash
systemctl enable --now lotspeedctl@ens3        # 网卡叫什么就填什么
systemctl status lotspeedctl@ens3
journalctl -u lotspeedctl@ens3 -f
```

### 2.1 DKMS (强烈建议, 近乎必选)

`/etc/modules-load.d/*.conf` 只表达"开机 modprobe 这个名字"。**内核一升级, 新内核目录
下没有这两个 `.ko`, modprobe 静默失败, CC 回落到 bbr/cubic, qdisc 回落到 fq_codel。**
无人值守安全更新会让这件事在没有任何人操作的深夜发生, 用户看到的只是"加速某天突然没了"。

仓库根目录的 `dkms.conf` 把"每装一个新内核就重编一次"接到内核包 postinst 上:

```bash
sudo apt-get install -y dkms                       # 或 yum install dkms
sudo cp -r /opt/lotspeed /usr/src/lotspeed-2.2     # 目录名必须是 <名>-<版本>
sudo dkms add    -m lotspeed -v 2.2
sudo dkms build  -m lotspeed -v 2.2
sudo dkms install -m lotspeed -v 2.2
dkms status                                        # lotspeed/2.2, <kver>, x86_64: installed
```

`/usr/src/lotspeed-2.2` 里的 `PACKAGE_VERSION` 必须与目录名后缀、与 `install.sh` 顶部的
`VERSION=` 三者一致。

> 一个 DKMS 包带两个模块。注意 `BUILT_MODULE_NAME[1]="sch_neoq"` —— **源文件叫
> `qdisc_newneo.c`, 产物叫 `sch_neoq.ko`** (Makefile 里 `sch_neoq-objs := qdisc_newneo.o`
> 做的改名)。写成源文件名会编译成功、然后在 "module not found" 上失败。

---

## 3. 对端要求 (**只装本机 = 只解决一半**)

单流吞吐的上限是 **接收端 rwnd / RTT**, 这是 TCP 不变式 (in-flight ≤ min(cwnd, rwnd)),
不是本项目能在发送端绕过的东西。已实测: **只改测试机的 `tcp_rmem` max, 6MB → 128MB,
colo 与 CC 一个字没动, 单流吞吐 3.4×** (47M → 159M 均值)。

含义很直接:

- 本机 (发送端) 装 LotSpeed → **上传方向** 受益。
- **下载方向受对端 rmem 约束。** 对端 rmem 小, 本机装再多也顶不上去。

所以对端 (下载方主机, 通常是国内那台) 也应该调:

```bash
# /etc/sysctl.d/99-lotspeed-peer.conf
net.ipv4.tcp_rmem = 4096 262144 134217728     # max = 128MB
net.core.rmem_max = 134217728                 # 128MB
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1              # 保持自动调优开启 (默认就是 1)
```

```bash
sudo sysctl --system && sysctl net.ipv4.tcp_rmem
```

几条容易踩的:

- **128MB 不是预分配。** `tcp_rmem` 的第三个值是 autotune 的**上界**, 不是每个 socket
  的实际占用。实际占用随窗口增长, 空闲连接仍是第二个值那一档。
- **`rmem_max` 不封顶 autotune。** 它只封 `setsockopt(SO_RCVBUF)` 的手动设置。两个都设
  是为了照顾那些自己调 SO_RCVBUF 的应用 (设了 SO_RCVBUF 的 socket 会**关闭** autotune,
  此时 `rmem_max` 就是硬顶)。
- **怎么定这个数**: `BDP = 带宽 × RTT`。300 Mbps × 264 ms ≈ 9.9 MB, 128MB 留了约 13×
  余量, 覆盖 RTT 漂到 1s 以上的劣化时段。内存紧的机器给 64MB 也够。
- 现代客户端 OS 默认 autotune 上限普遍 16MB+, 通常不需要动; **需要动的是那些默认
  6MB 的老配置和测试机**。

---

## 4. 卸载纪律 (rmmod 会失败, 这是正常的)

两个模块都有引用计数, **必须先把使用者摘掉再卸**, 否则 `rmmod` 报
`Module is in use` / `File exists`。

正确顺序:

```bash
# 1. CC 换回内建算法 (必须早于 rmmod lotspeed)
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# 2. 每一个挂了 neoq 的网卡都要摘 (必须早于 rmmod sch_neoq)
sudo tc qdisc replace dev ens3 root fq_codel

# 3. 等在途 socket 释放, 确认 refcount 归零
lsmod | grep -E '^lotspeed|^sch_neoq'        # 第三列必须是 0

# 4. 卸载
sudo rmmod sch_neoq
sudo rmmod lotspeed
```

### 4.1 “SSH 自 pin” —— 为什么 refcount 降不到 0

**每个 TCP socket 在创建时就把当时的默认 CC 模块引用住了** (`tcp_init_sock` →
`tcp_assign_congestion_control`)。也就是说:

> 你用来执行 `rmmod` 的那条 SSH 连接, 如果是在 `CC=lotspeed` 的时候建立的, 它自己就
> 持有一份引用。之后再怎么 `sysctl -w ...=bbr` 都改不了它 —— sysctl 只影响**此后**新建
> 的 socket。

**做法: `sysctl` 和 `rmmod` 必须在两条不同的 SSH 连接里执行。** 先连上去把 CC 切成 bbr,
**断开**, 重新连一次 (这条新连接用的是 bbr), 再执行 rmmod。

同一个机制还有另外三类持有者, 一起查:

| 持有者 | 为什么看不见 | 处理 |
|---|---|---|
| LISTEN socket | `ss -tip \| grep lotspeed` 不显示 listener 的 cc | `ss -tlni` 找出来; pkill 掉守护进程 → rmmod → 再起 |
| 容器 / netns 的默认 CC | 每个 netns 的 `tcp_congestion_control` 各持一份引用 | `lsns -t net` 枚举; `nsenter -t <pid> -n sysctl -w ...` 或重启容器 |
| 半关闭 socket | `ss -K state established` 漏掉 FIN_WAIT / CLOSE_WAIT / LAST_ACK | `ss -K "( sport != :22 and dport != :22 )"` |

最后一条尤其重要: **`ss -K` 的过滤条件一定要排除 :22**, 否则你会在踢掉别人的同时踢掉
自己这条 SSH。

---

## 5. 从既有手工部署迁移

生产机 (green1, 网卡 `ens3`) 上的 `/opt/lotspeed` 是 2026-02 手工 `scp` 上去的目录,
**不是 git 工作树** —— 没有 `.git`, 没有 remote, 与本仓库的对应关系只存在于当时那次拷贝。
直接在上面 `git pull` 是不可能的; 直接覆盖会丢掉手工改过的东西。

迁移步骤 (先在非生产机上完整走一遍):

```bash
# 1. 先取证: 手工目录和仓库到底差在哪
diff -ru /path/to/repo /opt/lotspeed | tee /root/lotspeed-drift.diff
# 重点看 lotspeed.c / qdisc_newneo.c / Makefile;
# 生成物 (*.ko *.o *.mod* Module.symvers modules.order) 的差异是噪音, 忽略

# 2. 原地备份 (不删, 只改名 —— 回滚就是改回来)
sudo mv /opt/lotspeed /opt/lotspeed.manual-2026-02

# 3. 用当前分支重新铺一份
sudo git clone -b adaptive-accel https://github.com/uk0/lotspeed /opt/lotspeed

# 4. 把第 1 步里确认要保留的手工改动挑回来 (逐个文件, 不要整目录覆盖)

# 5. 接 DKMS (见 2.1), 然后用模板 unit 起控制器
sudo systemctl disable --now lotspeedctl.service 2>/dev/null || true   # 旧的硬编码 eth0 版
sudo cp /opt/lotspeed/lotspeedctl/lotspeedctl@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lotspeedctl@ens3
```

几点纪律:

- **不要在生产机上跑 `install.sh` 来"就地升级"。** 它会重编模块并触碰
  `/etc/sysctl.d` 与 `modules-load.d`; 这台机器上同时跑着 nginx / xray / docker。
  升级路径是"先备份, 再铺, 再逐项对齐", 不是"重跑安装脚本"。
- **模块换代必须走完第 4 节的卸载顺序**, 且 `sysctl` 与 `rmmod` 分两条 SSH。
- 旧的 `lotspeedctl.service` 把网卡写死成 `eth0`, 在 `ens3` 的机器上是**每 3 秒重启一次
  且加速从未生效**。迁移时必须 disable 掉, 不能和 `lotspeedctl@ens3` 并存 —— 两个实例
  会同时写 `/proc/net/neoq_rate`, 互相打架。

---

## 6. 效果数字的口径声明

**下面所有数字都是脚本化测试流 (iperf3 定向对拉) 的口径, 不是被动生产观测统计。**
读者不应把它们理解为"生产上真实用户体验平均提升了 N 倍"。

| 指标 | 数值 | 口径 |
|---|---|---|
| CC 对照 (vs BBR v3) | **7.3×** — 中位 18.43 vs 2.52 Mbps | 三轮**交替配对**测试, 同链路同时段轮换以抵消跨时段漂移。测试流。 |
| 排队延迟 | **309 ms → 4–6 ms** | 同批测试流内的排队时延观测。 |
| 丢包高峰单流 | +91% (67M vs 35M) | `iperf3 -R` 30s/轮, 交替轮换。测试流。 |
| 多流 P8 | +93% (366M vs 190M) | 同上。 |

关于口径, 三条必须说清:

1. **交替配对 ≠ 同时对比。** 两个 CC 不能同时跑在同一条流上, 所以是 A/B/A/B 轮换取中位
   数。这消除了慢漂移, 但消不掉轮次内的突发抖动 —— 所以看**中位数**, 不看单轮最好值。
2. **测试流的负载形状 ≠ 生产负载。** iperf3 是长期满速单向大流; 生产流量是隧道里的
   交互小包与批量传输混跑。测试流量恰好落在 lotspeed 最占优的工况上 (长肥管 + 丢包)。
3. **唯一的生产实测是延迟护栏那一条**, 且是**个别流**的观测而非统计:
   一条膨胀到 4309 ms 的真实流在 8s 内降到 3799 ms, 同时段健康流 (p50 227 / max 243 ms)
   在开关前后 4 个观测窗完全不变 (零误伤)。这是"该生效时生效、不该动时不动"的证据,
   **不是**吞吐提升的生产证据。

也要说清**没有测过什么**: 没有生产环境的被动 A/B, 没有用户侧体感统计, 没有长周期
(> 数小时) 的稳定性统计。宣称收益时请连同上面的口径一起给出。
