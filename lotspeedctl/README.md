# lotspeedctl

自适应 TCP 加速控制器 —— 统一控制 **LotSpeed 拥塞控制** + **NeoQ qdisc**,面向洲际高丢包/高延迟链路。

## 目标
- **对抗洲际丢包**、解决 TCP 起步慢
- **游戏/网页流量优先加速**(NeoQ 多层队列)
- **数据驱动自适应寻优**:前期激进抢带宽 → 长期平衡最大带宽与延迟

## 编译
内核模块只能在容器内构建(byJoey 内核 host 工具是 24.04 glibc),CLI 本地交叉编译即可:
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lotspeedctl .
scp lotspeedctl root@host:/usr/local/bin/
```

## 命令
| 命令 | 说明 |
|------|------|
| `status` | 当前 CC + 可用 CC + lotspeed 关键参数 + NeoQ 统计 |
| `enable [iface]` | 设 `CC=lotspeed`(+ 给 iface 挂 `neoq` qdisc) |
| `disable [iface]` | 还原 `CC=bbr`(+ 移除 iface 的 neoq) |
| `set <param> <val>` / `get [param]` | 读写 `/proc/sys/net/ipv4/lotspeed/<param>` |
| `preset <name>` | `intercontinental` / `game` / `web` / `balanced` |
| `monitor [sec]` | 实时刷新 CC + NeoQ 统计 |
| `daemon --iface X [--interval N]` | 抗丢包闭环 **+ 自动游戏/网页优先级** |
| `optimize --iface X [--interval N]` | 自适应寻优(`EXPLORE` 抢带宽 → `OPTIMIZE` 调参) |
| `prio [list\|add P..\|del P..\|clear\|auto]` | NeoQ 优先端口管理(`auto`=自动识别游戏/网页) |

## 工作原理
- **抗丢包**:`daemon` 采集 `/proc/net/snmp` 重传率 → 动态调 `loss_thresh`/`fast_recovery`/`brave`(实测 8% loss → loss_thresh 2→50)
- **游戏/网页优先级**:`prio auto` 解析 `ss` 识别 web(443/80)+ 游戏(活跃 UDP 端口)→ 写 `/proc/net/neoq_prio` → NeoQ `classify` 命中 → **EXPRESS tier**(实测端口 5201 流量整体进 Express)
- **自适应寻优**:`optimize` 内存维护 `peakBw`/`minRtt` 基线,`score = bw/peakBw − α·max(0,rtt/minRtt−1) − β·loss`,coordinate ascent 逐参数爬山,变差则回退(min/max 护栏)

## systemd 常驻服务
`/etc/systemd/system/lotspeedctl.service`:
```ini
[Unit]
Description=LotSpeed adaptive accelerator
After=network-online.target

[Service]
ExecStartPre=/usr/local/bin/lotspeedctl enable eth0
ExecStart=/usr/local/bin/lotspeedctl optimize --iface eth0 --interval 5
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
```bash
systemctl enable --now lotspeedctl
```

## 依赖
- 已加载 `lotspeed.ko`(CC)+ `sch_neoq.ko`(qdisc)— 见 `docs/tasks/lotspeed-fixes.md` 的容器编译方案
- `iproute2`(`ss`/`tc`)、Secure Boot 关闭(否则未签名模块无法加载)
