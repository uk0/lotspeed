# Changelog

## 2026-08-28 参数搜索退役 + 安装/管理面重做 {#2026-08-28-mechanism}

### 为什么退掉 bandit

优化器在一个 12 臂空间里搜 `loss_thresh`,实测 SNR 约 1/34 —— 要分辨相邻臂需要每臂约 4600 个样本,而 green1 一天只产出约 106 个学习拍。它不可能收敛,那些臂搜的是噪声。人工 A/B 已经定下来的几个参数(`startup_gain` / `hd_rho_max` / `fast_alpha` / `delay_cap_thresh` / `neoq_sparse_thresh` / `shaper_headroom`)冻结为常数,写入点收敛到 `applyFrozenConstants` 一处。`--legacy-bandit` 逐字恢复旧表。

`loss_thresh` 拆成两件各自能做对的事:

- **闭环只测量与报告**。`lossThreshFor(ambient, rtt)` 是冷启动与运行时共用的唯一实现;ambient 首选 qdisc 的 `ambient_share`(1s 滚动窗,只计 ≥128B 的包),退化时用 ss/snmp 差分。全部状态只在活跃拍推进。
- **`lotspeedctl abtest` 负责裁决**。交替配对 A/B + 精确符号检验,是本工具里唯一能对参数下因果判断的路径。

闭环默认**不写** sysctl。`ambient_share` 就是重传占比,而 `loss_thresh` 正是决定 CC 遇到丢包退不退避的旋钮:抬高它 → 少退避 → 重传占比上升 → 公式据此要求更高的值。回归量与误差项相关,参数在观测数据上不可识别。实测棘轮:真实 ambient 8%(正确答案 12)时,自致系数只要 ≥0.2pp/单位就会越过正确答案,≥0.5pp 直接钉死在上限。打破它需要外生变异,那正是 `abtest` 的交替提供的。`--auto-loss-thresh` 供不适用此推理的链路使用。

### 安装与管理面

- `install.sh` 1692 → 644 行。停止发 `rmmod -f`,改成六步卸载:切 CC → `tc` 摘 qdisc → 停服务 → 等 refcount → rmmod → 校验。失败时打印真实 refcount 与持有者提示,而不是强拆。
- 管理脚本从 942 行内联堆砌降成 100 行的 `lotspeedctl` 薄别名。
- systemd unit 改成模板 `lotspeedctl@%i.service`。旧 unit 把网卡写死成 `eth0`,而目标机器叫 `ens3` —— 后果不是启动失败,是 `Restart=always` 下每 3 秒重启一次、加速从未生效。
- 新增 `dkms.conf`、`INSTALL.md`。

### 本轮修掉的接线缺陷

- `measure()` 从未把 `ambient_share` 搬进 metrics,闭环一直跑在 ss/snmp 兜底上,日志却打印 `src=ambient_share`。
- `abtest` 在 `main.go` 的 dispatch 里没有 case —— 809 行实现加 17 个单测全绿,因为测试直接调 `cmdABTest`,绕过了 dispatch。`wiring_test.go` 现在断言每个 `cmdXxx` 都有调用点。
- `applyFrozenConstants` 无条件把 `loss_thresh` 播成 4,等于每次启动都断言链路干净;配合 `Restart=always`,任何一次崩溃都把 18% ambient 的链路打回 bbr 等效行为。改为读运行值。
- `preset intercontinental` 写 30、`tuneForLoss` 写 50,都高于本仓库自己测出重传风暴的阈值。

### 部署验证 (green1, 6.19.3, ens3)

一次 134 秒窗口完成换装。`lotspeed` `A211B185` → `DA4CA374`,`sch_neoq` `566CB0B1` → `946CCDF0`。refcount 归零耗时 99s(容器 netns 与 socket-activated `ssh.socket` 是主要持有者)。换装后 nginx HTTP 200 / 1.2ms,3 个容器正常,`lotspeedctl@ens3` `NRestarts=0`,无内核告警。`ambient_share=20` 与此前实测的 18-20% 一致。回滚点 `/opt/lotspeed-p0`(`E2A637C8`)保留。

117 个用例通过。

## adaptive-accel (2026-06)

行为化调度 + 学习闭环分支。全部特性在真实洲际链路（美东 colo → 国内，RTT 13↔264ms 漂移、丢包 2-10%）上完成 A/B 验证，对照为同内核 BBR v3。

### 实测结果摘要

| 场景 | lotspeed | BBR v3 | Δ |
|---|---|---|---|
| 多流 P8（交替 A/B 均值） | **366 Mbps** | 190 Mbps | **+93%** |
| 丢包高峰单流 | **67 Mbps**（崩溃轮稳 45-78M） | 35 Mbps（崩至 7-9M） | **+91%** |
| 干净时段单流 | ≈持平（per-flow ISP 限制所致） | — | — |
| 并发扩展（P1→P16） | 118M → 442M | — | 链路容量 ≥442M |
| 短流 256KB（hist 暖缓存） | 中位 **-19%**，尾延迟 **-49%**（2.34→1.20s），方差 ±0.5→±0.08s | — | hits/seeds 100% 转化 |
| 混合负载（P8 满载 + 交互小包） | bulk 356M + Express 排队 **1-2us**、0 drop | fq_codel：bulk 340M、p99 +5ms | — |
| 生产 ~3h 抽样 | hist 70/70 命中；**25.6% 重传被防滥用门隔离**；全 tier 0 drop | — | — |

### CC（lotspeed.c）

- **min_rtt 双窗口修复**：`<=` 比较在相等时重新盖戳导致 10s 过期窗与 PROBE_RTT 永不触发、min_rtt 锁死全时最低（RTT 上漂时 cwnd 目标偏小最高 20×）。分离短窗（probe_rtt_min_stamp, 5s）与全局窗（min_rtt_stamp, 10s）；PROBE_RTT 复活并改 BBRv3 式浅排空（~50% BDP，不再砍到 min_cwnd）。
- **CRUISE headroom 门控**：-6.25% 的 inflight headroom 仅在 loss 压力（inflight_lo 被收缩）时应用，干净单流不再恒扣。
- **hist 短流加速（v2/v3，四轮迭代闭环）**：
  - lookup 改种 **bw 滤波器**（×0.7 折扣）替代种 cwnd/min_rtt——pacing CC 的发送闸门是 pacing rate，旧实现种 cwnd 对短流无效；错误种子在一个滤波窗内被真实样本自愈。
  - lookup 命中时**直写 sk_pacing_rate**——bw 种子不立即生效（pacing 仅在 per-ACK 路径重算），首轮 1 RTT 的空窗会吞掉全部收益。
  - **长连接周期写入**（10s）——原先仅在连接关闭时写入，永不关闭的隧道连接从不贡献样本，缓存恒冷。
  - 不再种 min_rtt（漂移链路上旧 era 的 min_rtt 会卡死短流的 cwnd 目标）。
  - `/proc/net/lotspeed_hist` 可观测接口（hits/seeds 计数 + 全表 dump）——前三轮盲调无果，证据链一轮定位门槛拦截（sample_cnt 3→2）。
  - 安全闸全保留：STARTUP 不跳过、写入 sanity check、TTL、毒化兜底下界。

### NeoQ（qdisc_newneo.c）

- **CAKE 式 sparse/bulk 行为分类**：流速率低于阈值（默认 2×quantum/100ms，`/proc/net/neoq_sparse` 可调）保持 Express/High；持续超阈值自动降级——端口无关，隧道内混合流量同样生效。端口 hint 仅对小包提速，大包不再因 443/80 进 Express。
- **全局 5-tuple flow 表**：替代 4 个每档独立表，连接状态（highest_seq/srtt/CoDel）连贯，重传检测真正工作；分类一次（原先两次 + 重传第三次 hash）。
- **跨档 WRR 8:4:2:1**（字节配额，work-conserving）替代严格优先级——bulk 吃满剩余带宽且不被饿死；补充循环无上限（有上限时一个 64KB GSO 包可造成假空停摆，用户态复现验证）。
- **满队列驱逐**：Express/High 到达时从最低非空档驱逐，而非丢弃高优包。
- **重传 CoDel 免疫**：重传包被 CoDel 判 drop 时改 CE 标记或放行（250ms 链路丢恢复包 = 恢复时间翻倍），drop 动作顺延至下一非重传包，普通流量控制律不变。
- **Express 防滥用门**：上一 100ms 窗口重传占比 >15%（`/proc/net/neoq_retrans` 可调）且 bulk 行为的流，其重传不再升 Express（仍保留 CoDel 免疫）——高丢包下 bulk 重传洪泛不挤占交互快车道。
- **compute-then-commit 分类**：被丢弃的包不再污染 highest_seq/速率窗口（原先丢弃包会导致后续真实传输被误判重传、错误降级）。
- `/proc/net/neoq_ml` 机器可读统计（每档 pkts/bytes/drops/marks/延迟 + retrans 计数器）供调优器消费；IPv6 流哈希；GSO 段计数对称；rwnd boost 默认关闭（egress-only 无法获知对端 wscale，无法做对）。

### lotspeedctl（自适应调优器）

- **Δ 信用归因**：reward = 同窗配对增量，只 credit 本周期变化的参数——原先单个 score 记给全部参数，无效参数靠链路天气也能"学出"偏好（纯噪声拟合）。
- **reward 调理**：压缩至 [0,1]、有效计数封顶（旧 regime 自动遗忘）；坏链路周期（rtt 通胀 >2×）跳过信用与决策；apply 后 settle（8×RTT）再测，杜绝把上一配置的尾巴记到新配置头上。
- **体验感知 score**：`- γ·clamp(Express峰值延迟/5ms)`（读 neoq_ml，仅混合负载时生效）+ `- 0.2·clamp(jitter_MAD/rtt)`——吞吐、延迟、抖动三维质量目标。
- **per-target 测量**：`--target` 时 rtt/loss/bw 全部来自该目标的 per-socket 增量（churn 自动重基线）——混合出口（近端 CDN 13ms + 洲际 250ms 并存）下全机 minRtt 被近端连接锚定、健康样本被系统性打成负分的问题就此修复（生产 354 样本实锤后验证：rtt 信号纯净、score 回归健康区间）。
- 效应量冻结（无效参数自动出局）、loss-aware 冷启动、KNN 同 regime 邻居门控、`loss_thresh` 范围收窄至实测甜区、`neoq_sparse_thresh` 范围覆盖网页突发与持续下载的真实分界（0.24-9.9 Mbps，6 arms）。

### 运维

- 模块换装顺序与引用持有者排查手册（listener / 容器 netns / 半关闭 socket 均持 CC 引用）见 README 注意事项。
- 学习闭环 systemd 服务化：开机 bbr 安全默认，服务拉起后切换；空闲（无真实流量）时自动 holding 不产生噪声样本。
