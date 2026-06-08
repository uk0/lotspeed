# 招牌功能修复 — review 后优化

## 目标
review 发现三大招牌功能失效。按 ROI 修复 + colo 部署内核 + 10段测试机拉下载验证。
测试方向: 测试机 iperf3 -R 拉 colo 上传 = 下载方向 = 单边加速正确测法 (10段上传低/下载高)

## 修复清单
- [x] C1 CLI PASSIVE 不记录样本 — 已修已部署 (commit 72415f6)
- [x] K1 内核 loss_thresh 死代码 → 接通丢包率门控 (抗丢包核心)
- [ ] N1 NeoQ rwnd 诱骗无视 window scaling → 感知 wscale
- [ ] N2 NeoQ 分类两次 → 一次/单 flow 表 (重传→Express 快恢复)  (K3幽灵RACK已随K1顺手中和)
- [x] C3 score peakBw 永不衰减 → 衰减/窗口化
- [ ] C2 UCB 信用分配错误 → 只 credit 变化的参数(delta)
- [ ] C5 loss/RTT 全机 → per-link
- [ ] C6 heuristicPlan 与优化器参数集脱节 → 统一

## 编译/部署
- docker 24.04 lsbuild 容器编译 (glibc 2.39 匹配 byJoey 内核 host 工具)
- 卸载顺序: sysctl bbr → tc fq_codel → 等 socket 释放 → rmmod sch_neoq && rmmod lotspeed
- 装新: cp .ko /lib/modules/$(uname -r)/extra/ → depmod -a → modprobe

## 验证基线
- 当前: lotspeed(hist=0) vs bbr +7%; UCB-tuned +36% (噪声大)
- K1 后预期: 高丢包链路下载吞吐显著提升 (不再每轮砍 cwnd)

## ✅ K1 验证结果 (测试机拉 colo 下载, 5 轮交替)
| 配置 | 均值 | vs bbr |
|------|------|--------|
| bbr | 35M | 基线 |
| lotspeed K1 lt=2 | 67M | +91% |
| lotspeed K1 lt=30 | 53M | +51% |

- 丢包高峰期 (R1/3/5): bbr 崩 7-9M, lotspeed 稳 45-78M ← 洲际抗丢包核心价值
- 反直觉: lt=2 > lt=30 (lt=30 重传 1724/3441/2385 高, 自造拥塞 → 有效吞吐降)
- 教训: loss_thresh 最优适中(~2), 非越大越好。优化器 range 应收窄 2->~16, 别探到 50
- K1 实现: 新增 loss_too_high:1 (复用死位 bw_probe_samples, struct 不变), 按 tx_in_flight 丢包率门控,
  只在 backoff 两点(1809砍下界/2094中止PROBE_UP)用它。K3 幽灵RACK设的是loss_in_round不再触发backoff

## N1/N3 实测结论 (重要规律)
- N1 (rwnd 诱骗 wscale): 实测推翻 agent. boost 线性生效非 no-op; 但 colo 有 32MB rmem,
  接收窗口自动涨到 26MB ≫ BDP 2.5MB, rwnd 从不是瓶颈 → 诱骗在 colo 无用武之地. 不改.
- N3 (CoDel RTT 自适应): CLI 驱动实现 (出站 qdisc 测不到 RTT). 实测 2 组矛盾(aggr 65 vs def 53; def 58 vs ada 50)
  → 统计不显著, 链路噪声淹没. 单流 path-limited 场景 colo 出站队列小(pacing), 瓶颈在洲际路径中间非本地.
- 规律: 单流洲际吞吐 CC 才是杠杆(K1 +91%); NeoQ AQM/窗口戏法不在瓶颈上.
  NeoQ 真正价值=多流竞争优先级(游戏/网页 vs 大下载). N3 代码保留(正确+匹配原设计死函数, egress瓶颈/多流场景有用).
- 下一杠杆: CC 深度优化 K2(max_cwnd高速封顶) / STARTUP高RTT更激进 / Hybla rho 边界滞现
