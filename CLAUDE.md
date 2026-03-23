# LotMonitor - 智能 TCP 拥塞控制系统

## 项目目标

基于机器学习的 TCP 拥塞控制系统，核心目标:

- **降低重传率** - 通过预测拥塞，提前调整发送速率
- **提高发包效率** - 最大化带宽利用率
- **实时自适应** - 根据网络状态动态调整

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              用户空间 (Python)                               │
│                                                                              │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐              │
│  │  collector.py  │   │   trainer.py   │   │  controller.py │              │
│  │   数据采集      │ → │   DQN 训练     │ → │   实时控制      │              │
│  └────────────────┘   └────────────────┘   └────────────────┘              │
│          ↑                    ↑                    │                        │
│          │ 读取状态            │ 离线训练           │ 控制指令              │
│          │                    │                    ↓                        │
│  ┌───────┴────────────────────┴────────────────────┴───────────────────┐   │
│  │                    /proc/lotmonitor/ 接口                            │   │
│  │   samples (状态读取)              control (动作写入)                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                    ═══════════════════════════════════
                              内核边界
                    ═══════════════════════════════════
                                     │
┌────────────────────────────────────┴────────────────────────────────────────┐
│                              内核空间                                        │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    lotmonitor.ko (Netfilter 模块)                    │   │
│  │                                                                       │   │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │   │
│  │  │  状态监控        │    │   策略执行       │    │   窗口控制       │  │   │
│  │  │  • RTT 测量      │ →  │   • 读取动作     │ →  │   • 修改 rwnd    │  │   │
│  │  │  • 丢包检测      │    │   • 目标窗口     │    │   • 更新校验和   │  │   │
│  │  │  • 吞吐量统计    │    │   • 平滑过渡     │    │   • 应用限速     │  │   │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────┘  │   │
│  │                                                                       │   │
│  │  Hooks: LOCAL_IN (监控入站) ←→ LOCAL_OUT (控制出站ACK窗口)            │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ↓                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         TCP/IP 协议栈                                 │   │
│  │   发送窗口 = min(cwnd, rwnd)  ← 通过控制 rwnd 间接控制发送速率        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 核心原理

### 控制机制: 通过 rwnd 控制发送速率

TCP 发送窗口计算公式:
```
effective_window = min(cwnd, rwnd)
```

我们通过修改出站 ACK 包中的 window 字段 (即通告给对方的 rwnd)，
间接控制对方的发送速率:

```c
// 在 LOCAL_OUT hook 中
if (control_enabled && th->ack) {
    u16 target_rwnd = conn->target_rwnd;
    if (target_rwnd < ntohs(th->window)) {
        th->window = htons(target_rwnd);
        // 重新计算校验和
        th->check = tcp_v4_check(...);
    }
}
```

## MDP 定义

### 状态空间 (State)

| 特征 | 说明 | 范围 |
|------|------|------|
| `rtt_ratio` | RTT 膨胀比 (curr_rtt / min_rtt) | 1.0 - 10.0 |
| `rtt_trend` | RTT 变化趋势 | -1, 0, 1 |
| `loss_rate` | 丢包率 | 0 - 1 |
| `utilization` | 窗口利用率 (inflight / rwnd) | 0 - 1 |

### 动作空间 (Action)

| 动作 | rwnd 调整 | 触发场景 |
|------|-----------|----------|
| `DECREASE_LARGE` | rwnd *= 0.5 | 检测到丢包或严重拥塞 |
| `DECREASE_MEDIUM` | rwnd *= 0.7 | RTT 明显上升 |
| `DECREASE_SMALL` | rwnd *= 0.9 | RTT 轻微上升 |
| `MAINTAIN` | rwnd 不变 | 状态稳定 |
| `INCREASE_SMALL` | rwnd *= 1.1 | RTT 稳定 |
| `INCREASE_MEDIUM` | rwnd *= 1.3 | 有余量 |
| `INCREASE_LARGE` | rwnd *= 1.5 | 带宽空闲 |

### 奖励函数 (Reward)

```python
def reward(throughput, rtt_ratio, loss_rate):
    # 吞吐量奖励
    tp_reward = throughput / max_throughput

    # 延迟惩罚
    delay_penalty = max(0, rtt_ratio - 1.0) * 0.3

    # 丢包惩罚
    loss_penalty = loss_rate * 5

    return tp_reward - delay_penalty - loss_penalty
```

## 文件结构

```
lotspeed/
├── lotmonitor.c         # 内核模块 (监控 + rwnd 控制)
├── Makefile             # 编译配置
├── collector.py         # 数据采集工具
├── trainer.py           # DQN/Q-learning 训练
├── controller.py        # 实时控制器
├── requirements.txt     # Python 依赖
├── CLAUDE.md            # 本文档
└── mdp_data/            # 数据和模型目录
    ├── samples_*.csv    # 采集的训练数据
    ├── best_model.pth   # 最佳 DQN 模型
    ├── final_model.pth  # 最终模型
    └── policy_table.json # 导出的策略表
```

## 快速开始

### 1. 编译内核模块

```bash
make clean && make
```

### 2. 加载模块

```bash
sudo insmod lotmonitor.ko
cat /proc/lotmonitor/stats
```

### 3. 采集训练数据

```bash
# 采集 60 秒数据
make collect

# 或自定义时长
python3 collector.py collect --duration 300

# 分析数据质量
python3 collector.py analyze
```

### 4. 训练模型

```bash
# 训练 DQN 模型 (500 episodes)
make train

# 或快速训练 (100 episodes)
make train-quick

# 评估模型
make evaluate
```

### 5. 启动实时控制

```bash
# 启动交互式控制器
make control

# 或直接启动
sudo python3 controller.py start --interactive
```

### 6. 完整工作流

```bash
# 一键执行: 采集 -> 训练 -> 评估
make workflow

# 部署: 加载模块 + 启动控制器
make deploy
```

## /proc 接口

### /proc/lotmonitor/stats
全局统计信息

```
LotMonitor v2.0.0
=====================================
Active Connections: 5
RX Packets:         123456
TX Packets:         123456
-------------------------------------
Total Samples:      1000
Dropped Samples:    0
Sample Interval:    100 ms
Buffer Size:        4096
Buffer Used:        50
-------------------------------------
Control Enabled:    yes
Control Commands:   100
rwnd Modifications: 50
```

### /proc/lotmonitor/samples
实时状态样本 (CSV 格式)

### /proc/lotmonitor/control
控制接口

```bash
# 启用控制
echo "enable" > /proc/lotmonitor/control

# 禁用控制
echo "disable" > /proc/lotmonitor/control

# 设置特定连接的 rwnd
echo "192.168.1.1:8080=32768" > /proc/lotmonitor/control

# 设置所有连接的 rwnd
echo "all=16384" > /proc/lotmonitor/control

# 重置所有 rwnd
echo "reset" > /proc/lotmonitor/control
```

### /proc/lotmonitor/conns
活跃连接列表

## 模块参数

```bash
# 自定义采样间隔
sudo insmod lotmonitor.ko sample_interval_ms=50

# 启用调试模式
sudo insmod lotmonitor.ko debug_mode=1

# 启动时启用控制
sudo insmod lotmonitor.ko control_enabled=1
```

## 性能目标

| 指标 | 基线 (CUBIC) | 目标 | 说明 |
|------|--------------|------|------|
| 重传率 | 1-3% | < 0.3% | 降低 90% |
| 带宽利用率 | 70-80% | > 95% | 接近理论最大 |
| 平均 RTT | 1.5x min | < 1.15x min | 更低的排队延迟 |
| 收敛时间 | 10+ RTT | < 5 RTT | 更快适应变化 |

## 开发计划

### Phase 1: 数据采集 ✅
- [x] Netfilter 监控模块
- [x] RTT/丢包/吞吐量测量
- [x] /proc 接口
- [x] Python 数据采集器

### Phase 2: 模型训练 ✅
- [x] DQN 模型实现
- [x] Q-learning 备选实现
- [x] 网络模拟器
- [x] 策略评估

### Phase 3: 实时控制 ✅
- [x] rwnd 修改功能
- [x] /proc/control 接口
- [x] 控制器守护进程
- [x] 交互式控制

### Phase 4: 生产部署 📋
- [ ] 性能测试
- [ ] A/B 对比测试
- [ ] 文档完善
