### lotspeed 开心版

<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/main/img.png" width="400" height="400" />
</div>


### branch explanation

* `main`: lotspeed 自动优化版本最新版
* `v2.1`: lotspeed 暴力版本
* `v3.1`: lotspeed 最小优化算法版本
* `lotspeed-mini`  lotspeed 极简版本，仅包含核心代码



* auto install


```bash
curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
#   or
wget -qO- https://raw.githubusercontent.com/uk0/lotspeed/main/install.sh | sudo bash
```


* manual compile and load

```bash

# 下载代码/编译

git clone https://github.com/uk0/lotspeed.git 

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

```


* helper

```bash
root@racknerd-6bf1e7b:~# lotspeed
╔════════════════════════════════════════════════════════╗
║        LotSpeed v3.3 Management Tool                   ║
║        公路超跑 完整整合版                                ║
║        Created by uk0 @ 2025-11-20 19:14:01            ║
╚════════════════════════════════════════════════════════╝

Usage: lotspeed {command} [options]

Commands:
  start       - Start LotSpeed
  stop        - Stop LotSpeed (switch to default algorithm)
  restart     - Restart LotSpeed
  status      - Show current status and parameters
  preset      - Apply preset configuration
  set         - Set parameter value
  connections - Show active connections
  log         - Show recent logs
  monitor     - Monitor logs in real-time
  benchmark   - Run simple speed test
  uninstall   - Completely uninstall LotSpeed

Presets:
  lotspeed preset conservative  - 1Gbps, 1.5x gain, safe
  lotspeed preset balanced      - 5Gbps, 2.0x gain [RECOMMENDED]
  lotspeed preset aggressive    - 10Gbps, 3.0x gain
  lotspeed preset extreme       - 20Gbps, 5.0x gain, TURBO
  lotspeed preset bbr-like      - BBR-style behavior
  lotspeed preset debug         - Enable debug logging

Examples (v3.3 new features):
  lotspeed status                          # Check status
  lotspeed preset balanced                 # Apply balanced preset
  lotspeed set lotserver_rate 0            # Auto-detect rate
  lotspeed set lotserver_gain 25           # Set 2.5x gain
  lotspeed set lotserver_beta 819          # Set 80% fairness
  lotspeed set lotserver_turbo 1           # Enable turbo mode
  lotspeed set lotserver_verbose 1         # Enable debug log
  lotspeed set lotserver_adaptive 1        # Enable adaptive
  lotspeed set force_unload 1              # Force unload
  lotspeed monitor                         # Watch real-time logs

Advanced Examples:
  # For 100Mbps VPS:
  lotspeed set lotserver_rate 12500000     # 100Mbps limit
  lotspeed set lotserver_gain 18           # 1.8x gain

  # For 10Gbps dedicated server:
  lotspeed set lotserver_rate 1250000000   # 10Gbps
  lotspeed set lotserver_gain 30           # 3.0x gain
  lotspeed set lotserver_max_cwnd 10000    # Large cwnd

  # For lossy network (packet loss):
  lotspeed set lotserver_beta 921          # 90% (gentle)
  lotspeed set lotserver_turbo 1           # Ignore loss

Note: v3.3 includes ProbeRTT, Smart Startup, ECN support
```


### test youtube


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/main/img_2.png" width="1024" height="768" />
</div>



### changelog
* 支持 `debian`,`ubunut` 5.x.x ,6.x.x 内核
* RN垃圾服务器能实现双 `8K 60fps` 秒开，


