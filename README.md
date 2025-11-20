### lotspeed 开心版

<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/main/img.png" width="400" height="400" />
</div>



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

* 核心原理与设计哲学

<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/main/img_1.png" width="800" height="600" />
</div>



* helper

```bash

root@ubuntu:~# lotspeed
╔════════════════════════════════════════════════════════╗
║          LotSpeed v2.0 Management Tool                 ║
║          Created by uk0 @ 2025-11-18                   ║
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
  uninstall   - Completely uninstall LotSpeed

Presets:
  lotspeed preset conservative  - 1Gbps, 1.5x gain
  lotspeed preset balanced      - 5Gbps, 2.5x gain [RECOMMENDED]
  lotspeed preset aggressive    - 10Gbps, 4.0x gain
  lotspeed preset extreme       - 20Gbps, 5.0x gain, TURBO

Examples:
  lotspeed status
  lotspeed preset balanced
  lotspeed set lotserver_rate 1000000000
  lotspeed set lotserver_turbo 1
  lotspeed monitor
```


### test youtube


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/main/img_2.png" width="1024" height="768" />
</div>



### changelog
* 支持 `debian`,`ubunut` 5.x.x ,6.x.x 内核
* RN垃圾服务器能实现双 `8K 120fps` 秒开，
