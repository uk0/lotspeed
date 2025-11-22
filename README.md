### lotspeed zeta-tcp

<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/zeta-tcp/img.png" width="400" height="400" />
</div>


### branch explanation

* `zeta-tcp`: lotspeed zeta-tcp 参考AppEx Networking TCP算法优化版本
* `main`: lotspeed 自动优化版本最新版
* `v2.1`: lotspeed 暴力版本
* `v3.1`: lotspeed 最小优化算法版本
* `lotspeed-mini`  lotspeed 极简版本，仅包含核心代码



* auto install


```bash
curl -fsSL https://raw.githubusercontent.com/uk0/lotspeed/zeta-tcp/install.sh | sudo bash
#   or
wget -qO- https://raw.githubusercontent.com/uk0/lotspeed/zeta-tcp/install.sh | sudo bash
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


* helper （lotserver_beta越小强的越凶，建议大雨620否则会导致CPU飙高）

```bash
root@racknerd-6bf1e7b:~# lotspeed
╔════════════════════════════════════════════════════════════════════╗
║                      LotSpeed v5.6 Management                      ║
╟────────────────────────────────────────────────────────────────────╢
║ start                                               Start LotSpeed ║
║ stop                                                 Stop LotSpeed ║
║ restart                                           Restart LotSpeed ║
║ status                                                Check Status ║
║ preset [name]                                         Apply Config ║
║ set [k] [v]                                          Set Parameter ║
║ monitor                                                  Live Logs ║
║ uninstall                                        Remove Completely ║
╟────────────────────────────────────────────────────────────────────╢
║ Presets: conservative, balanced                                    ║
╚════════════════════════════════════════════════════════════════════╝
```


### test youtube


<div align=center>
    <img src="https://github.com/uk0/lotspeed/blob/zeta-tcp/img_2.png" width="1024" height="768" />
</div>


### test iperf3

```bash

sudo tc qdisc add dev ens3 root netem loss 6%

sudo tc qdisc del dev ens3 root netem 


 iperf3 -s -p 25201
 iperf3 -c green1 -p 25201 -R -t 30
```


### changelog
* 支持 `debian`,`ubunut` 5.x.x ,6.x.x 内核
* RN垃圾服务器能实现双 `8K 60fps` 秒开，


