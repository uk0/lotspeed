### lotspeed 开心版




```bash

# 编译

make

# 加载模块
sudo insmod lotspeed.ko

# 设置为当前拥塞控制算法
sudo sysctl -w net.ipv4.tcp_congestion_control=lotspeed
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1

# 查看是否生效
sysctl net.ipv4.tcp_congestion_control

# 查看模块参数
ls -la /sys/module/lotspeed/parameters/
# 你会看到以下参数：
lotserver_adaptive  lotserver_gain  lotserver_max_cwnd  lotserver_min_cwnd  lotserver_rate  lotserver_turbo

cat /sys/module/lotspeed/parameters/lotserver_rate
cat /sys/module/lotspeed/parameters/lotserver_gain

# 调整参数（例如设置为 5Gbps）
echo 625000000 | sudo tee /sys/module/lotspeed/parameters/lotserver_rate

lsmod |grep lotspeed
```