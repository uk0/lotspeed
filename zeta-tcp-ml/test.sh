
dmesg -c

make clean && make
sudo rmmod zeta_tcp 2>/dev/null
# 加载（启用 ACK Splitting）
sudo insmod zeta_tcp.ko verbose=1 ack_split=1

# 查看模块详细信息
modinfo zeta_tcp.ko

# 查看内存布局
size zeta_tcp.ko

# 查看 SLAB 缓存（加载后）
cat /proc/slabinfo | grep zeta

# 查看统计
cat /proc/zeta_tcp/stats
cat /proc/zeta_tcp/percpu
cat /proc/zeta_tcp/connections

# 配置 ACK Splitting
echo "ack_split=1" | sudo tee /proc/zeta_tcp/config
# 去掉debug
echo "verbose=1" | sudo tee /proc/zeta_tcp/config

# 生成流量
nohup curl -o /dev/null http://speedtest.tele2.net/500MB.zip &

# 查看日志
dmesg -w

