
dmesg -c

make clean && make
sudo rmmod zeta_tcp 2>/dev/null
sudo insmod zeta_tcp.ko verbose=1


# 生成流量
nohup curl -o /dev/null http://speedtest.tele2.net/500MB.zip &

# 查看日志
dmesg -w | grep -E "(ENTER_MODIFY|CALLING|returned|SUCCESS|NO CHANGE)"


cat /proc/zeta_tcp/stats
cat /proc/zeta_tcp/connections
