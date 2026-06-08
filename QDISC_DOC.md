### 加载 NeoQ 模块

``` 
sudo insmod sch_neoq.ko
```


### 在接口上启用 NeoQ

```
sudo tc qdisc replace dev eth0 root neoq
```

### 查看状态

```
tc -s qdisc show dev eth0

# 默认不支持show方法，直接查看文件即可。

[linux-6.18.2]# cat /proc/net/neoq
===============================================
 NeoQ v3.0 Statistics
===============================================
 Queue Length:    0 / 10240 packets
 Memory:          0 / 33554432 bytes
 Active Flows:    5 / 4096
 HTTP Boost:      ON
 ECN:             ON
 Target Delay:    5000 us
 Interval:        100000 us
-----------------------------------------------
 Tier       Packets       Bytes    Drops  Marks  Flows  Backlog
-----------------------------------------------
 Express        2851      372240        0      0      2        0
 High              2         450        0      0      1        0
 Normal            7        5320        0      0      1        0
 Bulk              3        8546        0      0      1        0
-----------------------------------------------
 Delay Statistics (Tier 0 - Express):
   Average:  0 us
   Peak:     8 us
   Base:     0 us
===============================================
```