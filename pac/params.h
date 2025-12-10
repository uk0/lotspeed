#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

// 时间单位转换
#define US_TO_NS(x)    ((x) * 1000L)
#define MS_TO_NS(x)    ((x) * 1000000L)

// DEBUG 开关：改为变量，可通过 /proc 动态修改
static unsigned int PAC_DEBUG = 1;

// PAC_LOG 宏：运行时检查 PAC_DEBUG 变量
#define PAC_LOG(fmt, ...) do { \
    if (PAC_DEBUG) \
        printk(KERN_DEBUG "PAC-INTER: " fmt, ##__VA_ARGS__); \
} while(0)

// TCP 阶段
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1

// 流优先级
#define HIGH_PRIORITY 1
#define LOW_PRIORITY 0

static char PAC_NIC[32] = "eth0";

// ============ 洲际网络优化参数 ============
// MSS: 1460 bytes (标准以太网)
static unsigned int MSS = 1460;

// 初始窗口：洲际网络建议更大的初始窗口 (64 MSS)
// 这有助于快速填充高 BDP 管道
static unsigned int MIN_WIN = 64;

// ============ 定时器参数 ============
// 定时器间隔：10ms（洲际网络不需要过高精度，降低CPU开销）
static unsigned long DELAY_IN_US = 10000L;

// ============ RTT 参数（洲际通讯典型值）============
// 基础 RTT：250ms = 250000us（典型洲际延迟）
// 亚洲-美国:  150-200ms
// 亚洲-欧洲: 200-300ms
// 美国-欧洲: 80-120ms
// 跨太平洋: 150-250ms
static unsigned int MIN_RTT = 250000;

// 最大 RTT：1500ms（允许 6 倍抖动，应对网络拥塞）
static unsigned int MAX_RTT = 1500000;

// 最大排队延迟：设为 3 个基础 RTT（750ms）
// 洲际链路抖动大，需要更长的容忍时间
static unsigned int MAX_DELAY = 750000;

// ============ 缓冲区大小（基于 BDP 计算）============
// 假设带宽 100Mbps，RTT 250ms
// BDP = 100Mbps * 250ms = 100 * 0.25 / 8 = 3.125 MB
// 设为 3 倍 BDP，提供足够缓冲应对突发
static unsigned int BUFFER_SIZE = 10 * 1024 * 1024;  // 10MB

// 最小包长度（包含以太网头部）
static unsigned int MIN_PKT_LEN = 74;

// ============ 平滑参数（更保守的平滑）============
// 吞吐量平滑：0.85 * 旧值 + 0.15 * 新值（更稳定）
static unsigned int THROUGHPUT_SMOOTH = 850;

// RTT 平滑：0.875 * 旧值 + 0.125 * 新值（标准 TCP 算法）
static unsigned int RTT_SMOOTH = 875;

// ============ 拥塞检测参数（更宽松）============
// 吞吐量下降阈值：下降到 50% 以下才认为是拥塞
// 洲际链路波动大，需要更宽松的阈值
static unsigned int ALPHA = 500;

// 连续下降次数阈值：需要连续 4 次才切换到拥塞避免
// 避免因偶然抖动误判
static unsigned short int REDUCTION_THRESH = 4;

// ============ 流分类参数 ============
// 短流阈值：20MB 以下为高优先级（洲际传输文件通常更大）
static unsigned long PRIO_THRESH = 20UL * 1024 * 1024;

// 慢启动阈值：15MB（更长的慢启动阶段）
static unsigned long SS_THRESH = 15UL * 1024 * 1024;

#endif