#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

// 时间单位转换
#define US_TO_NS(x)    ((x) * 1000L)
#define MS_TO_NS(x)    ((x) * 1000000L)

// 设为 1 启用详细日志，0 关闭
// DEBUG 开关：改为变量，可通过 /proc 动态修改
static unsigned int PAC_DEBUG = 1;

// PAC_LOG 宏：运行时检查 PAC_DEBUG 变量
#define PAC_LOG(fmt, ...) do { \
if (PAC_DEBUG) \
printk(KERN_DEBUG "PAC: " fmt, ##__VA_ARGS__); \
} while(0)

// TCP 阶段
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1

// 流优先级
#define HIGH_PRIORITY 1
#define LOW_PRIORITY 0


static char PAC_NIC[32] = "eth0";

// ============ 基础参数 ============
// MSS: 1460 bytes
static unsigned int MSS = 1460;

// 初始窗口：广域网建议 10 MSS
static unsigned int MIN_WIN = 32;

// ============ 定时器参数 ============
// 定时器间隔：5ms（广域网不需要微秒级精度）
static unsigned long DELAY_IN_US = 1000L;

// ============ RTT 参数 ============
// 基础 RTT：166ms = 166000us
static unsigned int MIN_RTT = 166000;

// 最大 RTT：允许 3 倍抖动，约 500ms
static unsigned int MAX_RTT = 500000;

// 最大排队延迟：设为 2 个 RTT（330ms）
// 超过此时间的包会被强制发送
static unsigned int MAX_DELAY = 330000;

// BDP = 100Mbps * 166ms = 12.5Mbps * 0.166s = 2.075 MB
// 设为 1.5 倍 BDP，允许一定的突发
static unsigned int BUFFER_SIZE = 3 * 1024 * 1024;  // 3MB

// 最小包长度
static unsigned int MIN_PKT_LEN = 74;

// ============ 平滑参数 ============
// 吞吐量平滑：0.8 * 旧值 + 0.2 * 新值
static unsigned int THROUGHPUT_SMOOTH = 800;

// RTT 平滑：0.9 * 旧值 + 0.1 * 新值
static unsigned int RTT_SMOOTH = 900;

// ============ 拥塞检测参数 ============
// 吞吐量下降阈值：下降到 60% 以下才认为是拥塞
static unsigned int ALPHA = 600;

// 连续下降次数阈值：需要连续 5 次才切换到拥塞避免
static unsigned short int REDUCTION_THRESH = 3;

// ============ 流分类参数 ============
// 短流阈值：10MB 以下为高优先级
static unsigned long PRIO_THRESH = 10UL * 1024 * 1024;

// 慢启动阈值：5MB
static unsigned long SS_THRESH = 8UL * 1024 * 1024;

#endif