#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    #define NF_NEW_HOOK_API 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    #define NF_NEW_HOOK_FUNC 1
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/interrupt.h>

#include "hash.h"
#include "queue.h"
#include "params.h"
#include "network_func.h"

// ============ 发送队列结构（用于 tasklet）============
#define SEND_QUEUE_SIZE 8192

struct SendItem {
    struct sk_buff *skb;
    okfn_t okfn;
};

static struct SendItem send_items[SEND_QUEUE_SIZE];
static unsigned int send_head = 0;
static unsigned int send_tail = 0;
static unsigned int send_size = 0;
static DEFINE_SPINLOCK(sendLock);

static struct tasklet_struct send_tasklet;

// 发送队列：添加包
static int SendQueue_Add(struct sk_buff *skb, okfn_t okfn)
{
    unsigned long flags;
    int result = 0;

    spin_lock_irqsave(&sendLock, flags);
    if (send_size < SEND_QUEUE_SIZE) {
        send_items[send_tail].skb = skb;
        send_items[send_tail]. okfn = okfn;
        send_tail = (send_tail + 1) % SEND_QUEUE_SIZE;
        send_size++;
        result = 1;
    }
    spin_unlock_irqrestore(&sendLock, flags);

    return result;
}

// 发送队列：获取包
static int SendQueue_Get(struct sk_buff **skb, okfn_t *okfn)
{
    unsigned long flags;
    int result = 0;

    spin_lock_irqsave(&sendLock, flags);
    if (send_size > 0) {
        *skb = send_items[send_head].skb;
        *okfn = send_items[send_head].okfn;
        send_items[send_head]. skb = NULL;
        send_items[send_head]. okfn = NULL;
        send_head = (send_head + 1) % SEND_QUEUE_SIZE;
        send_size--;
        result = 1;
    }
    spin_unlock_irqrestore(&sendLock, flags);

    return result;
}

// tasklet 处理函数 - 在软中断上下文执行，可以安全调用网络发送
static void send_tasklet_handler(unsigned long data)
{
    struct sk_buff *skb;
    okfn_t okfn;
    int count = 0;
    const int max_batch = 128;  // 每次最多处理的包数

    while (count < max_batch && SendQueue_Get(&skb, &okfn)) {
        if (skb && okfn) {
#if defined(OKFN_NEW_API)
            okfn(&init_net, NULL, skb);
#else
            okfn(skb);
#endif
        }
        count++;
    }

    // 如果还有剩余包，重新调度 tasklet
    if (send_size > 0) {
        tasklet_schedule(&send_tasklet);
    }
}

// 安全发送函数 - 从 hrtimer 回调中调用
static void safe_send_packet(struct sk_buff *skb, okfn_t okfn)
{
    if (SendQueue_Add(skb, okfn)) {
        tasklet_schedule(&send_tasklet);
    } else {
        // 发送队列满，丢弃包
        kfree_skb(skb);
        printk(KERN_WARNING "PAC: Send queue full, dropping packet\n");
    }
}

// ============ 以下为原有代码 ============

#include "pac_control.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.5");
MODULE_DESCRIPTION("Kernel module of Proactive ACK Control (PAC) - softirq fix");

static char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate PAC");
module_param(param_dev, charp, 0);

static struct FlowTable ft;
static spinlock_t tableLock;
static spinlock_t globalLock;

static unsigned int last_update;
static unsigned long total_rtt;
static unsigned long samples;
static unsigned long avg_rtt;
static unsigned int avg_throughput;

static unsigned long traffic = 0;
static unsigned long ecn_traffic = 0;
static unsigned long tokens = 0;
static unsigned long bucket = 0;

int init_module(void);
void cleanup_module(void);

static struct PacketQueue *q_high = NULL;
static struct PacketQueue *q_low = NULL;
static struct nf_hook_ops nfho_outgoing;
static struct nf_hook_ops nfho_incoming;
static struct hrtimer hr_timer;

// POSTROUTING for outgoing packets
#if defined(NF_NEW_HOOK_API)
static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    const struct net_device *out = state->out;
#elif defined(NF_NEW_HOOK_FUNC)
static unsigned int hook_func_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
                                   const struct net_device *in, const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
#else
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in, const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
#endif
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct Flow f;
    struct Info* info_pointer = NULL;
    unsigned int trigger = 0;
    unsigned long flags;
    unsigned int ack;
    unsigned int payload_len;
    unsigned short int prio;
    int result = 0;
    int is_client = 0;

#if defined(NF_NEW_HOOK_API)
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#endif

    if (! out)
        return NF_ACCEPT;

    if (strcmp(out->name, param_dev) != 0)
        return NF_ACCEPT;

    ip_header = (struct iphdr *)skb_network_header(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
        payload_len = (unsigned int)ntohs(ip_header->tot_len) - (ip_header->ihl<<2) - (tcp_header->doff<<2);

        f.local_ip = ip_header->saddr;
        f.remote_ip = ip_header->daddr;
        f.local_port = ntohs(tcp_header->source);
        f.remote_port = ntohs(tcp_header->dest);

        //=================================================================
        // 处理 SYN 包
        //=================================================================
        if (tcp_header->syn)
        {
            if (! tcp_header->ack)
            {
                //=================================================================
                // 纯 SYN：客户端主动发起连接，标记为客户端模式
                //=================================================================
                f. i.srtt = MIN_RTT;
                f.i. phase = SLOW_START;
                f.i.direction = FLOW_DIR_CLIENT;
                f. i.bytes_sent_latest = 0;
                f.i. bytes_sent_total = 0;
                f.i. last_ack = 0;
                f.i.last_seq = ntohl(tcp_header->seq);
                f. i.last_throughput = 0;
                f.i.throughput_reduction_num = 0;
                f.i. last_update = get_tsval();

                spin_lock_irqsave(&tableLock, flags);
                Insert_Table(&ft, &f);
                spin_unlock_irqrestore(&tableLock, flags);

                PAC_LOG(KERN_INFO "Client SYN: %pI4:%d -> %pI4:%d (bypass)\n",
                    &f.local_ip, f. local_port, &f.remote_ip, f.remote_port);

                // 客户端连接：不修改时间戳，直接放行
                return NF_ACCEPT;
            }
            else
            {
                //=================================================================
                // SYN-ACK：服务器响应，标记为服务器模式
                //=================================================================
                f.i.srtt = MIN_RTT;
                f.i.phase = SLOW_START;
                f.i.direction = FLOW_DIR_SERVER;
                f.i.bytes_sent_latest = 0;
                f.i.bytes_sent_total = 0;
                f.i.last_ack = ntohl(tcp_header->ack_seq);
                f.i.last_seq = 0;
                f.i.last_throughput = 0;
                f. i.throughput_reduction_num = 0;
                f.i.last_update = get_tsval();

                spin_lock_irqsave(&tableLock, flags);
                Insert_Table(&ft, &f);
                spin_unlock_irqrestore(&tableLock, flags);

                PAC_LOG(KERN_INFO "Server SYN-ACK: %pI4:%d -> %pI4:%d (controlled)\n",
                    &f.local_ip, f. local_port, &f.remote_ip, f.remote_port);

                trigger = MIN_PKT_LEN;
                prio = HIGH_PRIORITY;
                // 继续走 PAC 控制逻辑
            }
        }
        else if (tcp_header->ack)
        {
            //=================================================================
            // ACK 包：先查流表判断方向
            //=================================================================
            spin_lock_irqsave(&tableLock, flags);
            info_pointer = Search_Table(&ft, &f);
            if (info_pointer != NULL) {
                is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
            }
            spin_unlock_irqrestore(&tableLock, flags);

            //=================================================================
            // 客户端连接或未知连接：直接放行，不做任何修改
            //=================================================================
            if (info_pointer == NULL || is_client)
            {
                return NF_ACCEPT;
            }

            //=================================================================
            // 服务器连接：执行原有 PAC 逻辑
            //=================================================================
            ack = ntohl(tcp_header->ack_seq);

            if (info_pointer->bytes_sent_total < PRIO_THRESH)
                prio = HIGH_PRIORITY;
            else
                prio = LOW_PRIORITY;

            if (info_pointer->last_ack == 0)
            {
                info_pointer->last_ack = ack;
                if (payload_len > 0)
                    trigger = MIN_WIN * (MSS + 54);
                else
                    trigger = MIN_PKT_LEN;
            }
            else
            {
                if (tcp_header->ece)
                    info_pointer->phase = CONGESTION_AVOIDANCE;

                if (is_larger(ack, info_pointer->last_ack) == 1)
                {
                    trigger = cumulative_ack(ack, info_pointer->last_ack);
                    info_pointer->last_ack = ack;
                }

                if (trigger > 0)
                {
                    if (info_pointer->phase == SLOW_START)
                        trigger = (trigger + MSS) * (MSS + 54) / MSS;
                    else
                        trigger = trigger * (MSS + 54) / MSS;
                }
                else if (payload_len > 0)
                {
                    trigger = MIN_WIN * (MSS + 54);
                }
                else
                {
                    trigger = MIN_PKT_LEN;
                }
            }
        }
        else
        {
            //=================================================================
            // 其他包：检查是否是客户端连接
            //=================================================================
            spin_lock_irqsave(&tableLock, flags);
            info_pointer = Search_Table(&ft, &f);
            if (info_pointer != NULL) {
                is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
            }
            spin_unlock_irqrestore(&tableLock, flags);

            if (info_pointer == NULL || is_client)
            {
                return NF_ACCEPT;
            }

            prio = HIGH_PRIORITY;
            trigger = MIN_PKT_LEN;
        }

        //=================================================================
        // 以下是服务器模式的 PAC 控制逻辑
        //=================================================================

        if (trigger >= bucket)
        {
            PAC_LOG(KERN_INFO "Alert: trigger %u >= bucket %lu, bypass\n", trigger, bucket);
            tcp_modify_outgoing(skb, 0, get_tsval());
            return NF_ACCEPT;
        }

        // 只有服务器模式才修改时间戳
        tcp_modify_outgoing(skb, 0, get_tsval());

        if (bucket - tokens >= trigger &&
           ((prio == HIGH_PRIORITY && q_high->size == 0) ||
            (prio == LOW_PRIORITY && q_high->size == 0 && q_low->size == 0)))
        {
            spin_lock_irqsave(&globalLock, flags);
            tokens += trigger;
            spin_unlock_irqrestore(&globalLock, flags);
            return NF_ACCEPT;
        }

        if (prio == HIGH_PRIORITY)
            result = Enqueue_PacketQueue(q_high, skb, okfn, trigger, get_tsval());
        else
            result = Enqueue_PacketQueue(q_low, skb, okfn, trigger, get_tsval());

        if (result == 1)
        {
            return NF_STOLEN;
        }
        else
        {
            PAC_LOG(KERN_INFO "No enough space in queue\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

// PREROUTING for incoming packets
#if defined(NF_NEW_HOOK_API)
static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    const struct net_device *in = state->in;
#elif defined(NF_NEW_HOOK_FUNC)
static unsigned int hook_func_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
                                  const struct net_device *in, const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
#else
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in, const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
#endif
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct Flow f;
    unsigned long flags;
    struct Info* info_pointer = NULL;
    unsigned int rtt = 0;
    unsigned int payload_len;
    unsigned int throughput;
    unsigned int time;
    int is_client = 0;

    if (!in)
        return NF_ACCEPT;

    if (strcmp(in->name, param_dev) != 0)
        return NF_ACCEPT;

    ip_header = (struct iphdr *)skb_network_header(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
        payload_len = (unsigned int)ntohs(ip_header->tot_len) - (ip_header->ihl<<2) - (tcp_header->doff<<2);

        // 入站时交换源和目的来查找流表
        f.local_ip = ip_header->daddr;
        f.remote_ip = ip_header->saddr;
        f.local_port = ntohs(tcp_header->dest);
        f. remote_port = ntohs(tcp_header->source);

        //=================================================================
        // 首先查找流表，确定连接方向
        //=================================================================
        spin_lock_irqsave(&tableLock, flags);
        info_pointer = Search_Table(&ft, &f);
        if (info_pointer != NULL) {
            is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
        }
        spin_unlock_irqrestore(&tableLock, flags);

        //=================================================================
        // 客户端连接：完全不处理，直接放行
        //=================================================================
        if (is_client)
        {
            PAC_LOG(KERN_INFO "Client IN: %pI4:%d <- %pI4:%d (pass-through)\n",
                &f.local_ip, f. local_port, &f.remote_ip, f.remote_port);
            return NF_ACCEPT;
        }

        //=================================================================
        // 未知连接（可能是入站 SYN 到服务器）：也直接放行
        //=================================================================
        if (info_pointer == NULL)
        {
            return NF_ACCEPT;
        }

        //=================================================================
        // 服务器连接：处理 FIN/RST
        //=================================================================
        if (tcp_header->fin || tcp_header->rst)
        {
            spin_lock_irqsave(&tableLock, flags);
            Delete_Table(&ft, &f);
            spin_unlock_irqrestore(&tableLock, flags);
            return NF_ACCEPT;
        }

        //=================================================================
        // 服务器连接：执行原有逻辑
        //=================================================================
        rtt = tcp_modify_incoming(skb);

        info_pointer->bytes_sent_latest += skb->len - (ip_header->ihl<<2) - tcp_header->doff*4;
        info_pointer->srtt = RTT_SMOOTH * info_pointer->srtt / 1000 + (1000 - RTT_SMOOTH) * rtt / 1000;

        if (info_pointer->bytes_sent_total <= 4294900000)
        {
            info_pointer->bytes_sent_total += skb->len - (ip_header->ihl<<2) - tcp_header->doff*4;
            if (info_pointer->bytes_sent_total > SS_THRESH && info_pointer->phase == SLOW_START)
            {
                info_pointer->phase = CONGESTION_AVOIDANCE;
            }
        }

        if (payload_len > 0 && is_larger(tcp_header->seq + payload_len - 1, info_pointer->last_seq) == 1)
        {
            info_pointer->last_seq = tcp_header->seq + payload_len - 1;
        }

        time = get_tsval() - info_pointer->last_update;
        if (time > info_pointer->srtt)
        {
            info_pointer->last_update = get_tsval();
            throughput = info_pointer->bytes_sent_latest * 8 / time;
            info_pointer->bytes_sent_latest = 0;

            if (throughput <= info_pointer->last_throughput * ALPHA / 1000)
            {
                info_pointer->throughput_reduction_num += 1;
                if (info_pointer->throughput_reduction_num >= REDUCTION_THRESH && info_pointer->phase == SLOW_START)
                {
                    info_pointer->phase = CONGESTION_AVOIDANCE;
                    PAC_LOG(KERN_INFO "Throughput reduction -> congestion avoidance\n");
                }
            }
            else
            {
                info_pointer->throughput_reduction_num = 0;
            }
            info_pointer->last_throughput = throughput;
        }

        //=================================================================
        // 更新全局统计和令牌（仅服务器连接）
        //=================================================================
        spin_lock_irqsave(&globalLock, flags);
        traffic += skb->len;

        if (ip_header->tos == 0x03)
            ecn_traffic += skb->len;

        if (tokens >= skb->len)
            tokens -= skb->len;
        else
            tokens = 0;

        total_rtt += rtt;
        samples++;
        spin_unlock_irqrestore(&globalLock, flags);
    }
    return NF_ACCEPT;
}

static enum hrtimer_restart my_hrtimer_callback(struct hrtimer *timer)
{
    ktime_t interval, now;
    unsigned long flags;
    unsigned int len;
    unsigned int time = 0;
    unsigned int current_time = 0;
    unsigned long int throughput = 0;
    struct sk_buff *skb;
    okfn_t okfn;

    spin_lock_irqsave(&globalLock, flags);
    current_time = get_tsval();
    time = current_time - last_update;

    if (time > avg_rtt)
    {
        last_update = current_time;

        if (time > 0)
            throughput = traffic * 8 / time;

        if (throughput < ALPHA && 2 * traffic > ecn_traffic && avg_throughput > 0)
        {
            unsigned long new_tokens = bucket * throughput / avg_throughput;
            if ((2 * traffic - ecn_traffic) > 0)
                new_tokens = new_tokens * 2 * traffic / (2 * traffic - ecn_traffic);
            tokens = min(tokens, new_tokens);

            if (tokens > 0)
                PAC_LOG(KERN_INFO "Reset in-flight traffic to %lu\n", tokens);
        }

        if (samples > 0)
            avg_rtt = min(max(MIN_RTT, total_rtt / samples), MAX_RTT);
        else
            avg_rtt = MIN_RTT;

        traffic = 0;
        ecn_traffic = 0;
        total_rtt = 0;
        samples = 0;
    }
    spin_unlock_irqrestore(&globalLock, flags);

    // 处理高优先级队列
    while (q_high->size > 0)
    {
        len = q_high->packets[q_high->head]. trigger;
        if (bucket - tokens >= len)
        {
            if (Dequeue_PacketQueue_GetPacket(q_high, &skb, &okfn))
            {
                spin_lock_irqsave(&globalLock, flags);
                tokens += len;
                spin_unlock_irqrestore(&globalLock, flags);
                safe_send_packet(skb, okfn);
            }
        }
        else if (get_tsval() - q_high->packets[q_high->head].enqueue_time >= MAX_DELAY)
        {
            if (Dequeue_PacketQueue_GetPacket(q_high, &skb, &okfn))
            {
                safe_send_packet(skb, okfn);
            }
        }
        else
        {
            break;
        }
    }

    // 处理低优先级队列
    if (q_high->size == 0)
    {
        while (q_low->size > 0)
        {
            len = q_low->packets[q_low->head]. trigger;
            if (bucket - tokens >= len)
            {
                if (Dequeue_PacketQueue_GetPacket(q_low, &skb, &okfn))
                {
                    spin_lock_irqsave(&globalLock, flags);
                    tokens += len;
                    spin_unlock_irqrestore(&globalLock, flags);
                    safe_send_packet(skb, okfn);
                }
            }
            else if (get_tsval() - q_low->packets[q_low->head]. enqueue_time >= MAX_DELAY)
            {
                if (Dequeue_PacketQueue_GetPacket(q_low, &skb, &okfn))
                {
                    safe_send_packet(skb, okfn);
                }
            }
            else
            {
                break;
            }
        }
    }

    interval = ktime_set(0, US_TO_NS(DELAY_IN_US));
    now = ktime_get();
    hrtimer_forward(timer, now, interval);
    return HRTIMER_RESTART;
}

int init_module(void)
{
    int i = 0;
    ktime_t ktime;

    if (param_dev == NULL)
    {
        PAC_LOG(KERN_INFO "PAC: not specify network interface (eth0 by default).\n");
        param_dev = "eth0\0";
    }

    for (i = 0; i < 32 && param_dev[i] != '\0'; i++)
    {
        if (param_dev[i] == '\n')
        {
            param_dev[i] = '\0';
            break;
        }
    }

    bucket = BUFFER_SIZE;
    tokens = 0;
    last_update = get_tsval();
    total_rtt = 0;
    samples = 0;
    avg_rtt = MIN_RTT;
    avg_throughput = 1000;

    // 初始化 tasklet
    tasklet_init(&send_tasklet, send_tasklet_handler, 0);

    q_high = vmalloc(sizeof(struct PacketQueue));
    Init_PacketQueue(q_high);
    q_low = vmalloc(sizeof(struct PacketQueue));
    Init_PacketQueue(q_low);

    Init_Table(&ft);
    spin_lock_init(&tableLock);
    spin_lock_init(&globalLock);

    ktime = ktime_set(0, US_TO_NS(DELAY_IN_US));
    hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hr_timer.function = &my_hrtimer_callback;
    hrtimer_start(&hr_timer, ktime, HRTIMER_MODE_REL);

    nfho_outgoing. hook = hook_func_out;
    nfho_outgoing.hooknum = NF_INET_POST_ROUTING;
    nfho_outgoing. pf = PF_INET;
    nfho_outgoing.priority = NF_IP_PRI_FIRST;

    nfho_incoming.hook = hook_func_in;
    nfho_incoming.hooknum = NF_INET_PRE_ROUTING;
    nfho_incoming.pf = PF_INET;
    nfho_incoming.priority = NF_IP_PRI_FIRST;

#if defined(NF_NEW_HOOK_API)
    nf_register_net_hook(&init_net, &nfho_outgoing);
    nf_register_net_hook(&init_net, &nfho_incoming);
#else
    nf_register_hook(&nfho_outgoing);
    nf_register_hook(&nfho_incoming);
#endif

    if (pac_setup_proc() != 0) {
        printk(KERN_ERR "PAC: Failed to setup proc interface\n");
    }

    printk(KERN_INFO "PAC: Module loaded (v1.5 - softirq fix)\n");
    return 0;
}

void cleanup_module(void)
{
    int ret;
    struct sk_buff *skb;
    okfn_t okfn;

    pac_remove_proc();

    ret = hrtimer_cancel(&hr_timer);
    if (ret)
        PAC_LOG("Timer was still in use.. .\n");

    // 停止 tasklet
    tasklet_kill(&send_tasklet);

    // 清空发送队列中的残留包
    while (SendQueue_Get(&skb, &okfn)) {
        if (skb)
            kfree_skb(skb);
    }

#if defined(NF_NEW_HOOK_API)
    nf_unregister_net_hook(&init_net, &nfho_outgoing);
    nf_unregister_net_hook(&init_net, &nfho_incoming);
#else
    nf_unregister_hook(&nfho_outgoing);
    nf_unregister_hook(&nfho_incoming);
#endif

    Free_PacketQueue(q_high);
    Free_PacketQueue(q_low);
    Empty_Table(&ft);

    printk(KERN_INFO "PAC: Module unloaded\n");
}