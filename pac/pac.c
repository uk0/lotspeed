/*
 * PAC-Intercontinental:  Proactive ACK Control for Intercontinental Communication
 * 洲际通讯优化版本 - BH Context Fixed
 * Version:  2.1-FIXED
 *
 * 主要优化：
 * 1.适配高延迟（150-300ms）
 * 2.处理高抖动（最大 6 倍 RTT）
 * 3.更大的缓冲区（10MB）
 * 4.智能拥塞检测
 * 5.自适应令牌桶
 * 6.修复BH上下文问题
 */

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
#include <linux/random.h>
#include <linux/workqueue.h>

#include "hash.h"
#include "queue.h"
#include "params.h"
#include "network_func.h"
#include "pac_control.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PAC-Intercontinental Team");
MODULE_VERSION("2.1-FIXED");
MODULE_DESCRIPTION("Proactive ACK Control optimized for intercontinental communication - BH Fixed");

static char *param_dev=NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate PAC");
module_param(param_dev, charp, 0);

// ============ 洲际优化：增加统计变量 ============
static struct FlowTable ft;
static spinlock_t tableLock;
static spinlock_t globalLock;

static unsigned int last_update;
static unsigned long total_rtt;
static unsigned long samples;
static unsigned long avg_rtt;
static unsigned int avg_throughput;

// 新增：洲际链路统计
static unsigned long min_observed_rtt = UINT_MAX;  // 观测到的最小 RTT
static unsigned long max_observed_rtt = 0;         // 观测到的最大 RTT
static unsigned int rtt_variance = 0;              // RTT 方差
static unsigned int packet_loss_estimate = 0;      // 丢包率估算

// 自适应令牌桶
static unsigned long traffic=0;
static unsigned long ecn_traffic=0;
static unsigned long tokens=0;
static unsigned long bucket=0;
static unsigned long adaptive_bucket_size=0;      // 自适应桶大小

int init_module(void);
void cleanup_module(void);

static struct PacketQueue *q_high=NULL;
static struct PacketQueue *q_low=NULL;
static struct PacketQueue *q_urgent=NULL;  // 新增：紧急队列（用于控制包）
static struct nf_hook_ops nfho_outgoing;
static struct nf_hook_ops nfho_incoming;
static struct hrtimer hr_timer;

// ============ 修复：使用工作队列处理包发送 ============
struct pac_work_data {
    struct work_struct work;
    struct sk_buff *skb;
    okfn_t okfn;
};

static struct workqueue_struct *pac_workqueue = NULL;

// 工作队列处理函数
static void pac_send_work(struct work_struct *work)
{
    struct pac_work_data *data = container_of(work, struct pac_work_data, work);

    if (data->skb && data->okfn) {
#if defined(OKFN_NEW_API)
        data->okfn(&init_net, NULL, data->skb);
#else
        data->okfn(data->skb);
#endif
    }

    kfree(data);
}

// 修复后的出队函数
static int Dequeue_PacketQueue_Safe(struct PacketQueue* q)
{
    struct Packet *pkt;
    struct pac_work_data *work_data;

    if (! q || ! q->packets || q->size == 0)
        return 0;

    pkt = &q->packets[q->head];

    if (pkt->okfn && pkt->skb) {
        // 在中断上下文中，使用工作队列延迟处理
        if (in_interrupt() || in_softirq()) {
            work_data = kmalloc(sizeof(*work_data), GFP_ATOMIC);
            if (work_data) {
                INIT_WORK(&work_data->work, pac_send_work);
                work_data->skb = pkt->skb;
                work_data->okfn = pkt->okfn;
                queue_work(pac_workqueue, &work_data->work);
            } else {
                // 内存分配失败，丢弃包
                kfree_skb(pkt->skb);
            }
        } else {
            // 非中断上下文，可以直接发送
#if defined(OKFN_NEW_API)
            pkt->okfn(&init_net, NULL, pkt->skb);
#else
            pkt->okfn(pkt->skb);
#endif
        }
    }

    // 清理
    pkt->skb = NULL;
    pkt->okfn = NULL;

    q->head = (q->head + 1) % q->capacity;
    q->size--;

    return 1;
}

// ============ 洲际优化：智能队列管理 ============
static unsigned int calculate_adaptive_trigger(struct Info* info, unsigned int base_trigger)
{
    unsigned int adaptive_trigger = base_trigger;
    unsigned int rtt_ratio;

    // 根据当前 RTT 与最小 RTT 的比值调整触发量
    if(info->srtt > 0 && min_observed_rtt < UINT_MAX)
    {
        rtt_ratio = info->srtt * 100 / min_observed_rtt;

        if(rtt_ratio > 200)  // RTT 增加超过 2 倍
        {
            // 减少触发量，更保守
            adaptive_trigger = adaptive_trigger * 70 / 100;
            PAC_LOG("High RTT detected (%u), reducing trigger to %u\n",
                    info->srtt, adaptive_trigger);
        }
        else if(rtt_ratio < 120)  // RTT 接近最小值
        {
            // 增加触发量，更激进
            adaptive_trigger = adaptive_trigger * 130 / 100;
        }
    }

    // 根据丢包率调整
    if(packet_loss_estimate > 100)  // > 1% 丢包
    {
        adaptive_trigger = adaptive_trigger * 80 / 100;
        PAC_LOG("Packet loss detected, reducing trigger to %u\n", adaptive_trigger);
    }

    return adaptive_trigger;
}

// ============ 洲际优化：自适应缓冲区大小 ============
static void update_adaptive_buffer(void)
{
    unsigned long bdp;

    if(avg_rtt > 0 && avg_throughput > 0)
    {
        // BDP = throughput * RTT
        bdp = (unsigned long)avg_throughput * avg_rtt / 8 / 1000;  // 转换为字节

        // 自适应缓冲区：2-4 倍 BDP
        if(rtt_variance > avg_rtt / 4)  // 高抖动
        {
            adaptive_bucket_size = bdp * 4;
            PAC_LOG("High jitter, setting buffer to 4x BDP: %lu\n", adaptive_bucket_size);
        }
        else
        {
            adaptive_bucket_size = bdp * 2;
        }

        // 限制范围
        adaptive_bucket_size = max(adaptive_bucket_size, (unsigned long)(5 * 1024 * 1024));   // 最小 5MB
        adaptive_bucket_size = min(adaptive_bucket_size, (unsigned long)(20 * 1024 * 1024));  // 最大 20MB

        bucket = adaptive_bucket_size;
    }
}

//POSTROUTING for outgoing packets - 洲际优化版
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
	struct Info* info_pointer=NULL;
	unsigned int trigger=0;
	unsigned long flags;
	unsigned int ack;
	unsigned int payload_len;
	unsigned short int prio;
	int result=0;
	int is_client = 0;
	struct PacketQueue *target_queue = NULL;

#if defined(NF_NEW_HOOK_API)
	int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#endif

	if(! out)
		return NF_ACCEPT;

	if(strcmp(out->name, param_dev) != 0)
		return NF_ACCEPT;

	ip_header = (struct iphdr *)skb_network_header(skb);
	if(! ip_header)
		return NF_ACCEPT;

	if(ip_header->protocol == IPPROTO_TCP)
	{
		tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
		payload_len = (unsigned int)ntohs(ip_header->tot_len) - (ip_header->ihl<<2) - (tcp_header->doff<<2);

		f.local_ip = ip_header->saddr;
		f.remote_ip = ip_header->daddr;
		f.local_port = ntohs(tcp_header->source);
		f.remote_port = ntohs(tcp_header->dest);

		//=================================================================
		// 处理 SYN 包 - 洲际优化
		//=================================================================
		if(tcp_header->syn)
		{
			if(! tcp_header->ack)
			{
				// 客户端 SYN
				f.i.srtt = MIN_RTT;
				f.i.phase = SLOW_START;
				f.i.direction = FLOW_DIR_CLIENT;
				f.i.bytes_sent_latest = 0;
				f.i.bytes_sent_total = 0;
				f.i.last_ack = 0;
				f.i.last_seq = ntohl(tcp_header->seq);
				f.i.last_throughput = 0;
				f.i.throughput_reduction_num = 0;
				f.i.last_update = get_tsval();

				spin_lock_irqsave(&tableLock, flags);
				Insert_Table(&ft, &f);
				spin_unlock_irqrestore(&tableLock, flags);

				PAC_LOG("INTER:  Client SYN to %pI4:%d (bypass)\n",
					&f.remote_ip, f.remote_port);

				return NF_ACCEPT;
			}
			else
			{
				// 服务器 SYN-ACK
				f.i.srtt = MIN_RTT;
				f.i.phase = SLOW_START;
				f.i.direction = FLOW_DIR_SERVER;
				f.i.bytes_sent_latest = 0;
				f.i.bytes_sent_total = 0;
				f.i.last_ack = ntohl(tcp_header->ack_seq);
				f.i.last_seq = 0;
				f.i.last_throughput = 0;
				f.i.throughput_reduction_num = 0;
				f.i.last_update = get_tsval();

				spin_lock_irqsave(&tableLock, flags);
				Insert_Table(&ft, &f);
				spin_unlock_irqrestore(&tableLock, flags);

				PAC_LOG("INTER: Server SYN-ACK from %pI4:%d\n",
					&f.local_ip, f.local_port);

				// 洲际链路：SYN-ACK 使用更大的初始触发量
				trigger = MIN_WIN * MSS;
				prio = HIGH_PRIORITY;
			}
		}
		else if(tcp_header->ack)
		{
			spin_lock_irqsave(&tableLock, flags);
			info_pointer = Search_Table(&ft, &f);
			if(info_pointer != NULL) {
				is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
			}
			spin_unlock_irqrestore(&tableLock, flags);

			if(info_pointer == NULL || is_client)
			{
				return NF_ACCEPT;
			}

			ack = ntohl(tcp_header->ack_seq);

			// 洲际优化：动态优先级
			if(info_pointer->bytes_sent_total < PRIO_THRESH)
				prio = HIGH_PRIORITY;
			else if(info_pointer->srtt > MAX_RTT / 2)  // RTT 过高时提高优先级
				prio = HIGH_PRIORITY;
			else
				prio = LOW_PRIORITY;

			if(info_pointer->last_ack == 0)
			{
				info_pointer->last_ack = ack;
				// 洲际链路：更大的初始窗口
				if(payload_len > 0)
					trigger = MIN_WIN * 2 * (MSS + 54);
				else
					trigger = MIN_WIN * (MSS + 54);
			}
			else
			{
				if(tcp_header->ece)
					info_pointer->phase = CONGESTION_AVOIDANCE;

				if(is_larger(ack, info_pointer->last_ack) == 1)
				{
					trigger = cumulative_ack(ack, info_pointer->last_ack);
					info_pointer->last_ack = ack;
				}

				// 洲际优化：自适应触发量
				if(trigger > 0)
				{
					if(info_pointer->phase == SLOW_START)
						trigger = (trigger + MSS * 2) * (MSS + 54) / MSS;
					else
						trigger = trigger * (MSS + 54) / MSS;

					// 应用自适应调整
					trigger = calculate_adaptive_trigger(info_pointer, trigger);
				}
				else if(payload_len > 0)
				{
					trigger = MIN_WIN * (MSS + 54);
				}
				else
				{
					trigger = MIN_PKT_LEN * 2;  // 洲际链路：更大的最小触发
				}
			}
		}
		else if(tcp_header->fin || tcp_header->rst)
		{
			// 控制包：使用紧急队列
			prio = HIGH_PRIORITY;
			trigger = MIN_PKT_LEN;
			target_queue = q_urgent;
		}
		else
		{
			spin_lock_irqsave(&tableLock, flags);
			info_pointer = Search_Table(&ft, &f);
			if(info_pointer != NULL) {
				is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
			}
			spin_unlock_irqrestore(&tableLock, flags);

			if(info_pointer == NULL || is_client)
			{
				return NF_ACCEPT;
			}

			prio = HIGH_PRIORITY;
			trigger = MIN_PKT_LEN * 2;
		}

		// 洲际优化：更智能的令牌桶管理
		if(trigger >= bucket)
		{
			PAC_LOG("INTER Alert: trigger %u >= bucket %lu, expanding bucket\n",
			        trigger, bucket);
			// 洲际链路：动态扩展桶大小
			bucket = min(bucket * 3 / 2, (unsigned long)(20 * 1024 * 1024));
			tcp_modify_outgoing(skb, 0, get_tsval());
			return NF_ACCEPT;
		}

		tcp_modify_outgoing(skb, 0, get_tsval());

		// 快速路径：令牌充足且队列空
		if(bucket - tokens >= trigger &&
		   ((target_queue && target_queue->size == 0) ||
		    (prio == HIGH_PRIORITY && q_high->size == 0) ||
		    (prio == LOW_PRIORITY && q_high->size == 0 && q_low->size == 0)))
		{
			spin_lock_irqsave(&globalLock, flags);
			tokens += trigger;
			spin_unlock_irqrestore(&globalLock, flags);
			return NF_ACCEPT;
		}

		// 选择目标队列
		if(target_queue)
			result = Enqueue_PacketQueue(target_queue, skb, okfn, trigger, get_tsval());
		else if(prio == HIGH_PRIORITY)
			result = Enqueue_PacketQueue(q_high, skb, okfn, trigger, get_tsval());
		else
			result = Enqueue_PacketQueue(q_low, skb, okfn, trigger, get_tsval());

		if(result == 1)
		{
			return NF_STOLEN;
		}
		else
		{
			PAC_LOG("INTER:  Queue full, dropping packet\n");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

//PREROUTING for incoming packets - 洲际优化版
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
	unsigned long old_srtt;

	if(!in)
		return NF_ACCEPT;

	if(strcmp(in->name, param_dev) != 0)
		return NF_ACCEPT;

	ip_header = (struct iphdr *)skb_network_header(skb);
	if(!ip_header)
		return NF_ACCEPT;

	if(ip_header->protocol == IPPROTO_TCP)
	{
		tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
		payload_len = (unsigned int)ntohs(ip_header->tot_len) - (ip_header->ihl<<2) - (tcp_header->doff<<2);

		f.local_ip = ip_header->daddr;
		f.remote_ip = ip_header->saddr;
		f.local_port = ntohs(tcp_header->dest);
		f.remote_port = ntohs(tcp_header->source);

		spin_lock_irqsave(&tableLock, flags);
		info_pointer = Search_Table(&ft, &f);
		if(info_pointer != NULL) {
			is_client = (info_pointer->direction == FLOW_DIR_CLIENT);
		}
		spin_unlock_irqrestore(&tableLock, flags);

		if(is_client)
		{
			return NF_ACCEPT;
		}

		if(info_pointer == NULL)
		{
			return NF_ACCEPT;
		}

		if(tcp_header->fin || tcp_header->rst)
		{
			spin_lock_irqsave(&tableLock, flags);
			Delete_Table(&ft, &f);
			spin_unlock_irqrestore(&tableLock, flags);
			return NF_ACCEPT;
		}

		// 获取 RTT 测量值
		rtt = tcp_modify_incoming(skb);

		// 洲际优化：RTT 统计和方差计算
		if(rtt > 0 && rtt < MAX_RTT)
		{
			old_srtt = info_pointer->srtt;

			// 更新最小/最大 RTT
			if(rtt < min_observed_rtt)
			{
				min_observed_rtt = rtt;
				PAC_LOG("INTER: New min RTT:  %u us\n", min_observed_rtt);
			}
			if(rtt > max_observed_rtt)
			{
				max_observed_rtt = rtt;
				PAC_LOG("INTER: New max RTT: %u us\n", max_observed_rtt);
			}

			// 计算 RTT 方差
			if(old_srtt > 0)
			{
				unsigned int diff = (rtt > old_srtt) ? (rtt - old_srtt) : (old_srtt - rtt);
				rtt_variance = (rtt_variance * 7 + diff) / 8;
			}

			// 平滑 RTT（使用更保守的参数）
			info_pointer->srtt = RTT_SMOOTH * info_pointer->srtt / 1000 +
			                     (1000 - RTT_SMOOTH) * rtt / 1000;
		}

		info_pointer->bytes_sent_latest += skb->len - (ip_header->ihl<<2) - tcp_header->doff*4;

		if(info_pointer->bytes_sent_total <= 4294900000)
		{
			info_pointer->bytes_sent_total += skb->len - (ip_header->ihl<<2) - tcp_header->doff*4;

			// 洲际优化：更大的慢启动阈值
			if(info_pointer->bytes_sent_total > SS_THRESH && info_pointer->phase == SLOW_START)
			{
				info_pointer->phase = CONGESTION_AVOIDANCE;
				PAC_LOG("INTER:  Entering congestion avoidance at %lu bytes\n",
				        info_pointer->bytes_sent_total);
			}
		}

		if(payload_len > 0 && is_larger(tcp_header->seq + payload_len - 1, info_pointer->last_seq) == 1)
		{
			info_pointer->last_seq = tcp_header->seq + payload_len - 1;
		}

		time = get_tsval() - info_pointer->last_update;

		// 洲际优化：使用更长的测量间隔（2个RTT）
		if(time > info_pointer->srtt * 2)
		{
			info_pointer->last_update = get_tsval();
			throughput = info_pointer->bytes_sent_latest * 8 / time;
			info_pointer->bytes_sent_latest = 0;

			// 洲际优化：更宽松的拥塞检测
			if(throughput <= info_pointer->last_throughput * ALPHA / 1000)
			{
				info_pointer->throughput_reduction_num += 1;

				// 估算丢包率
				if(info_pointer->throughput_reduction_num > 2)
				{
					packet_loss_estimate = (1000 - throughput * 1000 /
					                        max(info_pointer->last_throughput, 1U)) / 10;
					PAC_LOG("INTER: Estimated packet loss:  %u.%u%%\n",
					        packet_loss_estimate / 100, packet_loss_estimate % 100);
				}

				if(info_pointer->throughput_reduction_num >= REDUCTION_THRESH &&
				   info_pointer->phase == SLOW_START)
				{
					info_pointer->phase = CONGESTION_AVOIDANCE;
					PAC_LOG("INTER: Throughput reduction -> congestion avoidance\n");
				}
			}
			else
			{
				info_pointer->throughput_reduction_num = 0;
				packet_loss_estimate = max(0, (int)packet_loss_estimate - 10);
			}
			info_pointer->last_throughput = throughput;

			// 更新平均吞吐量
			if(avg_throughput == 0)
				avg_throughput = throughput;
			else
				avg_throughput = (avg_throughput * 7 + throughput) / 8;
		}

		spin_lock_irqsave(&globalLock, flags);
		traffic += skb->len;

		if(ip_header->tos == 0x03)
			ecn_traffic += skb->len;

		if(tokens >= skb->len)
			tokens -= skb->len;
		else
			tokens = 0;

		total_rtt += rtt;
		samples++;
		spin_unlock_irqrestore(&globalLock, flags);
	}
	return NF_ACCEPT;
}

// 修复后的定时器回调函数
static enum hrtimer_restart my_hrtimer_callback_fixed(struct hrtimer *timer)
{
	ktime_t interval, now;
	unsigned long flags;
	unsigned int len;
	unsigned int time = 0;
	unsigned int current_time = 0;
	unsigned long int throughput = 0;
	int packets_to_send = 0;

	spin_lock_irqsave(&globalLock, flags);
	current_time = get_tsval();
	time = current_time - last_update;

	// 洲际优化：使用 2 倍平均 RTT 作为更新间隔
	if(time > avg_rtt * 2)
	{
		last_update = current_time;

		if(time > 0)
			throughput = traffic * 8 / time;

		// 洲际优化：自适应令牌重置
		if(throughput < ALPHA && 2 * traffic > ecn_traffic && avg_throughput > 0)
		{
			unsigned long new_tokens = bucket * throughput / avg_throughput;

			// 考虑 RTT 变化
			if(rtt_variance > avg_rtt / 4)
			{
				new_tokens = new_tokens * 80 / 100;  // 高抖动时更保守
			}

			if((2 * traffic - ecn_traffic) > 0)
				new_tokens = new_tokens * 2 * traffic / (2 * traffic - ecn_traffic);

			tokens = min(tokens, new_tokens);

			if(tokens > 0 && PAC_DEBUG)
				printk(KERN_DEBUG "PAC-INTER: Reset in-flight traffic to %lu (variance=%u)\n",
				        tokens, rtt_variance);
		}

		// 更新平均 RTT
		if(samples > 0)
		{
			avg_rtt = min(max(MIN_RTT, total_rtt / samples), MAX_RTT);
			if(PAC_DEBUG)
				printk(KERN_DEBUG "PAC-INTER:  Avg RTT updated to %lu us (samples=%lu)\n",
				        avg_rtt, samples);
		}
		else
			avg_rtt = MIN_RTT;

		// 洲际优化：更新自适应缓冲区
		update_adaptive_buffer();

		traffic = 0;
		ecn_traffic = 0;
		total_rtt = 0;
		samples = 0;
	}
	spin_unlock_irqrestore(&globalLock, flags);

	// 处理紧急队列（最高优先级）- 限制数量
	while(q_urgent && q_urgent->size > 0 && packets_to_send < 10)
	{
		len = q_urgent->packets[q_urgent->head].trigger;
		Dequeue_PacketQueue_Safe(q_urgent);
		packets_to_send++;
	}

	// 处理高优先级队列 - 限制数量
	while(q_high->size > 0 && packets_to_send < 20)
	{
		len = q_high->packets[q_high->head].trigger;
		if(bucket - tokens >= len)
		{
			spin_lock_irqsave(&globalLock, flags);
			tokens += len;
			spin_unlock_irqrestore(&globalLock, flags);
			Dequeue_PacketQueue_Safe(q_high);
			packets_to_send++;
		}
		else if(get_tsval() - q_high->packets[q_high->head].enqueue_time >= MAX_DELAY)
		{
			if(PAC_DEBUG)
				printk(KERN_DEBUG "PAC-INTER: High priority packet timeout, force send\n");
			Dequeue_PacketQueue_Safe(q_high);
			packets_to_send++;
		}
		else
		{
			break;
		}
	}

	// 处理低优先级队列 - 限制数量
	if(q_high->size == 0 && packets_to_send < 30)
	{
		while(q_low->size > 0 && packets_to_send < 30)
		{
			len = q_low->packets[q_low->head].trigger;
			if(bucket - tokens >= len)
			{
				spin_lock_irqsave(&globalLock, flags);
				tokens += len;
				spin_unlock_irqrestore(&globalLock, flags);
				Dequeue_PacketQueue_Safe(q_low);
				packets_to_send++;
			}
			else if(get_tsval() - q_low->packets[q_low->head].enqueue_time >= MAX_DELAY * 2)
			{
				if(PAC_DEBUG)
					printk(KERN_DEBUG "PAC-INTER: Low priority packet timeout, force send\n");
				Dequeue_PacketQueue_Safe(q_low);
				packets_to_send++;
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

	printk(KERN_INFO "PAC-Intercontinental v2.1-FIXED loading...\n");

	if(param_dev == NULL)
	{
		printk(KERN_INFO "PAC-INTER: not specify network interface (eth0 by default).\n");
		param_dev = "eth0\0";
	}

	// 复制并移除额外的字符
	strncpy(PAC_NIC, param_dev, 31);
	PAC_NIC[31] = '\0';

	for(i = 0; i < 32 && param_dev[i] != '\0'; i++)
	{
		if(param_dev[i] == '\n')
		{
			param_dev[i] = '\0';
			break;
		}
	}

	// 创建工作队列
	pac_workqueue = create_singlethread_workqueue("pac_workqueue");
	if (!pac_workqueue) {
		printk(KERN_ERR "PAC-INTER: Failed to create workqueue\n");
		return -ENOMEM;
	}

	// 洲际优化：初始化参数
	bucket = BUFFER_SIZE;
	adaptive_bucket_size = BUFFER_SIZE;
	tokens = 0;
	last_update = get_tsval();
	total_rtt = 0;
	samples = 0;
	avg_rtt = MIN_RTT;
	avg_throughput = 10000;  // 初始 10 Mbps
	min_observed_rtt = UINT_MAX;
	max_observed_rtt = 0;
	rtt_variance = 0;
	packet_loss_estimate = 0;

	// 初始化队列
	q_high = vmalloc(sizeof(struct PacketQueue));
	if (! q_high) {
		destroy_workqueue(pac_workqueue);
		return -ENOMEM;
	}
	Init_PacketQueue(q_high);

	q_low = vmalloc(sizeof(struct PacketQueue));
	if (!q_low) {
		Free_PacketQueue(q_high);
		destroy_workqueue(pac_workqueue);
		return -ENOMEM;
	}
	Init_PacketQueue(q_low);

	q_urgent = vmalloc(sizeof(struct PacketQueue));
	if (!q_urgent) {
		Free_PacketQueue(q_high);
		Free_PacketQueue(q_low);
		destroy_workqueue(pac_workqueue);
		return -ENOMEM;
	}
	Init_PacketQueue(q_urgent);

	Init_Table(&ft);
	spin_lock_init(&tableLock);
	spin_lock_init(&globalLock);

	// 启动定时器（10ms间隔）
	ktime = ktime_set(0, US_TO_NS(DELAY_IN_US));
	hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hr_timer.function = &my_hrtimer_callback_fixed;
	hrtimer_start(&hr_timer, ktime, HRTIMER_MODE_REL);

	// 注册 netfilter 钩子
	nfho_outgoing.hook = hook_func_out;
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;
	nfho_outgoing.pf = PF_INET;
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
		printk(KERN_ERR "PAC-INTER: Failed to setup proc interface\n");
	}

	printk(KERN_INFO "=====================================\n");
	printk(KERN_INFO "PAC-Intercontinental v2.1-FIXED loaded\n");
	printk(KERN_INFO "  Interface: %s\n", param_dev);
	printk(KERN_INFO "  Base RTT: %u ms\n", MIN_RTT / 1000);
	printk(KERN_INFO "  Max RTT: %u ms\n", MAX_RTT / 1000);
	printk(KERN_INFO "  Buffer:  %u MB\n", BUFFER_SIZE / (1024*1024));
	printk(KERN_INFO "  Mode:  Intercontinental Optimized (BH-Safe)\n");
	printk(KERN_INFO "=====================================\n");

	return 0;
}

void cleanup_module(void)
{
	int ret;

	pac_remove_proc();

	ret = hrtimer_cancel(&hr_timer);
	if(ret)
		printk(KERN_INFO "Timer was still in use...\n");

	// 等待工作队列完成
	if (pac_workqueue) {
		flush_workqueue(pac_workqueue);
		destroy_workqueue(pac_workqueue);
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
	Free_PacketQueue(q_urgent);
	Empty_Table(&ft);

	printk(KERN_INFO "PAC-Intercontinental:  Module unloaded\n");
	printk(KERN_INFO "  Min observed RTT: %lu ms\n",
	       min_observed_rtt == UINT_MAX ? 0 : min_observed_rtt / 1000);
	printk(KERN_INFO "  Max observed RTT: %lu ms\n", max_observed_rtt / 1000);
	printk(KERN_INFO "  RTT variance: %u ms\n", rtt_variance / 1000);
}