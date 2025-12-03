/*
 * Zeta-TCP V8 (Full Stats Mode - Fixed)
 * 修复了编译错误: 'interval' undeclared
 * 功能：
 * 1. 分离 TX (出站/加速方向) 和 RX (入站/反馈方向) 的吞吐量统计
 * 2. 状态日志直观显示 Server -> Client 的加速带宽
 * 3. 继承 V7 的抗抖动和稳定学习特性
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <net/tcp.h>
#include <net/checksum.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zeta-TCP V8 Fix");
MODULE_DESCRIPTION("Zeta-TCP with Bi-directional Throughput Monitoring");

/* ================= 参数配置 ================= */
#define RTT_SMOOTH 900
#define MIN_RTT 50000
#define MAX_RTT 500000
#define DELAY_IN_US 200
#define BUFFER_SIZE (4 * 1024 * 1024)
#define PRIO_THRESH (10UL * 1024 * 1024)
#define MIN_PKT_LEN 74
#define HASH_RANGE 256
#define QUEUE_SIZE 131072
#define HIGH_PRIORITY 1
#define LOW_PRIORITY 0
#define FLOW_DIR_SERVER 0
#define FLOW_DIR_CLIENT 1
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define MIN_WIN_PKTS 128

static char *param_dev = "eth0";
module_param(param_dev, charp, 0);

static int debug = 1;
module_param(debug, int, 0644);

#define US_TO_NS(x) ((x) * 1000L)
#define MSS 1460

#define ZETA_LOG(fmt, ...) do { \
    if (debug && printk_ratelimit()) \
        printk(KERN_INFO "[ZetaV8] " fmt, ##__VA_ARGS__); \
} while(0)

#define ZETA_STATUS(fmt, ...) do { \
    if (debug) \
        printk(KERN_INFO "[ZetaStatus] " fmt, ##__VA_ARGS__); \
} while(0)

/* ================= 数据结构 ================= */

struct Info {
    unsigned int srtt;
    unsigned short int phase;
    unsigned short int direction;

    // [V8] 分离 TX/RX 统计
    unsigned long tx_bytes_latest; // 出站 (Server->Client)
    unsigned long rx_bytes_latest; // 入站 (Client->Server)
    unsigned long bytes_sent_total;

    unsigned int last_ack;

    unsigned int tx_throughput;    // 出站带宽 (加速效果)
    unsigned int rx_throughput;    // 入站带宽

    unsigned int last_update;
    unsigned int max_seen_throughput; // 基于 TX 计算
    unsigned int base_min_rtt;
};

struct Flow {
    __be32 local_ip;
    __be32 remote_ip;
    __be16 local_port;
    __be16 remote_port;
    struct Info i;
};

struct FlowNode {
    struct Flow f;
    struct FlowNode* next;
};

struct FlowList {
    struct FlowNode* head;
    unsigned int len;
};

struct FlowTable {
    struct FlowList* table;
    unsigned int size;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    typedef int (*okfn_t)(struct net *, struct sock *, struct sk_buff *);
#else
    typedef int (*okfn_t)(struct sk_buff *);
#endif

struct Packet {
    struct sk_buff *skb;
    okfn_t okfn;
    unsigned int trigger;
    unsigned int enqueue_time;
};

struct PacketQueue {
    struct Packet *packets;
    unsigned int head;
    unsigned int tail;
    unsigned int size;
    unsigned int capacity;
};

/* ================= 全局变量 ================= */
static struct FlowTable ft;
static spinlock_t tableLock;
static spinlock_t globalLock;
static struct PacketQueue *q_high = NULL;
static struct PacketQueue *q_low = NULL;
static struct hrtimer hr_timer;

static unsigned long tokens = 0;
static unsigned long bucket = BUFFER_SIZE;
static unsigned int last_update;
static unsigned long total_rtt = 0;
static unsigned long samples = 0;
static unsigned long avg_rtt = MIN_RTT;

// [V8] 全局双向统计
static unsigned long tx_traffic = 0;
static unsigned long rx_traffic = 0;
static unsigned long global_tx_throughput = 0;
static unsigned long global_rx_throughput = 0;

static struct nf_hook_ops nfho_outgoing;
static struct nf_hook_ops nfho_incoming;

/* ================= 工具函数 ================= */

static unsigned int get_tsval(void) {
    return (unsigned int)(ktime_to_ns(ktime_get()) >> 10);
}

static unsigned int cumulative_ack_diff(unsigned int ack, unsigned int last_ack) {
    if (ack >= last_ack) return ack - last_ack;
    else return (0xFFFFFFFF - last_ack) + ack + 1;
}

static unsigned int tcp_parse_rtt(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *th = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    unsigned int tcp_header_len = th->doff * 4;
    unsigned char *ptr;
    unsigned int *tsecr;
    unsigned int rtt = 0;

    if (tcp_header_len < 30) return 0;
    if (!pskb_may_pull(skb, iph->ihl * 4 + tcp_header_len)) return 0;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((__u32 *)iph + iph->ihl);

    ptr = (unsigned char *)th + 20;
    while ((ptr - (unsigned char *)th) < tcp_header_len) {
        int opcode = *ptr;
        int opsize;

        if (opcode == TCPOPT_EOL) break;
        if (opcode == TCPOPT_NOP) { ptr++; continue; }

        opsize = *(ptr + 1);
        if (opsize < 2) break;
        if (ptr + opsize > (unsigned char *)th + tcp_header_len) break;

        if (opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP) {
            tsecr = (unsigned int *)(ptr + 6);
            rtt = get_tsval() - ntohl(*tsecr);
            break;
        }
        ptr += opsize;
    }
    return rtt;
}

static void tcp_modify_packet(struct sk_buff *skb, unsigned int time, unsigned int win) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *th;
    unsigned int tcp_header_len;
    unsigned char *ptr;
    unsigned int *tsval;
    __be32 old_ts, new_ts;
    __be16 old_win, new_win;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) return;
    th = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    tcp_header_len = th->doff * 4;
    if (!pskb_may_pull(skb, iph->ihl * 4 + tcp_header_len)) return;

    iph = ip_hdr(skb);
    th = (struct tcphdr *)((__u32 *)iph + iph->ihl);

    if (win > 0) {
        if (win > 65535) win = 65535;
        old_win = th->window;
        new_win = htons((unsigned short)win);

        if (old_win != new_win) {
            inet_proto_csum_replace2(&th->check, skb, old_win, new_win, 0);
            th->window = new_win;
        }
    }

    if (time > 0) {
        ptr = (unsigned char *)th + 20;
        while ((ptr - (unsigned char *)th) < tcp_header_len) {
            int opcode = *ptr;
            int opsize;
            if (opcode == TCPOPT_EOL) break;
            if (opcode == TCPOPT_NOP) { ptr++; continue; }
            opsize = *(ptr + 1);
            if (opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP) {
                 tsval = (unsigned int *)(ptr + 2);
                 old_ts = *tsval;
                 new_ts = htonl(time);
                 if (old_ts != new_ts) {
                     inet_proto_csum_replace4(&th->check, skb, old_ts, new_ts, 0);
                     *tsval = new_ts;
                 }
                 break;
            }
            ptr += opsize;
        }
    }
}

/* ================= 队列操作 ================= */

static void Init_PacketQueue(struct PacketQueue* q) {
    q->packets = vmalloc(QUEUE_SIZE * sizeof(struct Packet));
    memset(q->packets, 0, QUEUE_SIZE * sizeof(struct Packet));
    q->head = q->tail = q->size = 0;
    q->capacity = QUEUE_SIZE;
}

static int Enqueue_PacketQueue(struct PacketQueue* q, struct sk_buff *skb, okfn_t okfn, unsigned int trigger, unsigned int time) {
    if (q->size >= q->capacity) return 0;
    q->packets[q->tail].skb = skb;
    q->packets[q->tail].okfn = okfn;
    q->packets[q->tail].trigger = trigger;
    q->packets[q->tail].enqueue_time = time;
    q->tail = (q->tail + 1) % q->capacity;
    q->size++;
    return 1;
}

static int Dequeue_PacketQueue(struct PacketQueue* q) {
    struct Packet *pkt;
    if (q->size == 0) return 0;
    pkt = &q->packets[q->head];
    if (pkt->okfn && pkt->skb) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
        pkt->okfn(&init_net, NULL, pkt->skb);
#else
        pkt->okfn(pkt->skb);
#endif
    }
    q->head = (q->head + 1) % q->capacity;
    q->size--;
    return 1;
}

/* ================= 流表操作 ================= */

static unsigned int Hash(struct Flow* f) {
    return ((f->local_ip + f->remote_ip + f->local_port + f->remote_port) % HASH_RANGE);
}

static int Equal(struct Flow* f1, struct Flow* f2) {
    return (f1->local_ip == f2->local_ip && f1->remote_ip == f2->remote_ip &&
            f1->local_port == f2->local_port && f1->remote_port == f2->remote_port);
}

static void Init_Table(struct FlowTable* ft) {
    int i;
    ft->table = vmalloc(HASH_RANGE * sizeof(struct FlowList));
    ft->size = 0;
    for(i=0; i<HASH_RANGE; i++) {
        ft->table[i].head = kmalloc(sizeof(struct FlowNode), GFP_ATOMIC);
        ft->table[i].head->next = NULL;
        ft->table[i].len = 0;
    }
}

static struct Info* Search_Table(struct FlowTable* ft, struct Flow* f) {
    unsigned int index = Hash(f);
    struct FlowNode* tmp = ft->table[index].head;
    while(tmp->next != NULL) {
        if(Equal(&(tmp->next->f), f)) return &(tmp->next->f.i);
        tmp = tmp->next;
    }
    return NULL;
}

static void Insert_Table(struct FlowTable* ft, struct Flow* f) {
    unsigned int index = Hash(f);
    struct FlowNode* buf = kmalloc(sizeof(struct FlowNode), GFP_ATOMIC);
    buf->f = *f;
    buf->next = ft->table[index].head->next;
    ft->table[index].head->next = buf;
    ft->table[index].len++;
    ft->size++;
}

static void Empty_Table(struct FlowTable* ft) {
    int i;
    for(i=0; i<HASH_RANGE; i++) {
        struct FlowNode *p = ft->table[i].head, *tmp;
        while(p) { tmp = p; p = p->next; kfree(tmp); }
    }
    vfree(ft->table);
}

/* ================= Netfilter 核心逻辑 ================= */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct net_device *out = state->out;
#else
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
                                   const struct net_device *in, const struct net_device *out,
                                   int (*okfn)(struct sk_buff *)) {
#endif
    struct iphdr *iph;
    struct tcphdr *th;
    struct Flow f;
    struct Info* info = NULL;
    unsigned int trigger = 0;
    unsigned long flags;
    int is_client = 0;
    int prio = HIGH_PRIORITY;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#endif

    if (!out || strcmp(out->name, param_dev) != 0) return NF_ACCEPT;
    if (!skb->len) return NF_ACCEPT;
    if (skb->protocol != htons(ETH_P_IP)) return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) return NF_ACCEPT;
    th = (struct tcphdr *)((__u32 *)iph + iph->ihl);

    f.local_ip = iph->saddr; f.remote_ip = iph->daddr;
    f.local_port = ntohs(th->source); f.remote_port = ntohs(th->dest);

    int new_flow = 0;

    if (th->syn) {
        if (!th->ack) {
            f.i.direction = FLOW_DIR_CLIENT;
            new_flow = 1;
        } else {
            f.i.srtt = MIN_RTT;
            f.i.base_min_rtt = MIN_RTT;
            f.i.phase = SLOW_START;
            f.i.direction = FLOW_DIR_SERVER;
            f.i.bytes_sent_total = 0;
            f.i.last_ack = ntohl(th->ack_seq);
            f.i.last_update = get_tsval();
            new_flow = 1;
        }
    }

    if (new_flow) {
        spin_lock_irqsave(&tableLock, flags);
        if (Search_Table(&ft, &f) == NULL) Insert_Table(&ft, &f);
        spin_unlock_irqrestore(&tableLock, flags);
        if (f.i.direction == FLOW_DIR_CLIENT) return NF_ACCEPT;
        trigger = MIN_PKT_LEN;
    } else {
        spin_lock_irqsave(&tableLock, flags);
        info = Search_Table(&ft, &f);

        if (info == NULL && skb->len > 1000) {
             f.i.srtt = MIN_RTT;
             f.i.base_min_rtt = MIN_RTT;
             f.i.phase = SLOW_START;
             f.i.direction = FLOW_DIR_SERVER;
             f.i.bytes_sent_total = 0;
             f.i.last_ack = ntohl(th->ack_seq);
             f.i.last_update = get_tsval();
             Insert_Table(&ft, &f);
             info = Search_Table(&ft, &f);
        }
        if (info) is_client = (info->direction == FLOW_DIR_CLIENT);

        // [V8] 统计出站流量 (加速效果)
        if (info && !is_client) {
            info->tx_bytes_latest += skb->len;
            info->bytes_sent_total += skb->len;
        }

        spin_unlock_irqrestore(&tableLock, flags);

        if (!info || is_client) return NF_ACCEPT;

        if (info->bytes_sent_total < PRIO_THRESH) prio = HIGH_PRIORITY;
        else prio = LOW_PRIORITY;

        trigger = skb->len;
    }

    // 全局出站流量累计
    spin_lock_irqsave(&globalLock, flags);
    tx_traffic += skb->len;
    spin_unlock_irqrestore(&globalLock, flags);

    unsigned int target_win = MIN_WIN_PKTS * MSS;

    if (info && info->srtt > 0) {
        unsigned int bw = (info->max_seen_throughput > info->tx_throughput)
                          ? info->max_seen_throughput : info->tx_throughput;

        if (bw > 0) {
            unsigned int calc_rtt = (info->base_min_rtt > 0) ? info->base_min_rtt : info->srtt;
            unsigned long long bdp = (unsigned long long)bw * calc_rtt / 8;
            if (bdp > target_win) target_win = (unsigned int)(bdp * 25 / 10);
        }

        if (target_win > MIN_WIN_PKTS * MSS) {
            ZETA_LOG("[Egress] Inflating Win to %u\n", target_win);
        }
    }

    tcp_modify_packet(skb, get_tsval(), target_win);

    if (trigger >= bucket) return NF_ACCEPT;

    if (bucket - tokens >= trigger &&
       ((prio == HIGH_PRIORITY && q_high->size == 0) ||
        (prio == LOW_PRIORITY && q_high->size == 0 && q_low->size == 0))) {
        spin_lock_irqsave(&globalLock, flags);
        tokens += trigger;
        spin_unlock_irqrestore(&globalLock, flags);
        return NF_ACCEPT;
    }

    int res;
    if (prio == HIGH_PRIORITY) res = Enqueue_PacketQueue(q_high, skb, okfn, trigger, get_tsval());
    else res = Enqueue_PacketQueue(q_low, skb, okfn, trigger, get_tsval());

    if (res) return NF_STOLEN;
    else return NF_DROP;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct net_device *in = state->in;
#else
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
                                  const struct net_device *in, const struct net_device *out,
                                  int (*okfn)(struct sk_buff *)) {
#endif
    struct iphdr *iph;
    struct tcphdr *th;
    struct Flow f;
    struct Info* info = NULL;
    unsigned long flags;
    unsigned int rtt, time;

    if (!in || strcmp(in->name, param_dev) != 0) return NF_ACCEPT;
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) return NF_ACCEPT;
    th = (struct tcphdr *)((__u32 *)iph + iph->ihl);

    f.local_ip = iph->daddr; f.remote_ip = iph->saddr;
    f.local_port = ntohs(th->dest); f.remote_port = ntohs(th->source);

    spin_lock_irqsave(&tableLock, flags);
    info = Search_Table(&ft, &f);

    if (!info || info->direction == FLOW_DIR_CLIENT) {
        spin_unlock_irqrestore(&tableLock, flags);
        return NF_ACCEPT;
    }

    if (th->ack) {
        unsigned int ack = ntohl(th->ack_seq);
        unsigned int bytes_acked = 0;

        if (info->last_ack != 0 && ack != info->last_ack) {
            bytes_acked = cumulative_ack_diff(ack, info->last_ack);
            info->last_ack = ack;
        }

        spin_lock(&globalLock);
        if (bytes_acked > 0) {
            if (tokens >= bytes_acked) tokens -= bytes_acked;
            else tokens = 0;
        } else {
            if (tokens >= MIN_PKT_LEN) tokens -= MIN_PKT_LEN;
        }
        spin_unlock(&globalLock);
    }

    // [V8] 统计入站流量
    if (info) {
        info->rx_bytes_latest += skb->len;
    }
    spin_unlock_irqrestore(&tableLock, flags);

    unsigned int inflated_win = MIN_WIN_PKTS * MSS;

    if (info && info->srtt > 0) {
        unsigned int bw = (info->max_seen_throughput > info->tx_throughput)
                          ? info->max_seen_throughput : info->tx_throughput;

        if (bw > 0) {
            unsigned int calc_rtt = (info->base_min_rtt > 0) ? info->base_min_rtt : info->srtt;
            unsigned long long bdp = (unsigned long long)bw * calc_rtt / 8;
            if (bdp > inflated_win) inflated_win = (unsigned int)(bdp * 25 / 10);
        }
    }

    tcp_modify_packet(skb, 0, inflated_win);

    if (inflated_win > MIN_WIN_PKTS * MSS) {
        ZETA_LOG("[Ingress] Inflating ACK Win to %u\n", inflated_win);
    }

    rtt = tcp_parse_rtt(skb);
    if (rtt > 0 && info) {
        info->srtt = RTT_SMOOTH * info->srtt / 1000 + (1000 - RTT_SMOOTH) * rtt / 1000;
        if (info->base_min_rtt == 0 || rtt < info->base_min_rtt) {
            info->base_min_rtt = rtt;
        } else if (rtt > info->base_min_rtt * 2) {
            info->base_min_rtt = (info->base_min_rtt * 99 + rtt) / 100;
        }
    }

    if (info) {
        // 更新吞吐量 (Per-Flow)
        time = get_tsval() - info->last_update;
        if (time > info->srtt && time > 0) {
            // RX 带宽
            info->rx_throughput = info->rx_bytes_latest * 8 / time;
            info->rx_bytes_latest = 0;

            // TX 带宽 (从 tx_bytes_latest 计算)
            info->tx_throughput = info->tx_bytes_latest * 8 / time;
            info->tx_bytes_latest = 0;

            info->last_update = get_tsval();

            if (info->tx_throughput > info->max_seen_throughput) {
                info->max_seen_throughput = info->tx_throughput;
            }
        }
    }

    spin_lock_irqsave(&globalLock, flags);
    rx_traffic += skb->len;
    total_rtt += rtt;
    samples++;
    spin_unlock_irqrestore(&globalLock, flags);

    return NF_ACCEPT;
}

static enum hrtimer_restart my_hrtimer_callback(struct hrtimer *timer) {
    unsigned long flags;
    unsigned int current_time = get_tsval();
    unsigned int time_diff;
    static int status_tick = 0;
    ktime_t interval;

    spin_lock_irqsave(&globalLock, flags);

    unsigned long decay = bucket / 10;
    if (tokens >= decay) tokens -= decay;
    else tokens = 0;

    time_diff = current_time - last_update;

    if (time_diff > avg_rtt) {
        last_update = current_time;
        if (time_diff > 0) {
            // [V8] 双向吞吐全局计算
            global_rx_throughput = rx_traffic * 8 / time_diff;
            global_tx_throughput = tx_traffic * 8 / time_diff;
        }

        if (samples > 0) {
            unsigned long current_avg = total_rtt / samples;
            if (avg_rtt == MIN_RTT) avg_rtt = current_avg;
            else avg_rtt = (avg_rtt * 7 + current_avg * 3) / 10;
        }

        rx_traffic = 0;
        tx_traffic = 0;
        total_rtt = 0;
        samples = 0;
    }
    spin_unlock_irqrestore(&globalLock, flags);

    status_tick++;
    if (status_tick >= 5000) {
        unsigned long pct_x10 = (tokens * 1000) / BUFFER_SIZE;
        ZETA_STATUS(">>> Global Status <<<\n");
        // [V8] 显示双向数据
        ZETA_STATUS("   [Perf] TX (Accel): %lu Mbps | RX (Feedback): %lu Mbps | RTT: %lu us\n",
                    global_tx_throughput, global_rx_throughput, avg_rtt);
        ZETA_STATUS("   [Congestion] Tokens Used: %lu / %u (%lu.%lu%%)\n",
                    tokens, BUFFER_SIZE, pct_x10 / 10, pct_x10 % 10);
        ZETA_STATUS("   [Pacing] Q_High: %u, Q_Low: %u\n", q_high->size, q_low->size);
        status_tick = 0;
    }

    while(q_high->size > 0) {
        struct Packet *pkt = &q_high->packets[q_high->head];
        if (bucket - tokens >= pkt->trigger) {
            spin_lock_irqsave(&globalLock, flags);
            tokens += pkt->trigger;
            spin_unlock_irqrestore(&globalLock, flags);
            Dequeue_PacketQueue(q_high);
        } else if (get_tsval() - pkt->enqueue_time >= MAX_RTT) {
            Dequeue_PacketQueue(q_high);
        } else break;
    }

    if (q_high->size == 0) {
        while(q_low->size > 0) {
            struct Packet *pkt = &q_low->packets[q_low->head];
            if (bucket - tokens >= pkt->trigger) {
                spin_lock_irqsave(&globalLock, flags);
                tokens += pkt->trigger;
                spin_unlock_irqrestore(&globalLock, flags);
                Dequeue_PacketQueue(q_low);
            } else if (get_tsval() - pkt->enqueue_time >= MAX_RTT) {
                Dequeue_PacketQueue(q_low);
            } else break;
        }
    }

    interval = ktime_set(0, US_TO_NS(DELAY_IN_US));
    hrtimer_forward_now(timer, interval);
    return HRTIMER_RESTART;
}

static int __init zeta_init(void) {
    ktime_t ktime;

    q_high = vmalloc(sizeof(struct PacketQueue)); Init_PacketQueue(q_high);
    q_low = vmalloc(sizeof(struct PacketQueue)); Init_PacketQueue(q_low);
    Init_Table(&ft);
    spin_lock_init(&tableLock);
    spin_lock_init(&globalLock);

    nfho_outgoing.hook = hook_func_out;
    nfho_outgoing.hooknum = NF_INET_POST_ROUTING;
    nfho_outgoing.pf = PF_INET;
    nfho_outgoing.priority = NF_IP_PRI_FIRST;

    nfho_incoming.hook = hook_func_in;
    nfho_incoming.hooknum = NF_INET_PRE_ROUTING;
    nfho_incoming.pf = PF_INET;
    nfho_incoming.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, &nfho_outgoing);
    nf_register_net_hook(&init_net, &nfho_incoming);
#else
    nf_register_hook(&nfho_outgoing);
    nf_register_hook(&nfho_incoming);
#endif

    ktime = ktime_set(0, US_TO_NS(DELAY_IN_US));
    hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hr_timer.function = &my_hrtimer_callback;
    hrtimer_start(&hr_timer, ktime, HRTIMER_MODE_REL);

    printk(KERN_INFO "Zeta-TCP V8 (Full Stats) Loaded on %s\n", param_dev);
    return 0;
}

static void __exit zeta_exit(void) {
    hrtimer_cancel(&hr_timer);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho_outgoing);
    nf_unregister_net_hook(&init_net, &nfho_incoming);
#else
    nf_unregister_hook(&nfho_outgoing);
    nf_unregister_hook(&nfho_incoming);
#endif
    vfree(q_high->packets); vfree(q_high);
    vfree(q_low->packets); vfree(q_low);
    Empty_Table(&ft);
    printk(KERN_INFO "Zeta-TCP Unloaded\n");
}

module_init(zeta_init);
module_exit(zeta_exit);