#ifndef HASH_H
#define HASH_H

#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "flow.h"

#define HASH_RANGE 256
#define QUEUE_SIZE 10240  // 增大队列，广域网可能有更多并发流

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

static void Print_Flow(struct Flow* f, int type)
{
    char local_ip[16] = {0};
    char remote_ip[16] = {0};

    snprintf(local_ip, 16, "%pI4", &(f->local_ip));
    snprintf(remote_ip, 16, "%pI4", &(f->remote_ip));

    if (type == 0) {
        printk(KERN_DEBUG "PAC: Insert flow %s:%hu -> %s:%hu\n",
               local_ip, f->local_port, remote_ip, f->remote_port);
    } else if (type == 1) {
        printk(KERN_DEBUG "PAC: Delete flow %s:%hu -> %s:%hu\n",
               local_ip, f->local_port, remote_ip, f->remote_port);
    }
}

static unsigned int Hash(struct Flow* f)
{
    return ((f->local_ip % HASH_RANGE + 1) *
            (f->remote_ip % HASH_RANGE + 1) *
            (f->local_port % HASH_RANGE + 1) *
            (f->remote_port % HASH_RANGE + 1)) % HASH_RANGE;
}

static int Equal(struct Flow* f1, struct Flow* f2)
{
    return (f1->local_ip == f2->local_ip) &&
           (f1->remote_ip == f2->remote_ip) &&
           (f1->local_port == f2->local_port) &&
           (f1->remote_port == f2->remote_port);
}

static void Init_Info(struct Info* i)
{
    i->srtt = 0;
    i->phase = 0;
    i->bytes_sent_latest = 0;
    i->bytes_sent_total = 0;
    i->last_ack = 0;
    i->last_seq = 0;
    i->last_throughput = 0;
    i->throughput_reduction_num = 0;
    i->last_update = 0;
}

static void Init_Flow(struct Flow* f)
{
    f->local_ip = 0;
    f->remote_ip = 0;
    f->local_port = 0;
    f->remote_port = 0;
    Init_Info(&(f->i));
}

static void Init_Node(struct FlowNode* fn)
{
    fn->next = NULL;
    Init_Flow(&(fn->f));
}

static void Init_List(struct FlowList* fl)
{
    struct FlowNode* buf = NULL;
    fl->len = 0;
    buf = vmalloc(sizeof(struct FlowNode));
    if (!buf) {
        printk(KERN_ERR "PAC: Vmalloc error\n");
    } else {
        fl->head = buf;
        Init_Node(fl->head);
    }
}

static void Init_Table(struct FlowTable* ft)
{
    int i = 0;
    struct FlowList* buf = NULL;

    buf = vmalloc(HASH_RANGE * sizeof(struct FlowList));
    if (! buf) {
        printk(KERN_ERR "PAC: Vmalloc error\n");
    } else {
        ft->table = buf;
        for (i = 0; i < HASH_RANGE; i++) {
            Init_List(&(ft->table[i]));
        }
    }
    ft->size = 0;
}

static int Insert_List(struct FlowList* fl, struct Flow* f)
{
    struct FlowNode* tmp;
    struct FlowNode* buf;

    if (fl->len >= QUEUE_SIZE) {
        return 0;
    }

    tmp = fl->head;

    while (1) {
        if (tmp->next == NULL) {
            buf = kmalloc(sizeof(struct FlowNode), GFP_ATOMIC);
            if (! buf) {
                return 0;
            }
            tmp->next = buf;
            tmp->next->f = *f;
            tmp->next->next = NULL;
            fl->len++;
            return 1;
        } else if (Equal(&(tmp->next->f), f) == 1) {
            tmp->next->f = *f;
            return 1;
        } else {
            tmp = tmp->next;
        }
    }
    return 0;
}

static int Insert_Table(struct FlowTable* ft, struct Flow* f)
{
    int result = 0;
    unsigned int index = Hash(f);

    result = Insert_List(&(ft->table[index]), f);
    ft->size += result;

    return result;
}

static struct Info* Search_List(struct FlowList* fl, struct Flow* f)
{
    struct FlowNode* tmp;

    if (fl->len == 0) {
        return NULL;
    }

    tmp = fl->head;
    while (tmp->next != NULL) {
        if (Equal(&(tmp->next->f), f) == 1) {
            return &(tmp->next->f.i);
        }
        tmp = tmp->next;
    }
    return NULL;
}

static struct Info* Search_Table(struct FlowTable* ft, struct Flow* f)
{
    unsigned int index = Hash(f);
    return Search_List(&(ft->table[index]), f);
}

// 静默删除，不打印日志
static unsigned int Delete_List(struct FlowList* fl, struct Flow* f)
{
    struct FlowNode* tmp;
    struct FlowNode* s;

    if (fl->len == 0) {
        return 0;
    }

    tmp = fl->head;

    while (tmp->next != NULL) {
        if (Equal(&(tmp->next->f), f) == 1) {
            s = tmp->next;
            tmp->next = s->next;
            kfree(s);
            fl->len--;
            return 1;
        }
        tmp = tmp->next;
    }

    return 0;
}

static unsigned int Delete_Table(struct FlowTable* ft, struct Flow* f)
{
    unsigned int result = 0;
    unsigned int index = Hash(f);

    result = Delete_List(&(ft->table[index]), f);
    if (result > 0) {
        ft->size--;
    }

    return result;
}

// 尝试双向删除流（处理入站 FIN 的情况）
static unsigned int Delete_Table_BiDir(struct FlowTable* ft, struct Flow* f)
{
    unsigned int result;
    struct Flow f_reverse;

    // 先尝试正向删除
    result = Delete_Table(ft, f);
    if (result > 0) {
        return result;
    }

    // 如果失败，尝试反向删除
    f_reverse. local_ip = f->remote_ip;
    f_reverse.remote_ip = f->local_ip;
    f_reverse.local_port = f->remote_port;
    f_reverse.remote_port = f->local_port;
    Init_Info(&(f_reverse.i));

    return Delete_Table(ft, &f_reverse);
}

static void Empty_List(struct FlowList* fl)
{
    struct FlowNode* NextNode;
    struct FlowNode* Ptr;

    for (Ptr = fl->head; Ptr != NULL; Ptr = NextNode) {
        NextNode = Ptr->next;
        if (Ptr == fl->head)
            vfree(Ptr);
        else
            kfree(Ptr);
    }
}

static void Empty_Table(struct FlowTable* ft)
{
    int i;
    for (i = 0; i < HASH_RANGE; i++) {
        Empty_List(&(ft->table[i]));
    }
    vfree(ft->table);
}

static void Print_Table(struct FlowTable* ft)
{
    int i;
    struct FlowNode* Ptr;

    printk(KERN_INFO "PAC: Flow table (%d flows):\n", ft->size);
    for (i = 0; i < HASH_RANGE; i++) {
        if (ft->table[i].len > 0) {
            for (Ptr = ft->table[i]. head->next; Ptr != NULL; Ptr = Ptr->next) {
                Print_Flow(&(Ptr->f), 2);
            }
        }
    }
}

#endif