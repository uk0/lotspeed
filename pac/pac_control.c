/* pac_control.c */
/* 注意：不要独立编译此文件，请将其 include 到主逻辑文件中 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROC_DIR_NAME "lotspeed"

enum {
    T_UINT,   // unsigned int
    T_ULONG,  // unsigned long
    T_USHORT,  // unsigned short int
	T_STRING // char[]
};

// 映射表结构
struct pac_param_map {
    const char *name;
    void *ptr;
    int type;
};

// 1. 在这里建立映射，直接引用 params.h 中的变量名
// 因为是 include 进来的，所以能直接访问到 static 变量
static struct pac_param_map pac_params[] = {
    {"debug",             &PAC_DEBUG,         T_UINT},
    {"mss",               &MSS,               T_UINT},
	{"param_dev",         PAC_NIC,            T_STRING},
    {"min_win",           &MIN_WIN,           T_UINT},
    {"delay_in_us",       &DELAY_IN_US,       T_ULONG},
    {"min_rtt",           &MIN_RTT,           T_UINT},
    {"max_rtt",           &MAX_RTT,           T_UINT},
    {"max_delay",         &MAX_DELAY,         T_UINT},
    {"buffer_size",       &BUFFER_SIZE,       T_UINT},
    {"min_pkt_len",       &MIN_PKT_LEN,       T_UINT},
    {"throughput_smooth", &THROUGHPUT_SMOOTH, T_UINT},
    {"rtt_smooth",        &RTT_SMOOTH,        T_UINT},
    {"alpha",             &ALPHA,             T_UINT},
    {"reduction_thresh",  &REDUCTION_THRESH,  T_USHORT},
    {"prio_thresh",       &PRIO_THRESH,       T_ULONG},
    {"ss_thresh",         &SS_THRESH,         T_ULONG},
    {NULL, NULL, 0}
};

static struct proc_dir_entry *pac_proc_dir = NULL;

// --- Read (GET) ---
static int pac_show(struct seq_file *m, void *v)
{
    struct pac_param_map *map = (struct pac_param_map *)m->private;

    switch(map->type) {
        case T_UINT:   seq_printf(m, "%u\n", *(unsigned int *)map->ptr); break;
        case T_ULONG:  seq_printf(m, "%lu\n", *(unsigned long *)map->ptr); break;
        case T_USHORT: seq_printf(m, "%hu\n", *(unsigned short int *)map->ptr); break;
		// 新增：字符串打印
        case T_STRING: seq_printf(m, "%s\n", (char *)map->ptr); break;
    }
    return 0;
}

static int pac_open(struct inode *inode, struct file *file)
{
    return single_open(file, pac_show, PDE_DATA(inode));
}

// --- Write (SET) ---
static ssize_t pac_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    struct seq_file *m = file->private_data;
    struct pac_param_map *map = (struct pac_param_map *)m->private;
    char kbuf[32];
    unsigned long val;
    int ret;
	char *p;

    // 防止缓冲区溢出，最大读取 31 字节
    if (count > sizeof(kbuf) - 1) count = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, count)) return -EFAULT;
    kbuf[count] = '\0';

	// 处理字符串类型
    if (map->type == T_STRING) {
        // 去除末尾的换行符 \n (echo 命令会自动加换行)
        p = strchr(kbuf, '\n');
        if (p) *p = '\0';

        // 拷贝字符串到目标变量，确保安全
        // 假设 params.h 里定义的是 32 字节，这里用 strncpy
        strncpy((char *)map->ptr, kbuf, 31);
        // 强制最后一位为 \0 确保安全
        ((char *)map->ptr)[31] = '\0';

        if (PAC_DEBUG) {
            printk(KERN_INFO "PAC: Set %s = %s\n", map->name, (char *)map->ptr);
        }
        return count;
    }

	// 处理数字类型
    ret = kstrtoul(kbuf, 10, &val);
    if (ret < 0) return ret;

    // 赋值回对应的变量
    switch(map->type) {
        case T_UINT:   *(unsigned int *)map->ptr = (unsigned int)val; break;
        case T_ULONG:  *(unsigned long *)map->ptr = val; break;
        case T_USHORT: *(unsigned short int *)map->ptr = (unsigned short int)val; break;
    }

    if (PAC_DEBUG) {
        printk(KERN_INFO "PAC: Set %s = %lu\n", map->name, val);
    }
    return count;
}

// 定义文件操作
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops pac_fops = {
    .proc_open = pac_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = pac_write,
};
#else
static const struct file_operations pac_fops = {
    .open = pac_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = pac_write,
};
#endif

// --- Init & Exit ---
static int pac_setup_proc(void)
{
    struct pac_param_map *map;

    pac_proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!pac_proc_dir) {
        printk(KERN_ERR "PAC: Failed to create /proc/%s directory\n", PROC_DIR_NAME);
        return -ENOMEM;
    }

    for (map = pac_params; map->name; map++) {
        if (! proc_create_data(map->name, 0644, pac_proc_dir, &pac_fops, map)) {
            printk(KERN_ERR "PAC: Failed to create /proc/%s/%s\n", PROC_DIR_NAME, map->name);
        }
    }

    printk(KERN_INFO "PAC: Created /proc/%s with %d parameters\n",
           PROC_DIR_NAME, (int)(sizeof(pac_params)/sizeof(pac_params[0]) - 1));
    return 0;
}

static void pac_remove_proc(void)
{
    struct pac_param_map *map;
    if (! pac_proc_dir) return;

    for (map = pac_params; map->name; map++) {
        remove_proc_entry(map->name, pac_proc_dir);
    }
    remove_proc_entry(PROC_DIR_NAME, NULL);
    printk(KERN_INFO "PAC: Removed /proc/%s\n", PROC_DIR_NAME);
}