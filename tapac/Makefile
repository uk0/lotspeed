# TAPAC Kernel Module Makefile

obj-m := tapac.o
tapac-objs := tapac_main.o tapac_flow.o tapac_queue.o tapac_ack.o \
              tapac_ack_opt.o tapac_upload.o tapac_rtt.o tapac_sack.o \
              tapac_checksum.o tapac_proc.o
# 内核源码路径
KDIR := /lib/modules/$(shell uname -r)/build

# 当前目录
PWD := $(shell pwd)

# 默认网卡
NIC ?= eth0

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers
	rm -rf .tmp_versions

install: all
	sudo insmod tapac.ko param_dev=$(NIC)

uninstall:
	sudo rmmod tapac || true

reload: uninstall install

status:
	@lsmod | grep tapac || echo "Module not loaded"
	@cat /proc/tapac/stats 2>/dev/null || true

log:
	sudo dmesg | tail -50 | grep -i tapac

. PHONY: all clean install uninstall reload status log