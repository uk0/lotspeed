# Zeta-TCP Makefile (High-Performance Version)

obj-m += zeta_tcp.o
zeta_tcp-objs := zeta_main.o zeta_conn.o zeta_learning.o zeta_ack_control.o \
                 zeta_hooks.o zeta_proc.o zeta_percpu.o zeta_batch.o

KDIR:= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# 优化选项
ccflags-y := -O2 -DZETA_VERSION=\"2.0.0\"

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.order *.symvers

install:
	sudo insmod zeta_tcp.ko verbose=1 ack_split=1

uninstall:
	sudo rmmod zeta_tcp

reload: uninstall install

test:
	@echo "=== Zeta-TCP Stats ==="
	@cat /proc/zeta_tcp/stats
	@echo ""
	@echo "=== Per-CPU Stats ==="
	@cat /proc/zeta_tcp/percpu

.PHONY: all clean install uninstall reload test