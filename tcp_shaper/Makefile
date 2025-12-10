# APX 加速器 v6.0 Makefile

obj-m := apx_accelerator.o

apx_accelerator-objs := apx_main.o \
                        apx_bandwidth.o \
                        apx_rtt.o \
                        apx_retrans.o \
                        apx_queue.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.symvers *.order

install:
	sudo insmod apx_accelerator. ko

uninstall:
	sudo rmmod apx_accelerator

test:
	@echo "检查模块状态..."
	@lsmod | grep apx_accelerator || echo "模块未加载"
	@echo "查看日志..."
	@sudo dmesg | grep APX | tail -20

config:
	@echo "配置APX参数..."
	@echo "10" | sudo tee /sys/module/apx_accelerator/parameters/initial_cwnd_scale
	@echo "1" | sudo tee /sys/module/apx_accelerator/parameters/dynamic_bw
	@echo "1" | sudo tee /sys/module/apx_accelerator/parameters/smart_retrans
	@echo "1" | sudo tee /sys/module/apx_accelerator/parameters/multi_queue

.PHONY: all clean install uninstall test config