
obj-m := zeta_control_poc.o
# 内核源码路径
KDIR := /lib/modules/$(shell uname -r)/build

# 当前目录
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	insmod zeta_control_poc.ko

uninstall:
	rmmod zeta_control_poc

. PHONY: all clean install uninstall