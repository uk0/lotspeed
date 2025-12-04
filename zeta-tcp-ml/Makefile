# Zeta-TCP Learning-based Accelerator
# NetFilter Hook Implementation

obj-m := zeta_tcp.o
zeta_tcp-objs := zeta_main.o zeta_hooks.o zeta_learning.o \
                 zeta_ack_control.o zeta_conn.o zeta_proc.o

KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

# 编译选项
ccflags-y := -O2 -Wall -Wno-declaration-after-statement
ccflags-y += -DZETA_VERSION=\"1.0.0\"

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.order *.symvers

install: all
	sudo insmod zeta_tcp.ko
	@echo "Zeta-TCP loaded.  Check /proc/zeta_tcp for status."

uninstall:
	sudo rmmod zeta_tcp || true

reload: uninstall install

. PHONY: all clean install uninstall reload