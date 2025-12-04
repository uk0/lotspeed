obj-m := zetatcp.o
zetatcp-objs := zeta_main.o zeta_cong.o zeta_loss.o zeta_rtt.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod zetatcp.ko param_dev=eth0

uninstall:
	sudo rmmod zetatcp

. PHONY: all clean install uninstall