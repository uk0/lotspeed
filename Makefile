VERSION		:= 3.3
KERNEL_RELEASE  ?= $(shell uname -r)
KERNEL_DIR      ?= /lib/modules/$(KERNEL_RELEASE)/build
obj-m           += lotspeed.o

ccflags-y := -std=gnu99

.PHONY: all clean load unload

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load:
	sudo insmod lotspeed.ko

unload:
	sudo rmmod lotspeed

.PHONY: dkms-prepare dkms-add dkms-build dkms-install dkms-remove dkms-clean
dkms-prepare:
	cp -r ./ /usr/src/lotspeed-${VERSION}

dkms-add:
	dkms add -m lotspeed -v ${VERSION}

dkms-build:
	dkms build -m lotspeed -v ${VERSION}

dkms-install:
	dkms install -m lotspeed -v ${VERSION}

dkms-remove:
	dkms remove -m lotspeed -v $(VERSION) --all

dkms-clean: dkms-remove
	rm -rf /usr/src/lotspeed-${VERSION}
