KERNEL_RELEASE  ?= $(shell uname -r)
KERNEL_DIR      ?= /lib/modules/$(KERNEL_RELEASE)/build
DKMS_TARBALL    ?= dkms.tar.gz
TAR             ?= tar
obj-m           += lotspeed.o
obj-m           += sch_neoq.o
sch_neoq-objs   := qdisc_newneo.o

ccflags-y := -std=gnu99 -DCONFIG_NET_SCH_DEFAULT \
	-Wno-error=int-in-bool-context \
	-Wno-error=unused-variable \
	-Wno-error=unused-function

.PHONY: all clean load unload load-neoq unload-neoq v1 install-neoq neoq-status
.PHONY: .always-make

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean: clean-dkms.conf clean-dkms-tarball
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load:
	sudo insmod lotspeed.ko

unload:
	sudo rmmod lotspeed

load-neoq:
	sudo insmod sch_neoq.ko

unload-neoq:
	sudo rmmod sch_neoq

install-neoq: sch_neoq.ko
	sudo cp sch_neoq.ko /lib/modules/$(KERNEL_RELEASE)/kernel/net/sched/
	sudo depmod -a
	sudo cp neoqstat /usr/local/bin/
	@echo "NeoQ installed. Load with: sudo modprobe sch_neoq"
	@echo "Stats command: neoqstat [interface]"

neoq-status:
	@echo "=== NeoQ Module Status ==="
	@lsmod | grep -E "^sch_neoq" || echo "Module not loaded"
	@echo ""
	@echo "=== Active qdiscs ==="
	@tc qdisc show 2>/dev/null | grep neoq || echo "No NeoQ qdisc configured"
	@echo ""
	@echo "=== Stats ==="
	@cat /proc/net/neoq 2>/dev/null || echo "/proc/net/neoq not available"

.PHONY: dkms-tarball clean-dkms-tarball clean-dkms.conf

.always.make:

dkms.conf: ./scripts/mkdkmsconf.sh .always-make
	./scripts/mkdkmsconf.sh > dkms.conf

clean-dkms.conf:
	$(RM) dkms.conf

$(DKMS_TARBALL): dkms.conf Makefile lotspeed.c qdisc_newneo.c
	$(TAR) zcf $(DKMS_TARBALL) \
		--transform 's,^,./dkms_source_tree/,' \
		dkms.conf \
		Makefile \
		lotspeed.c \
		qdisc_newneo.c

dkms-tarball: $(DKMS_TARBALL)

clean-dkms-tarball:
	$(RM) $(DKMS_TARBALL)
