ccflags-y += -fno-stack-protector -Wno-error
obj-m := zynqmp-fpga-fmod.o

SRC := $(shell pwd)
KERNEL_SRC ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
