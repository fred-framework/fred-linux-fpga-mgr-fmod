ifeq ($(CROSS_CC),1)
	export ARCH:=arm
	export CROSS_COMPILE:=arm-linux-gnueabihf-

	CC=$(CROSS_COMPILE)gcc
	KDIR := /home/marco/xil_linux/linux-xlnx-xilinx-v2019.2.01-arm
else
	KDIR := /lib/modules/`uname -r`/build
endif

# Temporary fix for building this module with older versions of GCC
ccflags-y += -fno-stack-protector

ccflags-y += -DDEBUG -Wall
obj-m += zynqmp-fpga-fmod.o

default:
	${MAKE} -C ${KDIR} -I ${KDIR}/include M=`pwd` modules

clean:
	${MAKE} -C ${KDIR} -I ${KDIR}/include M=`pwd` clean

