PWD = $(shell pwd)
ARCH = arm64
obj-m := counter_agent.o

LINUX_SRC = /home/stefano/Scrivania/tgr/artifacts/imx8_tgr_linux/linux-imx

EXTRA_CFLAGS += -I$(LINUX_SRC)/include \
		-I$(PWD)

CROSS_COMPILE = aarch64-linux-gnu-
EXTRA_CFLAGS += -Werror -Wfatal-errors

ALL:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(LINUX_SRC) M=$(PWD) modules V=1

clean:
	rm -rf .*.cmd *.o *.mod.c *.ko *.order *.symvers .tmp_versions
