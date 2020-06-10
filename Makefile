obj-m := ncp.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	rm *.cmd *.symvers *.order *.log *.o ncp.mod ncp.mod.c