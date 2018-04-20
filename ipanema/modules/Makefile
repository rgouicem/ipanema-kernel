obj-m += Simple.o cfs.o cfs_wwc.o
KERNEL=../../
UBSAN_SANITIZE := y
ccflags-y := -O0

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
	rm -rf *~

.PHONY: all clean
