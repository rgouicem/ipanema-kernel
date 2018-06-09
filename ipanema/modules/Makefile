obj-m += Simple.o
obj-m += cfs.o
obj-m += cfs_wwc.o
obj-m += cfs_no_wwc.o
obj-m += ule_wwc.o
obj-m += ipanema_template.o
obj-m += batch.o

KERNEL=../../

# UBSAN_SANITIZE := y
# ccflags-y := -O0

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
	rm -rf *~

.PHONY: all clean
