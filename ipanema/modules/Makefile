obj-m += Simple.o
obj-m += cfs.o
obj-m += cfs_wwc.o
obj-m += cfs_wwc_lookalike.o
obj-m += cfs_wwc_local_new_unblock.o
obj-m += cfs_wwc_dumb_new_unblock.o
obj-m += cfs_wwc_blocked.o
obj-m += cfs_no_wwc.o
obj-m += cfs_wwc_flat.o
obj-m += cfs_wwc_flat_4msLB.o
obj-m += cfs_wwc_flat_4msLB_lock.o
obj-m += ule.o
obj-m += ule_wwc.o
obj-m += ipanema_template.o
obj-m += batch.o
obj-m += batch_blocked.o
obj-m += oltp.o

KERNEL?=../../

# UBSAN_SANITIZE := y
# ccflags-y := -O0

all:
	+make -C $(KERNEL) M=$(PWD) modules

clean:
	+make -C $(KERNEL) M=$(PWD) clean
	rm -rf *~

.PHONY: all clean
