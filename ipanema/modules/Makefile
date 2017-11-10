obj-m += Simple.o
KERNEL=../../
UBSAN_SANITIZE := y

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
	rm -rf *~

.PHONY: all clean
