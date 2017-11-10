all: ipastart

ipastart: ipastart.c
	gcc -Wall -o $@ $<

clean:
	rm -rf *~ *.o

mrproper: clean
	rm -rf ipastart

.PHONY: all clean mrproper

