all: ipastart

ipastart: ipastart.c
	gcc -Wall -o $@ $<

install: ipastart
	cp ipastart /usr/bin/

clean:
	rm -rf *~ *.o

mrproper: clean
	rm -rf ipastart

.PHONY: all clean mrproper install

