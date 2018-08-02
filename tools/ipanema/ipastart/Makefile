BIN=ipastart

all: ${BIN}

${BIN}: ${BIN}.c
	gcc -Wall -o $@ $<

install: ${BIN}
	cp ${BIN} /usr/bin/

clean:
	rm -rf *~ *.o

mrproper: clean
	rm -rf ${BIN}

.PHONY: all clean mrproper install

