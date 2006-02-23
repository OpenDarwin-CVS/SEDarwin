
include ../../Makeconfig

all: mgetpmac prboot ca compute_label

VPATH = $(EXPORT_HDRS)/osfmk/mach
CFLAGS += -g
CFLAGS += -I$(EXPORT_HDRS)/osfmk

security.c: security.defs
	mig $(CFLAGS) -user $@ -header security.h -server /dev/null -sheader /dev/null $<

security.o: security.c
	$(CC) $(CFLAGS) -c -o $@ $<

mgetpmac: security.o mgetpmac.o
	$(CC) -o $@ security.o mgetpmac.o
ca: ca.o security.o
	$(CC) -o $@ security.o ca.o

compute_label: compute_label.o security.o
	$(CC) -o $@ security.o compute_label.o

server: server.o security.o
	$(CC) -o $@ security.o server.o
prboot: BootstrapDump.o security.o
	$(CC) -o $@ security.o BootstrapDump.o

install: all
	install -o $(BINOWN) -g $(BINGRP) -m 755 ca $(DESTDIR)/usr/bin
	install -o $(BINOWN) -g $(BINGRP) -m 755 compute_label $(DESTDIR)/usr/bin
	install -o $(BINOWN) -g $(BINGRP) -m 755 mgetpmac $(DESTDIR)/usr/bin
	install -o $(BINOWN) -g $(BINGRP) -m 755 prboot $(DESTDIR)/usr/bin

clean:
	rm -f *.o ca mgetpmac prboot security.c security.h
