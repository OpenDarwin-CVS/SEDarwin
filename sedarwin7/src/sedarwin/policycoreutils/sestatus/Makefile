# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LIBDIR ?= ${PREFIX}/lib

CFLAGS = -Werror -Wall -W
override CFLAGS += -I$(PREFIX)/include -D_FILE_OFFSET_BITS=64
LDLIBS = -lselinux -lsepol -L$(LIBDIR)

all: sestatus

sestatus:  sestatus.o 

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 sestatus $(SBINDIR)
	install -m 644 sestatus.8 $(MANDIR)/man8
	-mkdir -p $(ETCDIR)
	install -m 644 sestatus.conf $(ETCDIR)

clean:
	rm -f sestatus *.o 

relabel:
