# Installation directories.
PREFIX ?= ${DESTDIR}/usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
LIBDIR ?= $(PREFIX)/lib

CFLAGS = -Werror -Wall -W
override CFLAGS += -D_FILE_OFFSET_BITS=64 -I$(PREFIX)/include
LDLIBS = -lselinux -lsepol -L$(LIBDIR)

all: setfiles

setfiles:  setfiles.o 

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 setfiles $(SBINDIR)
	install -m 644 setfiles.8 $(MANDIR)/man8

clean:
	rm -f setfiles *.o 

relabel: install
	/sbin/restorecon $(SBINDIR)/setfiles
