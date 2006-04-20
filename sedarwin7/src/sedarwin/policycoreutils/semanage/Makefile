# Installation directories.
PREFIX ?= ${DESTDIR}/usr
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
PYLIBVER ?= python2.4
PYTHONLIBDIR ?= $(LIBDIR)/$(PYLIBVER)

TARGETS=semanage

all: $(TARGETS)

install: all
	[ -d $(MANDIR)/man8 ] || mkdir -p $(MANDIR)/man8
	-mkdir -p $(SBINDIR)
	install -m 755 semanage $(SBINDIR)
	install -m 644 semanage.8 $(MANDIR)/man8
	test -d $(PYTHONLIBDIR)/site-packages || install -m 755 -d $(PYTHONLIBDIR)/site-packages
	install -m 755 seobject.py $(PYTHONLIBDIR)/site-packages

clean:

relabel:
