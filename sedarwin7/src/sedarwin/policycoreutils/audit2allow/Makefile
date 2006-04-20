# Installation directories.
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
LOCALEDIR ?= /usr/share/locale

TARGETS=audit2allow

all: $(TARGETS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)
	-mkdir -p $(MANDIR)/man1
	install -m 644 audit2allow.1 $(MANDIR)/man1/

clean:

relabel:
