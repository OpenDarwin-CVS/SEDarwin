# Installation directories.
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
ETCDIR ?= $(DESTDIR)/etc
LOCALEDIR = /usr/share/locale
PAMH = $(shell ls /usr/include/security/pam_appl.h 2>/dev/null)
AUDITH = $(shell ls /usr/include/libaudit.h 2>/dev/null)
# If LOG_AUDIT_PRIV is y, then newrole will be made into setuid root program.
# This is so that we have the CAP_AUDIT_WRITE capability. newrole will
# shed all privileges and change to the user's uid.
LOG_AUDIT_PRIV ?= n
VERSION = $(shell cat ../VERSION)

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -DVERSION=\"$(VERSION)\" $(LDFLAGS) -I$(PREFIX)/include -DUSE_NLS -DLOCALEDIR="\"$(LOCALEDIR)\"" -DPACKAGE="\"policycoreutils\""
LDLIBS += -lselinux -lsepol -L$(PREFIX)/lib
ifeq (${PAMH}, /usr/include/security/pam_appl.h)
	override CFLAGS += -DUSE_PAM
	LDLIBS += -lpam -lpam_misc
else
	override CFLAGS += -D_XOPEN_SOURCE=500
	LDLIBS += -lcrypt
endif
ifeq (${AUDITH}, /usr/include/libaudit.h)
	override CFLAGS += -DUSE_AUDIT
	LDLIBS += -laudit
endif
ifeq (${LOG_AUDIT_PRIV},y)
	override CFLAGS += -DLOG_AUDIT_PRIV -D_GNU_SOURCE
	LDLIBS += -lcap
	MODE := 4555
else
	MODE := 555
endif

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS)

install: all
	test -d $(BINDIR)      || install -m 755 -d $(BINDIR)
	test -d $(ETCDIR)/pam.d || install -m 755 -d $(ETCDIR)/pam.d
	test -d $(MANDIR)/man1 || install -m 755 -d $(MANDIR)/man1
	install -m $(MODE) newrole $(BINDIR)
	install -m 644 newrole.1 $(MANDIR)/man1/
ifeq (${PAMH}, /usr/include/security/pam_appl.h)
	test -d $(ETCDIR)/pam.d || install -m 755 -d $(ETCDIR)/pam.d
	install -m 644 newrole.pamd $(ETCDIR)/pam.d/newrole
endif

clean:
	rm -f $(TARGETS) *.o 

relabel: install
	/sbin/restorecon $(BINDIR)/newrole
