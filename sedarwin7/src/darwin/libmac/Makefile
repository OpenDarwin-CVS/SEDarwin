include ../../Makeconfig

MIGSOURCE= ../xnu/BUILD/obj/EXPORT_HDRS/osfmk/mach/

CFLAGS+=-I$(MIGSOURCE) $(DARWIN_HDRS)

LIB= mac
OBJS = mac.o mac_exec.o mac_get.o mac_set.o security.o
AR = ar cq
RANLIB = ranlib
INSTALL = install

all: lib$(LIB).a

install: all
	$(INSTALL) -o $(LIBOWN) -g $(LIBGRP) -m 0644 lib$(LIB).a \
		$(DESTDIR)/usr/lib
	$(RANLIB) $(DESTDIR)/usr/lib/lib$(LIB).a
	$(INSTALL) -d $(DESTDIR)/usr/share/man/man3
	$(INSTALL) -d $(DESTDIR)/usr/share/man/man4
	$(INSTALL) -d $(DESTDIR)/usr/share/man/man7
	$(INSTALL) -c -m 444 mac.4 $(DSTROOT)/usr/share/man/man4/
	$(INSTALL) -c -m 444 maclabel.7 $(DSTROOT)/usr/share/man/man7/
	$(INSTALL) -c -m 444 mac.3 mac_free.3 mac_get.3 mac_is_present_np.3 \
		mac_prepare.3 mac_set.3 mac_text.3 mac_execve.3 mac_syscall.3 \
		$(DSTROOT)/usr/share/man/man3/

clean:
	rm -f lib$(LIB).a $(OBJS) security.c

lib$(LIB).a:: $(OBJS)
	rm -f lib$(LIB).a
	$(AR) lib$(LIB).a `lorder $(OBJS) | tsort -q`
	$(RANLIB) lib$(LIB).a

security.c: $(MIGSOURCE)/security.defs
	mig $(CFLAGS) -user $@ -header security.h -server /dev/null -sheader /dev/null $(MIGSOURCE)/security.defs
