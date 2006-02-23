include ../../Makeconfig

CFLAGS+= -O -pipe $(DARWIN_HDRS)

LIB= extattr
OBJS = extattr.o
AR = ar cq
RANLIB = ranlib
INSTALL = install

all: lib$(LIB).a

install: all
	$(INSTALL) -o $(LIBOWN) -g $(LIBGRP) -m 0644 lib$(LIB).a \
		$(DESTDIR)/usr/lib
	$(RANLIB) $(DESTDIR)/usr/lib/lib$(LIB).a

clean:
	rm -f lib$(LIB).a $(OBJS)

lib$(LIB).a:: $(OBJS)
	rm -f lib$(LIB).a
	$(AR) lib$(LIB).a `lorder $(OBJS) | tsort -q`
	$(RANLIB) lib$(LIB).a