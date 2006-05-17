include ../../Makeconfig

#CFLAGS+= -I$(EXPORT_HDRS)/bsd -idirafter $(EXPORT_HDRS)/osfmk -I../.. -I../include -I../include/selinux -I../../libsepol/include

# Installation directories.
PREFIX = $(DESTDIR)/usr
LIBDIR = $(PREFIX)/lib
SHLIBDIR = $(DESTDIR)/lib

LIBVERSION = 1

SRCS=   getline.c strndup.c

LIBA=libsecompat.a 
OBJS= $(patsubst %.c,%.o,$(SRCS))

all: $(LIBA)

$(LIBA):  $(OBJS)
	libtool -static -c -o $@ $^

#install: all
#	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
#	install -c -m 644 $(LIBA) $(LIBDIR)

install:

clean: 
	rm -f $(OBJS) $(LIBA) $(TARGET) 

.PHONY: install
