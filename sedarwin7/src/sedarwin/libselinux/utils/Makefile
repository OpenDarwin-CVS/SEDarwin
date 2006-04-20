include ../../../Makeconfig

CFLAGS+= -I$(EXPORT_HDRS)/bsd -idirafter $(EXPORT_HDRS)/osfmk
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin

# Installation directories.
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin

override CFLAGS += -I../include 
LDLIBS += -L../src -L../../libsepol/src -L../../libsecompat
LDLIBS += -lselinux -lsepol -lsecompat $(LIBMAC)

SRCS= getfilecon.c getsebool.c getcon.c \
      setfilecon.c setsebool.c togglesebool.c

TARGETS=$(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

install: all
	-mkdir -p $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)

clean:
	rm -f $(TARGETS) *.o 

relabel:

