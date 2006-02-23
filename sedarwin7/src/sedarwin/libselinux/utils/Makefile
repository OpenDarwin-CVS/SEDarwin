include ../../../Makeconfig

PROG= sebsd_newrole
MAN1= sebsd_newrole.1

OBJS= sebsd_newrole.o

CFLAGS+= $(DARWIN_HDRS)
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin

# Installation directories.
PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin

override CFLAGS += -I../include
LDLIBS += -L../src -lselinux $(LIBMAC) -lmac

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

