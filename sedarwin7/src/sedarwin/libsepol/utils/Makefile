include ../../../Makeconfig

# Installation directories.
BINDIR ?= /usr/bin

CFLAGS ?= -Wall
override CFLAGS += -I../include
LDLIBS += -L../src -lsepol -L../../libsecompat -lsecompat

TARGETS=$(patsubst %.c,%,$(wildcard *.c))

all: $(TARGETS)

install: all
	-mkdir -p $(DESTDIR)/$(BINDIR)
	install -m 755 $(TARGETS) $(DESTDIR)/$(BINDIR)

clean:
	-rm -f $(TARGETS) *.o 

relabel:

