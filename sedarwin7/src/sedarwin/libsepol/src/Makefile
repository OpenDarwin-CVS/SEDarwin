include ../../../Makeconfig

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib

LIBVERSION = 1

# Set to y for MLS
MLS=n

LIBA=libsepol.a 
#TARGET=libsepol.so
#LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(wildcard *.c))
#LOBJS= $(patsubst %.c,%.lo,$(wildcard *.c))
CFLAGS = -Wall $(OPTIONS)
override CFLAGS += -I. -I../include

all: $(LIBA)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^ -Wl,-soname,$(LIBSO),--version-script=libsepol.map
	ln -sf $@ $(TARGET) 

%.o:  %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

install: all
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
#	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
#	install -m 755 $(LIBSO) $(SHLIBDIR)
#	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

clean: 
	rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) 

