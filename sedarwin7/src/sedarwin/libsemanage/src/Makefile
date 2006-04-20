include ../../../Makeconfig

CFLAGS+= -I$(EXPORT_HDRS)/bsd -idirafter $(EXPORT_HDRS)/osfmk -I../.. -I../include -I../include/selinux -I../../libsepol/include

# Installation directories.
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
SHLIBDIR ?= $(DESTDIR)/lib
INCLUDEDIR ?= $(PREFIX)/include
PYLIBVER ?= python2.4
PYINC ?= /usr/include/${PYLIBVER}
PYLIBDIR ?= $(LIBDIR)/${PYLIBVER}

DEFAULT_SEMANAGE_CONF_LOCATION=$(DESTDIR)/private/etc/sedarwin

ifeq ($(DEBUG),1)
	export CFLAGS = -g3 -O0 -gdwarf-2 -fno-strict-aliasing -Wall -Wshadow
	export LDFLAGS = -g
endif

LEX = flex
LFLAGS = -s
YACC = yacc
YFLAGS = -d -p semanage_

LIBVERSION = 1

LIBA=libsemanage.a
#TARGET=libsemanage.so
SWIGIF= semanageswig_python.i
SWIGCOUT= semanageswig_wrap.c
SWIGLOBJ:= $(patsubst %.c,%.lo,$(SWIGCOUT)) 
#SWIGSO=_semanage.so
#SWIGFILES=$(SWIGSO) semanage.py 
#LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(filter-out $(SWIGCOUT),$(wildcard *.c))) conf-scan.o conf-parse.o
LOBJS= $(patsubst %.c,%.lo,$(filter-out $(SWIGCOUT),$(wildcard *.c))) conf-scan.lo conf-parse.lo
CFLAGS ?= -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wno-unused-parameter

override CFLAGS += -I../include -I$(INCLUDEDIR) -D_GNU_SOURCE 

SWIG = swig -Wall -python -o $(SWIGCOUT) -outdir ./

all: $(LIBA) $(LIBSO) 

pywrap: all $(SWIGLOBJ) $(SWIGSO) 

$(SWIGLOBJ): $(SWIGCOUT)
	$(CC) $(CFLAGS) -I$(PYINC) -fpic -DSHARED -c -o $@ $<

$(SWIGSO): $(SWIGLOBJ)
	$(CC) $(LDFLAGS) -shared -o $@ $< -L. -lsemanage -l$(PYLIBVER) -L$(LIBDIR) -Wl,-soname,$@,-z,defs

$(LIBA): $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^ -lsepol -lselinux -L$(LIBDIR) -Wl,-soname,$(LIBSO),--version-script=libsemanage.map,-z,defs
	ln -sf $@ $(TARGET)

conf-scan.c: conf-scan.l conf-parse.h
	$(LEX) $(LFLAGS) -t $< > $@

conf-parse.c: conf-parse.y
	$(YACC) $(YFLAGS) -o $@ $<

conf-parse.h: conf-parse.c

%.o:  %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fpic -DSHARED -c -o $@ $<

$(SWIGCOUT): $(SWIGIF)
	$(SWIG) $^

swigify: $(SWIGIF)
	$(SWIG) $^

install: all 
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 644 $(LIBA) $(LIBDIR)
	#test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
	#install -m 755 $(LIBSO) $(SHLIBDIR)
	install -d -m 755 $(DEFAULT_SEMANAGE_CONF_LOCATION)
	install -m 644 semanage.conf $(DEFAULT_SEMANAGE_CONF_LOCATION)
	#cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

install-pywrap: pywrap 
	test -d $(PYLIBDIR)/site-packages || install -m 755 -d $(PYLIBDIR)/site-packages
	install -m 755 $(SWIGFILES) $(PYLIBDIR)/site-packages

relabel:
	/sbin/restorecon $(SHLIBDIR)/$(LIBSO)

clean: 
	rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(SWIGLOBJ) $(SWIGSO) $(TARGET) conf-parse.c conf-parse.h conf-scan.c

distclean: clean
	rm -f $(SWIGCOUT) $(SWIGFILES)

.PHONY: all clean pywrap swigify install install-pywrap distclean
