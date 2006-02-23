include ../../../Makeconfig

CFLAGS+= $(DARWIN_HDRS) -I../.. -I../include -I../../sedarwin

# Installation directories.
PREFIX = $(DESTDIR)/usr
LIBDIR = $(PREFIX)/lib
SHLIBDIR = $(DESTDIR)/lib

LIBVERSION = 1

SRCS=   system.c security_get_user_contexts.c get_context_list.c \
        getseccontext.c query_user_context.c \
        context.c check_context.c getcon.c \
        get_default_type.c filecon.c sedarwin_config.c \
        freecon.c freeconary.c booleans.c

LIBA=libselinux.a 
#TARGET=libselinux.so
#LIBSO=$(TARGET).$(LIBVERSION)
OBJS= $(patsubst %.c,%.o,$(SRCS))
LOBJS= $(patsubst %.c,%.lo,$(SRCS))

all: $(LIBA)

$(LIBA):  $(OBJS)
	$(AR) rcs $@ $^
	ranlib $@

$(LIBSO): $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^ -Wl,-soname,$(LIBSO) 
	ln -sf $@ $(TARGET) 

%.o:  %.c policy.h
	$(CC) $(CFLAGS) -c -o $@ $<

%.lo:  %.c policy.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

install: all
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -c -m 644 $(LIBA) $(LIBDIR)
	ranlib $(LIBDIR)/$(LIBA)
#	test -d $(SHLIBDIR) || install -m 755 -d $(SHLIBDIR)
#	install -m 755 $(LIBSO) $(SHLIBDIR)
#	cd $(LIBDIR) && ln -sf ../../`basename $(SHLIBDIR)`/$(LIBSO) $(TARGET)

clean: 
	rm -f $(OBJS) $(LOBJS) $(LIBA) $(LIBSO) $(TARGET) 

