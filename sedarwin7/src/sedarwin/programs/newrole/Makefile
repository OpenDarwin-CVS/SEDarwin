include ../../../Makeconfig

PROG= newrole
MAN1= newrole.1

OBJS= newrole.o

CFLAGS+= $(DARWIN_HDRS)
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src -lselinux $(LIBMAC) -lpam

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG) $(MAN1)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN1) $(DESTDIR)/usr/share/man/man1

clean:
	rm -f $(OBJS) $(PROG)
