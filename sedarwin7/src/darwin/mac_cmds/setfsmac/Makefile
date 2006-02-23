include ../../../Makeconfig

PROG= setfsmac
MAN8= setfsmac.8 setfmac.8

OBJS= setfsmac.o

CFLAGS+= $(DARWIN_HDRS)
LDADD+= $(LIBMAC)
LINKS+= $(DESTDIR)/usr/bin/setfsmac $(DESTDIR)/usr/bin/setfmac

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	ln -f $(LINKS)
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(PROG) $(OBJS)

