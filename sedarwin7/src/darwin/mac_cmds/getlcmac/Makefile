include ../../../Makeconfig

PROG= getlcmac
MAN8= getlcmac.8

OBJS= getlcmac.o

CFLAGS+= $(DARWIN_HDRS)
LDADD+= $(LIBMAC)

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(PROG) $(OBJS)
