include ../../../Makeconfig

PROG= getpmac
MAN8= getpmac.8

OBJS= getpmac.o

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
