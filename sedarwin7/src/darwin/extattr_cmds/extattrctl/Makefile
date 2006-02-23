include ../../../Makeconfig

PROG= extattrctl
MAN= extattrctl.8
SRC= extattrctl.c

CFLAGS+= -O -pipe $(DARWIN_HDRS)
LDADD+= $(LIBEXTATTR)

all: $(PROG)

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDADD)

install: $(PROG) $(MAN)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(PROG) $(OBJS)