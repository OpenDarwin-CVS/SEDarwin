include ../../../Makeconfig

PROG= rmextattr
MAN= rmextattr.8
SRC= rmextattr.c

CFLAGS+= -O -pipe $(DARWIN_HDRS)
LDADD+= $(LIBEXTATTR)

all: $(PROG)

$(PROG): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDADD)

install: $(PROG) $(MAN)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN) $(DESTDIR)/usr/share/man/man8
	ln -f $(DESTDIR)/usr/bin/$(PROG) $(DESTDIR)/usr/bin/getextattr
	ln -f $(DESTDIR)/usr/bin/$(PROG) $(DESTDIR)/usr/bin/lsextattr
	ln -f $(DESTDIR)/usr/bin/$(PROG) $(DESTDIR)/usr/bin/setextattr
	ln -f $(DESTDIR)/usr/share/man/man8/$(MAN) $(DESTDIR)/usr/share/man/man8/getextattr.8 
	ln -f $(DESTDIR)/usr/share/man/man8/$(MAN) $(DESTDIR)/usr/share/man/man8/lsextattr.8 
	ln -f $(DESTDIR)/usr/share/man/man8/$(MAN) $(DESTDIR)/usr/share/man/man8/setextattr.8 

clean:
	rm -f $(PROG) $(OBJS)