include ../../Makeconfig

CFLAGS=	-I../module/ $(DARWIN_HDRS)

all: dumptrace

ikotnames.h: $(DARWIN_ROOT)/xnu/osfmk/kern/ipc_kobject.h
	perl ikotnames $< > $@

dumptrace: dumptrace.c ikotnames.h
	gcc -o $@ $(CFLAGS) $< $(LIBMAC)

install:
	install -m 755 dumptrace $(DESTDIR)/$(BINDIR)

clean:
	rm -f dumptrace dumptrace.o ikotnames.h
