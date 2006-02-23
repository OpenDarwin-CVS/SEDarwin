include ../../../Makeconfig

PROG= mexec
NOMAN=

OBJS= mexec.o

CFLAGS+= $(DARWIN_HDRS)
LDADD+= $(LIBMAC)

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin

clean:
	rm -f $(PROG) $(OBJS)
