include ../../../Makeconfig

CFLAGS += -Wall -g $(DARWIN_HDRS) -I../..

PROG= sec_trace
LDADD+= $(LIBMAC)
NOMAN=
OBJS= sec_trace.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin

clean:
	rm -f $(OBJS) $(PROG)
