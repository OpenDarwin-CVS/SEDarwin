include ../../../Makeconfig

CFLAGS += -g -Wall $(DARWIN_HDRS) -I../..

PROG= save_trace
NOMAN=
LDADD+= $(LIBMAC)
OBJS= save_trace.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin

clean:
	rm -f $(OBJS) $(PROG)
