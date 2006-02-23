include ../../../Makeconfig

PROG= sebsd_loadpolicy
MAN8= sebsd_loadpolicy.8

OBJS= sebsd_loadpolicy.o


CFLAGS+= -Wall -I$(SOURCE_ROOT)/sedarwin
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src
LDADD+= -lselinux $(LIBMAC)

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install:
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(OBJS) $(PROG)
