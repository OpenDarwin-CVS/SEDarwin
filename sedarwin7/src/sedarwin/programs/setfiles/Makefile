include ../../../Makeconfig

POLICYCOREUTILS=../../policycoreutils
VPATH = $(POLICYCOREUTILS)/setfiles

PROG= setfiles
MAN8= $(POLICYCOREUTILS)/setfiles/setfiles.8

OBJS= setfiles.o

CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libselinux/include
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libsepol/include
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libsecompat
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src 
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libsepol/src
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libsecompat
LDADD+= -lselinux -lsepol -lsecompat $(LIBMAC)


all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG) $(MAN8)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(OBJS) $(PROG)
