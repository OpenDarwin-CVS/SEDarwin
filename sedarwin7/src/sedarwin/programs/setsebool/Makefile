include ../../../Makeconfig

POLICYCOREUTILS=../../policycoreutils
VPATH = $(POLICYCOREUTILS)/setsebool

PROG= setsebool
MAN8= $(POLICYCOREUTILS)/setsebool/setsebool.8

OBJS= setsebool.o

CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libselinux/include
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libsepol/include
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libsemanage/include
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src 
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libsepol/src
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libsemanage/src
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libsecompat
LDADD+= -lsemanage -lselinux -lsepol -lsecompat $(LIBMAC)


all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG) $(MAN8)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(OBJS) $(PROG)
