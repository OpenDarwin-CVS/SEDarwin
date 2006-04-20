include ../../../Makeconfig

POLICYCOREUTILS=../../policycoreutils
VPATH = $(POLICYCOREUTILS)/load_policy

PROG= load_policy
MAN8= $(POLICYCOREUTILS)/load_policy/load_policy.8

OBJS= load_policy.o


CFLAGS+= -Wall -I$(SOURCE_ROOT)/sedarwin/libselinux/include -I$(SOURCE_ROOT)/sedarwin/libsepol/include
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src -L$(SOURCE_ROOT)/sedarwin/libsepol/src -L$(SOURCE_ROOT)/sedarwin/libsecompat
LDADD+= -lselinux -lsepol -lsecompat $(LIBMAC)

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install:
	install -m 555 $(PROG) $(DESTDIR)/usr/bin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	rm -f $(OBJS) $(PROG)
