include ../../../Makeconfig

POLICYCOREUTILS=../../policycoreutils
VPATH = $(POLICYCOREUTILS)/scripts

SCRIPT= $(POLICYCOREUTILS)/scripts/genhomedircon
MAN8= $(POLICYCOREUTILS)/scripts/genhomedircon.8

all: $(SCRIPT)

install: $(SCRIPT) $(MAN8)
	install -m 555 $(SCRIPT) $(DESTDIR)/usr/sbin
	install -m 444 $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:

.PHONY: $(SCRIPT) $(MAN8)
